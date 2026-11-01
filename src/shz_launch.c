/* shz_launch.c -- intent 703 (i553b)
 *
 * Stage 3 of goal 223 ("Shizuku runs as root and distributes privilege").
 *
 * Baseline: i552z/src/glx_p11.c (facts 695/698: on the real device, with
 * --perm-armed, SETIDS gives setresuid(0,0,0) rc=0, Uid/Gid all 0, ctx still
 * u:r:shell:s0, global enforcing=1 for the whole run).
 *
 * This file is a pure increment: it is compiled as a second translation unit
 * and called from exactly one place in do_chain() (after SETIDS / N10_LEGIT,
 * before the permset stop).  Nothing in i552z/i552w/i662/i552u/i418/i51x/i601
 * is modified.
 *
 * What it does, in Shizuku's own contract order (i262 §2.2, device-observed):
 *   1. resolve base.apk (--shz-apk or auto-scan /data/app)
 *   2. build the INIT environment (snapshot + /proc/1/environ +
 *      /data/system/environ/classpath; LD_xxx / ANDROID_SOCKET_xxx / TMPDIR
 *      are filtered out because Termux injects them)
 *   3. SELinux self-check untrusted_app -> self : binder {call,transfer}
 *      through /sys/fs/selinux/access (the same gate libshizuku.so runs)
 *   4. optionally kill a stale shizuku_server
 *   5. fork(); child: setsid, chdir("/"), stdio->/dev/null, close fds>=3,
 *      CLASSPATH=<apk>, then execve /system/bin/app_process with
 *        -Djava.class.path=<apk>
 *        -Dshizuku.library.path=<apkdir>/lib/arm64
 *        /system/bin --nice-name=shizuku_server
 *        rikka.shizuku.server.ShizukuService
 *      (or execve libshizuku.so --apk=<apk> with --shz-mode=starter)
 *   6. verify the new process: uid/gid all 0, CapEff contains 0xC6,
 *      ctx == u:r:shell:s0, /proc/<pid>/comm == shizuku_server
 *
 * Why the capability survives the execve twice: WC4/WC5 in glx_p11 wrote
 * cred+0x28 (cap_inheritable) and cred+0x48 (cap_ambient) = V (low 32 bits
 * 0x10f830c6, i.e. superset of 0xC6).  On 5.4 cap_bprm_set_creds() does
 *   new->cap_ambient = old->cap_ambient
 *   new->cap_permitted = combine(new->cap_permitted, new->cap_ambient)
 *   new->cap_effective = old->cap_ambient      (no file caps, no setid)
 * so pP' = pE' = pA' = V and cap_ambient_invariant_ok() holds because
 * permitted == inheritable == ambient (all V).  See GATE_NOTES_i553b.md.
 */
#define _GNU_SOURCE
#include "shz_launch.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "shz_env_snapshot.h"

#define DEFAULT_APP_PROCESS "/system/bin/app_process"
#define SHZ_JSON "/data/user_de/0/com.android.shell/shizuku.json"
#define SHZ_MANAGER_DIR "/data/app"
#define SHZ_MANAGER_PKG "moe.shizuku.privileged.api"
/* device-observed on PHQ110 C.53 (i262 §1.1); only a fallback for auto-scan */
#define SHZ_APK_KNOWN \
    "/data/app/~~vH3Vm9f6DDO2CHE-VAQZWw==/moe.shizuku.privileged.api-4Xx4RkAMSV_-70E9l0ii-A==/base.apk"

#define SHZ_MAXENV 256

#ifdef GLX_UT
/* host-only seam (never in the device build): the mock E2E runs on a machine
 * without selinuxfs, so the ctx leg of verify_pid() is skipped when 0. */
int ut_shz_ctx_must_match = 1;
#endif

/* ------------------------------------------------------------------ log */
static void lg(char *log, size_t logn, const char *fmt, ...)
{
    size_t used;
    va_list ap;
    if (!log || logn == 0) return;
    used = strlen(log);
    if (used + 2 >= logn) return;
    va_start(ap, fmt);
    vsnprintf(log + used, logn - used, fmt, ap);
    va_end(ap);
    used = strlen(log);
    if (used + 2 < logn) { log[used] = '\n'; log[used + 1] = 0; }
}

/* i775: per-stage machine anchors, one per line, greppable by the i770
 * harness and the i776 criteria matrix.  Pure output: no argv/env constant,
 * no ordering and no control flow is changed by these calls. */
static void anchor(const char *fmt, ...)
{
    char b[768];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    printf("GLX|%s\n", b);
    fflush(stdout);
}

/* ------------------------------------------------------------- small io */
static int read_all(const char *p, char **out, size_t *len)
{
    int fd, n;
    size_t cap = 4096, used = 0;
    char *b;
    *out = NULL; *len = 0;
    fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    b = malloc(cap);
    if (!b) { close(fd); return -1; }
    while ((n = (int)read(fd, b + used, cap - used - 1)) > 0) {
        used += (size_t)n;
        if (used + 1 >= cap) {
            char *nb;
            if (cap >= (1u << 20)) break;
            cap *= 2;
            nb = realloc(b, cap);
            if (!nb) { free(b); close(fd); return -1; }
            b = nb;
        }
    }
    close(fd);
    b[used] = 0;
    *out = b; *len = used;
    return 0;
}

static int rd_first_line(const char *p, char *b, int n)
{
    int fd, r;
    if (n < 2) return -1;
    fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    r = (int)read(fd, b, (size_t)n - 1);
    close(fd);
    if (r <= 0) return -1;
    b[r] = 0;
    while (r > 0 && (b[r-1] == '\n' || b[r-1] == '\r' || b[r-1] == 0)) b[--r] = 0;
    return r;
}

/* --------------------------------------------------------------- envp */
static char **ev_new(void)
{
    char **v = calloc(SHZ_MAXENV, sizeof(char *));
    return v;
}

static int ev_count(char **v)
{
    int n = 0;
    while (v && v[n] && n < SHZ_MAXENV - 1) n++;
    return n;
}

static void ev_free(char **v)
{
    int i;
    if (!v) return;
    for (i = 0; v[i]; i++) free(v[i]);
    free(v);
}

static const char *ev_get(char **v, const char *key, size_t klen)
{
    int i;
    for (i = 0; v && v[i]; i++)
        if (!strncmp(v[i], key, klen) && v[i][klen] == '=')
            return v[i] + klen + 1;
    return NULL;
}

static void ev_del(char **v, const char *key)
{
    size_t klen = strlen(key);
    int i = 0;
    if (!v) return;
    while (v[i]) {
        if (!strncmp(v[i], key, klen) && v[i][klen] == '=') {
            int j;
            free(v[i]);
            for (j = i; v[j]; j++) v[j] = v[j + 1];
            continue;
        }
        i++;
    }
}

/* Insert/replace.  The value is copied; key is implied by kv. */
static int ev_put(char **v, const char *key, const char *val)
{
    int i, n = ev_count(v);
    size_t kl = strlen(key), vl = strlen(val);
    char *kv;
    if (n >= SHZ_MAXENV - 1) return -1;
    kv = malloc(kl + vl + 2);
    if (!kv) return -1;
    memcpy(kv, key, kl); kv[kl] = '=';
    memcpy(kv + kl + 1, val, vl + 1);
    for (i = 0; i < n; i++) {
        if (!strncmp(v[i], key, kl) && v[i][kl] == '=') {
            free(v[i]);
            v[i] = kv;
            return 0;
        }
    }
    v[n] = kv;
    v[n + 1] = NULL;
    return 0;
}

static void ev_put_kv(char **v, const char *kv)
{
    const char *eq = strchr(kv, '=');
    char key[128];
    size_t kl;
    if (!eq) return;
    kl = (size_t)(eq - kv);
    if (kl == 0 || kl >= sizeof(key)) return;
    memcpy(key, kv, kl); key[kl] = 0;
    ev_put(v, key, eq + 1);
}

/* names we never forward (i262 §3: Termux LD_* hijack / adbd socket leak) */
static int env_drop(const char *kv)
{
    static const char *bad[] = {
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_DEBUG", "LD_AUDIT", "LD_ORIGIN_PATH",
        "TMPDIR", "LOGNAME", "PWD", "SHLVL", "_", "ANDROID_SOCKET_adbd",
        "ANDROID_SOCKET_", "ASEC_MOUNTPOINT", "ANDROID_BOOTLOGO", NULL
    };
    int i;
    for (i = 0; bad[i]; i++) {
        size_t l = strlen(bad[i]);
        if (!strncmp(kv, bad[i], l) &&
            (kv[l] == '=' || (l && bad[i][l-1] == '_') || bad[i][l-1] == '.'))
            return 1;
    }
    return 0;
}

static void env_load_nul(char **v, const char *path, int *n_added)
{
    char *buf;
    size_t len, i = 0;
    if (read_all(path, &buf, &len) != 0) return;
    while (i < len) {
        size_t j = i;
        while (j < len && buf[j]) j++;
        if (j > i) {
            char *kv = strndup(buf + i, j - i);
            if (kv) {
                if (strchr(kv, '=') && !env_drop(kv)) {
                    ev_put_kv(v, kv);
                    (*n_added)++;
                }
                free(kv);
            }
        }
        i = j + 1;
    }
    free(buf);
}

/* /data/system/environ/classpath: lines of the form "export K V" */
static void env_load_exports(char **v, const char *path, int *n_added)
{
    char *buf;
    size_t len, i = 0;
    if (read_all(path, &buf, &len) != 0) return;
    while (i < len) {
        size_t j = i;
        while (j < len && buf[j] != '\n') j++;
        {
            char *line = strndup(buf + i, j - i);
            i = j + 1;
            if (line) {
                char *p = line;
                while (*p == ' ' || *p == '\t') p++;
                if (!strncmp(p, "export ", 7)) p += 7;
                while (*p == ' ' || *p == '\t') p++;
                {
                    char *sp = p;
                    while (*sp && *sp != ' ' && *sp != '\t' && *sp != '=') sp++;
                    if (*sp && *sp != '=') {
                        char key[128];
                        size_t kl = (size_t)(sp - p);
                        if (kl && kl < sizeof(key)) {
                            memcpy(key, p, kl); key[kl] = 0;
                            sp++;
                            while (*sp == ' ' || *sp == '\t') sp++;
                            {
                                char kv[4096];
                                snprintf(kv, sizeof(kv), "%s=%s", key, sp);
                                if (!env_drop(kv)) { ev_put_kv(v, kv); (*n_added)++; }
                            }
                        }
                    } else if (*sp == '=') {
                        char kv[4096];
                        snprintf(kv, sizeof(kv), "%s", p);
                        if (!env_drop(kv)) { ev_put_kv(v, kv); (*n_added)++; }
                    }
                }
                free(line);
            }
        }
    }
    free(buf);
}

int shz_build_env(const struct shz_opts *o, const char *apk,
                  char ***outv, char *why, size_t wn)
{
    char **v = ev_new();
    int i, added = 0;

    if (!v) { snprintf(why, wn, "out of memory"); return SHZ_EXIT_ENV; }

    /* (4) compiled C.53 snapshot is the always-available floor */
    for (i = 0; ENV_SNAPSHOT[i].k; i++)
        ev_put(v, ENV_SNAPSHOT[i].k, ENV_SNAPSHOT[i].v);

    /* (1) explicit file, else (2) /proc/1/environ, else (3) exports */
    if (o && o->env_file) {
        env_load_nul(v, o->env_file, &added);
        if (!added) env_load_exports(v, o->env_file, &added);
    } else {
        env_load_nul(v, "/proc/1/environ", &added);
        if (!added)
            env_load_exports(v, "/data/system/environ/classpath", &added);
    }

    /* hygiene + forced values (i262 §3 / §4.1) */
    {
        int n = ev_count(v), k = 0;
        for (i = 0; i < n; i++) {
            if (env_drop(v[i])) { free(v[i]); continue; }
            v[k++] = v[i];
        }
        v[k] = NULL;
    }
    ev_put(v, "ANDROID_ROOT", "/system");
    ev_put(v, "ANDROID_DATA", "/data");
    if (apk && *apk) ev_put(v, "CLASSPATH", apk);
    if (getenv("GLX_SHZ_ENV_EXTRA"))
        ev_put_kv(v, getenv("GLX_SHZ_ENV_EXTRA"));
#ifdef GLX_UT
    /* host-only seam: the mock target is driven through MOCK_* variables, and
     * the child gets the synthetic init environment (not our environ).  These
     * keys are compiled out of the device binary. */
    {
        static const char *keys[] = { "MOCK_OUT", "MOCK_ROLE", "MOCK_EXIT",
                                      "MOCK_FORK_SERVER", NULL };
        for (i = 0; keys[i]; i++) {
            const char *mv = getenv(keys[i]);
            if (mv) ev_put(v, keys[i], mv);
        }
    }
#endif

    if (!ev_get(v, "BOOTCLASSPATH", 13) ||
        !strstr(ev_get(v, "BOOTCLASSPATH", 13), "/system/framework/framework.jar")) {
        snprintf(why, wn, "BOOTCLASSPATH missing or lacks "
                 "/system/framework/framework.jar (libart would treat the APK "
                 "as boot classpath)");
        ev_free(v);
        return SHZ_EXIT_ENV;
    }
    *outv = v;
    return SHZ_EXIT_OK;
}

/* ------------------------------------------------------- apk discovery */
static int apk_ok(const char *p)
{
    struct stat st;
    if (!p || !*p) return 0;
    if (stat(p, &st) != 0) return 0;
    if (!S_ISREG(st.st_mode)) return 0;
    return access(p, R_OK) == 0;
}

static int apk_auto(char *out, size_t n, char *log, size_t logn)
{
    DIR *d = opendir(SHZ_MANAGER_DIR);
    struct dirent *de;
    int found = 0;
    if (!d) return 0;
    while ((de = readdir(d)) != NULL) {
        char dirp[PATH_MAX], apkp[PATH_MAX];
        char sub[512];
        DIR *d2;
        struct dirent *de2;
        if (strncmp(de->d_name, SHZ_MANAGER_PKG "-", strlen(SHZ_MANAGER_PKG) + 1))
            continue;
        snprintf(dirp, sizeof(dirp), "%s/%s", SHZ_MANAGER_DIR, de->d_name);
        snprintf(apkp, sizeof(apkp), "%s/base.apk", dirp);
        if (apk_ok(apkp)) {
            if (found) { lg(log, logn, "SHZ|APK|ambiguous: %s (keeping the "
                          "first match %s; pass --shz-apk to pin)", apkp, out); }
            else { snprintf(out, n, "%s", apkp); found = 1; }
            continue;
        }
        /* the package dir may hold the versioned subdir directly; also look
         * one level down for the base.apk */
        d2 = opendir(dirp);
        if (!d2) continue;
        while ((de2 = readdir(d2)) != NULL) {
            if (de2->d_name[0] == '.') continue;
            snprintf(sub, sizeof(sub), "%s/%s/base.apk", dirp, de2->d_name);
            if (apk_ok(sub)) {
                if (!found) { snprintf(out, n, "%s", sub); found = 1; }
                break;
            }
        }
        closedir(d2);
    }
    closedir(d);
    if (found) lg(log, logn, "SHZ|APK|auto-discovered %s", out);
    return found;
}

static int apk_resolve(const struct shz_opts *o, char *out, size_t n,
                       char *log, size_t logn, char *why, size_t wn)
{
    if (o && o->apk && *o->apk) {
        snprintf(out, n, "%s", o->apk);
        if (!apk_ok(out)) {
            snprintf(why, wn, "--shz-apk=%s missing/unreadable", out);
            return SHZ_EXIT_APK;
        }
        return SHZ_EXIT_OK;
    }
    if (apk_auto(out, n, log, logn)) return SHZ_EXIT_OK;
    if (apk_ok(SHZ_APK_KNOWN)) {
        snprintf(out, n, "%s", SHZ_APK_KNOWN);
        lg(log, logn, "SHZ|APK|known C.53 path %s", out);
        return SHZ_EXIT_OK;
    }
    snprintf(why, wn, "manager apk not found under %s (%s-*/base.apk); pass "
             "--shz-apk=<pm path>", SHZ_MANAGER_DIR, SHZ_MANAGER_PKG);
    return SHZ_EXIT_APK;
}

/* -------------------------------------------------------- selinux gate */
/* The starter runs selinux_check_access("u:r:untrusted_app:s0", self,
 * "binder", {call,transfer}); a denial is its exit 10.  We reproduce the same
 * query through /sys/fs/selinux/access (shell has selinuxfs file write, CIL
 * devpolicy.cil:58608).  Result "0" = allowed; "-13" = denied; other =
 * infrastructure error (non-fatal, we log SKIP and continue -- the starter's
 * own copy is the authority when --shz-mode=starter). */
static int shz_selinux_gate(char *log, size_t logn, char *why, size_t wn)
{
    char ctx[160];
    const char *perms[2] = { "call", "transfer" };
    int i, denied = 0, checked = 0;

    ctx[0] = 0;
    if (rd_first_line("/proc/self/attr/current", ctx, sizeof(ctx)) <= 0) {
        lg(log, logn, "SHZ|SELGATE|self ctx unreadable -> SKIP");
        return SHZ_EXIT_OK;
    }
    for (i = 0; i < 2; i++) {
        char q[512], res[64];
        int fd, w, r;
        snprintf(q, sizeof(q), "u:r:untrusted_app:s0 %s binder %s\n", ctx, perms[i]);
        fd = open("/sys/fs/selinux/access", O_WRONLY | O_CLOEXEC);
        if (fd < 0) {
            lg(log, logn, "SHZ|SELGATE|open access errno=%d -> SKIP (starter "
               "will re-check; permissive_map(shell) does not cover this "
               "direction, base policy does)", errno);
            return SHZ_EXIT_OK;
        }
        w = (int)write(fd, q, strlen(q));
        close(fd);
        if (w < 0) {
            lg(log, logn, "SHZ|SELGATE|write errno=%d -> SKIP", errno);
            return SHZ_EXIT_OK;
        }
        res[0] = 0;
        r = rd_first_line("/sys/fs/selinux/access", res, sizeof(res));
        lg(log, logn, "SHZ|SELGATE|untrusted_app->%s|binder %s -> %s (rc=%d)",
           ctx, perms[i], r > 0 ? res : "?", r);
        if (r > 0 && res[0] == '0') { checked++; continue; }
        if (r > 0 && res[0] == '-') { denied++; }
    }
    (void)checked;
    if (denied) {
        snprintf(why, wn, "selinux_check_access(untrusted_app -> %s, binder "
                 "call/transfer) denied (starter exit 10)", ctx);
        return SHZ_EXIT_SELINUX;
    }
    return SHZ_EXIT_OK;
}

/* ----------------------------------------------------------- /proc scan */
pid_t shz_find_server(void)
{
    DIR *d = opendir("/proc");
    struct dirent *de;
    pid_t self = getpid();
    if (!d) return -1;
    while ((de = readdir(d)) != NULL) {
        char p[64], comm[64];
        long pid;
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        pid = atol(de->d_name);
        if (pid <= 0 || (pid_t)pid == self) continue;
        snprintf(p, sizeof(p), "/proc/%ld/comm", pid);
        if (rd_first_line(p, comm, sizeof(comm)) <= 0) continue;
        if (!strcmp(comm, "shizuku_server")) { closedir(d); return (pid_t)pid; }
    }
    closedir(d);
    return -1;
}

static int kill_old(char *log, size_t logn, char *why, size_t wn)
{
    pid_t p = shz_find_server();
    if (p <= 0) return SHZ_EXIT_OK;
    if (kill(p, SIGKILL) != 0) {
        lg(log, logn, "SHZ|KILLOLD|pid=%d kill errno=%d", (int)p, errno);
        if (errno == EPERM) {
            snprintf(why, wn, "kill(old shizuku_server pid=%d) EPERM "
                     "(starter exit 9)", (int)p);
            return SHZ_EXIT_KILL;
        }
        return SHZ_EXIT_OK;
    }
    lg(log, logn, "SHZ|KILLOLD|pid=%d SIGKILL ok", (int)p);
    usleep(150 * 1000);
    return SHZ_EXIT_OK;
}

/* --------------------------------------------------------------- verify */
static int status_field(const char *path, const char *key, char *out, int n)
{
    char *buf;
    size_t len;
    const char *p;
    out[0] = 0;
    if (read_all(path, &buf, &len) != 0) return -1;
    for (p = buf; *p; p++) {
        if ((p == buf || p[-1] == '\n') && !strncmp(p, key, strlen(key))) {
            const char *e = strchr(p, '\n');
            int l = e ? (int)(e - p) : (int)strlen(p);
            if (l >= n) l = n - 1;
            memcpy(out, p, (size_t)l); out[l] = 0;
            free(buf);
            return 0;
        }
        {
            const char *e = strchr(p, '\n');
            if (!e) break;
            p = e;
        }
    }
    free(buf);
    return -1;
}

static int verify_pid(pid_t pid, char *log, size_t logn, char *why, size_t wn)
{
    char p[64], s[512], ctx[160];
    unsigned long capeff = 0;
    int ok = 1;

    if (pid <= 0) { snprintf(why, wn, "no shizuku_server process"); return SHZ_EXIT_VERIFY; }

    snprintf(p, sizeof(p), "/proc/%d/status", (int)pid);
    if (status_field(p, "Uid:", s, sizeof(s)) != 0) {
        snprintf(why, wn, "%s unreadable", p);
        return SHZ_EXIT_VERIFY;
    }
    lg(log, logn, "SHZ|VERIFY|pid=%d %s", (int)pid, s);
    {
        long a, b, c, d;
        if (sscanf(s, "Uid: %ld %ld %ld %ld", &a, &b, &c, &d) != 4 ||
            a || b || c || d) ok = 0;
    }
    if (status_field(p, "Gid:", s, sizeof(s)) == 0) lg(log, logn, "SHZ|VERIFY|%s", s);
    if (status_field(p, "PPid:", s, sizeof(s)) == 0) lg(log, logn, "SHZ|VERIFY|%s", s);
    if (status_field(p, "CapEff:", s, sizeof(s)) == 0) {
        lg(log, logn, "SHZ|VERIFY|%s", s);
        if (sscanf(s, "CapEff: %lx", &capeff) == 1) {
            if ((capeff & 0xC6UL) != 0xC6UL) ok = 0;
        } else ok = 0;
    } else ok = 0;
    snprintf(p, sizeof(p), "/proc/%d/attr/current", (int)pid);
    ctx[0] = 0;
    if (rd_first_line(p, ctx, sizeof(ctx)) > 0) {
        lg(log, logn, "SHZ|VERIFY|ctx=%s", ctx);
#ifdef GLX_UT
        /* Host seam: the build host has no SELinux, so attr/current reads
         * "kernel"/"unconfined".  Skipped only in the GLX_UT build; the device
         * binary always compares against u:r:shell:s0. */
        if (ut_shz_ctx_must_match && strncmp(ctx, "u:r:shell:s0", 12)) ok = 0;
#else
        if (strncmp(ctx, "u:r:shell:s0", 12)) ok = 0;
#endif
    } else {
#ifdef GLX_UT
        /* Host-only seam: there is no selinuxfs on the build host, so the ctx
         * leg is skipped for the mock E2E.  Compiled out of the device binary;
         * the device run always enforces ctx == u:r:shell:s0. */
        if (!ut_shz_ctx_must_match)
            lg(log, logn, "SHZ|VERIFY|ctx SKIP (host UT: no selinuxfs)");
        else ok = 0;
#else
        lg(log, logn, "SHZ|VERIFY|ctx unreadable");
        ok = 0;
#endif
    }

    if (!ok) {
        snprintf(why, wn, "post-launch verification failed (uid/caps/ctx), "
                 "see SHZ|VERIFY lines");
        anchor("STAGE3_MAIN|FAIL|pid=%d|ctx=%s", (int)pid, ctx);
        return SHZ_EXIT_VERIFY;
    }
    /* i775: uid0 + CapEff 0xC6 + u:r:shell:s0 on the live server == ART ran
     * main entry (fact 761/758); this is the parent-side STAGE3_MAIN anchor. */
    anchor("STAGE3_MAIN|PASS|pid=%d|ctx=%s", (int)pid, ctx);
    return SHZ_EXIT_OK;
}

static void wait_json_once(char *log, size_t logn)
{
    struct stat st;
    if (stat(SHZ_JSON, &st) == 0) {
        lg(log, logn, "SHZ|JSON|%s mode=%04o uid=%d size=%lld", SHZ_JSON,
           (unsigned)(st.st_mode & 07777), (int)st.st_uid, (long long)st.st_size);
        /* i775: the config record is written by the Shizuku server AFTER it
         * received the binder and saved Manager config (fact 761), so its
         * presence is the parent-side proxy for "binder delivered". */
        anchor("STAGE3_BINDER|PASS|json=%s|size=%lld", SHZ_JSON,
               (long long)st.st_size);
    } else {
        lg(log, logn, "SHZ|JSON|%s not (yet) present errno=%d -- the server "
           "writes it best-effort; only the authorization record is lost",
           SHZ_JSON, errno);
        anchor("STAGE3_BINDER|UNKNOWN|json=%s|errno=%d", SHZ_JSON, errno);
    }
}

/* ---------------------------------------------------------------- spawn */
static int spawn(const struct shz_opts *o, const char *apk, int mode,
                 const char *lib, char *const *envv, char *log, size_t logn,
                 pid_t *out_pid, char *why, size_t wn)
{
    pid_t p;

    (void)log; (void)logn;
    p = fork();
    if (p < 0) { snprintf(why, wn, "fork errno=%d", errno); return SHZ_EXIT_FORK; }
    if (p == 0) {
        int fd, cf;
        setsid();
        (void)chdir("/");
        fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
            dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);
            if (fd > 2) close(fd);
        }
        for (cf = 3; cf < 1024; cf++) close(cf);
        if (mode == SHZ_MODE_STARTER) {
            char a1[PATH_MAX + 16];
            char *av[3];
            snprintf(a1, sizeof(a1), "--apk=%s", apk);
            av[0] = lib; av[1] = a1; av[2] = NULL;
            execve(lib, av, envv);
        } else {
            char c1[PATH_MAX + 32], c2[PATH_MAX + 32];
            char *av[8];
            const char *ap = (o->app_process && *o->app_process)
                             ? o->app_process : DEFAULT_APP_PROCESS;
            const char *slash = strrchr(apk, '/');
            int dl = slash ? (int)(slash - apk) : 0;
            snprintf(c1, sizeof(c1), "-Djava.class.path=%s", apk);
            snprintf(c2, sizeof(c2), "-Dshizuku.library.path=%.*s/lib/arm64",
                     dl, apk);
            av[0] = (char *)ap;
            av[1] = c1;
            av[2] = c2;
            av[3] = (char *)"/system/bin";
            av[4] = (char *)"--nice-name=shizuku_server";
            av[5] = (char *)"rikka.shizuku.server.ShizukuService";
            av[6] = NULL;
            execve(ap, av, envv);
        }
        _exit(SHZ_EXIT_EXEC);
    }
    *out_pid = p;
    return SHZ_EXIT_OK;
}

/* ------------------------------------------------------------ entrypoints */
/* <apkdir>/lib/arm64/libshizuku.so  (the starter libshizuku execs) */
static void shz_lib_path(const struct shz_opts *o, const char *apk, char *out, size_t n)
{
    if (o && o->lib && *o->lib) { snprintf(out, n, "%s", o->lib); return; }
    {
        const char *slash = strrchr(apk, '/');
        int dl = slash ? (int)(slash - apk) : 0;
        snprintf(out, n, "%.*s/lib/arm64/libshizuku.so", dl, apk);
    }
}

int shz_run(const struct shz_opts *o, char *log, size_t logn, char *why, size_t wn)
{
    char apk[PATH_MAX];
    char lib[PATH_MAX];
    char **envv = NULL;
    pid_t pid = -1;
    int rc, waited = 0, status = 0, mode;
    int wait_ms = (o && o->wait_ms > 0) ? o->wait_ms : 2500;
    uid_t uid = getuid();

    why[0] = 0;
    mode = o ? o->mode : SHZ_MODE_AUTO;
    lg(log, logn, "SHZ|BEGIN|mode=%s uid=%d euid=%d",
       mode == SHZ_MODE_STARTER ? "starter" :
       (mode == SHZ_MODE_APPPROCESS ? "appprocess" : "auto"),
       (int)uid, (int)geteuid());
    if (!o->uid_gate_exempt && (uid != 0 && uid != 2000)) {
        snprintf(why, wn, "real uid=%d is neither 0 nor 2000 (starter gate, "
                 "exit 6) -- cred swap/SETIDS did not reach this process", (int)uid);
        return SHZ_EXIT_UID;
    }
    rc = apk_resolve(o, apk, sizeof(apk), log, logn, why, wn);
    if (rc != SHZ_EXIT_OK) return rc;
    lg(log, logn, "SHZ|APK|%s", apk);
    shz_lib_path(o, apk, lib, sizeof(lib));
    if (mode == SHZ_MODE_AUTO) {
        mode = (access(lib, R_OK) == 0) ? SHZ_MODE_STARTER : SHZ_MODE_APPPROCESS;
        lg(log, logn, "SHZ|MODE|auto -> %s (starter=%s readable=%d)",
           mode == SHZ_MODE_STARTER ? "starter" : "appprocess", lib,
           mode == SHZ_MODE_STARTER);
    }


    rc = shz_build_env(o, apk, &envv, why, wn);
    if (rc != SHZ_EXIT_OK) return rc;
    lg(log, logn, "SHZ|ENV|vars=%d BOOTCLASSPATH=%s ANDROID_DATA=%s "
       "SYSTEMSERVERCLASSPATH=%s", ev_count(envv),
       ev_get(envv, "BOOTCLASSPATH", 13) ? "present" : "MISSING",
       ev_get(envv, "ANDROID_DATA", 12) ? ev_get(envv, "ANDROID_DATA", 12) : "?",
       ev_get(envv, "SYSTEMSERVERCLASSPATH", 21) ? "present" : "missing");

    rc = shz_selinux_gate(log, logn, why, wn);
    if (rc != SHZ_EXIT_OK) { ev_free(envv); return rc; }

    /* i775 machine anchor: everything below this line is the actual stage-3
     * launch (mode, uid, resolved apk; argv/env constants are untouched). */
    anchor("STAGE3_INIT|mode=%s|uid=%d|euid=%d|apk=%s",
           mode == SHZ_MODE_STARTER ? "starter" : "appprocess",
           (int)getuid(), (int)geteuid(), apk);

    if (!o->keep_old) {
        rc = kill_old(log, logn, why, wn);
        if (rc != SHZ_EXIT_OK) { ev_free(envv); return rc; }
    }

    if (mode == SHZ_MODE_STARTER && access(lib, R_OK) != 0) {
        snprintf(why, wn, "starter %s missing/unreadable (exit 7)", lib);
        ev_free(envv);
        return SHZ_EXIT_APK;
    }

    rc = spawn(o, apk, mode, lib, envv, log, logn, &pid, why, wn);
    ev_free(envv);
    if (rc != SHZ_EXIT_OK) return rc;
    lg(log, logn, "SHZ|FORK|pid=%d", (int)pid);
    anchor("STAGE3_EXEC|pid=%d|mode=%s", (int)pid,
           mode == SHZ_MODE_STARTER ? "starter" : "appprocess");

    /* Wait briefly: the starter exits 0 right after forking the server; the
     * app_process mode never exits on success.  A quick non-zero exit is the
     * starter's own failure code and is propagated verbatim. */
    for (;;) {
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            waited = 1;
            break;
        }
        if (w < 0) break;
        if (wait_ms <= 0) break;
        usleep(50 * 1000);
        wait_ms -= 50;
    }
    if (waited) {
        int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        lg(log, logn, "SHZ|CHILD_EXIT|pid=%d code=%d (starter contract: 3 env, "
           "4 fork, 5 exec, 6 uid, 7 apk, 9 kill-old, 10 selinux)", (int)pid, code);
        if (mode == SHZ_MODE_STARTER) {
            if (code != 0) {
                snprintf(why, wn, "libshizuku starter exited %d (see SHZ|CHILD_EXIT)",
                         code);
                return code ? code : SHZ_EXIT_VERIFY;
            }
            /* the server is the starter's child: find it */
            {
                int tries;
                pid_t sp = -1;
                for (tries = 0; tries < 40 && sp <= 0; tries++) {
                    sp = shz_find_server();
                    if (sp <= 0) usleep(100 * 1000);
                }
                if (sp <= 0) {
                    snprintf(why, wn, "starter exited 0 but no shizuku_server "
                             "appeared (logcat waitSystemService/System.exit)");
                    return SHZ_EXIT_VERIFY;
                }
                rc = verify_pid(sp, log, logn, why, wn);
                wait_json_once(log, logn);
                return rc;
            }
        }
        /* app_process mode: a quick exit is a failure */
        snprintf(why, wn, "app_process exited %d before verification", code);
        return code ? code : SHZ_EXIT_VERIFY;
    }
    rc = verify_pid(pid, log, logn, why, wn);
    if (rc == SHZ_EXIT_OK) wait_json_once(log, logn);
    return rc;
}

int shz_check(char *log, size_t logn, char *why, size_t wn)
{
    pid_t p;
    int rc;
    why[0] = 0;
    p = shz_find_server();
    if (p <= 0) {
        snprintf(why, wn, "no live shizuku_server (comm match) -- not started "
                 "or already killed");
        lg(log, logn, "SHZ|CHECK|no shizuku_server");
        return SHZ_EXIT_VERIFY;
    }
    lg(log, logn, "SHZ|CHECK|found pid=%d", (int)p);
    rc = verify_pid(p, log, logn, why, wn);
    wait_json_once(log, logn);
    return rc;
}
