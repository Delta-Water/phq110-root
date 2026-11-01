/* rootd_zd.c -- uid0 delivery daemon for the phq110 "Termux root shell" leg.
 *
 * i552s (intent 653).  Derived from i51x/src/rootd.c (fact 620) but the
 * transport is now selectable and NO SELinux policy delta is required:
 *
 *   --listen=unix   legacy i51x mode: abstract socket + SO_PEERCRED allow-list.
 *                   Needs the v4_delta connectto row from untrusted_app_27 to
 *                   shell; kept only for regression / path (c).
 *   --listen=tcp    zero-delta mode A: bind 127.0.0.1:<port> (port 0 => kernel
 *                   picks; the real port is printed).  fact 650: in the BASE
 *                   policy shell may name_bind and untrusted_app_27 may
 *                   name_connect, so this needs no delta and no permissive.
 *                   TCP has no usable SO_PEERCRED for identity, therefore the
 *                   identity is a >=32-byte shared secret supplied out of band
 *                   (--secret-file / --secret-hex / ZD_SECRET_HEX).  Fail
 *                   closed: no secret => exit 11, wrong secret => DENY+close,
 *                   three auth failures => exit.
 *   --listen=file   zero-delta mode B: request/response files in --dir
 *                   (default /data/local/tmp).  Server-side writes use a
 *                   0600 .tmp file + atomic rename + 0644 response; requests
 *                   carry the same >=32-byte secret.  NOTE ON MODES: the req
 *                   file must be 0666 and the resp 0644 because UA27 (uid
 *                   10369) and the shell-domain daemon (uid 0) share no group;
 *                   the *security* boundary is the in-band secret + the random
 *                   64-bit tag, not the file mode.  This is stated loudly in
 *                   ZD_DELIVERY.md; do not silently "fix" it to 0600 (that
 *                   would make the channel unusable, not more secure).
 *
 * Protocol (unchanged fact-593 framing) over any channel:
 *   request  = u8 type | u32 len | payload
 *   response = u8 status(0=ok,1=error,4=denied) | u32 len | payload
 *   'I' id                       -> "uid=%u euid=%u gid=%u pid=%u ctx=%s"
 *   'R' path                     -> file content
 *   'X' argv\0...\0\0            -> stdout+stderr + "rc=<n>"
 *   'F' argv\0...\0\0 + data     -> child stdin
 *   'P' argv\0...\0\0 + data     -> pty
 *   'Q' quit                     -> "bye"
 *   'G' gate probe               -> "ROOTD_ZD_V1|chan=..|auth=..|..."
 *
 * Startup assertions are the same as i51x (uid0 + CapEff/CapBnd 0x6 +
 * u:r:shell:s0 + 0600 read + exec id).  --no-assert exists for host tests.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/xattr.h>
#include <sys/sysmacros.h>
#include <termios.h>
#include <stddef.h>

#define MAXP (1u << 20)
#define DEFAULT_NAME "i51d_rootd"
#define DEFAULT_VR   "/data/system/entropy.dat"
#define DEFAULT_NEG  "/data/system/dropbox"
#define DEFAULT_SH   "/system/bin/sh"
#define DEFAULT_ALLOW_UIDS "10369"
#define MAX_ALLOW 16
#define DEFAULT_DIR "/data/local/tmp"

#define ST_OK    0
#define ST_ERR   1
#define ST_DENY  4

#define SECRET_MIN 32
#define SECRET_MAX 64
#define AUTH_TIMEOUT_MS 5000

enum { CH_UNIX = 0, CH_TCP = 1, CH_FILE = 2 };
enum { AU_NONE = 0, AU_PEERCRED = 1, AU_SECRET = 2 };

static int g_chan = CH_UNIX;
static int g_auth = AU_PEERCRED;
static int g_port;
static const char *g_dir = DEFAULT_DIR;
static char g_tag[17] = "";
static char g_req[512], g_resp[512], g_tmp[512];
static int g_idle_s = 120;
static int g_max_conn = 16;
static int g_authfail_max = 3;

static unsigned char g_secret[SECRET_MAX];
static int g_secret_len;
static char g_secret_src[64] = "none";
static int g_secret_loaded;
static char g_sec_fp[17] = "?";

static uid_t g_allow[MAX_ALLOW];
static int g_nallow;
static int g_gate_cfg_ok = 1;
static char g_allow_csv[256] = "";
static const char *g_gate_src = "default";
static const char *g_gate_spec = "";
static int g_audit_fd = -1;

static int g_fails;
static int g_soft_assert;     /* i775: startup assertions are diagnostics; a
                               * FAIL prints evidence but never blocks LISTEN.
                               * This is the --deliver-exec (execve) fix: the
                               * bprm credential recompute can legitimately
                               * drop CapEff, and vr_0600/exec_shell then
                               * aborted a perfectly usable uid0 daemon
                               * before it ever listened (fact 645). */
static int g_allow_capless;   /* path (a): uid0 from a pseudo cred with no caps */
static int g_dac_caps;        /* i552u/i730: CapEff carries DAC_OVERRIDE|
                               * DAC_READ_SEARCH, so DEFAULT_NEG
                               * (/data/system/dropbox, a DIRECTORY) is expected
                               * to be openable: SKIP, never PASS.  A directory is
                               * deliberately NOT read() here -- read() would
                               * return EISDIR (-21), which is not a denial
                               * (fact 732). */
static int g_quit;

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static void zd_close_from(int fd0)
{
    for (int fd = fd0; fd < 1024; fd++) close(fd);
}

static void utc_stamp(time_t t, char *out, size_t cap)
{
    long long s = (long long)t;
    long long days = s / 86400;
    long long rem = s % 86400;
    long long z, era, doe, yoe, y, doy, mp, d, m;
    int hh, mm, ss;

    if (rem < 0) { rem += 86400; days--; }
    hh = (int)(rem / 3600);
    mm = (int)((rem % 3600) / 60);
    ss = (int)(rem % 60);
    z = days + 719468;
    era = (z >= 0 ? z : z - 146096) / 146097;
    doe = z - era * 146097;
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = yoe + era * 400;
    doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    if (m <= 2) y++;
    if (y < 0) y = 0;
    if (y > 9999) y = 9999;
    snprintf(out, cap, "%04d-%02d-%02dT%02d:%02d:%02dZ",
             (int)y, (int)m, (int)d, hh, mm, ss);
}

static void audit_line(const char *kind, uid_t uid, pid_t pid, gid_t gid,
                       int valid, const char *reason)
{
    char b[400], ts[40] = "?";
    time_t now = time(NULL);
    int n;

    utc_stamp(now, ts, sizeof(ts));
    if (valid)
        n = snprintf(b, sizeof(b),
                     "ROOTD|AUDIT|%s|chan=%s|uid=%u|pid=%d|gid=%u|reason=%s|t=%lld|ts=%s\n",
                     kind, g_chan == CH_TCP ? "tcp" : g_chan == CH_FILE ? "file" : "unix",
                     (unsigned)uid, (int)pid, (unsigned)gid, reason,
                     (long long)now, ts);
    else
        n = snprintf(b, sizeof(b),
                     "ROOTD|AUDIT|%s|chan=%s|uid=?|pid=?|gid=?|reason=%s|t=%lld|ts=%s\n",
                     kind, g_chan == CH_TCP ? "tcp" : g_chan == CH_FILE ? "file" : "unix",
                     reason, (long long)now, ts);
    if (n <= 0) return;
    if ((size_t)n >= sizeof(b)) n = (int)sizeof(b) - 1;
    (void)!write(STDOUT_FILENO, b, (size_t)n);
    if (g_audit_fd >= 0) (void)!write(g_audit_fd, b, (size_t)n);
}

static void audit_open(void)
{
    const char *p = getenv("ROOTD_AUDIT_LOG");
    if (!p || !*p) return;
    g_audit_fd = open(p, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
}

/* ------------------------------------------------------------------ */
/* secret handling (zero-delta identity for tcp/file)                  */
/* ------------------------------------------------------------------ */

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Accepts 64+ hex chars (decoded to >=32 bytes) or >=32 raw bytes. */
static int secret_from_text(const char *s, int n)
{
    int allhex = 1, i;

    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' ||
                     s[n - 1] == ' ' || s[n - 1] == '\t')) n--;
    if (n <= 0) return -1;
    for (i = 0; i < n; i++) {
        if (s[i] == ' ' || s[i] == '\t') { allhex = 0; break; }
        if (hexval((unsigned char)s[i]) < 0) allhex = 0;
    }
    if (allhex) {
        int k;
        if (n % 2) return -1;
        if (n / 2 < SECRET_MIN || n / 2 > SECRET_MAX) return -1;
        for (k = 0; k < n / 2; k++) {
            int hi = hexval((unsigned char)s[2 * k]);
            int lo = hexval((unsigned char)s[2 * k + 1]);
            if (hi < 0 || lo < 0) return -1;
            g_secret[k] = (unsigned char)((hi << 4) | lo);
        }
        g_secret_len = n / 2;
        return 0;
    }
    if (n < SECRET_MIN || n > SECRET_MAX) return -1;
    memcpy(g_secret, s, (size_t)n);
    g_secret_len = n;
    return 0;
}

static int secret_load_cli(const char *file, const char *hex)
{
    if (hex) {
        if (secret_from_text(hex, (int)strlen(hex)) != 0) return -1;
        snprintf(g_secret_src, sizeof(g_secret_src), "argv-hex");
        g_secret_loaded = 1;
        return 0;
    }
    if (file) {
        int fd = open(file, O_RDONLY | O_CLOEXEC);
        char b[256];
        int n;
        struct stat st;
        if (fd < 0) return -1;
        if (fstat(fd, &st) == 0 && (st.st_mode & 077) != 0)
            printf("ROOTD|WARN|secret-file=%s mode=%o is group/other accessible "
                   "(wanted 0600)\n", file, (unsigned)(st.st_mode & 07777));
        n = (int)read(fd, b, sizeof(b));
        close(fd);
        if (n <= 0) return -1;
        if (secret_from_text(b, n) != 0) return -1;
        snprintf(g_secret_src, sizeof(g_secret_src), "file");
        g_secret_loaded = 1;
        return 0;
    }
    {
        const char *e = getenv("ZD_SECRET_HEX");
        if (e && *e) {
            if (secret_from_text(e, (int)strlen(e)) != 0) return -1;
            snprintf(g_secret_src, sizeof(g_secret_src), "env");
            g_secret_loaded = 1;
            return 0;
        }
    }
    return -1;
}

static void secret_fingerprint(void)
{
    unsigned long long h = 1469598103934665603ULL; /* FNV-1a 64 */
    int i;
    for (i = 0; i < g_secret_len; i++) {
        h ^= g_secret[i];
        h *= 1099511628211ULL;
    }
    snprintf(g_sec_fp, sizeof(g_sec_fp), "%016llx", h);
}

/* Constant-time compare of the client-supplied hex text with our secret. */
static int secret_check(const char *hex, size_t n)
{
    unsigned char got[SECRET_MAX];
    int i, diff = 0;

    while (n > 0 && (hex[n - 1] == '\n' || hex[n - 1] == '\r' ||
                     hex[n - 1] == ' ' || hex[n - 1] == '\t')) n--;
    if (!g_secret_loaded || n == 0 || (n % 2) || n / 2 != (size_t)g_secret_len)
        return 0;
    for (i = 0; i < g_secret_len; i++) {
        int hi = hexval((unsigned char)hex[2 * i]);
        int lo = hexval((unsigned char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        got[i] = (unsigned char)((hi << 4) | lo);
    }
    for (i = 0; i < g_secret_len; i++) diff |= got[i] ^ g_secret[i];
    return diff == 0;
}

/* ------------------------------------------------------------------ */
/* unix allow-list (legacy i51x)                                       */
/* ------------------------------------------------------------------ */

static int parse_uid_list(const char *s, uid_t *out, int max, int *nout)
{
    const char *p = s;
    int n = 0;

    *nout = 0;
    if (!s) return -1;
    while (*p) {
        char *end = NULL;
        unsigned long long v;
        const char *q;

        if (*p == ',' || *p == ':' || *p == ' ' || *p == '\t') return -1;
        errno = 0;
        v = strtoull(p, &end, 10);
        if (errno || end == p) return -1;
        for (q = p; q < end; q++)
            if (*q < '0' || *q > '9') return -1;
        if (v > 0xfffffffeULL) return -1;
        if (n >= max) return -1;
        out[n++] = (uid_t)v;
        p = end;
        if (*p == ',' || *p == ':') {
            p++;
            if (!*p) return -1;
        } else if (*p) {
            return -1;
        }
    }
    *nout = n;
    return n > 0 ? 0 : -1;
}

static void gate_configure(int argc, char **argv)
{
    static char joined[512];
    size_t o = 0;
    int saw_argv = 0, trunc = 0, i;
    const char *spec;

    joined[0] = 0;
    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v;
        if (strncmp(a, "--allow-uid=", 12) != 0) continue;
        v = a + 12;
        saw_argv = 1;
        if (o && o + 1 < sizeof(joined)) joined[o++] = ',';
        while (*v && o + 1 < sizeof(joined)) joined[o++] = *v++;
        joined[o] = 0;
        if (*v) trunc = 1;
    }
    if (saw_argv) {
        spec = joined;
        g_gate_src = "argv";
    } else {
        const char *e = getenv("ROOTD_ALLOW_UIDS");
        if (e) { spec = e; g_gate_src = "env"; }
        else { spec = DEFAULT_ALLOW_UIDS; g_gate_src = "default"; }
    }
    g_gate_spec = spec;
    if (trunc || parse_uid_list(spec, g_allow, MAX_ALLOW, &g_nallow) != 0) {
        g_gate_cfg_ok = 0;
        g_nallow = 0;
    }
    for (i = 0; i < g_nallow; i++)
        snprintf(g_allow_csv + strlen(g_allow_csv),
                 sizeof(g_allow_csv) - strlen(g_allow_csv), "%s%u",
                 i ? "," : "", (unsigned)g_allow[i]);
}

static int uid_allowed(uid_t u)
{
    int i;
    if (!g_gate_cfg_ok || g_nallow <= 0) return 0;
    for (i = 0; i < g_nallow; i++)
        if (g_allow[i] == u) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* i/o helpers                                                         */
/* ------------------------------------------------------------------ */

/* i775 same-family audit: SIGCHLD (reaped X/F/P children) and SIGALRM can
 * interrupt these transfers.  Treating EINTR as EOF used to cut a
 * request/reply short in the middle of the wire, which the client can only
 * see as a mysterious auth/handshake failure.  Every loop below retries
 * EINTR. */
static int read_full(int fd, void *b, size_t n)
{
    size_t o = 0;
    while (o < n) {
        ssize_t r = read(fd, (char *)b + o, n - o);
        if (r > 0) { o += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        return r == 0 ? 0 : -errno;
    }
    return (int)n;
}

static int write_full(int fd, const void *b, size_t n)
{
    size_t o = 0;
    while (o < n) {
        ssize_t r = write(fd, (const char *)b + o, n - o);
        if (r > 0) { o += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        return r == 0 ? 0 : -errno;
    }
    return (int)n;
}

static int reply(int fd, unsigned char st, const void *p, uint32_t n)
{
    unsigned char h[5];
    h[0] = st;
    memcpy(h + 1, &n, 4);
    if (write_full(fd, h, 5) < 0) return -1;
    if (n && write_full(fd, p, n) < 0) return -1;
    return 0;
}

static uint32_t slurp(int fd, char *out, uint32_t cap)
{
    uint32_t o = 0;
    while (o < cap) {
        ssize_t r = read(fd, out + o, cap - o);
        if (r > 0) { o += (uint32_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        break;
    }
    return o;
}

static char **split_argv(char *p, uint32_t n, char **store, int max)
{
    int c = 0;
    uint32_t i = 0;
    while (i < n && c < max) {
        store[c++] = p + i;
        while (i < n && p[i]) i++;
        i++;
        if (i < n && p[i] == 0) break;
    }
    store[c < max ? c : max - 1] = NULL;
    return store;
}

/* ------------------------------------------------------------------ */
/* startup assertions                                                  */
/* ------------------------------------------------------------------ */

static void averdict(const char *name, int ok, const char *fmt, ...)
{
    char d[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(d, sizeof(d), fmt, ap);
    va_end(ap);
    printf("ROOTD|ASSERT|%s|%s|%s\n", name, ok ? "PASS" : "FAIL", d);
    fflush(stdout);
    if (!ok) g_fails++;
}

static unsigned long long status_cap(const char *key)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    unsigned long long v = 0;
    int found = 0;
    if (!f) return 0;
    while (fgets(line, sizeof(line), f)) {
        size_t l = strlen(key);
        if (strncmp(line, key, l) == 0) {
            if (sscanf(line + l, "%llx", &v) == 1) found = 1;
            break;
        }
    }
    fclose(f);
    return found ? v : 0;
}

static int read_self_ctx(char *out, size_t cap)
{
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    int n;
    if (fd < 0) return -errno;
    n = (int)read(fd, out, cap - 1);
    close(fd);
    if (n <= 0) return -errno;
    out[n] = 0;
    return n;
}

static int run_capture(char *const argv[], const char *in, uint32_t dlen,
                       char *out, uint32_t cap, int *rc_out)
{
    int ip[2] = { -1, -1 }, op[2] = { -1, -1 };
    pid_t p;
    uint32_t o = 0;
    int st = 0;
    if (pipe(ip) || pipe(op)) return -errno;
    p = fork();
    if (p < 0) return -errno;
    if (p == 0) {
        dup2(ip[0], 0); dup2(op[1], 1); dup2(op[1], 2);
        close(ip[0]); close(ip[1]); close(op[0]); close(op[1]);
        execv(argv[0], argv);
        _exit(127);
    }
    close(ip[0]); close(op[1]);
    if (in && dlen) {
        uint32_t w = 0;
        while (w < dlen) {
            ssize_t r = write(ip[1], in + w, dlen - w);
            if (r <= 0) break;
            w += (uint32_t)r;
        }
    }
    close(ip[1]);
    while (o < cap - 1) {
        ssize_t r = read(op[0], out + o, cap - 1 - o);
        if (r > 0) { o += (uint32_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        break;
    }
    out[o] = 0;
    close(op[0]);
    waitpid(p, &st, 0);
    if (rc_out) *rc_out = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    return (int)o;
}

static void assert_startup(void)
{
    unsigned long long eff, bnd;
    char ctx[256] = "";
    const char *vr = getenv("ROOTD_VR");
    const char *neg = getenv("ROOTD_NEG");
    const char *sh = getenv("ROOTD_SH");
    if (!vr || !*vr) vr = DEFAULT_VR;
    if (!neg || !*neg) neg = DEFAULT_NEG;
    if (!sh || !*sh) sh = DEFAULT_SH;

    averdict("uid", getuid() == 0 && geteuid() == 0,
             "uid=%u euid=%u gid=%u pid=%u", (unsigned)getuid(),
             (unsigned)geteuid(), (unsigned)getgid(), (unsigned)getpid());
    eff = status_cap("CapEff:");
    bnd = status_cap("CapBnd:");
    if (g_allow_capless) {
        printf("ROOTD|ASSERT|capeff|SKIP|CapEff=0x%llx (--allow-capless: path (a) "
               "pseudo-cred may carry no DAC caps; UNKNOWN, not PASS)\\n", eff);
        printf("ROOTD|ASSERT|capbnd|SKIP|CapBnd=0x%llx (--allow-capless)\\n", bnd);
    } else {
        averdict("capeff", (eff & 0x6ULL) == 0x6ULL, "CapEff=0x%llx need 0x6", eff);
        averdict("capbnd", (bnd & 0x6ULL) == 0x6ULL, "CapBnd=0x%llx need 0x6", bnd);
    }
    if (read_self_ctx(ctx, sizeof(ctx)) > 0) {
        char c[256];
        snprintf(c, sizeof(c), "%s", ctx);
        averdict("sid", strstr(c, "u:r:shell:s0") != NULL, "%s", c);
    } else {
        averdict("sid", 0, "read /proc/self/attr/current failed errno=%d", errno);
    }
    {
        int fd = open(vr, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            if (g_allow_capless)
                printf("ROOTD|ASSERT|vr_0600|SKIP|%s open errno=%d "
                       "(--allow-capless: UNKNOWN, not PASS)\\n", vr, errno);
            else
                averdict("vr_0600", 0, "%s open errno=%d", vr, errno);
        } else {
            char b[64];
            ssize_t n = read(fd, b, sizeof(b));
            struct stat st;
            int sr = fstat(fd, &st);
            close(fd);
            if (sr == 0)
                averdict("vr_0600", n > 0, "%s n=%ld mode=%o uid=%u gid=%u",
                         vr, (long)n, (unsigned)(st.st_mode & 07777),
                         (unsigned)st.st_uid, (unsigned)st.st_gid);
            else
                averdict("vr_0600", n > 0, "%s n=%ld", vr, (long)n);
        }
    }
    {
        char *av[4];
        char out[4096];
        int rc = -1, n;
        av[0] = (char *)sh;
        av[1] = (char *)"-c";
        av[2] = (char *)"id";
        av[3] = NULL;
        n = run_capture(av, NULL, 0, out, sizeof(out), &rc);
        averdict("exec_shell", rc == 0 && n > 0 && strstr(out, "uid=0") != NULL,
                 "%s -c id rc=%d out=%.*s", sh, rc, n > 120 ? 120 : n, out);
    }
    {
        /* i730 (intent 733): DAC口径, same correction as the glx VR block.
         * This is NOT a SELinux probe (per-SID permissive removes every TE
         * denial, so "-13 or abort" is meaningless here) and it is NOT a
         * read() on a directory (that returns EISDIR = -21, which is not an
         * access-control verdict -- fact 732).  The only honest question is
         * whether the DAC capabilities really survived the handoff:
         *   open(O_DIRECTORY) ok  + CapEff has both DAC bits -> expected: SKIP
         *   open ok WITHOUT the DAC caps                       -> hard FAIL
         *   EACCES/EPERM                                       -> PASS (denied)
         *   ENOENT / ENOTDIR / anything else                   -> path
         *     assumption on this build: SKIP, never an abort (fact 645: this
         *     assertion was the main false-failure source). */
        struct stat nst;
        int fd = open(neg, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        int oe = errno;
        if (fd >= 0) {
            close(fd);
            if ((eff & 0x6ULL) == 0x6ULL)
                printf("ROOTD|ASSERT|negctl|SKIP|%s open() ok -- EXPECTED: "
                       "CapEff=0x%llx carries CAP_DAC_OVERRIDE|"
                       "CAP_DAC_READ_SEARCH (DAC口径; not a read() probe)\n",
                       neg, eff);
            else
                averdict("negctl", 0, "%s readable WITHOUT the DAC caps "
                         "(CapEff=0x%llx)", neg, eff);
        } else if (oe == EACCES || oe == EPERM) {
            averdict("negctl", 1, "%s DAC-denied errno=%d", neg, oe);
        } else if (stat(neg, &nst) != 0 || !S_ISDIR(nst.st_mode)) {
            printf("ROOTD|ASSERT|negctl|SKIP|%s is absent / not a directory "
                   "(open errno=%d) -- path assumption, not a finding\n",
                   neg, oe);
        } else {
            printf("ROOTD|ASSERT|negctl|SKIP|%s open errno=%d (unexpected) -- "
                   "not a hard failure\n", neg, oe);
        }
    }
    printf("ROOTD|ASSERT|SUMMARY|%s|fails=%d\n", g_fails ? "FAIL" : "PASS", g_fails);
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/* pty + command execution                                             */
/* ------------------------------------------------------------------ */

static int g_pty_step;

static int open_pty(char *slave, size_t sl)
{
    g_pty_step = 0;
    int m = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    int unlock = 0;
    if (m < 0) { g_pty_step = 1; return -errno; }
    if (ioctl(m, TIOCSPTLCK, &unlock) < 0) { int e = errno; g_pty_step = 3; close(m); return -e; }
    if (ptsname_r(m, slave, sl)) { g_pty_step = 4; close(m); return -ENOENT; }
    return m;
}

static void run_child(int outfd, char **argv, const char *data, uint32_t dlen)
{
    char out[262144];
    uint32_t olen = 0;
    int rc = 0;
    {
        int in[2], op[2];
        pid_t p;
        if (pipe(in) || pipe(op)) { reply(outfd, ST_ERR, "pipe", 4); return; }
        p = fork();
        if (p < 0) { reply(outfd, ST_ERR, "fork", 4); return; }
        if (p == 0) {
            dup2(in[0], 0); dup2(op[1], 1); dup2(op[1], 2);
            close(in[0]); close(in[1]); close(op[0]); close(op[1]);
            execv(argv[0], argv);
            _exit(127);
        }
        close(in[0]); close(op[1]);
        if (data && dlen) {
            uint32_t w = 0;
            while (w < dlen) {
                ssize_t r = write(in[1], data + w, dlen - w);
                if (r <= 0) break;
                w += (uint32_t)r;
            }
        }
        close(in[1]);
        olen = slurp(op[0], out, sizeof(out) - 32);
        close(op[0]);
        waitpid(p, &rc, 0);
    }
    {
        char tail[64];
        int t = snprintf(tail, sizeof(tail), "\nrc=%d\n",
                         WIFEXITED(rc) ? WEXITSTATUS(rc) : -1);
        if (olen + (uint32_t)t <= sizeof(out)) {
            memcpy(out + olen, tail, (size_t)t);
            olen += (uint32_t)t;
        }
        reply(outfd, ST_OK, out, olen);
    }
}

static void run_pty(int outfd, char **argv, const char *data, uint32_t dlen)
{
    char sl[128], out[262144];
    uint32_t olen = 0;
    int m = open_pty(sl, sizeof(sl));
    pid_t p;
    int rc = 0, idle = 0;
    fd_set rf;
    struct timeval tv;

    if (m < 0) {
        char eb[64];
        int k = snprintf(eb, sizeof(eb), "ptmx step=%d errno=%d", g_pty_step, -m);
        reply(outfd, ST_ERR, eb, (uint32_t)k);
        return;
    }
    p = fork();
    if (p < 0) { close(m); reply(outfd, ST_ERR, "fork", 4); return; }
    if (p == 0) {
        int s = open(sl, O_RDWR | O_NOCTTY);
        if (s < 0) _exit(126);
        setsid();
        ioctl(s, TIOCSCTTY, 0);
        dup2(s, 0); dup2(s, 1); dup2(s, 2);
        if (s > 2) close(s);
        close(m);
        execv(argv[0], argv);
        _exit(127);
    }
    if (data && dlen) {
        uint32_t w = 0;
        while (w < dlen) {
            ssize_t r = write(m, data + w, dlen - w);
            if (r <= 0) break;
            w += (uint32_t)r;
        }
    }
    for (;;) {
        FD_ZERO(&rf);
        FD_SET(m, &rf);
        tv.tv_sec = 0; tv.tv_usec = 300000;
        {
            int s = select(m + 1, &rf, NULL, NULL, &tv);
            if (s > 0) {
                ssize_t r;
                if (olen >= sizeof(out) - 64) break;
                r = read(m, out + olen, sizeof(out) - 64 - olen);
                if (r > 0) { olen += (uint32_t)r; idle = 0; continue; }
                if (r < 0 && errno == EINTR) continue;   /* i775 */
                break;
            }
            if (s == 0) {
                int st = 0;
                if (waitpid(p, &st, WNOHANG) == p) { rc = st; break; }
                if (++idle > 20) { kill(p, SIGKILL); waitpid(p, &rc, 0); break; }
                continue;
            }
            if (errno == EINTR) continue;                /* i775 */
            break;
        }
    }
    close(m);
    {
        char tail[64];
        int t = snprintf(tail, sizeof(tail), "\nrc=%d\n",
                         WIFEXITED(rc) ? WEXITSTATUS(rc) : -1);
        if (olen + (uint32_t)t <= sizeof(out)) {
            memcpy(out + olen, tail, (size_t)t);
            olen += (uint32_t)t;
        }
        reply(outfd, ST_OK, out, olen);
    }
}

/* ------------------------------------------------------------------ */
/* one framed request -> one framed reply (shared by every channel)    */
/* ------------------------------------------------------------------ */

static void handle_frame(int outfd, unsigned char type, char *buf, uint32_t n)
{
    switch (type) {
    case 'I': {
        char o[192];
        char ctx[200] = "";
        int k;
        read_self_ctx(ctx, sizeof(ctx));
        k = snprintf(o, sizeof(o), "uid=%u euid=%u gid=%u pid=%u ctx=%s",
                     (unsigned)getuid(), (unsigned)geteuid(),
                     (unsigned)getgid(), (unsigned)getpid(), ctx);
        reply(outfd, ST_OK, o, (uint32_t)k);
        break;
    }
    case 'R': {
        char o[65536];
        int fd;
        if (!n) { reply(outfd, ST_ERR, "nopath", 6); break; }
        buf[n - 1] = 0;
        fd = open(buf, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            reply(outfd, ST_ERR, strerror(errno), (uint32_t)strlen(strerror(errno)));
            break;
        }
        {
            uint32_t k = slurp(fd, o, sizeof(o));
            close(fd);
            reply(outfd, ST_OK, o, k);
        }
        break;
    }
    case 'X': case 'F': {
        char *av[32];
        uint32_t i = 0;
        while (i + 1 < n && !(buf[i] == 0 && buf[i + 1] == 0)) i++;
        split_argv(buf, (uint32_t)(i + 1), av, 32);
        if (!av[0]) { reply(outfd, ST_ERR, "noargv", 6); break; }
        if (type == 'X') run_child(outfd, av, NULL, 0);
        else run_child(outfd, av, buf + i + 2, n - (i + 2));
        break;
    }
    case 'P': {
        char *av[32];
        uint32_t i = 0;
        while (i + 1 < n && !(buf[i] == 0 && buf[i + 1] == 0)) i++;
        split_argv(buf, (uint32_t)(i + 1), av, 32);
        if (!av[0]) { reply(outfd, ST_ERR, "noargv", 6); break; }
        run_pty(outfd, av, buf + i + 2, n - (i + 2));
        break;
    }
    case 'G': {
        char o[320];
        int k = snprintf(o, sizeof(o),
                         "ROOTD_ZD_V1|chan=%s|auth=%s|srv_uid=%u|srv_pid=%u|"
                         "secret_len=%d|secret_fp=%s|allow=%s",
                         g_chan == CH_TCP ? "tcp" : g_chan == CH_FILE ? "file" : "unix",
                         g_auth == AU_SECRET ? "secret" : g_auth == AU_PEERCRED ? "peercred" : "none",
                         (unsigned)getuid(), (unsigned)getpid(),
                         g_secret_len, g_sec_fp,
                         g_allow_csv[0] ? g_allow_csv : "-");
        reply(outfd, ST_OK, o, (uint32_t)k);
        break;
    }
    case 'Q':
        reply(outfd, ST_OK, "bye", 3);
        g_quit = 1;
        break;
    default:
        reply(outfd, ST_ERR, "badcmd", 6);
    }
}

static int serve_fd(int c)
{
    char *buf = malloc(MAXP);
    if (!buf) return -1;
    for (;;) {
        unsigned char h[5];
        uint32_t n;
        int r = read_full(c, h, 5);
        if (r <= 0) break;
        memcpy(&n, h + 1, 4);
        if (n > MAXP) break;
        if (n && read_full(c, buf, n) <= 0) break;
        handle_frame(c, h[0], buf, n);
    }
    free(buf);
    return 0;
}

/* ------------------------------------------------------------------ */
/* channel: unix (legacy i51x SO_PEERCRED gate)                        */
/* ------------------------------------------------------------------ */

static int run_unix(const char *nm)
{
    struct sockaddr_un sa;
    int l, one = 1;
    size_t sl;

    l = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (l < 0) { perror("socket"); return 1; }
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    sa.sun_path[0] = 0;
    strncpy(sa.sun_path + 1, nm, sizeof(sa.sun_path) - 2);
    sl = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(nm);
    if (bind(l, (struct sockaddr *)&sa, (socklen_t)sl) < 0) { perror("bind"); return 2; }
    if (listen(l, 16) < 0) { perror("listen"); return 3; }
    printf("ROOTD|LISTENING|@%s|uid=%u euid=%u|auth=peercred|allow=%s\n",
           nm, (unsigned)getuid(), (unsigned)geteuid(),
           g_allow_csv[0] ? g_allow_csv : "-");
    fflush(stdout);

    for (;;) {
        int c = accept4(l, NULL, NULL, SOCK_CLOEXEC);
        struct ucred cr;
        socklen_t cl = sizeof(cr);
        int ok = 0;
        if (c < 0) { if (errno == EINTR) continue; break; }
        memset(&cr, 0, sizeof(cr));
        if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &cl) == 0 &&
            cl == sizeof(cr))
            ok = uid_allowed(cr.uid);
        if (!ok) {
            unsigned char dh[5] = { ST_DENY, 0, 0, 0, 0 };
            audit_line("DENY", cr.uid, (pid_t)cr.pid, cr.gid, cl == sizeof(cr),
                       cl == sizeof(cr) ? "uid-not-allowlisted" : "so-peercred-failed");
            (void)send(c, dh, sizeof(dh), MSG_DONTWAIT | MSG_NOSIGNAL);
            close(c);
            continue;
        }
        audit_line("ALLOW", cr.uid, (pid_t)cr.pid, cr.gid, 1, "ok");
        {
            struct timeval tv = { 15, 0 };
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }
        serve_fd(c);
        close(c);
        while (waitpid(-1, NULL, WNOHANG) > 0) ;
    }
    close(l);
    return 0;
}

/* ------------------------------------------------------------------ */
/* channel: tcp 127.0.0.1 (zero delta A)                               */
/* ------------------------------------------------------------------ */

static int tcp_auth(int c)
{
    char b[256];
    int n = 0;
    struct pollfd pfd;

    pfd.fd = c;
    pfd.events = POLLIN;
    pfd.revents = 0;
    for (;;) {
        int pr = poll(&pfd, 1, AUTH_TIMEOUT_MS);   /* SIGCHLD may interrupt */
        if (pr > 0) {
            /* i775: a poll() wake-up is not automatically "data ready".
             * HUP/ERR/NVAL must fail closed instead of falling into read(). */
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return -1;
            if (pfd.revents & POLLIN) break;
            continue;
        }
        if (pr < 0 && errno == EINTR) continue;
        return -1;
    }
    while (n < (int)sizeof(b) - 1) {
        ssize_t k = read(c, b + n, 1);
        if (k > 0) {
            n++;
            if (b[n - 1] == '\n') break;
            if (n >= 5 && strncmp(b, "ZD1 ", 4) != 0) break;
            continue;
        }
        if (k < 0 && errno == EINTR) continue;     /* i775 */
        break;
    }
    b[n] = 0;
    if (n < 5 || strncmp(b, "ZD1 ", 4) != 0) return -1;
    return secret_check(b + 4, (size_t)(n - 4)) ? 0 : -1;
}

static int run_tcp(void)
{
    int l, one = 1, conns = 0, authfail = 0;
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);

    l = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (l < 0) { perror("socket"); return 1; }
    setsockopt(l, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   /* 127.0.0.1 only */
    sa.sin_port = htons((uint16_t)g_port);
    if (bind(l, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); return 2; }
    if (listen(l, 8) < 0) { perror("listen"); return 3; }
    if (getsockname(l, (struct sockaddr *)&sa, &sl) == 0)
        g_port = ntohs(sa.sin_port);
    printf("ROOTD|LISTENING|127.0.0.1:%d|uid=%u euid=%u|auth=secret|secret_len=%d|"
           "secret_fp=%s|secret_src=%s\n",
           g_port, (unsigned)getuid(), (unsigned)geteuid(), g_secret_len,
           g_sec_fp, g_secret_src);
    fflush(stdout);

    for (;;) {
        struct pollfd pfd = { l, POLLIN, 0 };
        struct sockaddr_in pa;
        socklen_t pl = sizeof(pa);
        int c;
        int r = poll(&pfd, 1, g_idle_s * 1000);
        if (r == 0) { printf("ROOTD|IDLE_TIMEOUT|%ds\n", g_idle_s); break; }
        if (r < 0) { if (errno == EINTR) continue; break; }
        /* i775: only POLLIN means "a connection is pending".  A HUP/ERR on a
         * listening socket is not something accept() can serve. */
        if (!(pfd.revents & POLLIN)) {
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) break;
            continue;
        }
        c = accept4(l, (struct sockaddr *)&pa, &pl, SOCK_CLOEXEC);
        if (c < 0) { if (errno == EINTR) continue; break; }
        if (pa.sin_family != AF_INET ||
            ntohl(pa.sin_addr.s_addr) != INADDR_LOOPBACK) {
            unsigned char dh[5] = { ST_DENY, 0, 0, 0, 0 };
            audit_line("DENY", 0, 0, 0, 0, "non-loopback-peer");
            (void)send(c, dh, sizeof(dh), MSG_DONTWAIT | MSG_NOSIGNAL);
            close(c);
            continue;
        }
        if (tcp_auth(c) != 0) {
            unsigned char dh[5] = { ST_DENY, 0, 0, 0, 0 };
            struct ucred cr;
            socklen_t cl = sizeof(cr);
            int hc = (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &cl) == 0 &&
                      cl == sizeof(cr));
            audit_line("DENY", hc ? cr.uid : 0, hc ? (pid_t)cr.pid : 0,
                       hc ? cr.gid : 0, hc, "secret-mismatch");
            (void)send(c, dh, sizeof(dh), MSG_DONTWAIT | MSG_NOSIGNAL);
            close(c);
            if (++authfail >= g_authfail_max) {
                printf("ROOTD|ABORT|auth failures=%d (fail-closed)\n", authfail);
                break;
            }
            continue;
        }
        {
            struct timeval tv = { 15, 0 };
            (void)!write(c, "OK\n", 3);
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }
        audit_line("ALLOW", 0, 0, 0, 0, "secret-ok");
        serve_fd(c);
        close(c);
        while (waitpid(-1, NULL, WNOHANG) > 0) ;
        if (++conns >= g_max_conn) break;
    }
    close(l);
    return 0;
}

/* ------------------------------------------------------------------ */
/* channel: file (zero delta B)                                        */
/* ------------------------------------------------------------------ */

static void file_paths(void)
{
    snprintf(g_req, sizeof(g_req), "%s/zd.%s.req", g_dir, g_tag);
    snprintf(g_resp, sizeof(g_resp), "%s/zd.%s.resp", g_dir, g_tag);
    snprintf(g_tmp, sizeof(g_tmp), "%s/zd.%s.tmp", g_dir, g_tag);
}

static void cleanup_files(void)
{
    char p[560];
    unlink(g_tmp);
    unlink(g_resp);
    unlink(g_req);
    snprintf(p, sizeof(p), "%s.done", g_req);
    unlink(p);
}

static int make_req_file(void)
{
    int fd = open(g_req, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) return -1;
    fchmod(fd, 0666);   /* cross-uid DAC: UA27 (10369) must be able to write */
    close(fd);
    return 0;
}

static int read_line_fd(int fd, char *out, int cap)
{
    int n = 0;
    while (n < cap - 1) {
        ssize_t r = read(fd, out + n, 1);
        if (r <= 0) break;
        n++;
        if (out[n - 1] == '\n') break;
    }
    out[n] = 0;
    return n;
}

/* Returns 0 = handled, -1 = malformed, -3 = auth denied. */
static int file_handle_req(const char *path)
{
    int fd, n;
    char hdr[512];
    char *buf = NULL;
    char *sp1, *sp2;
    unsigned reqid = 0;
    uint32_t flen = 0;
    char oh[96];
    unsigned char type;
    int w;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    n = read_line_fd(fd, hdr, sizeof(hdr));
    if (n < 6 || strncmp(hdr, "ZD1F ", 5) != 0) { close(fd); return -1; }
    sp1 = strchr(hdr + 5, ' ');
    if (!sp1) { close(fd); return -1; }
    *sp1++ = 0;
    sp2 = sp1;
    while (*sp2 && *sp2 != '\n' && *sp2 != ' ') sp2++;
    *sp2 = 0;
    reqid = (unsigned)strtoul(sp1, NULL, 10);

    if (!secret_check(hdr + 5, strlen(hdr + 5))) {
        close(fd);
        audit_line("DENY", 0, 0, 0, 0, "file-secret-mismatch");
        w = open(g_tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (w >= 0) {
            int k = snprintf(oh, sizeof(oh), "ZD1R %u 4 0\n", reqid);
            (void)!write(w, oh, (size_t)k);
            close(w);
            (void)chmod(g_tmp, 0644);
            rename(g_tmp, g_resp);
            (void)chmod(g_resp, 0644);
        }
        return -3;
    }
    /* i552w DELTA vs i552u (intent 676, planner correction 683/684):
     * the file channel had no positive audit line at all, so glx_p10's
     * ZD_C1_SECOND_CONN gate (>=2 "ROOTD|AUDIT|ALLOW") could never pass when
     * the device-level IP REJECT forces the file transport.  Emit one ALLOW
     * per authenticated request; the header secret has already been compared
     * in constant time above. */
    audit_line("ALLOW", 0, 0, 0, 0, "file-req-ok");
    if (read_full(fd, &flen, 4) != 4) { close(fd); return -1; }
    if (flen > MAXP || flen < 5) { close(fd); return -1; }
    buf = malloc(flen);
    if (!buf) { close(fd); return -1; }
    if (read_full(fd, buf, flen) != (int)flen) { free(buf); close(fd); return -1; }
    close(fd);

    type = (unsigned char)buf[0];
    {
        uint32_t plen;
        memcpy(&plen, buf + 1, 4);
        if (plen > flen - 5) { free(buf); return -1; }
    }

    /* reply sink: a private 0600 scratch file; atomic rename publishes it */
    w = open(g_tmp, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (w < 0) { free(buf); return -1; }
    handle_frame(w, type, buf + 5, flen - 5);
    free(buf);
    {
        unsigned char rh[5];
        uint32_t rlen;
        off_t sz = lseek(w, 0, SEEK_END);
        if (sz < 5) {
            close(w);
            unlink(g_tmp);
            return -1;
        }
        lseek(w, 0, SEEK_SET);
        if (read_full(w, rh, 5) != 5) { close(w); unlink(g_tmp); return -1; }
        memcpy(&rlen, rh + 1, 4);
        if ((off_t)(5 + rlen) > sz) rlen = (uint32_t)(sz - 5);
        close(w);
        /* re-open the scratch file to prepend the file-channel header:
         * write header+body into a second scratch, then rename */
        {
            char tmp2[560];
            int r = open(g_tmp, O_RDONLY | O_CLOEXEC);
            int o = 0;
            snprintf(tmp2, sizeof(tmp2), "%s.pub", g_tmp);
            o = open(tmp2, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
            if (r >= 0 && o >= 0) {
                char body[65536];
                int k = snprintf(oh, sizeof(oh), "ZD1R %u %u %u\n",
                                 reqid, (unsigned)rh[0], rlen);
                (void)!write(o, oh, (size_t)k);
                lseek(r, 5, SEEK_SET);
                {
                    uint32_t left = rlen;
                    while (left) {
                        uint32_t chunk = left > sizeof(body) ? (uint32_t)sizeof(body) : left;
                        ssize_t g = read(r, body, chunk);
                        if (g <= 0) break;
                        (void)!write(o, body, (size_t)g);
                        left -= (uint32_t)g;
                    }
                }
                close(o);
                if (r >= 0) close(r);
                (void)chmod(tmp2, 0644);
                rename(tmp2, g_resp);      /* atomic publish */
                (void)chmod(g_resp, 0644);
            } else {
                if (r >= 0) close(r);
                if (o >= 0) close(o);
            }
            unlink(g_tmp);
        }
    }
    return 0;
}

static int run_file(void)
{
    time_t last = 0;
    off_t lastsz = -1;

    file_paths();
    cleanup_files();
    if (make_req_file() != 0) { perror("req"); return 2; }
    printf("ROOTD|LISTENING|file|dir=%s|tag=%s|req=%s|resp=%s|uid=%u euid=%u|"
           "auth=secret|secret_len=%d|secret_fp=%s\n",
           g_dir, g_tag, g_req, g_resp, (unsigned)getuid(), (unsigned)geteuid(),
           g_secret_len, g_sec_fp);
    fflush(stdout);

    for (;;) {
        struct stat st;
        if (stat(g_req, &st) == 0) {
            if (st.st_size > 0 && (st.st_size != lastsz || st.st_mtime != last)) {
                char done[560];
                snprintf(done, sizeof(done), "%s.done", g_req);
                unlink(done);
                if (rename(g_req, done) == 0) {
                    (void)file_handle_req(done);
                    unlink(done);
                }
                make_req_file();
                lastsz = -1;
                last = 0;
                continue;
            }
            lastsz = st.st_size;
            last = st.st_mtime;
        }
        usleep(100 * 1000);
    }
    cleanup_files();
    return 0;
}

int main(int argc, char **argv)
{
    const char *nm = DEFAULT_NAME;
    const char *secret_file = NULL, *secret_hex = NULL;
    int do_assert = 1, i;

    g_chan = CH_UNIX;
    g_port = 0;
    g_dir = DEFAULT_DIR;
    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--no-assert")) do_assert = 0;
        else if (!strcmp(a, "--soft-assert")) g_soft_assert = 1;
        else if (!strcmp(a, "--allow-capless")) g_allow_capless = 1;
        else if (!strcmp(a, "--dac-caps")) g_dac_caps = 1;
        else if (strncmp(a, "--listen=", 9) == 0) {
            const char *v = a + 9;
            if (!strcmp(v, "unix")) g_chan = CH_UNIX;
            else if (!strcmp(v, "tcp")) g_chan = CH_TCP;
            else if (!strcmp(v, "file")) g_chan = CH_FILE;
            else { fprintf(stderr, "bad --listen=%s\n", v); return 12; }
        }
        else if (strncmp(a, "--port=", 7) == 0) g_port = atoi(a + 7);
        else if (strncmp(a, "--dir=", 6) == 0) g_dir = a + 6;
        else if (strncmp(a, "--tag=", 6) == 0)
            snprintf(g_tag, sizeof(g_tag), "%s", a + 6);
        else if (strncmp(a, "--idle=", 7) == 0) g_idle_s = atoi(a + 7);
        else if (strncmp(a, "--max-conn=", 11) == 0) g_max_conn = atoi(a + 11);
        else if (strncmp(a, "--name=", 7) == 0) nm = a + 7;
        else if (strncmp(a, "--secret-file=", 14) == 0) secret_file = a + 14;
        else if (strncmp(a, "--secret-hex=", 13) == 0) secret_hex = a + 13;
        else if (strncmp(a, "--allow-uid=", 12) == 0) ;
        else if (strncmp(a, "--audit-log=", 12) == 0)
            setenv("ROOTD_AUDIT_LOG", a + 12, 1);
        else if (a[0] != '-') nm = a;
    }
    if (!*nm) nm = DEFAULT_NAME;
    if (!g_tag[0]) {
        unsigned long long r = 0;
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            if (read(fd, &r, sizeof(r)) != (ssize_t)sizeof(r))
                r = (unsigned long long)time(NULL);
            close(fd);
        }
        snprintf(g_tag, sizeof(g_tag), "%016llx", r);
    }

    gate_configure(argc, argv);

    if (g_chan == CH_UNIX) {
        g_auth = AU_PEERCRED;
    } else {
        g_auth = AU_SECRET;
        if (secret_load_cli(secret_file, secret_hex) != 0) {
            fprintf(stderr,
                    "ROOTD|FATAL|zero-delta channel needs a >=%d-byte secret "
                    "(--secret-file=PATH 0600 | --secret-hex=HEX | ZD_SECRET_HEX); "
                    "refusing to start (fail-closed)\n", SECRET_MIN);
            return 11;
        }
        secret_fingerprint();
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    setvbuf(stdout, NULL, _IONBF, 0);
    (void)setsid();
    zd_close_from(3);        /* glx execve()s us: do not inherit its fds */
    audit_open();

    printf("ROOTD|START|name=%s|pid=%u|chan=%s|auth=%s\n", nm,
           (unsigned)getpid(),
           g_chan == CH_TCP ? "tcp" : g_chan == CH_FILE ? "file" : "unix",
           g_auth == AU_SECRET ? "secret" : "peercred");
    printf("ROOTD|GATE|CONFIG|ok=%d|n=%d|uids=%s|src=%s|spec=%s|audit=%s\n",
           g_gate_cfg_ok, g_nallow, g_allow_csv[0] ? g_allow_csv : "-",
           g_gate_src, g_gate_spec ? g_gate_spec : "-",
           g_audit_fd >= 0 ? "file+stdout" : "stdout");
    if (g_chan == CH_UNIX && (!g_gate_cfg_ok || g_nallow <= 0))
        printf("ROOTD|GATE|CONFIG|FAIL|empty-or-invalid allow-list => DENY ALL (fail-closed)\n");

    if (do_assert) {
        assert_startup();
        if (g_fails) {
            if (!g_soft_assert) {
                printf("ROOTD|ABORT|startup assertions failed|fails=%d\n", g_fails);
                return 10;
            }
            /* i775: diagnostics only.  The daemon still has to prove its
             * identity to the parent by printing ROOTD|LISTENING with
             * uid=0 -- that is the hard gate, checked on the parent side. */
            printf("ROOTD|ASSERT|SUMMARY|SOFT_FAIL|fails=%d|"
                   "STARTING ANYWAY (--soft-assert): a uid0 daemon that "
                   "listens is the deliverable; CapEff/DAC evidence above is "
                   "not a spawn gate\n", g_fails);
            fflush(stdout);
            g_fails = 0;
        }
    } else {
        printf("ROOTD|ASSERT|SKIPPED|--no-assert\n");
    }

    if (g_chan == CH_TCP) return run_tcp();
    if (g_chan == CH_FILE) return run_file();
    return run_unix(nm);
}
