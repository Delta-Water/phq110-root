/* shz_launch.h -- intent 703 (i553b)
 *
 * Stage 3 of goal 223: from the already-uid0 / u:r:shell:s0 process produced
 * by glx_p11 (SETIDS), fork+exec /system/bin/app_process with the INIT
 * environment so rikka.shizuku.server.ShizukuService (shizuku_server) runs as
 * uid 0 and can hand privileged binders to supported apps.
 *
 * Exit codes are the Shizuku starter contract (i262 §2.1 / i51e RUNBOOK §4.3):
 *   0 ok | 3 env/setenv failure | 4 fork failure | 5 execvp(app_process)
 *   failure | 6 real uid not 0/2000 | 7 apk path missing/unreadable |
 *   9 kill(old shizuku_server) EPERM | 10 SELinux self-check (untrusted_app ->
 *   self, binder call/transfer) denied | 11 post-launch verification failed.
 */
#ifndef SHZ_LAUNCH_H
#define SHZ_LAUNCH_H

#include <stddef.h>
#include <sys/types.h>

#define SHZ_EXIT_OK       0
#define SHZ_EXIT_ENV      3
#define SHZ_EXIT_FORK     4
#define SHZ_EXIT_EXEC     5
#define SHZ_EXIT_UID      6
#define SHZ_EXIT_APK      7
#define SHZ_EXIT_KILL     9
#define SHZ_EXIT_SELINUX 10
#define SHZ_EXIT_VERIFY  11

#define SHZ_MODE_APPPROCESS 0   /* exec /system/bin/app_process directly      */
#define SHZ_MODE_STARTER    1   /* exec <apkdir>/lib/arm64/libshizuku.so       */
#define SHZ_MODE_AUTO       2   /* starter if libshizuku.so is readable        */

struct shz_opts {
    const char *apk;          /* --shz-apk: base.apk; NULL = auto-discover   */
    const char *lib;          /* --shz-lib: libshizuku.so (starter mode)     */
    int   mode;               /* SHZ_MODE_*                                  */
    const char *app_process;  /* default /system/bin/app_process             */
    const char *env_file;     /* --shz-env-file: NUL or "export K V" file    */
    int   keep_old;           /* do not SIGKILL a pre-existing server        */
    int   wait_ms;            /* wait for a quick child exit (starter: 4000) */
    int   check_only;         /* no fork: verify an existing shizuku_server  */
    int   uid_gate_exempt;    /* UT only: skip the getuid()==0||2000 gate     */
};

/* Build the init environment (returns a NULL-terminated, malloc'ed vector).
 * Always succeeds unless the resulting BOOTCLASSPATH is empty/invalid. */
int shz_build_env(const struct shz_opts *o, const char *apk,
                  char ***outv, char *why, size_t wn);

/* Full launch: resolve apk -> SELinux gate -> kill old -> fork/exec -> verify. */
int shz_run(const struct shz_opts *o, char *log, size_t logn, char *why, size_t wn);

/* Verify only (no fork, no writes). */
int shz_check(char *log, size_t logn, char *why, size_t wn);

/* Locate a live shizuku_server (comm == "shizuku_server"). */
pid_t shz_find_server(void);

#endif
