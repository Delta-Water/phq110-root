#!/usr/bin/env bash
# termux_accept.sh -- i771: paste-and-run acceptance for the Termux-side uid0
# surface of goal 223.
#
# What it checks (nothing is deleted; the only write probe is one small file
# under /data/system that you may remove later with an explicitly authorized
# root step):
#   0. PRE-CONNECT (start this BEFORE glx!): glx_p11m's zd_spawn_verify has a
#      poll bug (fact 774) that SIGKILLs the daemon 10s after LISTENING unless a
#      client request lands first.  Default: block up to ZD_WAIT seconds on
#      TCP 127.0.0.1:10369 (fact 774 real-run shape); fall back to the file
#      channel if TCP never appears.  The first authenticated request is what
#      makes glx see ROOTD|AUDIT|ALLOW and keep the daemon alive.
#   1. Termux-side preconditions: uid, SECRET (0600, >=32B), CHANNEL DIR (0700),
#      python3, this directory's termux_uid0.py.
#   2. The uid0 daemon itself over the FILE channel (glx_p11m default):
#      G/I/R/X/F/P/reconnect selftest.
#   3. Real root evidence: `id` reports uid=0 and the daemon (in-process, with
#      CAP_DAC_* ) reads /data/system/entropy.dat (0600 system:system).
#   4. Capability tier of EXEC'd children (the crucial distinction):
#        CapEff & 0xC6 == 0xC6  -> AMBIENT tier (writable uid0 shell)
#        CapEff & 0xC6 == 0     -> FORK-ONLY tier (uid0 but no DAC caps)
#   5. Protected-path write through an exec'd child; PASS only in ambient tier.
#   6. Shizuku root-mode distribution via rish (A/B/C forms, see i675 §4).
#
# Usage (inside Termux):
#   chmod +x termux_accept.sh termux_uid0.py
#   ./termux_accept.sh                 # START BEFORE glx; waits for TCP 10369
#   ./termux_accept.sh --rootd-pid=26109   # GLX|DELIVER child_pid, to check PPid=1
#   ./termux_accept.sh --chan=file --wait=120
#   ./termux_accept.sh --skip-write --skip-rish     # if you only want 1..4
# Environment overrides: ZD_SECRET, ZD_DIR, ZD_TAG, ZD_CHAN, ZD_PORT, ZD_WAIT,
#   ZD_SURVIVE_WAIT, ZD_ROOTD_PID, EXPECT_UID, PYTHON, ZD_SH, ENTROPY, PROBE_DIR
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${PYTHON:-python3}"
ZD_SECRET="${ZD_SECRET:-$HOME/zd_secret}"
ZD_DIR="${ZD_DIR:-$HOME/zd_chan}"
ZD_TAG="${ZD_TAG:-glx10}"
EXPECT_UID="${EXPECT_UID:-0}"
ENTROPY="${ENTROPY:-/data/system/entropy.dat}"     # host tests may override
PROBE_DIR="${PROBE_DIR:-/data/system}"             # host tests may override
ZD_CHAN="${ZD_CHAN:-auto}"                         # auto|tcp|file
ZD_PORT="${ZD_PORT:-10369}"                        # fact 774: real run listened here
ZD_WAIT="${ZD_WAIT:-120}"                          # pre-connect rescue window
ZD_SURVIVE_WAIT="${ZD_SURVIVE_WAIT:-12}"           # > glx's 10s kill window
ZD_ROOTD_PID="${ZD_ROOTD_PID:-}"                   # GLX|DELIVER child_pid (optional)
ZD_SH="${ZD_SH:-/system/bin/sh}"                   # host tests may override
REQ="$ZD_DIR/zd.$ZD_TAG.req"
RESP="$ZD_DIR/zd.$ZD_TAG.resp"
TS="$(date +%s)"
LOG="${HOME}/i771_accept_${TS}.log"
SKIP_WRITE=0
SKIP_RISH=0
CREATE=1

for a in "$@"; do
  case "$a" in
    --skip-write) SKIP_WRITE=1 ;;
    --skip-rish)  SKIP_RISH=1 ;;
    --no-create-secret) CREATE=0 ;;
    --chan=*) ZD_CHAN="${a#*=}" ;;
    --port=*) ZD_PORT="${a#*=}" ;;
    --wait=*) ZD_WAIT="${a#*=}" ;;
    --survive-wait=*) ZD_SURVIVE_WAIT="${a#*=}" ;;
    --rootd-pid=*) ZD_ROOTD_PID="${a#*=}" ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "unknown option: $a"; exit 2 ;;
  esac
done

exec > >(tee -a "$LOG") 2>&1
PASS=0; FAIL=0; WARN=0
ok()   { PASS=$((PASS+1)); echo "ACCEPT|PASS|$*"; }
bad()  { FAIL=$((FAIL+1)); echo "ACCEPT|FAIL|$*"; }
warn() { WARN=$((WARN+1)); echo "ACCEPT|WARN|$*"; }
info() { echo "ACCEPT|INFO|$*"; }

echo "=== i771 Termux uid0 acceptance  $(date) ==="
info "log=$LOG HERE=$HERE HOME=$HOME uid=$(id -u) euid=$(id -u)"
info "secret=$ZD_SECRET dir=$ZD_DIR tag=$ZD_TAG expect_uid=$EXPECT_UID"

# ---------------------------------------------------------------- 1 preflight
[ -d "${PREFIX:-/nonexistent}" ] && info "PREFIX=$PREFIX (looks like Termux)" \
    || warn "no \$PREFIX: not Termux? the uid/paths below may not match"
U="$(id -u)"
case "$U" in
  ''|*[!0-9]*) bad "cannot read uid";;
  0) warn "you are uid0 right now (unusual for Termux)";;
  *) [ "$U" -ge 10000 ] && ok "Termux-like uid=$U" || warn "uid=$U (<10000): not the usual Termux uid 10369";;
esac
info "selinux ctx=$(tr -d '\000' < /proc/self/attr/current 2>/dev/null || echo '?')"

if [ ! -x "$PY" ] && ! command -v "$PY" >/dev/null 2>&1; then
  bad "python3 missing in Termux: run  pkg install python  (the client needs it)"
fi
if [ ! -f "$HERE/termux_uid0.py" ]; then
  bad "termux_uid0.py not next to this script ($HERE) -- copy it into Termux first"
fi

if [ ! -f "$ZD_SECRET" ]; then
  if [ "$CREATE" = 1 ] && command -v "$PY" >/dev/null 2>&1; then
    "$PY" - "$ZD_SECRET" <<'PY'
import os, sys
p = sys.argv[1]
with open(p, "x") as f:
    f.write(os.urandom(32).hex())
os.chmod(p, 0o600)
PY
    [ -f "$ZD_SECRET" ] && ok "created $ZD_SECRET (64 hex, 0600)" || bad "cannot create $ZD_SECRET"
  else
    bad "secret missing: $ZD_SECRET (create it before glx runs, or let glx provision uid10369)"
  fi
else
  ok "secret exists: $ZD_SECRET"
fi
if [ -f "$ZD_SECRET" ]; then
  SMODE="$(stat -c '%a %u %g %s' "$ZD_SECRET" 2>/dev/null || echo '?')"
  SSIZE="$(wc -c < "$ZD_SECRET" 2>/dev/null | tr -d ' ')"
  info "secret stat(mode uid gid size)=$SMODE bytes=$SSIZE"
  case "$SMODE" in
    600\ *) ok "secret mode is 0600";;
    *) bad "secret mode is not 0600 (other apps may read it): $SMODE";;
  esac
  if [ "${SSIZE:-0}" -lt 32 ]; then bad "secret too short (<32 bytes)"; else ok "secret length ok"; fi
fi

mkdir -p "$ZD_DIR" 2>/dev/null
chmod 700 "$ZD_DIR" 2>/dev/null
DMODE="$(stat -c '%a %u %g' "$ZD_DIR" 2>/dev/null || echo '?')"
info "channel dir stat(mode uid gid)=$DMODE"
case "$DMODE" in
  700\ *) ok "channel dir is 0700";;
  *) warn "channel dir mode is not 0700: $DMODE";;
esac

if [ ! -e "$REQ" ]; then
  info "file-channel req not present yet: $REQ (normal if the run uses TCP)"
else
  ok "file-channel req present: $REQ"
  [ -e "$RESP" ] || warn "response file not created yet: $RESP"
fi

# ------------------------------------------------ 1b channel + PRE-CONNECT rescue
# fact 774: glx_p11m's zd_spawn_verify has `if (poll(...) <= 0) continue;` before
# the break test, so after ROOTD|LISTENING (and no further daemon output) it
# times out and SIGKILLs the daemon at t0+10s.  The ONLY rescue is a client
# request inside that 10s window: rootd emits ROOTD|AUDIT|ALLOW, the parent's
# poll sees data, rc becomes 0, and the daemon survives (then PPid=1 after glx
# exits).  Therefore this script must be started BEFORE glx and block here.
CHAN="$ZD_CHAN"
PROBE="$HOME/.i771_probe"
if [ "$CHAN" = auto ]; then
  # If a file-channel req already exists, do not burn the whole ZD_WAIT on TCP
  # (the file daemon is the likely peer); still give TCP 2s so a mixed stale
  # req file cannot hide a live TCP daemon.
  WAIT_T="$ZD_WAIT"
  [ -e "$REQ" ] && WAIT_T=2
  echo "--- [1b] PRE-CONNECT TCP 127.0.0.1:${ZD_PORT} (up to ${WAIT_T}s; this is the 10s rescue) ---"
  if "$PY" "$HERE/termux_uid0.py" --chan=tcp --port="$ZD_PORT" \
       --secret-file="$ZD_SECRET" --expect-uid="$EXPECT_UID" \
       --wait="$WAIT_T" id >"$PROBE" 2>>"$LOG"; then
    CHAN=tcp
    ok "pre-connect TCP ${ZD_PORT}: $(tr -d '\000' < "$PROBE")"
  elif [ -e "$REQ" ]; then
    CHAN=file
    warn "TCP ${ZD_PORT} not reachable; falling back to file (req present)"
  else
    CHAN=none
    bad "neither TCP ${ZD_PORT} nor the file req is available"
    info "  => START THIS SCRIPT BEFORE glx (it blocks in --wait); a post-mortem run cannot"
    info "     rescue a daemon that glx already SIGKILLed at LISTENING+10s (fact 774)."
  fi
else
  ok "channel forced: $CHAN"
fi
if [ "$CHAN" = tcp ]; then
  ok "using TCP 127.0.0.1:${ZD_PORT} (fact 774 real-run shape)"
  CLIENT=( "$PY" "$HERE/termux_uid0.py" --chan=tcp --port="$ZD_PORT" \
           --secret-file="$ZD_SECRET" --expect-uid="$EXPECT_UID" \
           --sh="$ZD_SH" --vr="$ENTROPY" --timeout=60 )
elif [ "$CHAN" = file ]; then
  ok "using FILE channel ${ZD_DIR}/zd.${ZD_TAG}.{req,resp}"
  CLIENT=( "$PY" "$HERE/termux_uid0.py" --chan=file --dir="$ZD_DIR" --tag="$ZD_TAG" \
           --secret-file="$ZD_SECRET" --expect-uid="$EXPECT_UID" \
           --sh="$ZD_SH" --vr="$ENTROPY" --timeout=60 )
else
  CLIENT=( "$PY" "$HERE/termux_uid0.py" --chan=file --dir="$ZD_DIR" --tag="$ZD_TAG" \
           --secret-file="$ZD_SECRET" --expect-uid="$EXPECT_UID" \
           --sh="$ZD_SH" --vr="$ENTROPY" --timeout=10 )
fi

# ---------------------------------------------------------------- 2 selftest
echo "--- [2] rootd FILE-channel selftest (G/I/R/X/F/P/Q + reconnect) ---"
if "${CLIENT[@]}" selftest; then ok "rootd selftest"; else bad "rootd selftest (see lines above)"; fi

# ---------------------------------------------------------------- 3 real root
echo "--- [3] identity + 0600 protected READ through the daemon ---"
IDOUT="$("${CLIENT[@]}" id 2>>"$LOG")"
echo "$IDOUT"
case "$IDOUT" in
  *"uid=$EXPECT_UID "*) ok "daemon identity uid=$EXPECT_UID";;
  *) bad "daemon identity is not uid=$EXPECT_UID";;
esac

ENT="$ENTROPY"
OUT="$HOME/entropy.dat.out.$TS"
if "${CLIENT[@]}" --out "$OUT" read "$ENT"; then
  SZ="$(wc -c < "$OUT" 2>/dev/null | tr -d ' ')"
  SHA="$(sha256sum "$OUT" 2>/dev/null | cut -d' ' -f1)"
  info "entropy.dat bytes=$SZ sha256=$SHA (reference 512B / sha256=789a3e95…)"
  if [ "${SZ:-0}" -gt 0 ]; then ok "daemon read $ENT (DAC_READ_SEARCH path)"; else bad "entropy.dat read returned 0 bytes"; fi
else
  bad "daemon cannot read $ENT (VR assertion would also fail)"
fi

# ---------------------------------------------------------------- 4 cap tier
echo "--- [4] capability tier of EXEC'd children (ambient vs fork-only) ---"
CAPOUT="$("${CLIENT[@]}" sh 'id -u; grep -E "^(CapEff|CapAmb|CapBnd|CapPrm):" /proc/self/status' 2>>"$LOG")"
echo "$CAPOUT"
CHILD_UID="$(printf '%s\n' "$CAPOUT" | head -1 | tr -d '[:space:]')"
[ "$CHILD_UID" = "$EXPECT_UID" ] && ok "exec'd child uid=$EXPECT_UID" || bad "exec'd child uid='$CHILD_UID' (want $EXPECT_UID)"
CAPEFF="$(printf '%s\n' "$CAPOUT" | awk '/^CapEff:/{print $2; exit}')"
if [ -n "${CAPEFF:-}" ] && command -v "$PY" >/dev/null 2>&1; then
  TIER="$("$PY" - "$CAPEFF" <<'PY'
import sys
v = int(sys.argv[1], 16)
print("AMBIENT" if (v & 0xC6) == 0xC6 else "FORK_ONLY")
PY
)"
  info "CapEff=$CAPEFF tier=$TIER"
  case "$TIER" in
    AMBIENT) ok "children keep DAC caps (CapEff&0xC6==0xC6) -> writable uid0 shell";;
    FORK_ONLY) warn "children are uid0 but CapEff&0xC6==0: this is the --no-ambient fork-only tier (daemon R still works, exec'd writes do not)";;
  esac
fi

# ------------------------------------------------ 4b survival (goal 223 first half)
echo "--- [4b] rootd survival past glx's 10s kill window (goal 223 first half) ---"
if [ "$ZD_SURVIVE_WAIT" -gt 0 ] 2>/dev/null; then
  info "sleep ${ZD_SURVIVE_WAIT}s (> zd_spawn_verify's 10s window), then reconnect"
  sleep "$ZD_SURVIVE_WAIT"
  if "${CLIENT[@]}" id >/dev/null 2>>"$LOG"; then
    ok "rootd still reachable after ${ZD_SURVIVE_WAIT}s -> the pre-connect ALLOW rescued it; after glx exits PPid should be 1"
  else
    bad "rootd gone after ${ZD_SURVIVE_WAIT}s -> no client request landed inside 10s (fact 774 poll bug)"
  fi
fi
if [ -n "$ZD_ROOTD_PID" ]; then
  if [ -r "/proc/$ZD_ROOTD_PID/stat" ]; then
    PP="$(awk '{print $4}' "/proc/$ZD_ROOTD_PID/stat" 2>/dev/null)"
    info "rootd pid=$ZD_ROOTD_PID ppid=$PP (want 1 after glx exit)"
    [ "$PP" = "1" ] && ok "rootd PPid=1 (survived glx exit)" \
                    || warn "rootd ppid=$PP (glx may still be running; re-check after it exits)"
    grep -E '^(Uid|CapEff|CapAmb|CapBnd):' "/proc/$ZD_ROOTD_PID/status" 2>/dev/null \
      | while IFS= read -r l; do info "rootd $l"; done
  else
    warn "cannot read /proc/$ZD_ROOTD_PID from Termux (uid0); check from the host:"
  fi
fi
cat <<EOF
  Host-side confirmation of the SAME survival (adb shell is uid2000):
    adb shell 'ps -A -o USER,PID,PPID,NAME | grep -E "glx_p11m|shizuku_server"'
    adb shell 'grep -E "^(Uid|CapEff|CapAmb|CapBnd):" /proc/<child_pid>/status'
    adb shell 'cat /proc/<child_pid>/attr/current'      # expect u:r:shell:s0
  (readlink /proc/<child_pid>/exe may EACCES for uid2000; the GLX|DELIVER line
   already says exec=NO, which is the no-exec proof.)
EOF

# ---------------------------------------------------------------- 5 protected write
if [ "$SKIP_WRITE" = 0 ]; then
  echo "--- [5] protected-path WRITE (expected PASS only in AMBIENT tier) ---"
  P="$PROBE_DIR/zd_probe_$TS"
  WOUT="$("${CLIENT[@]}" sh "echo ZD_WRITE_$TS > $P 2>&1; r=\$?; stat -c '%U %G %a %s' $P 2>/dev/null; echo rc=\$r" 2>>"$LOG")"
  echo "$WOUT"
  case "$WOUT" in
    *rc=0*) ok "wrote $P ; leave it or remove later with an explicitly authorized root step";;
    *) warn "protected write failed (expected in FORK_ONLY tier; EACCES/SELinux). file may not exist";;
  esac
  if "${CLIENT[@]}" read "$P" >/dev/null 2>&1; then ok "daemon can read back $P"; else
    [ -e "$P" ] && warn "daemon could not read back $P" || info "no probe file created"
  fi
else
  info "protected-write test skipped (--skip-write)"
fi

# ---------------------------------------------------------------- 6 rish / Shizuku
if [ "$SKIP_RISH" = 0 ]; then
  echo "--- [6] Shizuku root-mode distribution (rish) ---"
  if ! command -v rish >/dev/null 2>&1; then
    warn "rish not in PATH: in Shizuku Manager use 'Use in terminal apps' -> Termux, or copy"
    warn "  the app's assets/rish + rish_shizuku.dex into a directory and export RISH_APPLICATION_ID=com.termux"
  else
    ok "rish found: $(command -v rish)"
    info "RISH_APPLICATION_ID=${RISH_APPLICATION_ID:-<unset>} (should be com.termux)"
    R1="$(rish -c 'id -u; id' 2>&1)"
    echo "$R1"
    case "$R1" in
      *"uid=0"*) ok "rish runs as uid=0 (Shizuku ROOT mode)";;
      *"uid=2000"*) bad "rish runs as uid=2000: Shizuku is in ADB/shell mode, not root mode";;
      *) bad "rish failed / no Shizuku server (see output above)";;
    esac
    R2="$(rish -c 'head -c16 /data/system/entropy.dat 2>/dev/null | wc -c' 2>&1 | tr -d '[:space:]')"
    info "rish entropy16=$R2 (16 => form B/C, 0 => form A / EACCES)"
    R3="$(rish -c 'head -c1 /proc/kallsyms >/dev/null 2>&1; echo rc=$?' 2>&1 | tr -d '[:space:]')"
    info "rish kallsyms $R3 (rc=0 => form C with permissive_map(shell), rc=1 => A/B)"
    R4="$(rish -c 'grep -E "^(CapEff|CapAmb):" /proc/self/status' 2>&1)"
    echo "$R4"
    case "$R2" in
      16) ok "Shizuku newProcess has DAC access (form B/C)";;
      0)  warn "Shizuku newProcess has no DAC caps (form A: server started without ambient?)";;
      *)  warn "unexpected rish entropy result: $R2";;
    esac
  fi
else
  info "rish test skipped (--skip-rish)"
fi

# ---------------------------------------------------------------- UI checklist
cat <<'EOF'
--- Shizuku Manager UI (manual, authoritative machine checks are above) ---
  1. Open moe.shizuku.privileged.api. The card should show RUNNING / 运行中,
     version 13.6.0, and uid 0 (root). Do NOT tap "Start via root" (that path
     uses `su`, which does not exist on this device).
  2. If the card says "not running" but `ps -A | grep shizuku_server` shows a
     uid-0 process: the binder was not re-delivered. Run:
        am force-stop moe.shizuku.privileged.api
     then open it again (server re-sends the binder).
  3. Authorized apps: the list should keep bin.mt.plus (uid 10355) and
     com.farplace.qingzhuo (uid 10464). For Termux, tap Allow when the rish
     authorization dialog appears (first run).
  4. Success is NOT "Manager says root"; success is:
        rish -c 'id -u'                          -> 0
        rish -c 'head -c16 /data/system/entropy.dat | wc -c' -> 16  (B/C)
     and, for this chain, `rish -c 'head -c1 /proc/kallsyms'` -> rc=0 (form C).
EOF

# ---------------------------------------------------------------- summary
echo "=== ACCEPT|SUMMARY|PASS=$PASS FAIL=$FAIL WARN=$WARN log=$LOG ==="
echo "ACCEPT|INFO|goal 223 第一句 = [2] selftest + [3] uid0/0600 read + [4b] survival；"
echo "ACCEPT|INFO|即使 [6] Shizuku/rish 失败，只要 [2][3][4b] PASS，Termux 内 uid0 使用面即成立。"
echo "ACCEPT|INFO|TCP rootd 空闲 300s 会退出（glx 硬编码 --idle=300）：长期使用请每 60s 发一次"
echo "ACCEPT|INFO|  termux_uid0.py --chan=tcp --port=${ZD_PORT} --secret-file=\"$ZD_SECRET\" id ，或接受退出/panic 后冷启动。"
if [ "$FAIL" -ne 0 ]; then
  cat <<'EOF'
--- Fallback tiers (choose in this order) ---
A. If only the Termux client failed: prove the daemon side from adb (read-only) and
   localise the failure to Termux DAC/SELinux. NOTE: adb shell is uid2000, so it
   cannot read Termux's 0700 home and cannot kill the uid0 daemon -- use `ps` and
   `/proc` only:
     adb shell 'ps -A -o USER,PID,PPID,NAME | grep -E "glx|rootd|shizuku"'
     adb shell 'grep -E "^(Uid|CapEff|CapAmb|CapBnd):" /proc/<child_pid>/status'
     adb shell 'cat /proc/<child_pid>/attr/current'
   If glx was run with `--zd=tcp --zd-port=45271 --zd-client-selftest`, look for
   GLX|ZDCL|SELFTEST|PASS (in-process 10369 client; note: shell domain, not
   untrusted_app_27, so it only narrows the failure -- it is not a Termux proof).
B. On a FRESH boot, re-run glx with `--stop-after=deliver-fork` (keep ambient, i.e.
   do NOT add --no-ambient) AND start this script FIRST with
       ./termux_accept.sh --wait=120
   so its first request lands inside glx's 10s window (fact 774). This isolates
   Phase B from stage 3 and restores the writable-shell capability tier.
C. Stop and report: quote the last GLX|DELIVER / ROOTD| / ACCEPT| lines and the
   exact client output. Do not retry the same boot twice (fact 677).
EOF
  exit 1
fi
exit 0
