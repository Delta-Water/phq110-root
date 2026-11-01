#!/usr/bin/env python3
# termux_uid0.py -- Termux-side client for the uid0 rootd that glx_p11m forks.
#
# i771 (intent 771).  It is the *file/TCP compatible* sibling of the legacy
# i51x uaclient (which speaks ONLY an abstract-unix SO_PEERCRED socket and
# rejects rootd_zd's 'G' banner -- see ALIGNMENT_i771.md).  It speaks the exact
# wire format of i766/src/rootd_zd.c (glx_p11m Phase B):
#
#   TCP   : "ZD1 <hex-secret>\n"  ->  "OK\n"   then frames
#   FILE  : req  = "ZD1F <hex-secret> <reqid>\n" + u32(len(frame)) + frame
#           resp = "ZD1R <reqid> <status> <len>\n" + body
#   frame : request  = u8 type | u32 le len | payload
#           response = u8 status(0 ok / 1 err / 4 denied) | u32 le len | payload
#   types : G probe, I id, R path\0, X argv\0...\0\0, F argv..+stdin,
#           P argv..+pty stdin, Q quit
#
# Subcommands:
#   selftest                 G / I / R(entropy) / X / F4k / P / reconnect
#   id                       'I' only
#   read PATH                'R', raw bytes to stdout (or --out FILE)
#   sh CMD                   'X' /system/bin/sh -c CMD
#   exec ARGV...             'X' ARGV...
#   repl                     one uid0 shell line per input line ('!quit')
#
# Exit codes: 0 PASS, 1 FAIL, 2 usage, 3 secret/config, 4 connect/auth,
#             5 gate mismatch (wrong server / not uid0).
#
# Security note: on Android 127.0.0.1 is NOT a trust boundary.  The TCP and
# file channels are protected ONLY by the >=32-byte shared secret in a 0600
# file owned by Termux.  Never move it to a world-readable path.
import argparse
import errno
import os
import socket
import struct
import sys
import time

ST_OK, ST_ERR, ST_DENY = 0, 1, 4
SECRET_MIN = 32
DEFAULT_SECRET = os.path.expanduser("~/zd_secret")
DEFAULT_DIR = os.path.expanduser("~/zd_chan")
DEFAULT_TAG = "glx10"
DEFAULT_REQ = os.path.join(DEFAULT_DIR, "zd.%s.req" % DEFAULT_TAG)
DEFAULT_RESP = os.path.join(DEFAULT_DIR, "zd.%s.resp" % DEFAULT_TAG)
DEFAULT_ENTROPY = "/data/system/entropy.dat"


def log(msg):
    # Diagnostics go to stderr so `read`/`sh`/`exec`/`repl` keep stdout
    # byte-clean (scripts capture the payload, not our chatter).
    sys.stderr.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), msg))
    sys.stderr.flush()


def die(code, msg):
    log("FAIL: %s" % msg)
    sys.exit(code)


def read_secret(path):
    """Return raw secret bytes.  Accepts 64+ hex chars or >=32 raw bytes,
    exactly like rootd_zd secret_from_text()."""
    try:
        with open(path, "rb") as f:
            raw = f.read(256).strip()
    except OSError as e:
        die(3, "cannot read secret %s (%s)" % (path, e))
    if len(raw) >= 2 * SECRET_MIN and len(raw) % 2 == 0:
        try:
            dec = bytes.fromhex(raw.decode("ascii"))
            if len(dec) >= SECRET_MIN:
                return dec
        except (ValueError, UnicodeDecodeError):
            pass
    if len(raw) >= SECRET_MIN:
        return raw
    die(3, "secret %s too short (%d bytes, need >=%d)" % (path, len(raw), SECRET_MIN))


def recvn(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            raise EOFError("timeout after %d/%d bytes" % (len(buf), n))
        if not chunk:
            raise EOFError("peer closed after %d/%d bytes" % (len(buf), n))
        buf += chunk
    return buf


def frame(t, payload=b""):
    return bytes([t]) + struct.pack("<I", len(payload)) + payload


def parse_reply(hdr, body):
    st = hdr[0]
    (n,) = struct.unpack("<I", hdr[1:5])
    return st, body[:n]


def argv_block(argv, data=b""):
    return b"".join(a.encode() + b"\0" for a in argv) + b"\0" + data


class Chan:
    """Common frame RPC over an established, authenticated connection."""

    name = "?"

    def _read_reply(self):
        hdr = self._read_exact(5)
        (n,) = struct.unpack("<I", hdr[1:5])
        body = self._read_exact(n) if n else b""
        return hdr[0], body

    def _read_exact(self, n):
        raise NotImplementedError

    def _write(self, data):
        raise NotImplementedError

    def rpc(self, t, payload=b""):
        self._write(frame(t, payload))
        return self._read_reply()

    def gate(self, expect_uid, require_zd=True):
        st, body = self.rpc(ord("G"))
        txt = (body or b"").decode("utf-8", "replace")
        log("GATE|%s|status=%r|%s" % (self.name, st, txt[:300]))
        if st != 0:
            return False, "gate probe status=%r" % (st,)
        if require_zd and not txt.startswith("ROOTD_ZD_V1|"):
            return False, "not a glx rootd_zd banner: %r" % txt[:120]
        tok = [x for x in txt.replace("|", " ").split() if x.startswith("srv_uid=")]
        if tok:
            try:
                su = int(tok[0].split("=", 1)[1])
            except ValueError:
                su = -1
            if su != expect_uid:
                return False, "srv_uid=%d want %d" % (su, expect_uid)
        return True, txt

    def identify(self, expect_uid):
        st, body = self.rpc(ord("I"))
        txt = (body or b"").decode("utf-8", "replace")
        log("IDENT|%s|status=%r|%s" % (self.name, st, txt[:300]))
        ok = st == ST_OK and ("uid=%d " % expect_uid) in txt
        return ok, txt

    def close(self, quiet=True):
        try:
            self.rpc(ord("Q"))
        except Exception:
            pass


class TcpChan(Chan):
    name = "tcp"

    def __init__(self, host, port, secret, timeout, deadline=None):
        deadline = deadline if deadline is not None else time.time() + timeout
        last = None
        while True:
            try:
                self.sock = socket.create_connection((host, int(port)), timeout)
                break
            except OSError as e:
                last = e
                if time.time() >= deadline:
                    raise IOError("connect %s:%s failed after wait: %s"
                                  % (host, port, last))
                time.sleep(0.1)
        self.sock.settimeout(timeout)
        self.sock.sendall(b"ZD1 " + secret.hex().encode() + b"\n")
        first = recvn(self.sock, 1)
        if first == b"O":
            if recvn(self.sock, 2) != b"K\n":
                raise IOError("bad auth greeting")
        elif first == bytes([ST_DENY]):
            recvn(self.sock, 4)
            raise PermissionError("daemon denied the secret (status=4)")
        else:
            raise IOError("unexpected auth byte %r" % first)

    def _read_exact(self, n):
        return recvn(self.sock, n)

    def _write(self, data):
        self.sock.sendall(data)

    def close(self, quiet=True):
        super().close(quiet)
        try:
            self.sock.close()
        except OSError:
            pass


class UnixChan(Chan):
    """Legacy abstract-unix channel.  Only useful with a rootd that has the
    connectto policy row; glx_p11m's default is NOT this channel."""
    name = "unix"

    def __init__(self, sockname, timeout=5.0):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect("\0" + sockname)

    def _read_exact(self, n):
        return recvn(self.sock, n)

    def _write(self, data):
        self.sock.sendall(data)

    def close(self, quiet=True):
        super().close(quiet)
        try:
            self.sock.close()
        except OSError:
            pass


class FileChan(Chan):
    """Request/response files created by rootd_zd --listen=file.

    The daemon owns the files (0666 req / 0644 resp); Termux can read/write
    them because the *directory* is Termux-owned and traversal is by DAC, not
    by file ownership.  The security boundary is the in-band secret plus the
    random request id.

    i771 improvement over i552s/ua27one.py: the request is published with an
    atomic os.replace() of a fully-written temp file.  A direct write into the
    live req file can be renamed away mid-write by the daemon and silently
    lose the request; atomic publish removes that partial-write window.
    """
    name = "file"

    def __init__(self, req, resp, secret, timeout=60.0, poll=0.05):
        self.req = req
        self.resp = resp
        self.secret = secret
        self.timeout = timeout
        self.poll = poll
        self.reqid = int.from_bytes(os.urandom(4), "little") or 1
        self.wtmp = "%s.w%d" % (req, os.getpid())

    def _wait_empty_req(self, deadline):
        """Wait until the daemon has (re)created an empty req file.  Publishing
        into a non-empty req (or into the gap where make_req_file() is about to
        O_TRUNC it) loses the request."""
        while time.time() < deadline:
            try:
                if os.path.getsize(self.req) == 0:
                    return True
            except OSError:
                pass
            time.sleep(self.poll)
        return False

    def _publish(self, blob, deadline):
        if not self._wait_empty_req(deadline):
            raise IOError("req file %s never became empty (daemon dead or busy)"
                          % self.req)
        with open(self.wtmp, "wb", buffering=0) as f:
            f.write(blob)
            os.fsync(f.fileno())
        try:
            os.chmod(self.wtmp, 0o666)   # cross-uid DAC, same as the daemon's req
        except OSError:
            pass
        os.replace(self.wtmp, self.req)

    def rpc(self, t, payload=b""):
        reqid = self.reqid
        self.reqid += 1
        fr = frame(t, payload)
        hdr = ("ZD1F %s %u\n" % (self.secret.hex(), reqid)).encode()
        blob = hdr + struct.pack("<I", len(fr)) + fr
        deadline = time.time() + self.timeout
        self._publish(blob, deadline)
        prefix = ("ZD1R %u " % reqid).encode()
        while time.time() < deadline:
            try:
                with open(self.resp, "rb") as f:
                    data = f.read()
            except OSError:
                data = b""
            if data.startswith(prefix):
                nl = data.find(b"\n")
                if nl < 0:
                    raise IOError("bad response header")
                parts = data[:nl].split()
                st = int(parts[2])
                n = int(parts[3])
                body = data[nl + 1:nl + 1 + n]
                return st, body
            time.sleep(self.poll)
        raise IOError("timeout waiting for %s (reqid=%u)" % (self.resp, reqid))

    def close(self, quiet=True):
        try:
            super().close(quiet)
        except Exception:
            pass


def make_chan(a):
    deadline = time.time() + max(a.timeout, a.wait)
    if a.chan == "tcp":
        if not a.port:
            die(2, "--chan=tcp needs --port=N (the port printed by glx)")
        secret = read_secret(a.secret_file)
        return TcpChan(a.host, a.port, secret, a.timeout, deadline)
    if a.chan == "file":
        req = a.req or os.path.join(a.dir, "zd.%s.req" % a.tag)
        resp = a.resp or os.path.join(a.dir, "zd.%s.resp" % a.tag)
        secret = read_secret(a.secret_file)
        return FileChan(req, resp, secret, max(a.timeout, a.wait))
    # legacy unix: client-side uid self-gate first (fail-closed)
    allow = [int(x) for x in a.allow_uid.split(",") if x.strip()]
    if not allow or os.getuid() not in allow:
        die(3, "unix channel: own uid=%d not in allow-list %r (fail-closed)"
            % (os.getuid(), allow))
    return UnixChan(a.name, 5.0)


def open_checked(a):
    ch = make_chan(a)
    ok, why = ch.gate(a.expect_uid, require_zd=(a.chan != "unix"))
    if not ok:
        ch.close(quiet=True)
        die(5, "gate mismatch: %s" % why)
    ok, ident = ch.identify(a.expect_uid)
    if not ok:
        ch.close(quiet=True)
        die(5, "identity is not uid=%d: %s" % (a.expect_uid, ident))
    return ch


def cmd_selftest(a):
    fails = 0
    ch = open_checked(a)

    def one(tag, t, payload, check):
        nonlocal fails
        try:
            st, body = ch.rpc(t, payload)
        except Exception as e:
            log("RES|%s|FAIL|channel error: %s" % (tag, e))
            fails += 1
            return None
        ok = st == ST_OK and (check is None or check(body))
        log("RES|%s|%s|status=%d|%r" % (tag, "PASS" if ok else "FAIL", st,
                                       (body or b"")[:160]))
        if not ok:
            fails += 1
        return body

    one("id", ord("I"), b"",
        lambda b: ("uid=%d " % a.expect_uid).encode() in b)
    one("vr_read_0600", ord("R"), (a.vr + "\0").encode(), lambda b: len(b) > 0)
    one("exec_shell", ord("X"),
        argv_block([a.sh, "-c", "echo hello-root"]),
        lambda b: b"hello-root" in b)
    big = bytes((ord("A") + (i % 26)) for i in range(4096))
    one("pipe_4k", ord("F"), argv_block([a.sh, "-c", "cat"], big),
        lambda b: b[:4096] == big)
    if not a.no_pty:
        ptyin = b"id\necho pty-ok\nexit\n"
        one("pty", ord("P"), argv_block([a.sh], ptyin),
            lambda b: (("uid=%d" % a.expect_uid).encode() in b) and (b"pty-ok" in b))
    ch.close(quiet=True)
    if not a.no_reconnect:
        try:
            ch2 = open_checked(a)
            ok, ident = ch2.identify(a.expect_uid)
            log("RES|reconnect|%s|%s" % ("PASS" if ok else "FAIL", ident[:160]))
            if not ok:
                fails += 1
            ch2.close(quiet=True)
        except SystemExit:
            raise
        except Exception as e:
            log("RES|reconnect|FAIL|%s" % e)
            fails += 1
    log("SUMMARY|%s|fails=%d" % ("PASS" if fails == 0 else "FAIL", fails))
    return 0 if fails == 0 else 1


def cmd_id(a):
    ch = open_checked(a)
    st, body = ch.rpc(ord("I"))
    sys.stdout.write((body or b"").decode("utf-8", "replace") + "\n")
    ch.close(quiet=True)
    return 0 if st == ST_OK else 1


def cmd_read(a):
    ch = open_checked(a)
    st, body = ch.rpc(ord("R"), (a.path + "\0").encode())
    if st != ST_OK:
        log("READ|%s|FAIL|status=%d|%r" % (a.path, st, (body or b"")[:160]))
        ch.close(quiet=True)
        return 1
    if a.out:
        with open(a.out, "wb") as f:
            f.write(body or b"")
        log("READ|%s|PASS|bytes=%d|out=%s" % (a.path, len(body or b""), a.out))
    else:
        sys.stdout.buffer.write(body or b"")
        sys.stdout.buffer.flush()
    ch.close(quiet=True)
    return 0


def cmd_exec(a, argv):
    ch = open_checked(a)
    st, body = ch.rpc(ord("X"), argv_block(argv))
    sys.stdout.write((body or b"").decode("utf-8", "replace"))
    sys.stdout.flush()
    ch.close(quiet=True)
    return 0 if st == ST_OK else 1


def cmd_repl(a):
    ch = open_checked(a)
    log("REPL: uid0 shell over chan=%s; one line = /system/bin/sh -c LINE; "
        "'!quit' exits" % a.chan)
    while True:
        try:
            line = input("uid0# ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if line.strip() in ("!quit", "exit", "quit", ":q"):
            break
        if not line.strip():
            continue
        try:
            st, body = ch.rpc(ord("X"), argv_block([a.sh, "-c", line]))
        except Exception as e:
            log("REPL|channel error: %s" % e)
            return 1
        sys.stdout.write((body or b"").decode("utf-8", "replace"))
        sys.stdout.flush()
        if st != ST_OK:
            log("REPL|status=%d" % st)
    ch.close(quiet=True)
    return 0


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--chan", choices=["file", "tcp", "unix"], default="file")
    ap.add_argument("--secret-file", default=DEFAULT_SECRET)
    ap.add_argument("--dir", default=DEFAULT_DIR)
    ap.add_argument("--tag", default=DEFAULT_TAG)
    ap.add_argument("--req")
    ap.add_argument("--resp")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int)
    ap.add_argument("--name", default="i51d_rootd", help="unix abstract name")
    ap.add_argument("--allow-uid", default="10369", help="unix client self-gate")
    ap.add_argument("--expect-uid", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--wait", type=float, default=0.0,
                    help="keep retrying the FIRST connect for up to N seconds "
                         "(i771: glx's zd_spawn_verify kills the daemon 10s "
                         "after LISTENING unless a client request lands first; "
                         "start this before glx with --wait=120)")
    ap.add_argument("--sh", default="/system/bin/sh")
    ap.add_argument("--vr", default=DEFAULT_ENTROPY)
    ap.add_argument("--out")
    ap.add_argument("--no-pty", action="store_true")
    ap.add_argument("--no-reconnect", action="store_true")
    ap.add_argument("cmd", nargs="?", default="selftest",
                    choices=["selftest", "id", "read", "sh", "exec", "repl", "wait"])
    ap.add_argument("rest", nargs=argparse.REMAINDER)
    a = ap.parse_args()

    log("termux_uid0 start cmd=%s chan=%s uid=%d ctx=%s py=%s" %
        (a.cmd, a.chan, os.getuid(), self_ctx(), sys.version.split()[0]))
    if a.cmd == "selftest":
        return cmd_selftest(a)
    if a.cmd == "id":
        return cmd_id(a)
    if a.cmd == "wait":
        # pre-connect rescue / readiness probe: keeps retrying until the daemon
        # answers, then prints the identity.  Its first authenticated request is
        # what makes glx's zd_spawn_verify see an ALLOW line and keep the daemon.
        log("WAIT|chan=%s|up to %.0fs" % (a.chan, max(a.timeout, a.wait)))
        return cmd_id(a)
    if a.cmd == "read":
        if not a.rest:
            die(2, "read needs PATH")
        a.path = a.rest[0]
        return cmd_read(a)
    if a.cmd == "sh":
        if not a.rest:
            die(2, "sh needs CMD")
        return cmd_exec(a, [a.sh, "-c", " ".join(a.rest)])
    if a.cmd == "exec":
        if not a.rest:
            die(2, "exec needs ARGV")
        return cmd_exec(a, a.rest)
    return cmd_repl(a)


def self_ctx():
    try:
        with open("/proc/self/attr/current") as f:
            return f.read().strip()
    except OSError:
        return "?"


if __name__ == "__main__":
    sys.exit(main())
