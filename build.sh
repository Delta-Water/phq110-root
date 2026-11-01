#!/bin/sh
# build.sh -- self-contained rebuild of glx_p11n from ./src
#
# Requirements (Linux/WSL):
#   aarch64-linux-gnu-gcc   (Ubuntu: apt install gcc-aarch64-linux-gnu)
#   gcc, python3, sha256sum, cmp
#
# This script only reads ./src and writes ./build.  It does NOT touch a device.
# The full original gate suite (host UT / fork-delivery E2E / structural verify /
# stage3 constant diff) is described in BUILD.md; those test sources are not part
# of this delivery, so this script stops at "build + double-build identity +
# ELF contract + sha256".
set -e
cd "$(dirname "$0")"
mkdir -p build

CC=${CC:-aarch64-linux-gnu-gcc}

echo "== toolchain =="
command -v "$CC" || { echo "missing $CC (install gcc-aarch64-linux-gnu)"; exit 1; }
"$CC" --version | head -1
python3 --version

echo "== source fingerprints =="
sha256sum src/glx_p11n.c src/rootd_zd.c src/shz_launch.c src/shz_launch.h \
          src/dtable.h src/qtable.h src/shz_env_snapshot.h | tee build/src.sha256

echo "== embedded rootd object (rename main -> rootd_main) =="
"$CC" -static -O2 -Dmain=rootd_main -c src/rootd_zd.c -o build/rootd_zd_main.o

echo "== glx_p11n (build twice) =="
"$CC" -static -O2 -pthread -o build/glx_p11n \
      src/glx_p11n.c src/shz_launch.c build/rootd_zd_main.o
"$CC" -static -O2 -pthread -o build/glx_p11n.rebuild \
      src/glx_p11n.c src/shz_launch.c build/rootd_zd_main.o

if cmp -s build/glx_p11n build/glx_p11n.rebuild; then
    echo "GLX_P11N_REBUILD_IDENTICAL"
else
    echo "GLX_P11N_REBUILD_DIFF (different toolchain/flags => expected mismatch; see BUILD.md)"
fi

echo "== ELF contract (ET_EXEC / AArch64 / static) =="
python3 - build/glx_p11n <<'PY'
import struct, sys
p = sys.argv[1]
d = open(p, "rb").read()
assert d[:4] == b"\x7fELF", "not ELF"
(e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
 e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
 e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", d, 16)
kinds = []
for i in range(e_phnum):
    off = e_phoff + i * e_phentsize
    p_type = struct.unpack_from("<I", d, off)[0]
    kinds.append(p_type)
print("e_type=%#x e_machine=%#x e_entry=%#x e_phnum=%d" % (e_type, e_machine, e_entry, e_phnum))
assert e_type == 2, "must be ET_EXEC"
assert e_machine == 0xB7, "must be AArch64"
assert 3 not in kinds, "PT_INTERP must be absent (static)"
assert 2 not in kinds, "PT_DYNAMIC must be absent (static)"
print("ELF_CONTRACT=PASS (ET_EXEC AArch64, no PT_INTERP/PT_DYNAMIC)")
PY

echo "== fingerprints =="
sha256sum build/glx_p11n build/glx_p11n.rebuild | tee build/artifact.sha256
stat -c '%n %s' build/glx_p11n | tee build/artifact.size
echo "== BUILD DONE =="
