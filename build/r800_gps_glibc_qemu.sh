#!/bin/sh
# Execute only trusted donor glibc in an isolated, unprivileged QEMU user-mode sandbox.
# Usage: r800_gps_glibc_qemu.sh <NDK r27c> <resolved donor library dir>
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 NDK-r27c donor-libdir" >&2; exit 2; }
[ "$(id -u)" -ne 0 ] || { echo "run as an unprivileged user" >&2; exit 2; }
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
NDK=$(CDPATH= cd -- "$1" && pwd)
SRC=$(CDPATH= cd -- "$2" && pwd)
grep -Eq '^Pkg.Revision[[:space:]]*=[[:space:]]*27\.2\.12479018$' "$NDK/source.properties"
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
QEMU=$(command -v qemu-arm-static) || { echo "BLOCKED: qemu-arm-static missing" >&2; exit 2; }
BWRAP=$(command -v bwrap) || { echo "BLOCKED: bubblewrap missing" >&2; exit 2; }
command -v timeout >/dev/null
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
trap 'exit 1' HUP INT TERM
mkdir -p "$TMP/root/lib" "$TMP/root/dev" "$TMP/root/proc"
: > "$TMP/root/qemu"
# Read bounded regular files, not guest symlinks. Use identical bytes for link and runtime.
python3 - "$ROOT" "$SRC" "$TMP/root/lib" <<'PY'
import hashlib, pathlib, sys
sys.path.insert(0,str(pathlib.Path(sys.argv[1])/"build"))
from r800_gps_link_gate import DONORS, LIMIT, elf
from r800_android_userspace_preflight import read_regular
src,dst=map(pathlib.Path,sys.argv[2:])
for name in DONORS:
    raw=read_regular(src/name,LIMIT)
    info=elf(raw)
    if info["soname"] != name:
        raise ValueError("unexpected SONAME: "+name)
    (dst/name).write_bytes(raw)
    print("DONOR_SHA256",name,hashlib.sha256(raw).hexdigest())
PY
(cd "$TMP/root/lib" && sha256sum libc.so.6 libdl.so.2 libpthread.so.0 ld-linux.so.3) > "$TMP/manifest"
"$TC/clang" --target=armv7a-linux-gnueabi -mfloat-abi=softfp -mfpu=vfpv3-d16 \
  -O2 --no-default-config -nostdinc -ffreestanding -fno-builtin -fno-stack-protector -fPIC -shared -nostdlib -fuse-ld=lld --ld-path="$TC/ld.lld" \
  -Wl,--hash-style=sysv,-z,noexecstack,--no-undefined \
  -o "$TMP/root/probe_plugin.so" "$ROOT/tests/r800_glibc_probe_plugin.c"
"$TC/clang" --target=armv7a-linux-gnueabi -mfloat-abi=softfp -mfpu=vfpv3-d16 \
  -O2 --no-default-config -nostdinc -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -no-pie -nostdlib -fuse-ld=lld --ld-path="$TC/ld.lld" \
  -Wl,--hash-style=sysv,-z,noexecstack,-z,now,--no-undefined \
  -Wl,--dynamic-linker=/lib/ld-linux.so.3,-e,_start \
  -o "$TMP/root/probe" "$ROOT/tests/r800_glibc_probe.c" \
  "$TMP/root/lib/libc.so.6" "$TMP/root/lib/libdl.so.2" "$TMP/root/lib/libpthread.so.0"
python3 "$ROOT/build/r800_gps_link_gate.py" --binary "$TMP/root/probe" --libdir "$TMP/root/lib"
(cd "$TMP/root/lib" && sha256sum -c "$TMP/manifest")
sha256sum "$TMP/root/probe" "$TMP/root/probe_plugin.so" "$QEMU"
# No host filesystem mounts, no network, no privilege escalation, no fallback.
# A dynamic host qemu binary cannot run in this isolated root.
# Explicit LD_LIBRARY_PATH in the guest avoids host library search.
timeout -k 5s 30s "$BWRAP" --unshare-all --die-with-parent --new-session \
  --clearenv --ro-bind "$TMP/root" / --ro-bind "$QEMU" /qemu \
  --dev /dev --proc /proc --chdir / \
  /qemu -cpu cortex-a15 -L / -E LD_LIBRARY_PATH=/lib /probe > "$TMP/run.log" 2>&1 || {
    cat "$TMP/run.log"; echo "QEMU_PROBE=FAILED_OR_SANDBOX_UNAVAILABLE" >&2; exit 1;
  }
cat "$TMP/run.log"
for marker in GLIBC_2_24 PTHREAD_TLS DLOPEN_DLSYM R800_GLIBC_QEMU_PROBE; do
    [ "$(grep -Fxc "$marker=PASS" "$TMP/run.log")" -eq 1 ]
done
(cd "$TMP/root/lib" && sha256sum -c "$TMP/manifest")
echo "QEMU_USER_ONLY=PASS"
echo "GNSS_RUNTIME_VERIFIED=false"
echo "safe_to_flash=false"
