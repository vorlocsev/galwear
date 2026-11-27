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
"$TC/clang" --target=armv7a-linux-gnueabi -marm -mfloat-abi=softfp -mfpu=vfpv3-d16 \
  -O2 --no-default-config -nostdinc -ffreestanding -fno-builtin -fno-stack-protector -fPIC -shared -nostdlib -fuse-ld=lld --ld-path="$TC/ld.lld" \
  -Wl,--build-id=none,--hash-style=sysv,-z,noexecstack,--no-undefined \
  -o "$TMP/root/probe_plugin.so" "$ROOT/tests/r800_glibc_probe_plugin.c"
python3 "$ROOT/build/r800_gps_probe_plugin.py" "$TMP/root/probe_plugin.so"
# ARMv7 has the user-mode thread pointer register. Require actual TLS
# relocations and avoid relying on an unverified donor __aeabi_read_tp.
"$TC/clang" --target=armv7a-linux-gnueabi -marm -mfloat-abi=softfp -mfpu=vfpv3-d16 -mtp=cp15 -ftls-model=local-exec \
  -O2 --no-default-config -nostdinc -ffreestanding -fno-builtin -fno-stack-protector -fno-pic -fno-pie \
  -Wall -Wextra -Werror -c "$ROOT/tests/r800_glibc_probe.c" -o "$TMP/probe.o"
sh "$ROOT/build/r800_gps_probe_tls_object.sh" "$TC/llvm-readelf" "$TMP/probe.o"
"$TC/clang" --target=armv7a-linux-gnueabi -marm -mfloat-abi=softfp -mfpu=vfpv3-d16 \
  --no-default-config -nostdlib -no-pie -fuse-ld=lld --ld-path="$TC/ld.lld" \
  -Wl,--hash-style=sysv,-z,noexecstack,-z,now,--no-undefined \
  -Wl,--dynamic-linker=/lib/ld-linux.so.3,-e,_start \
  -o "$TMP/root/probe" "$TMP/probe.o" \
  "$TMP/root/lib/libc.so.6" "$TMP/root/lib/libdl.so.2" "$TMP/root/lib/libpthread.so.0"
python3 "$ROOT/build/r800_gps_probe_linked.py" "$TMP/root/probe"
python3 "$ROOT/build/r800_gps_link_gate.py" --binary "$TMP/root/probe" --libdir "$TMP/root/lib" > "$TMP/audit.json"
cat "$TMP/audit.json"
(cd "$TMP/root/lib" && sha256sum -c "$TMP/manifest")
EVIDENCE=$ROOT/build/r800_gps_qemu_evidence.py
python3 "$EVIDENCE" capture --root "$TMP/root" --qemu "$QEMU" --bwrap "$BWRAP" > "$TMP/before.json"
# No host filesystem mounts, no network, no privilege escalation, no fallback.
# A dynamic host qemu binary cannot run in this isolated root.
# Explicit LD_LIBRARY_PATH in the guest avoids host library search.
RC=0
timeout -k 5s 30s "$BWRAP" --unshare-all --die-with-parent --new-session \
  --clearenv --ro-bind "$TMP/root" / --ro-bind "$QEMU" /qemu \
  --dev /dev --proc /proc --chdir / \
  /qemu -cpu cortex-a15 -L / -E LD_LIBRARY_PATH=/lib /probe > "$TMP/run.log" 2>&1 || RC=$?
# Capture both successful and failed executions; review detects identity changes.
python3 "$EVIDENCE" capture --root "$TMP/root" --qemu "$QEMU" --bwrap "$BWRAP" > "$TMP/after.json" || true
cat "$TMP/run.log"
python3 "$EVIDENCE" review --before "$TMP/before.json" --after "$TMP/after.json" --audit "$TMP/audit.json" --log "$TMP/run.log" --exit-code "$RC"
(cd "$TMP/root/lib" && sha256sum -c "$TMP/manifest")
echo "QEMU_USER_ONLY=PASS"
echo "GNSS_RUNTIME_VERIFIED=false"
echo "safe_to_flash=false"
