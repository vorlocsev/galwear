#!/bin/sh
# Tizen ARM32 soft-float GPS bridge, build only, never run on host.
# Usage: build.sh <NDK r27c> <local Tizen library directory> <new-output-file>
set -eu
XTRA_ABI=${R800_XTRA_ABI:-0}
case "$XTRA_ABI" in 0|1|2) ;; *) echo "invalid R800_XTRA_ABI" >&2; exit 2;; esac
[ "$#" -eq 3 ] || { echo "usage: $0 <NDK r27c> <Tizen lib dir> <new output file>" >&2; exit 2; }
S=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$S/../../.." && pwd)
NDK=$(CDPATH= cd -- "$1" && pwd)
SR=$(CDPATH= cd -- "$2" && pwd)
OUT=$3
[ ! -e "$OUT" ] && [ ! -L "$OUT" ] || { echo "output already exists" >&2; exit 2; }
grep -Eq '^Pkg.Revision[[:space:]]*=[[:space:]]*27\.2\.12479018$' "$NDK/source.properties"
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
for lib in libc.so.6 libdl.so.2 libpthread.so.0 ld-linux.so.3; do
    [ -f "$SR/$lib" ] && [ ! -L "$SR/$lib" ] || { echo "supply resolved local library: $lib" >&2; exit 2; }
    "$TC/llvm-readelf" -h "$SR/$lib" | grep -Eq 'Class:[[:space:]]*ELF32'
    "$TC/llvm-readelf" -h "$SR/$lib" | grep -Eq 'Machine:[[:space:]]*ARM'
    "$TC/llvm-readelf" -h "$SR/$lib" | grep -Eq 'Type:[[:space:]]*DYN'
done
PARENT=$(CDPATH= cd -- "$(dirname -- "$OUT")" && pwd)
OUT=$PARENT/$(basename -- "$OUT")
TMP=$(mktemp -d "$PARENT/.gpsbridge.XXXXXX")
trap 'rm -rf -- "$TMP"' EXIT
trap 'exit 1' HUP INT TERM
sha256sum "$SR/libc.so.6" "$SR/libdl.so.2" "$SR/libpthread.so.0" "$SR/ld-linux.so.3" > "$TMP/input.txt"
mkdir "$TMP/libs"
for lib in libc.so.6 libdl.so.2 libpthread.so.0 ld-linux.so.3; do
    cp -- "$SR/$lib" "$TMP/libs/$lib"
    cmp -- "$SR/$lib" "$TMP/libs/$lib"
done
sha256sum -c "$TMP/input.txt"
(cd "$TMP/libs" && sha256sum libc.so.6 libdl.so.2 libpthread.so.0 ld-linux.so.3) > "$TMP/snapshot.txt"
"$TC/clang" --target=armv7a-linux-gnueabi -mfloat-abi=softfp -mfpu=vfpv3-d16 \
    -DR800_XTRA_ABI="$XTRA_ABI" -O2 -fno-pic -no-pie -fno-stack-protector -fno-builtin -ffreestanding -nostdlib -fuse-ld=lld \
    -Wl,--hash-style=sysv -Wl,-z,noexecstack -Wl,-z,now -Wl,--no-undefined \
    -Wl,--dynamic-linker=/lib/ld-linux.so.3 -Wl,-e,_start \
    -o "$TMP/gpsbridge" "$S/gpsbridge.c" "$TMP/libs/libc.so.6" "$TMP/libs/libdl.so.2" "$TMP/libs/libpthread.so.0"
"$TC/llvm-readelf" -h -l -d --wide "$TMP/gpsbridge" > "$TMP/elf.txt"
grep -Eq 'Class:[[:space:]]*ELF32' "$TMP/elf.txt"
grep -Eq 'Machine:[[:space:]]*ARM' "$TMP/elf.txt"
grep -Fq '/lib/ld-linux.so.3' "$TMP/elf.txt"
python3 "$ROOT/build/r800_gps_link_gate.py" --binary "$TMP/gpsbridge" --libdir "$TMP/libs"
(cd "$TMP/libs" && sha256sum -c "$TMP/snapshot.txt")
sha256sum -c "$TMP/input.txt"
ln -- "$TMP/gpsbridge" "$OUT"
sha256sum "$OUT"
echo "R800_XTRA_ABI=$XTRA_ABI (0=disabled; 1=legacy; 2=sized vendor candidate)"
echo "NON-RELEASE Tizen GPS bridge; glibc compatibility and GNSS runtime NOT verified."
