#!/bin/sh
# Tizen ARM32 soft-float GPS bridge, build only, never run on host.
# Usage: build.sh <NDK r27c> <local Tizen library directory> <new-output-file>
set -eu
[ "$#" -eq 3 ] || { echo "usage: $0 <NDK r27c> <Tizen lib dir> <new output file>" >&2; exit 2; }
S=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
NDK=$(CDPATH= cd -- "$1" && pwd)
SR=$(CDPATH= cd -- "$2" && pwd)
OUT=$3
[ ! -e "$OUT" ] && [ ! -L "$OUT" ] || { echo "output already exists" >&2; exit 2; }
grep -Eq '^Pkg.Revision[[:space:]]*=[[:space:]]*27\.2\.12479018$' "$NDK/source.properties"
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
for lib in libc.so.6 libdl.so.2 libpthread.so.0; do
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
sha256sum "$SR/libc.so.6" "$SR/libdl.so.2" "$SR/libpthread.so.0" > "$TMP/input.txt"
"$TC/clang" --target=armv7a-linux-gnueabi -mfloat-abi=softfp -mfpu=vfpv3-d16 \
    -O2 -fno-pic -no-pie -fno-stack-protector -fno-builtin -ffreestanding -nostdlib -fuse-ld=lld \
    -Wl,--dynamic-linker=/lib/ld-linux.so.3 -Wl,-e,_start \
    -o "$TMP/gpsbridge" "$S/gpsbridge.c" "$SR/libc.so.6" "$SR/libdl.so.2" "$SR/libpthread.so.0"
"$TC/llvm-readelf" -h -l -d --wide "$TMP/gpsbridge" > "$TMP/elf.txt"
grep -Eq 'Class:[[:space:]]*ELF32' "$TMP/elf.txt"
grep -Eq 'Machine:[[:space:]]*ARM' "$TMP/elf.txt"
grep -Fq '/lib/ld-linux.so.3' "$TMP/elf.txt"
sha256sum -c "$TMP/input.txt"
ln -- "$TMP/gpsbridge" "$OUT"
sha256sum "$OUT"
echo "NON-RELEASE Tizen GPS bridge; glibc compatibility and GNSS runtime NOT verified."
