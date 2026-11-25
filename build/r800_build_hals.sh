#!/bin/sh
# Compile legacy Android ARM32 HAL candidates; never load or execute them.
# Usage: sh build/r800_build_hals.sh <Android NDK r27c> <new-output-dir>
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 <NDK r27c> <new-output-dir>" >&2; exit 2; }
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
NDK=$(CDPATH= cd -- "$1" && pwd)
OUT=$2
[ ! -e "$OUT" ] && [ ! -L "$OUT" ] || { echo "output must not exist" >&2; exit 2; }
grep -Eq '^Pkg.Revision[[:space:]]*=[[:space:]]*27\.2\.12479018$' "$NDK/source.properties" || { echo "Expected NDK r27c" >&2; exit 2; }
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
CC=$TC/armv7a-linux-androideabi28-clang
[ -x "$CC" ] && [ -x "$TC/llvm-readelf" ] || { echo "NDK compiler missing" >&2; exit 2; }
mkdir -- "$OUT"
OUT=$(CDPATH= cd -- "$OUT" && pwd)
"$CC" --version > "$OUT/toolchain.txt"
build() {
    "$CC" -std=gnu11 -O2 -g0 -fPIC -shared -Wl,--no-undefined \
        -march=armv7-a -mfpu=neon -I "$REPO/src/hal/include" \
        -Wl,-soname,"$2" -o "$OUT/$2" "$REPO/src/hal/$1" -llog -ldl -lm
    "$TC/llvm-readelf" -h -d --dyn-syms --wide "$OUT/$2" > "$OUT/$2.elf.txt"
    grep -Eq 'Class:[[:space:]]*ELF32' "$OUT/$2.elf.txt"
    grep -Eq 'Machine:[[:space:]]*ARM' "$OUT/$2.elf.txt"
    grep -Eq 'Type:[[:space:]]*DYN' "$OUT/$2.elf.txt"
    grep -Eq 'OBJECT[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]+HMI([[:space:]]|$)' "$OUT/$2.elf.txt"
    sha256sum "$OUT/$2"
}
build lights_r800.c lights.r800.so
build gps_r800.c gps.r800.so
build sensors_r800.c sensors.r800.so
build hwcomposer_r800.c hwcomposer.r800.so
echo "NON-RELEASE ARM32 HAL compilation only; audio requires patched tinyalsa."
echo "No HAL executed, no device contact, no firmware published."
