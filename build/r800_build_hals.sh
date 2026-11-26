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
    source=$1; module=$2; shift 2
    "$CC" -std=gnu11 -O2 -g0 -fPIC -shared -Wl,--no-undefined \
        -march=armv7-a -mfpu=neon -I "$REPO/src/hal/include" \
        -Wl,-soname,"$module" -o "$OUT/$module" "$REPO/src/hal/$source" "$@" -llog -ldl -lm
    "$TC/llvm-readelf" -h -d --dyn-syms --wide "$OUT/$module" > "$OUT/$module.elf.txt"
    grep -Eq 'Class:[[:space:]]*ELF32' "$OUT/$module.elf.txt"
    grep -Eq 'Machine:[[:space:]]*ARM' "$OUT/$module.elf.txt"
    grep -Eq 'Type:[[:space:]]*DYN' "$OUT/$module.elf.txt"
    grep -Eq 'OBJECT[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]+HMI([[:space:]]|$)' "$OUT/$module.elf.txt"
    sha256sum "$OUT/$module"
}
build lights_r800.c lights.r800.so
build gps_r800.c gps.r800.so
build sensors_r800.c sensors.r800.so
build hwcomposer_r800.c hwcomposer.r800.so
# Fetch only the exact public tinyalsa base into disposable output.
# Keep the third-party source/license in the scratch tree; do not publish binaries.
TINY=$OUT/tinyalsa
BASE=1c5fb68ced57d838f2b7ecd0c00bc1fefc9ab60d
git init -q "$TINY"
git -C "$TINY" remote add origin https://github.com/tinyalsa/tinyalsa.git
git -C "$TINY" fetch --depth=1 origin "$BASE"
git -C "$TINY" checkout --detach -q FETCH_HEAD
[ "$(git -C "$TINY" rev-parse HEAD)" = "$BASE" ]
PATCH=$REPO/src/vendor/audio/tinyalsa-2.0.0-sync-ptr.patch
git -C "$TINY" apply --check "$PATCH"
git -C "$TINY" apply "$PATCH"
{
    printf 'tinyalsa_base=%s\n' "$BASE"
    sha256sum "$PATCH"
    git -C "$TINY" diff --stat
} > "$OUT/tinyalsa-evidence.txt"
# Compile PIC objects, archive them, and link only this patched copy.
# Match the pinned upstream src/Makefile OBJECTS inventory exactly.
set -- limits mixer pcm pcm_plugin pcm_hw snd_card_plugin mixer_plugin mixer_hw
printf 'tinyalsa_units=%s\n' "$*" >> "$OUT/tinyalsa-evidence.txt"
for unit in "$@"; do
    "$CC" -std=gnu11 -D_GNU_SOURCE -O2 -g0 -fPIC -fvisibility=hidden \
        -I "$TINY/include" -c "$TINY/src/$unit.c" -o "$OUT/$unit.o"
done
"$TC/llvm-ar" rcs "$OUT/libtinyalsa-r800.a" \
    "$OUT/limits.o" "$OUT/mixer.o" "$OUT/pcm.o" "$OUT/pcm_plugin.o" \
    "$OUT/pcm_hw.o" "$OUT/snd_card_plugin.o" "$OUT/mixer_plugin.o" "$OUT/mixer_hw.o"
"$TC/llvm-nm" --defined-only "$OUT/libtinyalsa-r800.a" > "$OUT/tinyalsa-symbols.txt"
grep -Eq '[[:space:]][Tt][[:space:]]snd_utils_close_dev_node$' "$OUT/tinyalsa-symbols.txt"
build audio_r800.c audio.primary.r800.so -I "$TINY/include" \
    "$OUT/libtinyalsa-r800.a" -Wl,--exclude-libs,ALL
echo "NON-RELEASE ARM32 HAL compilation only; PCM runtime untested."
echo "No HAL executed, no device contact, no firmware published."
