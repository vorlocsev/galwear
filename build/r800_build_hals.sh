#!/bin/sh
# Compile legacy Android ARM32 HAL candidates; never load or execute them.
# Usage: sh build/r800_build_hals.sh <Android NDK r27c> <new-output-dir>
set -eu
GPS_IPC_V2=${R800_GPS_IPC_V2-1}
case "$GPS_IPC_V2" in 0|1) ;; *) echo "invalid R800_GPS_IPC_V2 (expected 0 or 1)" >&2; exit 2;; esac
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
build gps_r800.c gps.r800.so -DR800_GPS_IPC_V2="$GPS_IPC_V2"
printf 'R800_GPS_IPC_V2=%s\n' "$GPS_IPC_V2" > "$OUT/gps-ipc-evidence.txt"
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
for unit in pcm pcm_hw mixer mixer_hw snd_card_plugin; do
    "$CC" -std=gnu11 -D_GNU_SOURCE -O2 -g0 -fPIC -fvisibility=hidden \
        -I "$TINY/include" -c "$TINY/src/$unit.c" -o "$OUT/$unit.o"
done
"$TC/llvm-ar" rcs "$OUT/libtinyalsa-r800.a" "$OUT/pcm.o" "$OUT/pcm_hw.o" "$OUT/mixer.o" "$OUT/mixer_hw.o" "$OUT/snd_card_plugin.o"
build audio_r800.c audio.primary.r800.so -I "$TINY/include" \
    "$OUT/libtinyalsa-r800.a" -Wl,--exclude-libs,ALL
echo "NON-RELEASE ARM32 HAL compilation only; PCM runtime untested."
echo "No HAL executed, no device contact, no firmware published."
