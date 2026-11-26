#!/bin/sh
# Compile/link only the Android GPS HAL in both protocol modes.
# No donor, mount, device access, image creation or binary publication.
set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 <NDK r27c>" >&2; exit 2; }
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
NDK=$(CDPATH= cd -- "$1" && pwd)
grep -Eq '^Pkg.Revision[[:space:]]*=[[:space:]]*27\.2\.12479018$' "$NDK/source.properties"
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
CC=$TC/armv7a-linux-androideabi28-clang
[ -x "$CC" ] && [ -x "$TC/llvm-readelf" ]
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
trap 'exit 1' HUP INT TERM
"$CC" --version
for mode in 0 1; do
    mkdir "$TMP/$mode"
    module="$TMP/$mode/gps.r800.so"
    "$CC" -std=gnu11 -O2 -g0 -Wall -Wextra -Werror -fPIC -shared \
        -Wl,--no-undefined -march=armv7-a -mfpu=neon \
        -I "$ROOT/src/hal/include" -DR800_GPS_IPC_V2="$mode" \
        -Wl,-soname,gps.r800.so -o "$module" "$ROOT/src/hal/gps_r800.c" -llog -ldl -lm
    "$TC/llvm-readelf" -h -d --dyn-syms --wide "$module" > "$TMP/elf-$mode.txt"
    grep -Eq 'Class:[[:space:]]*ELF32' "$TMP/elf-$mode.txt"
    grep -Eq 'Machine:[[:space:]]*ARM' "$TMP/elf-$mode.txt"
    grep -Eq 'Type:[[:space:]]*DYN' "$TMP/elf-$mode.txt"
    grep -Eq 'Flags:.*(0x5[0-9a-fA-F]{6}|Version5 EABI)' "$TMP/elf-$mode.txt"
    grep -Eq 'SONAME.*\[gps\.r800\.so\]' "$TMP/elf-$mode.txt"
    grep -Eq 'OBJECT[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]+HMI([[:space:]]|$)' "$TMP/elf-$mode.txt"
    if grep -Eq 'NEEDED.*\[(libc\.so\.6|libpthread\.so\.0|libdl\.so\.2)\]' "$TMP/elf-$mode.txt"; then
        echo "unexpected glibc dependency" >&2
        exit 1
    fi
    if grep -qi 'hard-float ABI' "$TMP/elf-$mode.txt"; then exit 1; fi
    sha256sum "$module"
    echo "GPS_ANDROID_API28_ARM32_IPC_$mode=PASS"
done
mkdir "$TMP/default"
"$CC" -std=gnu11 -O2 -g0 -Wall -Wextra -Werror -fPIC -shared \
    -Wl,--no-undefined -march=armv7-a -mfpu=neon \
    -I "$ROOT/src/hal/include" -Wl,-soname,gps.r800.so \
    -o "$TMP/default/gps.r800.so" "$ROOT/src/hal/gps_r800.c" -llog -ldl -lm
cmp "$TMP/default/gps.r800.so" "$TMP/1/gps.r800.so"
echo "GPS_ANDROID_DEFAULT_IPC_V2=PASS"
if cmp -s "$TMP/0/gps.r800.so" "$TMP/1/gps.r800.so"; then
    echo "IPC modes unexpectedly identical" >&2
    exit 1
fi
if "$CC" -std=gnu11 -fsyntax-only -I "$ROOT/src/hal/include" \
        -DR800_GPS_IPC_V2=2 "$ROOT/src/hal/gps_r800.c" > "$TMP/reject.txt" 2>&1; then
    echo "invalid IPC mode accepted" >&2
    exit 1
fi
grep -q 'Invalid R800_GPS_IPC_V2' "$TMP/reject.txt"
echo "GPS_INVALID_IPC_MODE=REJECTED"
echo "GPS_ANDROID_HAL_NDK_LINK=PASS"
echo "GNSS_RUNTIME_VERIFIED=false"
echo "safe_to_flash=false"
