#!/bin/sh
# Offline compilation only. Never execute watch utilities on the build host.
# Usage: sh build/r800_build_tools.sh <NDK r27c> <new-output-dir>
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 <NDK r27c> <new-output-dir>" >&2; exit 2; }
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
NDK=$(CDPATH= cd -- "$1" && pwd)
OUT=$2
[ ! -e "$OUT" ] && [ ! -L "$OUT" ]
grep -Eq '^Pkg.Revision[[:space:]]*=[[:space:]]*27\.2\.12479018$' "$NDK/source.properties"
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
CC=$TC/armv7a-linux-androideabi30-clang
[ -x "$CC" ] && [ -x "$TC/llvm-readelf" ]
mkdir -- "$OUT"
OUT=$(CDPATH= cd -- "$OUT" && pwd)
mkdir "$OUT/bin" "$OUT/charger" "$OUT/evidence"
"$CC" --version > "$OUT/evidence/toolchain.txt"
compile() {
    src=$1; target=$2
    "$CC" -static -O2 -g0 -Wall -Wl,--no-undefined \
        -o "$OUT/$target" "$REPO/src/tools/$src" -lm
    report="$OUT/evidence/$(basename "$target").elf.txt"
    "$TC/llvm-readelf" -h -l -d --wide "$OUT/$target" > "$report"
    grep -Eq 'Class:[[:space:]]*ELF32' "$report"
    grep -Eq 'Machine:[[:space:]]*ARM' "$report"
    if grep -Eq 'INTERP|\(NEEDED\)' "$report"; then
        echo "Unexpected dynamic runtime dependency: $target" >&2; exit 2
    fi
    sha256sum "$OUT/$target"
}
compile tzlite/fsfreeze.c bin/fsfreeze
compile loopdio.c bin/loopdio
compile r800boost.c bin/r800boost
compile r800keys.c bin/r800keys
compile sensors/ukey.c bin/ukey
compile sensors/gpiotool.c bin/gpiotool
compile wpcd.c bin/wpcd
compile charger/r800charger.c charger/r800charger
compile charger/r800wdui.c charger/r800wdui
cp "$OUT/bin/wpcd" "$OUT/charger/wpcd"
cmp "$OUT/bin/wpcd" "$OUT/charger/wpcd"

# Tizen GNSS bridge: compile actual source without pretending Bionic is glibc.
# Linking is intentionally deferred until matching local Tizen libraries are supplied.
"$TC/clang" --target=armv7a-linux-gnueabi -mfloat-abi=softfp -mfpu=vfpv3-d16 \
    -O2 -fno-pic -fno-stack-protector -fno-builtin -ffreestanding \
    -c "$REPO/src/tools/gps/gpsbridge.c" -o "$OUT/gpsbridge.o"
"$TC/llvm-readelf" -h -s --wide "$OUT/gpsbridge.o" > "$OUT/evidence/gpsbridge-object.elf.txt"
grep -Eq 'Class:[[:space:]]*ELF32' "$OUT/evidence/gpsbridge-object.elf.txt"
grep -Eq 'Machine:[[:space:]]*ARM' "$OUT/evidence/gpsbridge-object.elf.txt"
grep -Eq 'Type:[[:space:]]*REL' "$OUT/evidence/gpsbridge-object.elf.txt"
sha256sum "$OUT/gpsbridge.o"
echo "Nine static executables; GPS bridge object only. No device access or execution."
echo "safe_to_flash=false"
