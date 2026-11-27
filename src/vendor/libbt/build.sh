#!/bin/sh
# NON-RELEASE ARM32 Broadcom vendor HAL for BCM43012, no radio access.
# Usage: sh src/vendor/libbt/build.sh <NDK r27c> <new-output-dir>
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 <NDK r27c> <new-output-dir>" >&2; exit 2; }
S=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
NDK=$(CDPATH= cd -- "$1" && pwd)
OUT=$2
[ ! -e "$OUT" ] && [ ! -L "$OUT" ] || { echo "output must not exist" >&2; exit 2; }
grep -Eq '^Pkg.Revision[[:space:]]*=[[:space:]]*27\.2\.12479018$' "$NDK/source.properties"
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
CC=$TC/armv7a-linux-androideabi28-clang
[ -x "$CC" ] && [ -x "$TC/llvm-readelf" ]
mkdir -- "$OUT"
OUT=$(CDPATH= cd -- "$OUT" && pwd)
G=https://android.googlesource.com/platform
TAG=android-11.0.0_r48
BASE=a7191619f320c9c48c0cfc376996ca2836c7a799
fetch_source() {
    git init -q "$2"
    git -C "$2" remote add origin "$G/$1"
    git -C "$2" fetch --depth=1 origin "$3"
    git -C "$2" checkout --detach -q 'FETCH_HEAD^{commit}'
}
fetch_source hardware/broadcom/libbt "$OUT/src" "$BASE"
[ "$(git -C "$OUT/src" rev-parse HEAD)" = "$BASE" ]
BT_BASE=30098cc2b2fc751f76018ba9e013a86cb883fbd3
fetch_source system/bt "$OUT/bdroid" "$BT_BASE"
[ "$(git -C "$OUT/bdroid" rev-parse HEAD)" = "$BT_BASE" ]
# All generated headers and source checkouts are disposable; repo stays clean.
cp -R "$S/shim" "$OUT/shim"
touch "$OUT/shim/bdroid_buildcfg.h"
bash "$OUT/src/gen-buildcfg.sh" "$S/vnd_r800.txt" "$OUT/shim/vnd_buildcfg.h"
"$CC" -shared -fPIC -O2 -Wall -Wl,--no-undefined -Wl,-soname,libbt-vendor.so \
    -Wno-switch -Wno-unused-function -Wno-unused-parameter \
    -Wno-unused-variable -Wno-unused-but-set-variable \
    -I"$OUT/shim" -I"$OUT/src/include" -I"$OUT/bdroid/hci/include" -I"$OUT/bdroid/include" \
    -I"$OUT/bdroid/device/include" -I"$OUT/bdroid/stack/include" -I"$OUT/bdroid" \
    -o "$OUT/libbt-vendor.so" "$OUT"/src/src/*.c -llog
"$TC/llvm-readelf" -h -d --dyn-syms --wide "$OUT/libbt-vendor.so" > "$OUT/libbt-vendor.elf.txt"
grep -Eq 'Class:[[:space:]]*ELF32' "$OUT/libbt-vendor.elf.txt"
grep -Eq 'Machine:[[:space:]]*ARM' "$OUT/libbt-vendor.elf.txt"
grep -Eq 'Type:[[:space:]]*DYN' "$OUT/libbt-vendor.elf.txt"
grep -Eq 'OBJECT[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]+BLUETOOTH_VENDOR_LIB_INTERFACE([[:space:]]|$)' "$OUT/libbt-vendor.elf.txt"
{
    printf 'broadcom_commit=%s\n' "$BASE"
    printf 'system_bt_tag=%s\n' "$TAG"
    printf 'system_bt_commit=%s\n' "$(git -C "$OUT/bdroid" rev-parse HEAD)"
    "$CC" --version
    sha256sum "$OUT/libbt-vendor.so" "$S/vnd_r800.txt" "$S/bt_vendor.conf"
    echo 'runtime_verified=false'
    echo 'safe_to_flash=false'
} > "$OUT/bt-build-evidence.txt"
cat "$OUT/bt-build-evidence.txt"
