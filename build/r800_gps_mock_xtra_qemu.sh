#!/bin/sh
# Synthetic XTRA integration only. Never substitute real LTO or libbrcm.
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 NDK-r27c donor-libdir" >&2; exit 2; }
[ "$(id -u)" -ne 0 ] || { echo "run as an unprivileged user" >&2; exit 2; }
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
NDK=$(CDPATH= cd -- "$1" && pwd -P)
SRC=$(CDPATH= cd -- "$2" && pwd -P)
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
QEMU=$(command -v qemu-arm-static) || { echo "BLOCKED: qemu-arm-static missing" >&2; exit 2; }
BWRAP=$(command -v bwrap) || { echo "BLOCKED: bubblewrap missing" >&2; exit 2; }
QEMU=$(realpath "$QEMU")
BWRAP=$(realpath "$BWRAP")
command -v timeout >/dev/null
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
trap 'exit 1' HUP INT TERM
export LC_ALL=C TZ=UTC
unset CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH LIBRARY_PATH
unset COMPILER_PATH GCC_EXEC_PREFIX CCC_OVERRIDE_OPTIONS CLANG_CONFIG_FILE
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT
for abi in 0 1 2; do
    GUEST=$TMP/guest-$abi
    mkdir -p "$GUEST/lib" "$GUEST/usr/lib" "$GUEST/dev" "$GUEST/proc" "$GUEST/opt/usr/r800dev" "$GUEST/opt/gnss/data"
    : > "$GUEST/qemu"
    python3 "$ROOT/build/r800_gps_donor_snapshot.py" create "$SRC" "$GUEST/lib" "$TMP/donor-$abi.json"
    R800_XTRA_ABI=$abi R800_TIZEN_ARCHIVE='' R800_HOST_SNAPSHOT=0 sh "$ROOT/src/tools/gps/build.sh" "$NDK" "$GUEST/lib" "$GUEST/gpsbridge"
    python3 "$ROOT/build/r800_gps_link_gate.py" --binary "$GUEST/gpsbridge" --libdir "$GUEST/lib"
    if [ "$abi" = 0 ]; then cases=0; else cases='1 2 3 4 5'; fi
    for case in $cases; do
        fixture=$case
        if [ "$case" = 5 ]; then fixture=1; fi
        LTO=$GUEST/opt/gnss/data/lto2.dat
        rm -f -- "$LTO"
        if [ "$case" != 5 ]; then
            printf '\001\000\003\004' > "$LTO"
            chmod 0600 "$LTO"
        fi
        "$TC/clang" --target=armv7a-linux-gnueabi -marm -mfloat-abi=softfp -mfpu=vfpv3-d16 \
            -O2 --no-default-config -nostdinc -ffreestanding -fno-builtin -fno-stack-protector \
            -Wall -Wextra -Werror -fPIC -fvisibility=hidden -shared -nostdlib -fuse-ld=lld --ld-path="$TC/ld.lld" \
            -Wl,--hash-style=sysv,-z,noexecstack,-z,now,--no-undefined \
            -DR800_XTRA_ABI="$abi" -DMOCK_XTRA_CASE="$fixture" \
            -o "$GUEST/usr/lib/libbrcm.so" "$ROOT/tests/r800_mock_gps_hal.c"
        sha256sum "$GUEST/gpsbridge" "$GUEST/usr/lib/libbrcm.so" "$QEMU" "$BWRAP" > "$TMP/inputs.sha"
        if [ "$case" != 5 ]; then sha256sum "$LTO" >> "$TMP/inputs.sha"; fi
        rc=0
        timeout -k 5s 20s "$BWRAP" --unshare-all --die-with-parent --new-session \
            --clearenv --ro-bind "$GUEST" / --ro-bind "$QEMU" /qemu \
            --dev /dev --proc /proc --chdir / \
            /qemu -cpu cortex-a15 -L / -E LD_LIBRARY_PATH=/lib /gpsbridge 0 \
            > "$TMP/run.log" 2>&1 || rc=$?
        sha256sum -c "$TMP/inputs.sha"
        if [ "$case" = 5 ]; then test ! -e "$LTO" && test ! -L "$LTO"; fi
        python3 "$ROOT/build/r800_gps_donor_snapshot.py" verify "$SRC" "$GUEST/lib" "$TMP/donor-$abi.json"
        python3 "$ROOT/build/r800_gps_mock_xtra_transcript.py" --abi "$abi" --case "$case" --exit-code "$rc" --log "$TMP/run.log" || { cat "$TMP/run.log" >&2; exit 2; }
    done
done
echo 'QEMU_SYNTHETIC_XTRA_MATRIX=PASS'
echo 'VENDOR_ABI_VERIFIED=false'
echo 'GNSS_RUNTIME_VERIFIED=false'
echo 'safe_to_flash=false'
