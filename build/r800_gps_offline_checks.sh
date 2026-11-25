#!/bin/sh
# Offline gate; never executes ARM code.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
trap 'exit 1' HUP INT TERM
export PYTHONDONTWRITEBYTECODE=1
echo "SOURCE_SHA=$(git rev-parse HEAD)"
cc --version
clang --version
for test in frame command lto output wire nmea; do
    cc -std=c11 -O2 -Wall -Wextra -Werror -UNDEBUG \
        -fsanitize=undefined -fno-sanitize-recover=all \
        "tests/test_r800_gps_$test.c" -o "$TMP/test-$test"
    "$TMP/test-$test"
    echo "HOST_$test=PASS"
done
cc -std=gnu11 -O2 -Wall -Wextra -Werror -UNDEBUG -pthread \
    -fsanitize=undefined -fno-sanitize-recover=all \
    tests/test_r800_gps_hal_lifecycle.c -o "$TMP/test-hal-lifecycle"
timeout 30s "$TMP/test-hal-lifecycle"
cc -std=gnu11 -O2 -Wall -Wextra -Werror -UNDEBUG -fsanitize=undefined -fno-sanitize-recover=all tests/test_r800_gps_ipc.c -o "$TMP/test-ipc"
timeout 10s "$TMP/test-ipc"
cc -std=gnu11 -O2 -Wall -Wextra -Werror -UNDEBUG -pthread \
    -fsanitize=undefined -fno-sanitize-recover=all \
    tests/test_r800_gps_hal_peer.c -o "$TMP/test-hal-peer"
timeout 45s "$TMP/test-hal-peer"
python3 -m unittest discover -s tests -p "test_r800_gps_bridge_integration.py" -v
python3 -m unittest discover -s tests -p 'test_r800_gnss_registration.py' -v
python3 -m unittest discover -s tests -p 'test_r800_gps_link_gate.py' -v
python3 -m unittest discover -s tests -p 'test_r800_extract_ext4.py' -v
python3 -m unittest discover -s tests -p 'test_android_linker_audit.py' -v
for script in src/tools/gps/build.sh build/r800_gps_glibc_qemu.sh payload/android-helper.sh; do
    sh -n "$script"
done
arm_compile() {
    clang --target=armv7a-linux-gnueabi -marm -mfloat-abi=softfp -mfpu=vfpv3-d16 \
        -std=c11 -O2 -ffreestanding -fno-builtin -fno-pic -fno-stack-protector \
        -Wall -Wextra -Werror "$@"
}
check_arm() {
    readelf -h "$1" > "$TMP/elf.txt"
    grep -Eq 'Class:[[:space:]]*ELF32' "$TMP/elf.txt"
    grep -Eq 'Machine:[[:space:]]*ARM' "$TMP/elf.txt"
    grep -Eq 'Flags:.*Version5 EABI' "$TMP/elf.txt"
    if grep -qi 'hard-float ABI' "$TMP/elf.txt"; then
        echo "unexpected hard-float" >&2; exit 1
    fi
}
for abi in 0 1 2; do
    arm_compile -DR800_XTRA_ABI="$abi" -c tests/r800_gps_abi_probe.c -o "$TMP/abi-$abi.o"
    check_arm "$TMP/abi-$abi.o"
    arm_compile -DR800_XTRA_ABI="$abi" -c src/tools/gps/gpsbridge.c -o "$TMP/bridge-$abi.o"
    check_arm "$TMP/bridge-$abi.o"
    echo "ARM32_GPS_OBJECT_ABI_$abi=PASS"
done
arm_compile -c tests/r800_glibc_probe.c -o "$TMP/glibc-probe.o"
check_arm "$TMP/glibc-probe.o"
arm_compile -fPIC -c tests/r800_glibc_probe_plugin.c -o "$TMP/plugin.o"
check_arm "$TMP/plugin.o"
reject_abi() {
    label=$1; shift
    if clang "$@" -std=c11 -ffreestanding -c tests/r800_gps_abi_probe.c -o "$TMP/rejected.o" > "$TMP/rejected.log" 2>&1; then
        echo "unexpected accepted ABI: $label" >&2
        exit 1
    fi
    grep -Eq 'R800 GPS requires ARM32 EABI|Invalid R800_XTRA_ABI' "$TMP/rejected.log"
    echo "REJECT_$label=PASS"
}
reject_abi HARD_FLOAT --target=armv7a-linux-gnueabihf -mfloat-abi=hard -mfpu=vfpv3-d16
reject_abi ARM64 --target=aarch64-linux-gnu
reject_abi INVALID_XTRA --target=armv7a-linux-gnueabi -mfloat-abi=softfp -DR800_XTRA_ABI=3
echo "GPS_OFFLINE_COMPILE_GATE=PASS"
echo "DONOR_LINK_VERIFIED=false"
echo "QEMU_RUNTIME_VERIFIED=false"
echo "GNSS_RUNTIME_VERIFIED=false"
echo "safe_to_flash=false"
