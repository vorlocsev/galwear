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
sh build/r800_gps_core_checks.sh
cc -std=gnu11 -O2 -Wall -Wextra -Werror -UNDEBUG -pthread \
    -fsanitize=undefined -fno-sanitize-recover=all \
    tests/test_r800_gps_hal_lifecycle.c -o "$TMP/test-hal-lifecycle"
timeout 30s "$TMP/test-hal-lifecycle"
cc -std=gnu11 -O2 -Wall -Wextra -Werror -UNDEBUG -pthread \
    -fsanitize=undefined -fno-sanitize-recover=all \
    tests/test_r800_gps_hal_peer.c -o "$TMP/test-hal-peer"
timeout 45s "$TMP/test-hal-peer"
cc -std=gnu11 -O2 -Wall -Wextra -Werror -UNDEBUG -pthread \
    -fsanitize=undefined -fno-sanitize-recover=all \
    tests/test_r800_gps_hal_v2.c -o "$TMP/test-hal-v2"
timeout 45s "$TMP/test-hal-v2"
python3 build/r800_run_required_suite.py "test_r800_gps_bridge_integration.py"
python3 build/r800_run_required_suite.py 'test_r800_gnss_registration.py'
python3 build/r800_run_required_suite.py 'test_r800_gnss_ipc_layout.py'
python3 build/r800_run_required_suite.py 'test_r800_gps_link_gate.py'
python3 build/r800_run_required_suite.py 'test_r800_gps_binary_elf.py'
python3 build/r800_run_required_suite.py 'test_r800_stage_gps_donors.py'
python3 build/r800_run_required_suite.py 'test_r800_broadcom_export.py'
python3 build/r800_run_required_suite.py 'test_r800_extract_ext4.py'
python3 build/r800_run_required_suite.py 'test_android_linker_audit.py'
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
    arm_compile -DR800_XTRA_ABI="$abi" -c src/tools/gps/gpsbridge.c -o "$TMP/bridge-$abi.o"
    check_arm "$TMP/bridge-$abi.o"
    readelf -Ws "$TMP/bridge-$abi.o" > "$TMP/bridge-symbols.txt"
    if grep -Eq 'UND[[:space:]]+__aeabi_(l|ul)divmod([[:space:]]|$)' "$TMP/bridge-symbols.txt"; then
        echo "unexpected freestanding ARM 64-bit division helper" >&2; exit 1
    fi
    echo "ARM32_NO_LONG_DIV_HELPER_$abi=PASS"
    echo "ARM32_GPS_OBJECT_ABI_$abi=PASS"
done
arm_compile -c tests/r800_glibc_probe.c -o "$TMP/glibc-probe.o"
check_arm "$TMP/glibc-probe.o"
arm_compile -fPIC -c tests/r800_glibc_probe_plugin.c -o "$TMP/plugin.o"
check_arm "$TMP/plugin.o"
echo "GPS_OFFLINE_COMPILE_GATE=PASS"
echo "DONOR_LINK_VERIFIED=false"
echo "QEMU_RUNTIME_VERIFIED=false"
echo "GNSS_RUNTIME_VERIFIED=false"
echo "safe_to_flash=false"
