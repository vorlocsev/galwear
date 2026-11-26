#!/bin/sh
# Native parser/IPC tests and compile-only ABI probes, not a full GPS regression.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
trap 'exit 1' HUP INT TERM
export PYTHONDONTWRITEBYTECODE=1
cc --version
clang --version
for test in frame command lto output wire nmea ipc interface standalone daemon shutdown callback; do
    standard=c11
    case "$test" in ipc|interface|shutdown) standard=gnu11;; esac
    cc -std="$standard" -O2 -Wall -Wextra -Werror -UNDEBUG \
        -fsanitize=undefined -fno-sanitize-recover=all -pthread \
        "tests/test_r800_gps_$test.c" -o "$TMP/test-$test"
    timeout 10s "$TMP/test-$test"
    echo "HOST_$test=PASS"
done
python3 build/r800_run_required_suite.py 'test_r800_required_suite.py'
python3 build/r800_run_required_suite.py 'test_r800_qemu_probe_log.py'
python3 build/r800_run_required_suite.py 'test_r800_gnss_readiness.py'
for abi in 0 1 2; do
    clang --target=armv7a-linux-gnueabi -marm -mfloat-abi=softfp -mfpu=vfpv3-d16 \
        -std=c11 -O2 -ffreestanding -fno-builtin -fno-pic -fno-stack-protector \
        -Wall -Wextra -Werror -DR800_XTRA_ABI="$abi" -c tests/r800_gps_abi_probe.c -o "$TMP/abi-$abi.o"
    readelf -h "$TMP/abi-$abi.o" > "$TMP/elf.txt"
    grep -Eq 'Class:[[:space:]]*ELF32' "$TMP/elf.txt"
    grep -Eq 'Machine:[[:space:]]*ARM' "$TMP/elf.txt"
    grep -Eq 'Flags:.*Version5 EABI' "$TMP/elf.txt"
    if grep -qi 'hard-float ABI' "$TMP/elf.txt"; then exit 1; fi
    echo "ARM32_ABI_PROBE_$abi=PASS"
done
reject_abi() {
    label=$1; shift
    if clang "$@" -std=c11 -ffreestanding -c tests/r800_gps_abi_probe.c -o "$TMP/rejected.o" > "$TMP/rejected.log" 2>&1; then
        echo "unexpected accepted ABI: $label" >&2; exit 1
    fi
    grep -Eq 'R800 GPS requires ARM32 EABI|Invalid R800_XTRA_ABI' "$TMP/rejected.log"
    echo "REJECT_$label=PASS"
}
reject_abi HARD_FLOAT --target=armv7a-linux-gnueabihf -mfloat-abi=hard -mfpu=vfpv3-d16
reject_abi ARM64 --target=aarch64-linux-gnu
reject_abi INVALID_XTRA --target=armv7a-linux-gnueabi -mfloat-abi=softfp -DR800_XTRA_ABI=3
echo "GPS_CORE_CHECKS=PASS"
echo "FULL_GPS_REGRESSION_VERIFIED=false"
echo "GPS_CORE_SAFE_TO_FLASH=false"
