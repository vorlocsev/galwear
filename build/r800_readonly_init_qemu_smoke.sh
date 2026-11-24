#!/bin/sh
# Emulated *user-mode* read-only AArch64 /init behavior; no SM-R800 device.
# Requires coreutils timeout and qemu-aarch64 installed in disposable Alpine.
set -eu
[ "$#" -eq 2 ] || {
    echo "usage: sh build/r800_readonly_init_qemu_smoke.sh <compiled-aarch64-init> <new-log-dir>" >&2
    exit 2
}
INIT=$1
OUT=$2
[ -f "$INIT" ] && [ ! -L "$INIT" ] || {
    echo "Missing or symlinked /init ELF" >&2; exit 2;
}
[ ! -e "$OUT" ] || {
    echo "QEMU output directory already exists; refusing overwrite" >&2
    exit 2
}
command -v qemu-aarch64 >/dev/null
command -v timeout >/dev/null
mkdir -p "$OUT"

# This PID1 smoke ELF deliberately never exits. A 3-second deadline is
# expected. Only a fixed welcome string may be written to stdout.
set +e
timeout --signal=TERM 3s qemu-aarch64 -strace "$INIT" \
    > "$OUT/stdout.txt" 2> "$OUT/guest-syscalls.txt"
RESULT=$?
set -e
[ "$RESULT" -eq 124 ] || {
    echo "QEMU guest unexpectedly exited or was not stopped at timeout ($RESULT)" >&2
    exit 2
}
grep -Fq 'r800-readonly-init: NON-RELEASE smoke image' "$OUT/stdout.txt" || {
    echo "Missing read-only PID1 diagnostic message" >&2; exit 2;
}
grep -Eq 'write\(1,' "$OUT/guest-syscalls.txt" || {
    echo "Expected guest write-to-stdout syscall absent" >&2; exit 2;
}
grep -Eq 'nanosleep\(' "$OUT/guest-syscalls.txt" || {
    echo "Expected guest nanosleep syscall absent" >&2; exit 2;
}
# No device-related syscalls are permitted. These are guest syscall names
# from QEMU -strace, not the host's package/tool startup.
if grep -Eq '(openat|mount|umount|mmap|ioctl|reboot|execve|socket|connect)\(' "$OUT/guest-syscalls.txt"; then
    echo "Unexpected guest device/network/mount syscall" >&2
    exit 2
fi
echo "PASS: QEMU read-only PID1 wrote only to stdout then idled; no eMMC tested"
