#!/bin/sh
# Compile only the read-only AArch64 /init; never build a flashable image.
# Requires LLVM/LLD 19.1.4 and a disposable workspace.
set -eu
[ "$#" -eq 2 ] || {
    echo "usage: sh build/r800_initramfs_compile_smoke.sh <repo> <new-output-dir>" >&2
    exit 2
}
REPO=$1
OUT=$2
[ -f "$REPO/src/initramfs/init-readonly.c" ] || { echo "init-readonly.c missing" >&2; exit 2; }
[ ! -e "$OUT" ] || { echo "output directory already exists" >&2; exit 2; }
case "$OUT" in *" "*|*"	"*) echo "output path contains whitespace" >&2; exit 2;; esac

clang-19 --version | grep -q 'version 19\.1\.4'
ld.lld --version | grep -q 'LLD 19\.1\.4'
mkdir -p "$OUT"
export SOURCE_DATE_EPOCH=0

clang-19 --target=aarch64-linux-gnu \
    -ffreestanding -nostdlib -static -fno-stack-protector \
    -fno-builtin -O2 -fuse-ld=lld -fno-pie -no-pie \
    -Wl,-e,_start -Wl,--build-id=none \
    -o "$OUT/init" "$REPO/src/initramfs/init-readonly.c"

python3 "$REPO/build/r800_initramfs_spec.py" \
    --init "$OUT/init" \
    --list "$OUT/initramfs.list" \
    --report "$OUT/initramfs-evidence.json"

echo "PASS: read-only experimental /init compiled and inspected, no kernel or watch modified"
