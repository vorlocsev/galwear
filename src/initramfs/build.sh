#!/bin/sh
# Build only the freestanding AArch64 /init. No host-specific source paths.
# Usage: sh src/initramfs/build.sh <new-output-directory>
set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 <new-output-directory>" >&2; exit 2; }
SRC=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=$1
[ ! -e "$OUT" ] && [ ! -L "$OUT" ] || { echo "output must not exist" >&2; exit 2; }
command -v clang >/dev/null
command -v ld.lld >/dev/null
mkdir -- "$OUT"
OUT=$(CDPATH= cd -- "$OUT" && pwd)
case "$OUT" in
    *[[:space:]]*) echo "initramfs list path must not contain whitespace" >&2; exit 2;;
esac
clang --target=aarch64-linux-gnu -ffreestanding -nostdlib -static \
    -fno-stack-protector -fno-builtin -O2 -fuse-ld=lld \
    -Wl,-e,_start -o "$OUT/init" "$SRC/init.c"
chmod 755 "$OUT/init"
# Kernel gen_init_cpio input. /init creates its mountpoints itself.
printf 'file /init %s/init 0755 0 0\n' "$OUT" > "$OUT/list.txt"
sha256sum "$OUT/init" "$OUT/list.txt"
printf 'Use CONFIG_INITRAMFS_SOURCE="%s/list.txt" in a separate kernel build config.\n' "$OUT"
printf 'NON-RELEASE: no kernel build or boot image generated.\n'
