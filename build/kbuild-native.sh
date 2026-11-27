#!/bin/sh
# Local read-only-init kernel smoke build; original checkout is never patched.
# Usage: sh build/kbuild-native.sh <pinned-kernel-source> <new-output-dir>
# Requires the same LLVM 19.1.4 toolchain as the CI smoke build.
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 <kernel-source> <new-output-dir>" >&2; exit 2; }
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
SRC=$(CDPATH= cd -- "$1" && pwd -P)
OUT=$2
BASE=50db73fc799f20a7120a8b5f653b16cc123d856f
[ ! -e "$OUT" ] && [ ! -L "$OUT" ] || { echo "output must not exist" >&2; exit 2; }
PARENT=$(CDPATH= cd -- "$(dirname -- "$OUT")" && pwd -P)
OUT=$PARENT/$(basename -- "$OUT")
case "$OUT/" in
    "$SRC/"*|"$REPO/"*) echo "output must be outside source and project trees" >&2; exit 2;;
esac
case "$SRC:$REPO:$OUT" in
    *[[:space:]]*) echo "kernel build paths must not contain whitespace" >&2; exit 2;;
esac
python3 "$REPO/build/r800_kernel_preflight.py" --source-tree "$SRC"
mkdir -- "$OUT"
git clone --local --no-hardlinks --no-checkout -- "$SRC" "$OUT/kernel"
git -C "$OUT/kernel" checkout --detach "$BASE"
sh "$REPO/build/r800_initramfs_compile_smoke.sh" "$REPO" "$OUT/initramfs"
R800_REPRO_KHEADERS=1 R800_STORAGE_ISOLATION=true \
    R800_SMOKE_INITRAMFS_LIST="$OUT/initramfs/initramfs.list" \
    sh "$REPO/build/r800_kernel_compile_smoke.sh" "$OUT/kernel" "$REPO" "$OUT/obj"
python3 "$REPO/build/r800_kernel_preflight.py" --source-tree "$SRC" > "$OUT/source-postflight.json"
sha256sum "$REPO/src/kernel/r800-wearos.patch" "$REPO/src/kernel/r800.config" \
    "$OUT/initramfs/init" "$OUT/obj/.config" "$OUT/obj/arch/arm64/boot/Image" > "$OUT/build-sha256.txt"
echo "NON-RELEASE read-only kernel smoke; hardware unverified; safe_to_flash=false"
