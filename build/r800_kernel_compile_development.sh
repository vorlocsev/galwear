#!/bin/sh
# Compile the functional development profile, never package or execute it.
# SOURCE must be disposable. The diagnostic build script is unchanged.
set -eu
[ "$#" -eq 4 ] || { echo "usage: $0 <disposable-source> <repo> <new-output-dir> <exact-galwear-sha>" >&2; exit 2; }
SOURCE=$(cd "$1" && pwd -P)
REPO=$(cd "$2" && pwd -P)
PARENT=$(cd "$(dirname "$3")" && pwd -P)
OUT=$PARENT/$(basename "$3")
SHA=$4
case "$SOURCE:$REPO:$OUT" in *[!a-zA-Z0-9_./:+-]*) echo "Unsafe build path" >&2; exit 2;; esac
case "$OUT/" in "$SOURCE/"*|"$REPO/"*) echo "Output overlaps source" >&2; exit 2;; esac
[ ! -e "$OUT" ] && [ ! -L "$OUT" ]
[ "$(git -C "$REPO" rev-parse HEAD)" = "$SHA" ]
python3 "$REPO/build/r800_kernel_preflight.py" --repository "$REPO" --source-tree "$SOURCE"
clang-19 --version | grep -q 'version 19\.1\.4'
ld.lld --version | grep -q 'LLD 19\.1\.4'
export PATH=/usr/lib/llvm19/bin:$PATH
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=0
export KBUILD_BUILD_USER=galwear-ci KBUILD_BUILD_HOST=github-actions KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_TIMESTAMP="Thu Jan  1 00:00:00 UTC 1970"
export ARCH=arm64 LLVM=1 LLVM_IAS=1 CC=clang-19 HOSTCC=clang-19 LD=ld.lld
export AR=llvm-ar NM=llvm-nm OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump STRIP=llvm-strip
export CLANG_TRIPLE=aarch64-linux-gnu- CROSS_COMPILE=aarch64-linux-gnu-
mkdir "$OUT"
mkdir "$OUT/obj"
python3 "$REPO/build/r800_development_initramfs.py" --output "$OUT/initramfs" --source-sha "$SHA"
git -C "$SOURCE" apply --check "$REPO/src/kernel/r800-wearos.patch"
git -C "$SOURCE" apply "$REPO/src/kernel/r800-wearos.patch"
python3 "$REPO/build/r800_development_kernel.py" prepare --initramfs "$OUT/initramfs" --config "$OUT/obj/.config" --source-sha "$SHA"
make -C "$SOURCE" O="$OUT/obj" olddefconfig
python3 "$REPO/build/r800_development_kernel.py" verify --initramfs "$OUT/initramfs" --config "$OUT/obj/.config" --source-sha "$SHA"
make -C "$SOURCE" O="$OUT/obj" -j2 Image
dtc -I dts -O dtb -S 133120 -o "$OUT/r800.dtb" "$REPO/src/dt/r800.dts"
CPIO="$OUT/obj/usr/initramfs_data.cpio.gz"
if [ ! -s "$CPIO" ]; then CPIO="$OUT/obj/usr/initramfs_data.cpio"; fi
python3 "$REPO/build/r800_development_kernel.py" finalize --initramfs "$OUT/initramfs" --config "$OUT/obj/.config" --source-sha "$SHA" --image "$OUT/obj/arch/arm64/boot/Image" --dtb "$OUT/r800.dtb" --archive "$CPIO" --output "$OUT/development-kernel-evidence.json"
echo "DEVELOPMENT_KERNEL_COMPILE_ONLY; no guest execution; safe_to_flash=false"
