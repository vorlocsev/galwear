#!/bin/sh
# Non-release kernel build from a clean pinned local source, never modifies it.
# Usage: sh build/kbuild-native.sh <kernel-source> <new-build-directory>
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 <kernel-source> <new-build-directory>" >&2; exit 2; }
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SRC=$(CDPATH= cd -- "$1" && pwd)
OUT=$2
BASE=50db73fc799f20a7120a8b5f653b16cc123d856f
[ ! -e "$OUT" ] && [ ! -L "$OUT" ] || { echo "output must not exist" >&2; exit 2; }
PARENT=$(CDPATH= cd -- "$(dirname -- "$OUT")" && pwd)
OUT=$PARENT/$(basename -- "$OUT")
case "$OUT/" in
    "$SRC/"*|"$REPO/"*) echo "output must be outside source and project trees" >&2; exit 2;;
esac
case "$SRC:$REPO:$OUT" in
    *[[:space:]]*) echo "kernel build paths must not contain whitespace" >&2; exit 2;;
esac
for tool in git python3 make clang ld.lld llvm-ar llvm-nm llvm-objcopy llvm-objdump llvm-strip sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing build tool: $tool" >&2; exit 127; }
done
JOBS=$(getconf _NPROCESSORS_ONLN)
case "$JOBS" in ''|*[!0-9]*|0) echo "invalid job count" >&2; exit 2;; esac

# Verify patch context against the exact unmodified base before cloning.
python3 "$REPO/build/r800_kernel_preflight.py" --source-tree "$SRC"
mkdir -- "$OUT"
git clone --local --no-hardlinks --no-checkout -- "$SRC" "$OUT/kernel"
git -C "$OUT/kernel" checkout --detach "$BASE"
git -C "$OUT/kernel" apply --check "$REPO/src/kernel/r800-wearos.patch"
git -C "$OUT/kernel" apply "$REPO/src/kernel/r800-wearos.patch"
sh "$REPO/src/initramfs/build.sh" "$OUT/initramfs"
mkdir "$OUT/obj"
cp "$REPO/src/kernel/r800.config" "$OUT/obj/.config"
"$OUT/kernel/scripts/config" --file "$OUT/obj/.config" --set-str INITRAMFS_SOURCE "$OUT/initramfs/list.txt"
# Preserve the existing compiler options of the historical build, while using
# separate source/output directories and a bounded explicit target.
kmake() {
    make -C "$OUT/kernel" O="$OUT/obj" ARCH=arm64 LLVM=1 LLVM_IAS=1 \
        CC=clang LD=ld.lld AR=llvm-ar NM=llvm-nm OBJCOPY=llvm-objcopy \
        OBJDUMP=llvm-objdump STRIP=llvm-strip CLANG_TRIPLE=aarch64-linux-gnu- \
        CROSS_COMPILE=aarch64-linux-gnu- HOSTCC=clang "-j$JOBS" "$@"
}
export LC_ALL=C TZ=UTC
export KBUILD_BUILD_USER=galwear KBUILD_BUILD_HOST=offline KBUILD_BUILD_VERSION=1
KBUILD_BUILD_TIMESTAMP=$(git -C "$OUT/kernel" show -s --format=%cI "$BASE")
export KBUILD_BUILD_TIMESTAMP
kmake olddefconfig
python3 - "$REPO" "$OUT/obj/.config" "$OUT/initramfs/list.txt" <<'PY'
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]) / "build"))
from r800_android_userspace_preflight import config_check, parse_kernel_config
config = pathlib.Path(sys.argv[2])
values = parse_kernel_config(config.read_bytes())
if config_check(config)["missing_or_wrong"]:
    raise SystemExit("required Android kernel configuration changed after olddefconfig")
if values.get("CONFIG_INITRAMFS_SOURCE") != '"' + sys.argv[3] + '"':
    raise SystemExit("initramfs source lost during olddefconfig")
PY
kmake Image
IMAGE=$OUT/obj/arch/arm64/boot/Image
[ -s "$IMAGE" ] || { echo "kernel Image missing" >&2; exit 1; }
sha256sum "$REPO/src/kernel/r800-wearos.patch" "$REPO/src/kernel/r800.config" \
    "$OUT/obj/.config" "$OUT/initramfs/init" "$IMAGE" > "$OUT/build-sha256.txt"
clang --version > "$OUT/toolchain.txt"
ld.lld --version >> "$OUT/toolchain.txt"
printf 'NON-RELEASE kernel candidate: %s\n' "$IMAGE"
printf 'Kernel compiled only; not a boot image, not validated for flashing.\n'
