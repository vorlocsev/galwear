#!/bin/sh
# Non-release compile smoke test. Only touch a disposable checkout and out-dir.
# Run from Alpine 3.21 with clang19 19.1.4 / lld 19.1.4 installed.
set -eu

[ "$#" -eq 3 ] || {
    echo "usage: sh build/r800_kernel_compile_smoke.sh <disposable-source> <galwear-repo> <out-dir>" >&2
    exit 2
}
SOURCE=$1
REPO=$2
OUT=$3
BASE=50db73fc799f20a7120a8b5f653b16cc123d856f

[ -d "$SOURCE/.git" ] || { echo "No disposable source Git tree"; exit 2; }
[ ! -e "$OUT" ] || { echo "Out directory already exists; refusing overwrite"; exit 2; }
[ "$(git -C "$SOURCE" rev-parse HEAD)" = "$BASE" ] || {
    echo "Source SHA mismatch, no compile"; exit 2;
}
[ -z "$(git -C "$SOURCE" status --porcelain)" ] || {
    echo "Source tree dirty before patch, no compile"; exit 2;
}

# Do not silently use another LLVM major/minor/patch version.
clang-19 --version | grep -q 'version 19\.1\.4'
ld.lld --version | grep -q 'LLD 19\.1\.4'
export PATH=/usr/lib/llvm19/bin:$PATH
for tool in llvm-ar llvm-nm llvm-objcopy llvm-objdump llvm-strip; do
    command -v "$tool" >/dev/null || { echo "Missing $tool"; exit 2; }
done

git -C "$SOURCE" apply --check "$REPO/src/kernel/r800-wearos.patch"
# Writes ONLY into the disposable checkout, never into Galwear or a remote.
git -C "$SOURCE" apply "$REPO/src/kernel/r800-wearos.patch"
# Opt-in experiment: keep the existing IKHEADERS dummy payload but normalize
# its archive metadata only in this pinned disposable source checkout.
if [ "${R800_REPRO_KHEADERS:-0}" = 1 ]; then
    python3 "$REPO/build/r800_kheaders_repro.py" --source "$SOURCE"
fi
mkdir -p "$OUT"
cp "$REPO/src/kernel/r800.config" "$OUT/.config"

# Only the temporary O= config is ever changed. By default this remains
# the previously validated Image-only smoke build. Embedding experimental
# AArch64 /init is an explicit separate, validated CI mode.
if [ -n "${R800_SMOKE_INITRAMFS_LIST:-}" ]; then
    python3 "$REPO/build/r800_embedded_initramfs_config.py" \
        --config "$OUT/.config" \
        --list "$R800_SMOKE_INITRAMFS_LIST" \
        --report "$OUT/embedded-initramfs-gate.json"
else
    python3 - "$OUT/.config" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
old = 'CONFIG_INITRAMFS_SOURCE="/root/initramfs/list.txt"'
if s.count(old) != 1:
    raise SystemExit("Unexpected kernel initramfs source; refusing smoke build")
p.write_text(s.replace(old, 'CONFIG_INITRAMFS_SOURCE=""'))
PY
fi

export KBUILD_BUILD_USER=galwear-ci
export KBUILD_BUILD_HOST=github-actions
export KBUILD_BUILD_TIMESTAMP="Thu Jan  1 00:00:00 UTC 1970"
export KBUILD_BUILD_VERSION=1
export SOURCE_DATE_EPOCH=0
export ARCH=arm64
export LLVM=1
export LLVM_IAS=1
export CC=clang-19
export HOSTCC=clang-19
export LD=ld.lld
export AR=llvm-ar
export NM=llvm-nm
export OBJCOPY=llvm-objcopy
export OBJDUMP=llvm-objdump
export STRIP=llvm-strip
export CLANG_TRIPLE=aarch64-linux-gnu-
export CROSS_COMPILE=aarch64-linux-gnu-

make -C "$SOURCE" O="$OUT" olddefconfig
if [ -n "${R800_SMOKE_INITRAMFS_LIST:-}" ]; then
    # olddefconfig can silently correct invalid options. Confirm the exact
    # validated file is still selected before any kernel compilation.
    grep -Fqx "CONFIG_INITRAMFS_SOURCE=\"$R800_SMOKE_INITRAMFS_LIST\"" "$OUT/.config" || {
        echo "Kernel olddefconfig did not preserve embedded initramfs source"; exit 2;
    }
fi
make -C "$SOURCE" O="$OUT" -j2 Image
test -s "$OUT/arch/arm64/boot/Image" || {
    echo "Kernel Image missing from smoke build"; exit 2;
}

echo "PASS: kernel Image compiled in isolated smoke environment"
if [ -n "${R800_SMOKE_INITRAMFS_LIST:-}" ]; then
    echo "NOTE: experimental initramfs embedded. /init NOT boot-tested; Image is NOT flashable"
    # Linux 4.19 creates a gen_init_cpio archive when embedding user input.
    # The exact archive filename is compression-dependent; require evidence
    # of generated initramfs data, not merely a Kconfig path.
    CPIO="$OUT/usr/initramfs_data.cpio.gz"
    if [ ! -s "$CPIO" ]; then
        CPIO="$OUT/usr/initramfs_data.cpio"
    fi
    [ -s "$CPIO" ] || { echo "Embedded cpio build artifact not generated"; exit 2; }
    python3 "$REPO/build/r800_cpio_audit.py" \
        --archive "$CPIO" \
        --init "$(dirname "$R800_SMOKE_INITRAMFS_LIST")/init" \
        --report "$OUT/embedded-cpio-audit.json"
else
    echo "NOTE: initramfs disabled in temporary config; image is NOT a flashable release"
fi
sha256sum "$OUT/arch/arm64/boot/Image"
