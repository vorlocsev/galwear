#!/bin/sh
# Disposable generic virt build from the patched pinned R800 source.
# NOT a SM-R800 kernel or firmware image.
set -eu
[ "$#" -eq 4 ] || [ "$#" -eq 5 ] || { echo "usage: $0 <source> <repo> <new-out> <initramfs.list> [minimal|property]" >&2; exit 2; }
SOURCE=$1
REPO=$2
OUT=$3
LIST=$4
PROFILE=${5:-minimal}
case "$PROFILE" in minimal|property) ;; *) exit 2;; esac
BASE=50db73fc799f20a7120a8b5f653b16cc123d856f
[ ! -e "$OUT" ]
[ "$(git -C "$SOURCE" rev-parse HEAD)" = "$BASE" ]
[ -z "$(git -C "$SOURCE" status --porcelain)" ]
case "$LIST" in /*/initramfs.list) ;; *) exit 2;; esac
[ -f "$LIST" ]
clang-19 --version | grep -q 'version 19\.1\.4'
ld.lld --version | grep -q 'LLD 19\.1\.4'
export PATH=/usr/lib/llvm19/bin:$PATH
export ARCH=arm64 LLVM=1 LLVM_IAS=1 CC=clang-19 HOSTCC=clang-19 LD=ld.lld
export AR=llvm-ar NM=llvm-nm OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump STRIP=llvm-strip
export CLANG_TRIPLE=aarch64-linux-gnu- CROSS_COMPILE=aarch64-linux-gnu-
export KBUILD_BUILD_USER=galwear-ci KBUILD_BUILD_HOST=github-actions KBUILD_BUILD_VERSION=1
export KBUILD_BUILD_TIMESTAMP="Thu Jan  1 00:00:00 UTC 1970" SOURCE_DATE_EPOCH=0
git -C "$SOURCE" apply --check "$REPO/src/kernel/r800-wearos.patch"
git -C "$SOURCE" apply "$REPO/src/kernel/r800-wearos.patch"
mkdir -p "$OUT"
if [ "$PROFILE" = property ]; then
    sed '/^# CONFIG_NET is not set$/d; /^CONFIG_PROC_FS=y$/d; /^CONFIG_SYSFS=y$/d' "$REPO/src/kernel/qemu-virt-minimal.config" > "$OUT/virt.config"
    cat "$REPO/src/kernel/qemu-virt-property.config" >> "$OUT/virt.config"
else
    cp "$REPO/src/kernel/qemu-virt-minimal.config" "$OUT/virt.config"
fi
printf 'CONFIG_INITRAMFS_SOURCE="%s"\n' "$LIST" >> "$OUT/virt.config"
make -C "$SOURCE" O="$OUT" KCONFIG_ALLCONFIG="$OUT/virt.config" allnoconfig
make -C "$SOURCE" O="$OUT" olddefconfig
python3 "$REPO/build/r800_qemu_virt_contract.py" --profile "$PROFILE" --config "$OUT/.config" --list "$LIST" --report "$OUT/virt-config-evidence.json"
make -C "$SOURCE" O="$OUT" -j2 Image
python3 "$REPO/build/r800_qemu_virt_contract.py" --profile "$PROFILE" --config "$OUT/.config" --list "$LIST" --report "$OUT/virt-config-evidence.json"
python3 "$REPO/build/r800_cpio_audit.py" --archive "$OUT/usr/initramfs_data.cpio" --init "$(dirname "$LIST")/init" --report "$OUT/virt-cpio-evidence.json"
test -s "$OUT/arch/arm64/boot/Image"
sha256sum "$OUT/arch/arm64/boot/Image"

# Bind the effective-config evidence to the exact raw Image just compiled.
python3 - "$OUT/virt-config-evidence.json" "$OUT/arch/arm64/boot/Image" <<'PY'
import hashlib, json, pathlib, sys
report, image = map(pathlib.Path, sys.argv[1:])
data = json.loads(report.read_text())
data["compiled_kernel_sha256"] = hashlib.sha256(image.read_bytes()).hexdigest()
report.write_text(json.dumps(data, indent=2) + "\n")
PY
