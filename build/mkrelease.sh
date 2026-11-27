#!/bin/sh
# NON-RELEASE offline assembly, never writes a device or the input release tree.
# Usage: sh build/mkrelease.sh <release-tree> <new-work-dir>
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 <release tree> <new work dir>" >&2; exit 2; }
REL=$(CDPATH= cd -- "$1" && pwd)
W=$2
[ ! -e "$W" ] && [ ! -L "$W" ] || { echo "work directory must not exist" >&2; exit 2; }
PARENT=$(CDPATH= cd -- "$(dirname -- "$W")" && pwd)
W=$PARENT/$(basename -- "$W")
case "$W/" in "$REL/"*) echo "work must be outside release tree" >&2; exit 2;; esac
[ "$(id -u)" -eq 0 ] || { echo "root required for local loop mounts" >&2; exit 2; }
for tool in python3 tar mount umount mountpoint e2fsck resize2fs mke2fs sha256sum md5sum; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 127; }
done
I=$REL/images
COMBO=$I/samsung/COMBINATION-FT40_R800XXU1ARI2_noCM.tar.md5
AUDIT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/../installer/r800_build_provenance.py
mkdir -- "$W"
mkdir -- "$W/combo" "$W/out" "$W/mnt"
O=$W/out; M=$W/mnt
cleanup() {
    rc=$?
    if mountpoint -q "$M"; then umount -- "$M" || rc=1; fi
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

python3 "$AUDIT" preflight --release-tree "$REL" --report "$W/r800-build-inputs.json"
# Extract only required known inputs; never unpack unneeded combination entries.
tar -C "$W/combo" -xf "$COMBO" csc.img user.img \
    dzImage-recovery sboot.bin param.bin ramdisk.img ramdisk-recovery.img \
    system-data.img nad_refer.bin nad_fw.bin

# e2fsck 0=clean, 1=corrected; every other exit is a hard failure.
repair() {
    rc=0
    e2fsck -fy "$1" || rc=$?
    case "$rc" in 0|1) ;; *) echo "e2fsck failed: $rc" >&2; return 1;; esac
}
grow() {
    input=$1; limit=$2; output=$3
    n=$(( $(stat -c %s "$input") - 272 ))
    [ "$n" -gt 2048 ] && [ "$n" -le "$limit" ] || { echo "ext4 input exceeds build size" >&2; return 1; }
    head -c "$n" "$input" > "$output"
    repair "$output"
    truncate -s "$limit" "$output"
    resize2fs "$output"
    e2fsck -fn "$output"
}
# Historical build sizes, not a verified PIT.
P15_BYTES=100663296
P17_BYTES=1918369792
P18_BYTES=268435456
[ "$(stat -c %s "$I/boot/r800-boot.img")" -eq 18874368 ] || { echo "unexpected boot candidate size" >&2; exit 2; }
[ "$(stat -c %s "$I/vendor.img")" -lt "$P15_BYTES" ] || { echo "vendor exceeds CSC budget" >&2; exit 2; }
[ "$(stat -c %s "$I/payload.tar")" -lt "$P17_BYTES" ] || { echo "payload exceeds USER budget" >&2; exit 2; }

grow "$W/combo/csc.img" "$P15_BYTES" "$O/csc.img"
mount -t ext4 -o loop,nodev,nosuid,noexec "$O/csc.img" "$M"
[ ! -e "$M/r800-android" ] && [ ! -L "$M/r800-android" ] || { echo "unexpected existing CSC payload" >&2; exit 2; }
mkdir "$M/r800-android"
cp "$I/vendor.img" "$M/r800-android/vendor.img"
chmod 755 "$M/r800-android"; chmod 644 "$M/r800-android/vendor.img"
sync; umount "$M"
e2fsck -fn "$O/csc.img"

grow "$W/combo/user.img" "$P17_BYTES" "$O/user.img"
mount -t ext4 -o loop,nodev,nosuid,noexec "$O/user.img" "$M"
[ ! -e "$M/r800dev" ] && [ ! -L "$M/r800dev" ] || { echo "unexpected existing USER payload" >&2; exit 2; }
tar -C "$M" -xf "$I/payload.tar"
sync; umount "$M"
e2fsck -fn "$O/user.img"

truncate -s "$P18_BYTES" "$O/rootfs.img"
mke2fs -q -t ext4 -b 4096 -L r800data -O ^metadata_csum,^64bit,^orphan_file "$O/rootfs.img"
e2fsck -fn "$O/rootfs.img"

# Keep the reference recovery and bootloader components byte-identical.
cp "$I/boot/r800-boot.img" "$O/dzImage"
for f in dzImage-recovery sboot.bin param.bin ramdisk.img ramdisk-recovery.img system-data.img nad_refer.bin nad_fw.bin; do
    cp "$W/combo/$f" "$O/$f"
done
[ "$(stat -c %s "$O/csc.img")" -eq "$P15_BYTES" ]
[ "$(stat -c %s "$O/user.img")" -eq "$P17_BYTES" ]
[ "$(stat -c %s "$O/rootfs.img")" -eq "$P18_BYTES" ]

# Candidate stays explicitly incomplete until all offline gates succeed.
PKG=$W/R800-WearOS.incomplete.tar.md5
( cd "$O" && tar --format=ustar -cf "$W/R800-WearOS.tar" \
    sboot.bin param.bin dzImage dzImage-recovery ramdisk.img ramdisk-recovery.img \
    rootfs.img system-data.img user.img csc.img nad_refer.bin nad_fw.bin )
cp "$W/R800-WearOS.tar" "$PKG"
sum=$(md5sum "$W/R800-WearOS.tar")
printf '%s  R800-WearOS.tar\n' "$(printf '%s' "$sum" | cut -d' ' -f1)" >> "$PKG"
python3 "$AUDIT" finalize --release-tree "$REL" \
    --input-manifest "$W/r800-build-inputs.json" --package "$PKG" \
    --report "$W/R800-WearOS.build-evidence.json"
mv -- "$PKG" "$W/R800-WearOS.NON-RELEASE.tar.md5"
sha256sum "$W/R800-WearOS.NON-RELEASE.tar.md5"
echo "Offline structural candidate only; PIT and S-Boot compatibility NOT verified."
echo "safe_to_flash=false"
