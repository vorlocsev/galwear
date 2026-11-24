#!/bin/sh
# Build the one-shot install package: Samsung's combination firmware with the
# Wear OS partitions swapped in, flashed with installer/netodin.py in the
# watch's Download (Wireless) mode.
#
#   build/mkrelease.sh <release tree> <work dir>
#
# Run as root in WSL/Linux (loop mounts). Inputs, all under <release>/images/:
#   samsung/COMBINATION-FT40_R800XXU1ARI2_noCM.tar.md5   Samsung combination firmware
#   boot/r800-boot.img     kernel + initramfs + DTB (NZIT), for p11 and p12
#   vendor.img             Android vendor partition image (lives on p15)
#   payload.tar            r800dev/ tree for p17 (build/mkpayload-release.sh)
# Output: <release>/images/R800-WearOS.tar.md5
#
# Partitions written (netodin's PIT map): p11 dzImage, p12 dzImage-recovery,
# p15 csc.img, p17 user.img, p18 rootfs.img, plus the combination's own
# sboot, param, ramdisks, system-data (p16) and NAD. The factory CSA (p1:
# Bluetooth/Wi-Fi addresses) and CM (p10) are never written.
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 <release tree> <work dir>"; exit 2; }
REL=$1; W=$2
# Later loop/mount commands in this legacy script are not fully quoted.
# Refuse unsupported whitespace in paths instead of silently writing elsewhere.
case "$REL:$W" in
    *" "*|*"	"*) echo "release/work paths must not contain whitespace"; exit 2;;
esac
I=$REL/images
[ -f "$I/payload.tar" ] && [ -f "$I/vendor.img" ] && [ -f "$I/boot/r800-boot.img" ] || {
    echo "usage: $0 <release tree> <work dir> (images/ incomplete)"; exit 2; }
COMBO=$I/samsung/COMBINATION-FT40_R800XXU1ARI2_noCM.tar.md5
SIG=272      # Samsung signature block appended to each image
mkdir -p "$W/combo" "$W/out" "$W/mnt"

# Fail before extracting archives or mounting loop devices. The manifest is a
# SHA-256 snapshot for later comparison, NOT proof of Samsung/Google provenance.
AUDIT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/../installer/r800_build_provenance.py
python3 "$AUDIT" preflight --release-tree "$REL" \
    --report "$W/r800-build-inputs.json"

# Never reuse an unpacked combination cache from an older firmware build.
tar -C "$W/combo" -xf "$COMBO"
O=$W/out; M=$W/mnt

# ext4 image of the combination, without its signature, grown to $2 bytes
grow() { # <combo image> <bytes> <out>
    n=$(( $(stat -c %s $1) - SIG ))
    head -c $n $1 > $3
    truncate -s $2 $3
    e2fsck -fy $3 > /dev/null 2>&1 || true
    resize2fs $3 > /dev/null
}
P17_BYTES=1918369792   # SM-R800 USER partition (p17)

# p15: Tizen's CSC files + r800-android/vendor.img (start.sh mounts p15 to find it)
grow $W/combo/csc.img $(( 96 * 1048576 )) $O/csc.img
mount -o loop $O/csc.img $M
mkdir -p $M/r800-android
cp $I/vendor.img $M/r800-android/vendor.img
chmod 755 $M/r800-android; chmod 644 $M/r800-android/vendor.img
umount $M

# p17: Tizen's /opt/usr + the r800dev payload, at the full partition size (it
# cannot be grown online: Android keeps it mounted and bound several times).
grow $W/combo/user.img $P17_BYTES $O/user.img
mount -o loop $O/user.img $M
rm -rf $M/r800dev
tar -C $M -xf $I/payload.tar
sync; umount $M
e2fsck -fy $O/user.img > /dev/null 2>&1 || true

# p18: blank ext4 for Android's /data, labelled r800data (start.sh looks for
# the label). 256 MB here; the helper grows it to the whole partition.
rm -f $O/rootfs.img
truncate -s 256M $O/rootfs.img
mke2fs -q -t ext4 -b 4096 -L r800data -O ^metadata_csum,^64bit,^orphan_file $O/rootfs.img

# p11: our kernel image. p12 keeps Samsung's recovery kernel: the bootloader's
# "Download (Wireless)" boots p12 (+ ramdisk-recovery) to run the Wi-Fi Odin
# server, so with our kernel there it just booted Wear OS and the watch could
# no longer be flashed over Wi-Fi (2026-11-20).
cp $I/boot/r800-boot.img $O/dzImage

# Samsung's other partitions unchanged
for f in dzImage-recovery sboot.bin param.bin ramdisk.img ramdisk-recovery.img system-data.img nad_refer.bin nad_fw.bin; do
    cp $W/combo/$f $O/$f
done

# Odin package: ustar archive + "md5  name.tar" trailer
PKG=$I/R800-WearOS.tar.md5
( cd $O && tar --format=ustar -cf $W/R800-WearOS.tar \
    sboot.bin param.bin dzImage dzImage-recovery ramdisk.img ramdisk-recovery.img \
    rootfs.img system-data.img user.img csc.img nad_refer.bin nad_fw.bin )
cp $W/R800-WearOS.tar $PKG
echo "$(md5sum $W/R800-WearOS.tar | cut -d' ' -f1)  R800-WearOS.tar" >> $PKG

# Hash all inputs again and verify the actual output/recovery against the
# reference before marking the local build structurally complete.
python3 "$AUDIT" finalize --release-tree "$REL" \
    --input-manifest "$W/r800-build-inputs.json" \
    --report "$I/R800-WearOS.build-evidence.json"
ls -l $O
echo "package: $(du -h $PKG | cut -f1) -> $PKG"
