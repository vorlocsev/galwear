#!/system/bin/sh
# Prepare a Tizen chroot for foreground sensor/GNSS workers.
# Fail closed on missing or conflicting mounts; never unmount existing paths.
B=/oem/r800dev/bin/busybox
T=/mnt/tz
L=/oem/r800dev/tzlite
P18=/dev/block/mmcblk0p18
P16=/dev/block/mmcblk0p16
MOUNTS=/proc/mounts
# BEGIN TZCHROOT_MOUNT_HELPERS
blocked() {
    printf 'chroot-blocked: %s\n' "$*" >&2
    exit 1
}
require() {
    "$@" || blocked "$*"
}
# Literal target comparison (fixed paths without whitespace); reject stacked
# or ambiguous records instead of choosing a mount by substring.
mounted() {
    "$B" awk -v target="$1" '$2==target { found=1 } END { exit !found }' "$MOUNTS"
}
mount_record() {
    "$B" awk -v target="$1" '
        $2==target { n++; source=$1; type=$3; options=$4 }
        END { if (n!=1) exit 1; print source, type, options }
    ' "$MOUNTS"
}
mount_kind() (
    record=$(mount_record "$1") || exit 1
    wanted=$2
    access=$3
    set -f
    set -- $record
    [ "$#" -eq 3 ] && [ "$2" = "$wanted" ] || exit 1
    case ",$3," in *",$access,"*) exit 0;; *) exit 1;; esac
)
mount_access() (
    record=$(mount_record "$1") || exit 1
    wanted=$2
    set -f
    set -- $record
    [ "$#" -eq 3 ] || exit 1
    case ",$3," in *",$wanted,"*) exit 0;; *) exit 1;; esac
)
same_object() (
    [ -d "$1" ] && [ -d "$2" ] || exit 1
    a=$("$B" stat -L -c '%d:%i' "$1") || exit 1
    b=$("$B" stat -L -c '%d:%i' "$2") || exit 1
    [ "$a" = "$b" ]
)
bind_mount() {
    if ! mounted "$2"; then
        require "$B" mount --bind "$1" "$2"
    fi
    require mount_record "$2" >/dev/null
    require same_object "$1" "$2"
}
tmpfs_mount() {
    if ! mounted "$1"; then
        require "$B" mount -t tmpfs -o "$2" tmpfs "$1"
    fi
    require mount_kind "$1" tmpfs rw
}
block_mount_matches() (
    record=$(mount_record "$1") || exit 1
    device=$2
    access=$3
    set -f
    set -- $record
    [ "$#" -eq 3 ] && [ "$2" = ext4 ] || exit 1
    source=$("$B" readlink -f "$1") || exit 1
    expected=$("$B" readlink -f "$device") || exit 1
    [ -b "$source" ] && [ "$source" = "$expected" ] || exit 1
    case ",$3," in *",$access,"*) exit 0;; *) exit 1;; esac
)
# END TZCHROOT_MOUNT_HELPERS

# tzlite on p17 is preferred. p18 is Android userdata after conversion;
# use p18 only if its ext4 label still identifies Tizen rootfs.
require "$B" mkdir -p "$T"
if [ -x "$L/usr/bin/lhd" ]; then
    if ! mounted "$T"; then
        require "$B" mount --bind "$L" "$T"
        require "$B" mount -o remount,bind,ro "$T"
    fi
    require mount_access "$T" ro
    require same_object "$L" "$T"
elif [ "$("$B" dd if="$P18" bs=1 skip=1144 count=6 2>/dev/null)" = rootfs ]; then
    if ! mounted "$T"; then
        require "$B" mount -o ro -t ext4 "$P18" "$T"
    fi
    require block_mount_matches "$T" "$P18" ro
else
    blocked "no Tizen subset and p18 is not the Tizen rootfs"
fi
[ -x "$T/usr/bin/lhd" ] || blocked "lhd unavailable in mounted root"
for d in dev proc sys; do
    bind_mount "/$d" "$T/$d"
done
bind_mount /dev/pts "$T/dev/pts"
for d in tmp run; do
    tmpfs_mount "$T/$d" size=8m,mode=755
done
if ! mounted "$T/opt"; then
    require "$B" mount -t ext4 -o noatime "$P16" "$T/opt"
fi
require block_mount_matches "$T/opt" "$P16" rw
bind_mount /oem "$T/opt/usr"
require "$B" mkdir -p "$T/tmp/crash_stack"
# Kernel firmware lookup must resolve the same directory in both roots.
tmpfs_mount "$T/mnt" size=1m,mode=755
require "$B" mkdir -p "$T/mnt/r800fw"
bind_mount /oem/r800dev/fw "$T/mnt/r800fw"
require "$B" mkdir -p /mnt/r800fw
bind_mount /oem/r800dev/fw /mnt/r800fw
printf '%s' /mnt/r800fw > /sys/module/firmware_class/parameters/path ||
    blocked "firmware path write failed"
[ "$("$B" cat /sys/module/firmware_class/parameters/path)" = /mnt/r800fw ] ||
    blocked "firmware path readback mismatch"
echo chroot-ready
