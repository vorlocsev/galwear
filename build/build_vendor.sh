#!/usr/bin/env bash
# NON-RELEASE vendor candidate. Use only trusted local donor files.
# Usage: bash build/build_vendor.sh <base-vendor.img> <j4-vendor.img> <overlay-dir> <libeffectsconfig.so> <new-work-dir>
set -Eeuo pipefail
[[ $# == 5 ]] || { echo "usage: $0 <base-vendor.img> <j4-vendor.img> <overlay-dir> <libeffectsconfig.so> <new-work-dir>" >&2; exit 2; }
REPO=$(cd -- "$(dirname -- "$0")/.." && pwd)
SRC=$(realpath -e -- "$1"); J4=$(realpath -e -- "$2"); S=$(realpath -e -- "$3"); EFFECTS=$(realpath -e -- "$4")
WORK=$5
[[ ! -e "$WORK" && ! -L "$WORK" ]] || { echo "work directory must not exist" >&2; exit 2; }
WORK=$(realpath -m -- "$WORK")
# Historical copy lists use unquoted expansions; refuse whitespace and shell metacharacters.
for p in "$SRC" "$J4" "$S" "$EFFECTS" "$WORK"; do
    [[ "$p" =~ ^/[A-Za-z0-9_./+-]+$ ]] || { echo "unsupported build path: $p" >&2; exit 2; }
done
[[ "$WORK/" != "$S/"* && "$WORK/" != "$REPO/"* ]] || { echo "work must be outside source trees" >&2; exit 2; }
[[ $EUID == 0 ]] || { echo "root required for isolated loop mounts" >&2; exit 2; }
for tool in python3 tar mount umount mountpoint llvm-readelf setfattr getfattr mkfs.ext4 e2fsck sha256sum; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 127; }
done
mkdir -- "$WORK"
python3 "$REPO/build/r800_vendor_inputs.py" --base "$SRC" --j4 "$J4" --overlay "$S" --effects "$EFFECTS" > "$WORK/input-evidence.json"
OUT=$WORK/tree; BASE_MNT=$WORK/base; J4_MNT=$WORK/j4; DST_MNT=$WORK/dst
IMAGE=$WORK/vendor.incomplete.img
mkdir -- "$OUT" "$BASE_MNT" "$J4_MNT" "$DST_MNT"
cleanup() {
    rc=$?
    cd /
    for m in "$DST_MNT" "$J4_MNT" "$BASE_MNT"; do
        if mountpoint -q "$m"; then umount -- "$m" || rc=1; fi
    done
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mount -t ext4 -o loop,ro,noload,nodev,nosuid,noexec "$SRC" "$BASE_MNT"
mount -t ext4 -o loop,ro,noload,nodev,nosuid,noexec "$J4" "$J4_MNT"
cd "$BASE_MNT"
# keep: policy, vintf, permissions, props, uid tables, codecs; vndservicemanager; generic gralloc
tar --xattrs --xattrs-include='*' -cf - \
  ./etc/selinux ./etc/vintf ./etc/fs_config_dirs ./etc/fs_config_files ./etc/group ./etc/passwd \
  ./etc/seccomp_policy ./etc/permissions ./etc/media_codecs.xml ./etc/media_codecs_google_audio.xml \
  ./etc/media_codecs_google_telephony.xml ./etc/media_profiles_vendor.xml \
  ./etc/init/vndservicemanager.rc ./bin/vndservicemanager ./lib/hw/gralloc.default.so \
  ./default.prop ./build.prop ./lib/hw/android.hardware.graphics.mapper@2.0-impl.so \
  ./lib/hw/android.hardware.graphics.allocator@2.0-impl.so \n  ./bin/hw/android.hardware.configstore@1.1-service ./etc/init/android.hardware.configstore@1.1-service.rc ./lib/libhwminijail.so \n  ./bin/hw/android.hardware.power@1.0-service ./etc/init/android.hardware.power@1.0-service.rc \n  ./lib/hw/android.hardware.power@1.0-impl.so ./lib/hw/power.default.so \n  ./bin/hw/android.hardware.health@2.0-service ./etc/init/android.hardware.health@2.0-service.rc \n  ./bin/hw/android.hardware.graphics.allocator@2.0-service ./etc/init/android.hardware.graphics.allocator@2.0-service.rc \n  ./etc/seccomp_policy | tar --xattrs --xattrs-include='*' -C $OUT -xpf -
# vndservicemanager deps that live in vendor/lib
deps=$(llvm-readelf -d bin/vndservicemanager | sed -n 's/.*Shared library: \[\(.*\)\]/\1/p')
for lib in $deps; do
  [[ "$lib" =~ ^[A-Za-z0-9_.+~-]+$ && "$lib" != . && "$lib" != .. ]] || { echo "invalid DT_NEEDED name" >&2; exit 2; }
  if [ -f "lib/$lib" ]; then
    mkdir -p "$OUT/lib"
    tar --xattrs --xattrs-include='*' -cf - "./lib/$lib" | tar --xattrs --xattrs-include='*' -C "$OUT" -xpf -
    echo "dep: $lib (vendor)"
  else
    echo "UNVERIFIED external dependency: $lib (system/vndk)"
  fi
done
cd /
# ---- J4 (SM-J400F, Android 9) graphics: Mali r28p0 + Samsung gralloc + composer service (fb adapter path) ----
rm -f $OUT/lib/hw/gralloc.default.so $OUT/lib/hw/android.hardware.graphics.allocator@2.0-impl.so $OUT/lib/hw/android.hardware.graphics.mapper@2.0-impl.so       $OUT/bin/hw/android.hardware.graphics.allocator@2.0-service $OUT/etc/init/android.hardware.graphics.allocator@2.0-service.rc
( cd $J4_MNT && tar --xattrs --xattrs-include='*' -cf -   ./lib/egl/libGLES_mali.so ./lib/hw/gralloc.exynos5.so   ./lib/hw/android.hardware.graphics.allocator@2.0-impl.so ./lib/hw/android.hardware.graphics.mapper@2.0-impl.so   ./lib/hw/android.hardware.graphics.composer@2.1-impl.so ./lib/libhwc2on1adapter.so ./lib/libhwc2onfbadapter.so   ./lib/libion_exynos.so ./lib/hw/memtrack.universal7570.so ./lib/hw/android.hardware.memtrack@1.0-impl.so   ./bin/hw/android.hardware.graphics.allocator@2.0-service ./bin/hw/android.hardware.graphics.composer@2.1-service   ./bin/hw/android.hardware.memtrack@1.0-service   ./etc/init/android.hardware.graphics.allocator@2.0-service.rc ./etc/init/android.hardware.graphics.composer@2.1-service.rc   ./etc/init/android.hardware.memtrack@1.0-service.rc ) | tar --xattrs --xattrs-include='*' -C $OUT -xpf -
# ---- keymaster 3.0 + gatekeeper (keystore aborts without them) ----
for f in \
    ./bin/hw/android.hardware.keymaster@3.0-service \
    ./bin/hw/android.hardware.gatekeeper@1.0-service \
    ./etc/init/android.hardware.keymaster@3.0-service.rc \
    ./etc/init/android.hardware.gatekeeper@1.0-service.rc \
    ./lib/hw/android.hardware.keymaster@3.0-impl.so \
    ./lib/hw/android.hardware.gatekeeper@1.0-impl.so \
    ./lib/hw/gatekeeper.exynos7570.so \
    ./lib/android.hardware.keymaster@3.0.so \
    ./lib/android.hardware.gatekeeper@1.0.so \
    ./lib/libsoftkeymasterdevice.so \
    ./lib/libkeymaster_portable.so \
    ./lib/libpuresoftkeymasterdevice.so \
    ./lib/libkeymaster3device.so \
    ./lib/libskeymaster3device.so ; do
    if [ -e "$J4_MNT/$f" ]; then
        tar --xattrs --xattrs-include='*' -C $J4_MNT -cf - "$f" | tar --xattrs --xattrs-include='*' -C $OUT -xpf -
        echo "km: $f"
    else
        echo "km: MISSING required component $f" >&2; exit 2
    fi
done
for f in $OUT/etc/init/android.hardware.keymaster@3.0-service.rc \
         $OUT/etc/init/android.hardware.gatekeeper@1.0-service.rc ; do
    if [ -e "$f" ]; then
        setfattr -n security.selinux -v u:object_r:vendor_configs_file:s0 "$f"
    fi
done

# ---- audio HAL 2.0 (audioserver aborts without it; system_server waits on audio_policy) ----
for f in \
    ./bin/hw/android.hardware.audio@2.0-service \
    ./etc/init/android.hardware.audio@2.0-service.rc \
    ./lib/hw/android.hardware.audio@2.0-impl.so \
    ./lib/hw/android.hardware.audio.effect@2.0-impl.so \
    ./lib/hw/audio.primary.universal7570.so \
    ./lib/hw/audio.primary.default.so \
    ./lib/hw/audio.r_submix.default.so \
    ./lib/hw/audio.usb.default.so \
    ./lib/android.hardware.audio@2.0.so \
    ./lib/android.hardware.audio@4.0.so \
    ./lib/android.hardware.audio.common@2.0.so \
    ./lib/android.hardware.audio.common@4.0.so \
    ./lib/android.hardware.audio.common@2.0-util.so \
    ./lib/android.hardware.audio.common-util.so \
    ./lib/android.hardware.audio.effect@2.0.so \
    ./lib/android.hardware.audio.effect@4.0.so \
    ./lib/android.hardware.bluetooth.a2dp@1.0.so \
    ./lib/android.hardware.soundtrigger@2.0.so \
    ./lib/android.hardware.soundtrigger@2.1.so \
    ./lib/libfmq.so ; do
    if [ -e "$J4_MNT/$f" ]; then
        tar --xattrs --xattrs-include='*' -C $J4_MNT -cf - "$f" | tar --xattrs --xattrs-include='*' -C $OUT -xpf -
        echo "audio: $f"
    else
        echo "audio: MISSING required component $f" >&2; exit 2
    fi
done
if [ -e "$OUT/etc/init/android.hardware.audio@2.0-service.rc" ]; then
    setfattr -n security.selinux -v u:object_r:vendor_configs_file:s0 "$OUT/etc/init/android.hardware.audio@2.0-service.rc"
fi

# ---- Samsung audio HAL support libs (needed by audio.primary.universal7570) ----
for f in \
    ./lib/libtinycompress.so \
    ./lib/libtinyalsa.so \
    ./lib/libaudioroute.so \
    ./lib/libfloatingfeature.so \
    ./lib/libsecaudioinfo.so \
    ./lib/libsamsungDiamondVoice.so \
    ./lib/librecordalive.so \
    ./lib/libpreprocessing_nxp.so \
    ./lib/libSamsungPostProcessConvertor.so \
    ./lib/libaudio-ril.so \
    ./lib/libvndsecril-client.so ./lib/libeffects.so ; do
    if [ -e "$J4_MNT/$f" ]; then
        tar --xattrs --xattrs-include='*' -C $J4_MNT -cf - "$f" | tar --xattrs --xattrs-include='*' -C $OUT -xpf -
        echo "audiolib: $f"
    else
        echo "audiolib: MISSING required component $f" >&2; exit 2
    fi
done

cp "$EFFECTS" "$OUT/lib/libeffectsconfig.so"
setfattr -n security.selinux -v u:object_r:vendor_file:s0 "$OUT/lib/libeffectsconfig.so"

# Legacy HIDL 1.0 wrappers must come from one complete donor per subsystem.
# Do not substitute a differently versioned or vendor-specific service silently.
copy_hidl_group() {
    local group=$1 donor f complete
    shift
    for donor in "$BASE_MNT" "$J4_MNT"; do
        complete=1
        for f in "$@"; do
            [[ -f "$donor/$f" && ! -L "$donor/$f" ]] || { complete=0; break; }
        done
        if [[ $complete == 1 ]]; then
            for f in "$@"; do
                tar --xattrs --xattrs-include='*' -C "$donor" -cf - "$f" |
                    tar --xattrs --xattrs-include='*' -C "$OUT" -xpf -
            done
            printf '%s donor=%s\n' "$group" "$(basename "$donor")" >> "$WORK/hidl-donors.txt"
            return 0
        fi
    done
    echo "Missing complete HIDL 1.0 donor group: $group" >&2
    printf '  %s\n' "$@" >&2
    return 2
}
copy_hidl_group sensors \
    ./bin/hw/android.hardware.sensors@1.0-service \
    ./lib/hw/android.hardware.sensors@1.0-impl.so \
    ./lib/android.hardware.sensors@1.0.so
copy_hidl_group gnss \
    ./bin/hw/android.hardware.gnss@1.0-service \
    ./etc/init/android.hardware.gnss@1.0-service.rc \
    ./lib/hw/android.hardware.gnss@1.0-impl.so \
    ./lib/android.hardware.gnss@1.0.so
cp "$S/sensors/android.hardware.sensors@1.0-service.rc" "$OUT/etc/init/"
setfattr -n security.selinux -v u:object_r:vendor_configs_file:s0 \
    "$OUT/etc/init/android.hardware.sensors@1.0-service.rc"
for group in sensors gnss; do
    for binary in "$OUT/bin/hw/android.hardware.$group@1.0-service" \
                  "$OUT/lib/hw/android.hardware.$group@1.0-impl.so"; do
        llvm-readelf -h "$binary" | grep -Eq 'Class:[[:space:]]*ELF32'
        llvm-readelf -h "$binary" | grep -Eq 'Machine:[[:space:]]*ARM'
        llvm-readelf -d "$binary" >> "$WORK/hidl-dependencies.txt"
    done
done

# ---- bluetooth HAL (crash loop without it: btHci == nullptr) ----
for f in \
    ./bin/hw/android.hardware.bluetooth@1.0-service \
    ./etc/init/android.hardware.bluetooth@1.0-service.rc \
    ./lib/hw/android.hardware.bluetooth@1.0-impl.so \
    ./lib/libbt-vendor.so \
    ./lib/vendor.samsung.hardware.bluetooth@1.0.so ; do
    if [ -e "$J4_MNT/$f" ]; then
        tar --xattrs --xattrs-include='*' -C $J4_MNT -cf - "$f" | tar --xattrs --xattrs-include='*' -C $OUT -xpf -
        echo "bt: $f"
    else
        echo "bt: MISSING required component $f" >&2; exit 2
    fi
done
if [ -e "$OUT/etc/init/android.hardware.bluetooth@1.0-service.rc" ]; then
    setfattr -n security.selinux -v u:object_r:vendor_configs_file:s0 "$OUT/etc/init/android.hardware.bluetooth@1.0-service.rc"
fi

cat >> $OUT/build.prop <<'P2'
# ---- graphics: J4 Mali-T720 r28p0 + Samsung gralloc, framebuffer composer (no hwcomposer module) ----
ro.hardware.egl=mali
ro.hardware.gralloc=exynos5
ro.hardware.memtrack=universal7570
ro.opengles.version=196609
debug.sf.hw=1
P2

# our files
cp $S/etc/init/init.r800.rc $OUT/etc/init/; cp $S/etc/fstab.r800 $OUT/etc/; cp $S/ueventd.rc $OUT/
cp $S/etc/vintf/manifest.xml $OUT/etc/vintf/manifest.xml
# our HWC 1.1 module (client composition -> fb0 copy + pan), built with the NDK
for module in hwcomposer.r800.so audio.primary.r800.so gps.r800.so sensors.r800.so; do
    cp "$S/$module" "$OUT/lib/hw/$module"
    chmod 644 "$OUT/lib/hw/$module"
    setfattr -n security.selinux -v u:object_r:vendor_file:s0 "$OUT/lib/hw/$module"
done
cp "$S/audio/audio_policy_configuration.xml" "$OUT/etc/audio_policy_configuration.xml"
chmod 644 "$OUT/etc/audio_policy_configuration.xml"
setfattr -n security.selinux -v u:object_r:vendor_configs_file:s0 "$OUT/etc/audio_policy_configuration.xml"
# Remove donor duplicates before setting the legacy primary module.
sed -i '/^ro.hardware.audio.primary=/d' "$OUT/build.prop" "$OUT/default.prop"
printf 'ro.hardware.hwcomposer=r800
' >> $OUT/build.prop
# lights: Samsung light service + HIDL impl from J4, our legacy module for exynos_panel
( cd $J4_MNT && tar --xattrs --xattrs-include='*' -cf - ./bin/hw/vendor.samsung.hardware.light@2.0-service ./etc/init/vendor.samsung.hardware.light@2.0-service.rc ./lib/hw/vendor.samsung.hardware.light@2.0-impl.so ./lib/vendor.samsung.hardware.light@2.0.so ) | tar --xattrs --xattrs-include='*' -C $OUT -xpf -
cp $S/lights.r800.so $OUT/lib/hw/lights.r800.so
setfattr -n security.selinux -v u:object_r:vendor_file:s0 $OUT/lib/hw/lights.r800.so
printf 'ro.hardware.lights=r800
' >> $OUT/build.prop
setfattr -n security.selinux -v u:object_r:vendor_configs_file:s0 $OUT/etc/vintf/manifest.xml
setfattr -n security.selinux -v u:object_r:vendor_configs_file:s0 $OUT/etc/init/init.r800.rc $OUT/etc/fstab.r800 $OUT/ueventd.rc
setfattr -n security.selinux -v u:object_r:vendor_file:s0 $OUT
# where bcmdhd looks if Wi-Fi is used later (driver prefixes /vendor): /vendor/data/r800dev/fw
mkdir -p $OUT/data/r800dev/fw
# props: identify as our device, keep the Wear OS characteristics
cat >> $OUT/build.prop <<'P'

# ---- SM-R800 bring-up overrides ----
ro.board.platform=exynos9110
persist.sys.dalvik.vm.lib.2=libart.so
# no GPU driver yet: do not preload EGL in zygote (it aborts when none is found)
ro.zygote.disable_gl_preload=true
ro.hardware.audio.primary=r800
ro.hardware.gps=r800
ro.hardware.sensors=r800
P
# identity: this is a Galaxy Watch, not the TicWatch the images came from
sed -i -e 's/^ro.product.vendor.model=.*/ro.product.vendor.model=Galaxy Watch/'        -e 's/^ro.product.vendor.brand=.*/ro.product.vendor.brand=samsung/'        -e 's/^ro.product.vendor.manufacturer=.*/ro.product.vendor.manufacturer=Samsung/' $OUT/build.prop
du -sh $OUT; find $OUT -type f | wc -l
# image: 64 MiB ext4, keep xattrs
truncate -s 64M "$IMAGE"
mkfs.ext4 -q -b 4096 -m 0 -I 256 -O ^metadata_csum,^64bit -L vendor $IMAGE
mount -t ext4 -o loop,nodev,nosuid,noexec "$IMAGE" "$DST_MNT"
tar --xattrs --xattrs-include='*' -C $OUT -cf - . | tar --xattrs --xattrs-include='*' -C $DST_MNT -xpf -
setfattr -n security.selinux -v u:object_r:vendor_file:s0 $DST_MNT
# label anything that came out unlabeled (dirs created by tar, our new dirs)
find "$DST_MNT" -path "$DST_MNT/lost+found" -prune -o -print0 | while IFS= read -r -d "" f; do
    getfattr -h -n security.selinux "$f" >/dev/null 2>&1 || setfattr -h -n security.selinux -v u:object_r:vendor_file:s0 "$f"
done
find "$DST_MNT" -path "$DST_MNT/lost+found" -prune -o -print0 | while IFS= read -r -d "" f; do
    getfattr -h -n security.selinux "$f" >/dev/null || { echo "missing SELinux label: $f" >&2; exit 2; }
done
echo "label check: $(getfattr -n security.selinux --only-values $DST_MNT/bin/vndservicemanager) / $(getfattr -n security.selinux --only-values $DST_MNT/etc/init/init.r800.rc) / $(getfattr -n security.selinux --only-values $DST_MNT/etc/selinux/precompiled_sepolicy)"
ls $DST_MNT $DST_MNT/etc $DST_MNT/etc/init
umount "$DST_MNT"
e2fsck -fn "$IMAGE"
python3 "$REPO/build/r800_vendor_inputs.py" --base "$SRC" --j4 "$J4" --overlay "$S" --effects "$EFFECTS" > "$WORK/input-evidence-after.json"
cmp "$WORK/input-evidence.json" "$WORK/input-evidence-after.json"
umount "$J4_MNT"
umount "$BASE_MNT"
mv -- "$IMAGE" "$WORK/vendor.candidate.img"
IMAGE=$WORK/vendor.candidate.img
sha256sum "$IMAGE" > "$WORK/vendor-sha256.txt"
echo "NON-RELEASE vendor candidate: $IMAGE"
echo "HAL compatibility and SELinux policy not verified; safe_to_flash=false"
