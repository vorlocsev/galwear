#!/bin/sh
# SM-R800 bring-up userspace, started by /init from p17 (mounted read-only at /data).
B=/data/r800dev/bin/busybox
$B mkdir -p /bin && $B --install -s /bin
export PATH=/bin:/sbin:/data/r800dev/bin
log() { echo "<0>r800-sh: $*" > /dev/kmsg; }
logfile() { while read -r l; do log "$1$l"; done; }
log "start.sh running as pid $"

# Do not fall through to the legacy network/debug path after Android fails.
# PID 1 must remain alive; leave the existing watchdog policy unchanged.
android_abort() {
	log "android: HANDOVER_BLOCKED: $*"
	while :; do "$B" sleep 30; done
}
android_require() {
	stage=$1; shift
	"$@" || android_abort "$stage"
	log "android: $stage OK"
}

# ---- off-mode charging: S-Boot starts the kernel with Tizen's
# "systemd.unit=charging-mode.target" when the watch is off and put on the charger.
# Show the charging screen instead of booting Android (tools/charger; long press =
# boot Wear OS, charger removed = power off). charger/DISABLE turns it off.
CHG=/data/r800dev/charger
if $B grep -q "charging-mode" /proc/cmdline && [ -x $CHG/r800charger ] && [ ! -f $CHG/DISABLE ]; then
	log "charger mode"
	# sensor hub for the screen's rotation (accelerometer): same Tizen chroot +
	# lhd as android-helper.sh, with the paths Android would have (/oem = p17)
	if [ -c /dev/bbd_patch ] && [ -x /data/r800dev/tzchroot.sh ]; then
		[ -e /oem ] || $B ln -s /data /oem
		$B mkdir -p /dev/block
		for p in 16 17 18; do [ -e /dev/block/mmcblk0p$p ] || $B ln -s /dev/mmcblk0p$p /dev/block/mmcblk0p$p; done
		$B sh /data/r800dev/tzchroot.sh 2>&1 | logfile "charger: tzchroot: "
		( while true; do
			$B chroot /mnt/tz /usr/bin/lhd /etc/lhd/lhd.conf > /dev/null 2>&1 < /dev/null
			$B sleep 3
		done ) &
	fi
	exec $CHG/r800charger
fi

# ---- wireless download (Odin over Wi-Fi): S-Boot starts the kernel with
# bootmode=wireless-download (or -upload) after "reboot wdownload" or the
# download key combo. Tizen handled it from its recovery ramdisk (p7), which
# Odin never rewrites for us: run that ramdisk's tool (wirelesstool-init:
# soft AP, then the LOKE protocol on TCP 13579; installer/netodin.py is the PC
# side) in a chroot. It reboots the watch itself after a flash; if it exits
# without one, reboot normally (that also clears the wdownload boot mode).
WDM=$($B sed -n 's/.*bootmode=\(wireless-[a-z]*\).*/\1/p' /proc/cmdline)
if [ -n "$WDM" ] && [ -x /data/r800dev/charger/wpcd ]; then
	$B setsid /data/r800dev/charger/wpcd loop 5 > /dev/null 2>&1 < /dev/null &
fi
if [ -n "$WDM" ] && $B mkdir -p /wd/lo /wd/rw /wd/root &&
	$B mount -t ext4 -o ro /dev/mmcblk0p7 /wd/lo; then
	log "$WDM: p7 ramdisk mounted"
	# the bring-up watchdog (r800-deadman, ~60 s) is otherwise petted by
	# Android; keep it fed while the tool runs, or the watch resets mid-flash
	( while :; do echo pet > /proc/r800_deadman; $B sleep 10; done ) 2> /dev/null &
	# p7 stays untouched: the tool's writes (hostapd/udhcpd configs) land in RAM
	$B mount -t tmpfs tmpfs /wd/rw && $B mkdir -p /wd/rw/u /wd/rw/w
	$B mount -t overlay overlay -o lowerdir=/wd/lo,upperdir=/wd/rw/u,workdir=/wd/rw/w /wd/root
	R=/wd/root
	$B mount -t devtmpfs devtmpfs $R/dev
	$B mkdir -p $R/dev/pts; $B mount -t devpts devpts $R/dev/pts
	$B mount -t proc proc $R/proc
	$B mount -t sysfs sysfs $R/sys
	# Tizen's driver is the "dhd" module, ours "bcmdhd": wifi-loader writes the
	# soft-AP firmware path to /sys/module/dhd/parameters/firmware_path. Give
	# the chroot a /sys/module whose entries (dhd too) link to the real ones.
	$B mount -t sysfs sysfs $R/system-ro
	$B mount -t tmpfs tmpfs $R/sys/module
	for m in $R/system-ro/module/*; do $B ln -s /system-ro/module/${m##*/} $R/sys/module/${m##*/}; done
	$B ln -s /system-ro/module/bcmdhd $R/sys/module/dhd
	# the driver's built-in defaults (CLM blob, and the STA firmware when the
	# tool clears its path) are /vendor/data/r800dev/fw/*: resolve them in here too
	$B mkdir -p $R/vendor/data/r800dev/fw && $B mount --bind /data/r800dev/fw $R/vendor/data/r800dev/fw
	$B mount -t tmpfs tmpfs $R/run -o mode=755
	$B mount -t tmpfs tmpfs $R/tmp -o mode=1777
	# the tool's own UI (libtdm) cannot drive our display: show its state
	# from its log instead (bottom button held 3 s = cancel, back to Wear OS)
	[ -x /data/r800dev/charger/r800wdui ] &&
		$B setsid /data/r800dev/charger/r800wdui $R/csa/wd/wd_log > /dev/null 2>&1 < /dev/null &
	log "$WDM: running Tizen's ${WDM}-init"
	XDG_RUNTIME_DIR=/var/run TBM_DISPLAY_SERVER=1 PATH=/usr/bin:/bin:/usr/sbin:/sbin \
		$B chroot $R /sbin/${WDM}-init 2>&1 | logfile "$WDM: "
	log "$WDM: tool exited, rebooting"
	$B sync; $B umount $R/csa 2> /dev/null
	$B reboot -f
	while :; do $B sleep 1; done
fi

# ---- Android handover (only when the flag file exists) ----
# system.img (Wear OS 2, system-as-root) becomes /, our vendor.img /vendor, and p17
# moves to /oem so Android's init can start /oem/r800dev/android-helper.sh.
if [ -f /data/r800dev/android/BOOT_ANDROID ]; then
	log "android: handover requested"
	# Wireless charging pad: keep the P9222 session alive from the start of
	# boot (Tizen's kernel driver does it within seconds). The pad latches an
	# error (red LED, every later session cut at ~180 s until it is unplugged)
	# when the keep-alives stop, e.g. for the ~1 min until android-helper.sh
	# used to start wpcd. Static build (Android's libraries are not up yet);
	# the helper replaces it with bin/wpcd once Android runs.
	if [ -x /data/r800dev/charger/wpcd ]; then
		WL=/dev/null; [ -f /data/r800dev/android/DEV ] && WL=/data/r800dev/wpcd.log
		$B setsid /data/r800dev/charger/wpcd loop 5 >> $WL 2>&1 < /dev/null &
		log "android: early wpcd started"
	fi

	# Wi-Fi MAC: our bcmdhd build does not read the factory address, so wlan0
	# would come up with Broadcom's default 00:90:4c:... on every watch. The
	# factory one sits in CSA (p1) as /csa/.mac.info, as Tizen read it. Android
	# has no CSA mount, so hand it to the driver now: bcmdhd's r800_mac
	# parameter (kernel #102) is applied when the firmware starts.
	$B mkdir -p /csa && $B mount -t ext4 -o ro /dev/mmcblk0p1 /csa 2> /dev/null &&
		WMAC=$($B head -c 17 /csa/.mac.info 2> /dev/null | $B tr 'A-F' 'a-f'); $B umount /csa 2> /dev/null
	if echo "$WMAC" | $B grep -qE '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$' && [ "$WMAC" != 00:00:00:00:00:00 ]; then
		echo $WMAC > /sys/module/bcmdhd/parameters/r800_mac; log "android: wlan0 factory MAC rc=$?"
	else
		log "android: no factory MAC in CSA"
	fi

	# p17 arrives read-only from the initramfs; Android's helper needs to stage
	# tombstones/logs where Tizen can read them after the run.
	android_require "p17 remount" mount -o remount,rw /data
	android_require "newroot directory" mkdir -p /newroot
	# system.sqfs (squashfs, zstd; kernel run190+) is the same tree at ~45% of the
	# ext4 image's size, which p17 needs; the ext4 system.img is the fallback.
	SI=/data/r800dev/android/system.img
	[ -f /data/r800dev/android/system.sqfs ] && SI=/data/r800dev/android/system.sqfs
	[ -f "$SI" ] || android_abort "system image missing"
	android_require "system mount" mount -o loop,ro "$SI" /newroot
	[ -d /newroot/vendor ] && [ -d /newroot/oem ] || android_abort "required system mountpoints missing"
	# vendor.img lives on Tizen's CSC partition (p15: plain ext4, 1.5 MB of Tizen
	# config, ~180 MB free; Tizen mounts it read-only) when present, because p17 is
	# full and its space goes to userdata.img. Not p18: Tizen's rootfs is under
	# dm-verity, so any write there stops Tizen from booting. Fallback: p17 copy.
	VI=/data/r800dev/android/vendor.img
	$B mkdir -p /tzcsc
	if "$B" mount -t ext4 -o ro,noload /dev/mmcblk0p15 /tzcsc; then
		[ ! -f /tzcsc/r800-android/vendor.img ] || VI=/tzcsc/r800-android/vendor.img
	else
		log "android: p15 unavailable; checking local vendor fallback"
	fi
	[ -f "$VI" ] || android_abort "vendor image missing"
	android_require "vendor mount" mount -o loop,ro "$VI" /newroot/vendor
	# vendor.img's build.prop still has debug.sf.nobootanimation=1 from the
	# bring-up (no GPU driver then): the Wear OS boot animation exited after 0.5 s
	# and the splash stayed until SysUI's "Starting...". Bind a copy without it.
	# Same for ro.zygote.disable_gl_preload=true ("no GPU driver yet"): with the
	# GPU working, zygote preloads EGL/GLES once and apps start without it.
	VP=/data/r800dev/android/vendor-build.prop
	if $B grep -q -E '^(debug.sf.nobootanimation=1|ro.zygote.disable_gl_preload=true)' /newroot/vendor/build.prop 2>/dev/null; then
		$B grep -v -E '^(debug.sf.nobootanimation|ro.zygote.disable_gl_preload)=' /newroot/vendor/build.prop > $VP &&
			mount --bind $VP /newroot/vendor/build.prop && log "android: boot animation on, GL preload on"
	fi
	android_require "p17 bind to oem" mount --bind /data /newroot/oem
	# Our composer (zero-copy DECON present), kept on p17 so it can change without
	# rebuilding vendor.img.
	HW=/data/r800dev/hwc/hwcomposer.r800.so
	[ -f $HW ] && mount --bind $HW /newroot/vendor/lib/hw/hwcomposer.r800.so && log "android: hwcomposer from p17"
	# Same for the sensors HAL (hwc/sensors_r800.c) while it is being developed.
	SH=/data/r800dev/hwc/sensors.r800.so
	[ -f $SH ] && mount --bind $SH /newroot/vendor/lib/hw/sensors.r800.so && log "android: sensors HAL from p17"
	# And the audio HAL (hwc/audio_r800.c; Bluetooth call audio is new in it).
	AH=/data/r800dev/hwc/audio.primary.r800.so
	[ -f $AH ] && mount --bind $AH /newroot/vendor/lib/hw/audio.primary.r800.so && log "android: audio HAL from p17"
	# And the GPS HAL (hwc/gps_r800.c: satellite status, time reference, location).
	GH=/data/r800dev/hwc/gps.r800.so
	[ -f $GH ] && mount --bind $GH /newroot/vendor/lib/hw/gps.r800.so && log "android: GPS HAL from p17"
	# vendor.img carries the donor's Android 9 OMX service (without IOmxStore,
	# MediaCodecList fails and apps like Spotify crash). Its libminijail allows
	# one @include level; the Pixel system mediacodec.policy nests two, so bind a
	# flattened copy over it.
	MP=/data/r800dev/android/mediacodec.policy
	[ -f $MP ] && mount --bind $MP /newroot/system/etc/seccomp_policy/mediacodec.policy && log "android: flat mediacodec.policy"
	# The donor vendor declares NFC card emulation, but this watch has no NFC
	# driver: GMS (22.48+) then crashes on "NfcAdapter is null". Blank them.
	NP=/data/r800dev/android/empty-permissions.xml
	[ -f $NP ] || echo '<permissions/>' > $NP
	for F in android.hardware.nfc.hce.xml android.hardware.nfc.hcef.xml; do
		[ -f /newroot/vendor/etc/permissions/$F ] && mount --bind $NP /newroot/vendor/etc/permissions/$F
	done
	# Health Services (WHS) sees the Pixel Watch feature (com.google.android.feature.r11)
	# and, if it holds ACCESS_CONTEXT_HUB, opens the Pixel's CHRE context hub, which
	# this watch lacks: it crashed at start. Without the permission it skips the hub
	# and uses SensorManager (provider platform pinned by android-helper.sh). Deny it
	# to WHS only; deny-permission is allowed under privapp enforce.
	PX=/newroot/system/etc/permissions/privapp-permissions-clockwork.xml
	PXO=/data/r800dev/android/privapp-permissions-clockwork.xml
	# Gemini (com.google.android.wearable.assistant) as a privileged system app, as on
	# the Pixel Watch: the image has its allowlist entry but no copy of the app, so the
	# Play Store installed it as a normal app without CAPTURE_AUDIO_HOTWORD, and every
	# "Hey Google" AudioRecord failed (getInputForAttr -22). Its APKs (copied from the
	# Play install to android/privapp/WearAssistant) are bound over the unused DSU
	# priv-app folder. Newer Gemini requests 5 privileged permissions the 2023 list
	# lacks; enforce mode would stop the boot, so they are added below. Safety: the
	# helper zeroes gemini.tries at boot_completed; after 2 boots that never got there
	# this is skipped.
	GA=/data/r800dev/android/privapp/WearAssistant
	GT=/data/r800dev/android/gemini.tries
	GEMINI=0
	if [ -f $GA/base.apk ] && [ -d /newroot/system/priv-app/DynamicSystemInstallationService ]; then
		n=$($B cat $GT 2>/dev/null); n=${n:-0}
		if [ "$n" -lt 2 ]; then
			echo $((n + 1)) > $GT
			mount --bind $GA /newroot/system/priv-app/DynamicSystemInstallationService &&
				GEMINI=1 && log "android: Gemini as priv-app (try $((n + 1)))"
		else
			log "android: Gemini priv-app skipped after $n failed boots"
		fi
	fi
	if [ -f $PX ]; then
		$B sed '/package="com.google.android.wearable.healthservices"/,/<\/privapp-permissions>/ s#<permission name="android.permission.ACCESS_CONTEXT_HUB"/>#<deny-permission name="android.permission.ACCESS_CONTEXT_HUB"/>#' $PX > $PXO
		if [ $GEMINI = 1 ]; then
			$B sed -i '/package="com.google.android.wearable.assistant"/a\
        <permission name="android.permission.MANAGE_SOUND_TRIGGER"/>\
        <permission name="android.permission.MODIFY_AUDIO_ROUTING"/>\
        <permission name="com.google.android.permission.TAKE_WEARABLE_BUGREPORT"/>\
        <permission name="com.google.android.wearable.READ_SETTINGS"/>\
        <permission name="com.google.android.wearable.WRITE_SETTINGS"/>' $PXO
		fi
		$B grep -q deny-permission $PXO && mount --bind $PXO $PX && log "android: WHS context hub permission denied"
	fi
	# Extra framework overlays (e.g. pinner off: frees ~66 MB of mlocked RAM). They
	# only apply to non-overlayable resources from the product partition, so the
	# stock product/overlay dir is mirrored once to p17 with ours added, then bound.
	OV=/data/r800dev/android/overlay
	PO=/newroot/product/overlay   # /system/product is a symlink to /product
	PM=/data/r800dev/android/product_overlay
	if [ -d $OV ] && [ -d $PO ]; then
		[ -d $PM ] || { mkdir -p $PM && cp -a $PO/. $PM/; }
		cp -a $OV/. $PM/
		# system_server reads these as uid system: world-readable or they are dropped.
		$B find $PM -type d -exec $B chmod 755 {} +; $B find $PM -name '*.apk' -exec $B chmod 644 {} +
		mount --bind $PM $PO; log "android: product overlay mirror rc=$? ($(ls $PM | tr '\n' ' '))"
	fi
	# Persistent data block stand-in for ro.frp.pst (see the prop.default override).
	if [ -f /data/r800dev/android/persistent.img ]; then
		[ -b /dev/loop3 ] || $B mknod /dev/loop3 b 7 3
		$B losetup /dev/loop3 /data/r800dev/android/persistent.img; log "android: persistent.img -> loop3 rc=$?"
		$B chmod 666 /dev/loop3
	fi
	# Hide apps that can never work on this hardware and crash-loop forever. NFC is a
	# persistent app (pm disable does not stop it): every crash ran crash_dump and a
	# restart about every 5 s, stalling input (run 109). An empty tmpfs over the app
	# directory means PackageManager never sees it.
	# Same for Mobvoi's TicWatch add-ons that make no sense on a Galaxy Watch (their
	# watch faces stay).
	for A in system/app/Nfc_st system/priv-app/TicSystem system/priv-app/TicCompanionWear \
		 system/priv-app/TicAppsService system/app/PlayAutoInstallStub; do
		[ -d /newroot/$A ] && mount -t tmpfs -o size=4k,mode=0755 r800mask /newroot/$A && log "android: masked $A"
	done
	# Identity and density, via edited copies bind-mounted over the read-only system
	# prop files (no system.img rebuild). Density: the image is for a 454x454 TicWatch
	# at 320 dpi; on this 360x360 panel that is only 180 dp wide, so layouts clipped.
	# The build fingerprint and product name/device stay, for Google Play services.
	PD=/data/r800dev/android/props; mkdir -p $PD
	# ro.frp.pst: the image points at the TicWatch's "config" partition, which
	# this watch lacks; TestHarnessModeService then kills system_server with
	# "invalid checksum" in boot phase 500. Point it at the stand-in block.
	FRP=/dev/block/bootdevice/by-name/config
	[ -f /data/r800dev/android/persistent.img ] && FRP=/dev/loop3
	$B sed -e 's/^ro.sf.lcd_density=.*/ro.sf.lcd_density=300/' \
		-e "s#^ro.frp.pst=.*#ro.frp.pst=$FRP#" \
		/newroot/system/etc/prop.default > $PD/prop.default
	# The Pixel image's prop.default has neither line; add them when missing.
	$B grep -q '^ro.frp.pst=' $PD/prop.default || echo "ro.frp.pst=$FRP" >> $PD/prop.default
	$B grep -q '^ro.sf.lcd_density=' $PD/prop.default || echo 'ro.sf.lcd_density=300' >> $PD/prop.default
	# Developer mode: logd collects the kernel log too (logcat -b kernel) and
	# android-helper.sh keeps it in a rolling file on p17. (The image's
	# prop.default has ro.logd.kernel=eng, which logd reads as off.)
	if [ -f /data/r800dev/android/DEV ]; then
		$B sed -i 's/^ro.logd.kernel=.*/ro.logd.kernel=true/' $PD/prop.default
		$B grep -q '^ro.logd.kernel=' $PD/prop.default || echo 'ro.logd.kernel=true' >> $PD/prop.default
	fi
	# The Pixel Watch boot ramdisk names the phone app GMS may treat as this watch's
	# companion (its signing-cert SHA-1). Without them the watch's Play services never
	# delivers the Pixel Watch app's /setup/channel to WCS, and pairing hangs at
	# "Connecting to your watch".
	echo 'ro.oem.companion_package=com.google.android.apps.wear.companion' >> $PD/prop.default
	echo 'ro.oem.companion_digest=78f631ae7d905e163085a790049b875db65cab52' >> $PD/prop.default
	# Persistent logging (logcatd -> /data/misc/logd) was on for hang hunting; it
	# costs CPU, RAM and flash writes, so it is off now. To get it back for a
	# hung boot, add persist.logd.logpersistd=logcatd here.
	# logd copies every SELinux denial (permissive: thousands) into the kernel ring,
	# which then wraps within seconds and loses hang evidence.
	echo 'ro.logd.auditd.dmesg=false' >> $PD/prop.default
	# debug.egl.finish=1 (glFinish before every swap) came in with the zero-copy composer as a
	# fence workaround; the real fault was the layer-offset fence leak fixed then. Off since
	# 2026-11-19: p90 frame 50 -> 28 ms, p99 87 -> 45 ms in an A/B, no glitches in use.
	# ART memory for ~700 MB RAM (the image ships phone values: 32m start heap,
	# up to 32m kept free per app). These are Android Go's low-RAM numbers;
	# ~25 app processes each hold less idle heap. Later lines win for non-ro
	# props, and build.prop does not set these.
	# madvise sizes: ART reads ahead up to 100 MB of each app's vdex/odex at
	# start, which here only pushes out pages in use; 0 = no readahead.
	for P in heapstartsize=8m heapminfree=512k heapmaxfree=8m \
		madvise.vdexfile.size=0 madvise.odexfile.size=0; do
		echo "dalvik.vm.$P" >> $PD/prop.default
	done
	mount --bind $PD/prop.default /newroot/system/etc/prop.default; log "android: prop.default override rc=$?"
	$B sed -e 's/^ro.product.model=.*/ro.product.model=Galaxy Watch/' \
		-e 's/^ro.product.brand=.*/ro.product.brand=samsung/' \
		-e 's/^ro.product.manufacturer=.*/ro.product.manufacturer=Samsung/' \
		/newroot/system/build.prop > $PD/build.prop &&
		mount --bind $PD/build.prop /newroot/system/build.prop; log "android: build.prop override rc=$?"
	# Direct I/O on the image loops: otherwise every system.img page is cached twice
	# (image file + mounted fs); run 104 went from ~1000 to ~130 major faults/s.
	for L in $($B losetup -a 2>/dev/null | $B grep -E 'system.img|system.sqfs|vendor.img' | $B cut -d: -f1); do
		log "android: $(/data/r800dev/bin/loopdio $L 1 2>&1)"
	done
	# Absolute guest symlinks must be interpreted inside the guest root.
	if [ -L /newroot/init ]; then
		case "$("$B" readlink /newroot/init)" in
			/system/bin/init|system/bin/init) [ -x /newroot/system/bin/init ] || android_abort "guest init target missing";;
			*) android_abort "unsupported guest init symlink";;
		esac
	else
		[ -x /newroot/init ] || android_abort "guest init missing"
	fi
	echo pet > /proc/r800_deadman
	# /data = blank ext4 on zram (fstab.r800 mounts /dev/block/zram0). tmpfs lacks user.*
	# xattrs, so UserManager wiped /data/system_de/0 and system_server crash-looped.
	# /data for Android is always /dev/loop2 (fstab.r800). Persistent: userdata.img on
	# p17 (touch RESET_DATA next to it to start blank again). Otherwise the old
	# blank-every-boot zram disk.
	AD=/data/r800dev/android
	# Since Tizen was retired (tools/tzlite), /data lives on p18, Tizen's old 1.4 GB
	# rootfs: ext4 labelled r800data (migrated from userdata.img by block copy).
	P18=/dev/mmcblk0p18
	if [ "$($B dd if=$P18 bs=1 skip=1144 count=8 2>/dev/null)" = r800data ]; then
		android_require "data p18 loop attach" "$B" losetup /dev/loop2 "$P18"
		log "android: $(/data/r800dev/bin/loopdio /dev/loop2 1 2>&1)"
	elif [ -f $AD/userdata.img ]; then
		if [ -f $AD/RESET_DATA ]; then
			$B zcat $AD/userdata-blank.img.gz > $AD/userdata.img; log "android: userdata reset rc=$?"
			rm -f $AD/RESET_DATA; sync
		fi
		android_require "userdata loop attach" "$B" losetup /dev/loop2 "$AD/userdata.img"
		log "android: $(/data/r800dev/bin/loopdio /dev/loop2 1 2>&1)"
	else
		echo 209715200 > /sys/block/zram0/disksize; log "android: zram disksize rc=$?"
		$B zcat $AD/data.img.gz > /dev/zram0; log "android: zram fill rc=$?"
		android_require "zram loop attach" "$B" losetup /dev/loop2 /dev/zram0
	fi
	DATA_MAGIC=$("$B" dd if=/dev/loop2 bs=1 skip=1080 count=2 2>/dev/null | "$B" od -An -tx1 | "$B" tr -d " \n")
	[ "$DATA_MAGIC" = 53ef ] || android_abort "data loop lacks ext4 magic"
	log "android: data ext4 magic verified"
	umount /dev/pts 2>/dev/null; umount /sys; umount /proc
	log "android: init=$($B ls -l /newroot/init 2>&1)"
	# Android 11's first-stage init mounts /proc (hidepid=2,gid=readproc) and /sys
	# itself and treats EBUSY as fatal ("Init encountered errors starting first
	# stage, aborting"), so on SDK 30+ leave those two mounts to init. Android 9
	# tolerates the pre-mount, so keep the old behaviour there.
	SDK=$($B grep -m1 '^ro.build.version.sdk=' /newroot/system/build.prop 2>/dev/null | $B cut -d= -f2)
	case "$SDK" in ''|*[!0-9]*) android_abort "unknown Android SDK";; esac
	if [ "$SDK" -ge 30 ]; then
		log "android: sdk=$SDK, leaving proc/sys to init"
	else
		log "android: sdk=$SDK, pre-mounting proc/sys"
		android_require "guest proc mount" "$B" mount -t proc proc /newroot/proc
		android_require "guest sys mount" "$B" mount -t sysfs sysfs /newroot/sys
		log "android: misc=$($B cat /newroot/proc/misc 2>&1 | $B tr '\n' ' ')"
	fi
	android_require "guest dev mount" "$B" mount -t devtmpfs devtmpfs /newroot/dev
	# The stock ro.frp.pst names the TicWatch's config partition; also expose the
	# stand-in under that path in case the property override is ignored.
	$B mkdir -p /newroot/dev/block/bootdevice/by-name
	$B ln -sf /dev/loop3 /newroot/dev/block/bootdevice/by-name/config
	log "android: devnodes=$($B ls /newroot/dev 2>&1 | $B tr '\n' ' ')"
	# Hold fb0 across the handover: if the last user closes it, decon releases and
	# the panel powers down; the DSI re-init afterwards times out (black screen).
	# A forked holder survives switch_root (only PID 1 is chrooted).
	FBDEV=/dev/fb0
	[ -e $FBDEV ] || FBDEV=/dev/graphics/fb0
	log "android: fbdev=$FBDEV exists=$([ -e $FBDEV ] && echo yes || echo no) devs=$($B ls /dev | $B tr '\n' ' ')"
	( exec 9<>$FBDEV; while :; do $B sleep 3600; done ) &
	log "android: fb holder pid=$!"
	# A real root switch (not chroot): zygote checks open fds against a path whitelist and
	# aborted on "/newroot/dev/null" when the old root was still visible.
	log "android: exec switch_root -> /init"
	exec 2>/dev/kmsg
	exec $B switch_root /newroot /init
	android_abort "switch_root returned"
fi

# Feed the dead-man watchdog for 150 s unconditionally, then only while wlan0 has an
# IP (max 20 min), or forever once /tmp/stay exists. No network => reset ~60 s later.
( n=0; while true; do
    if [ $n -lt 15 ] || [ -f /tmp/stay ] || { [ $n -lt 120 ] && ip -4 addr show wlan0 2>/dev/null | grep -q inet; }; then
        echo pet > /proc/r800_deadman
    fi
    n=$((n+1)); sleep 10
  done ) &

mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /var
mkdir -p /var/run /var/run/wpa_supplicant /dev/pts
mount -t devpts devpts /dev/pts
hostname r800
# bcmdhd prefixes firmware paths with /vendor (VENDOR_PATH): /vendor/data/... -> /data/...
ln -s / /vendor

# ---- Wi-Fi ----
for i in $(seq 1 20); do [ -d /sys/class/net/wlan0 ] && break; sleep 1; done
log "net devices: $(ls /sys/class/net | tr '\n' ' ')"
ifconfig lo 127.0.0.1 up
ifconfig wlan0 up > /tmp/ifup.log 2>&1
log "ifup wlan0 rc=$? $(head -c 200 /tmp/ifup.log)"

# Scan first so the log shows what the radio can hear.
/usr/sbin/iw dev wlan0 scan > /tmp/scan.txt 2>&1
log "scan rc=$? bss=$(grep -c '^BSS ' /tmp/scan.txt) $(head -c 120 /tmp/scan.txt | tr '\n' ' ')"
grep 'SSID:' /tmp/scan.txt | head -10 | logfile "ssid "

# Foreground process in the background (not -B), so its stdout/stderr and exit are visible.
/sbin/wpa_supplicant -d -i wlan0 -D nl80211 -c /data/r800dev/wpa.conf > /tmp/wpa.log 2>&1 &
WPA=$!
for i in $(seq 1 40); do grep -q "CTRL-EVENT-CONNECTED" /tmp/wpa.log 2>/dev/null && break; kill -0 $WPA 2>/dev/null || break; sleep 1; done
log "wpa pid=$WPA alive=$(kill -0 $WPA 2>/dev/null && echo yes || echo no) lines=$(wc -l < /tmp/wpa.log) after ${i}s"
head -12 /tmp/wpa.log | logfile "wpa-head> "
tail -8 /tmp/wpa.log | logfile "wpa-tail> "
ls -la /var/run/wpa_supplicant 2>&1 | logfile "ctrl: "
grep -E 'CTRL-EVENT|Trying to|Associat|authenticat|WPA: |reason=|status_code|nl80211: (Connect|Associat|Authent|Scan)|Failed|SME' /tmp/wpa.log | grep -v ctrl_iface | tail -30 | logfile "wpa> "
/sbin/wpa_cli -i wlan0 status 2>&1 | logfile "wpa_cli: "

udhcpc -i wlan0 -s /data/r800dev/udhcpc.sh -b -t 15 -T 2 -x hostname:r800
for i in $(seq 1 20); do ip -4 addr show wlan0 | grep -q inet && break; sleep 1; done
log "wlan0: $(ip -4 addr show wlan0 | grep -o 'inet [0-9./]*') mac $(cat /sys/class/net/wlan0/address)"

# ---- shell ----
/data/r800dev/bin/busybox-extras telnetd -l /bin/sh -p 23
log "telnetd on port 23 rc=$?"

# Optional per-session hook, editable from Tizen without reflashing.
[ -f /data/r800dev/hook.sh ] && sh /data/r800dev/hook.sh

while true; do
	sleep 30
	log "alive up=$(cut -d' ' -f1 /proc/uptime) $(ip -4 addr show wlan0 | grep -o 'inet [0-9.]*')"
done
