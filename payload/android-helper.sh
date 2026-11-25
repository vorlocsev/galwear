#!/oem/r800dev/bin/busybox sh
# SM-R800 Wear OS helper. Runs under Android's init as service r800helper (root).
# Only static busybox and absolute paths. Keeps the board alive and adds what the
# images lack: swap, GPU clock, Wi-Fi support, one-time setup.
B=/oem/r800dev/bin/busybox
k() { echo "<6>r800: $*" > /dev/kmsg; }
# Bounded boot-stage observation; no service starts, property writes or IPC probes.
# A running process alone does not establish successful service registration.
boot_observe() {
    previous=
    for attempt in $("$B" seq 1 120); do
        managers=
        for service in servicemanager hwservicemanager vndservicemanager zygote; do
            state=$(/system/bin/getprop "init.svc.$service")
            case "$state" in running|stopped|restarting|stopping) ;; *) state=unknown;; esac
            managers="$managers $service=$state"
        done
        server=absent
        "$B" pidof system_server >/dev/null 2>&1 && server=present
        completed=$(/system/bin/getprop sys.boot_completed)
        case "$completed" in 1) ;; *) completed=0;; esac
        current="$managers system_server=$server boot_completed=$completed"
        if [ "$current" != "$previous" ]; then
            k "boot-stage:$current"
            previous=$current
        fi
        if [ "$completed" = 1 ]; then
            k "boot-stage: Android reports boot_completed; hardware acceptance not established"
            return 0
        fi
        "$B" sleep 2
    done
    k "boot-stage: observation window expired without boot_completed"
}
boot_observe &

# Developer mode: touch /oem/r800dev/android/DEV for the telnet shell, Wi-Fi
# forced on, the setup wizard skipped and debug logs on p17. Without it the
# watch runs as a normal user watch.
DEVF=/oem/r800dev/android/DEV
dev() { [ -f $DEVF ]; }
if dev; then SLOG=/oem/r800dev/sensors.log; else SLOG=/dev/null; fi
# ---- lmkd (2026-11-18): the 16:0x freeze ran ~3 min of stalls with zero
# low-memory kills, so lmkd reacts to stalls/thrashing sooner here. We start
# "on init", before class core starts lmkd, so these unset ro.lmk.* props are
# what lmkd reads. Defaults (low_ram): complete stall 700 ms, thrashing 30 %,
# swap-low 10 %. Undo: delete this block and reboot.
for p in psi_complete_stall_ms=500 thrashing_limit=20 swap_free_low_percentage=15; do
    [ -z "$(/system/bin/getprop ro.lmk.${p%%=*})" ] && /system/bin/setprop ro.lmk.${p%%=*} ${p#*=}
done
# Android's init mounts its own /dev, so the loop3 node start.sh made in the
# initramfs is gone. Recreate it (we are root, before system_server) so
# ro.frp.pst=/dev/loop3 resolves when PersistentDataBlockService starts.
[ -b /dev/loop3 ] || $B mknod /dev/loop3 b 7 3
$B chmod 666 /dev/loop3
$B mkdir -p /dev/block/bootdevice/by-name
[ -e /dev/block/bootdevice/by-name/config ] || $B ln -s /dev/loop3 /dev/block/bootdevice/by-name/config
# Kernel wakelock r800helper keeps the board out of deep sleep. Deep sleep
# itself works (Wi-Fi wakes the SoC, so the telnet shell still answers, and
# wpcd holds its own wakelock on the charging pad), but the watch can hang
# in it: 2026-11-16 it froze ~16 min into a sleep trial and needed a forced
# restart. Opt in with android/SLEEP until that is fixed.
# System suspend and per-core CPU idle are separate power states.
# Keep system suspend guarded by default; explicit SLEEP is experimental.
SLEEPF=/oem/r800dev/android/SLEEP
if [ -f "$SLEEPF" ]; then
    k "power: full suspend enabled by SLEEP opt-in (unverified stability)"
else
    if echo r800helper > /sys/power/wake_lock 2>/dev/null; then
        k "power: system suspend guarded"
    else
        k "power: WARNING: r800helper wake lock unavailable"
    fi
fi
# Composer DECON overlays off by default (2026-11-19): A/B with the same
# 30 s scroll had 10.7% of SysUI frames >16 ms with overlays vs 6.7% with
# GPU composition (p99 150 vs 73 ms), although overlays halve SF/GPU work.
# Suspect: the GPU fallback for animated/scaled layers. Opt in: android/OVERLAY.
[ -f /oem/r800dev/android/OVERLAY ] || /system/bin/setprop vendor.hwc.r800.overlay 0
# Full SLEEP (MIF down) needs pd-is, pd-vts and pd-dispaud off, as in Tizen
# (kernel #97+: Tizen's PD SMC argument, decon keeps disp-rst-prev in
# ambient). With android/SLEEP the domains go off in the last syscore step;
# ABOX powers off when idle (set further down). 3 of 3 forced sleeps resumed
# with ambient on, 2026-11-19.
if [ -f /oem/r800dev/android/SLEEP ]; then
    echo 3 > /sys/module/exynos_pd/parameters/r800_sleep_pd_off 2>/dev/null
    echo Y > /sys/module/exynos_pd/parameters/r800_dispaud_sleep_off 2>/dev/null
fi
# Radio firmware is already bound by start.sh before Android init starts.
# Do not stack another mount over it here.
# Kernel firmware search path (no user-mode helper): /mnt/r800fw resolves both
# here (requests from kernel workers: ABOX calliope_*.bin, VTS vts.bin) and in
# the sensor chroot (BBD patch, requested in lhd's context; tzchroot.sh mounts
# the same directory there).
$B mkdir -p /mnt/r800fw && $B mount --bind /oem/r800dev/fw /mnt/r800fw
echo -n /mnt/r800fw > /sys/module/firmware_class/parameters/path
# ---- Bluetooth (BCM43012 on uart5, kernel #88+): the J4 libbt-vendor drives a
# Samsung SCSC chip, so bind our AOSP Broadcom build over it (firmware, conf and
# lib in fw/bt). The HAL runs as uid bluetooth: hand it the UART and rfkill.
BT=/oem/r800dev/fw/bt
if [ -f $BT/libbt-vendor.so ]; then
    $B chmod 755 $BT; $B chmod 644 $BT/*
    # libbt-vendor.so was bound before switch_root; avoid a late replacement.
fi
for r in /sys/class/rfkill/rfkill*; do
    [ "$($B cat $r/type 2>/dev/null)" = bluetooth ] || continue
    $B chown 1002:1002 $r/state; $B chmod 660 $r/state
done
[ -e /dev/ttySAC5 ] && { $B chown 1002:1002 /dev/ttySAC5; $B chmod 660 /dev/ttySAC5; }
# This watch's own Bluetooth address, from the factory CSA partition (p1,
# bluetooth/.bd_addr: NAP, UAP, LAP in hex on three lines). Set every boot,
# before the Bluetooth stack starts; the HAL otherwise invents a random one,
# and a pairing made with it breaks once the address changes.
C=/mnt/r800csa; $B mkdir -p $C
if $B mount -t ext4 -o ro /dev/block/mmcblk0p1 $C 2>/dev/null; then
    A=$($B tr -dc '0-9A-Fa-f' < $C/bluetooth/.bd_addr 2>/dev/null)
    $B umount $C
    [ ${#A} = 12 ] && /system/bin/setprop persist.service.bdroid.bdaddr \
        "$(echo $A | $B sed 's/\(..\)/\1:/g; s/:$//')"
fi
FRP=$(/system/bin/getprop ro.frp.pst)
dev && { echo "frp=$FRP"; ls -l /dev/loop3 2>&1; ls -l /dev/block/bootdevice/by-name/config 2>&1; } > /oem/r800dev/frp-debug.txt
k "frp=$FRP loop3=$(ls -l /dev/loop3 2>&1)"
# The composer (uid system) blanks the panel by writing DCS display off/on
# commands to this root-only node.
$B chmod 666 /sys/devices/platform/148e0000.dsim/cmd_rw 2>/dev/null
# Keep the previous boot's logs: a hang usually ends in a button reset, and the
# streams below would otherwise truncate the only record of it.
for f in kdisp fatal wedge; do [ -f /oem/r800dev/$f.log ] && $B mv -f /oem/r800dev/$f.log /oem/r800dev/$f-prev.log; done

# ---- dead-man watchdog (60 s), fed for as long as the helper runs: a real hang
# stops this loop and resets the watch.
( while :; do echo pet > /proc/r800_deadman; $B sleep 10; done ) &
PETTER=$!

# p17 (shared with Tizen and holding the Android images) has ~20 MB free: logs
# that only ever get appended to are emptied at boot once they pass 1 MB.
# Tizen's connman/netconfig/wpa logs rotate in 1 MB steps and it keeps packet
# captures; they refill p17 with every Tizen boot (it hit 0 free on 2026-11-17).
$B rm -f /oem/data/network/packet.pcap* /oem/data/network/*.log.[0-9]* 2>/dev/null
for f in /oem/r800dev/*.log; do
    [ -f "$f" ] && [ $($B stat -c %s "$f") -gt 1048576 ] && : > "$f"
done

# ---- wireless charging: no P9222 kernel driver, so wpcd keeps the pad session
# alive (Samsung watchdog kick, AP battery mode, TX ID, CS100). Log is appended.
# start.sh runs a static wpcd from early boot; start ours first, then stop
# that one, so the pad never misses a keep-alive (two kickers for a moment
# are harmless).
if dev; then WPCDLOG=/oem/r800dev/wpcd.log; else WPCDLOG=/dev/null; fi
$B pgrep -f "bin/wpcd loop" > /dev/null || /oem/r800dev/bin/wpcd loop 5 >> $WPCDLOG 2>&1 &
$B sleep 1; $B pkill -f "charger/wpcd loop" 2>/dev/null
# ---- memrec: memory/CPU flight recorder (developer mode only)
dev && [ -x /oem/r800dev/memrec.sh ] && /oem/r800dev/memrec.sh &

# ---- sensors: the SSP sensor hub lives in the BCM47758 GPS chip. Tizen's lhd
# downloads the MCU patch (/dev/bbd_patch -> request_firmware) and relays the
# traffic; it runs unmodified from the Tizen rootfs (p18, read-only) in a chroot
# with Tizen's /opt (p16) and /opt/usr (= /oem) in place (tzchroot.sh). gpm13-0
# takes the chip out of standby (lhd toggles it through sec_gps_bcm477x's gps_pwr_en).
# See tools/sensors/README.md. Restarted like Tizen's Restart=always.
# tools/tzlite: with android/TZTRACE present, every Tizen program started below
# logs the files it touches to the chroot's /tmp/openlog.txt
TZPL=
[ -f /oem/r800dev/android/TZTRACE ] && TZPL=/opt/usr/r800dev/lib/openlog.so
TZE="/usr/bin/env ${TZPL:+LD_PRELOAD=$TZPL}"
if [ -c /dev/bbd_patch ] && [ -x /oem/r800dev/tzchroot.sh ]; then
    (
        /oem/r800dev/tzchroot.sh > $SLOG 2>&1
        $B pkill -f "gpiotool hold gpm13" 2>/dev/null
        # kernel #20+: sec_gps_bcm477x owns the pin and lhd drives it through
        # gps_pwr_en (GpioNStdbyPath); older kernels need it held from userspace
        [ -e /sys/class/gps/gps/gps_pwr_en ] ||
            $B setsid /oem/r800dev/bin/gpiotool hold gpm13 0 1 >> $SLOG 2>&1 < /dev/null &
        $B sleep 1
        n=0
        while [ $n -lt 20 ]; do
            k "sensors: starting lhd ($n)"
            $B chroot /mnt/tz $TZE /usr/bin/lhd /etc/lhd/lhd.conf > /mnt/tz/tmp/lhd.log 2>&1 < /dev/null
            n=$((n+1))
            $B tail -20 /mnt/tz/tmp/lhd.log >> $SLOG
            $B sleep 5
        done
        k "sensors: lhd gave up after $n starts"
    ) &

    # ---- GPS: Broadcom's gpsd (the GNSS engine) talks to lhd; gpsbridge drives
    # it through Tizen's libbrcm and serves gps.r800.so on /oem/r800dev/gps.sock.
    # gpsd exits when its client goes away, so both are respawned (Tizen: systemd
    # Restart=always). See tools/gps/README.md.
    if [ -x /oem/r800dev/gpsbridge ]; then
        (
            $B sleep 20   # lhd up first
            $B chroot /mnt/tz $TZE chown -R location:location /opt/gnss
            while true; do
                $B chroot /mnt/tz $TZE /usr/bin/gpsd -c /etc/gps-manager/brcm/gpsd.xml > /dev/null 2>&1 < /dev/null
                # gpsd runs as root here but as "location" on Tizen: a root-owned
                # /opt/gnss/gldata.sto (mode 600) makes Tizen's gpsd crash-loop and
                # fill p17 with crash dumps. Hand its state back after every run.
                $B chroot /mnt/tz $TZE chown -R location:location /opt/gnss
                $B sleep 1
            done
        ) &
        (
            $B sleep 25
            ( $B sleep 60; $B chroot /mnt/tz $TZE chown -R location:location /opt/gnss ) &
            while true; do
                $B chroot /mnt/tz $TZE /opt/usr/r800dev/gpsbridge daemon > /oem/r800dev/gpsbridge.out 2>&1 < /dev/null
                # libbrcm (root here) creates /opt/gnss/.gps.interface.pipe.* when missing;
                # root-owned, they crash-loop Tizen's gpsd (location) at ~90% CPU.
                $B chroot /mnt/tz $TZE chown -R location:location /opt/gnss
                k "gps: gpsbridge exited, restarting"
                $B sleep 3
            done
        ) &
        # Broadcom LTO (4-day orbit prediction) for gpsbridge to inject: Tizen's lbs
        # plugin downloads it, which never runs here, and the chroot has no DNS. Fetch
        # it daily over Android's network (busybox has no resolver config, so resolve
        # first and send the Host header). Without it every start is a cold start.
        (
            L=/mnt/tz/opt/gnss/data
            S=/oem/r800dev/lto.stamp
            $B sleep 120
            while true; do
                W=3600
                if [ -z "$($B find $S -mmin -1200 2>/dev/null)" ]; then
                    IP=$($B nslookup gllto1.glpals.com 1.1.1.1 2>/dev/null | $B awk '/^Address/ && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $2; exit }')
                    if [ -n "$IP" ] && $B timeout 60 $B wget -q -O $L/.lto.new \
                            --header "Host: gllto1.glpals.com" http://$IP/4day/v3/latest/lto2.dat &&
                            [ $($B stat -c %s $L/.lto.new) -gt 20000 ]; then
                        $B mv $L/.lto.new $L/lto2.dat
                        $B chown 654:654 $L/lto2.dat   # Tizen's "location" user
                        $B touch $S
                        k "gps: LTO refreshed ($($B stat -c %s $L/lto2.dat) bytes)"
                    else
                        $B rm -f $L/.lto.new
                        W=600   # no network yet: try again sooner
                    fi
                fi
                $B sleep $W
            done
        ) &
    fi

    # ---- context sensors: the hub's own wrist-up and wear on/off algorithms,
    # driven by Samsung's libsensor-hal inside Tizen's sensord (same chroot).
    # sensorctl streams their events (wrist up/down, wear on/off, pedometer);
    # sensors.r800.so reads them from the FIFO as wrist tilt, ungaze, low-latency
    # off-body and step counter/detector.
    (
        for i in $($B seq 1 90); do
            $B dmesg | $B grep -q "Normal Booting OK" && break
            $B sleep 1
        done
        CTX=/dev/r800_context
        [ -p $CTX ] || $B mkfifo $CTX
        $B chmod 666 $CTX
        # privileged sensors (pedometer: healthinfo) are checked through Cynara,
        # which the chroot doesn't run; cynara_allow.so answers "allowed"
        ( while true; do
            $B chroot /mnt/tz /usr/bin/env LD_PRELOAD="/opt/usr/r800dev/lib/cynara_allow.so $TZPL" \
                /usr/bin/sensord > /dev/null 2>&1 < /dev/null
            k "sensors: sensord exited, restarting"; $B sleep 5
        done ) &
        $B sleep 4
        # instant key injection (uinput) for ungaze; `input keyevent` takes ~2.3 s.
        # A held-open writer keeps ukey's stdin from hitting EOF between events.
        UK=/dev/r800_ukey
        [ -p $UK ] || $B mkfifo $UK
        $B sleep 2147483647 > $UK &
        /oem/r800dev/bin/ukey < $UK > /dev/null 2>&1 &
        # sensorctl output: "<us> <value> ..." per event (colour/banner lines skipped)
        ( while true; do
            $B chroot /mnt/tz $TZE /usr/bin/sensorctl test wristup 2>/dev/null < /dev/null |
                while read ts v rest; do case $ts in [0-9]*) echo "W $ts";; esac; done > $CTX
            $B sleep 5
        done ) &
        # wrist turned down/away: Wear OS "ungaze" (screen off). ClockworkAmbient's
        # ungaze detector never subscribes to a sensor on this build (neither the
        # com.google.sensor.ungaze_gesture one the HAL offers nor its accelerometer
        # fallback), so do what it would: put the screen to sleep, if the user's
        # ungaze setting is on. KEY_SLEEP is a no-op when already asleep.
        ungaze() {
            [ "$(/system/bin/settings get global ungaze_enabled)" = 0 ] && return
            echo sleep > $UK
            k "ungaze: wrist down -> sleep"
        }
        ( while true; do
            $B chroot /mnt/tz $TZE /usr/bin/sensorctl test wristdown 2>/dev/null < /dev/null |
                while read ts v rest; do
                    case $ts in [0-9]*) echo "D $ts"; ungaze > /dev/null 2>&1 & ;; esac
                done > $CTX
            $B sleep 5
        done ) &
        ( while true; do
            $B chroot /mnt/tz $TZE /usr/bin/sensorctl test wear_on 2>/dev/null < /dev/null |
                while read ts v rest; do case $ts in [0-9]*) echo "O $v";; esac; done > $CTX
            $B sleep 5
        done ) &
        # hub pedometer, always on like the stock firmware: "<us> <steps> <walk>
        # <run> <m> <kcal> ..."; the HAL makes a monotonic step counter of it
        ( while true; do
            $B chroot /mnt/tz $TZE /usr/bin/sensorctl test pedo 2>/dev/null < /dev/null |
                while read ts v rest; do case $ts in [0-9]*) echo "P ${v%%.*}";; esac; done > $CTX
            $B sleep 5
        done ) &
        k "sensors: context bridge up"

        # docked charging: turn the display to how the watch sits on the charger
        [ -f /oem/r800dev/dockrot.sh ] && $B sh /oem/r800dev/dockrot.sh "$TZE" > /dev/null 2>&1 < /dev/null &
    ) &
fi

# ---- early kernel messages, before the ring buffer wraps (for debugging only)
dev && $B dmesg | $B grep -i -E "exynos-dm|exynos_acme|fvmap|devfreq|G3D|ztm620|s6e36w3x01|r800-sh|panic|Oops" \
    > /oem/r800dev/boot-log.txt 2>/dev/null

# ---- swap: 768 MB RAM; a second zram device as lz4 swap (the node appears late)
SW=$($B cat /sys/class/zram-control/hot_add 2>/dev/null)
if [ -n "$SW" ]; then
    echo lz4 > /sys/block/zram$SW/comp_algorithm 2>/dev/null
    # 400 MB: lz4 packs ~3:1 here, so a full device costs ~135 MB of RAM; at
    # 300 MB it sat nearly full and lmkd dropped cached apps more often.
    echo 419430400 > /sys/block/zram$SW/disksize
    for i in 1 2 3 4 5 6 7 8 9 10; do [ -b /dev/block/zram$SW ] && break; $B sleep 1; done
    [ -b /dev/block/zram$SW ] || $B mknod /dev/block/zram$SW b $($B cat /sys/block/zram$SW/dev | $B tr : ' ')
    $B mkswap /dev/block/zram$SW >/dev/null 2>&1 && $B swapon /dev/block/zram$SW
    echo 100 > /proc/sys/vm/swappiness
    # kswapd starts earlier (default 10): fewer direct-reclaim stalls (UI jank)
    echo 40 > /proc/sys/vm/watermark_scale_factor
fi

# ---- GPU. CONFIG_MALI_SEC_UTILIZATION is on in the kernel config now, so the
# Mali DVFS governor should see real utilization and scale 200-667 by itself.
# Until that build is flashed and verified, keep pinning: with utilization
# stuck at 0 (the old config) the governor parks at 200 MHz and the UI crawls.
# Verify on the new kernel: /sys/class/misc/mali0/device/gpu_utilization goes
# non-zero while the screen animates, and the clock drops to 200 MHz when idle.
# Then touch /oem/r800dev/android/GPU_SCALE (/opt/usr/r800dev/android from
# Tizen) and the governor owns the clock; remove the file to pin again.
G=/sys/class/misc/mali0/device
if [ -f /oem/r800dev/android/GPU_SCALE ]; then
    k "gpu: DVFS left to the governor (GPU_SCALE)"
else
    ( for i in $($B seq 1 60); do
          echo 667 > $G/dvfs_min_lock 2>/dev/null
          $B grep -q 667 $G/dvfs_min_lock 2>/dev/null && break
          $B sleep 1
      done ) &
fi

# ---- after boot: one-time setup, then Wi-Fi and the telnet shell
(
    for i in $($B seq 1 120); do [ "$(/system/bin/getprop sys.boot_completed)" = 1 ] && break; $B sleep 1; done
    # boot got through: reset start.sh's Gemini priv-app failure counter
    [ "$(/system/bin/getprop sys.boot_completed)" = 1 ] && echo 0 > /oem/r800dev/android/gemini.tries
    # Kernel #66+ re-initialises the panel after a real power-down, so let
    # screen-off power the panel/DSIM/DECON down (the composer blanks with
    # FBIOBLANK). Revert: echo 1 here, or setprop debug.r800.realblank 0.
    echo 0 > /sys/module/decon/parameters/r800_keep_panel_on 2>/dev/null
    # storaged is left running (2026-11-19): with it stopped, system_server's
    # StorageManagerService retried "storaged not found" once a second for
    # the whole session (seen in the realuse97 logcat), which cost more
    # wakeups than storaged itself.
    # CPU split (2026-11-18): AOSP leaves every cpuset on both cores and no
    # device rc narrows them, so background work (sync, app jobs, dex2oat)
    # competed with the UI for both CPUs. Background/restricted -> cpu0 only,
    # dex2oat -> cpu0; top-app gets a schedtune boost so schedutil ramps
    # sooner for what is on screen. Undo: echo 0-1 to the cpus files, boost 0.
    echo 0 > /dev/cpuset/background/cpus
    echo 0 > /dev/cpuset/restricted/cpus
    echo 10 > /dev/stune/top-app/schedtune.boost
    echo 1 > /dev/stune/top-app/schedtune.prefer_idle
    echo 1 > /dev/stune/foreground/schedtune.prefer_idle
    /system/bin/setprop dalvik.vm.dex2oat-cpu-set 0
    /system/bin/setprop dalvik.vm.boot-dex2oat-cpu-set 0
    # ABOX idle power-off (2026-11-18): when audio goes idle, stop the DSP
    # cleanly so it drops its MIF request (flexpmu "MIF req_Master 0x2");
    # idle (SICD) can then power the memory interface down like Tizen
    # (MIF seq down 0 -> ~10/s). It applies at the next ABOX runtime
    # suspend, so cycle the device once (DSP firmware needs ~16 s to boot
    # before it may be stopped). Undo: delete this block.
    (
        echo 1 > /sys/module/abox/parameters/r800_rtpm_poweroff
        A=/sys/devices/platform/14a50000.abox/power
        echo on > $A/control; $B sleep 25; echo auto > $A/control
    ) &
    # Top button (gpio_keys, BACK) on the watch face turns the screen off (Back
    # does nothing there; neither button maps to POWER). Native helper with a
    # persistent uinput keyboard: "input keyevent" would take ~3 s.
    KTOP=; KOTHER=
    for e in /sys/class/input/event*; do
        case "$($B cat $e/device/name 2>/dev/null)" in
        gpio_keys) KTOP=/dev/input/${e##*/} ;;
        # tizen_detent: a bezel turn in ambient wakes the screen (not grabbed,
        # so Android still gets the rotation)
        s2mpw02-power-keys|sec_touchscreen|tizen_detent) KOTHER="$KOTHER /dev/input/${e##*/}" ;;
        esac
    done
    [ -n "$KTOP" ] && /oem/r800dev/bin/r800keys $KTOP $KOTHER > /dev/null 2>&1 &
    # Vibrator: the kernel's ztm620_motor exposes timed_output/vibrator/enable;
    # the vibrator HAL (vibrator.default.so) writes it as user system.
    V=/sys/class/timed_output/vibrator/enable
    [ -e $V ] && $B chown system:system $V && $B chmod 0664 $V
    # Touch boost (tools/r800boost.c): the power HAL here is the no-op default,
    # so CPU min freq goes to max on touch/buttons, and the GPU to 667 MHz when
    # the governor owns it (GPU_SCALE), until 1 s after the last event.
    [ -x /oem/r800dev/bin/r800boost ] && $B setsid /oem/r800dev/bin/r800boost $KTOP $KOTHER > /oem/r800dev/r800boost.log 2>&1 < /dev/null &
    # Charging ring needs this on (persist props load late, so set it after boot);
    # the "Not charging" dialog is fixed by the kernel reporting current_max = 300.
    /system/bin/setprop persist.enable_charging_experience true
    # Bottom (power) button: a long press opens the power menu, like the Galaxy
    # Watch. The Pixel image leaves it at "nothing" (its crown does the work), so
    # people kept holding until the PMIC reset and S-Boot's key-held boot menu.
    /system/bin/settings put global power_button_long_press 1

    # Every boot: skip the phone-pairing setup. This must not be gated by the
    # one-time flag: /data can carry r800-setup-done from an older image while
    # the current one still boots into the Mobvoi/Wear setup screen.
    # Pair mode (touch /data/r800-pair-mode): leave the setup wizard alone so it can
    # pair with the phone's Pixel Watch app; it marks setup complete itself.
    # User mode (no DEV): the setup wizard is never touched, so a new watch
    # (blank /data) starts with Wear OS's own setup and pairs with the phone.
    ( if ! dev; then
          k "user mode: setup wizard left to Wear OS"
      elif [ -f /data/r800-pair-mode ]; then
          /system/bin/pm enable com.google.android.wearable.setupwizard
          k "pair mode: setup wizard left on"
      else
          /system/bin/settings put global device_provisioned 1
          /system/bin/settings put secure user_setup_complete 1
          /system/bin/pm disable-user --user 0 com.google.android.wearable.setupwizard
          /system/bin/am start -a android.intent.action.MAIN -c android.intent.category.HOME
          k "setup bypass done"
      fi
      # HLPM for ambient (panel low-power mode, ~23 mA) is a kernel parameter:
      # run185+ defaults to normal mode at the lowest level, so select HLPM.
      # A plain echo, so it stays on the every-boot path.
      echo 1 > /sys/module/panel_samsung_s6e36w3x01/parameters/r800_hlpm
      # The phone's Bluetooth internet proxy (sysproxyd) stays on, as stock: on
      # 2026-11-20 it connected ~20-60 s after start (WearConnectivityService
      # "Companion proxy" CONNECTED, network COMPANION_PROXY, VALIDATED, default)
      # while Wi-Fi stayed up too. It used to be stopped here in the belief the
      # phone passed no traffic; tests had simply ended before it connected.
      # Wake the screen now that boot is done: ukey (the persistent uinput
      # keyboard from the sensor bridge) costs nothing, and only stands down
      # to a whole "input keyevent" VM when ukey is not running.
      if $B pgrep -f ukey >/dev/null 2>&1 && [ -p /dev/r800_ukey ]; then
          echo wakeup > /dev/r800_ukey &
      else
          /system/bin/input keyevent 224
      fi
      # Everything in this block persists in /data (settings XMLs, overlay
      # state), and each settings/cmd call is a whole VM, ~2 s of CPU each,
      # landing exactly when the watch first answers touch. So: one pass per
      # /data lifetime, marked by /data/r800-prefs. Any /data that predates
      # the marker (old images, RESET_DATA) gets exactly one corrective pass.
      # Re-apply by hand: rm /data/r800-prefs and reboot. (repair.sh is not it:
      # that one resets pairing state on purpose.)
      #   screen sleeps after 15 s (the composer turns the panel off with DCS
      #   "display off" and back on, see hwcomposer_r800.c) and stay-on-while-
      #   plugged is off (old images stored "stay on" here);
      #   ambient on by default, once per /data lifetime (then it is the
      #   user's setting; the HLPM echo above is the panel side of it);
      #   the two RROs: WCS's system complication map (1 = battery, 4 = steps,
      #   16 = day/date, ...) comes up disabled here and without it the system
      #   UI can't push battery/steps updates, faces refresh only every ~15+ min;
      #   our framework RRO (pinner off, no ambient burn-in mask) was found
      #   disabled once.
      if [ ! -f /data/r800-prefs ]; then
          /system/bin/cmd overlay enable com.google.android.wearable.app.overlay.sysui.default
          /system/bin/cmd overlay enable com.r800.overlay.pinner
          /system/bin/settings put global ambient_enabled 1
          /system/bin/settings put secure ambient_enabled 1
          /system/bin/settings put global stay_on_while_plugged_in 0
          /system/bin/settings put system screen_off_timeout 15000
          touch /data/r800-prefs
          k "bring-up settings applied (/data/r800-prefs)"
      fi
      # Memory trims, once per /data lifetime (own marker so a /data that
      # already has r800-prefs gets them too). ~700 MB RAM: every app that
      # starts on its own gets killed by lmkd, restarts, and pulls memory back
      # from swap, which is where the long UI stalls come from.
      #   Dynamic System Updates: never used on this watch, ~43 MB per start.
      #   Play Store: no background starts (~65 MB for :background, auto-update
      #   storms after boot); it still updates apps while it is open. Its boot
      #   receiver is off too: BOOT_COMPLETED is exempt from the background
      #   block, so it otherwise started ~280 MB of Play Store at every boot.
      #   Secure element service (com.android.se, persistent, ~46 MB): only
      #   for NFC payments / eSIM, and this watch has neither. Uninstalled for
      #   user 0, not disabled: the activity manager starts persistent apps
      #   even when they are disabled (same as the NFC app).
      # Undo: pm enable com.android.dynsystem;
      #   cmd package install-existing com.android.se;
      #   cmd appops set com.android.vending RUN_ANY_IN_BACKGROUND allow;
      #   pm enable com.android.vending/com.google.android.finsky.backgroundbroadcast.receiver.BootReceiver
      # The marker is versioned: bump it when a trim is added.
      if [ ! -f /data/r800-memtrim3 ]; then
          /system/bin/pm disable-user --user 0 com.android.dynsystem
          /system/bin/pm uninstall --user 0 com.android.se
          /system/bin/cmd appops set com.android.vending RUN_ANY_IN_BACKGROUND ignore
          /system/bin/pm disable com.android.vending/com.google.android.finsky.backgroundbroadcast.receiver.BootReceiver
          touch /data/r800-memtrim3
          k "memory trims applied (/data/r800-memtrim3)"
      fi
      # Touchscreen IDC (2026-11-19): with no IDC, InputReader treats the
      # internal touchscreen as touch.wake=0, so touches never wake the device.
      # A tilt-to-wake "peek" lights the screen while the power manager stays
      # Dozing; touches still reach sysui, but PowerManager ignores user
      # activity while dozing, and the peek drops back to ambient ~8 s later in
      # the middle of use. touch.wake=1 turns a touch in ambient or a peek into
      # a real wake. Android reads /data/system/devices/idc after the image
      # partitions. If the file was missing, system_server has already opened
      # the device without it: recreate the node so EventHub reopens it (made
      # 666 first, or EventHub's open loses the race to the chmod).
      # Undo: rm /data/system/devices/idc/sec_touchscreen.idc and reboot.
      IDC=/data/system/devices/idc/sec_touchscreen.idc
      if [ ! -f $IDC ]; then
          $B mkdir -p ${IDC%/*}
          printf '%s\n' 'touch.deviceType = touchScreen' 'touch.orientationAware = 1' \
              'touch.wake = 1' > $IDC
          chown -R system:system /data/system/devices; chmod 755 /data/system/devices ${IDC%/*}
          chmod 644 $IDC; /system/bin/restorecon -R /data/system/devices
          for n in /sys/class/input/input*; do
              [ "$($B cat $n/name)" = sec_touchscreen ] || continue
              E=$($B basename $n/event*); D=$($B cat $n/$E/dev)
              rm /dev/input/$E; $B sleep 1
              $B mknod -m 666 /dev/input/$E c ${D%:*} ${D#*:}; $B sleep 2
              chown root:input /dev/input/$E; chmod 660 /dev/input/$E
              /system/bin/restorecon /dev/input/$E
          done
          k "touchscreen IDC installed (touch.wake=1), $E reopened"
      fi
      # Deep doze would stop telnet answering and Wi-Fi being serviced, and it
      # has not been verified to persist across reboots, so this one stays on
      # the every-boot path. Fold it into the marker block once that is
      # checked (dumpsys deviceidle after a reboot).
      /system/bin/dumpsys deviceidle disable
      # Input/power diagnostics only on demand: touch /oem/r800dev/android/DIAG.
      [ -f /oem/r800dev/android/DIAG ] && \
          { /system/bin/dumpsys input; /system/bin/dumpsys power; } > /oem/r800dev/diag-input.txt 2>&1
      k "post-boot done" ) > /dev/null 2>&1 &
    # Health Services (heart rate, steps, exercise for Fit/Fitbit/complications):
    # pin its provider platform to GENERAL (2) = plain SensorManager sensors. Its
    # default here is HOMIE (Pixel Watch: CHRE context hub providers); start.sh
    # denies it the context hub. The setting is read when WHS starts, so stop it
    # once after changing it.
    WD=/data/user_de/0/com.google.android.wearable.healthservices
    WF=$WD/shared_prefs/provider_switch_config.xml
    if [ -d $WD ] && ! $B grep -q 'provider_platform_key" value="2"' $WF 2>/dev/null; then
        ( U=$($B stat -c %u $WD)
          /system/bin/am force-stop com.google.android.wearable.healthservices
          $B mkdir -p $WD/shared_prefs
          printf '%s\n' "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>" '<map>' \
              '    <int name="provider_platform_key" value="2" />' '</map>' > $WF
          $B chown -R $U:$U $WD/shared_prefs; $B chmod 771 $WD/shared_prefs; $B chmod 660 $WF
          /system/bin/restorecon -R $WD/shared_prefs
          /system/bin/pm enable com.google.android.wearable.healthservices
          k "whs: provider platform GENERAL" ) > /dev/null 2>&1 &
    fi
    # Fit's "Background heart rate" (its CHRM setting) has Play Services sample the
    # HR sensor every 10 min (GMS ManualSampleSensorAdapter: alarm, short burst,
    # skipped off the wrist). Fit only offers it behind a server flag that is off
    # for this device; the flag lives in Fit's phenotype cache, which a flag sync
    # can rewrite, so check it now and every 2 h. The user's on/off choice stays
    # in Fit's settings.
    FP=/data/data/com.google.android.apps.fitness/shared_prefs/phenotype_.xml
    ( while :; do
        if $B grep -q 'micro.enable_continuous_heart_rate_nadal" value="false"' $FP 2>/dev/null; then
            $B sed -i 's/micro.enable_continuous_heart_rate_nadal" value="false"/micro.enable_continuous_heart_rate_nadal" value="true"/' $FP
            # sed -i keeps owner and mode but drops the app's MLS categories
            /system/bin/restorecon $FP
            /system/bin/am kill com.google.android.apps.fitness
            k "fit: background heart rate flag set"
        fi
        $B sleep 7200
      done ) > /dev/null 2>&1 &
    # CPU deep-idle is independent of system suspend. Separate the flags so
    # either mechanism can be tested on its own. Keep state1 off by default;
    # opt in only with android/CPUIDLE_DEEP (may hang, may save battery).
    for c in 0 1; do
        IDLE=/sys/devices/system/cpu/cpu$c/cpuidle/state1/disable
        [ -e "$IDLE" ] || continue
        if [ -f /oem/r800dev/android/CPUIDLE_DEEP ]; then
            echo 0 > "$IDLE" 2>/dev/null || k "power: state1 enable failed cpu$c"
        else
            echo 1 > "$IDLE" 2>/dev/null || k "power: state1 disable failed cpu$c"
        fi
    done

    # /data is only 190 MB: Play Store keeps re-downloading an update (35-57 MB a
    # try) that can never install, until writes fail with ENOSPC (overlays, prefs
    # and settings then break). Drop its stale downloads when free space is low.
    PD=/data/data/com.android.vending/files/phonesky-download-service
    if [ "$($B df -k /data | $B awk 'NR==2{print $4}')" -lt 61440 ] && [ -d $PD ]; then
        $B rm -rf $PD/*; k "low /data: cleared Play Store downloads"
    fi

    # A fresh install's /data (p18) is a small ext4 from the install package:
    # grow it online to the whole partition, once.
    if [ ! -f /data/r800-grown ]; then
        /system/bin/resize2fs /dev/block/loop2 > /dev/null 2>&1 &&
            touch /data/r800-grown && k "/data grown to $($B df -h /data | $B awk 'NR==2{print $2}')"
    fi

    # One-time, kept in the persistent /data: each svc/settings/pm/am call starts a
    # whole VM. rm /data/r800-setup-done (or RESET_DATA) to redo it.
    if [ ! -f /data/r800-setup-done ]; then
        ( /system/bin/settings put global device_name "Galaxy Watch"
          # developer mode skips the setup wizard (it wants a paired phone);
          # without this flag Settings only shows its short pre-pairing menu
          dev && /system/bin/settings put system setup_wizard_has_run 1
          # NFC crash-loops forever on this hardware; pm uninstall --user 0 is
          # reversible with: cmd package install-existing <pkg>
          /system/bin/pm uninstall -k --user 0 com.android.nfc
          touch /data/r800-setup-done
          k "one-time setup done" ) > /dev/null 2>&1 &
    fi

    # Developer mode (android/DEV): Wi-Fi forced on with the Wear Wi-Fi mediator
    # off. No network shell is provided in either mode. Without DEV, Wear OS
    # manages Wi-Fi and the phone link itself.
    if [ -f /oem/r800dev/android/DEV ]; then
    W=/dev/r800wpa; $B mkdir -p $W
    WPA=/oem/r800dev/bin/wpa_supplicant
    inet() { $B ip -4 addr show wlan0 2>/dev/null | $B grep -q inet; }
    # Android owns Wi-Fi: it gets a real network (apps have internet) and nothing
    # fights over wlan0. Join the Tizen network with the passphrase in wifi.pass.
    SSID=$($B sed -n 's/^[[:space:]]*ssid="\(.*\)"[[:space:]]*$//p' /oem/r800dev/wpa.conf | $B head -1)
    PASS=$($B cat /oem/r800dev/wifi.pass 2>/dev/null)
    # Keep Wi-Fi on: once paired, WearWifiMediator turns it off ~30 s after boot
    # (OFF_NO_REQUESTS; the phone link is meant to carry traffic) and the shell is lost.
    /system/bin/settings put global cw_disable_wifimediator 1
    /system/bin/cmd wifi set-wifi-enabled enabled
    for i in $($B seq 1 20); do inet && break; $B sleep 2; done
    if ! inet && [ -n "$PASS" ]; then
        /system/bin/cmd wifi connect-network "$SSID" wpa2 "$PASS" > /dev/null 2>&1
        for i in $($B seq 1 45); do inet && break; $B sleep 2; done
    fi
    MODE=android
    if ! inet; then
        # fallback: our own supplicant + DHCP (Android Wi-Fi off so it cannot fight)
        MODE=helper
        /system/bin/cmd wifi set-wifi-enabled disabled; /system/bin/setprop ctl.stop wpa_supplicant; $B sleep 3
        for i in 1 2 3 4 5 6 7 8 9 10; do [ -d /sys/class/net/wlan0 ] && break; $B sleep 1; done
        $B ifconfig wlan0 up
        $B sed 's#^ctrl_interface=.*#ctrl_interface=/dev/r800wpa#' /oem/r800dev/wpa.conf > $W/wpa.conf
        $B cat > $W/dhcp.sh <<'H'
#!/oem/r800dev/bin/busybox sh
B=/oem/r800dev/bin/busybox
case "$1" in
    deconfig) $B ifconfig "$interface" 0.0.0.0 ;;
    bound|renew)
        $B ifconfig "$interface" "$ip" netmask "${subnet:-255.255.255.0}"
        for r in $router; do $B route add default gw "$r" dev "$interface"; break; done ;;
esac
exit 0
H
        $B chmod 755 $W/dhcp.sh
        "$WPA"             -B -i wlan0 -D nl80211 -c $W/wpa.conf > /dev/null 2>&1
        $B udhcpc -i wlan0 -s $W/dhcp.sh -b -t 20 -T 3 -x hostname:galaxywatch > /dev/null 2>&1
        for i in $($B seq 1 30); do inet && break; $B sleep 1; done
    fi
    # Policy routing: LAN traffic must find the LAN route, which
    # lives in the main table (helper mode) or the wlan0 table (Android mode).
    /system/bin/ip rule add from all lookup main pref 9999 2>/dev/null
    /system/bin/ip rule add from all lookup wlan0 pref 9998 2>/dev/null
    # Once paired, the Bluetooth companion proxy outranks Wi-Fi (score 100 vs 60) and
    # ConnectivityService tears Wi-Fi down after a ~20 s linger. KeepWifi files a
    # standing Wi-Fi request so it stays up (tools/keepwifi). With sysproxyd stopped
    # there is no proxy network and Wi-Fi stays up on its own, so KeepWifi (a
    # 21 MB Java process) only starts if Wi-Fi has been gone for a minute.
    # The phone proxy (sysproxyd) now runs and becomes the default network, so
    # hold the Wi-Fi request from the start: on 2026-11-20 Wi-Fi was torn down
    # and re-made several times (network 102 -> 106) and the shell dropped.
    [ -f /oem/r800dev/keepwifi.dex ] && ! $B pgrep -f KeepWifi > /dev/null &&
        CLASSPATH=/oem/r800dev/keepwifi.dex $B setsid /system/bin/app_process / KeepWifi > /oem/r800dev/keepwifi.log 2>&1 &
    # KeepWifi's request lives in system_server: when that restarts (2026-11-20: a
    # KEYCODE_ASSIST crashed it, SearchManager is null on Wear) the request is gone
    # though KeepWifi still runs, the proxy took over and Wi-Fi was torn down. So
    # restart KeepWifi whenever system_server's pid changes.
    [ -f /oem/r800dev/keepwifi.dex ] && ( down=0; ss=$(/system/bin/pidof system_server); while :; do
        $B sleep 20
        if $B ip -4 addr show wlan0 2>/dev/null | $B grep -q inet; then down=0
        else down=$((down+1)); fi
        now=$(/system/bin/pidof system_server)
        if [ -n "$now" ] && [ "$now" != "$ss" ]; then
            k "system_server restarted ($ss -> $now): re-filing the Wi-Fi request"
            ss=$now
            $B pkill -f KeepWifi
            $B sleep 10
            CLASSPATH=/oem/r800dev/keepwifi.dex $B setsid /system/bin/app_process / KeepWifi > /oem/r800dev/keepwifi.log 2>&1 &
        elif [ $down -ge 3 ] && ! $B pgrep -f KeepWifi >/dev/null; then
            k "wifi lost for a minute: starting KeepWifi"
            CLASSPATH=/oem/r800dev/keepwifi.dex $B setsid /system/bin/app_process / KeepWifi > /oem/r800dev/keepwifi.log 2>&1 &
        fi
      done ) &
    k "wifi($MODE) $($B ip -4 addr show wlan0 | $B grep -o 'inet [0-9.]*'), network shell disabled"
    # In Android mode re-join if the network is lost.
    ( n=0; while :; do
            if [ $MODE = android ]; then
            if inet; then n=0; else n=$((n+1)); fi
            [ $n -eq 4 ] && [ -n "$PASS" ] && /system/bin/cmd wifi connect-network "$SSID" wpa2 "$PASS" > /dev/null 2>&1
            # 2026-11-19: after an AP deauth (reason 6) one connect-network was
            # not enough: Android sat scanning for 24 min until Wi-Fi was
            # toggled by hand. Still down after 4 min: toggle and re-join,
            # every 4 min until it comes back.
            if [ $n -ge 8 ] && [ $((n % 8)) -eq 0 ] && [ -n "$PASS" ]; then
                k "wifi down $((n / 2)) min: toggling Wi-Fi"
                /system/bin/cmd wifi set-wifi-enabled disabled; $B sleep 3
                /system/bin/cmd wifi set-wifi-enabled enabled; $B sleep 8
                /system/bin/cmd wifi connect-network "$SSID" wpa2 "$PASS" > /dev/null 2>&1
            fi
            /system/bin/ip rule add from all lookup wlan0 pref 9998 2>/dev/null
        else
            $B ps w 2>/dev/null | $B grep -q '[r]800wpa' ||                 "$WPA"                     -B -i wlan0 -D nl80211 -c $W/wpa.conf > /dev/null 2>&1
            inet || $B udhcpc -i wlan0 -s $W/dhcp.sh -b -t 10 -T 3 -x hostname:galaxywatch > /dev/null 2>&1
        fi
        $B sleep 30
      done ) &
    else
        /system/bin/settings put global cw_disable_wifimediator 0
        k "user mode: Wi-Fi and phone link managed by Wear OS, no telnet"
    fi
    # Developer mode: logs on p17 that survive a hang (fatal-only logcat, the
    # kernel log, display/panel/key kernel messages).
    if dev; then
    /system/bin/logcat -G 4M > /dev/null 2>&1
    /system/bin/logcat -b main,system,crash -v threadtime -f /oem/r800dev/fatal.log -r 512 -n 1 SurfaceFlinger:V HWComposer:V hwcomposer:V libc:V DEBUG:V AndroidRuntime:E *:W > /dev/null 2>&1 &
    /system/bin/logcat -b kernel -v threadtime -f /oem/r800dev/kmsg.log -r 1024 -n 1 > /dev/null 2>&1 &
    $B cat /dev/kmsg | $B awk '/unvalid fd/ {next} /decon|dsim|DSIM|PANEL|s6e36|KEY_|power_keys|gpio_keys|vsync|sysmmu|fence|underrun|timeout|Oops|BUG|WARNING|blocked for more|hung_task|sysrq|r800:/ {print; fflush()}' > /oem/r800dev/kdisp.log 2>/dev/null &
    fi
    # Composer watchdog. hwc2onfb can wedge after "NoResources" under memory
    # pressure: SurfaceFlinger presents in bursts (only when content changes),
    # each failing with HWComposer errors, and no frame reaches the panel (decon
    # frame IRQ stops). Rule: an error newer than the last decon frame, with no
    # frame for 5 s after it = wedged -> kill the composer (init restarts it + SF).
    # If still no frame since the previous restart, the DECON itself is hung:
    # reboot. Never sync first (a sync blocked forever in hang 3), and stop
    # feeding the hardware dead-man so it resets us if sysrq does not.
    HWCERR=/dev/r800_hwcerr
    ( /system/bin/logcat -T 1 -v epoch HWComposer:E '*:S' 2>/dev/null |
        while read -r ts _; do echo "${ts%%.*}" > $HWCERR; done ) &
    ( irq() { $B awk '/decon_f/ { print $2; exit }' /proc/interrupts; }
      d0=$(irq); tframe=$($B date +%s); last=0
      while :; do
        $B sleep 3
        d=$(irq); now=$($B date +%s); e=$($B cat $HWCERR 2>/dev/null || echo 0)
        [ "$d" != "$d0" ] && tframe=$now
        d0=$d
        # grace: a freshly (re)started composer/SF logs errors while it comes up
        cp=$($B pidof android.hardware.graphics.composer@2.1-service)
        cage=$(( $($B cut -d. -f1 /proc/uptime) - $($B cut -d" " -f22 /proc/$cp/stat 2>/dev/null || echo 0) / 100 ))
        if [ "$e" -ge "$tframe" ] && [ $((now - e)) -ge 5 ] && [ $((now - last)) -ge 60 ] && [ "$cage" -ge 60 ]; then
            # Zero-copy (the default): a composer restart deadlocks the GPU side
            # (an app's RenderThread blocks in mmap, no frame ever arrives), so
            # skip straight to the reboot. debug.r800.zerocopy=0 keeps restarts.
            zc=$(/system/bin/getprop debug.r800.zerocopy)
            if { [ $last -gt 0 ] && [ $tframe -le $last ]; } || [ "$zc" != 0 ]; then
                k "decon hung (no frame since restart, irq $d): rebooting"
                echo "$($B date) REBOOT (irq $d)" >> /oem/r800dev/wedge.log
                kill $PETTER 2>/dev/null
                echo 1 > /proc/sys/kernel/sysrq
                echo w > /proc/sysrq-trigger     # blocked tasks -> kmsg -> kdisp.log
                $B sleep 2
                /system/bin/timeout 5 $B dmesg > /oem/r800dev/hang-dmesg.txt 2>/dev/null
                /system/bin/timeout 8 /system/bin/logcat -d -v threadtime -t 1500 > /oem/r800dev/hang-logcat.txt 2>/dev/null
                echo s > /proc/sysrq-trigger; $B sleep 3
                echo b > /proc/sysrq-trigger
                $B sleep 120                     # dead-man fires if we are still here
            fi
            k "composer wedged (hwc errors, decon irq stuck at $d): restarting"
            /system/bin/logcat -d -v threadtime -t 400 > /oem/r800dev/wedge-logcat.txt 2>/dev/null
            echo "$($B date) restart (irq $d)" >> /oem/r800dev/wedge.log
            kill $($B pidof android.hardware.graphics.composer@2.1-service) 2>/dev/null
            last=$now
        fi
      done ) &
    # Developer mode: post-boot logcat snapshot on p17 every 30 s; timeout so a
    # stuck logd cannot wedge us.
    dev && ( while :; do
        /system/bin/timeout 10 /system/bin/logcat -b main,system,crash -d -v threadtime -t 3000 > /oem/r800dev/last-logcat.txt 2>/dev/null
        $B sleep 30
      done ) &
) &

# Idle for good. Do not exit: init kills the service's whole process group when
# it ends, which would take the watchdog feeder with it.
while :; do $B sleep 3600; done
