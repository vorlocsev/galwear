#!/bin/sh
# Build the release payload (everything under /oem/r800dev on p17) from a
# working watch's p17 tree, keeping only what start.sh and android-helper.sh
# load, and taking the scripts from this release tree.
#
#   build/mkpayload-release.sh <extracted p17 tree> <release tree> <out.tar>
#
# Run in WSL (keeps the Unix modes and the symlinks in tzlite/).
set -e
SRC=$1; REL=$2; OUT=$3
[ -d "$SRC/android" ] && [ -d "$REL/payload" ] || { echo "usage: $0 <p17 tree> <release tree> <out.tar>"; exit 2; }
T=$(mktemp -d)
P=$T/r800dev
mkdir -p $P/bin $P/hwc

# Android images, overlays, Gemini, props, blank /data. Per-watch state and the
# developer-only flags (DEV, STAY, gemini.tries) are left out.
cp -a $SRC/android $P/
# Do not inherit watch-specific state or experimental kernel power flags.
# These markers are *opt-in* runtime overrides; shipping them in a release
# bypasses the conservative suspend/CPU-idle defaults.
for marker in DEV STAY SLEEP CPUIDLE_DEEP OVERLAY PANEL_REALBLANK ABOX_POWEROFF GPU_SCALE gemini.tries userdata.img RESET_DATA; do
    rm -f "$P/android/$marker"
done
# Factory-reset-protection block: per-watch state (Android writes the owner's
# account hash there). Ship it blank; Android formats it on first boot.
dd if=/dev/zero of=$P/android/persistent.img bs=1M count=1 2> /dev/null

# Binaries the scripts start (no test or debug tools, no .bak/.old copies)
for f in busybox busybox-extras fsfreeze loopdio r800boost r800keys ukey wpcd; do
    [ -f $SRC/bin/$f ] && cp -a $SRC/bin/$f $P/bin/
done
# HALs start.sh binds over the vendor ones
for f in audio.primary.r800.so gps.r800.so hwcomposer.r800.so sensors.r800.so; do
    cp -a $SRC/hwc/$f $P/hwc/
done
# Firmware, off-mode charger, Tizen sensor/GNSS subset, musl Wi-Fi tools, preload libs
cp -a $SRC/fw $SRC/charger $SRC/tzlite $SRC/root $SRC/lib $P/
rm -f $P/charger/*.log
# Single files
for f in keepwifi.dex gpsbridge splash.raw; do cp -a $SRC/$f $P/; done

# Scripts from this release tree (user mode by default, android/DEV for development)
for f in start.sh android-helper.sh r800-display-watchdog.sh dockrot.sh udhcpc.sh repair.sh; do
    install -m 755 $REL/payload/$f $P/$f
done
install -m 755 $REL/src/tools/sensors/tzchroot.sh $P/tzchroot.sh

tar -C $T -cf "$OUT" r800dev
rm -rf $T
echo "payload: $(du -h "$OUT" | cut -f1) -> $OUT"
