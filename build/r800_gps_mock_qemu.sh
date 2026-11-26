#!/bin/sh
# Synthetic GPS HAL, never real hardware. Local trusted Tizen glibc required.
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 NDK-r27c donor-libdir" >&2; exit 2; }
[ "$(id -u)" -ne 0 ] || { echo "run as an unprivileged user" >&2; exit 2; }
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
NDK=$(CDPATH= cd -- "$1" && pwd -P)
SRC=$(CDPATH= cd -- "$2" && pwd -P)
TC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
QEMU=$(command -v qemu-arm-static) || { echo "BLOCKED: qemu-arm-static missing" >&2; exit 2; }
BWRAP=$(command -v bwrap) || { echo "BLOCKED: bubblewrap missing" >&2; exit 2; }
QEMU=$(realpath "$QEMU")
BWRAP=$(realpath "$BWRAP")
command -v timeout >/dev/null
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
trap 'exit 1' HUP INT TERM
mkdir -p "$TMP/guest/lib" "$TMP/guest/usr/lib" "$TMP/guest/dev" "$TMP/guest/proc" "$TMP/guest/opt/usr/r800dev"
mkdir -m 700 "$TMP/daemon-runtime"
: > "$TMP/guest/qemu"
python3 "$ROOT/build/r800_gps_donor_snapshot.py" create "$SRC" "$TMP/guest/lib" "$TMP/donor.json"
R800_XTRA_ABI=0 R800_TIZEN_ARCHIVE='' sh "$ROOT/src/tools/gps/build.sh" "$NDK" "$TMP/guest/lib" "$TMP/guest/gpsbridge"
python3 "$ROOT/build/r800_gps_link_gate.py" --binary "$TMP/guest/gpsbridge" --libdir "$TMP/guest/lib"
(cd "$TMP/guest" && sha256sum gpsbridge lib/*) > "$TMP/bridge.sha"
for stage in 0 1 2 3 4; do
    "$TC/clang" --target=armv7a-linux-gnueabi -marm -mfloat-abi=softfp -mfpu=vfpv3-d16 \
        -O2 --no-default-config -nostdinc -ffreestanding -fno-builtin -fno-stack-protector \
        -Wall -Wextra -Werror -fPIC -fvisibility=hidden -shared -nostdlib -fuse-ld=lld --ld-path="$TC/ld.lld" \
        -Wl,--hash-style=sysv,-z,noexecstack,-z,now,--no-undefined \
        -DR800_XTRA_ABI=0 -DMOCK_FAIL="$stage" \
        -o "$TMP/guest/usr/lib/libbrcm.so" "$ROOT/tests/r800_mock_gps_hal.c"
    sha256sum "$TMP/guest/usr/lib/libbrcm.so" "$QEMU" "$BWRAP" > "$TMP/stage.sha"
    rc=0
    timeout -k 5s 20s "$BWRAP" --unshare-all --die-with-parent --new-session \
        --clearenv --ro-bind "$TMP/guest" / --ro-bind "$QEMU" /qemu \
        --dev /dev --proc /proc --chdir / \
        /qemu -cpu cortex-a15 -L / -E LD_LIBRARY_PATH=/lib /gpsbridge 0 \
        > "$TMP/run-$stage.log" 2>&1 || rc=$?
    (cd "$TMP/guest" && sha256sum -c "$TMP/bridge.sha")
    sha256sum -c "$TMP/stage.sha"
    python3 "$ROOT/build/r800_gps_donor_snapshot.py" verify "$SRC" "$TMP/guest/lib" "$TMP/donor.json"
    python3 "$ROOT/build/r800_gps_mock_transcript.py" --stage "$stage" --exit-code "$rc" --log "$TMP/run-$stage.log"
    if [ "$stage" = 0 ]; then
        # Only the fresh private runtime directory is writable by the guest.
        # Pathname UNIX sockets can be reached from the host via this mount.
        (
            timeout -k 5s 45s "$BWRAP" --unshare-all --die-with-parent --new-session \
                --clearenv --ro-bind "$TMP/guest" / --ro-bind "$QEMU" /qemu \
                --bind "$TMP/daemon-runtime" /opt/usr/r800dev \
                --dev /dev --proc /proc --chdir / \
                /qemu -cpu cortex-a15 -L / -E LD_LIBRARY_PATH=/lib /gpsbridge daemon \
                > "$TMP/daemon.log" 2>&1 &
            daemon_pid=$!
            trap 'kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true' EXIT
            trap 'exit 1' HUP INT TERM
            timeout -k 2s 35s python3 "$ROOT/build/r800_gps_mock_peer.py" \
                --socket "$TMP/daemon-runtime/gps.sock" --log "$TMP/daemon.log"
            kill -0 "$daemon_pid"
        )
        (cd "$TMP/guest" && sha256sum -c "$TMP/bridge.sha")
        sha256sum -c "$TMP/stage.sha"
        python3 "$ROOT/build/r800_gps_donor_snapshot.py" verify "$SRC" "$TMP/guest/lib" "$TMP/donor.json"
        echo "QEMU_SYNTHETIC_GPS_DAEMON_SOCKET=PASS"
    fi
done
echo "QEMU_SYNTHETIC_GPS_HAL=PASS"
echo "GNSS_RUNTIME_VERIFIED=false"
echo "safe_to_flash=false"
