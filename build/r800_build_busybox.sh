#!/bin/sh
# Non-release BusyBox source build, ARM EABI soft-float, no device access.
# Usage: sh build/r800_build_busybox.sh <new-output-dir>
set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 <new-output-dir>" >&2; exit 2; }
OUT=$1
[ ! -e "$OUT" ] && [ ! -L "$OUT" ]
for tool in arm-linux-gnueabi-gcc arm-linux-gnueabi-readelf make curl sha256sum tar python3 qemu-arm; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 2; }
done
mkdir -- "$OUT"
OUT=$(CDPATH= cd -- "$OUT" && pwd)
VERSION=1.38.0
SHA=34f9ea6ff8636f2c9241153b9114eefa9e65674a45318ae1ef95bb5f31c53bb2
curl --fail --location --retry 3 --max-time 180 \
    "https://www.busybox.net/downloads/busybox-$VERSION.tar.bz2" -o "$OUT/source.tar.bz2"
printf '%s  %s\n' "$SHA" "$OUT/source.tar.bz2" | sha256sum -c -
tar -xjf "$OUT/source.tar.bz2" -C "$OUT"
cd "$OUT/busybox-$VERSION"
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- defconfig > "$OUT/configure.log"
python3 - <<'PY'
from pathlib import Path
import re
p=Path(".config")
c=p.read_text()
def set_bool(name,value):
    global c
    pattern=r"^(?:CONFIG_"+name+r"=.*|# CONFIG_"+name+r" is not set)$"
    replacement="CONFIG_"+name+"=y" if value else "# CONFIG_"+name+" is not set"
    c,n=re.subn(pattern,replacement,c,flags=re.M)
    if n!=1:
        raise SystemExit("Missing or duplicate config key: "+name)
set_bool("STATIC",True)
# tc references legacy CBQ structures removed from current Linux UAPI.
# No R800 startup script calls tc.
set_bool("TC",False)
# No network server applets or login/credential tools in this candidate.
for name in ("TELNETD","HTTPD","FTPD","TFTPD","INETD","NC","LOGIN","PASSWD","SU"):
    if re.search(r"^(?:CONFIG_"+name+r"=.*|# CONFIG_"+name+r" is not set)$",c,re.M):
        set_bool(name,False)
p.write_text(c)
PY
yes "" | make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- oldconfig >> "$OUT/configure.log"
grep -qx 'CONFIG_STATIC=y' .config
grep -qx '# CONFIG_TC is not set' .config || { echo 'TC unexpectedly enabled by oldconfig' >&2; exit 2; }
make -j2 ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- > "$OUT/build.log" 2>&1 || { tail -80 "$OUT/build.log"; exit 1; }
mkdir "$OUT/bin"
cp busybox "$OUT/bin/busybox"
cp .config "$OUT/busybox.config"
arm-linux-gnueabi-readelf -h -l -d --wide "$OUT/bin/busybox" > "$OUT/busybox.elf.txt"
grep -Eq 'Class:[[:space:]]*ELF32' "$OUT/busybox.elf.txt"
grep -Eq 'Machine:[[:space:]]*ARM' "$OUT/busybox.elf.txt"
if grep -Eq 'INTERP|\(NEEDED\)' "$OUT/busybox.elf.txt"; then
    echo "Unexpected dynamic dependency" >&2; exit 2
fi
# Execute only harmless applet inventory in user-mode CPU emulation.
qemu-arm "$OUT/bin/busybox" --list > "$OUT/applets.txt"
python3 - "$OUT/applets.txt" <<'PY'
import sys
from pathlib import Path
actual=set(Path(sys.argv[1]).read_text().splitlines())
required=set("ash sh awk basename cat chmod chown chroot cut date dd df dmesg find grep head ifconfig ip ln losetup ls mkdir mkfifo mknod mkswap mount mv nslookup od pgrep pidof pkill ps reboot rm route sed seq setsid sleep stat swapon switch_root sync tail timeout touch tr udhcpc umount wget zcat".split())
forbidden=set("tc telnetd httpd ftpd tftpd inetd nc login passwd su".split())
if required-actual or actual&forbidden:
    raise SystemExit("Missing: %s; forbidden: %s" % (sorted(required-actual),sorted(actual&forbidden)))
print("PASS: required BusyBox applets present; forbidden applets absent")
PY
{
    arm-linux-gnueabi-gcc --version
    sha256sum "$OUT/source.tar.bz2" "$OUT/bin/busybox" "$OUT/busybox.config"
    echo "runtime_verified=false"
    echo "safe_to_flash=false"
} > "$OUT/busybox-evidence.txt"
cat "$OUT/busybox-evidence.txt"
