#!/bin/sh
# Experimental standalone Wi-Fi tools, no network access by the built programs.
# Usage: sh build/r800_build_wifi_tools.sh <new-output-dir>
set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 <new-output-dir>" >&2; exit 2; }
OUT=$1
[ ! -e "$OUT" ] && [ ! -L "$OUT" ]
for tool in arm-linux-gnueabi-gcc arm-linux-gnueabi-readelf make curl sha256sum tar pkg-config qemu-arm flex bison; do
    command -v "$tool" >/dev/null || { echo "Missing tool: $tool" >&2; exit 2; }
done
mkdir -- "$OUT"
OUT=$(CDPATH= cd -- "$OUT" && pwd)
mkdir "$OUT/bin" "$OUT/src" "$OUT/evidence"
fetch() {
    url=$1; archive=$2; hash=$3
    curl --fail --location --retry 3 --max-time 180 "$url" -o "$OUT/src/$archive"
    printf '%s  %s\n' "$hash" "$OUT/src/$archive" | sha256sum -c -
    tar -xf "$OUT/src/$archive" -C "$OUT/src"
}
fetch https://github.com/thom311/libnl/releases/download/libnl3_11_0/libnl-3.11.0.tar.gz \
    libnl-3.11.0.tar.gz 2a56e1edefa3e68a7c00879496736fdbf62fc94ed3232c0baba127ecfa76874d
fetch https://w1.fi/releases/wpa_supplicant-2.12.tar.gz \
    wpa_supplicant-2.12.tar.gz 08e23937e16d0155e55cab2b51f51fbe10d80a1aa91c4e15442645059b737ef6
fetch https://cdn.kernel.org/pub/software/network/iw/iw-6.9.tar.xz \
    iw-6.9.tar.xz 3f2db22ad41c675242b98ae3942dbf3112548c60a42ff739210f2de4e98e4894
CC=arm-linux-gnueabi-gcc
export CC
PREFIX=$OUT/nl
cd "$OUT/src/libnl-3.11.0"
./configure --host=arm-linux-gnueabi --prefix="$PREFIX" --enable-static --disable-shared \
    --disable-cli > "$OUT/evidence/libnl-configure.log" 2>&1 || { tail -80 "$OUT/evidence/libnl-configure.log"; exit 1; }
make -j2 > "$OUT/evidence/libnl-build.log" 2>&1 || { tail -80 "$OUT/evidence/libnl-build.log"; exit 1; }
make install > "$OUT/evidence/libnl-install.log" 2>&1
test -f "$PREFIX/lib/libnl-3.a"
test -f "$PREFIX/lib/libnl-genl-3.a"
export PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig"
export PKG_CONFIG_PATH=
pkg-config --static --cflags --libs libnl-3.0 libnl-genl-3.0 > "$OUT/evidence/libnl-flags.txt"
cd "$OUT/src/wpa_supplicant-2.12/wpa_supplicant"
# Deliberately limited initial build: station-mode WPA2-PSK, not enterprise EAP,
# WPS, AP or WPA3/SAE. Android's primary Wi-Fi service is unchanged.
cat > .config <<EOF
CONFIG_DRIVER_NL80211=y
CONFIG_LIBNL32=y
CONFIG_CTRL_IFACE=y
CONFIG_BACKEND=file
CONFIG_TLS=internal
CONFIG_CRYPTO=internal
CONFIG_INTERNAL_LIBTOMMATH=y
CONFIG_NO_CONFIG_WRITE=y
CFLAGS += -I$PREFIX/include/libnl3
LDFLAGS += -static -L$PREFIX/lib
EOF
cp .config "$OUT/evidence/wpa.config"
make -j2 CC="$CC" wpa_supplicant wpa_cli > "$OUT/evidence/wpa-build.log" 2>&1 || { tail -80 "$OUT/evidence/wpa-build.log"; exit 1; }
cp wpa_supplicant wpa_cli "$OUT/bin/"
cd "$OUT/src/iw-6.9"
# Make pkg-config report transitive static libraries, not host headers.
cat > "$OUT/pkg-config-static" <<'EOF'
#!/bin/sh
exec pkg-config --static "$@"
EOF
chmod 755 "$OUT/pkg-config-static"
make -j2 CC="$CC" PKG_CONFIG="$OUT/pkg-config-static" LDFLAGS=-static \
    > "$OUT/evidence/iw-build.log" 2>&1 || { tail -80 "$OUT/evidence/iw-build.log"; exit 1; }
cp iw "$OUT/bin/"
for name in wpa_supplicant wpa_cli iw; do
    arm-linux-gnueabi-readelf -h -l -d --wide "$OUT/bin/$name" > "$OUT/evidence/$name.elf.txt"
    grep -Eq 'Class:[[:space:]]*ELF32' "$OUT/evidence/$name.elf.txt"
    grep -Eq 'Machine:[[:space:]]*ARM' "$OUT/evidence/$name.elf.txt"
    if grep -Eq 'INTERP|\(NEEDED\)' "$OUT/evidence/$name.elf.txt"; then
        echo "Unexpected dynamic dependency: $name" >&2; exit 2
    fi
done
# Version flags exit before interface access. Do not start services or scan.
qemu-arm "$OUT/bin/wpa_supplicant" -v > "$OUT/evidence/wpa_supplicant.version.txt"
qemu-arm "$OUT/bin/wpa_cli" -v > "$OUT/evidence/wpa_cli.version.txt"
qemu-arm "$OUT/bin/iw" --version > "$OUT/evidence/iw.version.txt"
grep -F '2.12' "$OUT/evidence/wpa_supplicant.version.txt"
grep -F '2.12' "$OUT/evidence/wpa_cli.version.txt"
grep -F '6.9' "$OUT/evidence/iw.version.txt"
{
    "$CC" --version
    sha256sum "$OUT"/src/*.tar.* "$OUT"/bin/*
    echo "wifi_association_verified=false"
    echo "safe_to_flash=false"
} > "$OUT/evidence/wifi-build-evidence.txt"
cat "$OUT/evidence/wifi-build-evidence.txt"
