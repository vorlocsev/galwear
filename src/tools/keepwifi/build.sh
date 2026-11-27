#!/bin/sh
# Compile the helper only; never invoke app_process or connect to a network.
# Usage: sh build.sh <Android API 30 android.jar> <build-tools 30.0.3 dir> <new-out>
set -eu
[ "$#" -eq 3 ] || { echo "usage: $0 <android.jar> <build-tools dir> <new output directory>" >&2; exit 2; }
S=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
JAR=$1; BT=$2; OUT=$3
[ -f "$JAR" ] && [ -x "$BT/d8" ] && [ -x "$BT/dexdump" ]
[ ! -e "$OUT" ] && [ ! -L "$OUT" ]
grep -Eq '^Pkg.Revision[[:space:]]*=[[:space:]]*30\.0\.3$' "$BT/source.properties"
mkdir -- "$OUT"
mkdir "$OUT/classes" "$OUT/dex"
javac --release 8 -cp "$JAR" -d "$OUT/classes" "$S/KeepWifi.java"
"$BT/d8" --min-api 28 --lib "$JAR" --output "$OUT/dex" "$OUT"/classes/*.class
[ -f "$OUT/dex/classes.dex" ]
[ "$(find "$OUT/dex" -type f | wc -l)" -eq 1 ]
"$BT/dexdump" -f "$OUT/dex/classes.dex" > "$OUT/keepwifi-dex-evidence.txt"
grep -Fq 'LKeepWifi;' "$OUT/keepwifi-dex-evidence.txt"
mv "$OUT/dex/classes.dex" "$OUT/keepwifi.dex"
{
    javac -version 2>&1
    "$BT/d8" --version
    sha256sum "$JAR" "$OUT/keepwifi.dex"
    echo "runtime_verified=false"
} > "$OUT/keepwifi-build-evidence.txt"
cat "$OUT/keepwifi-build-evidence.txt"
