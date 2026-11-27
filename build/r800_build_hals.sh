#!/bin/sh
# Local non-release HAL build. Reuse the integrated compile/PCM evidence path.
# Usage: sh build/r800_build_hals.sh <NDK r27c> <new-output-dir>
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 <NDK r27c> <new-output-dir>" >&2; exit 2; }
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
NDK=$(CDPATH= cd -- "$1" && pwd)
OUT=$2
[ ! -e "$OUT" ] && [ ! -L "$OUT" ] || { echo "output already exists" >&2; exit 2; }
grep -Eq '^Pkg.Revision[[:space:]]*=[[:space:]]*27\.2\.12479018[[:space:]]*$' "$NDK/source.properties"
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
trap 'exit 1' HUP INT TERM
BASE=1c5fb68ced57d838f2b7ecd0c00bc1fefc9ab60d
git init -q "$TMP/tinyalsa"
git -C "$TMP/tinyalsa" remote add origin https://github.com/tinyalsa/tinyalsa.git
git -C "$TMP/tinyalsa" fetch --depth=1 origin "$BASE"
git -C "$TMP/tinyalsa" checkout --detach -q FETCH_HEAD
test "$(git -C "$TMP/tinyalsa" rev-parse HEAD)" = "$BASE"
sh "$REPO/build/r800_hal_compile_smoke.sh" "$REPO" "$NDK" "$TMP/tinyalsa" "$OUT"
echo "NON-RELEASE; safe_to_flash=false"
