#!/bin/sh
# Build a structural SM-R800 NZIT candidate only (not a signed boot image).
# Usage: sh build/mkboot.sh <Image> <r800.dts> <template> <new-output.img>
set -eu
[ "$#" -eq 4 ] || { echo "usage: $0 <Image> <DTS> <template> <new-output.img>" >&2; exit 2; }
IMG=$1; DTS=$2; TPL=$3; OUT=$4
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for tool in python3 dtc; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing build tool: $tool" >&2; exit 127; }
done
[ ! -e "$OUT" ] && [ ! -L "$OUT" ] || { echo "output must not exist" >&2; exit 2; }
T=$(mktemp -d)
trap 'rm -rf -- "$T"' EXIT
trap 'exit 1' HUP INT TERM
dtc -I dts -O dtb -S 133120 -o "$T/r800.dtb" "$DTS"
python3 "$BASE/r800_boot_candidate.py" --kernel "$IMG" --dtb "$T/r800.dtb" \
    --template "$TPL" --output "$OUT"
echo "NON-RELEASE: copied signature does not authenticate the modified kernel or DTB." >&2
