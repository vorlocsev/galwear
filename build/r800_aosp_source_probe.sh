#!/bin/sh
# Read-only public combined Exynos kernel checkout into a disposable directory.
# Never touches a real watch, kernel image, or the original Galwear project.
# Invoked by GitHub Actions; source checkout itself is disposable.
set -eu

[ "$#" -eq 3 ] || {
    echo "usage: sh build/r800_aosp_source_probe.sh <galwear-repo> <scratch-kernel-dir> <report-json>" >&2
    exit 2
}
REPO=$(CDPATH= cd -- "$1" && pwd)
SOURCE=$2
REPORT=$3
BASE=50db73fc799f20a7120a8b5f653b16cc123d856f
SOURCE_URL=https://github.com/xanderlent/COMBINED_android-kernel-exynos.git

[ -f "$REPO/src/kernel/r800-wearos.patch" ] || {
    echo "missing local R800 patch" >&2; exit 2;
}
[ ! -e "$SOURCE" ] || {
    echo "scratch source path already exists; refusing overwrite" >&2; exit 2;
}
mkdir -p "$SOURCE"
trap 'echo "source probe completed; disposable checkout remains in runner scratch only" >&2' EXIT
git -C "$SOURCE" init -q
git -C "$SOURCE" remote add origin "$SOURCE_URL"

# Request only the exact commit object. Do not silently substitute a branch
# head or a similarly named kernel. The combined tree contains the pin.
echo "Checking exact public combined Exynos base $BASE (read-only remote)"
if ! git -C "$SOURCE" -c protocol.version=2 fetch --depth=1 --filter=blob:none origin "$BASE"; then
    echo "Cannot fetch pinned combined Exynos base; refusing substitutes" >&2
    exit 3
fi
# This combined kernel is large. Limit checkout to the 131 paths actually
# touched by the Galwear diff, instead of fetching all the source blobs.
PATTERNS="$SOURCE-sparse-patterns.txt"
awk '/^diff --git a\\// {sub(/^b\\//, "", $4); print "/" $4}' \
    "$REPO/src/kernel/r800-wearos.patch" | LC_ALL=C sort -u > "$PATTERNS"
[ "$(wc -l < "$PATTERNS")" -ge 100 ] || {
    echo "Kernel diff has unexpectedly few paths; refusing sparse checkout" >&2
    exit 5
}
git -C "$SOURCE" sparse-checkout set --no-cone --stdin < "$PATTERNS"
git -C "$SOURCE" -c advice.detachedHead=false checkout --detach -q FETCH_HEAD
ACTUAL=$(git -C "$SOURCE" rev-parse HEAD)
[ "$ACTUAL" = "$BASE" ] || {
    echo "Fetched commit SHA does not match pin; refusing" >&2
    exit 4
}

# Python preflight requires a clean HEAD and uses only git apply --check.
python3 "$REPO/build/r800_kernel_preflight.py" \
    --repository "$REPO" \
    --source-tree "$SOURCE" \
    --report "$REPORT"

echo "Exact-base dry-run check done. NO kernel compiled or flashed."
