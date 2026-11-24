#!/bin/sh
# Regenerate kernel/r800-wearos.patch from the working kernel tree.
#
#   build/mk_kernel_patch.sh <kernel tree> <out.patch>
#   EXTRA="path ..." build/mk_kernel_patch.sh ...   (first time a tracked file changes)
#
# The patch covers the files listed in the current patch plus every untracked
# file under the directories we added wholesale. New files must be in the diff, so
# they are marked intent-to-add (git add -N) first. Only those paths are reset
# afterwards: a bare `git reset --` resets the whole index and drops the
# intent-to-add entries of earlier new files (detent, motor, bt-power).
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 <kernel source tree> <output patch>"; exit 2; }
KT=$1
OUT=$2
[ -d "$KT/.git" ] || { echo "not a git kernel source tree"; exit 2; }
BASE=50db73fc799f20a7120a8b5f653b16cc123d856f
REPO=$(cd "$(dirname "$0")/.." && pwd)
NEW_DIRS="drivers/sensorhub drivers/gps include/linux/sensor include/linux/ssp_platformdata.h"

cd "$KT"
[ "$(git rev-parse HEAD)" = "$BASE" ] || {
  echo "kernel SHA differs from pinned base; patch generation refused"; exit 2; }
old=$(grep '^diff --git' "$REPO/src/kernel/r800-wearos.patch" | awk '{print $3}' | sed 's|^a/||')
old=$(printf '%s
' $old $EXTRA | sort -u)
new=$(git ls-files -o --exclude-standard $NEW_DIRS)
[ -n "$new" ] && git add -N $new
git -c core.autocrlf=false diff $BASE -- $old $new > "$OUT"
[ -n "$new" ] && git reset -q -- $new
echo "$(grep -c '^diff --git' "$OUT") files in $OUT"
