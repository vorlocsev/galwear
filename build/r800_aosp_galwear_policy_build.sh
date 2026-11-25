#!/usr/bin/env bash
# Disposable AOSP checkout only. Builds a modified diagnostic policy, never stock.
set -euo pipefail
[[ $# == 2 ]] || { echo "usage: $0 <disposable-synced-aosp-root> <new-output-dir>" >&2; exit 2; }
TOOLS=$(cd -- "$(dirname -- "$0")" && pwd)
FIXTURE="$TOOLS/../src/android/sepolicy"
ROOT=$(realpath "$1")
OUT=$(realpath -m "$2")
test ! -e "$OUT"
[[ "$OUT" != "$ROOT" && "$OUT" != "$ROOT/"* ]]
cd "$ROOT"
test "$(git -C .repo/manifests rev-parse HEAD)" = 4466d48178452bf5ac136852bf2768af407a0584
test ! -e .repo/local_manifest.xml
if [[ -d .repo/local_manifests && -n "$(find .repo/local_manifests -name '*.xml' -print -quit)" ]]; then exit 2; fi
repo forall -e -c 'test "$(git rev-parse HEAD)" = "$(git rev-parse "$REPO_LREV")" && test -z "$(git status --porcelain)"'
PRIVATE="$ROOT/system/sepolicy/private"
TE="$PRIVATE/galwear_property_client.te"
test ! -e "$TE" && test ! -L "$TE"
for f in file_contexts property_contexts; do
    test -f "$PRIVATE/$f" && test ! -L "$PRIVATE/$f"
done
# Refuse an existing exact key (including a future platform version mapping).
python3 "$TOOLS/r800_galwear_policy_fixture.py" --private "$PRIVATE" --fixture "$FIXTURE"
mkdir "$OUT"
repo manifest -r -o "$OUT/manifest-resolved.xml"
BACKUP=$(mktemp -d "$OUT/original-contexts.XXXXXX")
cp -p "$PRIVATE/file_contexts" "$PRIVATE/property_contexts" "$BACKUP/"
cleanup() {
    cp -p "$BACKUP/file_contexts" "$BACKUP/property_contexts" "$PRIVATE/"
    rm -f -- "$TE"
    git -C "$ROOT/system/sepolicy" diff --exit-code
}
trap cleanup EXIT
cp "$FIXTURE/galwear_property_client.te" "$TE"
for f in file_contexts property_contexts; do
    printf '\n# GalWear disposable diagnostic fixture\n' >> "$PRIVATE/$f"
    cat "$FIXTURE/$f" >> "$PRIVATE/$f"
done
unset OUT_DIR_COMMON_BASE
export OUT_DIR="$OUT/aosp-out"
set +u
source build/envsetup.sh
lunch aosp_arm64-eng
test "$(get_build_var TARGET_ARCH)" = arm64
test "$(get_build_var SELINUX_IGNORE_NEVERALLOWS)" != true
m -j4 selinux_policy checkfc sepolicy-analyze e2fsdroid
PRODUCT_OUT=$(get_build_var PRODUCT_OUT)
HOST_OUT=$(get_build_var HOST_OUT)
set -u
test -x "$HOST_OUT/bin/e2fsdroid"
printf '%s\n' "$(realpath "$PRODUCT_OUT")" > "$OUT/product-out-path.txt"
printf '%s\n' "$(realpath "$HOST_OUT")" > "$OUT/host-out-path.txt"
python3 "$TOOLS/r800_galwear_policy_fixture.py" \
    --product-out "$PRODUCT_OUT" --checkfc "$HOST_OUT/bin/checkfc" \
    --analyze "$HOST_OUT/bin/sepolicy-analyze" --report "$OUT/fixture-policy-audit.json"
sha256sum "$OUT/manifest-resolved.xml" "$FIXTURE/galwear_property_client.te" \
    "$FIXTURE/file_contexts" "$FIXTURE/property_contexts" \
    "$OUT/fixture-policy-audit.json" > "$OUT/input-digests.sha256"
printf 'status=GALWEAR_CLIENT_POLICY_BUILD_ONLY\nproduction_policy=false\nsafe_to_flash=false\n' > "$OUT/status.txt"
