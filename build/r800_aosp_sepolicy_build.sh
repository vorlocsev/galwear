#!/usr/bin/env bash
# Build stock AOSP policy and host checkfc, never install/load host or guest policy.
set -euo pipefail
[[ $# == 2 ]] || { echo "usage: $0 <synced-aosp-root> <new-output-dir>" >&2; exit 2; }
TOOLS=$(cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(realpath "$1")
OUT=$(realpath -m "$2")
test ! -e "$OUT"
[[ "$OUT" != "$ROOT" && "$OUT" != "$ROOT/"* ]]
cd "$ROOT"
test "$(git -C .repo/manifests rev-parse HEAD)" = 4466d48178452bf5ac136852bf2768af407a0584
test ! -e .repo/local_manifest.xml
if [[ -d .repo/local_manifests && -n "$(find .repo/local_manifests -name '*.xml' -print -quit)" ]]; then exit 2; fi
repo forall -e -c 'test "$(git rev-parse HEAD)" = "$(git rev-parse "$REPO_LREV")" && test -z "$(git status --porcelain)"'
mkdir "$OUT"
repo manifest -r -o "$OUT/manifest-resolved.xml"
unset OUT_DIR_COMMON_BASE
export OUT_DIR="$OUT/aosp-out"
set +u
source build/envsetup.sh
lunch aosp_arm64-eng
test "$(get_build_var TARGET_ARCH)" = arm64
m -j4 selinux_policy checkfc
PRODUCT_OUT=$(get_build_var PRODUCT_OUT)
HOST_OUT=$(get_build_var HOST_OUT)
set -u
python3 "$TOOLS/r800_android_sepolicy_audit.py" --product-out "$PRODUCT_OUT" \
    --checkfc "$HOST_OUT/bin/checkfc" --report "$OUT/sepolicy-audit.json"
git -C system/sepolicy rev-parse HEAD > "$OUT/sepolicy-source-commit.txt"
sha256sum "$OUT/manifest-resolved.xml" "$OUT/sepolicy-audit.json" > "$OUT/source-evidence.sha256"
printf 'status=ANDROID_SEPOLICY_BUILD_AND_STATIC_AUDIT_ONLY\nsafe_to_flash=false\n' > "$OUT/status.txt"
