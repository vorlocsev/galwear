#!/usr/bin/env bash
# Build ONLY the Android 11 ARM64 runtime APEX from a dedicated AOSP checkout.
# No firmware, no flashing, no publication. Full source sync is a separate step.
set -euo pipefail
TOOLS=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
TAG=android-11.0.0_r48
MANIFEST=4466d48178452bf5ac136852bf2768af407a0584
[ "$#" -eq 3 ] || { echo "usage: $0 <synced-aosp-root> <new-evidence-dir> <jobs>" >&2; exit 2; }
ROOT=$(realpath "$1")
EVIDENCE=$(realpath -m "$2")
JOBS=$3
[[ "$JOBS" =~ ^[1-9][0-9]?$ ]] || { echo "Invalid job count" >&2; exit 2; }
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || { echo "Linux x86_64 required" >&2; exit 2; }
[[ ! -e "$EVIDENCE" && "$EVIDENCE" != "$ROOT" && "$EVIDENCE" != "$ROOT/"* ]] || {
    echo "Use a new evidence directory outside AOSP" >&2; exit 2;
}
cd "$ROOT"
command -v repo >/dev/null
test -f build/envsetup.sh
test -d .repo/manifests
test "$(git -C .repo/manifests rev-parse HEAD)" = "$MANIFEST"
if [[ -d .repo/local_manifests ]] && [[ -n "$(find .repo/local_manifests -name '*.xml' -print -quit)" ]]; then
    echo "Local manifests forbidden for this diagnostic" >&2; exit 2
fi
test ! -e .repo/local_manifest.xml
# Ensure project heads match the manifest-resolved revision and no tracked
# or untracked modifications enter the build. Run after repo sync -d.
repo forall -e -c 'test "$(git rev-parse HEAD)" = "$(git rev-parse "$REPO_LREV")" && test -z "$(git status --porcelain)"'
mkdir -p "$EVIDENCE"
repo manifest -r -o "$EVIDENCE/manifest-resolved.xml"
printf 'tag=%s\nmanifest_commit=%s\n' "$TAG" "$MANIFEST" > "$EVIDENCE/source.txt"
sha256sum "$EVIDENCE/manifest-resolved.xml" >> "$EVIDENCE/source.txt"
repo version >> "$EVIDENCE/source.txt"
# Refuse stale outputs and environment overrides from unrelated builds.
unset OUT_DIR_COMMON_BASE
export OUT_DIR="$EVIDENCE/aosp-out"
test ! -e "$OUT_DIR"
# AOSP envsetup is not guaranteed to be nounset-safe.
set +u
source build/envsetup.sh
lunch aosp_arm64-eng
test "$(get_build_var TARGET_ARCH)" = arm64
test "$(get_build_var TARGET_PRODUCT)" = aosp_arm64
m -j"$JOBS" com.android.runtime
PRODUCT_OUT=$(get_build_var PRODUCT_OUT)
set -u
APEX="$PRODUCT_OUT/system/apex/com.android.runtime.apex"
test -s "$APEX" || { echo "Runtime APEX missing (flattened or unsupported build output)" >&2; exit 2; }
# Local evidence only. Do not copy the APEX to an artifact or release.
sha256sum "$APEX" > "$EVIDENCE/runtime-apex.sha256"
printf '%s\n' "$(realpath "$APEX")" > "$EVIDENCE/runtime-apex-path.txt"
APEX_SHA=$(sha256sum "$APEX" | cut -d ' ' -f 1)
python3 "$TOOLS/r800_android_runtime_extract.py" --donor "$APEX" --sha256 "$APEX_SHA" \
    --out "$EVIDENCE/runtime-root" --report "$EVIDENCE/runtime-extraction.json"
printf 'status=AOSP_RUNTIME_EXTRACTED_STATIC_ONLY\nsafe_to_flash=false\n' >> "$EVIDENCE/source.txt"
