#!/usr/bin/env bash
# Build a host-only property metadata fixture with pinned AOSP libraries.
# The disposable overlay is removed on exit. No Android service is started.
set -euo pipefail
[[ $# == 2 ]] || { echo "usage: $0 <synced-aosp-root> <new-output-dir>" >&2; exit 2; }
REPO=$(cd -- "$(dirname -- "$0")/.." && pwd)
ROOT=$(realpath "$1")
OUT=$(realpath -m "$2")
test ! -e "$OUT"
[[ "$OUT" != "$ROOT" && "$OUT" != "$ROOT/"* ]]
cd "$ROOT"
test "$(git -C .repo/manifests rev-parse HEAD)" = 4466d48178452bf5ac136852bf2768af407a0584
test ! -e .repo/local_manifest.xml
if [[ -d .repo/local_manifests && -n "$(find .repo/local_manifests -name '*.xml' -print -quit)" ]]; then
    exit 2
fi
repo forall -e -c 'test "$(git rev-parse HEAD)" = "$(git rev-parse "$REPO_LREV")" && test -z "$(git status --porcelain)"'
OVERLAY="$ROOT/galwear_property_fixture"
mkdir "$OVERLAY"
trap 'rm -f -- "$OVERLAY/Android.bp" "$OVERLAY/property-info-generator.cpp"; rmdir -- "$OVERLAY"' EXIT
cp "$REPO/src/android/property-info-generator.cpp" "$OVERLAY/"
cat > "$OVERLAY/Android.bp" <<'BP'
cc_binary_host {
    name: "galwear_property_info",
    srcs: ["property-info-generator.cpp"],
    static_libs: ["libpropertyinfoserializer", "libpropertyinfoparser", "libbase", "liblog"],
    cpp_std: "experimental",
    cflags: ["-Wall", "-Wextra", "-Werror"],
}
BP
mkdir "$OUT"
repo manifest -r -o "$OUT/manifest-resolved.xml"
unset OUT_DIR_COMMON_BASE
export OUT_DIR="$OUT/aosp-out"
set +u
source build/envsetup.sh
lunch aosp_arm64-eng
m -j4 galwear_property_info
HOST_OUT=$(get_build_var HOST_OUT)
set -u
"$HOST_OUT/bin/galwear_property_info" "$OUT/property_info"
"$HOST_OUT/bin/galwear_property_info" "$OUT/property_info.virt" --virt-fixture
test -s "$OUT/property_info.virt"
test -s "$OUT/property_info"
sha256sum "$OUT/property_info" "$OUT/property_info.virt" "$OUT/manifest-resolved.xml" "$OVERLAY/property-info-generator.cpp" > "$OUT/property-info.sha256"
printf 'status=PROPERTY_INFO_FIXTURE_ONLY\nproperty_service_started=false\nsafe_to_flash=false\n' > "$OUT/status.txt"
