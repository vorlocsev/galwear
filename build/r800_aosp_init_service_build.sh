#!/usr/bin/env bash
# Compile original Android init and an experimental libinit harness, never run them on host.
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
OVERLAY="$ROOT/system/core/init/galwear_property_fixture"
mkdir "$OVERLAY"
trap 'rm -f -- "$OVERLAY/Android.bp" "$OVERLAY/property-service-harness.cpp" "$OVERLAY/property-service-client.c"; rmdir -- "$OVERLAY"' EXIT
cp "$TOOLS/../src/android/property-service-harness.cpp" "$TOOLS/../src/android/property-service-client.c" "$OVERLAY/"
cat > "$OVERLAY/Android.bp" <<'BP'
cc_binary {
    name: "galwear_property_service",
    defaults: ["init_defaults"],
    srcs: ["property-service-harness.cpp"],
    include_dirs: ["system/core/init"],
    static_libs: ["libinit"],
    compile_multilib: "64",
}

cc_binary {
    name: "galwear_property_client",
    srcs: ["property-service-client.c"],
    compile_multilib: "64",
    stl: "none",
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
test "$(get_build_var TARGET_ARCH)" = arm64
m -j4 init_second_stage galwear_property_service galwear_property_client
PRODUCT_OUT=$(get_build_var PRODUCT_OUT)
set -u
python3 "$TOOLS/r800_android_init_inventory.py" --product-out "$PRODUCT_OUT" --report "$OUT/init-inventory.json"
git -C system/core rev-parse HEAD > "$OUT/system-core-commit.txt"
sha256sum system/core/init/property_service.cpp system/core/init/property_service.h \
    system/core/init/Android.bp "$OVERLAY/Android.bp" "$OVERLAY/property-service-harness.cpp" \
    "$OVERLAY/property-service-client.c" "$OUT/manifest-resolved.xml" > "$OUT/source-inputs.sha256"
# Do not upload binaries, execute Android init on the host or package a flash image.
printf 'status=ORIGINAL_INIT_AND_LIBINIT_HARNESS_BUILD_ONLY\nsafe_to_flash=false\n' > "$OUT/status.txt"
