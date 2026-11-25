#!/usr/bin/env bash
# Build a host-only property metadata fixture with pinned AOSP libraries.
# The disposable overlay is removed on exit. No Android service is started.
set -euo pipefail
[[ $# == 2 || $# == 3 ]] || { echo "usage: $0 <synced-aosp-root> <new-output-dir> [fixture-policy.bin]" >&2; exit 2; }
REPO=$(cd -- "$(dirname -- "$0")/.." && pwd)
ROOT=$(realpath "$1")
OUT=$(realpath -m "$2")
POLICY=""
if [[ $# == 3 ]]; then POLICY=$(realpath "$3"); test -f "$POLICY"; fi
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
trap 'rm -f -- "$OVERLAY/Android.bp" "$OVERLAY/property-info-generator.cpp" "$OVERLAY/bionic-property-area.c" "$OVERLAY/property_fixture.h"; rmdir -- "$OVERLAY"' EXIT
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

if [[ -n "$POLICY" ]]; then
    python3 - "$POLICY" "$OUT/property_info.virt" "$OVERLAY/property_fixture.h" <<'PY'
import pathlib, sys
policy, info, header = map(pathlib.Path, sys.argv[1:])
with header.open("x") as out:
    for name, path, limit in (("policy_blob", policy, 1048576), ("property_info_blob", info, 65536)):
        with path.open("rb") as f:
            data = f.read(limit + 1)
        if not 0 < len(data) <= limit:
            raise ValueError("Fixture input exceeds bounds")
        out.write("static const unsigned char " + name + "[] = {\n")
        for i in range(0, len(data), 24):
            out.write(",".join(str(b) for b in data[i:i+24]) + ",\n")
        out.write("};\n")
PY
    cp "$REPO/src/initramfs/bionic-property-area.c" "$OVERLAY/"
    cat >> "$OVERLAY/Android.bp" <<'BP'

cc_binary {
    name: "galwear_property_area",
    srcs: ["bionic-property-area.c"],
    compile_multilib: "64",
    static_executable: true,
    stl: "none",
    cflags: ["-Wall", "-Wextra", "-Werror"],
}
BP
    set +u
    m -j4 galwear_property_area
    PRODUCT_OUT=$(get_build_var PRODUCT_OUT)
    set -u
    mkdir "$OUT/property-area"
    cp "$PRODUCT_OUT/system/bin/galwear_property_area" "$OUT/property-area/init"
    python3 "$REPO/build/r800_initramfs_spec.py" --init "$OUT/property-area/init" \
        --list "$OUT/property-area/initramfs.list" --report "$OUT/property-area/initramfs-evidence.json"
    sha256sum "$POLICY" "$OUT/property_info.virt" "$OUT/property-area/init" > "$OUT/property-area/inputs.sha256"
fi
