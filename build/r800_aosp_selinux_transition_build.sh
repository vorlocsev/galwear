#!/usr/bin/env bash
# Build a static AOSP libselinux diagnostic, not the original init.
set -euo pipefail
[[ $# == 2 || $# == 3 ]] || { echo "usage: $0 <synced-aosp-root> <new-output-dir> [transition|relabel|service]" >&2; exit 2; }
MODE=${3:-transition}
SERVICE_FLAG=""
case "$MODE" in
    transition) SOURCE=selinux-transition-probe.c; STATUS=SELINUX_TRANSITION_COMPILE_ONLY ;;
    relabel) SOURCE=rootfs-relabel-probe.c; STATUS=SELINUX_ROOTFS_RELABEL_COMPILE_ONLY ;;
    service) SOURCE=rootfs-relabel-probe.c; STATUS=SELINUX_SERVICE_BOOT_COMPILE_ONLY; SERVICE_FLAG="-DGALWEAR_SERVICE_BOOT" ;;
    *) exit 2 ;;
esac
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
OVERLAY="$ROOT/galwear_selinux_transition"
mkdir "$OVERLAY"
trap 'rm -f -- "$OVERLAY/Android.bp" "$OVERLAY/selinux-transition-probe.c"; rmdir -- "$OVERLAY"' EXIT
cp "$TOOLS/../src/android/$SOURCE" "$OVERLAY/selinux-transition-probe.c"
cat > "$OVERLAY/Android.bp" <<'BP'
cc_binary {
    name: "galwear_selinux_transition",
    srcs: ["selinux-transition-probe.c"],
    static_executable: true,
    static_libs: ["libselinux", "libpcre2", "libbase", "liblog"],
    compile_multilib: "64",
    cflags: ["-Wall", "-Wextra", "-Werror"],
}
BP
if [[ -n "$SERVICE_FLAG" ]]; then
    sed -i 's/"-Werror"/"-Werror", "-DGALWEAR_SERVICE_BOOT"/' "$OVERLAY/Android.bp"
fi
mkdir "$OUT"
repo manifest -r -o "$OUT/manifest-resolved.xml"
unset OUT_DIR_COMMON_BASE
export OUT_DIR="$OUT/aosp-out"
set +u
source build/envsetup.sh
lunch aosp_arm64-eng
m -j4 galwear_selinux_transition
PRODUCT_OUT=$(get_build_var PRODUCT_OUT)
set -u
cp "$PRODUCT_OUT/system/bin/galwear_selinux_transition" "$OUT/init"
python3 "$TOOLS/r800_initramfs_spec.py" --init "$OUT/init" --list "$OUT/initramfs.list" --report "$OUT/initramfs-evidence.json"
sha256sum "$OUT/init" "$OUT/manifest-resolved.xml" "$OVERLAY/selinux-transition-probe.c" "$OVERLAY/Android.bp" > "$OUT/input-digests.sha256"
printf 'status=%s\nsafe_to_flash=false\n' "$STATUS" > "$OUT/status.txt"
