#!/bin/sh
# Separate Bionic diagnostic executable, never a release image.
set -eu
[ "$#" -eq 4 ] || { echo "usage: $0 <repo> <ndk> <pinned-uapi-dir> <new-output>" >&2; exit 2; }
REPO=$1
NDK=$2
UAPI=$3
OUT=$4
[ ! -e "$OUT" ]
grep -Eq '^Pkg.Revision[[:space:]]*=[[:space:]]*27\.3\.13750724[[:space:]]*$' "$NDK/source.properties"
CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang"
test -x "$CC"
test -f "$UAPI/linux/android/binder.h"
test -f "$UAPI/linux/ashmem.h"
mkdir -p "$OUT"
"$CC" -std=c11 -Wall -Wextra -Werror -O2 -pthread -Dmain=abi_probe_main \
    -c "$REPO/src/initramfs/abi-probe.c" -o "$OUT/probe.o"
"$CC" -std=c11 -Wall -Wextra -Werror -O2 -static -pthread \
    -DGALWEAR_BIONIC_PROBE -Wl,--build-id=none -Wl,--strip-all -I"$UAPI" \
    "$REPO/src/initramfs/abi-probe-pid1.c" \
    "$REPO/src/initramfs/binder-probe.c" \
    "$REPO/src/initramfs/binder-roundtrip.c" \
    "$REPO/src/initramfs/shared-memory-probe.c" "$OUT/probe.o" -o "$OUT/init"
python3 "$REPO/build/r800_initramfs_spec.py" --init "$OUT/init" \
    --list "$OUT/initramfs.list" --report "$OUT/initramfs-evidence.json"
python3 - "$OUT" "$NDK" "$UAPI" <<'PY'
import hashlib, json, pathlib, sys
out, ndk, uapi = map(pathlib.Path, sys.argv[1:])
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
report = {
    "status": "BIONIC_STATIC_COMPILE_ONLY",
    "ndk_revision": "27.3.13750724",
    "android_api": 30,
    "init_sha256": sha(out / "init"),
    "ndk_metadata_sha256": sha(ndk / "source.properties"),
    "binder_uapi_sha256": sha(uapi / "linux/android/binder.h"),
    "ashmem_uapi_sha256": sha(uapi / "linux/ashmem.h"),
    "safe_to_flash": False,
}
(out / "bionic-compile-evidence.json").write_text(json.dumps(report, indent=2) + "\n")
PY
"$CC" --version > "$OUT/clang-version.txt"
