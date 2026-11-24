#!/bin/sh
# Compile four complete Android HAL translation units. No link, payload or flash.
set -eu
[ "$#" -eq 4 ] || {
    echo "usage: $0 <repo> <ndk-r27c> <tinyalsa-checkout> <new-out-dir>" >&2
    exit 2
}
repo=$1
ndk=$2
tiny=$3
out=$4
[ ! -e "$out" ] || { echo "output already exists" >&2; exit 2; }
grep -Eq '^Pkg.Revision[[:space:]]*=[[:space:]]*27\.2\.12479018[[:space:]]*$' "$ndk/source.properties"
test "$(git -C "$tiny" rev-parse HEAD)" = 1c5fb68ced57d838f2b7ecd0c00bc1fefc9ab60d
test -z "$(git -C "$tiny" status --porcelain)"
toolchain="$ndk/toolchains/llvm/prebuilt/linux-x86_64/bin"
cc="$toolchain/armv7a-linux-androideabi28-clang"
test -x "$cc"
mkdir -p "$out"
failed=0
for module in audio_r800 gps_r800 sensors_r800 hwcomposer_r800; do
    echo "Compiling $module (ARM32, API 28)"
    rc=0
    "$cc" -std=gnu11 -O2 -fPIC -mfpu=neon \
        -Werror=implicit-function-declaration -Werror=incompatible-pointer-types \
        -I"$repo/src/hal/include" -I"$tiny/include" \
        -c "$repo/src/hal/$module.c" -o "$out/$module.o" >"$out/$module.log" 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
        "$toolchain/llvm-readelf" -h "$out/$module.o" >"$out/$module.elf" 2>>"$out/$module.log" || rc=$?
        if [ "$rc" -eq 0 ]; then
            grep -Eq 'Machine:[[:space:]]+ARM' "$out/$module.elf" || rc=$?
        fi
    fi
    printf '%s\n' "$rc" >"$out/$module.rc"
    cat "$out/$module.log"
    [ "$rc" -eq 0 ] || failed=1
done
# Keep diagnostics even if compilation fails, without exporting objects.
python3 - "$out" "$repo" <<'PY'
import json, os, pathlib, subprocess, sys
out, repo = map(pathlib.Path, sys.argv[1:])
names = ("audio_r800", "gps_r800", "sensors_r800", "hwcomposer_r800")
modules = {}
for name in names:
    rc = int((out / (name + ".rc")).read_text())
    with (out / (name + ".log")).open("rb") as stream:
        raw = stream.read(32769)
    modules[name] = {"exit_code": rc, "compiled_and_arm_header_checked": rc == 0,
                     "diagnostics": raw[:32768].decode("utf-8", errors="replace"),
                     "diagnostics_truncated": len(raw) > 32768}
report = {"schema": "galwear-r800-hal-compile-diagnostics-v1",
          "commit": subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip(),
          "run_id": os.getenv("GITHUB_RUN_ID"), "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
          "modules": modules, "all_compiled": all(x["exit_code"] == 0 for x in modules.values()),
          "safe_to_flash": False}
(out / "hal-compile-diagnostics.json").write_text(json.dumps(report, indent=2) + "\n")
PY
[ "$failed" -eq 0 ] || exit 1
# Only JSON metadata leaves the runner, not binaries.
python3 - "$out" "$repo" <<'PY'
import hashlib, json, os, pathlib, subprocess, sys
out, repo = map(pathlib.Path, sys.argv[1:])
names = ("audio_r800", "gps_r800", "sensors_r800", "hwcomposer_r800")
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
report = {
    "schema": "galwear-r800-hal-compile-v1",
    "status": "FOUR_ARM32_OBJECTS_COMPILED",
    "commit": subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip(),
    "run_id": os.getenv("GITHUB_RUN_ID"),
    "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
    "ndk": "27.2.12479018",
    "tinyalsa_headers_commit": "1c5fb68ced57d838f2b7ecd0c00bc1fefc9ab60d",
    "abi": "armeabi-v7a",
    "api_level": 28,
    "objects": {n: {"source_sha256": sha(repo / "src/hal" / (n + ".c")),
                    "object_sha256": sha(out / (n + ".o"))} for n in names},
    "shared_libraries_linked": False,
    "patched_tinyalsa_linked": False,
    "android_boot_tested": False,
    "hardware_tested": False,
    "safe_to_flash": False,
}
(out / "hal-compile.json").write_text(json.dumps(report, indent=2) + "\n")
PY
