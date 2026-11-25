#!/bin/sh
# Compile five Android HAL translation units and link four NDK-only modules. No payload or flash.
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
for module in audio_r800 gps_r800 sensors_r800 hwcomposer_r800 lights_r800; do
    echo "Compiling $module (ARM32, API 28)"
    "$cc" -std=gnu11 -O2 -fPIC -mfpu=neon \
        -Werror=implicit-function-declaration -Werror=incompatible-pointer-types \
        -I"$repo/src/hal/include" -I"$tiny/include" \
        -c "$repo/src/hal/$module.c" -o "$out/$module.o"
    "$toolchain/llvm-readelf" -h "$out/$module.o" | grep -Eq 'Machine:[[:space:]]+ARM'
done
# Audio needs the hardware-specific tinyalsa patch; do not substitute stock
# tinyalsa or claim that its runtime linkage has been validated.
for module in hwcomposer gps sensors lights; do
    soname="$module.r800.so"
    echo "Linking $soname (ARM32, API 28)"
    "$cc" -shared -Wl,--no-undefined -Wl,-soname,"$soname" \
        "$out/${module}_r800.o" -llog -ldl -lm -o "$out/$soname"
    "$toolchain/llvm-readelf" -h "$out/$soname" > "$out/$module-elf.txt"
    grep -Eq 'Class:[[:space:]]+ELF32' "$out/$module-elf.txt"
    grep -Eq 'Machine:[[:space:]]+ARM' "$out/$module-elf.txt"
    grep -Eq 'Type:[[:space:]]+DYN' "$out/$module-elf.txt"
    "$toolchain/llvm-readelf" --dyn-syms --wide "$out/$soname" > "$out/$module-symbols.txt"
    grep -Eq '[[:space:]]OBJECT[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]+HMI$' "$out/$module-symbols.txt"
    "$toolchain/llvm-readelf" -d "$out/$soname" > "$out/$module-dynamic.txt"
done
# Only JSON metadata leaves the runner, not binaries.
python3 - "$out" "$repo" <<'PY'
import hashlib, json, os, pathlib, re, subprocess, sys
out, repo = map(pathlib.Path, sys.argv[1:])
names = ("audio_r800", "gps_r800", "sensors_r800", "hwcomposer_r800", "lights_r800")
linked = ("hwcomposer", "gps", "sensors", "lights")
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
libraries = {}
for name in linked:
    soname = name + ".r800.so"
    dynamic = (out / (name + "-dynamic.txt")).read_text()
    needed = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic)
    actual_soname = re.findall(r"\(SONAME\).*?\[([^\]]+)\]", dynamic)
    if actual_soname != [soname] or not needed:
        raise SystemExit("unexpected ELF dynamic metadata: " + soname)
    unexpected = set(needed) - {"libc.so", "libm.so", "libdl.so", "liblog.so"}
    if unexpected:
        raise SystemExit("unexpected dependencies: " + soname + ": " + repr(unexpected))
    libraries[name] = {
        "soname": soname,
        "sha256": sha(out / soname),
        "exported_hmi_verified": True,
        "no_undefined_link": True,
        "needed": needed,
        "dynamic_section": dynamic,
    }
report = {
    "schema": "galwear-r800-hal-compile-v3",
    "status": "FIVE_ARM32_OBJECTS_COMPILED_FOUR_HAL_LINKED",
    "commit": subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip(),
    "run_id": os.getenv("GITHUB_RUN_ID"),
    "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
    "ndk": "27.2.12479018",
    "tinyalsa_headers_commit": "1c5fb68ced57d838f2b7ecd0c00bc1fefc9ab60d",
    "abi": "armeabi-v7a",
    "api_level": 28,
    "objects": {n: {"source_sha256": sha(repo / "src/hal" / (n + ".c")),
                    "object_sha256": sha(out / (n + ".o"))} for n in names},
    "shared_libraries_linked": False,  # not all HALs
    "hwc_shared_library_linked": True,
    "hwc_shared_library": libraries["hwcomposer"],
    "linked_libraries": libraries,
    "audio_linked": False,
    "audio_link_blocker": "hardware-specific tinyalsa sync_ptr patch not available",
    "patched_tinyalsa_linked": False,
    "android_boot_tested": False,
    "hardware_tested": False,
    "safe_to_flash": False,
}
(out / "hal-compile.json").write_text(json.dumps(report, indent=2) + "\n")
PY
