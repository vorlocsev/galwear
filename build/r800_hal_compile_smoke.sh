#!/bin/sh
# Compile five Android HAL translation units and link all five (Audio experimental). No payload or flash.
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
# Reconstructed candidate, never a claim of original patch recovery.
mkdir "$out/tinyalsa"
git -C "$tiny" archive HEAD | tar -x -C "$out/tinyalsa"
(
    cd "$out/tinyalsa"
    git apply --check "$repo/tools/audio/tinyalsa-2.0.0-sync-ptr.patch"
    git apply "$repo/tools/audio/tinyalsa-2.0.0-sync-ptr.patch"
)
python3 "$repo/build/r800_tinyalsa_sync_test.py" "$out/tinyalsa"
for unit in pcm pcm_hw pcm_plugin snd_card_plugin mixer mixer_hw mixer_plugin; do
    "$cc" -std=gnu11 -O2 -fPIC -I"$out/tinyalsa/include" \
        -c "$out/tinyalsa/src/$unit.c" -o "$out/tinyalsa/$unit.o"
done
"$toolchain/llvm-ar" rcs "$out/tinyalsa-candidate.a" "$out/tinyalsa/"*.o
"$cc" -shared -Wl,--no-undefined -Wl,-soname,audio.primary.r800.so \
    "$out/audio_r800.o" "$out/tinyalsa-candidate.a" -llog -ldl -lm \
    -o "$out/audio.primary.r800.so"
"$toolchain/llvm-readelf" -h "$out/audio.primary.r800.so" > "$out/audio-elf.txt"
grep -Eq 'Class:[[:space:]]+ELF32' "$out/audio-elf.txt"
grep -Eq 'Machine:[[:space:]]+ARM' "$out/audio-elf.txt"
grep -Eq 'Type:[[:space:]]+DYN' "$out/audio-elf.txt"
"$toolchain/llvm-readelf" --dyn-syms --wide "$out/audio.primary.r800.so" > "$out/audio-symbols.txt"
grep -Eq '[[:space:]]OBJECT[[:space:]]+GLOBAL[[:space:]]+DEFAULT[[:space:]]+[0-9]+[[:space:]]+HMI$' "$out/audio-symbols.txt"
"$toolchain/llvm-readelf" -d "$out/audio.primary.r800.so" > "$out/audio-dynamic.txt"
"$cc" -std=gnu11 -c "$repo/build/r800_pcm_abi_probe.c" -o "$out/pcm-abi.o"
"$toolchain/llvm-objcopy" --dump-section ".r800_pcm_abi=$out/pcm-abi.bin" "$out/pcm-abi.o" "$out/pcm-abi-copy.o"
# Only JSON metadata leaves the runner, not binaries.
python3 - "$out" "$repo" <<'PY'
import hashlib, json, os, pathlib, re, struct, subprocess, sys
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
audio_dynamic = (out / "audio-dynamic.txt").read_text()
audio_needed = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", audio_dynamic)
audio_soname = re.findall(r"\(SONAME\).*?\[([^\]]+)\]", audio_dynamic)
if audio_soname != ["audio.primary.r800.so"] or not audio_needed:
    raise SystemExit("unexpected Audio ELF dynamic metadata")
if set(audio_needed) - {"libc.so", "libm.so", "libdl.so", "liblog.so"}:
    raise SystemExit("unexpected Audio dependencies: " + repr(audio_needed))
if re.search(r"\((?:RPATH|RUNPATH|TEXTREL)\)", audio_dynamic):
    raise SystemExit("unexpected Audio dynamic search path or text relocation")
abi_keys = (
    "pointer_bytes", "uframes_bytes", "sync_ptr_bytes", "mmap_status_bytes",
    "mmap_control_bytes", "sync_flags_offset", "sync_status_offset",
    "sync_control_offset", "status_hw_ptr_offset", "control_appl_ptr_offset",
    "control_avail_min_offset", "xferi_bytes", "xferi_result_offset",
    "xferi_buf_offset", "xferi_frames_offset", "ioctl_sync_ptr",
    "ioctl_readi", "ioctl_writei", "flag_hwsync", "flag_appl", "flag_avail_min",
)
abi_raw = (out / "pcm-abi.bin").read_bytes()
if len(abi_raw) != 4 * len(abi_keys):
    raise SystemExit("unexpected PCM ABI section size")
pcm_abi = dict(zip(abi_keys, struct.unpack("<" + "I" * len(abi_keys), abi_raw)))
if pcm_abi["pointer_bytes"] != 4 or pcm_abi["uframes_bytes"] != 4:
    raise SystemExit("not the expected ARM32 PCM ABI")
if [pcm_abi[k] for k in ("flag_hwsync", "flag_appl", "flag_avail_min")] != [1, 2, 4]:
    raise SystemExit("unexpected SYNC_PTR flags")
report = {
    "schema": "galwear-r800-hal-compile-v4",
    "status": "FIVE_ARM32_OBJECTS_COMPILED_FIVE_LINKED_AUDIO_EXPERIMENTAL",
    "commit": subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip(),
    "run_id": os.getenv("GITHUB_RUN_ID"),
    "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
    "ndk": "27.2.12479018",
    "tinyalsa_headers_commit": "1c5fb68ced57d838f2b7ecd0c00bc1fefc9ab60d",
    "abi": "armeabi-v7a",
    "api_level": 28,
    "objects": {n: {"source_sha256": sha(repo / "src/hal" / (n + ".c")),
                    "object_sha256": sha(out / (n + ".o"))} for n in names},
    "shared_libraries_linked": True,  # includes experimental Audio candidate
    "hwc_shared_library_linked": True,
    "hwc_shared_library": libraries["hwcomposer"],
    "linked_libraries": libraries,
    "audio_linked": False,
    "audio_link_blocker": "original hardware-validated patch unavailable",
    "audio_candidate_linked": True,
    "audio_candidate": {
        "sha256": sha(out / "audio.primary.r800.so"),
        "tinyalsa_patch_sha256": sha(repo / "tools/audio/tinyalsa-2.0.0-sync-ptr.patch"),
        "sync_ptr_mock_passed": True,
        "soname": audio_soname[0],
        "needed": audio_needed,
        "exported_hmi_verified": True,
        "no_undefined_link": True,
        "dynamic_section": audio_dynamic,
        "pcm_ndk_abi": pcm_abi,
        "kernel_compat_abi_verified": False,
        "hardware_validated": False,
    },
    "patched_tinyalsa_linked": False,
    "android_boot_tested": False,
    "hardware_tested": False,
    "safe_to_flash": False,
}
(out / "hal-compile.json").write_text(json.dumps(report, indent=2) + "\n")
PY
