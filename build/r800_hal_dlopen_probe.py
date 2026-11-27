#!/usr/bin/env python3
"""Compile or run a bounded ARM32 HAL metadata-only Bionic probe."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_android_linker_audit import inspect

HALS = {"audio.primary.r800.so": "audio", "gps.r800.so": "gps",
        "sensors.r800.so": "sensors", "lights.r800.so": "lights",
        "hwcomposer.r800.so": "hwcomposer"}
RUNTIME = ("linker", "libc.so", "libdl.so", "libm.so", "liblog.so", "libc++.so")
SYSTEM_RUNTIME_LIBS = ("liblog.so", "libc++.so")
HAL_COMPILE_LIBS = {"libc.so", "libdl.so", "libm.so", "liblog.so"}
LINKER_SONAME = "ld-android.so"
LIMIT = 64*1024**2
ROOT = Path(__file__).resolve().parents[1]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def check(path, library=False):
    raw = read_regular(path, LIMIT)
    info = inspect(raw)
    if info["abi"] != "arm" or not info["has_dynamic"] or info["custom_search_path"]:
        raise ValueError("Unexpected ARM32 ELF: " + path.name)
    if library and (info["elf_type"] != "ET_DYN" or info["soname"] != path.name):
        raise ValueError("Unexpected library identity: " + path.name)
    return raw, info


def runtime_dependencies(name, info, linker_soname):
    allowed = set(RUNTIME[1:])
    if linker_soname == LINKER_SONAME:
        allowed.add(LINKER_SONAME)
    unexpected = sorted(set(info["needed"]) - allowed)
    if unexpected:
        raise ValueError("Runtime dependency outside allowlist: " + name + ": " + ", ".join(unexpected))
    if name == "linker" and (info["elf_type"] != "ET_DYN" or info["needed"]):
        raise ValueError("Unexpected ARM32 linker structure")


def compile_probe(ndk, hals, output, source_sha):
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("Expected full source SHA")
    if not re.search(r"^Pkg.Revision\s*=\s*27\.2\.12479018\s*$",
                     (ndk/"source.properties").read_text(), re.M):
        raise ValueError("Expected NDK r27c")
    report = json.loads(read_regular(hals/"hal-compile.json", 1024*1024))
    if report["commit"] != source_sha or report["safe_to_flash"] is not False:
        raise ValueError("HAL compile evidence mismatch")
    hashes = {}
    for name in HALS:
        raw, info = check(hals/name, True)
        expected = (report["audio_candidate"] if name.startswith("audio.") else
                    report["linked_libraries"][name.split(".")[0]])
        if sha(raw) != expected["sha256"] or not set(info["needed"]) <= HAL_COMPILE_LIBS:
            raise ValueError("HAL evidence/dependency mismatch: " + name)
        hashes[name] = sha(raw)
    output.mkdir(exist_ok=False)
    probe = output/"hal-probe"
    cc = ndk/"toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi28-clang"
    subprocess.run([str(cc), "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-O2",
                    "-I"+str(ROOT/"src/hal/include"), str(ROOT/"src/initramfs/r800-hal-probe.c"),
                    "-ldl", "-Wl,--no-undefined", "-o", str(probe)], check=True, timeout=60)
    shim = output/"libevdev-fixture.so"
    subprocess.run([str(cc), "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-O2", "-shared", "-fPIC",
                    str(ROOT/"src/initramfs/r800-evdev-fixture.c"),
                    "-Wl,-soname,libevdev-fixture.so", "-Wl,--no-undefined", "-o", str(shim)], check=True, timeout=60)
    shim_raw, shim_info = check(shim, True)
    if not set(shim_info["needed"]) <= HAL_COMPILE_LIBS:
        raise ValueError("Unexpected test adapter dependency")
    pcm_shim = output/"libpcm-fixture.so"
    subprocess.run([str(cc), "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-O2", "-shared", "-fPIC",
                    "-I"+str(hals/"tinyalsa/include"), str(ROOT/"src/initramfs/r800-pcm-fixture.c"),
                    "-Wl,-soname,libpcm-fixture.so", "-Wl,--no-undefined", "-o", str(pcm_shim)],
                   check=True, timeout=60)
    pcm_raw, pcm_info = check(pcm_shim, True)
    if not set(pcm_info["needed"]) <= HAL_COMPILE_LIBS:
        raise ValueError("Unexpected PCM test adapter dependency")
    hwc_shim = output/"libhwc-fixture.so"
    subprocess.run([str(cc), "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-O2", "-shared", "-fPIC",
                    str(ROOT/"src/initramfs/r800-fb-fixture.c"),
                    "-Wl,-soname,libhwc-fixture.so", "-Wl,--no-undefined", "-o", str(hwc_shim)],
                   check=True, timeout=60)
    hwc_raw, hwc_info = check(hwc_shim, True)
    if not set(hwc_info["needed"]) <= HAL_COMPILE_LIBS:
        raise ValueError("Unexpected HWC test adapter dependency")
    gralloc = output/"libhardware.so"
    subprocess.run([str(cc), "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-O2", "-shared", "-fPIC",
                    "-I"+str(ROOT/"src/hal/include"), str(ROOT/"src/initramfs/r800-gralloc-fixture.c"),
                    "-Wl,-soname,libhardware.so", "-Wl,--no-undefined", "-o", str(gralloc)], check=True, timeout=60)
    gralloc_raw, gralloc_info = check(gralloc, True)
    if not set(gralloc_info["needed"]) <= HAL_COMPILE_LIBS:
        raise ValueError("Unexpected gralloc test adapter dependency")
    ns_hashes = {}
    for name, extra, private in (
        ("libgalwear-ns-leaf.so", ["-DR800_NAMESPACE_LEAF"], set()),
        ("libgalwear-ns-parent.so", ["-L"+str(output), "-lgalwear-ns-leaf"], {"libgalwear-ns-leaf.so"}),
        ("libgalwear-ns-absent.so", ["-DR800_NAMESPACE_LEAF"], set()),
        ("libgalwear-ns-missing.so", ["-L"+str(output), "-lgalwear-ns-absent"], {"libgalwear-ns-absent.so"}),
        ("libgalwear-ns-bad-symbol.so", ["-DR800_NAMESPACE_BAD_SYMBOL"], set()),
    ):
        target = output/name
        subprocess.run([str(cc), "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-O2",
                        "-shared", "-fPIC", str(ROOT/"src/initramfs/r800-namespace-fixture.c"),
                        *extra, "-Wl,-soname,"+name,
                        *([] if name == "libgalwear-ns-bad-symbol.so" else ["-Wl,--no-undefined"]),
                        "-o", str(target)], check=True, timeout=60)
        ns_raw, ns_info = check(target, True)
        if set(ns_info["needed"]) - HAL_COMPILE_LIBS != private:
            raise ValueError("Unexpected synthetic namespace dependency graph")
        ns_hashes[name] = sha(ns_raw)
    raw, info = check(probe)
    if not set(info["needed"]) <= HAL_COMPILE_LIBS:
        raise ValueError("Unexpected probe dependency")
    result = {"status": "ARM32_HAL_DLOPEN_PROBE_COMPILE_ONLY", "source_sha": source_sha,
              "probe_sha256": sha(raw), "namespace_fixture_sha256": ns_hashes, "gralloc_fixture_sha256": sha(gralloc_raw), "evdev_fixture_sha256": sha(shim_raw), "pcm_fixture_sha256": sha(pcm_raw), "hwc_fixture_sha256": sha(hwc_raw), "hal_sha256": hashes,
              "runtime_verified": False, "hardware_tested": False, "safe_to_flash": False}
    (output/"hal-probe-evidence.json").write_text(json.dumps(result, indent=2, sort_keys=True)+"\n")
    return result


def run_probe(probe_dir, hals, runtime, runtime_manifest, output, lifecycle=False,
              lights_fixture=False, sensors_fixture=False, sensors_context=False, sensors_evdev=False, gps_fixture=False, audio_fixture=False, audio_pcm_fixture=False, hwc_fixture=False, namespace_fixture=False):
    if sum((lifecycle, lights_fixture, sensors_fixture, sensors_context, sensors_evdev, gps_fixture, audio_fixture, audio_pcm_fixture, hwc_fixture, namespace_fixture)) > 1:
        raise ValueError("Choose one probe mode")
    if os.geteuid() == 0:
        raise ValueError("Non-root execution required")
    qemu = shutil.which("qemu-arm-static")
    bwrap = shutil.which("bwrap")
    if not qemu or not bwrap:
        raise ValueError("Static QEMU and bubblewrap required; no fallback")
    evidence = json.loads(read_regular(probe_dir/"hal-probe-evidence.json", 1024*1024))
    pins = json.loads(read_regular(runtime_manifest, 1024*1024))
    if (evidence["status"] != "ARM32_HAL_DLOPEN_PROBE_COMPILE_ONLY" or
            evidence["safe_to_flash"] is not False or set(evidence["hal_sha256"]) != set(HALS) or
            set(pins) != set(RUNTIME) or any(not re.fullmatch(r"[0-9a-f]{64}", v) for v in pins.values())):
        raise ValueError("Invalid runtime or probe evidence")
    output.mkdir(exist_ok=False)
    results = {}
    with tempfile.TemporaryDirectory(prefix="r800-hal-runtime-") as tmp:
        root = Path(tmp)/"guest"
        for name in ("system/bin", "system/lib", "vendor/lib/hw", "dev", "proc", "linkerconfig",
                     "apex/com.android.runtime/bin", "apex/com.android.runtime/lib/bionic"):
            (root/name).mkdir(parents=True, exist_ok=True)
        (root/"qemu").touch()
        linker_raw, linker_info = check(runtime/"linker")
        if sha(linker_raw) != pins["linker"]:
            raise ValueError("Linker digest mismatch")
        linker_soname = linker_info["soname"]
        runtime_dependencies("linker", linker_info, linker_soname)
        def add(src, rel, digest, lib=False, executable=False, private_needed=()):
            raw, info = check(src, lib)
            if sha(raw) != digest:
                raise ValueError("ELF digest mismatch: " + src.name)
            # Only the explicitly compiled parent may have this private edge.
            if private_needed and not set(private_needed) <= set(info["needed"]):
                raise ValueError("Missing synthetic namespace dependency")
            runtime_dependencies(src.name, {**info, "needed": [n for n in info["needed"] if n not in private_needed]}, linker_soname)
            target = root/rel
            target.write_bytes(raw)
            target.chmod(0o555 if executable else 0o444)
        for name in RUNTIME:
            if name == "linker":
                rel = "apex/com.android.runtime/bin/linker"
            elif name in SYSTEM_RUNTIME_LIBS:
                rel = "system/lib/" + name
            else:
                rel = "apex/com.android.runtime/lib/bionic/" + name
            add(runtime/name, rel, pins[name], name != "linker", name == "linker")
        (root/"system/bin/linker").symlink_to("../../apex/com.android.runtime/bin/linker")
        add(probe_dir/"hal-probe", "system/bin/hal-probe", evidence["probe_sha256"], executable=True)
        for name in HALS:
            add(hals/name, "vendor/lib/hw/"+name, evidence["hal_sha256"][name], True)
        (root/"linkerconfig/ld.config.txt").write_text(
            "dir.fixture = /system/bin\n[fixture]\n"
            "namespace.default.isolated = false\n"
            "namespace.default.search.paths = /apex/com.android.runtime/lib/bionic:/system/lib\n")
        if namespace_fixture:
            ns_graph = {
                "libgalwear-ns-leaf.so": (),
                "libgalwear-ns-parent.so": ("libgalwear-ns-leaf.so",),
                "libgalwear-ns-missing.so": ("libgalwear-ns-absent.so",),
                "libgalwear-ns-bad-symbol.so": (),
            }
            absent = "libgalwear-ns-absent.so"
            ns_hashes = evidence["namespace_fixture_sha256"]
            if set(ns_hashes) != set(ns_graph) | {absent}:
                raise ValueError("Unexpected synthetic namespace inventory")
            # Verify the intentionally omitted provider, but do not stage it.
            absent_raw, absent_info = check(probe_dir/absent, True)
            if sha(absent_raw) != ns_hashes[absent]:
                raise ValueError("Omitted provider digest mismatch")
            runtime_dependencies(absent, absent_info, linker_soname)
            for name, private_needed in ns_graph.items():
                add(probe_dir/name, "vendor/lib/hw/"+name, ns_hashes[name], True,
                    private_needed=private_needed)
            # Deliberately no LD_LIBRARY_PATH, no permissive default namespace.
            # Only this synthetic configuration is tested, not donor policy.
            (root/"linkerconfig/ld.config.txt").write_text(
                "dir.fixture = /system/bin\n[fixture]\n"
                "additional.namespaces = vendor\n"
                "namespace.default.isolated = true\n"
                "namespace.default.search.paths = /apex/com.android.runtime/lib/bionic:/system/lib\n"
                "namespace.default.links = vendor\n"
                "namespace.default.link.vendor.shared_libs = lights.r800.so:libgalwear-ns-parent.so:libgalwear-ns-missing.so:libgalwear-ns-bad-symbol.so\n"
                "namespace.vendor.isolated = true\n"
                "namespace.vendor.search.paths = /vendor/lib/hw\n"
                "namespace.vendor.links = default\n"
                "namespace.vendor.link.default.shared_libs = libc.so:libdl.so:libm.so:liblog.so:libc++.so:ld-android.so\n")
        namespace_config_sha = sha((root/"linkerconfig/ld.config.txt").read_bytes())
        def snapshot():
            return {p.relative_to(root).as_posix(): ("symlink:"+os.readlink(p) if p.is_symlink() else sha(p.read_bytes()))
                    for p in sorted(root.rglob("*")) if p.is_file() or p.is_symlink()}
        fixture = None
        if hwc_fixture:
            add(probe_dir/"libhwc-fixture.so", "system/lib/libhwc-fixture.so",
                evidence["hwc_fixture_sha256"], True)
            add(probe_dir/"libhardware.so", "system/lib/libhardware.so",
                evidence["gralloc_fixture_sha256"], True)
            fixture = Path(tmp)/"hwc-fb"
            fixture.mkdir()
            (fixture/".galwear-fixture").write_text("GALWEAR_HWC_FIXTURE_V1\n")
            (fixture/"fb0").write_bytes(bytes(360*720*4))
            raw_rows = [b"".join(bytes((x & 255, y & 255, (x+y) & 255, 255))
                                 for x in range(360)) for y in range(360)]
            pixel_input = b"".join(row + bytes([0xa5])*32 for row in raw_rows)
            (fixture/"pixels").write_bytes(pixel_input)
            (fixture/"pixels").chmod(0o444)
            swapped = b"".join(bytes(((x+y) & 255, y & 255, x & 255, 255))
                               for y in range(360) for x in range(360))
            expected_fb = b"".join(raw_rows) + swapped
            dsim = Path(tmp)/"hwc-dsim"
            dsim.mkdir()
            (dsim/".galwear-fixture").write_text("GALWEAR_DSIM_FIXTURE_V1\n")
            (dsim/"cmd_rw").write_text("0")
            (root/"sys/devices/platform/148e0000.dsim").mkdir(parents=True)
        elif audio_pcm_fixture:
            add(probe_dir/"libpcm-fixture.so", "system/lib/libpcm-fixture.so",
                evidence["pcm_fixture_sha256"], True)
        elif gps_fixture:
            fixture = Path(tmp)/"gps-fixture"
            fixture.mkdir()
            (fixture/".galwear-fixture").write_text("GALWEAR_GPS_FIXTURE_V1\n")
            (root/"oem/r800dev").mkdir(parents=True)
        elif sensors_evdev:
            add(probe_dir/"libevdev-fixture.so", "system/lib/libevdev-fixture.so",
                evidence["evdev_fixture_sha256"], True)
            fixture = Path(tmp)/"evdev-ssp"
            fixture.mkdir()
            (fixture/".galwear-fixture").write_text("GALWEAR_EVDEV_FIXTURE_V1\n")
            (fixture/"enable").write_text("1073741824")
            (fixture/"hrm_lib_poll_delay").write_text("")
            (root/"sys/class/sensors/ssp_sensor").mkdir(parents=True)
            inputs = Path(tmp)/"evdev-inputs"
            inputs.mkdir()
            (inputs/".galwear-fixture").write_text("GALWEAR_EVDEV_FIXTURE_V1\n")
            for i in range(6):
                os.mkfifo(inputs/("event"+str(i)), 0o600)
        elif lights_fixture:
            fixture = Path(tmp)/"lights-fixture"
            fixture.mkdir()
            (fixture/".galwear-fixture").write_text("GALWEAR_LIGHTS_FIXTURE_V1\n")
            (fixture/"brightness").write_text("")
            (root/"sys/class/backlight/exynos_panel").mkdir(parents=True)
        elif sensors_fixture or sensors_context:
            fixture = Path(tmp)/"sensors-fixture"
            fixture.mkdir()
            (fixture/".galwear-fixture").write_text("GALWEAR_SSP_FIXTURE_V1\n")
            (fixture/"enable").write_text("262144")
            (fixture/"accel_poll_delay").write_text("00000000")
            (root/"sys/class/sensors/ssp_sensor").mkdir(parents=True)
            if sensors_context:
                os.mkfifo(fixture/"context", 0o600)
        before = snapshot()
        selected = {name: identity for name, identity in HALS.items()
                    if (not lights_fixture or identity == "lights") and
                       (not (sensors_fixture or sensors_context or sensors_evdev) or identity == "sensors") and (not gps_fixture or identity == "gps") and
                       (not (audio_fixture or audio_pcm_fixture) or identity == "audio") and
                       (not hwc_fixture or identity == "hwcomposer") and
                       (not namespace_fixture or identity == "lights")}
        for name, identity in selected.items():
            cmd = [bwrap, "--unshare-all", "--die-with-parent", "--new-session",
                   "--clearenv", "--ro-bind", str(root), "/", "--ro-bind", qemu, "/qemu",
                   "--dev", "/dev", "--proc", "/proc", "--chdir", "/",
                   "/qemu", "-cpu", "cortex-a15", "-L", "/",
                   "-E", "LD_LIBRARY_PATH=/apex/com.android.runtime/lib/bionic:/system/lib", "/system/bin/hal-probe",
                   "/vendor/lib/hw/"+name, identity]
            if namespace_fixture:
                i = cmd.index("LD_LIBRARY_PATH=/apex/com.android.runtime/lib/bionic:/system/lib")
                del cmd[i-1:i+1]
                cmd[cmd.index("/vendor/lib/hw/"+name)] = name
                cmd.append("--namespace-fixture")
            if lifecycle:
                cmd.append("--lifecycle")
            if lights_fixture:
                cmd[cmd.index("--chdir"):cmd.index("--chdir")] = [
                    "--bind", str(fixture), "/sys/class/backlight/exynos_panel"]
                cmd.append("--lights-fixture")
            if sensors_fixture or sensors_context:
                mounts = ["--bind", str(fixture), "/sys/class/sensors/ssp_sensor"]
                if sensors_context:
                    mounts += ["--bind", str(fixture/"context"), "/dev/r800_context"]
                cmd[cmd.index("--chdir"):cmd.index("--chdir")] = mounts
                cmd.append("--sensors-context" if sensors_context else "--sensors-fixture")
            if sensors_evdev:
                cmd[cmd.index("--chdir"):cmd.index("--chdir")] = [
                    "--bind", str(fixture), "/sys/class/sensors/ssp_sensor",
                    "--bind", str(inputs), "/dev/input"]
                cmd[cmd.index("/system/bin/hal-probe"):cmd.index("/system/bin/hal-probe")] = [
                    "-E", "LD_PRELOAD=/system/lib/libevdev-fixture.so"]
                cmd.append("--sensors-evdev")
            if gps_fixture:
                cmd[cmd.index("--chdir"):cmd.index("--chdir")] = ["--bind", str(fixture), "/oem/r800dev"]
                cmd.append("--gps-fixture")
            if audio_fixture:
                cmd.append("--audio-fixture")
            if audio_pcm_fixture:
                cmd[cmd.index("/system/bin/hal-probe"):cmd.index("/system/bin/hal-probe")] = [
                    "-E", "LD_PRELOAD=/system/lib/libpcm-fixture.so"]
                cmd.append("--audio-pcm-fixture")
            if hwc_fixture:
                cmd[cmd.index("--chdir"):cmd.index("--chdir")] = [
                    "--bind", str(fixture), "/dev/graphics",
                    "--bind", str(dsim), "/sys/devices/platform/148e0000.dsim"]
                cmd[cmd.index("/system/bin/hal-probe"):cmd.index("/system/bin/hal-probe")] = [
                    "-E", "LD_PRELOAD=/system/lib/libhwc-fixture.so"]
                cmd.append("--hwc-fixture")
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                log = proc.stdout + proc.stderr
                marker = re.compile(r"HAL_HMI_PASS "+re.escape(identity)+r" module_api=\d+ hal_api=\d+")
                matches = [line for line in log.splitlines() if marker.fullmatch(line)]
                expected = -2 if identity in ("hwcomposer", "sensors") else 0
                life_marker = ("HAL_LIFECYCLE_PASS " + identity +
                               " repeats=16 open_rc=" + str(expected) + " fd_window=256")
                life_ok = log.splitlines().count(life_marker) == 1
                fixture_marker = "HAL_LIGHTS_FIXTURE_PASS rgb_cases=6 cache_skip=1 missing_retry=1"
                fixture_ok = (log.splitlines().count(fixture_marker) == 1 and
                              (fixture/"brightness").read_bytes() == b"255\n" and
                              not (fixture/"brightness.saved").exists()) if lights_fixture else False
                if sensors_fixture:
                    fixture_marker = "HAL_SENSORS_FIXTURE_PASS external_bit=18 delay_clamp=1 rollback=1 close_retry=1 repeats=16"
                    fixture_ok = (log.splitlines().count(fixture_marker) == 1 and
                                  (fixture/"enable").read_bytes() == b"262144" and
                                  (fixture/"accel_poll_delay").read_bytes() == b"20000000" and
                                  not (fixture/"enable.saved").exists())
                if sensors_context:
                    fixture_marker = "HAL_SENSORS_CONTEXT_PASS single_slot=1 gestures=3 offbody=2 step_events=12 malformed=3 flush=1 reopen=1"
                    fixture_ok = (log.splitlines().count(fixture_marker) == 1 and
                                  (fixture/"enable").read_bytes() == b"262144")
                if sensors_evdev:
                    fixture_marker = "HAL_SENSORS_EVDEV_PASS handles=6 events=8 pressure_reject=1 syn_dropped=1"
                    fixture_ok = (log.splitlines().count(fixture_marker) == 1 and
                                  (fixture/"enable").read_bytes() == b"1073741824" and
                                  (fixture/"hrm_lib_poll_delay").read_bytes() == b"1000000000")
                if gps_fixture:
                    fixture_marker = "HAL_GPS_FIXTURE_PASS fixes=2 nmea=3 sv=1 reconnect=1 commands=5"
                    fixture_ok = (log.splitlines().count(fixture_marker) == 1 and
                                  not (fixture/"gps.sock").exists() and
                                  log.splitlines().count("HAL_GPS_CLEANUP_PASS joined=3 active_stop=1 reinit=2 absent_bridge=1") == 1)
                if audio_fixture:
                    fixture_marker = "HAL_AUDIO_FIXTURE_PASS cycles=8 mono=4 stereo=4 silent_reads=16 missing_pcm=1 busy_close=8"
                    fixture_ok = log.splitlines().count(fixture_marker) == 1
                if audio_pcm_fixture:
                    fixture_marker = "HAL_AUDIO_PCM_PASS out_frames=2000 in_frames=4000 mono=1 stereo=1 mute=2 retry=1 opens=4 closes=4"
                    fixture_ok = (log.splitlines().count(fixture_marker) == 1 and
                                  log.splitlines().count("HAL_AUDIO_HFP_PASS sco=8000,16000 starts=10 stops=10 rollback=1 media_resume=2") == 1)
                if hwc_fixture:
                    fixture_marker = "HAL_HWC_FIXTURE_PASS geometry=360x360 cycles=4 invalid_bpp=1 power_recovery=4 timer_vsync=4"
                    fixture_ok = (log.splitlines().count(fixture_marker) == 1 and
                                  log.splitlines().count("HAL_HWC_PRESENT_GUARD_PASS cycles=4 invalid_list=4 ready_null_target=4 hungup=4") == 1 and
                                  log.splitlines().count("HAL_HWC_CPU_PRESENT_PASS frames=8 rgba=4 bgra=4 stride=368 pan=8") == 1 and
                                  log.splitlines().count("HAL_HWC_ZERO_COPY_PASS win_config=2 accepted=1 enotty=1 fallback=1 retire=1 release_closed=1") == 1 and
                                  log.splitlines().count("HAL_HWC_OVERLAY_PASS windows=2,3 releases=5 retire=2 eio=5 disabled=1 transform_reject=1") == 1 and
                                  log.splitlines().count("HAL_HWC_OVERLAY_RECOVERY_PASS reopen=1 format_gate=1 release_dup=1 no_fences_disable=1") == 1 and
                                  (fixture/"fb0").read_bytes() == expected_fb and
                                  (fixture/"pixels").read_bytes() == pixel_input and
                                  (dsim/"cmd_rw").read_bytes() == b"2")
                if namespace_fixture:
                    fixture_marker = "HAL_NAMESPACE_FIXTURE_PASS linked_lights=1 denied_name=2 denied_absolute=2"
                    fixture_ok = (log.splitlines().count(fixture_marker) == 1 and
                                  log.splitlines().count("HAL_NAMESPACE_TRANSITIVE_PASS parent=1 relocated=1 private_denials=6") == 1 and
                                  log.splitlines().count("HAL_NAMESPACE_FAILURE_RECOVERY_PASS missing_needed=3 missing_symbol=3 recovered=6 fd_stable=1") == 1)
                passed = (proc.returncode == 0 and len(matches) == 1 and
                          (not lifecycle or life_ok) and
                          (not (lights_fixture or sensors_fixture or sensors_context or sensors_evdev or gps_fixture or audio_fixture or audio_pcm_fixture or hwc_fixture or namespace_fixture) or fixture_ok))
                results[name] = {"status": ("NAMESPACE_FIXTURE_PASS" if namespace_fixture else
                                             "HWC_FIXTURE_PASS" if hwc_fixture else
                                             "AUDIO_PCM_FIXTURE_PASS" if audio_pcm_fixture else
                                             "AUDIO_FIXTURE_PASS" if audio_fixture else
                                             "GPS_FIXTURE_PASS" if gps_fixture else
                                             "SENSORS_EVDEV_PASS" if sensors_evdev else
                                             "SENSORS_CONTEXT_PASS" if sensors_context else
                                             "SENSORS_FIXTURE_PASS" if sensors_fixture else
                                             "LIGHTS_FIXTURE_PASS" if lights_fixture else
                                             "LIFECYCLE_ONLY_PASS" if lifecycle else "HMI_ONLY_PASS")
                                 if passed else "REVIEW_REQUIRED", "exit_code": proc.returncode,
                                 "marker": matches[0] if len(matches) == 1 else None,
                                 "lifecycle_marker": life_marker if lifecycle and life_ok else None,
                                 "fixture_marker": fixture_marker if fixture_ok else None,
                                 "log": log[-8192:]}
            except subprocess.TimeoutExpired:
                results[name] = {"status": "REVIEW_REQUIRED", "reason": "Timeout"}
        if snapshot() != before:
            raise ValueError("Guest input changed")
    expected_status = ("NAMESPACE_FIXTURE_PASS" if namespace_fixture else
                       "HWC_FIXTURE_PASS" if hwc_fixture else
                       "AUDIO_PCM_FIXTURE_PASS" if audio_pcm_fixture else
                       "AUDIO_FIXTURE_PASS" if audio_fixture else
                       "GPS_FIXTURE_PASS" if gps_fixture else
                       "SENSORS_EVDEV_PASS" if sensors_evdev else
                       "SENSORS_CONTEXT_PASS" if sensors_context else
                       "SENSORS_FIXTURE_PASS" if sensors_fixture else
                       "LIGHTS_FIXTURE_PASS" if lights_fixture else
                       "LIFECYCLE_ONLY_PASS" if lifecycle else "HMI_ONLY_PASS")
    result = {"status": ("ARM32_SYNTHETIC_NAMESPACE_LINK_ONLY" if namespace_fixture else
                         "ARM32_HWC_SYNTHETIC_FB_LIFECYCLE_ONLY" if hwc_fixture else
                         "ARM32_AUDIO_SYNTHETIC_PCM_ONLY" if audio_pcm_fixture else
                         "ARM32_AUDIO_NO_PCM_FALLBACK_ONLY" if audio_fixture else
                         "ARM32_GPS_SYNTHETIC_BRIDGE_ONLY" if gps_fixture else
                         "ARM32_SENSORS_SYNTHETIC_EVDEV_ONLY" if sensors_evdev else
                         "ARM32_SENSORS_SYNTHETIC_CONTEXT_ONLY" if sensors_context else
                         "ARM32_SENSORS_SYNTHETIC_SSP_ONLY" if sensors_fixture else
                         "ARM32_LIGHTS_SYNTHETIC_SYSFS_ONLY" if lights_fixture else
                         "ARM32_HAL_LIFECYCLE_QEMU_USER_ONLY" if lifecycle
                         else "ARM32_HAL_HMI_QEMU_USER_ONLY") if all(
        v["status"] == expected_status for v in results.values()) else "REVIEW_REQUIRED",
        "source_sha": evidence["source_sha"], "runtime_sha256": pins,
        "hal_sha256": evidence["hal_sha256"], "results": results,
        "namespace_fixture_requested": namespace_fixture,
        "synthetic_namespace_link_verified": namespace_fixture and all(v["status"] == expected_status for v in results.values()),
        "synthetic_namespace_config_sha256": namespace_config_sha if namespace_fixture else None,
        "synthetic_namespace_failure_recovery_verified": namespace_fixture and all(v["status"] == expected_status for v in results.values()),
        "synthetic_namespace_transitive_verified": namespace_fixture and all(v["status"] == expected_status for v in results.values()),
        "namespace_fixture_sha256": evidence.get("namespace_fixture_sha256") if namespace_fixture else None,
        "android_namespace_runtime_verified": False, "hal_open_called": lifecycle or lights_fixture or sensors_fixture or sensors_context or sensors_evdev or gps_fixture or audio_fixture or audio_pcm_fixture or hwc_fixture,
        "lifecycle_requested": lifecycle, "lights_fixture_requested": lights_fixture,
        "sensors_fixture_requested": sensors_fixture, "sensors_context_requested": sensors_context,
        "synthetic_context_events_passed": sensors_context and all(v["status"] == expected_status for v in results.values()),
        "sensors_evdev_requested": sensors_evdev,
        "synthetic_evdev_events_passed": sensors_evdev and all(v["status"] == expected_status for v in results.values()),
        "evdev_fixture_sha256": evidence.get("evdev_fixture_sha256") if sensors_evdev else None,
        "gps_fixture_requested": gps_fixture,
        "synthetic_gps_callbacks_passed": gps_fixture and all(v["status"] == expected_status for v in results.values()),
        "gps_reader_cleanup_verified": gps_fixture and all(v["status"] == expected_status for v in results.values()),
        "gnss_hardware_verified": False,
        "audio_fixture_requested": audio_fixture,
        "audio_no_pcm_fallback_verified": audio_fixture and all(v["status"] == expected_status for v in results.values()),
        "audio_pcm_fixture_requested": audio_pcm_fixture,
        "audio_synthetic_pcm_verified": audio_pcm_fixture and all(v["status"] == expected_status for v in results.values()),
        "pcm_fixture_sha256": evidence.get("pcm_fixture_sha256") if audio_pcm_fixture else None,
        "audio_synthetic_hfp_verified": audio_pcm_fixture and all(v["status"] == expected_status for v in results.values()),
        "audio_hfp_hardware_verified": False,
        "audio_pcm_hardware_verified": False,
        "hwc_fixture_requested": hwc_fixture,
        "hwc_synthetic_fb_lifecycle_verified": hwc_fixture and all(v["status"] == expected_status for v in results.values()),
        "hwc_fixture_sha256": evidence.get("hwc_fixture_sha256") if hwc_fixture else None,
        "hwc_synthetic_cpu_present_verified": hwc_fixture and all(v["status"] == expected_status for v in results.values()),
        "gralloc_fixture_sha256": evidence.get("gralloc_fixture_sha256") if hwc_fixture else None,
        "hwc_synthetic_decon_zero_copy_verified": hwc_fixture and all(v["status"] == expected_status for v in results.values()),
        "hwc_synthetic_decon_overlay_verified": hwc_fixture and all(v["status"] == expected_status for v in results.values()),
        "hwc_synthetic_overlay_recovery_verified": hwc_fixture and all(v["status"] == expected_status for v in results.values()),
        "hwc_frame_present_verified": False, "hwc_hardware_verified": False,
        "sensor_events_tested": False,
        "hardware_io_methods_tested": False,
        "hardware_tested": False, "safe_to_flash": False}
    (output/"hal-runtime-evidence.json").write_text(json.dumps(result, indent=2, sort_keys=True)+"\n")
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    c = sub.add_parser("compile")
    for name in ("ndk", "hals", "output"):
        c.add_argument("--"+name, type=Path, required=True)
    c.add_argument("--source-sha", required=True)
    q = sub.add_parser("run")
    for name in ("probe-dir", "hals", "runtime", "runtime-manifest", "output"):
        q.add_argument("--"+name, type=Path, required=True)
    modes = q.add_mutually_exclusive_group()
    modes.add_argument("--lifecycle", action="store_true")
    modes.add_argument("--lights-fixture", action="store_true")
    modes.add_argument("--sensors-fixture", action="store_true")
    modes.add_argument("--sensors-context", action="store_true")
    modes.add_argument("--sensors-evdev", action="store_true")
    modes.add_argument("--gps-fixture", action="store_true")
    modes.add_argument("--audio-fixture", action="store_true")
    modes.add_argument("--audio-pcm-fixture", action="store_true")
    modes.add_argument("--hwc-fixture", action="store_true")
    modes.add_argument("--namespace-fixture", action="store_true")
    a = p.parse_args()
    result = (compile_probe(a.ndk, a.hals, a.output, a.source_sha) if a.action == "compile"
              else run_probe(a.probe_dir, a.hals, a.runtime, a.runtime_manifest, a.output,
                             a.lifecycle, a.lights_fixture, a.sensors_fixture, a.sensors_context, a.sensors_evdev, a.gps_fixture, a.audio_fixture, a.audio_pcm_fixture, a.hwc_fixture, a.namespace_fixture))
    print(json.dumps(result, sort_keys=True))
    return 2 if result["status"] == "REVIEW_REQUIRED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
