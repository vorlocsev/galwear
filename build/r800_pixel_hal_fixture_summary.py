#!/usr/bin/env python3
"""Bind Pixel HAL fixture evidence to exact source, donor and compiled HALs.

The result is a synthetic QEMU gate only, never Vendor/boot/hardware approval.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

SYSTEM_PIN = "526da8f411f54e82ca9d20da863e31d00abd7c32e28388a91e9e39f1b9a41aed"
HALS = {"audio.primary.r800.so", "gps.r800.so", "hwcomposer.r800.so",
        "lights.r800.so", "sensors.r800.so"}
RUNTIME = {"linker", "libc.so", "libdl.so", "libm.so", "liblog.so", "libc++.so"}
MODES = {
    "lifecycle": ("ARM32_HAL_LIFECYCLE_QEMU_USER_ONLY", "LIFECYCLE_ONLY_PASS", HALS),
    "lights-fixture": ("ARM32_LIGHTS_SYNTHETIC_SYSFS_ONLY", "LIGHTS_FIXTURE_PASS", {"lights.r800.so"}),
    "sensors-fixture": ("ARM32_SENSORS_SYNTHETIC_SSP_ONLY", "SENSORS_FIXTURE_PASS", {"sensors.r800.so"}),
    "sensors-context": ("ARM32_SENSORS_SYNTHETIC_CONTEXT_ONLY", "SENSORS_CONTEXT_PASS", {"sensors.r800.so"}),
    "sensors-evdev": ("ARM32_SENSORS_SYNTHETIC_EVDEV_ONLY", "SENSORS_EVDEV_PASS", {"sensors.r800.so"}),
    "gps-fixture": ("ARM32_GPS_SYNTHETIC_BRIDGE_ONLY", "GPS_FIXTURE_PASS", {"gps.r800.so"}),
    "audio-fixture": ("ARM32_AUDIO_NO_PCM_FALLBACK_ONLY", "AUDIO_FIXTURE_PASS", {"audio.primary.r800.so"}),
    "audio-pcm-fixture": ("ARM32_AUDIO_SYNTHETIC_PCM_ONLY", "AUDIO_PCM_FIXTURE_PASS", {"audio.primary.r800.so"}),
    "hwc-fixture": ("ARM32_HWC_SYNTHETIC_FB_LIFECYCLE_ONLY", "HWC_FIXTURE_PASS", {"hwcomposer.r800.so"}),
    "namespace-fixture": ("ARM32_SYNTHETIC_NAMESPACE_LINK_ONLY", "NAMESPACE_FIXTURE_PASS", {"lights.r800.so"}),
}
MAX_REPORT = 1024*1024


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def pinned(rows, names):
    return isinstance(rows, dict) and set(rows) == names and all(
        isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in rows.values())


def read(path):
    from r800_android_userspace_preflight import read_regular
    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, "Duplicate report key")
            out[key] = value
        return out
    raw = read_regular(path, MAX_REPORT)
    result = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(result, dict), "Expected report object")
    return result, hashlib.sha256(raw).hexdigest()


def probe_valid(report, source, pins, hals, status, marker, modules):
    results = report.get("results")
    return (
        report.get("source_sha") == source and report.get("runtime_sha256") == pins
        and report.get("hal_sha256") == hals and report.get("hardware_tested") is False
        and report.get("safe_to_flash") is False and report.get("status") == status
        and isinstance(results, dict) and set(results) == modules
        and all(isinstance(v, dict) and v.get("status") == marker
                and type(v.get("exit_code")) is int and v["exit_code"] == 0
                for v in results.values()))


def summarize(directory, source):
    require(re.fullmatch(r"[0-9a-f]{40}", source), "Expected full source SHA")
    directory = Path(directory)
    runtime, runtime_digest = read(directory/"pixel-bionic-extraction.json")
    baseline, baseline_digest = read(directory/"pixel-hal-runtime.json")
    compile_report, compile_digest = read(directory/"pixel-hal-compile.json")
    require(runtime.get("source_sha") == source
            and runtime.get("status") == "ARM32_BIONIC_RUNTIME_EXTRACTED_STATIC_ONLY"
            and runtime.get("raw_system_sha256") == runtime.get("system_sha256") == SYSTEM_PIN
            and runtime.get("apex_layout") == "FLATTENED_APEX"
            and runtime.get("linker_provides_ld_android") is True
            and runtime.get("safe_to_flash") is False, "Pixel runtime evidence mismatch")
    pins = {k:v.get("sha256") for k,v in runtime["files"].items()}
    require(pinned(pins,RUNTIME), "Invalid runtime pins")
    require(compile_report.get("commit") == source
            and compile_report.get("abi") == "armeabi-v7a"
            and compile_report.get("safe_to_flash") is False, "Compile evidence mismatch")
    hals = {name: (compile_report["audio_candidate"] if name.startswith("audio.") else
                   compile_report["linked_libraries"][name.split(".")[0]])["sha256"]
            for name in HALS}
    require(pinned(hals,HALS), "Invalid HAL pins")
    require(probe_valid(baseline,source,pins,hals,"ARM32_HAL_HMI_QEMU_USER_ONLY","HMI_ONLY_PASS",HALS)
            and baseline.get("hal_open_called") is False, "Pixel HMI baseline mismatch")
    rows = {}
    for mode,(status,marker,modules) in MODES.items():
        path = directory/("pixel-hal-"+mode+".json")
        try:
            report, report_digest = read(path)
            valid = probe_valid(report,source,pins,hals,status,marker,modules)
            rows[mode] = {"status":"PASS" if valid else "REVIEW_REQUIRED",
                          "report_sha256":report_digest,"probe_status":report.get("status"),
                          "modules":sorted(modules) if valid else []}
        except FileNotFoundError:
            rows[mode] = {"status":"NOT_TESTED","reason":"Missing probe report"}
        except (OSError,ValueError,TypeError,KeyError) as exc:
            rows[mode] = {"status":"REVIEW_REQUIRED","reason":str(exc)}
    passed = all(row["status"]=="PASS" for row in rows.values())
    return {"schema":"galwear-r800-pixel-hal-fixtures-v1","source_sha":source,
            "system_sha256":SYSTEM_PIN,"runtime_sha256":pins,"hal_sha256":hals,
            "input_report_sha256":{"runtime":runtime_digest,"hmi":baseline_digest,
                                   "compile":compile_digest},
            "modes":rows,"status":"PIXEL_HAL_SYNTHETIC_FIXTURES_ONLY" if passed else "REVIEW_REQUIRED",
            "android_boot_tested":False,"hardware_tested":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--evidence",type=Path,required=True)
    p.add_argument("--source-sha",required=True)
    a=p.parse_args()
    result=summarize(a.evidence,a.source_sha)
    with (a.evidence/"pixel-hal-fixtures-summary.json").open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2,sort_keys=True)
        stream.write("\n")
    print("PIXEL_HAL_FIXTURE_SUMMARY",json.dumps(result,sort_keys=True))
    return 0 if result["status"]=="PIXEL_HAL_SYNTHETIC_FIXTURES_ONLY" else 2


if __name__=="__main__":
    raise SystemExit(main())
