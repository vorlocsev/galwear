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
    raw, info = check(probe)
    if not set(info["needed"]) <= HAL_COMPILE_LIBS:
        raise ValueError("Unexpected probe dependency")
    result = {"status": "ARM32_HAL_DLOPEN_PROBE_COMPILE_ONLY", "source_sha": source_sha,
              "probe_sha256": sha(raw), "hal_sha256": hashes,
              "runtime_verified": False, "hardware_tested": False, "safe_to_flash": False}
    (output/"hal-probe-evidence.json").write_text(json.dumps(result, indent=2, sort_keys=True)+"\n")
    return result


def run_probe(probe_dir, hals, runtime, runtime_manifest, output):
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
        def add(src, rel, digest, lib=False, executable=False):
            raw, info = check(src, lib)
            if sha(raw) != digest:
                raise ValueError("ELF digest mismatch: " + src.name)
            runtime_dependencies(src.name, info, linker_soname)
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
        def snapshot():
            return {p.relative_to(root).as_posix(): ("symlink:"+os.readlink(p) if p.is_symlink() else sha(p.read_bytes()))
                    for p in sorted(root.rglob("*")) if p.is_file() or p.is_symlink()}
        before = snapshot()
        for name, identity in HALS.items():
            cmd = [bwrap, "--unshare-all", "--die-with-parent", "--new-session",
                   "--clearenv", "--ro-bind", str(root), "/", "--ro-bind", qemu, "/qemu",
                   "--dev", "/dev", "--proc", "/proc", "--chdir", "/",
                   "/qemu", "-cpu", "cortex-a15", "-L", "/",
                   "-E", "LD_LIBRARY_PATH=/apex/com.android.runtime/lib/bionic:/system/lib", "/system/bin/hal-probe",
                   "/vendor/lib/hw/"+name, identity]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                log = proc.stdout + proc.stderr
                marker = re.compile(r"HAL_HMI_PASS "+re.escape(identity)+r" module_api=\d+ hal_api=\d+")
                matches = [line for line in log.splitlines() if marker.fullmatch(line)]
                results[name] = {"status": "HMI_ONLY_PASS" if proc.returncode == 0 and len(matches) == 1
                                 else "REVIEW_REQUIRED", "exit_code": proc.returncode,
                                 "marker": matches[0] if len(matches) == 1 else None,
                                 "log": log[-8192:]}
            except subprocess.TimeoutExpired:
                results[name] = {"status": "REVIEW_REQUIRED", "reason": "Timeout"}
        if snapshot() != before:
            raise ValueError("Guest input changed")
    result = {"status": "ARM32_HAL_HMI_QEMU_USER_ONLY" if all(
        v["status"] == "HMI_ONLY_PASS" for v in results.values()) else "REVIEW_REQUIRED",
        "source_sha": evidence["source_sha"], "runtime_sha256": pins,
        "hal_sha256": evidence["hal_sha256"], "results": results,
        "android_namespace_runtime_verified": False, "hal_open_called": False,
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
    a = p.parse_args()
    result = (compile_probe(a.ndk, a.hals, a.output, a.source_sha) if a.action == "compile"
              else run_probe(a.probe_dir, a.hals, a.runtime, a.runtime_manifest, a.output))
    print(json.dumps(result, sort_keys=True))
    return 2 if result["status"] == "REVIEW_REQUIRED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
