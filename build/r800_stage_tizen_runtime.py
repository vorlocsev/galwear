#!/usr/bin/env python3
"""Assemble a local Tizen device runtime, using actual donor ELF and firmware.

This deliberately requires a separately staged, pinned ELF closure and a
hash-pinned clean Tizen EXT4 image. No Debian fixture, device backup, mount,
guest execution, or installation package. Configuration and plugins are not
inferred from the executable closure.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_extract_ext4 import extract, TIZEN, MAX_FILE
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha
from r800_gps_donor_snapshot import DONORS
from r800_gps_link_gate import audit
from r800_stage_runtime_layer import build as build_bridge
from r800_tizen_dependencies import TARGETS
from r800_verify_tizen_stage import verify, guest_name, unique_keys, MANIFEST, MAX_MANIFEST
from r800_peripheral_firmware import REQUIRED, check_bytes
from r800_tizen_config_layout import extract_configs, PREFIX, MOUNTPOINTS, materialize
from r800_tizen_plugins import bind_canonical_image, selected

MAX_TOTAL = 1024*1024**2
FIRMWARE = tuple(sorted(n for n in TIZEN if n.startswith("payload/fw/")))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load_closure(root, pin, pins):
    raw = read_regular(root/MANIFEST, MAX_MANIFEST)
    require(sha(raw) == pin, "Tizen closure manifest pin mismatch")
    report = json.loads(raw, object_pairs_hook=unique_keys)
    verify(root, expected=report)
    files = report["files"]
    for name in TARGETS:
        require(name in files, "Required Tizen target missing: "+name)
        if name.startswith("/usr/bin/"):
            require(files[name]["mode"] == "0o755", "Tizen daemon or tool not executable: "+name)
    for name in DONORS:
        candidates = [row for path, row in files.items()
                      if path in ("/lib/"+name, "/usr/lib/"+name, "/usr/lib/sensor/"+name)]
        require(candidates and all(row["sha256"] == pins[name] for row in candidates),
                "Tizen closure and image glibc differ or alias absent: "+name)
    return report, raw


def merge_file(stage, rows, name, raw, mode, origin, total):
    digest = sha(raw)
    if name in rows:
        require(rows[name]["sha256"] == digest and rows[name]["bytes"] == len(raw),
                "Conflicting runtime file: "+name)
        # Only identical glibc files may overlap. Preserve the staged donor
        # mode, except that the final PT_INTERP loader must be executable.
        require(rows[name]["mode"] == mode or
                (name in {"r800dev/tzlite/lib/"+n for n in DONORS} and
                 {rows[name]["mode"], mode} == {"0o644", "0o755"}),
                "Conflicting runtime mode: "+name)
        if name == "r800dev/tzlite/lib/ld-linux.so.3":
            (stage/name).chmod(0o755)
            rows[name]["mode"] = "0o755"
        rows[name]["origins"].append(origin)
        return total
    total += len(raw)
    require(total <= MAX_TOTAL, "Runtime byte budget exceeded")
    target = stage/name
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        stream.write(raw)
    target.chmod(int(mode, 8))
    rows[name] = {"bytes": len(raw), "sha256": digest, "mode": mode, "origins": [origin]}
    return total


def assemble(image, image_sha, closure, closure_sha, ndk, output, source_sha, xtra_abi=0):
    checkout_sha(source_sha)
    require(all(re.fullmatch(r"[0-9a-f]{64}", p) for p in (image_sha, closure_sha)),
            "Explicit image and closure SHA-256 required")
    closure = Path(closure).absolute()
    require(closure.resolve(strict=True) == closure, "Closure must be a canonical local directory")
    image, ndk = Path(image).absolute(), Path(ndk).resolve(strict=True)
    output = Path(output).absolute()
    repo = Path(__file__).resolve().parents[1]
    require(not output.exists() and not output.is_symlink() and
            not any(output.resolve().is_relative_to(p) for p in (closure, ndk, repo)),
            "Fresh output outside input trees required")
    with tempfile.TemporaryDirectory(dir=output.parent, prefix="r800-tizen-runtime-") as tmp:
        work = Path(tmp)
        extracted = work/"extracted"
        extraction = extract(image, extracted, "tizen", image_sha)
        require(extraction["status"] == "EXT4_DONOR_EXTRACTION_ONLY" and
                extraction["snapshot_verified"] is True and not extraction["missing_or_ambiguous"],
                "Complete selected Tizen firmware and library extraction required")
        pins = {name: extraction["files"]["tizen/"+name]["sha256"] for name in DONORS}
        report, manifest_raw = load_closure(closure, closure_sha, pins)
        origin = bind_canonical_image(image, image_sha, report["files"], work)
        minimal = work/"minimal"
        bridge = build_bridge(extracted/"tizen", pins, ndk, minimal, source_sha,
                              "LOCAL_TIZEN_CANDIDATE", xtra_abi)
        require(bridge["scope"] == "LOCAL_TIZEN_CANDIDATE" and
                bridge["library_sha256"] == pins and bridge["source_sha"] == source_sha,
                "Unexpected linked runtime scope")
        stage = work/"result"
        stage.mkdir()
        rows, total = {}, 0
        for guest, info in sorted(report["files"].items()):
            relative = guest_name(guest)
            raw = read_regular(closure/relative, MAX_FILE)
            require(sha(raw) == info["sha256"] and len(raw) == info["bytes"], "Closure file changed")
            total = merge_file(stage, rows, "r800dev/tzlite/"+relative,
                               raw, info["mode"], "tizen-closure:"+guest, total)
        for name, info in sorted(bridge["files"].items()):
            require(name in {"r800dev/gpsbridge"} |
                    {"r800dev/tzlite/lib/"+n for n in DONORS}, "Unexpected minimal runtime path")
            raw = read_regular(minimal/name, MAX_FILE)
            require(sha(raw) == info["sha256"] and len(raw) == info["bytes"], "Linked runtime changed")
            mode = "0o755" if name.endswith("/ld-linux.so.3") else info["mode"]
            total = merge_file(stage, rows, name, raw, mode, "linked-runtime", total)
        for source in FIRMWARE:
            info = extraction["files"][source]
            raw = read_regular(extracted/source, MAX_FILE)
            require(info["status"] == "EXTRACTED" and sha(raw) == info["sha256"] and
                    len(raw) == info["bytes"], "Extracted firmware changed")
            name = source.removeprefix("payload/")
            if name in REQUIRED:
                check_bytes(name, raw)
            total = merge_file(stage, rows, "r800dev/"+name, raw, "0o644", "tizen-image:"+info["source"], total)
        plugins = selected(stage/PREFIX, list(report.get("selected_plugins", {})), report["files"])
        require(plugins == report.get("selected_plugins", {}), "Final plugin evidence mismatch")
        configs, config_identity = extract_configs(image, image_sha, work)
        for path, raw in sorted(configs.items()):
            total = merge_file(stage, rows, PREFIX+path, raw, "0o644", "tizen-image:"+path, total)
        materialize(stage, MOUNTPOINTS)
        # Link audit is repeated on the exact final staged library path.
        final = audit(stage/"r800dev/gpsbridge", stage/"r800dev/tzlite/lib")
        require(final["status"] == "STATIC_GLIBC_CLOSURE_ONLY" and
                final["sha256"] == bridge["gpsbridge_sha256"] and
                final["donor_sha256"] == pins, "Final GPSBridge closure mismatch")
        verify(closure, expected=report)
        require(read_regular(closure/MANIFEST, MAX_MANIFEST) == manifest_raw, "Closure manifest changed")
        checkout_sha(source_sha)
        result = {"schema": "galwear-r800-tizen-runtime-v1",
                  "status": "LOCAL_TIZEN_ELF_FIRMWARE_RUNTIME_STAGED_ONLY",
                  "source_sha": source_sha, "tizen_image_sha256": image_sha,
                  "closure_manifest_sha256": closure_sha, "library_sha256": pins,
                  "gpsbridge_sha256": final["sha256"], "files": rows, "total_bytes": total,
                  "chroot_mountpoints": MOUNTPOINTS, "configuration_identity": config_identity,
                  "selected_plugins": plugins, "canonical_elf_image_binding": origin,
                  "missing_inputs": ["Additional Tizen configuration and plugins",
                                     "Original ownership, permissions and SELinux acceptance",
                                     "Device daemon startup and hardware GNSS"],
                  "same_origin_proven": False, "donor_authenticity_verified": False,
                  "configuration_complete": False, "plugins_complete": False,
                  "full_runtime_built": False, "gnss_runtime_verified": False,
                  "hardware_tested": False, "safe_to_flash": False}
        (stage/"tizen-runtime-evidence.json").write_text(json.dumps(result, indent=2, sort_keys=True)+"\n")
        require(not output.exists() and not output.is_symlink(), "Output already exists")
        os.rename(stage, output)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("image", "closure", "ndk", "output"):
        p.add_argument("--"+name, required=True, type=Path)
    for name in ("image-sha256", "closure-sha256", "source-sha"):
        p.add_argument("--"+name, required=True)
    p.add_argument("--xtra-abi", type=int, choices=(0,1,2), default=0)
    a = p.parse_args()
    report = assemble(a.image, a.image_sha256, a.closure, a.closure_sha256,
                      a.ndk, a.output, a.source_sha, a.xtra_abi)
    print(report["status"], len(report["files"]), "files; safe_to_flash=false")


if __name__ == "__main__":
    main()
