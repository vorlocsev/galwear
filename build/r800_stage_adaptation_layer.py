#!/usr/bin/env python3
"""Compose the compiled device and local Tizen runtime layers, not firmware."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha
from r800_stage_device_layer import COMPILED, OVERLAY, SCRIPTS, destination, CHARGER_TOOLS
from r800_stage_tizen_runtime import FIRMWARE, DONORS, TARGETS
from r800_verify_tizen_stage import unique_keys, guest_name
from r800_gps_link_gate import audit
from r800_tizen_config_layout import layout, check_guest, materialize, verify_dir

MAX_FILE = 64*1024**2
MAX_TOTAL = 1536*1024**2
MAX_MANIFEST = 4*1024**2
MAX_ENTRIES = 1024

DEVICE = {"r800dev/"+n: "0o755" if n.startswith("bin/") or n in CHARGER_TOOLS else "0o644"
          for n in COMPILED}
DEVICE.update({"vendor/"+destination(n): "0o644" for n in OVERLAY})
DEVICE.update({"r800dev/"+n: "0o755" for n in SCRIPTS})
DEVICE["r800dev/tzchroot.sh"] = "0o755"
RUNTIME_REQUIRED = {"r800dev/gpsbridge", *("r800dev/tzlite"+n for n in TARGETS),
                    *("r800dev/tzlite/lib/"+n for n in DONORS),
                    *("r800dev/"+n.removeprefix("payload/") for n in FIRMWARE)}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def valid_pin(pin):
    return isinstance(pin, str) and re.fullmatch(r"[0-9a-f]{64}", pin)


def load(root, name, pin, source_sha, runtime):
    require(valid_pin(pin), "Explicit manifest SHA-256 required")
    raw = read_regular(root/name, MAX_MANIFEST)
    require(sha(raw) == pin, "Layer manifest pin mismatch")
    report = json.loads(raw, object_pairs_hook=unique_keys)
    schema, status, flags = (
        ("galwear-r800-tizen-runtime-v1", "LOCAL_TIZEN_ELF_FIRMWARE_RUNTIME_STAGED_ONLY",
         ("same_origin_proven", "donor_authenticity_verified", "configuration_complete",
          "plugins_complete", "full_runtime_built", "gnss_runtime_verified", "hardware_tested", "safe_to_flash"))
        if runtime else
        ("galwear-r800-device-layer-v1", "COMPILED_DEVICE_LAYER_STAGED_ONLY",
         ("donor_images_used", "complete_vendor_built", "android_handover_tested",
          "payload_complete", "hardware_tested", "safe_to_flash")))
    require(report.get("schema") == schema and report.get("status") == status and
            report.get("source_sha") == source_sha and
            all(report.get(f) is False for f in flags), "Layer scope or source SHA mismatch")
    files = report["files"]
    require(isinstance(files, dict) and 0 < len(files) <= MAX_ENTRIES, "Invalid layer inventory")
    if runtime:
        require(RUNTIME_REQUIRED <= files.keys(), "Missing required runtime member")
        require(all(valid_pin(report.get(k)) for k in ("tizen_image_sha256", "closure_manifest_sha256", "gpsbridge_sha256")),
                "Missing runtime provenance pin")
        pins = report["library_sha256"]
        require(set(pins) == set(DONORS) and all(valid_pin(p) for p in pins.values()),
                "Missing runtime glibc pins")
    else:
        require(files.keys() == DEVICE.keys(), "Unexpected device inventory")
        require(valid_pin(report.get("component_manifest_sha256")), "Missing component manifest pin")
    mountpoints = layout(report, files) if runtime else {}
    require(runtime or not report.get("chroot_mountpoints"), "Device layer must not declare Tizen mountpoints")
    dirs = set(mountpoints)
    for path, row in files.items():
        require(isinstance(path, str) and len(path) <= 1024 and
                all(re.fullmatch(r"[A-Za-z0-9_.@+-]+", p) and p not in (".","..") for p in path.split("/")),
                "Unsafe layer path")
        if runtime:
            if path.startswith("r800dev/tzlite/"):
                check_guest(path, mountpoints)
            else:
                require(path in RUNTIME_REQUIRED, "Unexpected runtime path")
        require(type(row.get("bytes")) is int and 0 < row["bytes"] <= MAX_FILE and
                valid_pin(row.get("sha256")) and row.get("mode") in ("0o644","0o755"),
                "Invalid layer member metadata")
        if not runtime:
            require(row["mode"] == DEVICE[path], "Unexpected device mode")
        elif path.startswith("r800dev/fw/"):
            require(row["mode"] == "0o644", "Unexpected firmware mode")
        elif path == "r800dev/gpsbridge" or path == "r800dev/tzlite/lib/ld-linux.so.3" or path.startswith("r800dev/tzlite/usr/bin/"):
            require(row["mode"] == "0o755", "Runtime executable mode missing")
        dirs.update(p.as_posix() for p in Path(path).parents if p.as_posix() != ".")
    require(type(report.get("total_bytes")) is int and report["total_bytes"] ==
            sum(row["bytes"] for row in files.values()) <= MAX_TOTAL, "Invalid layer byte total")
    seen, seen_dirs = set(), set()
    pending = [root]
    while pending:
        for entry in os.scandir(pending.pop()):
            p = Path(entry.path)
            rel = p.relative_to(root).as_posix()
            s = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(s.st_mode):
                require(rel in dirs and not s.st_mode & 0o7000, "Unexpected layer directory: "+rel)
                verify_dir(p, rel, mountpoints)
                seen_dirs.add(rel)
                pending.append(p)
            else:
                require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and
                        (rel == name or rel in files), "Unexpected layer entry: "+rel)
                seen.add(rel)
                if rel != name:
                    require(oct(stat.S_IMODE(s.st_mode)) == files[rel]["mode"], "Layer mode mismatch: "+rel)
    require(seen == set(files)|{name} and seen_dirs == dirs, "Layer inventory differs from disk")
    return report, raw


def assemble(device, device_sha, runtime, runtime_sha, output, source_sha):
    checkout_sha(source_sha)
    device, runtime = Path(device).absolute(), Path(runtime).absolute()
    require(all(p.resolve(strict=True) == p and p.is_dir() for p in (device,runtime)),
            "Canonical layer directories required")
    output = Path(output).absolute()
    repo = Path(__file__).resolve().parents[1]
    require(not output.exists() and not output.is_symlink() and
            not any(output.resolve().is_relative_to(p) for p in (device,runtime,repo)),
            "Fresh output outside input trees required")
    inputs = [(device,"device-layer-evidence.json",device_sha,False),
              (runtime,"tizen-runtime-evidence.json",runtime_sha,True)]
    loaded = [load(root,name,pin,source_sha,kind) for root,name,pin,kind in inputs]
    d, t = (item[0] for item in loaded)
    require(not set(d["files"]) & set(t["files"]), "Device and runtime paths collide")
    require(d["total_bytes"]+t["total_bytes"] <= MAX_TOTAL, "Combined layer byte budget exceeded")
    with tempfile.TemporaryDirectory(dir=output.parent,prefix="r800-adaptation-") as tmp:
        stage = Path(tmp)/"tree"
        stage.mkdir()
        rows = {}
        for (root,_,_,kind), (report,_) in zip(inputs,loaded):
            for path,row in sorted(report["files"].items()):
                data = read_regular(root/path, MAX_FILE)
                require(len(data)==row["bytes"] and sha(data)==row["sha256"], "Layer bytes changed: "+path)
                dest = stage/path
                dest.parent.mkdir(parents=True,exist_ok=True)
                with dest.open("xb") as stream:
                    stream.write(data)
                dest.chmod(int(row["mode"],8))
                rows[path] = {k:row[k] for k in ("bytes","sha256","mode")}
                rows[path]["layer"] = "tizen-runtime" if kind else "device"
        mountpoints = layout(t, t["files"])
        materialize(stage, mountpoints)
        for module in ("audio.primary.r800.so","gps.r800.so","hwcomposer.r800.so","sensors.r800.so"):
            require(rows["vendor/lib/hw/"+module]["sha256"] == rows["r800dev/hwc/"+module]["sha256"],
                    "HAL copies differ: "+module)
        require(rows["r800dev/bin/wpcd"]["sha256"] == rows["r800dev/charger/wpcd"]["sha256"],
                "WPCD copies differ")
        final = audit(stage/"r800dev/gpsbridge",stage/"r800dev/tzlite/lib")
        require(final["status"] == "STATIC_GLIBC_CLOSURE_ONLY" and
                final["sha256"] == t["gpsbridge_sha256"] and
                final["donor_sha256"] == t["library_sha256"], "Final GPSBridge audit mismatch")
        for (root,name,pin,kind), (_,raw) in zip(inputs,loaded):
            require(load(root,name,pin,source_sha,kind)[1] == raw, "Layer manifest changed")
        checkout_sha(source_sha)
        result = {"schema":"galwear-r800-adaptation-layer-v1",
                  "status":"DEVICE_AND_LOCAL_TIZEN_ADAPTATION_STAGED_ONLY",
                  "source_sha":source_sha,"device_manifest_sha256":device_sha,
                  "runtime_manifest_sha256":runtime_sha,"files":rows,
                  "total_bytes":sum(r["bytes"] for r in rows.values()),
                  "chroot_mountpoints":mountpoints,
                  "missing_inputs":["Wear OS system and complete Android vendor",
                                    "Additional Tizen configuration/plugins and ownership",
                                    "Display assets and validated kernel handover",
                                    "Independent hardware and recovery acceptance"],
                  "donor_authenticity_verified":False,"full_runtime_built":False,
                  "complete_vendor_built":False,"payload_complete":False,
                  "android_handover_tested":False,"hardware_tested":False,"safe_to_flash":False}
        (stage/"adaptation-layer-evidence.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
        require(not output.exists() and not output.is_symlink(), "Output already exists")
        os.rename(stage,output)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("device","runtime","output"):
        p.add_argument("--"+name,type=Path,required=True)
    for name in ("device-sha256","runtime-sha256","source-sha"):
        p.add_argument("--"+name,required=True)
    a=p.parse_args()
    result=assemble(a.device,a.device_sha256,a.runtime,a.runtime_sha256,a.output,a.source_sha)
    print(result["status"],len(result["files"]),"files; safe_to_flash=false")


if __name__ == "__main__":
    main()
