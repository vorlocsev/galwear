#!/usr/bin/env python3
"""Stage explicitly prepared raw EXT4 Android system-as-root and vendor images.

No conversion of Pixel Watch partitions into a bootable R800 system is implied.
Inputs must already use the historical GalWear system-as-root layout. No
mounting, guest execution, boot flag, persistent image or flashing package.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import tempfile

from r800_extract_ext4 import snapshot_image, command
from r800_framework_inventory import ext4_member
from r800_partition_identity import filesystem, literal_properties, property_inventory
from r800_donor_preflight import digest, MAX_DONOR
from r800_graphics_donor_binding import checkout_sha
from r800_extract_super import require

SYSTEM_DIRS = ("/system", "/system/bin", "/system/etc/init", "/vendor", "/oem",
               "/dev", "/proc", "/sys")
VENDOR_DIRS = ("/etc/init", "/etc/vintf", "/lib/hw", "/data/r800dev/fw")
SYSTEM_FILES = ("/system/bin/servicemanager", "/system/bin/hwservicemanager",
                "/system/bin/app_process32")
VENDOR_FILES = ("/bin/vndservicemanager", "/lib/libbt-vendor.so",
                "/lib/hw/hwcomposer.r800.so", "/lib/hw/audio.primary.r800.so",
                "/lib/hw/gps.r800.so", "/lib/hw/sensors.r800.so")
MAX_MEMBER = 64*1024**2
MAX_TOTAL = 256*1024**2


def metadata(tool, image, path):
    result = command(tool, image, "stat "+path)
    match = re.search(r"Inode:\s+(\d+)\s+Type:\s+(\w+)\s+Mode:\s+(\d+)", result.stdout)
    require(match is not None, "Missing or unreadable Android member: "+path)
    return {"inode": int(match[1]), "type": match[2], "mode": int(match[3], 8),
            "stat": result.stdout}


def directory(tool, image, path):
    row = metadata(tool, image, path)
    require(row["type"] == "directory", "Expected Android directory: "+path)
    return {"type": row["type"], "mode": oct(row["mode"])}


def elf_header(raw, path, executable, arm32=False):
    require(len(raw) >= 52 and raw[:4] == b"\x7fELF" and raw[5:7] == b"\x01\x01",
            "Expected little-endian ELF: "+path)
    cls = raw[4]
    kind, machine = struct.unpack_from("<HH", raw, 16)
    require((cls, machine) in ((1,40),(2,183)) and (cls != 2 or len(raw) >= 64)
            and (not arm32 or cls == 1) and kind in ((2,3) if executable else (3,)),
            "Unexpected Android ELF architecture or type: "+path)
    return {"abi":"arm" if cls == 1 else "arm64", "elf_type":kind}


def inspect_pair(system, vendor, scratch):
    tool = shutil.which("debugfs")
    require(tool, "debugfs required")
    for image in (system,vendor):
        require(filesystem(image)["kind"] == "EXT4", "Prepared raw EXT4 images required")
    result = {}
    total = 0
    for partition, image, dirs, files in (
            ("system",system,SYSTEM_DIRS,SYSTEM_FILES),
            ("vendor",vendor,VENDOR_DIRS,VENDOR_FILES)):
        members = {p: directory(tool,image,p) for p in dirs}
        if partition == "system":
            init = metadata(tool,image,"/init")
            if init["type"] == "symlink":
                link = re.search(r'Fast link dest:\s*"([^"]+)"', init["stat"])
                require(link and link[1] in ("/system/bin/init","system/bin/init"),
                        "Unexpected Android init symlink")
                members["/init"] = {"type":"symlink","target":link[1]}
                files = files+("/system/bin/init",)
            else:
                files = files+("/init",)
        for path in files:
            row = metadata(tool,image,path)
            require(row["type"] == "regular", "Expected regular Android member: "+path)
            executable = "/bin/" in path or path == "/init"
            require(not executable or row["mode"] & 0o111, "Android executable mode missing: "+path)
            raw = ext4_member(tool,image,path,min(MAX_MEMBER,MAX_TOTAL-total),scratch)
            require(raw is not None, "Android member missing: "+path)
            total += len(raw)
            members[path] = {"type":"regular","mode":oct(row["mode"]),
                             "sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw),
                             **elf_header(raw,path,executable,partition=="vendor" or path.endswith("app_process32"))}
        prop = "/system/build.prop" if partition == "system" else "/build.prop"
        raw = ext4_member(tool,image,prop,min(1024*1024,MAX_TOTAL-total),scratch)
        require(raw is not None, "Android build.prop missing: "+partition)
        total += len(raw)
        properties = property_inventory(literal_properties(raw,prop))
        require(not properties["conflicts"], "Conflicting Android properties: "+partition)
        if partition == "system":
            require(properties["literal_android_11_hint"] and properties["literal_arm32_hint"],
                    "Expected Android 11 system with ARM32 ABI")
        result[partition] = {"members":members,"properties":properties,
                             "build_prop_sha256":hashlib.sha256(raw).hexdigest()}
    return result


def stage(system, system_sha, vendor, vendor_sha, output, source_sha):
    checkout_sha(source_sha)
    require(all(re.fullmatch(r"[0-9a-f]{64}", s) for s in (system_sha,vendor_sha))
            and system_sha != vendor_sha, "Distinct explicit image SHA-256 pins required")
    system,vendor = Path(system).absolute(),Path(vendor).absolute()
    output = Path(output).absolute()
    repo = Path(__file__).resolve().parents[1]
    require(not output.exists() and not output.is_symlink() and
            not output.resolve().is_relative_to(repo), "Fresh output outside checkout required")
    with tempfile.TemporaryDirectory(dir=output.parent,prefix="r800-android-layer-") as tmp:
        work = Path(tmp)
        tree = work/"result"
        target_system = tree/"r800dev/android/system.img"
        target_vendor = tree/"r800-android/vendor.img"
        for target in (target_system,target_vendor):
            target.parent.mkdir(parents=True,exist_ok=True)
        snapshot_image(system,target_system,system_sha)
        snapshot_image(vendor,target_vendor,vendor_sha)
        evidence = inspect_pair(target_system,target_vendor,work)
        files = {}
        for source,target,pin in ((system,target_system,system_sha),(vendor,target_vendor,vendor_sha)):
            observed = digest(target,MAX_DONOR)
            require(observed["sha256"] == pin and digest(source,MAX_DONOR) == observed,
                    "Android source or staged image changed")
            files[target.relative_to(tree).as_posix()] = {**observed,"mode":"0o400"}
        checkout_sha(source_sha)
        report = {"schema":"galwear-r800-android-layer-v1",
                  "status":"PREPARED_ANDROID_EXT4_PAIR_STAGED_ONLY","source_sha":source_sha,
                  "files":files,"inspection":evidence,
                  "missing_inputs_and_gates":["Original Wear OS identity and donor provenance",
                    "Complete VINTF/SELinux, APEX/ART and dependency compatibility",
                    "Adaptation layer and payload integration, partition capacity and recovery",
                    "Android handover and hardware acceptance"],
                  "wear_os_verified":False,"donor_authenticity_verified":False,
                  "filesystem_integrity_verified":False,"vendor_compatibility_verified":False,
                  "android_handover_tested":False,"payload_complete":False,
                  "hardware_tested":False,"safe_to_flash":False}
        (tree/"android-layer-evidence.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
        require(not output.exists() and not output.is_symlink(),"Output already exists")
        os.rename(tree,output)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("system","vendor","output"):
        p.add_argument("--"+name,type=Path,required=True)
    for name in ("system-sha256","vendor-sha256","source-sha"):
        p.add_argument("--"+name,required=True)
    a=p.parse_args()
    report=stage(a.system,a.system_sha256,a.vendor,a.vendor_sha256,a.output,a.source_sha)
    print(report["status"],"safe_to_flash=false")


if __name__=="__main__":
    main()
