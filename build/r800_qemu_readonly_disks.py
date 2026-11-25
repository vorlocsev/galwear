#!/usr/bin/env python3
"""Read-only virt block experiment using exact audited regular-file images."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from r800_android_rootfs_preflight import snapshot, sha, newc
from r800_android_init_rootfs import unique_object
from r800_android_runtime_extract import digest, ext4
from r800_qemu_guest_abi import verify_baseline, read_bounded_json
from r800_qemu_system_init import kernel_bytes, observe_boot
from r800_qemu_rootfs_preflight import command as ram_command, verify_archive
from r800_initramfs_spec import validate_init
from r800_qemu_user_init import EXPECTED, HEARTBEAT_PREFIX

ORDER = ("system", "system_ext", "product", "vendor", "odm", "runtime")
LIMITS = {"system":128*1024*1024, "runtime":256*1024*1024,
          **{name:32*1024*1024 for name in ORDER[1:-1]}}
HEX = re.compile(r"[0-9a-f]{64}")
PREFIX = b"r800-virt-disk: "


def report(path, status):
    r = json.loads(snapshot(path, 4*1024*1024), object_pairs_hook=unique_object)
    if not isinstance(r,dict) or r.get("status") != status or r.get("safe_to_flash") is not False:
        raise ValueError("Invalid image evidence: "+str(path))
    return r


def verify_image(path, name, expected, size):
    if not isinstance(expected,str) or not HEX.fullmatch(expected):
        raise ValueError("Invalid image digest")
    if type(size) is not int or not 0 < size <= LIMITS[name]:
        raise ValueError("Invalid image size")
    if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
        raise ValueError("Expected non-symlink regular image")
    if path.stat().st_size != size or digest(path,LIMITS[name]) != expected:
        raise ValueError("Image identity mismatch: "+name)
    ext4(path)


def inventory(a, transition=False):
    system = report(a.system_report, "ANDROID_SYSTEM_EXT4_TRANSITION_STATIC_ONLY" if transition else
                    "ANDROID_SYSTEM_EXT4_LABELED_STATIC_ONLY")
    extra = report(a.context_report,"ANDROID_CONTEXT_PARTITIONS_STATIC_ONLY")
    runtime = report(a.runtime_report,"ANDROID_RUNTIME_APEX_PAYLOAD_PRESERVED_ONLY")
    policy = system["policy_sha256"]
    if not HEX.fullmatch(policy) or any(r["policy_sha256"] != policy for r in (extra,runtime)):
        raise ValueError("Image policy identity mismatch")
    if system["property_contexts_sha256"] != extra["property_contexts_sha256"]:
        raise ValueError("Partition property context identity mismatch")
    if system["platform_file_contexts_sha256"] != extra["file_contexts_sha256"]["system/etc/selinux/plat_file_contexts"]:
        raise ValueError("Platform file context identity mismatch")
    if system.get("e2fsck_read_only_passed") is not True or runtime.get("original_payload_bytes_preserved") is not True:
        raise ValueError("Incomplete image checks")
    records = {"system":(a.system_dir/"system.ext4",system["image_sha256"],system["image_bytes"]),
               "runtime":(a.runtime_dir/"runtime.ext4",runtime["payload_sha256"],runtime["payload_bytes"])}
    if not set(extra["partitions"]) <= set(ORDER[1:-1]):
        raise ValueError("Unexpected context partition")
    if set(extra["absent_partitions"]) != set(ORDER[1:-1])-set(extra["partitions"]):
        raise ValueError("Incomplete partition inventory")
    for name,r in extra["partitions"].items():
        records[name] = (a.context_dir/(name+".ext4"),r["sha256"],r["bytes"])
    disks = []
    for name in ORDER:
        if name in records:
            path,expected,size = records[name]
            verify_image(path,name,expected,size)
            disks.append({"name":name,"path":path,"sha256":expected,"bytes":size,
                          "manifest_slot":"vd"+chr(ord("a")+len(disks))})
    return policy,disks


def disk_archive(binary, disks, extra_entries=()):
    data = "".join(d["name"]+" "+d["manifest_slot"]+"\n" for d in disks).encode("ascii")
    return newc([(p,(0o040755,b"",0,0)) for p in ("dev","proc","sys","data")]+[
        ("dev/console",(0o020600,b"",5,1)),("init",(0o100755,binary,0,0)),
        ("galwear-disks.list",(0o100400,data,0,0))]+list(extra_entries))


def command(image,archive,disks):
    args = ram_command(image,archive)
    for i,d in enumerate(disks):
        # JSON blockdev avoids comma-escaping and disallows arbitrary device arguments.
        node = "galwear"+str(i)
        args += ["-blockdev",json.dumps({"driver":"raw","node-name":node,"read-only":True,
                  "file":{"driver":"file","filename":str(d["path"]),"read-only":True}}),
                 "-device","virtio-blk-device,drive="+node+",serial=galwear-"+d["name"]]
    return args


def inspect_console(log, disks, allow_label_probe=False):
    lines = log.replace(b"\r\n",b"\n").splitlines()
    markers = [PREFIX+d["name"].encode()+b" serial=PASS block-ro=1 ext4-ro=1" for d in disks]
    markers += [PREFIX+f"PASS count={len(disks)} policy=not-loaded android=not-started".encode()]
    if [line for line in lines if line.startswith(PREFIX)] != markers:
        raise ValueError("Unexpected read-only disk diagnostics")
    startup = EXPECTED.rstrip(b"\n")
    if lines.count(startup) != 1 or lines.index(startup) >= lines.index(markers[0]):
        raise ValueError("Disk diagnostics outside startup window")
    if any(line.startswith(HEARTBEAT_PREFIX) for line in lines[:lines.index(markers[-1])]):
        raise ValueError("Heartbeat before disk diagnostics")
    if any(line.startswith((b"r800-property-service:",b"r800-transition:",b"r800-relabel:")) for line in lines):
        raise ValueError("Unexpected Android diagnostics")
    if not allow_label_probe and any(line.startswith((b"r800-disk-label:", b"r800-ext4-transition:", b"r800-ext4-exec:")) for line in lines):
        raise ValueError("Unexpected loaded-policy diagnostics")
    return {"block_read_only_reported":True,"ext4_read_only_reported":True,
            "disk_serials_verified":True,"mounted_disk_count":len(disks),
            "selinux_policy_loaded":False,"guest_selinux_labels_verified":False,
            "android_init_started":False,"property_service_started":False}


def run(a, *, expected_inventory=None, extra_entries=(), label_parser=None, transition=False):
    kernel_sha = verify_baseline(a.baseline,a.kernel)
    cfg = read_bounded_json(a.config_evidence)
    if (cfg.get("status") != "VIRT_CONFIG_STATIC_ONLY" or cfg.get("profile") != "block"
            or cfg.get("compiled_kernel_sha256") != kernel_sha
            or cfg.get("virtio_block_profile") is not True or cfg.get("safe_to_flash") is not False):
        raise ValueError("Matching separate block profile required")
    if transition and label_parser is None:
        raise ValueError("Transition requires dedicated acceptance parser")
    policy,disks = inventory(a, transition=transition)
    if expected_inventory is not None and (policy,disks) != expected_inventory:
        raise ValueError("Disk inventory changed since label audit")
    init = validate_init(a.init)
    spec = read_bounded_json(a.compile_evidence)
    if spec.get("status") != "NON_RELEASE_INITRAMFS_SPEC_ONLY" or spec.get("init") != init:
        raise ValueError("Disk probe compile evidence mismatch")
    binary = snapshot(a.init,2*1024*1024)
    if sha(binary) != init["sha256"]:
        raise ValueError("Probe changed")
    archive = disk_archive(binary,disks,extra_entries)
    raw = kernel_bytes(a.kernel)
    if sha(raw) != kernel_sha:
        raise ValueError("Kernel changed")
    a.out_dir.mkdir(exist_ok=False)
    image,cpio = a.out_dir/"generic-Image",a.out_dir/"disks.cpio"
    image.write_bytes(raw)
    cpio.write_bytes(archive)
    # Use private regular-file copies, not caller-supplied backing devices.
    for d in disks:
        dest = a.out_dir/(d["name"]+".ext4")
        with d["path"].open("rb") as src,dest.open("xb") as dst:
            remaining = d["bytes"]
            while remaining:
                chunk = src.read(min(1024*1024,remaining))
                if not chunk:
                    raise ValueError("Truncated disk source")
                dst.write(chunk)
                remaining -= len(chunk)
            if src.read(1):
                raise ValueError("Disk source grew")
        d["path"] = dest
        verify_image(dest,d["name"],d["sha256"],d["bytes"])
        dest.chmod(0o444)
    verify_archive(cpio,archive)
    if sha(kernel_bytes(image)) != kernel_sha:
        raise ValueError("Staged kernel mismatch")
    log = a.out_dir/"generic-console.log"
    observed = observe_boot(command(image,cpio,disks),log)
    verify_archive(cpio,archive)
    if sha(kernel_bytes(image)) != kernel_sha:
        raise ValueError("Kernel changed during boot")
    for d in disks:
        verify_image(d["path"],d["name"],d["sha256"],d["bytes"])
    console = log.read_bytes()
    evidence = inspect_console(console,disks,allow_label_probe=label_parser is not None)
    status = "VIRT_ANDROID_READONLY_BLOCK_MOUNTS_ONLY"
    if label_parser is not None:
        evidence.update(label_parser(console,disks))
        status = ("VIRT_ANDROID_EXT4_DIAGNOSTIC_INIT_DOMAIN_ONLY" if transition else
                  "VIRT_ANDROID_PRELABELED_MOUNTS_ONLY")
    return {**observed,**evidence,
            "status":status,
            "generic_kernel_sha256":kernel_sha,"config_sha256":cfg["config_sha256"],
            "policy_sha256":policy,"archive_sha256":sha(archive),"init_sha256":init["sha256"],
            "disks":[{**d,"path":str(d["path"])} for d in disks],
            "disk_hashes_unchanged":True,"exynos9110_emulated":False,
            "device_contacted":False,"safe_to_flash":False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("system-dir","system-report","context-dir","context-report","runtime-dir","runtime-report",
                 "kernel","baseline","config-evidence","init","compile-evidence","out-dir","report"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    try:
        result=run(a)
        rc=0
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RuntimeError,subprocess.SubprocessError) as exc:
        result={"status":"REJECT","reason":str(exc),"safe_to_flash":False}
        rc=2
    a.report.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result["status"])
    return rc

if __name__=="__main__":
    raise SystemExit(main())
