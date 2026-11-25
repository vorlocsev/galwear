#!/usr/bin/env python3
"""Run the separate pre-labeled EXT4 experiment from a verified AOSP build.

Requires a previously booted exact block-profile kernel. No device access,
flashing, AOSP source sync or production image publication.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from r800_property_pipeline import (Pipeline, REPO, verify_build, resolved_output,
                                    require_report)
from r800_android_rootfs_preflight import snapshot
from r800_android_runtime_extract import digest, MAX_APEX
from r800_qemu_guest_abi import verify_baseline, read_bounded_json

SUCCESS = "VIRT_EXT4_PROPERTY_PIPELINE_ONLY"
PROBES = (
    ("mount", "virt-readonly-disks.c", ()),
    ("labels", "virt-readonly-disks.c", ("GALWEAR_LABEL_PROBE",)),
    ("transition", "virt-readonly-disks.c", ("GALWEAR_LABEL_PROBE", "GALWEAR_TRANSITION_PROBE")),
    ("second-stage", "ext4-init-domain-probe.c", ()),
    ("service", "virt-readonly-disks.c", ("GALWEAR_LABEL_PROBE", "GALWEAR_SERVICE_PROBE")),
)


def runtime_apex(root):
    build = root/"runtime"
    r = require_report(build/"runtime-extraction.json", "ANDROID_RUNTIME_EXTRACTED_STATIC_ONLY")
    path = Path(snapshot(build/"runtime-apex-path.txt",4096).decode().strip())
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not path.is_relative_to((build/"aosp-out").resolve(strict=True))
            or digest(path,MAX_APEX) != r["apex_sha256"]):
        raise ValueError("Runtime APEX identity/path mismatch")
    return path,r["apex_sha256"]


def block_config(a):
    sha = verify_baseline(a.baseline,a.kernel)
    cfg = read_bounded_json(a.config_evidence)
    if (cfg.get("status") != "VIRT_CONFIG_STATIC_ONLY" or cfg.get("profile") != "block"
            or cfg.get("virtio_block_profile") is not True
            or cfg.get("compiled_kernel_sha256") != sha or cfg.get("safe_to_flash") is not False):
        raise ValueError("Exact block-profile baseline required")


def compile_probes(p):
    result = {}
    for index,(name,source,defines) in enumerate(PROBES,1):
        binary = p.out/(name+"-init")
        evidence = p.out/(name+"-compile.json")
        p.step(f"02-{index:02d}-compile-{name}",["aarch64-linux-gnu-gcc","-std=c11",
            "-Wall","-Wextra","-Werror","-O2","-static",
            *["-D"+d for d in defines],REPO/"src/initramfs"/source,"-o",binary])
        p.py(f"02-{index:02d}-spec-{name}","r800_initramfs_spec.py",
             ["--init",binary,"--list",p.out/(name+".list")],
             evidence,"NON_RELEASE_INITRAMFS_SPEC_ONLY",False)
        result[name] = ["--init",binary,"--compile-evidence",evidence]
    return result


def execute(p,a):
    b,o = a.build_root,p.out
    verify_build(b,p.source_commit)
    block_config(a)
    apex,apex_sha = runtime_apex(b)
    service = resolved_output(b/"service","product")
    stock = resolved_output(b/"stock","product")
    fixture = resolved_output(b/"fixture","product")
    st = resolved_output(b/"stock","host")/"bin"
    ft = resolved_output(b/"fixture","host")/"bin"
    for path in (st/"e2fsdroid",st/"checkfc",ft/"e2fsdroid",ft/"checkfc",ft/"sepolicy-analyze"):
        if not path.is_file() or path.is_symlink():
            raise ValueError("Missing AOSP host tool: "+str(path))
    staged = o/"staged"
    p.py("01-stage-rootfs","r800_android_init_rootfs.py",
         ["--product-out",service,"--runtime-root",b/"runtime/runtime-root",
          "--choices",a.choices,"--out",staged],o/"layout.json","INIT_EXPERIMENTAL_ROOTFS_STAGED_ONLY")
    probes = compile_probes(p)
    common = ["--kernel",a.kernel,"--baseline",a.baseline,"--config-evidence",a.config_evidence]
    rootfs = ["--staged",staged,"--preflight-init",b/"preflight-init"]

    def images(prefix, product, host, system_options, system_status):
        base = ["--product-out",product,"--checkfc",host/"checkfc"]
        tools = [*base,"--e2fsdroid",host/"e2fsdroid"]
        result = []
        for name,script,options,status in (
                ("system","r800_android_system_ext4.py",[*rootfs,*tools,*system_options],system_status),
                ("context","r800_android_context_partitions.py",tools,"ANDROID_CONTEXT_PARTITIONS_STATIC_ONLY"),
                ("runtime","r800_android_apex_payload.py",
                 [*base,"--staged",staged,"--apex",apex,"--apex-sha256",apex_sha],
                 "ANDROID_RUNTIME_APEX_PAYLOAD_PRESERVED_ONLY")):
            dest = o/(prefix+"-"+name)
            report = o/(prefix+"-"+name+".json")
            p.py(prefix+"-"+name,script,[*options,"--out",dest],report,status)
            result += ["--"+name+"-dir",dest,"--"+name+"-report",report]
        return result

    stock_args = images("03-stock",stock,st,[],"ANDROID_SYSTEM_EXT4_LABELED_STATIC_ONLY")
    p.py("04-readonly-mount","r800_qemu_readonly_disks.py",
         [*common,*stock_args,*probes["mount"],"--out-dir",o/"mount-boot"],
         o/"mount.json","VIRT_ANDROID_READONLY_BLOCK_MOUNTS_ONLY")
    p.py("05-effective-labels","r800_qemu_prelabeled_mounts.py",
         [*common,*stock_args,*probes["labels"],"--product-out",stock,"--checkfc",st/"checkfc",
          "--mount-report",o/"mount.json","--out-dir",o/"labels-boot"],
         o/"labels.json","VIRT_ANDROID_PRELABELED_MOUNTS_ONLY")
    p.py("06-stock-nosuid-policy","r800_ext4_nosuid_policy_gate.py",
         ["--product-out",stock,"--checkfc",st/"checkfc","--profile","stock"],
         o/"stock-nosuid.json","EXT4_NOSUID_POLICY_PREREQUISITES_ONLY")
    second = probes["second-stage"]
    p.py("06-transition-image","r800_android_system_ext4.py",
         [*rootfs,"--product-out",stock,"--checkfc",st/"checkfc","--e2fsdroid",st/"e2fsdroid",
          "--transition-init",second[1],"--transition-compile-evidence",second[3],
          "--out",o/"transition-system"],o/"transition-system.json",
         "ANDROID_SYSTEM_EXT4_TRANSITION_STATIC_ONLY")
    p.py("07-init-transition","r800_qemu_ext4_init_transition.py",
         [*common,"--system-dir",o/"transition-system","--system-report",o/"transition-system.json",
          "--original-system-dir",o/"03-stock-system","--original-system-report",o/"03-stock-system.json",
          *stock_args[4:],*probes["transition"],"--diagnostic-init",second[1],
          "--diagnostic-compile-evidence",second[3],"--product-out",stock,"--checkfc",st/"checkfc",
          "--label-report",o/"labels.json","--out-dir",o/"transition-boot"],
         o/"transition.json","VIRT_ANDROID_EXT4_DIAGNOSTIC_INIT_DOMAIN_ONLY")
    p.py("08-fixture-nosuid-policy","r800_ext4_nosuid_policy_gate.py",
         ["--product-out",fixture,"--checkfc",ft/"checkfc","--profile","fixture"],
         o/"fixture-nosuid.json","EXT4_NOSUID_POLICY_PREREQUISITES_ONLY")
    fixture_args = images("08-fixture",fixture,ft,["--service-fixture"],"ANDROID_SYSTEM_EXT4_SERVICE_STATIC_ONLY")
    p.py("08-linker-resolution","r800_ext4_linker_resolution.py",
         ["--system-report",o/"08-fixture-system.json","--runtime-report",o/"08-fixture-runtime.json"],
         o/"linker-resolution.json","EXT4_LINKER_RESOLUTION_STATIC_ONLY")
    p.py("08-elf-abi","r800_ext4_elf_abi.py",
         ["--system-report",o/"08-fixture-system.json","--runtime-report",o/"08-fixture-runtime.json",
          "--system-image",o/"08-fixture-system/system.ext4","--runtime-image",o/"08-fixture-runtime/runtime.ext4"],
         o/"elf-abi.json","EXT4_ELF_ABI_STATIC_ADVISORY_ONLY")
    p.py("09-property-service","r800_qemu_ext4_property_service.py",
         [*common,*fixture_args,*probes["service"],"--stock-system-report",o/"03-stock-system.json",
          "--product-out",fixture,"--checkfc",ft/"checkfc","--analyze",ft/"sepolicy-analyze",
          "--transition-report",o/"transition.json","--out-dir",o/"service-boot"],
         o/"service.json","VIRT_GALWEAR_EXT4_PROPERTY_SERVICE_ONLY")
    p.status = SUCCESS


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("build-root","choices","kernel","baseline","config-evidence","out"):
        parser.add_argument("--"+name,type=Path,required=True)
    a=parser.parse_args()
    p=None
    try:
        for key,value in vars(a).items():
            if value.is_symlink():
                raise ValueError("Symlink input/output: "+key)
            setattr(a,key,value.resolve(strict=key!="out"))
        if a.out.is_relative_to(REPO) or a.out.is_relative_to(a.build_root):
            raise ValueError("Output must be separate from repository and build tree")
        source=subprocess.check_output(["git","rev-parse","HEAD"],cwd=REPO,text=True).strip()
        if subprocess.check_output(["git","status","--porcelain"],cwd=REPO,text=True).strip():
            raise ValueError("Clean GalWear checkout required")
        p=Pipeline(a.out,"ext4-boot",source)
        execute(p,a)
        p.save()
        return 0
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RuntimeError,subprocess.SubprocessError,KeyboardInterrupt) as exc:
        if p is not None:
            if p.status!="REJECT":
                p.steps.append({"name":"pipeline-validation","status":"FAILED","reason":str(exc)[:1000]})
            p.status="REJECT"
            p.save()
        print("REJECT:",exc,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
