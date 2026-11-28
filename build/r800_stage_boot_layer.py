#!/usr/bin/env python3
"""Stage a diagnostic boot layer, explicitly incompatible with Android handover.

A byte occurrence of the audited CPIO inside Image is checked, not the
kernel's linker symbols or actual decompression. Never create NZIT or flash.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

from r800_android_userspace_preflight import read_regular, parse_kernel_config, REQUIRED_CONFIG, MAX_CONFIG
from r800_boot_candidate import component_evidence, PARTITION, DT_SIZE
from r800_cpio_audit import inspect_cpio, MAX_ARCHIVE_BYTES
from r800_initramfs_spec import MAX_INIT_BYTES
from r800_storage_isolation import verify as verify_isolation
from r800_graphics_donor_binding import checkout_sha
from r800_extract_super import require
from r800_stage_adaptation_layer import valid_pin
from r800_verify_tizen_stage import unique_keys

LIMITS = {"Image": PARTITION, "r800.dtb": DT_SIZE, ".config": MAX_CONFIG,
          "init": MAX_INIT_BYTES, "initramfs.cpio": MAX_ARCHIVE_BYTES}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stage(inputs, pins, output, source_sha):
    checkout_sha(source_sha)
    require(set(inputs) == set(pins) == set(LIMITS) and
            all(valid_pin(p) for p in pins.values()), "Five explicit boot component pins required")
    inputs = {n:Path(p).absolute() for n,p in inputs.items()}
    require(all(p.resolve(strict=True) == p for p in inputs.values()),
            "Canonical boot input paths required")
    output = Path(output).absolute()
    repo = Path(__file__).resolve().parents[1]
    require(not output.exists() and not output.is_symlink() and
            not output.resolve().is_relative_to(repo), "Fresh output outside checkout required")
    with tempfile.TemporaryDirectory(dir=output.parent,prefix="r800-boot-layer-") as tmp:
        tree = Path(tmp)/"tree"
        boot = tree/"diagnostic-boot"
        boot.mkdir(parents=True)
        rows = {}
        blobs = {}
        for name,limit in LIMITS.items():
            raw = read_regular(inputs[name],limit)
            require(sha(raw)==pins[name],"Boot component pin mismatch: "+name)
            target = boot/name
            with target.open("xb") as stream:
                stream.write(raw)
            target.chmod(0o400)
            blobs[name]=raw
            rows["diagnostic-boot/"+name]={"bytes":len(raw),"sha256":pins[name],"mode":"0o400"}
        components = component_evidence(blobs["r800.dtb"],blobs["Image"])
        config = blobs[".config"]
        isolation = verify_isolation(config.decode("utf-8"))
        cpio = inspect_cpio(boot/"initramfs.cpio",boot/"init")
        require(cpio["archive_sha256"]==pins["initramfs.cpio"] and
                cpio["embedded_init_sha256"]==pins["init"],
                "CPIO or init evidence mismatch")
        image, archive = blobs["Image"],blobs["initramfs.cpio"]
        offset=image.find(archive,64)
        require(offset>=0 and image.find(archive,offset+1)<0,
                "Expected one exact CPIO byte occurrence in kernel Image")
        values = parse_kernel_config(config)
        missing={k:{"required":v,"observed":values.get(k)}
                 for k,v in REQUIRED_CONFIG.items() if values.get(k)!=v}
        # Physical Android handover requires storage and loop support that
        # this diagnostic profile deliberately removes.
        for key in ("CONFIG_MMC","CONFIG_MMC_BLOCK","CONFIG_MMC_DW_EXYNOS","CONFIG_BLK_DEV_LOOP"):
            if values.get(key)!="y":
                missing[key]={"required":"y","observed":values.get(key)}
        require("CONFIG_BLK_DEV_LOOP" in missing, "Diagnostic config unexpectedly enables loop")
        for name,limit in LIMITS.items():
            require(sha(read_regular(inputs[name],limit))==pins[name] and
                    sha(read_regular(boot/name,limit))==pins[name],
                    "Boot input or staged file changed: "+name)
        checkout_sha(source_sha)
        report={"schema":"galwear-r800-diagnostic-boot-layer-v1",
                "status":"DIAGNOSTIC_BOOT_LAYER_STAGED_ONLY","source_sha":source_sha,
                "files":rows,"components":components,"storage_isolation":isolation,
                "cpio":cpio,"exact_cpio_byte_offset":offset,
                "android_handover_blockers":missing,
                "boot_profile":"STORAGE_ISOLATED_DIAGNOSTIC",
                "kernel_initramfs_symbols_verified":False,
                "compiled_source_provenance_verified":False,
                "android_handover_supported":False,"android_handover_tested":False,
                "kernel_boot_tested":False,"hardware_tested":False,"safe_to_flash":False}
        (tree/"boot-layer-evidence.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
        require(not output.exists() and not output.is_symlink(),"Output already exists")
        os.rename(tree,output)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("image","dtb","config","init","cpio","pins","output"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--source-sha",required=True)
    a=p.parse_args()
    pins=json.loads(read_regular(a.pins,4096),object_pairs_hook=unique_keys)
    result=stage({"Image":a.image,"r800.dtb":a.dtb,".config":a.config,
                  "init":a.init,"initramfs.cpio":a.cpio},pins,a.output,a.source_sha)
    print(result["status"],"android_handover_supported=false; safe_to_flash=false")


if __name__=="__main__":
    main()
