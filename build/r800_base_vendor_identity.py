#!/usr/bin/env python3
"""Read-only base vendor candidate identification using the existing EXT4 audit.

Literal properties are claims from the supplied image, not authentication.
No donor model is assumed and no compatibility or flash approval is issued.
"""
import argparse
import json
from pathlib import Path
import tempfile

from r800_extract_ext4 import extract, identity_inventory
from r800_donor_preflight import digest, MAX_DONOR, MAX_FILE
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha
from r800_stage_adaptation_layer import valid_pin
from r800_vendor_recipe_preflight import GROUPS

KEYS={"brand":"ro.product.vendor.brand","manufacturer":"ro.product.vendor.manufacturer",
      "model":"ro.product.vendor.model","device":"ro.product.vendor.device",
      "build_id":"ro.vendor.build.id","fingerprint":"ro.vendor.build.fingerprint",
      "android_release":"ro.vendor.build.version.release","sdk":"ro.vendor.build.version.sdk",
      "vndk":"ro.vndk.version","platform":"ro.board.platform"}


def describe(report,pin,effects_pin=None):
    require(valid_pin(pin) and (effects_pin is None or valid_pin(effects_pin)),
            "Explicit base vendor and optional effects SHA-256 required")
    require(report.get("status")=="EXT4_DONOR_EXTRACTION_ONLY" and
            report.get("profile")=="vendor-identity" and report.get("image_sha256")==pin and
            report.get("snapshot_verified") is True and
            report.get("donor_compatibility_verified") is False and
            report.get("safe_to_flash") is False,"Unexpected base vendor extraction scope")
    inv=report["vendor_identity"]
    props=inv["properties"]
    conflicts=inv["property_conflicts"]
    identity=identity_inventory(props,conflicts)
    require(identity==inv["identity_inventory"],"Vendor identity inventory mismatch")
    observed={name:props.get(key) for name,key in KEYS.items()}
    for name in observed:
        if KEYS[name] in conflicts:
            observed[name]=None
    abi=props.get("ro.product.vendor.cpu.abilist") or props.get("ro.product.cpu.abilist")
    abi_list=abi.split(",") if abi and not set(conflicts)&{
        "ro.product.vendor.cpu.abilist","ro.product.cpu.abilist"} else []
    groups={}
    for name in sorted(GROUPS):
        row=inv["hidl_groups"][name]
        groups[name]={"inventory_complete":row["inventory_complete"],
                      "missing":row["missing"],"elf_review":row["elf_review"]}
    effects=report["files"].get("vendor/lib/libeffectsconfig.so",{})
    effects_status="NOT_SUPPLIED"
    if effects_pin is not None:
        effects_status=("NOT_IN_SELECTED_BASE" if effects.get("status")!="EXTRACTED" else
                        "MATCHES_BASE_MEMBER" if effects.get("sha256")==effects_pin else
                        "DIFFERS_FROM_BASE_MEMBER")
    blockers=list(identity["missing"])+list(identity["problems"])
    if not observed["android_release"] or not observed["sdk"] or not observed["vndk"]:
        blockers.append("Missing Android release, SDK or VNDK")
    if "armeabi-v7a" not in abi_list:
        blockers.append("ARM32 not established by literal ABI list")
    return {"schema":"galwear-r800-base-vendor-candidate-v1",
            "status":"BASE_VENDOR_IDENTITY_FIELDS_OBSERVED_ONLY" if not blockers else "REVIEW_REQUIRED",
            "image_sha256":pin,"observed_identity":observed,"literal_abi_list":abi_list,
            "literal_identity_inventory":identity,"identity_blockers":blockers,
            "hidl_groups":groups,"vintf_status":inv["vintf"]["status"],
            "effects_sha256":effects_pin,"effects_base_comparison":effects_status,
            "missing_or_ambiguous":report["missing_or_ambiguous"],
            "historical_donor_match_verified":False,"donor_authenticity_verified":False,
            "vndk_compatibility_verified":False,"hal_runtime_verified":False,
            "hardware_tested":False,"safe_to_flash":False}


def audit(image,pin,source_sha,*,effects=None,effects_pin=None):
    checkout_sha(source_sha)
    require((effects is None)==(effects_pin is None),"Effects file and SHA-256 must be paired")
    image=Path(image).absolute()
    require(image.resolve(strict=True)==image,"Canonical base vendor path required")
    before=digest(image,MAX_DONOR)
    require(before["sha256"]==pin,"Base vendor pin mismatch")
    if effects is not None:
        effects=Path(effects).absolute()
        require(effects.resolve(strict=True)==effects and digest(effects,MAX_FILE)["sha256"]==effects_pin,
                "Effects pin mismatch")
    with tempfile.TemporaryDirectory(prefix="r800-base-vendor-identity-") as tmp:
        report=extract(image,Path(tmp)/"candidate","vendor-identity",pin)
        result=describe(report,pin,effects_pin)
    require(digest(image,MAX_DONOR)==before,"Base vendor changed during audit")
    if effects is not None:
        require(digest(effects,MAX_FILE)["sha256"]==effects_pin,"Effects changed during audit")
    checkout_sha(source_sha)
    return {**result,"source_sha":source_sha}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image",required=True,type=Path)
    p.add_argument("--image-sha256",required=True)
    p.add_argument("--source-sha",required=True)
    p.add_argument("--effects",type=Path)
    p.add_argument("--effects-sha256")
    a=p.parse_args()
    result=audit(a.image,a.image_sha256,a.source_sha,effects=a.effects,effects_pin=a.effects_sha256)
    print(json.dumps(result,indent=2,sort_keys=True))
    return 2 if result["identity_blockers"] else 0


if __name__=="__main__":
    raise SystemExit(main())
