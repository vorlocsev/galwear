#!/usr/bin/env python3
"""Compare literal Pixel Vendor manifests and System matrices, not checkvintf."""
import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
import xml.etree.ElementTree as ET

from r800_extract_ext4 import snapshot_image
from r800_framework_inventory import ext4_member
from r800_pixel_runtime_layout import list_directory
from r800_donor_preflight import digest
from r800_graphics_donor_binding import checkout_sha

MAX_XML=1024*1024
MAX_FILES=64
MAX_PARTITION=4*1024**3
NAME=re.compile(r"[A-Za-z0-9_.-]{1,255}")
GROUPS=("audio","audio.effect","bluetooth","gnss","graphics.allocator",
        "graphics.composer","graphics.mapper","light","lights","sensors","wifi",
        "wifi.supplicant","power","health","vibrator")


def parse(raw, expected):
    if not 0<len(raw)<=MAX_XML:
        raise ValueError("VINTF XML size outside budget")
    text=raw.decode("utf-8-sig")
    if "<!" in text or "\0" in text:
        # Ordinary XML comments are permitted, but not DTD/entity declarations.
        if "\0" in text or "<!" in re.sub(r"<!--[\s\S]*?-->","",text):
            raise ValueError("Unsupported XML declaration")
    root=ET.fromstring(text)
    if root.tag != expected or root.get("type") not in ("device","framework"):
        raise ValueError("Unexpected VINTF document type")
    if len(root)>4096:
        raise ValueError("VINTF element budget exceeded")
    rows=[]
    for hal in root.findall("hal"):
        name=(hal.findtext("name") or "").strip()
        if not NAME.fullmatch(name):
            raise ValueError("Invalid HAL package name")
        if not any(name=="android.hardware."+group for group in GROUPS):
            continue
        versions=[(v.text or "").strip() for v in hal.findall("version")]
        interfaces=[]
        for iface in hal.findall("interface"):
            interfaces.append({"name":(iface.findtext("name") or "").strip(),
                               "instances":[(x.text or "").strip() for x in iface.findall("instance")],
                               "regex_instances":[(x.text or "").strip() for x in iface.findall("regex-instance")]})
        rows.append({"name":name,"format":hal.get("format","hidl"),
                     "optional":hal.get("optional"),"override":hal.get("override"),
                     "transport":hal.findtext("transport"),"versions":versions,
                     "fqnames":[(x.text or "").strip() for x in hal.findall("fqname")],
                     "interfaces":interfaces})
    return {"type":root.get("type"),"level":root.get("level"),
            "target_level":root.get("target-level"),"hals":rows}


def collect(tool,image,scratch,dirs,pattern,kind):
    rows={}
    for directory in dirs:
        listing=list_directory(tool,image,directory)
        if listing["status"]!="DIRECTORY_OBSERVED":
            continue
        for name,entry in sorted(listing["entries"].items()):
            if not pattern.fullmatch(name):
                continue
            path=directory+"/"+name
            if len(rows)>=MAX_FILES:
                raise ValueError("VINTF file count exceeded")
            if entry["type"]!="regular":
                rows[path]={"status":"REVIEW_REQUIRED","reason":"Nonregular XML"}
                continue
            try:
                raw=ext4_member(tool,image,path,MAX_XML,scratch)
                rows[path]={"status":"OBSERVED","sha256":hashlib.sha256(raw).hexdigest(),
                            **parse(raw,kind)}
            except (OSError,ValueError,TypeError,ET.ParseError,subprocess.SubprocessError) as exc:
                rows[path]={"status":"REVIEW_REQUIRED","reason":str(exc)}
    return rows


def audit(system,system_pin,vendor,vendor_pin,source):
    checkout_sha(source)
    tool=shutil.which("debugfs")
    if not tool:
        raise ValueError("debugfs required")
    with tempfile.TemporaryDirectory(prefix="r800-pixel-vintf-") as tmp:
        scratch=Path(tmp)
        s,v=scratch/"system.img",scratch/"vendor.img"
        snapshot_image(system,s,system_pin)
        snapshot_image(vendor,v,vendor_pin)
        manifests=collect(tool,v,scratch,("/etc/vintf",),re.compile(r"manifest\.xml"),"manifest")
        manifests.update(collect(tool,v,scratch,("/etc/vintf/manifest",),re.compile(r"[A-Za-z0-9_.@+-]+\.xml"),"manifest"))
        matrices=collect(tool,s,scratch,("/system/etc/vintf","/etc/vintf"),
                         re.compile(r"compatibility_matrix(?:\.[A-Za-z0-9_.-]+)?\.xml"),"compatibility-matrix")
        for path,pin in ((s,system_pin),(v,vendor_pin),(system,system_pin),(vendor,vendor_pin)):
            if digest(path,MAX_PARTITION)["sha256"]!=pin:
                raise ValueError("VINTF input changed")
    checkout_sha(source)
    groups={}
    for group in GROUPS:
        name="android.hardware."+group
        groups[group]={key:[{"path":path,**hal} for path,row in docs.items()
                             for hal in row.get("hals",[]) if hal["name"]==name]
                       for key,docs in (("vendor_declarations",manifests),("system_matrix_entries",matrices))}
    return {"schema":"galwear-r800-pixel-vintf-contract-v1","source_sha":source,
            "system_sha256":system_pin,"vendor_sha256":vendor_pin,
            "status":"LITERAL_VINTF_CONTRACT_OBSERVATIONS_ONLY",
            "vendor_manifests":manifests,"system_matrices":matrices,"groups":groups,
            "checkvintf_executed":False,"r800_service_registration_verified":False,
            "r800_vendor_compatibility_verified":False,"hardware_tested":False,"safe_to_flash":False}
