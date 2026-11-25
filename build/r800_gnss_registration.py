#!/usr/bin/env python3
"""Static GNSS registration contract for a clean, offline Android tree."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from r800_android_userspace_preflight import guest_path, read_regular
from r800_android_linker_audit import inspect
from r800_vintf_inventory import audit as vintf_audit
from r800_init_inventory import audit as init_audit

NAME = "android.hardware.gnss"
FQ = NAME + "@1.0::IGnss"
SERVICE = "/vendor/bin/hw/" + NAME + "@1.0-service"
IMPL = "/vendor/lib/hw/" + NAME + "@1.0-impl.so"
MODULE = "/vendor/lib/hw/gps.r800.so"
HIDL = NAME + "@1.0.so"
LIMIT = 64 * 1024**2


def registration_problems(vintf, init):
    issues = []
    declarations = [e for d in vintf["files"].values()
                    if d["kind"] == "manifest" and d["type"] == "device"
                    for e in d["entries"] if e["name"] == NAME]
    if len(declarations) != 1 or not any(
        e["format"] == "hidl" and e["interface"] == "IGnss"
        and e["instance"] == "default" and e["version"] == [1,0,0]
        and e["transport"] == "hwbinder" for e in declarations):
        issues.append("Expected unique HIDL 1.0 IGnss/default hwbinder declaration")
    if any("override" in r.lower() and NAME in r for d in vintf["files"].values()
           for r in d["review"]):
        issues.append("GNSS manifest override requires merge review")
    services = [s for s in init["gnss_services"] if s["executable"] == SERVICE]
    if len(services) != 1:
        issues.append("Expected unique GNSS 1.0 init service")
    else:
        s = services[0]
        opts = s["options"]
        interfaces = [o["args"] for o in opts if o["name"] == "interface"]
        if interfaces and [FQ,"default"] not in interfaces:
            issues.append("GNSS init interface differs from manifest")
        if any(o["name"] == "disabled" for o in opts) and [FQ,"default"] not in interfaces:
            issues.append("Disabled GNSS service has no matching lazy interface")
        if any(d["name"] == s["name"] for d in init["duplicate_services"]):
            issues.append("Duplicate GNSS init service")
        if any(x["executable"] != SERVICE for x in init["gnss_services"]):
            issues.append("Additional GNSS init service requires review")
    if vintf["errors"] or init["errors"] or init["unresolved_imports"]:
        issues.append("VINTF or init inventory incomplete")
    return issues


def properties(root):
    keys = {"ro.hardware", "ro.hardware.gps", "ro.hardware.gnss",
            "ro.board.platform", "ro.product.board"}
    records = {}
    for name in ("/default.prop", "/prop.default", "/system/etc/prop.default",
                 "/system/build.prop", "/vendor/default.prop", "/vendor/build.prop",
                 "/odm/build.prop", "/product/build.prop", "/system_ext/build.prop"):
        try:
            raw = read_regular(guest_path(root, name), 1024*1024)
        except FileNotFoundError:
            continue
        for line in raw.decode("utf-8").splitlines():
            key, sep, value = line.strip().partition("=")
            if sep and key in keys:
                records.setdefault(key, []).append({"source":name,"value":value.strip()})
    return records


def property_problems(records):
    # Static candidates only: Android property imports and bootconfig may
    # alter the effective value. Do not infer selection from board name.
    hw = records.get("ro.hardware", [])
    gps = records.get("ro.hardware.gps", [])
    if not hw and not gps:
        return ["GPS hardware selector not present in inspected properties"]
    selected = gps or hw
    if {r["value"] for r in selected} != {"r800"}:
        return ["GPS hardware selector not uniquely r800"]
    return []


def binary(root, name, module=False, service=False):
    raw = read_regular(guest_path(root,name), LIMIT)
    obj = inspect(raw)
    flags, = struct.unpack_from("<I",raw,36)
    if (obj["abi"] != "arm" or flags & 0xff000000 != 0x05000000
            or flags & 0x400 or not obj["has_dynamic"]):
        raise ValueError("Expected ARM32 EABI5 dynamic ELF")
    if not service and obj["elf_type"] != "ET_DYN":
        raise ValueError("Expected shared object")
    if obj["custom_search_path"]:
        raise ValueError("Custom library search path requires review")
    if obj["dynamic_symbol_count"] is None or obj["unsupported_symbols"]:
        raise ValueError("Incomplete symbol evidence")
    if module:
        exports = [s for s in obj["symbol_exports"] if s["name"]=="HMI"
                   and s["type"]==1 and s["binding"]==1 and s["visibility"]==0]
        if not exports:
            raise ValueError("Missing exported HMI object")
    if service and HIDL not in obj["needed"]:
        raise ValueError("GNSS 1.0 interface library not a direct dependency")
    if any(n.startswith(("libc.so.6","libpthread.so.0","libdl.so.2"))
           for n in obj["needed"]):
        raise ValueError("Tizen glibc dependency in Android component")
    return {"sha256":hashlib.sha256(raw).hexdigest(),"abi":obj["abi"],
            "needed":obj["needed"],"hmi_checked":module}


def audit(root):
    root=root.resolve(strict=True)
    issues=registration_problems(vintf_audit(root),init_audit(root))
    records=properties(root)
    issues.extend(property_problems(records))
    binaries={}
    for name in (SERVICE,IMPL,MODULE,"/vendor/lib/"+HIDL):
        try:
            binaries[name]=binary(root,name,module=name==MODULE,service=name==SERVICE)
        except (OSError,ValueError) as exc:
            issues.append(name+": "+str(exc))
    return {"status":"REVIEW_REQUIRED" if issues else "STATIC_GNSS_CONTRACT_ONLY",
            "problems":issues,"property_candidates":records,"binaries":binaries,
            "effective_properties_verified":False,"manifest_merge_verified":False,
            "linker_namespace_verified":False,"selinux_access_verified":False,
            "socket_mapping_verified":False,"hal_registered":False,
            "location_service_verified":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,required=True)
    a=p.parse_args()
    try:
        report=audit(a.root)
    except (OSError,ValueError) as exc:
        report={"status":"REVIEW_REQUIRED","problems":[str(exc)],"safe_to_flash":False}
    print(json.dumps(report,indent=2,sort_keys=True))
    return 2 if report["problems"] else 0


if __name__=="__main__":
    raise SystemExit(main())
