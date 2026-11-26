#!/usr/bin/env python3
"""Offline Tizen GPS bridge prerequisites; never execute or mount a donor."""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import struct
import re
import xml.etree.ElementTree as ET

from r800_gps_link_gate import elf
from r800_broadcom_export import assess, EXPORT
from r800_android_userspace_preflight import read_regular
from r800_tizen_dependencies import audit, resolve_guest, MAX_FILE

TARGETS = ("/usr/bin/gpsd", "/usr/bin/lhd", "/usr/lib/libbrcm.so")
BRIDGE_LIBRARY = "/usr/lib/libbrcm.so"
BRIDGE_EXPORT = EXPORT
SOCKET = "/opt/usr/r800dev/gps.sock"
LTO = "/opt/gnss/data/lto2.dat"
LAST = "/opt/usr/r800dev/gps.last"
DIRECTORIES = ("/dev", "/proc", "/sys", "/opt/usr/r800dev", "/opt/gnss/data")


def metadata(root, guest):
    """Inspect only type/mode, reject symlinks in runtime paths."""
    path = root
    try:
        for part in guest.strip("/").split("/"):
            path = path / part
            st = path.lstat()
            if stat.S_ISLNK(st.st_mode):
                return {"status":"REJECTED_SYMLINK"}
            if path != root / guest.lstrip("/") and not stat.S_ISDIR(st.st_mode):
                return {"status":"REJECTED_PARENT"}
    except FileNotFoundError:
        return {"status":"MISSING"}
    except OSError as exc:
        return {"status":"REJECTED","reason":str(exc)}
    kind = ("directory" if stat.S_ISDIR(st.st_mode) else
            "regular" if stat.S_ISREG(st.st_mode) else
            "socket" if stat.S_ISSOCK(st.st_mode) else
            "character" if stat.S_ISCHR(st.st_mode) else "other")
    return {"status":"PRESENT","kind":kind,"mode":oct(stat.S_IMODE(st.st_mode))}


CONFIGS=("/etc/lhd/lhd.conf","/etc/gps-manager/brcm/gpsd.xml",
         "/etc/passwd","/etc/group")
CONFIG_LIMIT=1024*1024


def location_account(raw, kind):
    records=[]
    for line in raw.decode("utf-8").splitlines():
        fields=line.split(":")
        if fields[0]!="location":
            continue
        expected=7 if kind=="passwd" else 4
        if len(fields)!=expected:
            raise ValueError("Malformed location account")
        ids=fields[2:4] if kind=="passwd" else fields[2:3]
        if any(not re.fullmatch(r"[1-9][0-9]{0,9}",v) or int(v)>2147483647 for v in ids):
            raise ValueError("Invalid non-root location account ID")
        records.append([int(v) for v in ids])
    if len(records)!=1:
        raise ValueError("Expected unique location account")
    return records[0]


def config_evidence(root):
    files,problems,accounts={},[],{}
    for guest in CONFIGS:
        try:
            if metadata(root,guest).get("kind")!="regular":
                raise ValueError("Missing, nonregular or symlinked configuration")
            path=root/guest.lstrip("/")
            raw=read_regular(path,CONFIG_LIMIT)
            if not raw.strip() or b"\0" in raw:
                raise ValueError("Empty or unsupported configuration")
            if guest.endswith(".xml"):
                # Do not interpret vendor-specific settings or expand entities.
                text=raw.decode("utf-8")
                if "<!DOCTYPE" in text or "<!ENTITY" in text:
                    raise ValueError("XML declaration requires review")
                ET.fromstring(text)
            elif guest.endswith("/passwd"):
                uid,gid=location_account(raw,"passwd")
                accounts.update(uid_candidate=uid,primary_gid_candidate=gid)
            elif guest.endswith("/group"):
                gid,=location_account(raw,"group")
                accounts["chown_group_candidate"]=gid
            files[guest]={"sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw)}
        except (OSError,ValueError,ET.ParseError):
            # No raw configuration lines, account passwords or coordinates.
            problems.append("CONFIGURATION_REVIEW:"+guest)
    return {"files":files,"location_account_candidates":accounts,
            "configuration_semantics_verified":False,
            "effective_account_verified":False,"problems":problems}


def closure_review(closure):
    """Conservative GNSS-only gate over the generic dependency inventory."""
    problems = []
    if closure["problems"]:
        problems.append("DEPENDENCY_CLOSURE_REVIEW")
    for path, item in sorted(closure["files"].items()):
        flags = item["arm_flags"]
        if flags & 0xff000000 != 0x05000000 or flags & 0x400:
            problems.append("DEPENDENCY_ARM_ABI_REVIEW:"+path)
        if not item["has_dynamic"] or item["dynamic_symbol_count"] is None:
            problems.append("DEPENDENCY_SYMBOL_INVENTORY_REVIEW:"+path)
    symbols = closure["symbol_candidates"]
    if symbols["limit_exceeded"]:
        problems.append("DEPENDENCY_SYMBOL_BUDGET_EXCEEDED")
    for target in TARGETS:
        item = symbols["targets"].get(target)
        if item is None:
            problems.append("DEPENDENCY_TARGET_SCOPE_MISSING:"+target)
            continue
        if item["inventory_incomplete"] or item["incomplete"]:
            problems.append("DEPENDENCY_SYMBOL_SCOPE_INCOMPLETE:"+target)
        if item["missing_strong"]:
            problems.append("DEPENDENCY_STRONG_IMPORT_REVIEW:"+target)
        if item["ambiguous"]:
            problems.append("DEPENDENCY_AMBIGUOUS_IMPORT_REVIEW:"+target)
    if closure["relocation_review_objects"]:
        problems.append("DEPENDENCY_RELOCATION_REVIEW")
    # These are only candidate scopes. Runtime dynamic resolution, plugins,
    # exact ABI layout and hardware behavior remain separate.
    return problems


def check(root):
    root = Path(root).resolve(strict=True)
    if not root.is_dir() or root == Path("/"):
        raise ValueError("Expected isolated offline donor directory")
    closure = audit(root, TARGETS)
    problems = closure_review(closure)
    library = {"status":"NOT_VERIFIED"}
    try:
        path, canonical = resolve_guest(root, BRIDGE_LIBRARY)
        raw = read_regular(path, MAX_FILE)
        recorded = closure["files"].get(canonical)
        if recorded is None or hashlib.sha256(raw).hexdigest() != recorded["sha256"]:
            raise ValueError("Bridge library is not bound to audited closure")
        library = assess(raw, elf(raw))
        if library["problems"]:
            problems.append("BRIDGE_EXPORT_NOT_CONFIRMED")
    except (OSError,ValueError,struct.error) as exc:
        library = {"status":"REJECTED","reason":str(exc)}
        problems.append("BRIDGE_LIBRARY_REJECTED")
    config = config_evidence(root)
    problems.extend(config["problems"])
    directories = {p:metadata(root,p) for p in DIRECTORIES}
    for p, item in directories.items():
        if item.get("kind") != "directory":
            problems.append("DIRECTORY_REVIEW:"+p)
    socket = metadata(root, SOCKET)
    if socket["status"] != "MISSING":
        problems.append("SOCKET_PATH_ALREADY_OCCUPIED_OR_UNSAFE")
    # No coordinate, orbit, device or socket content is ever read.
    optional = {p:metadata(root,p) for p in (LTO,LAST)}
    for p,item in optional.items():
        if item["status"] != "MISSING" and item.get("kind") != "regular":
            problems.append("OPTIONAL_FILE_PATH_REVIEW:"+p)
    return {"status":"TIZEN_GNSS_REVIEW_REQUIRED" if problems else "TIZEN_GNSS_STATIC_ONLY",
            "problems":problems,"closure_status":closure["status"],"bridge_library":library,
            "dependency_evidence":closure,"configuration_evidence":config,
            "directories":directories,"socket_path":SOCKET,"socket_metadata":socket,
            "optional_metadata":optional,"runtime_mounts_verified":False,
            "socket_permissions_verified":False,"bridge_protocol_verified":False,
            "hardware_interface_abi_verified":False,"hal_registered":False,
            "gnss_fix_verified":False,"safe_to_flash":False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,required=True)
    args = parser.parse_args()
    report = check(args.root)
    print(json.dumps(report,indent=2,sort_keys=True))
    return 2 if report["problems"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
