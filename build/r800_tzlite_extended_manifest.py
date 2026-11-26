"""Non-executable, digest-bound inventory for future extended tzlite staging."""
import re
from pathlib import PurePosixPath

from r800_tzlite_metadata_plan import digest
from r800_tizen_dependencies import MAX_FILE, MAX_TOTAL
from r800_tzlite_legacy_scope import MAX_ENTRIES, CONFIGS
from r800_tzlite_audit import MOUNTPOINTS, REQUIRED_TREES, TARGETS


def valid_path(name):
    return (isinstance(name,str) and re.fullmatch(r"/[A-Za-z0-9_.+@/-]{1,1023}",name)
            and all(p not in ("",".","..") for p in name[1:].split("/")))


def file_record(item,category):
    size=item.get("bytes")
    sha=item.get("sha256")
    if type(size) is not int or not 0<=size<=MAX_FILE or not isinstance(sha,str) or not re.fullmatch(r"[0-9a-f]{64}",sha):
        raise ValueError("Invalid extended manifest file evidence")
    return {"bytes":size,"sha256":sha,"category":category,"disposition":"REVIEW_ONLY"}


def build(image_sha,inventory,plugins):
    if not isinstance(image_sha,str) or not re.fullmatch(r"[0-9a-f]{64}",image_sha):
        raise ValueError("Invalid image digest")
    if (inventory.get("schema")!="r800-tzlite-legacy-image-scope-v1"
            or plugins.get("schema")!="r800-tzlite-extra-plugin-audit-v1"
            or any(r.get("safe_to_flash") is not False for r in (inventory,plugins))):
        raise ValueError("Invalid extended manifest evidence")
    report={"schema":"r800-tzlite-extended-manifest-v1","image_sha256":image_sha,
            "inventory_sha256":digest(inventory),"plugin_audit_sha256":digest(plugins),
            "status":"REVIEW_REQUIRED","files":{},"aliases":{},"directories":[],
            "review_items":sorted(set(inventory["problems"]+plugins["problems"])),
            "files_staged":False,"staging_authorized":False,"configuration_semantics_verified":False,
            "plugin_completeness_verified":False,"runtime_verified":False,"safe_to_flash":False}
    closure=plugins["dependency_evidence"]
    if (plugins["problems"] or closure["problems"]
            or plugins["status"] not in ("STATIC_EXTRA_PLUGIN_CLOSURE_ONLY","NO_ADDITIONAL_ELF_CANDIDATES_REPORTED")):
        report["status"]="BLOCKED_PLUGIN_CLOSURE"
        return report
    files={}
    aliases={}
    dirs=set(MOUNTPOINTS+REQUIRED_TREES)
    for name,item in sorted(closure["files"].items()):
        if not valid_path(name):
            raise ValueError("Invalid closure path")
        files[name]=file_record(item,"AUDITED_ELF")
    for target in TARGETS:
        if closure["aliases"].get(target) not in files:
            raise ValueError("Missing required closure target")
    for name,item in sorted(inventory["entries"].items()):
        if not valid_path(name):
            raise ValueError("Invalid inventory path")
        if item["kind"]=="directory":
            dirs.add(name)
        elif item["kind"]=="regular" and "sha256" in item:
            record=file_record(item,"KNOWN_CONFIG" if name in CONFIGS else "UNREVIEWED_DATA")
            if name in files:
                if any(files[name][k]!=record[k] for k in ("bytes","sha256")):
                    raise ValueError("Inventory and closure file evidence differs")
            elif item.get("elf_candidate"):
                report["review_items"].append("ELF_OUTSIDE_AUDITED_CLOSURE:"+name)
            else:
                files[name]=record
    for name,canonical in sorted(closure["aliases"].items()):
        if not valid_path(name) or canonical not in files or files[canonical]["category"]!="AUDITED_ELF":
            raise ValueError("Invalid audited alias")
        if name!=canonical:
            if name in files or name in dirs:
                raise ValueError("Extended manifest alias collision")
            aliases[name]={"canonical":canonical,"disposition":"REVIEW_ONLY"}
    for name in set(files)|set(aliases)|set(dirs):
        dirs.update(str(p) for p in PurePosixPath(name).parents if str(p)!="/")
    if dirs&(set(files)|set(aliases)):
        raise ValueError("Extended manifest parent collision")
    total=sum(v["bytes"] for v in files.values())
    if total>MAX_TOTAL or len(files)+len(aliases)+len(dirs)>MAX_ENTRIES:
        raise ValueError("Extended manifest aggregate budget exceeded")
    report.update(files=files,aliases=aliases,directories=sorted(dirs),total_bytes=total,
                  review_items=sorted(set(report["review_items"])))
    report["category_counts"]={category:sum(v["category"]==category for v in files.values())
                               for category in ("AUDITED_ELF","KNOWN_CONFIG","UNREVIEWED_DATA")}
    return report
