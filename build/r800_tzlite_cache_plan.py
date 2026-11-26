"""Review-only cache rebuild prerequisites for the extended static subset."""
import re
from collections import defaultdict

from r800_tzlite_cache_review import LD, GCONV
from r800_tzlite_extended_manifest import valid_path
from r800_tzlite_metadata_plan import digest


def plan(image_sha,manifest,cache,plugins):
    if (not re.fullmatch(r"[0-9a-f]{64}",image_sha)
            or manifest.get("schema")!="r800-tzlite-extended-manifest-v1"
            or cache.get("schema")!="r800-tzlite-cache-review-v1"
            or plugins.get("schema")!="r800-tzlite-extra-plugin-audit-v1"
            or manifest.get("image_sha256")!=image_sha
            or any(r.get("safe_to_flash") is not False for r in (manifest,cache,plugins))
            or any(r.get("plugin_audit_sha256")!=digest(plugins) for r in (manifest,cache))):
        raise ValueError("Cache plan evidence binding mismatch")
    report={"schema":"r800-tzlite-cache-plan-v1","image_sha256":image_sha,
            "extended_manifest_sha256":digest(manifest),"cache_review_sha256":digest(cache),
            "plugin_audit_sha256":digest(plugins),"status":"REVIEW_REQUIRED",
            "loader_candidates":[],"excluded_loader_records":[],"gconv_missing_paths":[],
            "problems":[],"original_cache_reuse_authorized":False,
            "cache_generation_authorized":False,"cache_installation_authorized":False,
            "runtime_verified":False,"safe_to_flash":False}
    if manifest["status"]!="REVIEW_REQUIRED" or plugins["problems"]:
        report.update(status="BLOCKED_PLUGIN_CLOSURE",problems=["CACHE_PLAN_CLOSURE_REVIEW"])
        return report
    closure=plugins["dependency_evidence"]
    files={p:v for p,v in manifest["files"].items() if v["category"]=="AUDITED_ELF"}
    if set(files)!=set(closure["files"]) or any(
            any(v[k]!=closure["files"][p][k] for k in ("bytes","sha256")) for p,v in files.items()):
        raise ValueError("Cache plan ELF inventory mismatch")
    aliases=manifest["aliases"]
    expected={p:{"canonical":q,"disposition":"REVIEW_ONLY"} for p,q in closure["aliases"].items() if p!=q}
    if aliases!=expected:
        raise ValueError("Cache plan alias inventory mismatch")
    def match(record):
        path=record["path"]
        if not valid_path(path):
            raise ValueError("Unsafe cache plan path")
        canonical=aliases.get(path,{}).get("canonical",path)
        if canonical not in files:
            if record["status"]!="NOT_IN_AUDITED_SUBSET":
                raise ValueError("Cache path classification mismatch")
            return None
        if record.get("canonical")!=canonical or record.get("sha256")!=files[canonical]["sha256"]:
            raise ValueError("Cache record hash or canonical mismatch")
        return canonical
    ld=cache["files"][LD]
    candidates=defaultdict(list)
    if ld["status"]=="STATIC_TABLE_INVENTORY_ONLY":
        for record in ld["records"]:
            canonical=match(record)
            if canonical is None:
                reason="PATH_ABSENT"
            elif record["status"]!="AUDITED_PATH_CANDIDATE" or closure["files"][canonical]["soname"]!=record["name"]:
                reason="SONAME_REVIEW"
            elif record["hwcap"]!=0 or record["osversion"]!=0:
                reason="LOADER_SELECTION_REVIEW"
            else:
                candidates[record["name"]].append(record)
                continue
            report["excluded_loader_records"].append({"name":record["name"],"path":record["path"],"reason":reason})
        for name,records in sorted(candidates.items()):
            if len(records)!=1:
                report["excluded_loader_records"].extend(
                    {"name":name,"path":r["path"],"reason":"DUPLICATE_SONAME_REVIEW"} for r in records)
                continue
            r=records[0]
            report["loader_candidates"].append({"name":name,"path":r["path"],"sha256":r["sha256"],
                "original_flags":r["flags"],"disposition":"REVIEW_ONLY"})
    else:
        report["problems"].append("LOADER_CACHE_FORMAT_OR_INPUT_REVIEW")
    gconv=cache["files"][GCONV]
    if gconv["status"]=="STATIC_TABLE_INVENTORY_ONLY":
        for r in gconv["records"]:
            if match(r) is None:
                report["gconv_missing_paths"].append(r["path"])
        report["gconv_missing_paths"]=sorted(set(report["gconv_missing_paths"]))
    else:
        report["problems"].append("GCONV_CACHE_FORMAT_OR_INPUT_REVIEW")
    report["loader_sonames_without_candidate"]=sorted(
        {v["soname"] for v in closure["files"].values() if v["soname"]}
        -{r["name"] for r in report["loader_candidates"]})
    report["excluded_loader_records"].sort(key=lambda r:(r["name"],r["path"],r["reason"]))
    report["actions"]=[
        {"path":LD,"decision":"OMIT_ORIGINAL_REVIEW_REBUILD","prerequisites":[
            "Verify target loader ABI, cache flags and search order",
            "Resolve missing and conflicting SONAME records",
            "Validate target-compatible cache generation in isolation"]},
        {"path":GCONV,"decision":"OMIT_ORIGINAL_REVIEW_REBUILD","prerequisites":[
            "Inventory gconv-modules text and required encodings",
            "Audit required conversion module ELF dependencies",
            "Verify target-compatible hash lookup and conversion chains"]}]
    return report
