"""Compare text declarations, cached external conversion references and audited ELF."""
from r800_tzlite_cache_review import GCONV
from r800_tzlite_metadata_plan import digest
from r800_tzlite_extended_manifest import valid_path


def compare(image_sha,plugins,cache,gconv):
    if (len(image_sha)!=64 or any(c not in "0123456789abcdef" for c in image_sha)
            or plugins.get("schema")!="r800-tzlite-extra-plugin-audit-v1"
            or cache.get("schema")!="r800-tzlite-cache-review-v1"
            or gconv.get("schema")!="r800-tzlite-gconv-review-v1"
            or any(r.get("safe_to_flash") is not False for r in (plugins,cache,gconv))
            or any(r.get("plugin_audit_sha256")!=digest(plugins) for r in (cache,gconv))):
        raise ValueError("Gconv consistency evidence binding mismatch")
    result={"schema":"r800-tzlite-gconv-consistency-v1","image_sha256":image_sha,
            "plugin_audit_sha256":digest(plugins),"cache_review_sha256":digest(cache),
            "gconv_review_sha256":digest(gconv),"status":"REVIEW_REQUIRED",
            "matched":[],"text_only":[],"cache_only":[],"unverified_modules":[],
            "problems":[],"hash_lookup_verified":False,"conversion_selection_verified":False,
            "conversion_abi_verified":False,"staging_authorized":False,
            "cache_generation_authorized":False,"runtime_verified":False,"safe_to_flash":False}
    record=cache["files"][GCONV]
    if (plugins["problems"] or gconv["status"]!="STATIC_GCONV_CANDIDATES_ONLY"
            or gconv["problems"] or record["status"]!="STATIC_TABLE_INVENTORY_ONLY"):
        result["problems"].append("GCONV_CONSISTENCY_PREREQUISITE_REVIEW")
        return result
    configuration=gconv["configuration"]
    aliases=configuration["aliases"]
    def canonical(value):
        name=value.upper()
        seen=set()
        while name in aliases:
            if name in seen or len(seen)>=64:
                raise ValueError("Gconv alias cycle or depth review")
            seen.add(name)
            name=aliases[name]
        return name
    def key(r):
        path=r["path"]
        if not valid_path(path):
            raise ValueError("Unsafe gconv reference path")
        return (canonical(r["from"]),canonical(r["to"]),path)
    text={key(r) for r in configuration["conversions"]}
    cached={key(r) for r in record["conversion_references"]}
    if len(text)!=len(configuration["conversions"]):
        result["problems"].append("GCONV_NORMALIZED_DECLARATION_COLLISION")
    text_paths={r[2] for r in text}
    cache_paths={r[2] for r in cached}
    if text_paths!=set(configuration["module_paths"]) or cache_paths!=set(record["module_paths"]):
        raise ValueError("Gconv path inventory differs from conversion references")
    closure=gconv["dependency_evidence"]
    for path in sorted(text_paths|cache_paths):
        item=gconv["modules"].get(path)
        canon=closure["aliases"].get(path)
        obj=closure["files"].get(canon)
        if (not item or not obj or item.get("status")!="STATIC_GCONV_MODULE_CANDIDATE_ONLY"
                or item.get("problems") or item.get("canonical")!=canon
                or item.get("sha256")!=obj.get("sha256")):
            result["unverified_modules"].append(path)
    def records(items):
        return [{"from":a,"to":b,"path":p} for a,b,p in sorted(items)]
    result["matched"]=records(text&cached)
    result["text_only"]=records(text-cached)
    result["cache_only"]=records(cached-text)
    for field,problem in (("text_only","GCONV_TEXT_ONLY_REFERENCES"),
                          ("cache_only","GCONV_CACHE_ONLY_REFERENCES"),
                          ("unverified_modules","GCONV_MODULE_EVIDENCE_REVIEW")):
        if result[field]:
            result["problems"].append(problem)
    if not result["problems"] and text:
        result["status"]="STATIC_EXTERNAL_REFERENCE_MATCH_ONLY"
    return result
