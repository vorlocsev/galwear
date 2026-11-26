"""Audit discovered sensor ELF candidates in the same verified image snapshot."""
import hashlib
from r800_tizen_dependencies import audit, MAX_NODES
from r800_tzlite_audit import TARGETS, closure_problems

PREFIX="/usr/lib/sensor/"
MAX_EXTRA=64


def check(resolver,inventory):
    entries=inventory["entries"]
    candidates=sorted(name for name in inventory["elf_candidates"] if name.startswith(PREFIX))
    if len(candidates)>MAX_EXTRA or len(set(TARGETS+tuple(candidates)))>MAX_NODES:
        raise ValueError("Additional plugin target budget exceeded")
    problems=[]
    for name in candidates:
        record=entries[name]
        if record.get("kind")!="regular" or record.get("links")!=1 or not record.get("elf_candidate"):
            raise ValueError("Plugin target is not an inventoried regular ELF")
    root=resolver.scratch/"plugin-elf"
    root.mkdir()
    targets=tuple(dict.fromkeys(TARGETS+tuple(candidates)))
    closure=audit(root,targets,resolver=resolver.resolve)
    problems.extend(closure_problems(closure))
    records={}
    for name in candidates:
        issues=[]
        canonical=closure["aliases"].get(name)
        obj=closure["files"].get(canonical)
        scope=closure["symbol_candidates"]["targets"].get(name)
        expected=entries[name]
        if (canonical!=name or obj is None or obj.get("sha256")!=expected["sha256"]
                or obj.get("bytes")!=expected["bytes"]):
            issues.append("INVENTORY_HASH_OR_PATH_MISMATCH")
        if obj is None or obj.get("elf_type")!="ET_DYN" or obj.get("interpreter") is not None:
            issues.append("PLUGIN_TYPE_REVIEW")
        if obj is None or not obj.get("has_dynamic") or obj.get("dynamic_symbol_count") is None:
            issues.append("PLUGIN_DYNAMIC_INVENTORY_REVIEW")
        if scope is None or any(scope.get(k) for k in
                ("inventory_incomplete","incomplete","missing_strong","ambiguous")):
            issues.append("PLUGIN_SYMBOL_SCOPE_REVIEW")
        if any(p.get("path")==name for p in closure["problems"]):
            issues.append("PLUGIN_DEPENDENCY_REVIEW")
        if canonical in closure["relocation_review_objects"]:
            issues.append("PLUGIN_RELOCATION_REVIEW")
        problems.extend(issue+":"+name for issue in issues)
        records[name]={"status":"REVIEW_REQUIRED" if issues else "STATIC_PLUGIN_CANDIDATE_ONLY",
                       "sha256":expected["sha256"],"canonical":canonical,"problems":issues}
    for name,item in closure["files"].items():
        raw=(root/name.lstrip("/")).read_bytes()
        if (len(raw)!=item["bytes"] or hashlib.sha256(raw).hexdigest()!=item["sha256"]
                or resolver.files.get(name,{}).get("sha256")!=item["sha256"]):
            raise ValueError("Extracted plugin dependency changed:"+name)
    status=("REVIEW_REQUIRED" if problems else "STATIC_EXTRA_PLUGIN_CLOSURE_ONLY"
            if candidates else "NO_ADDITIONAL_ELF_CANDIDATES_REPORTED")
    return {"schema":"r800-tzlite-extra-plugin-audit-v1","status":status,
            "problems":sorted(set(problems)),"candidate_count":len(candidates),
            "candidates":records,"dependency_evidence":closure,
            "scope_review_problems":inventory["problems"],
            "plugin_completeness_verified":False,"dlopen_verified":False,
            "runtime_verified":False,"safe_to_flash":False}
