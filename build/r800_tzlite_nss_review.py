"""Offline NSS config-to-ELF binding; never load a library or resolve a name."""
import hashlib
from r800_android_linker_audit import inspect
from r800_tzlite_metadata_plan import digest
from r800_tzlite_manifest import read_file
from r800_tizen_dependencies import MAX_FILE, DIRS

FUNCTIONS={
    "passwd":("getpwnam_r","getpwuid_r"),
    "group":("getgrnam_r","getgrgid_r"),
    "hosts":("gethostbyname2_r","gethostbyaddr_r"),
}


def export_review(info,provider,functions):
    issues=[]
    for function in sorted(functions):
        name="_nss_"+provider+"_"+function
        matches=[s for s in info["symbol_exports"] if s["name"]==name and not s["version_hidden"]]
        if len(matches)!=1 or matches[0]["type"]!=2 or matches[0]["weak"]:
            issues.append("NSS_EXPORT_REVIEW:"+name)
    return issues


def check(resolver,configs,plugins):
    result={"schema":"r800-tzlite-nss-review-v1","status":"REVIEW_REQUIRED",
            "configuration_review_sha256":digest(configs),"plugin_audit_sha256":digest(plugins),
            "providers":{},"problems":[],"loader_search_verified":False,
            "nss_abi_verified":False,"nss_runtime_verified":False,"dns_network_verified":False,
            "configuration_semantics_verified":False,"runtime_verified":False,"safe_to_flash":False}
    issues=result["problems"]
    nss=configs["files"]["/etc/nsswitch.conf"]
    if nss["status"]!="STATIC_SYNTAX_CANDIDATE_ONLY" or plugins["problems"]:
        issues.append("NSS_PREREQUISITE_REVIEW")
        return result
    detail=nss["detail"]
    if detail["other_database_count"]:
        issues.append("ADDITIONAL_NSS_DATABASES_UNVERIFIED")
    required={}
    for db,tokens in sorted(detail["basic_database_providers"].items()):
        if db not in FUNCTIONS:
            raise ValueError("Unexpected basic NSS database")
        for provider in tokens:
            if provider not in ("files","dns"):
                raise ValueError("Unexpected NSS provider")
            if provider=="dns" and db!="hosts":
                issues.append("NSS_PROVIDER_DATABASE_REVIEW:"+db+":"+provider)
                continue
            required.setdefault(provider,set()).update(FUNCTIONS[db])
    for provider in detail["provider_candidates"]:
        required.setdefault(provider,set())
    for path in ("/etc/hosts","/etc/resolv.conf"):
        relevant=(path=="/etc/hosts" and "files" in detail["basic_database_providers"]["hosts"]
                  or path=="/etc/resolv.conf" and "dns" in detail["basic_database_providers"]["hosts"])
        if relevant and configs["files"][path]["status"]!="STATIC_SYNTAX_CANDIDATE_ONLY":
            issues.append("NSS_DATA_REVIEW:"+path)
    closure=plugins["dependency_evidence"]
    root=resolver.scratch/"plugin-elf"
    for provider,functions in sorted(required.items()):
        if provider not in ("files","dns"):
            raise ValueError("Unexpected NSS provider candidate")
        soname="libnss_"+provider+".so.2"
        guest="/usr/lib/"+soname
        canonical=closure["aliases"].get(guest)
        item=closure["files"].get(canonical)
        problems=[]
        found={}
        for directory in DIRS:
            try:
                _,actual=resolver.resolve(root,directory+"/"+soname)
                found.setdefault(actual,[]).append(directory+"/"+soname)
            except FileNotFoundError:
                continue
            except (OSError,ValueError):
                problems.append("NSS_SEARCH_PATH_REVIEW:"+directory)
        if set(found)!={canonical} or item is None:
            problems.append("NSS_PROVIDER_MISSING_OR_AMBIGUOUS")
        if item is not None:
            raw=read_file(root/canonical.lstrip("/"),MAX_FILE,capture=True)[1]
            if len(raw)!=item["bytes"] or hashlib.sha256(raw).hexdigest()!=item["sha256"]:
                raise ValueError("NSS provider differs from audited closure")
            info=inspect(raw)
            if (item["soname"]!=soname or info["soname"]!=soname or
                    item["elf_type"]!="ET_DYN" or item["interpreter"] is not None or
                    info["unsupported_symbols"] or info["dynamic_symbol_count"] is None):
                problems.append("NSS_PROVIDER_TYPE_OR_SYMBOL_REVIEW")
            problems.extend(export_review(info,provider,functions))
        if not functions:
            problems.append("NSS_PROVIDER_DATABASE_SCOPE_UNVERIFIED")
        result["providers"][provider]={"status":"REVIEW_REQUIRED" if problems else "STATIC_NSS_PROVIDER_CANDIDATE_ONLY",
            "soname":soname,"canonical":canonical,"sha256":item["sha256"] if item else None,
            "required_export_count":len(functions),"observed_search_candidates":found,
            "problems":sorted(set(problems))}
        issues.extend(provider+":"+p for p in problems)
    result["problems"]=sorted(set(issues))
    if not result["problems"] and required:
        result["status"]="STATIC_NSS_CANDIDATES_ONLY"
    return result
