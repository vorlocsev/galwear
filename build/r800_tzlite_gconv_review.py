"""Review the fixed glibc gconv text configuration and its declared ELF modules."""
import hashlib
import re
import struct

from r800_extract_ext4 import command
from r800_tzlite_image_xattrs import check_diagnostics
from r800_tzlite_image_metadata import parse_inode
from r800_tzlite_manifest import read_file
from r800_tzlite_metadata_plan import digest
from r800_tizen_dependencies import audit, MAX_FILE, MAX_NODES
from r800_tzlite_audit import TARGETS, closure_problems
from r800_android_linker_audit import inspect

CONFIG="/usr/lib/gconv/gconv-modules"
PREFIX="/usr/lib/gconv/"
LIMIT=1024*1024
MAX_LINES=4096
MAX_MODULES=64
CHARSET=re.compile(r"[A-Za-z0-9_.+:-]{1,100}(?://)?")
MODULE=re.compile(r"[A-Za-z0-9_+-][A-Za-z0-9_.+-]{0,126}")


def parse(raw):
    if not 0<len(raw)<=LIMIT:
        raise ValueError("Gconv text size review")
    value=raw.decode("ascii")
    if any(ord(c)<32 and c not in "\n\r\t" or ord(c)==127 for c in value):
        raise ValueError("Gconv text control character")
    lines=value.splitlines()
    if len(lines)>MAX_LINES or any(len(s)>4096 for s in lines):
        raise ValueError("Gconv text line budget")
    aliases={}
    modules={}
    for line in lines:
        fields=line.split("#",1)[0].split()
        if not fields:
            continue
        if fields[0]=="alias" and len(fields)==3:
            a,b=fields[1:]
            if not CHARSET.fullmatch(a) or not CHARSET.fullmatch(b) or a.upper() in aliases:
                raise ValueError("Unsupported or duplicate gconv alias")
            aliases[a.upper()]=b.upper()
        elif fields[0]=="module" and len(fields) in (4,5):
            a,b,name=fields[1:4]
            if not CHARSET.fullmatch(a) or not CHARSET.fullmatch(b) or not MODULE.fullmatch(name):
                raise ValueError("Unsupported gconv module declaration")
            if name in (".",".."):
                raise ValueError("Unsafe gconv module name")
            cost=fields[4] if len(fields)==5 else "1"
            if not re.fullmatch(r"[1-9][0-9]{0,4}",cost):
                raise ValueError("Unsupported gconv cost")
            path=PREFIX+(name if name.endswith(".so") else name+".so")
            key=(a.upper(),b.upper())
            if key in modules:
                raise ValueError("Duplicate gconv conversion")
            modules[key]={"from":key[0],"to":key[1],"path":path,"cost":int(cost)}
        else:
            raise ValueError("Unsupported gconv directive")
    if not modules:
        raise ValueError("No gconv module declarations")
    # Check alias cycles without expanding or executing any conversion.
    for start in aliases:
        seen=set()
        name=start
        while name in aliases:
            if name in seen or len(seen)>=64:
                raise ValueError("Gconv alias cycle or depth review")
            seen.add(name)
            name=aliases[name]
    return {"alias_count":len(aliases),"aliases":aliases,"conversions":list(modules.values()),
            "module_paths":sorted({m["path"] for m in modules.values()})}


def read_config(resolver):
    for parent in ("/usr","/usr/lib","/usr/lib/gconv"):
        entry=resolver.stat_guest(parent)
        if entry is None or entry[1]!="directory":
            return None
    item=resolver.stat_guest(CONFIG)
    if item is None or item[1]!="regular" or not 0<item[2]<=LIMIT:
        return None
    inode,kind,size,_=item
    info=command(resolver.tool,resolver.snapshot,"stat <%d>"%inode)
    check_diagnostics(info.stderr)
    if parse_inode(info.stdout,inode,kind)["links"]!=1:
        return None
    member=resolver.scratch/"gconv-config-member"
    if member.exists() or member.is_symlink():
        raise ValueError("Unexpected private gconv member")
    try:
        reply=command(resolver.tool,resolver.snapshot,"dump <%d> gconv-config-member"%inode,cwd=resolver.scratch)
        check_diagnostics(reply.stderr)
        raw=read_file(member,LIMIT,capture=True)[1]
        if len(raw)!=size:
            raise ValueError("Gconv configuration size mismatch")
        return raw
    finally:
        member.unlink(missing_ok=True)


def check(resolver,plugins):
    result={"schema":"r800-tzlite-gconv-review-v1","status":"REVIEW_REQUIRED",
            "plugin_audit_sha256":digest(plugins),"configuration":None,"modules":{},
            "problems":[],"configuration_semantics_verified":False,
            "conversion_abi_verified":False,"conversion_runtime_verified":False,
            "staging_authorized":False,"cache_generation_authorized":False,
            "runtime_verified":False,"safe_to_flash":False}
    issues=result["problems"]
    if plugins["problems"]:
        issues.append("GCONV_BASELINE_CLOSURE_REVIEW")
        return result
    raw=read_config(resolver)
    if raw is None:
        issues.append("GCONV_CONFIG_REGULAR_INPUT_REQUIRED")
        return result
    result["configuration"]={"sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw)}
    try:
        parsed=parse(raw)
    except ValueError:
        issues.append("GCONV_CONFIG_SYNTAX_REVIEW")
        return result
    result["configuration"].update(parsed)
    paths=parsed["module_paths"]
    targets=tuple(dict.fromkeys(TARGETS+tuple(plugins["candidates"])+tuple(paths)))
    if len(paths)>MAX_MODULES or len(targets)>MAX_NODES:
        issues.append("GCONV_MODULE_BUDGET_REVIEW")
        return result
    root=resolver.scratch/"plugin-elf"
    closure=audit(root,targets,resolver=resolver.resolve)
    result["dependency_evidence"]=closure
    issues.extend(closure_problems(closure))
    for name,item in plugins["dependency_evidence"]["files"].items():
        if closure["files"].get(name)!=item:
            issues.append("GCONV_BASELINE_FILE_CHANGED:"+name)
    for name in paths:
        problems=[]
        canonical=closure["aliases"].get(name)
        obj=closure["files"].get(canonical)
        scope=closure["symbol_candidates"]["targets"].get(name)
        if obj is None or obj["elf_type"]!="ET_DYN" or obj["interpreter"] is not None:
            problems.append("GCONV_MODULE_TYPE_REVIEW")
        else:
            data=read_file(root/canonical.lstrip("/"),MAX_FILE,capture=True)[1]
            sha=hashlib.sha256(data).hexdigest()
            if len(data)!=obj["bytes"] or sha!=obj["sha256"] or resolver.files.get(canonical,{}).get("sha256")!=sha:
                raise ValueError("Gconv ELF hash mismatch")
            try:
                info=inspect(data)
                exports=[s for s in info["symbol_exports"] if s["name"]=="gconv" and not s["version_hidden"]]
                if len(exports)!=1 or exports[0]["type"]!=2 or exports[0]["weak"] or info["unsupported_symbols"]:
                    problems.append("GCONV_EXPORT_REVIEW")
            except (ValueError,struct.error):
                problems.append("GCONV_EXPORT_INVENTORY_REVIEW")
        if scope is None or any(scope.get(k) for k in ("inventory_incomplete","incomplete","missing_strong","ambiguous")):
            problems.append("GCONV_SYMBOL_SCOPE_REVIEW")
        if canonical in closure["relocation_review_objects"]:
            problems.append("GCONV_RELOCATION_REVIEW")
        result["modules"][name]={"canonical":canonical,"sha256":obj["sha256"] if obj else None,
            "status":"REVIEW_REQUIRED" if problems else "STATIC_GCONV_MODULE_CANDIDATE_ONLY",
            "problems":problems}
        issues.extend(p+":"+name for p in problems)
    result["problems"]=sorted(set(issues))
    if not result["problems"]:
        result["status"]="STATIC_GCONV_CANDIDATES_ONLY"
    return result
