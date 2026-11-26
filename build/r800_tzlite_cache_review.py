"""Bounded glibc 2.24 cache inventory; no cache installation or loader execution."""
import hashlib
import re
import struct

from r800_extract_ext4 import command
from r800_tzlite_image_xattrs import check_diagnostics
from r800_tzlite_manifest import read_file
from r800_tzlite_metadata_plan import digest
from r800_tzlite_extended_manifest import valid_path

LD="/etc/ld.so.cache"
GCONV="/usr/lib/gconv/gconv-modules.cache"
OLD=b"ld.so-1.7.0"
NEW=b"glibc-ld.so.cache1.1"
LIMIT=4*1024*1024
MAX_ROWS=4096


def string(raw,offset,start,end):
    if not start<=offset<end:
        raise ValueError("Cache string offset outside table")
    stop=raw.find(b"\0",offset,min(end,offset+1024))
    if stop<0:
        raise ValueError("Unterminated or oversized cache string")
    return raw[offset:stop].decode("ascii")


def parse_ld(raw):
    if not 0<len(raw)<=LIMIT:
        raise ValueError("Loader cache size review")
    base=0
    old_count=None
    if raw.startswith(OLD):
        if len(raw)<16:
            raise ValueError("Truncated legacy cache")
        old_count=struct.unpack_from("<I",raw,12)[0]
        if old_count>MAX_ROWS or 16+12*old_count>len(raw):
            raise ValueError("Legacy cache count review")
        old_end=16+12*old_count
        base=(old_end+7)&~7
    if raw[base:base+len(NEW)]==NEW:
        if base+48>len(raw):
            raise ValueError("Truncated new cache")
        count,length=struct.unpack_from("<II",raw,base+20)
        start=base+48+24*count
        end=start+length
        if count>MAX_ROWS or end>len(raw) or any(raw[base+28:base+48]):
            raise ValueError("Unsupported new cache layout")
        rows=[]
        for i in range(count):
            flags,key,value,osversion,hwcap=struct.unpack_from("<iIIIQ",raw,base+48+24*i)
            rows.append((string(raw,base+key,start,end),string(raw,base+value,start,end),
                         flags,osversion,hwcap))
        fmt="GLIBC_2_24_COMPAT_NEW" if old_count is not None else "GLIBC_2_24_NEW"
    elif old_count is not None:
        start=16+12*old_count
        rows=[]
        for i in range(old_count):
            flags,key,value=struct.unpack_from("<iII",raw,16+12*i)
            rows.append((string(raw,start+key,start,len(raw)),string(raw,start+value,start,len(raw)),
                         flags,None,None))
        fmt="LEGACY_ONLY"
    else:
        raise ValueError("Unrecognized loader cache")
    for name,path,*_ in rows:
        if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,255}",name) or not valid_path(path):
            raise ValueError("Unsupported loader cache name or path")
    return fmt,rows


def parse_gconv(raw):
    if not 16<=len(raw)<=LIMIT:
        raise ValueError("Gconv cache size review")
    magic,strings,hashes,slots,modules,extra=struct.unpack_from("<I5H",raw)
    if (magic!=0x20010324 or not 16<=strings<hashes<modules<extra<=len(raw)
            or not 3<=slots<=MAX_ROWS or hashes+4*slots!=modules
            or (extra-modules)%12 or (extra-modules)//12>MAX_ROWS):
        raise ValueError("Unsupported gconv table layout")
    count=(extra-modules)//12
    def get(offset):
        return string(raw,strings+offset,strings,hashes)
    for i in range(slots):
        offset,index=struct.unpack_from("<HH",raw,hashes+4*i)
        if offset:
            if not get(offset) or index>=count:
                raise ValueError("Invalid gconv hash reference")
    names=[get(struct.unpack_from("<H",raw,modules+12*i)[0]) for i in range(count)]
    references=[]
    paths=set()
    extra_paths=set()
    builtin=0
    offsets={}
    def reference(directory,name,*,required=False):
        nonlocal builtin
        d,n=get(directory),get(name)
        if not d:
            if n:
                builtin+=1
            elif required:
                raise ValueError("Empty gconv conversion step")
            return None
        path=d+n
        if not d.endswith("/") or not re.fullmatch(r"[A-Za-z0-9_.+-]{1,255}\.so",n) or not valid_path(path):
            raise ValueError("Unsupported gconv module path")
        paths.add(path)
        return path

    for i in range(count):
        canon,fd,fn,td,tn,other=struct.unpack_from("<6H",raw,modules+12*i)
        if not get(canon):
            raise ValueError("Empty gconv canonical name")
        for source,destination,directory,name in (("INTERNAL",names[i],fd,fn),
                                                    (names[i],"INTERNAL",td,tn)):
            path=reference(directory,name)
            if path is not None:
                references.append({"from":source,"to":destination,"path":path,"scope":"PRIMARY"})
        if other:
            start=extra+other-1
            if start%2 or start+2>len(raw) or start in offsets:
                raise ValueError("Invalid or duplicate gconv extra conversion offset")
            offsets[start]=i

    # glibc 2.24 iconvconfig writes contiguous zero-terminated lists,
    # with one-based byte offsets; outname_offset is a module index.
    cursor=extra
    chain_count=step_count=0
    for start,source in sorted(offsets.items()):
        if start!=cursor:
            raise ValueError("Gconv extra list gap or overlap")
        destinations=set()
        while True:
            if cursor+2>len(raw):
                raise ValueError("Unterminated gconv extra list")
            steps,=struct.unpack_from("<H",raw,cursor)
            cursor+=2
            if not steps:
                if not destinations:
                    raise ValueError("Empty gconv extra list")
                break
            chain_count+=1
            step_count+=steps
            if chain_count>MAX_ROWS or step_count>MAX_ROWS or cursor+6*steps>len(raw):
                raise ValueError("Gconv extra chain budget or bounds")
            current=source
            for _ in range(steps):
                dest,directory,name=struct.unpack_from("<3H",raw,cursor)
                cursor+=6
                if dest>=count:
                    raise ValueError("Invalid gconv extra module index")
                path=reference(directory,name,required=True)
                if path is not None:
                    extra_paths.add(path)
                    references.append({"from":names[current],"to":names[dest],"path":path,"scope":"EXTRA"})
                current=dest
            if dest in destinations:
                raise ValueError("Duplicate gconv extra destination")
            destinations.add(dest)
    if cursor!=len(raw):
        raise ValueError("Unreferenced gconv extra table bytes")
    return {"module_records":count,"hash_slots":slots,"builtin_reference_count":builtin,
            "extra_chain_reference_count":len(offsets),"extra_chain_count":chain_count,
            "extra_step_count":step_count,"extra_module_paths":sorted(extra_paths),
            "module_paths":sorted(paths),"conversion_references":references,"extra_chains_parsed":True,
            "hash_lookup_verified":False}


def classify(path,closure):
    canonical=closure["aliases"].get(path,path)
    item=closure["files"].get(canonical)
    return {"path":path,"canonical":canonical if item else None,
            "status":"AUDITED_PATH_CANDIDATE" if item else "NOT_IN_AUDITED_SUBSET",
            "sha256":item["sha256"] if item else None}


def check(resolver,inventory,plugins):
    closure=plugins["dependency_evidence"]
    result={"schema":"r800-tzlite-cache-review-v1","status":"STATIC_CACHE_REVIEW_ONLY",
            "plugin_audit_sha256":digest(plugins),"files":{},"problems":[],
            "cache_installation_authorized":False,"loader_selection_verified":False,
            "gconv_conversion_verified":False,"runtime_verified":False,"safe_to_flash":False}
    for name in (LD,GCONV):
        item=inventory["entries"].get(name,{})
        if item.get("kind")!="regular" or item.get("links")!=1 or "sha256" not in item:
            result["files"][name]={"status":"NOT_TESTED_REGULAR_INPUT_REQUIRED"}
            result["problems"].append("CACHE_INPUT_REVIEW:"+name)
            continue
        record={"sha256":item["sha256"],"bytes":item["bytes"],"status":"REVIEW_REQUIRED"}
        result["files"][name]=record
        if not 0<item["bytes"]<=LIMIT:
            result["problems"].append("CACHE_SIZE_REVIEW:"+name)
            continue
        member=resolver.scratch/"cache-review-member"
        if member.exists() or member.is_symlink():
            raise ValueError("Unexpected cache review member")
        try:
            reply=command(resolver.tool,resolver.snapshot,"dump <%d> cache-review-member"%item["inode"],
                          cwd=resolver.scratch)
            check_diagnostics(reply.stderr)
            raw=read_file(member,LIMIT,capture=True)[1]
            if len(raw)!=item["bytes"] or hashlib.sha256(raw).hexdigest()!=item["sha256"]:
                raise ValueError("Cache inventory hash mismatch")
            try:
                if name==LD:
                    fmt,rows=parse_ld(raw)
                    records=[]
                    for lib,path,flags,osversion,hwcap in rows:
                        rec=classify(path,closure)
                        rec.update(name=lib,flags=flags,osversion=osversion,hwcap=hwcap)
                        canonical=rec["canonical"]
                        if canonical and closure["files"][canonical]["soname"]!=lib:
                            rec["status"]="SONAME_REVIEW"
                        records.append(rec)
                    record.update(format=fmt,records=records,record_count=len(records))
                else:
                    details=parse_gconv(raw)
                    record.update(details)
                    record["records"]=[classify(p,closure) for p in details["module_paths"]]
                record["status"]="STATIC_TABLE_INVENTORY_ONLY"
                record["outside_audited_subset_count"]=sum(
                    r["status"]=="NOT_IN_AUDITED_SUBSET" for r in record["records"])
                if any(r["status"]!="AUDITED_PATH_CANDIDATE" for r in record["records"]):
                    result["problems"].append("CACHE_PATH_REVIEW:"+name)
                if name==GCONV and record["extra_chain_reference_count"]:
                    result["problems"].append("GCONV_EXTRA_CHAIN_RUNTIME_UNVERIFIED")
            except (ValueError,struct.error):
                result["problems"].append("CACHE_FORMAT_REVIEW:"+name)
        finally:
            member.unlink(missing_ok=True)
    if plugins["problems"]:
        result["problems"].append("CACHE_CLOSURE_REVIEW")
    return result
