#!/usr/bin/env python3
"""Bounded candidate DT_NEEDED graph for Wear OS 5.1 ART.

Only selected regular files in System, Runtime and ART are inspected.
Candidate discovery does not establish Android namespace resolution.
"""
from collections import deque
import hashlib
import re
import subprocess

from r800_android_linker_audit import inspect
from r800_framework_inventory import ext4_member, MAX_MEMBER
from r800_pixel_runtime_layout import list_directory

NAME=re.compile(r"[A-Za-z0-9_.+~@-]{1,255}")
ROOTS=("art:/bin/dex2oat32","art:/lib/libart.so")
# Observed in original dex2oat no-argument run 46167789388 (62611101).
RUNTIME_LOADS={"art:/lib/libartpalette.so":("libartpalette-system.so",)}
MAX_OBJECTS=128
MAX_EDGES=2048
MAX_BYTES=128*1024**2
MAX_DEPTH=16
# The public NDK surface pulls in much more of System than dex2oat.
# Only the standalone VM experiment may use these separate finite limits.
VM_MAX_OBJECTS=384
VM_MAX_EDGES=8192
VM_MAX_BYTES=384*1024**2
MAX_PUBLIC_PRELOADS=128


def walk(load, candidates, roots=ROOTS, runtime_loads=None, *, public_preloads=()):
    """Explore all eligible candidates, never choose an ambiguous provider."""
    runtime_loads=runtime_loads or {}
    pending=deque((path,0,None) for path in roots)
    objects, edges, reviews={},[],{}
    total=0
    visited=set()
    public_preloads=tuple(public_preloads)
    if len(public_preloads)>MAX_PUBLIC_PRELOADS or len(set(public_preloads))!=len(public_preloads):
        raise ValueError("Invalid public preload list size or duplicate")
    object_limit=VM_MAX_OBJECTS if public_preloads else MAX_OBJECTS
    byte_limit=VM_MAX_BYTES if public_preloads else MAX_BYTES
    edge_limit=VM_MAX_EDGES if public_preloads else MAX_EDGES
    for name in public_preloads:
        if not NAME.fullmatch(name) or not name.startswith("lib") or not name.endswith(".so"):
            raise ValueError("Invalid public preload SONAME")
        providers=sorted(set(candidates(name)))
        edges.append({"consumer":"/system/etc/public.libraries.txt","needed":name,
                      "kind":"PUBLIC_PRELOAD","candidates":providers})
        for provider in providers:
            pending.append((provider,0,name))
    while pending:
        path,depth,expected=pending.popleft()
        if path in visited:
            continue
        if depth>MAX_DEPTH or len(visited)>=object_limit:
            raise ValueError("ART dependency graph exceeds object/depth budget")
        visited.add(path)
        try:
            raw=load(path)
            if raw is None:
                raise ValueError("Selected member missing")
            total+=len(raw)
            if total>byte_limit:
                raise OverflowError("ART dependency graph byte budget exceeded")
            info=inspect(raw)
            if info["abi"]!="arm" or info["elf_type"]!="ET_DYN" or not info["has_dynamic"] or info["custom_search_path"]:
                raise ValueError("Unexpected ARM32 dynamic ELF")
            if expected is not None and info["soname"]!=expected:
                raise ValueError("Candidate SONAME mismatch: "+expected)
            objects[path]={"sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw),
                           "abi":info["abi"],"soname":info["soname"],"needed":info["needed"]}
        except (ValueError,OSError,RuntimeError,subprocess.SubprocessError) as exc:
            reviews[path]=str(exc)
            continue
        dependencies=[(name,"DT_NEEDED") for name in info["needed"]]
        dependencies.extend((name,"OBSERVED_DLOPEN") for name in runtime_loads.get(path,()))
        for name,kind in dependencies:
            if not NAME.fullmatch(name) or name in (".",".."):
                raise ValueError("Invalid dependency name")
            if len(edges)>=edge_limit:
                raise ValueError("ART dependency graph edge budget exceeded")
            providers=sorted(set(candidates(name)))
            edges.append({"consumer":path,"needed":name,"kind":kind,"candidates":providers})
            for provider in providers:
                pending.append((provider,depth+1,name))
    for edge in edges:
        eligible=[p for p in edge["candidates"] if p in objects and
                  objects[p]["soname"]==edge["needed"]]
        edge["eligible_candidates"]=eligible
        edge["candidate_sha256"]={p:objects[p]["sha256"] for p in eligible}
        edge["candidate_bytes_identical"]=len(eligible)>1 and len(set(edge["candidate_sha256"].values()))==1
        edge["status"]=("NOT_FOUND_IN_SELECTED_DIRS" if not edge["candidates"] else
                        "NO_ELIGIBLE_CANDIDATE" if not eligible else
                        "MULTIPLE_CANDIDATES" if len(eligible)>1 else
                        "SINGLE_STATIC_CANDIDATE")
    counts={}
    for e in edges:
        counts[e["status"]]=counts.get(e["status"],0)+1
    duplicates={}
    for edge in edges:
        if edge["status"]=="MULTIPLE_CANDIDATES":
            name=edge["needed"]
            row=duplicates.setdefault(name,{"candidate_sha256":edge["candidate_sha256"],
                "candidate_bytes_identical":edge["candidate_bytes_identical"],"consumers":[]})
            if row["candidate_sha256"]!=edge["candidate_sha256"]:
                raise ValueError("Inconsistent candidate inventory: "+name)
            row["consumers"].append(edge["consumer"])
    return {"status":"SELECTED_ART_DEPENDENCY_CANDIDATES_ONLY",
            "ambiguous_names":duplicates,
            "roots":list(roots),"public_preloads":list(public_preloads),"objects":objects,"edges":edges,"review":reviews,
            "counts":counts,"inspected_bytes":total,"namespace_resolution_verified":False,
            "symbol_resolution_verified":False,"art_initialized":False,"safe_to_flash":False}


def audit(sources,*,roots=ROOTS,public_preloads=()):
    """sources: fixed labels -> (debugfs, private image, private scratch)."""
    if not {"system","runtime","art"} <= set(sources) <= {"system","runtime","art","statsd","i18n","neuralnetworks"}:
        raise ValueError("Expected selected System, Runtime, ART and optional StatsD, i18n and NNAPI filesystems")
    dirs={"system":("/system/lib",),
          "runtime":("/lib/bionic","/lib","/bin"),
          "art":("/lib",)}
    if "statsd" in sources:
        dirs["statsd"]=("/lib",)
    if "i18n" in sources:
        dirs["i18n"]=("/lib",)
    if "neuralnetworks" in sources:
        dirs["neuralnetworks"]=("/lib",)
    listings={}
    for label,paths in dirs.items():
        tool,image,scratch=sources[label]
        for path in paths:
            listings[label+":"+path]=list_directory(tool,image,path)
    def candidates(name):
        for label,paths in dirs.items():
            for path in paths:
                # The linker supplies ld-android.so in this donor, but the
                # system also has a same-SONAME ELF; preserve both candidates.
                basename="linker" if label=="runtime" and path=="/bin" and name=="ld-android.so" else name
                entry=listings[label+":"+path]["entries"].get(basename,{})
                if entry.get("type")=="regular":
                    yield label+":"+path+"/"+basename
    def load(key):
        label,path=key.split(":",1)
        tool,image,scratch=sources[label]
        return ext4_member(tool,image,path,MAX_MEMBER,scratch)
    result=walk(load,candidates,roots=roots,runtime_loads=RUNTIME_LOADS,public_preloads=public_preloads)
    result["selected_directories"]={p:{"status":v["status"],"entries":len(v["entries"])}
                                    for p,v in listings.items()}
    return result

def audit_vm(sources):
    """Discover the original standalone VM and its separate static closure."""
    tool,image,scratch=sources["art"]
    listing=list_directory(tool,image,"/bin")
    names=("dalvikvm32","dalvikvm","dalvikvm64")
    entries={n:listing["entries"].get(n,{"type":"NOT_FOUND"}) for n in names}
    root="art:/bin/dalvikvm32"
    result={"status":"REVIEW_REQUIRED","bin_entries":entries,
            "guest_executed":False,"java_code_executed":False,"safe_to_flash":False}
    if entries["dalvikvm32"].get("type")!="regular":
        result["reason"]="Original regular dalvikvm32 not observed"
        return result
    closure=audit(sources,roots=(root,))
    result["graph"]=closure
    if root in closure["objects"] and not closure["review"] and all(
            e["eligible_candidates"] for e in closure["edges"]):
        result["status"]="DALVIKVM32_STATIC_CANDIDATES_ONLY"
    return result
