#!/usr/bin/env python3
"""Isolated original ARM32 dex2oat startup, not ART/Android boot acceptance."""
import hashlib
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess

from r800_framework_inventory import ext4_member, MAX_MEMBER
from r800_wear51_art_dependencies import MAX_BYTES, MAX_OBJECTS, NAME

PREFIX={"art":"/apex/com.android.art","runtime":"/apex/com.android.runtime",
        "statsd":"/apex/com.android.os.statsd","system":""}
LINKER="runtime:/bin/linker"
DEX="art:/bin/dex2oat32"
STUB="system:/system/lib/ld-android.so"
LIMIT=2*1024**2
TAIL=16384


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def guest_path(key):
    label,path=key.split(":",1)
    if label not in PREFIX:
        raise ValueError("Unexpected provider label")
    if key in (LINKER,DEX):
        return PREFIX[label]+path
    directory,name=path.rsplit("/",1)
    allowed={"art":{"/lib"},"statsd":{"/lib"},"runtime":{"/lib","/lib/bionic"},
             "system":{"/system/lib"}}
    if directory not in allowed[label] or not NAME.fullmatch(name) or not name.endswith(".so"):
        raise ValueError("Unexpected provider path")
    return PREFIX[label]+path


def config(objects):
    names={label:set() for label in PREFIX}
    for key,row in objects.items():
        guest_path(key)
        name=row["soname"]
        if key in (DEX,STUB):
            continue
        if not isinstance(name,str) or not NAME.fullmatch(name):
            raise ValueError("Unexpected provider SONAME")
        names[key.split(":",1)[0]].add(name)
    if not {"libc.so","libm.so","libdl.so","ld-android.so"}<=names["runtime"]:
        raise ValueError("Missing selected Bionic provider")
    if not {"libstatspull.so","libstatssocket.so"}<=names["statsd"]:
        raise ValueError("Missing selected StatsD provider")
    lines=["dir.art = /apex/com.android.art/bin","[art]",
           "additional.namespaces = runtime,statsd,system"]
    paths={"default":"/apex/com.android.art/lib",
           "runtime":"/apex/com.android.runtime/lib/bionic:/apex/com.android.runtime/lib",
           "statsd":"/apex/com.android.os.statsd/lib","system":"/system/lib"}
    links={"default":("runtime","statsd","system"),"runtime":(),
           "statsd":("runtime","system"),"system":("runtime",)}
    for ns,path in paths.items():
        p="namespace."+ns
        lines.extend([p+".isolated = true",p+".search.paths = "+path])
        if links[ns]:
            lines.append(p+".links = "+",".join(links[ns]))
            for dst in links[ns]:
                lines.append(p+".link."+dst+".shared_libs = "+":".join(sorted(names[dst])))
    return "\n".join(lines)+"\n"


def limit_child():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_FSIZE,(LIMIT,LIMIT))


def run_case(qemu,bwrap,guest,scratch,name,args):
    command=[bwrap,"--unshare-all","--die-with-parent","--new-session","--clearenv",
             "--ro-bind",str(guest),"/","--ro-bind",qemu,"/qemu","--dev","/dev",
             "--proc","/proc","--chdir","/","/qemu","-cpu","max","-L","/",
             "-E","ANDROID_ROOT=/system","-E","ANDROID_ART_ROOT=/apex/com.android.art",
             "-E","ANDROID_RUNTIME_ROOT=/apex/com.android.runtime",
             "-E","ANDROID_DATA=/data",*args]
    stdout=scratch/(name+".stdout")
    stderr=scratch/(name+".stderr")
    rc=None
    timed_out=False
    with stdout.open("xb") as out,stderr.open("xb") as err:
        try:
            rc=subprocess.run(command,stdout=out,stderr=err,timeout=30,
                              preexec_fn=limit_child).returncode
        except subprocess.TimeoutExpired:
            timed_out=True
    capped=any(p.stat().st_size>=LIMIT for p in (stdout,stderr))
    def tail(path):
        with path.open("rb") as stream:
            stream.seek(max(0,path.stat().st_size-TAIL))
            return stream.read(TAIL).decode("utf-8","replace")
    out,err=tail(stdout),tail(stderr)
    clean=not timed_out and not capped and not re.search(
        r"CANNOT LINK EXECUTABLE|cannot locate symbol|uncaught target signal|fatal signal",
        out+"\n"+err,re.I)
    # A --help return of 1 is allowed only with an actual dex2oat usage marker.
    marker=(rc==0 and "libart.so" in out if name=="linker-list" else
            rc in (0,1) and bool(re.search(r"(?im)^\s*usage:.*dex2oat|^\s*dex2oat\s+usage",out+"\n"+err)))
    return {"status":"MARKER_PASS" if clean and marker else "REVIEW_REQUIRED",
            "exit_code":rc,"timeout":timed_out,"output_capped":capped,
            "stdout_tail":out,"stderr_tail":err,"marker_observed":bool(marker)}


def probe(sources,graph,scratch,source,pin):
    if os.geteuid()==0:
        raise ValueError("Non-root execution required")
    qemu,bwrap=shutil.which("qemu-arm-static"),shutil.which("bwrap")
    if not qemu or not bwrap:
        raise ValueError("Isolated QEMU unavailable")
    if set(sources)!=set(PREFIX) or graph["status"]!="SELECTED_ART_DEPENDENCY_CANDIDATES_ONLY" or graph["review"]:
        raise ValueError("Incomplete ART candidate graph")
    if any(not e["eligible_candidates"] for e in graph["edges"]):
        raise ValueError("Missing eligible ART provider")
    objects=graph["objects"]
    if not {LINKER,DEX,STUB}<=set(objects) or not 1<=len(objects)<=MAX_OBJECTS:
        raise ValueError("Missing or excessive original objects")
    guest=scratch/"art-guest"
    guest.mkdir()
    for path in ("system/bin","system/lib","dev","proc","data","linkerconfig"):
        (guest/path).mkdir(parents=True,exist_ok=True)
    (guest/"qemu").touch()
    staged={}
    total=0
    for key,row in sorted(objects.items()):
        rel=guest_path(key)
        if key==STUB:
            continue
        label,path=key.split(":",1)
        tool,image,workspace=sources[label]
        raw=ext4_member(tool,image,path,MAX_MEMBER,workspace)
        if raw is None or len(raw)!=row["bytes"] or sha(raw)!=row["sha256"]:
            raise ValueError("Original ART object digest mismatch: "+key)
        total+=len(raw)
        if total>MAX_BYTES:
            raise ValueError("ART stage exceeds byte budget")
        target=guest/rel.lstrip("/")
        target.parent.mkdir(parents=True,exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
        target.chmod(0o555 if key in (LINKER,DEX) else 0o444)
        staged[rel]=row["sha256"]
    (guest/"system/bin/linker").symlink_to("../../apex/com.android.runtime/bin/linker")
    cfg=config(objects)
    (guest/"linkerconfig/ld.config.txt").write_text(cfg)
    # Separate physical paths and explicit synthetic namespace links.
    # No LD_LIBRARY_PATH, no activation, no host files or writable mounts.
    rows={}
    for name,args in (("linker-list",[guest_path(LINKER),"--list",guest_path(DEX)]),
                      ("dex2oat-help",[guest_path(DEX),"--help"])):
        rows[name]=run_case(str(Path(qemu).resolve()),bwrap,guest,scratch,name,args)
    return {"schema":"galwear-r800-wear51-art-startup-v1","source_sha":source,
            "system_sha256":pin,"qemu_cpu":"max","staged_sha256":staged,
            "excluded_system_ld_android_sha256":objects[STUB]["sha256"],
            "synthetic_config_sha256":sha(cfg.encode()),"synthetic_config":cfg,
            "results":rows,"status":"DEX2OAT_STARTUP_PROBE_ONLY" if all(
                v["status"]=="MARKER_PASS" for v in rows.values()) else "REVIEW_REQUIRED",
            "android_namespace_runtime_verified":False,"art_initialized":False,
            "dex_compilation_verified":False,"hardware_tested":False,"safe_to_flash":False}
