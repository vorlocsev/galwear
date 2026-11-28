#!/usr/bin/env python3
"""Isolated original dalvikvm32 Java execution experiment.

No native-code execution claim: explicitly use the interpreter and a private
verify-mode boot image. All generated and original binary files stay temporary.
"""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile

from r800_framework_inventory import ext4_member, MAX_MEMBER
from r800_pixel_runtime_layout import list_directory
from r800_wear51_art_dependencies import audit, ROOTS, NAME, VM_MAX_BYTES, VM_MAX_OBJECTS, MAX_PUBLIC_PRELOADS
from r800_wear51_art_boot_probe import OUTPUTS, MAX_OUTPUT, ART_ROOT
from r800_wear51_java_fixture import build, CLASS, MISSING_CLASS
from r800_android_userspace_preflight import read_regular

VM="art:/bin/dalvikvm32"
PUBLIC_LIBRARIES="/system/etc/public.libraries.txt"
MAX_PUBLIC_LIBRARIES=64*1024
NATIVE_CANDIDATES=("libjavacore.so","libopenjdk.so","libopenjdkjvm.so","libandroidio.so")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_public_libraries(sources):
    tool,image,workspace=sources["system"]
    raw=ext4_member(tool,image,PUBLIC_LIBRARIES,MAX_PUBLIC_LIBRARIES,workspace)
    if not raw or len(raw)>MAX_PUBLIC_LIBRARIES or b"\0" in raw:
        raise ValueError("Original public.libraries.txt missing or invalid")
    raw.decode("utf-8")
    return raw


def preload_names(raw):
    """Read ARM32 preload entries; the original config remains untouched."""
    selected=[]
    for line in raw.decode("utf-8").splitlines():
        line=line.strip()
        if not line or line.startswith("#"):
            continue
        name,*flags=line.split(" ")
        if (not NAME.fullmatch(name) or not name.startswith("lib") or not name.endswith(".so")
                or len(flags)>2 or len(set(flags))!=len(flags)
                or set(flags)-{"32","64","nopreload"} or {"32","64"}<=set(flags)):
            raise ValueError("Malformed public library entry: "+line)
        if "64" not in flags and "nopreload" not in flags and name not in selected:
            selected.append(name)
    if not 0<len(selected)<=MAX_PUBLIC_PRELOADS:
        raise ValueError("Public preload selection outside budget")
    return selected


def stage_public_libraries(sources,guest):
    """Preserve the exact donor NativeLoader configuration, never synthesize it."""
    raw=read_public_libraries(sources)
    target=guest/PUBLIC_LIBRARIES.lstrip("/")
    target.parent.mkdir(parents=True,exist_ok=True)
    with target.open("xb") as stream:
        stream.write(raw)
    target.chmod(0o444)
    if read_regular(target,MAX_PUBLIC_LIBRARIES)!=raw:
        raise ValueError("Public libraries staging mismatch")
    return {"path":PUBLIC_LIBRARIES,"source":"system","sha256":sha(raw),"bytes":len(raw),
            "status":"ORIGINAL_READ_ONLY_CONFIG"}


def vm_arguments(classpath,cls):
    if cls not in (CLASS,MISSING_CLASS):
        raise ValueError("Unexpected synthetic Java class")
    from r800_wear51_art_boot_probe import BOOT_JARS
    if classpath!=[ART_ROOT+"/javalib/"+n for n in BOOT_JARS]:
        raise ValueError("Unexpected selected boot classpath")
    return [ART_ROOT+"/bin/dalvikvm32","-Xint",
            "-Xbootclasspath:"+":".join(classpath),
            "-Xbootclasspath-locations:"+":".join(classpath),
            "-Ximage:/data/boot.art","-Xms64m","-Xmx512m",
            "-cp","/data/probe.dex",cls]


def experiment(sources,guest,scratch,boot_dir,boot_result,jars,qemu,bwrap):
    from r800_wear51_art_probe import guest_path, config, run_case, LINKER, DEX, STUB
    result={"status":"REVIEW_REQUIRED","java_code_executed":False,
            "compiled_java_code_executed":False,"android_boot_tested":False,
            "safe_to_flash":False}
    try:
        if boot_result.get("status")!="BOOT_OUTPUT_HEADERS_OBSERVED":
            raise ValueError("Successful private verify-mode boot image required")
        tool,image,workspace=sources["art"]
        listing=list_directory(tool,image,"/lib")["entries"]
        observed=[n for n in NATIVE_CANDIDATES if listing.get(n,{}).get("type")=="regular"]
        result["selected_native_candidates"]=observed
        public_raw=read_public_libraries(sources)
        names=preload_names(public_raw)
        result["public_preloads"]={"sha256":sha(public_raw),"names":names,"abi":"arm"}
        graph=audit(sources,roots=(*ROOTS,VM,*("art:/lib/"+n for n in observed)),public_preloads=names)
        result["graph_summary"]={"roots":graph["roots"],"counts":graph["counts"],
                                 "review":graph["review"],
                                 "unresolved":[e for e in graph["edges"] if not e["eligible_candidates"]]}
        objects=graph["objects"]
        if not {VM,LINKER,DEX,STUB}<=set(objects) or len(objects)>VM_MAX_OBJECTS or graph["review"] or result["graph_summary"]["unresolved"]:
            raise ValueError("VM selected dependency closure requires review")
        with tempfile.TemporaryDirectory(prefix="wear51-vm-",dir=scratch) as tmp:
            work=Path(tmp)
            vm_guest=work/"guest"
            shutil.copytree(guest,vm_guest,symlinks=True)
            staged={}
            total=0
            for key,row in sorted(objects.items()):
                if key==STUB:
                    continue
                label,path=key.split(":",1)
                tool,image,workspace=sources[label]
                raw=ext4_member(tool,image,path,MAX_MEMBER,workspace)
                if raw is None or len(raw)!=row["bytes"] or sha(raw)!=row["sha256"]:
                    raise ValueError("VM object digest mismatch: "+key)
                total+=len(raw)
                if total>VM_MAX_BYTES:
                    raise ValueError("VM staging budget exceeded")
                rel=guest_path(key)
                target=vm_guest/rel.lstrip("/")
                target.parent.mkdir(parents=True,exist_ok=True)
                if target.exists():
                    if target.is_symlink() or read_regular(target,MAX_MEMBER)!=raw:
                        raise ValueError("Existing VM object differs: "+key)
                else:
                    with target.open("xb") as stream:
                        stream.write(raw)
                    target.chmod(0o555 if key in (VM,LINKER,DEX) else 0o444)
                staged[rel]=row["sha256"]
            result["public_libraries"]=stage_public_libraries(sources,vm_guest)
            if result["public_libraries"]["sha256"]!=result["public_preloads"]["sha256"]:
                raise ValueError("Public preload config changed")
            cfg=config(objects,vm_oat=True)
            (vm_guest/"linkerconfig/ld.config.txt").write_text(cfg)
            data=vm_guest/"data"
            arm=data/"arm"
            arm.mkdir()
            boot_pins={}
            for name in OUTPUTS:
                row=boot_result["output_headers"][name]
                raw=read_regular(boot_dir/name,MAX_OUTPUT)
                if row["status"]!="HEADER_OBSERVED" or len(raw)!=row["bytes"] or sha(raw)!=row["sha256"]:
                    raise ValueError("Boot image input changed: "+name)
                (arm/name).write_bytes(raw)
                (arm/name).chmod(0o444)
                boot_pins[name]=row["sha256"]
            fixture=build()
            (data/"probe.dex").write_bytes(fixture)
            (data/"probe.dex").chmod(0o444)
            result.update(staged_sha256=staged,boot_sha256=boot_pins,
                          fixture_sha256=sha(fixture),fixture_bytes=len(fixture),
                          config_sha256=sha(cfg.encode()),execution_mode="interpreter",
                          cases={})
            cases=result["cases"]
            cases["vm-linker-list"]=run_case(qemu,bwrap,vm_guest,work,"vm-linker-list",
                    [guest_path(LINKER),"--list",guest_path(VM)],staged)
            if cases["vm-linker-list"]["status"]!="MARKER_PASS":
                return result
            for name,cls in (("vm-java",CLASS),("vm-missing-class",MISSING_CLASS)):
                args=vm_arguments(jars["classpath"],cls)
                cases[name]=run_case(qemu,bwrap,vm_guest,work,name,args,staged)
                cases[name]["arguments"]=args
            if (cases["vm-java"]["status"]=="JAVA_MARKER_PASS" and
                    cases["vm-missing-class"]["status"]=="MISSING_CLASS_CONTROL_PASS"):
                result.update(status="JAVA_INTERPRETER_FIXTURE_ONLY",java_code_executed=True)
    except (OSError,ValueError,RuntimeError,KeyError,OverflowError,subprocess.SubprocessError) as exc:
        result.update(status="REVIEW_REQUIRED",reason=str(exc))
    return result
