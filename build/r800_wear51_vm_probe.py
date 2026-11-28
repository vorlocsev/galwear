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
from r800_wear51_art_dependencies import audit, ROOTS, MAX_BYTES, MAX_OBJECTS
from r800_wear51_art_boot_probe import OUTPUTS, MAX_OUTPUT, ART_ROOT
from r800_wear51_java_fixture import build, CLASS, MISSING_CLASS
from r800_android_userspace_preflight import read_regular

VM="art:/bin/dalvikvm32"
NATIVE_CANDIDATES=("libjavacore.so","libopenjdk.so","libopenjdkjvm.so","libandroidio.so")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


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
        graph=audit(sources,roots=(*ROOTS,VM,*("art:/lib/"+n for n in observed)))
        result["graph_summary"]={"roots":graph["roots"],"counts":graph["counts"],
                                 "review":graph["review"],
                                 "unresolved":[e for e in graph["edges"] if not e["eligible_candidates"]]}
        objects=graph["objects"]
        if not {VM,LINKER,DEX,STUB}<=set(objects) or len(objects)>MAX_OBJECTS or graph["review"] or result["graph_summary"]["unresolved"]:
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
                if total>MAX_BYTES:
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
            cfg=config(objects)
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
