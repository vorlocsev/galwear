#!/usr/bin/env python3
"""Isolated Android 15 startup diagnostics; never a HAL acceptance substitute."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import tempfile

from r800_android_linker_audit import inspect
from r800_android_userspace_preflight import read_regular
from r800_graphics_donor_binding import checkout_sha
from r800_hal_dlopen_probe import check, runtime_dependencies, RUNTIME, SYSTEM_RUNTIME_LIBS
from r800_wear51_apex_runtime import SYSTEM_PIN

LIMIT=8*1024**2
TAIL=8192
CPU_MODELS=("cortex-a15","max")
STATIC_MARKER="WEAR51_STATIC_START"
DYNAMIC_MARKER="WEAR51_BIONIC_START"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(read_regular(path,1024*1024))


def limit_child():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_FSIZE,(LIMIT,LIMIT))


def tail(path):
    with path.open("rb") as stream:
        stream.seek(max(0,path.stat().st_size-TAIL))
        return stream.read(TAIL).decode("utf-8","replace")


def diagnostic(qemu,bwrap,guest,scratch,cpu,name,args,marker):
    stdout=scratch/(cpu+"-"+name+".stdout")
    stderr=scratch/(cpu+"-"+name+".stderr")
    command=[bwrap,"--unshare-all","--die-with-parent","--new-session",
             "--clearenv","--ro-bind",str(guest),"/","--ro-bind",qemu,"/qemu",
             "--dev","/dev","--proc","/proc","--chdir","/",
             "/qemu","-cpu",cpu,"-L","/","-strace","-d","in_asm",
             "-E","LD_LIBRARY_PATH=/apex/com.android.runtime/lib/bionic:/system/lib",*args]
    rc=None
    timed_out=False
    with stdout.open("xb") as out,stderr.open("xb") as err:
        try:
            rc=subprocess.run(command,stdout=out,stderr=err,timeout=20,
                              preexec_fn=limit_child).returncode
        except subprocess.TimeoutExpired:
            timed_out=True
    output=tail(stdout)
    log=tail(stderr)
    # Keep only bounded syscall/instruction tail; no binary/core artefacts.
    # A trace reaching the resource cap is not a successful diagnostic.
    capped=stdout.stat().st_size>=LIMIT or stderr.stat().st_size>=LIMIT
    return {"cpu":cpu,"probe":name,"exit_code":rc,"timeout":timed_out,
            "trace_capped":capped,"marker":marker,
            "marker_observed":marker in output.splitlines() if marker else None,
            "status":"MARKER_PASS" if marker and rc==0 and not capped and
                       not timed_out and marker in output.splitlines() else
                     "OBSERVED_ONLY" if not marker and not timed_out and not capped else
                     "REVIEW_REQUIRED",
            "stdout_tail":output,"trace_tail":log,"trace_bytes":stderr.stat().st_size}


def audit(root,evidence,source,output):
    checkout_sha(source)
    if os.geteuid()==0:
        raise ValueError("Non-root diagnostics required")
    qemu,bwrap=shutil.which("qemu-arm-static"),shutil.which("bwrap")
    if not qemu or not bwrap:
        raise ValueError("Static QEMU and bubblewrap required")
    qemu=str(Path(qemu).resolve())
    apex=read_json(evidence/"apex-runtime.json")
    pins=read_json(root/"wear51-bionic/runtime-manifest.json")
    compile_report=read_json(root/"hal/hal-compile.json")
    probe_report=read_json(root/"hal-probe/hal-probe-evidence.json")
    if (apex.get("source_sha")!=source or apex.get("system_sha256")!=SYSTEM_PIN or
            apex.get("status")!="WEAR51_MINIMAL_ARM32_RUNTIME_STATIC_ONLY" or
            pins!={k:v["sha256"] for k,v in apex["minimal_runtime"]["files"].items()} or
            set(pins)!=set(RUNTIME) or compile_report.get("commit")!=source or
            probe_report.get("source_sha")!=source or probe_report.get("safe_to_flash") is not False):
        raise ValueError("Wear51 diagnostic inputs not bound to exact source and System")
    ndk=root/"android-ndk-r27c"
    cc=ndk/"toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi28-clang"
    if "27.2.12479018" not in (ndk/"source.properties").read_text():
        raise ValueError("Expected NDK r27c")
    with tempfile.TemporaryDirectory(prefix="wear51-startup-",dir=root) as tmp:
        scratch=Path(tmp)
        guest=scratch/"guest"
        for path in ("system/bin","system/lib","vendor/lib/hw","apex/com.android.runtime/bin",
                     "apex/com.android.runtime/lib/bionic","dev","proc","linkerconfig"):
            (guest/path).mkdir(parents=True,exist_ok=True)
        (guest/"qemu").touch()
        runtime=root/"wear51-bionic"
        linker_soname=check(runtime/"linker")[1]["soname"]
        def stage(src,rel,pin,library=False,executable=False):
            raw,info=check(src,library)
            if sha(raw)!=pin:
                raise ValueError("Diagnostic ELF digest mismatch: "+src.name)
            runtime_dependencies(src.name,info,linker_soname)
            dst=guest/rel
            dst.write_bytes(raw)
            dst.chmod(0o555 if executable else 0o444)
        for name in RUNTIME:
            rel=("apex/com.android.runtime/bin/linker" if name=="linker" else
                 "system/lib/"+name if name in SYSTEM_RUNTIME_LIBS else
                 "apex/com.android.runtime/lib/bionic/"+name)
            stage(runtime/name,rel,pins[name],name!="linker",name=="linker")
        (guest/"system/bin/linker").symlink_to("../../apex/com.android.runtime/bin/linker")
        (guest/"linkerconfig/ld.config.txt").write_text(
            "dir.fixture = /system/bin\n[fixture]\nnamespace.default.isolated = false\n"
            "namespace.default.search.paths = /apex/com.android.runtime/lib/bionic:/system/lib\n")
        lights="lights.r800.so"
        lights_pin=compile_report["linked_libraries"]["lights"]["sha256"]
        if probe_report["hal_sha256"][lights]!=lights_pin:
            raise ValueError("Lights compile/probe evidence mismatch")
        stage(root/"hal"/lights,"vendor/lib/hw/"+lights,lights_pin,True)
        stage(root/"hal-probe/hal-probe","system/bin/hal-probe",probe_report["probe_sha256"],executable=True)
        # Compare freestanding Linux syscall startup to Bionic CRT startup.
        assembly=scratch/"start.S"
        assembly.write_text(".syntax unified\n.arm\n.global _start\n.text\n_start:\n"
                            " mov r0, #1\n adr r1, marker\n mov r2, #20\n mov r7, #4\n svc #0\n"
                            " mov r0, #0\n mov r7, #1\n svc #0\nmarker:\n"
                            ' .ascii "WEAR51_STATIC_START\\n"\n')
        static=guest/"system/bin/static-start"
        subprocess.run([str(cc),"-nostdlib","-static","-Wl,-e,_start","-Wl,--build-id=none",
                        str(assembly),"-o",str(static)],check=True,timeout=60)
        info=inspect(read_regular(static,1024*1024))
        if info["abi"]!="arm" or info["has_dynamic"]:
            raise ValueError("Unexpected freestanding control")
        static.chmod(0o555)
        c=scratch/"start.c"
        c.write_text('#include <unistd.h>\nint main(void) { static const char s[]="WEAR51_BIONIC_START\\n";'
                     ' return write(1,s,sizeof(s)-1)==(ssize_t)(sizeof(s)-1) ? 0 : 1; }\n')
        dynamic=scratch/"dynamic-start"
        subprocess.run([str(cc),"-O2","-Wall","-Wextra","-Werror",str(c),"-o",str(dynamic)],
                       check=True,timeout=60)
        stage(dynamic,"system/bin/dynamic-start",sha(read_regular(dynamic,1024*1024)),executable=True)
        cases=(("static",["/system/bin/static-start"],STATIC_MARKER),
               ("linker",["/apex/com.android.runtime/bin/linker","--help"],None),
               ("dynamic",["/system/bin/dynamic-start"],DYNAMIC_MARKER),
               ("lights",["/system/bin/hal-probe","/vendor/lib/hw/"+lights,"lights"],"HAL_HMI_PASS lights module_api=1 hal_api=0"))
        rows={}
        for cpu in CPU_MODELS:
            for name,args,marker in cases:
                rows[cpu+"/"+name]=diagnostic(qemu,bwrap,guest,scratch,cpu,name,args,marker)
        result={"schema":"galwear-r800-wear51-startup-diagnostics-v1","source_sha":source,
                "system_sha256":SYSTEM_PIN,"runtime_sha256":pins,"lights_sha256":lights_pin,
                "qemu_version":subprocess.check_output([qemu,"--version"],text=True,timeout=10).splitlines()[0],
                "qemu_cpu_models":subprocess.run([qemu,"-cpu","help"],capture_output=True,text=True,timeout=10).stdout.splitlines(),
                "results":rows,"status":"STARTUP_DIAGNOSTICS_ONLY",
                "hal_acceptance_verified":False,"hardware_tested":False,"safe_to_flash":False}
    checkout_sha(source)
    with output.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2,sort_keys=True)
        stream.write("\n")
    for name,row in rows.items():
        print("WEAR51_STARTUP_CASE",json.dumps({"case":name,**row},sort_keys=True))
    print("WEAR51_STARTUP_DIAGNOSTICS",json.dumps({k:v for k,v in result.items() if k!="results"},sort_keys=True))


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("root","evidence","output"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--source-sha",required=True)
    a=p.parse_args()
    audit(a.root,a.evidence,a.source_sha,a.output)
