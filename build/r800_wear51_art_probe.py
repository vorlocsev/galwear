#!/usr/bin/env python3
"""Isolated original ARM32 dex2oat startup, not ART/Android boot acceptance."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import select
import socket
import tempfile
import time

from r800_framework_inventory import ext4_member, MAX_MEMBER
from r800_wear51_art_dependencies import MAX_BYTES, MAX_OBJECTS, NAME

PREFIX={"art":"/apex/com.android.art","runtime":"/apex/com.android.runtime",
        "statsd":"/apex/com.android.os.statsd","i18n":"/apex/com.android.i18n","system":""}
LINKER="runtime:/bin/linker"
DEX="art:/bin/dex2oat32"
VM="art:/bin/dalvikvm32"
STUB="system:/system/lib/ld-android.so"
LIMIT=2*1024**2
TAIL=16384
LOG_LIMIT=1024*1024
LOG_RECORDS=512
INVALID_OPTION="--galwear-unknown-argument-probe"
USAGE_ERROR="See log for usage error information"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def guest_path(key):
    label,path=key.split(":",1)
    if label not in PREFIX:
        raise ValueError("Unexpected provider label")
    if key in (LINKER,DEX,VM):
        return PREFIX[label]+path
    directory,name=path.rsplit("/",1)
    allowed={"art":{"/lib"},"statsd":{"/lib"},"i18n":{"/lib"},"runtime":{"/lib","/lib/bionic"},
             "system":{"/system/lib"}}
    if directory not in allowed[label] or not NAME.fullmatch(name) or not name.endswith(".so"):
        raise ValueError("Unexpected provider path")
    return PREFIX[label]+path


def config(objects, *, vm_oat=False):
    names={label:set() for label in PREFIX}
    for key,row in objects.items():
        guest_path(key)
        name=row["soname"]
        if key in (DEX,VM,STUB):
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
    # Keep baseline ART namespace unchanged unless original ICU objects are staged.
    if names["i18n"]:
        lines[2]+=",i18n"
        paths["i18n"]="/apex/com.android.i18n/lib"
        links["default"]+=("i18n",)
        links["i18n"]=("runtime","system")
    for ns,path in paths.items():
        p="namespace."+ns
        lines.extend([p+".isolated = true",p+".search.paths = "+path])
        if ns=="system" and vm_oat:
            # Original ART uses android_get_exported_namespace("system")
            # for boot OAT outside ART APEX (observed in run 46177117834).
            # Only the sandbox private verified boot artifact directory is permitted.
            lines.extend([p+".visible = true",p+".permitted.paths = /data/arm"])
        if links[ns]:
            lines.append(p+".links = "+",".join(links[ns]))
            for dst in links[ns]:
                lines.append(p+".link."+dst+".shared_libs = "+":".join(sorted(names[dst])))
    return "\n".join(lines)+"\n"


def limit_child(file_limit=LIMIT):
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_FSIZE,(file_limit,file_limit))


def decode_log_record(packet):
    # Android logdw datagrams: packed log ID, TID, timestamp (11 bytes),
    # followed by priority byte and NUL-terminated tag/message.
    if len(packet)<15 or packet[11] not in range(2,8):
        return None
    parts=packet[12:].split(b"\0",2)
    if len(parts)<3 or not parts[0] or len(parts[0])>256:
        return None
    return {"priority":packet[11],"tag":parts[0].decode("utf-8","replace"),
            "message":parts[1].decode("utf-8","replace")}


def evaluate_case(name,rc,out,err,records,timeout,capped,staged):
    logs="\n".join(r["message"] for r in records)
    combined=out+"\n"+err+"\n"+logs
    clean=not timeout and not capped and not re.search(
        r"CANNOT LINK EXECUTABLE|cannot locate symbol|uncaught target signal|fatal signal",
        combined,re.I)
    if name=="linker-list":
        resolved=re.findall(r"(?m)^\s*(\S+)\s+=>\s+(/\S+)\s+\(",out)
        paths={path for _,path in resolved}
        required={"/apex/com.android.art/lib/libart.so",
                  "/apex/com.android.art/lib/libc++.so",
                  "/system/lib/libc++.so",
                  "/apex/com.android.runtime/lib/bionic/libc.so",
                  "/apex/com.android.os.statsd/lib/libstatspull.so",
                  "/apex/com.android.os.statsd/lib/libstatssocket.so"}
        marker=(rc==0 and required<=paths<=set(staged) and all(
            path.rsplit("/",1)[-1]==name for name,path in resolved))
        status="MARKER_PASS" if clean and marker else "REVIEW_REQUIRED"
        return status,marker,sorted(paths)
    if name=="vm-linker-list":
        resolved=re.findall(r"(?m)^\s*(\S+)\s+=>\s+(/\S+)\s+\(",out)
        paths={path for _,path in resolved}
        required={"libnativehelper.so","libsigchain.so","libc.so"}
        marker=(rc==0 and bool(paths) and paths<=set(staged) and
                required<={path.rsplit("/",1)[-1] for path in paths} and
                all(path.rsplit("/",1)[-1]==soname for soname,path in resolved))
        return ("MARKER_PASS" if clean and marker else "REVIEW_REQUIRED"),marker,sorted(paths)
    if name in ("vm-java","vm-missing-class"):
        from r800_wear51_java_fixture import MARKER, MISSING_CLASS
        if name=="vm-java":
            marker=rc==0 and out.splitlines()==[MARKER]
            status="JAVA_MARKER_PASS"
        else:
            marker=(rc==1 and MARKER not in combined and MISSING_CLASS in combined and
                    bool(re.search(r"ClassNotFoundException|Could not find class|NoClassDefFoundError",combined,re.I)))
            status="MISSING_CLASS_CONTROL_PASS"
        clean=clean and not re.search(r"Runtime aborting|SIGSEGV|SIGABRT|Assertion.*failed",combined,re.I)
        return (status if clean and marker else "REVIEW_REQUIRED"),marker,[]
    usage=bool(re.search(r"(?im)^\s*Usage:\s*dex2oat(?:\s|$)",combined))
    rejected=(rc==1 and USAGE_ERROR in err.splitlines())
    if name=="dex2oat-invalid":
        marker=rejected and usage and INVALID_OPTION in combined
    elif name=="dex2oat-help":
        marker=usage and (rc==0 or rejected)
    elif name=="dex2oat-noargs":
        marker=rejected and usage
    else:
        raise ValueError("Unexpected ART probe")
    return ("ARGUMENT_HANDLER_OBSERVED" if clean and marker else "REVIEW_REQUIRED"),marker,[]


def sandbox_command(qemu,bwrap,guest,logdir,args,boot_output=None):
    # QEMU 6.2 implements /proc/self/{stat,cmdline,maps,auxv} using
    # mkstemp in TMPDIR (default /tmp), then unlinks the backing file.
    # A private tmpfs is required even for otherwise read-only probes.
    command=[bwrap,"--unshare-all","--die-with-parent","--new-session","--clearenv",
             "--ro-bind",str(guest),"/","--ro-bind",qemu,"/qemu","--dev","/dev",
             "--ro-bind",str(logdir),"/dev/socket","--proc","/proc",
             "--tmpfs","/tmp","--setenv","TMPDIR","/tmp","--chdir","/",
             "/qemu","-cpu","max","-L","/",
             "-E","ANDROID_ROOT=/system","-E","ANDROID_ART_ROOT=/apex/com.android.art",
             "-E","ANDROID_RUNTIME_ROOT=/apex/com.android.runtime",
             "-E","ANDROID_DATA=/data","-E","ANDROID_LOG_TAGS=*:v",*args]
    if boot_output is not None:
        where=command.index("--chdir")
        command[where:where]=["--bind",str(boot_output),"/data"]
    return command


def run_case(qemu,bwrap,guest,scratch,name,args,staged,*,boot_output=None):
    if (name=="boot-image") != (boot_output is not None):
        raise ValueError("Explicit private output required only for boot image probe")
    stdout=scratch/(name+".stdout")
    stderr=scratch/(name+".stderr")
    rc=None
    timed_out=False
    log_capped=False
    packets=0
    received=0
    records=[]
    # A private, pathname-only AF_UNIX datagram sink. It never proxies
    # to the host logd and never supplies Android service responses.
    with tempfile.TemporaryDirectory(prefix="wear51-log-") as logdir:
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as sink:
            sink.bind(str(Path(logdir)/"logdw"))
            sink.setblocking(False)
            command=sandbox_command(qemu,bwrap,guest,logdir,args,boot_output)
            if boot_output is not None:
                from r800_wear51_art_boot_probe import MAX_OUTPUT
                file_limit=MAX_OUTPUT
            else:
                file_limit=LIMIT
            with stdout.open("xb") as out,stderr.open("xb") as err:
                proc=subprocess.Popen(command,stdout=out,stderr=err,
                                      preexec_fn=lambda:limit_child(file_limit))
                deadline=time.monotonic()+(120 if boot_output is not None else 30)
                try:
                    while True:
                        if time.monotonic()>=deadline:
                            timed_out=True
                            proc.kill()
                            break
                        ready,_,_=select.select([sink],[],[],0.05)
                        if ready:
                            packet=sink.recv(65536)
                            packets+=1
                            received+=len(packet)
                            if received>LOG_LIMIT or packets>LOG_RECORDS:
                                log_capped=True
                                proc.kill()
                                break
                            record=decode_log_record(packet)
                            if record is not None:
                                records.append(record)
                        elif proc.poll() is not None:
                            break
                finally:
                    if proc.poll() is None:
                        proc.kill()
                    rc=proc.wait(timeout=5)
    capped=log_capped or any(p.stat().st_size>=LIMIT for p in (stdout,stderr))
    def tail(path):
        with path.open("rb") as stream:
            stream.seek(max(0,path.stat().st_size-TAIL))
            return stream.read(TAIL).decode("utf-8","replace")
    out,err=tail(stdout),tail(stderr)
    if boot_output is not None:
        from r800_wear51_art_boot_probe import inspect_outputs
        artifacts=inspect_outputs(boot_output)
        combined=out+"\n"+err+"\n"+"\n".join(r["message"] for r in records)
        marker=(rc==0 and not timed_out and not capped and
                not re.search(r"CANNOT LINK EXECUTABLE|uncaught target signal|Runtime aborting",combined,re.I)
                and not re.search(r"(?:couldn.t open|failed to load|error opening) /proc/self/",combined,re.I)
                and all(v["status"]=="HEADER_OBSERVED" for v in artifacts.values()))
        status="BOOT_OUTPUT_HEADERS_OBSERVED" if marker else "REVIEW_REQUIRED"
        paths=[]
    else:
        status,marker,paths=evaluate_case(name,rc,out,err,records,timed_out,capped,staged)
        artifacts={}
    return {"status":status,"exit_code":rc,"timeout":timed_out,
            "output_capped":capped,"stdout_tail":out,"stderr_tail":err,
            "marker_observed":bool(marker),"resolved_paths":paths,
            "logdw_packets":packets,"logdw_bytes":received,
            "logdw_records":records,"logd_service_emulated":False,
            "qemu_private_tmpfs":True,
            "proc_self_access_errors_observed":bool(re.search(
                r"(?:couldn.t open|failed to load|error opening) /proc/self/",
                out+"\n"+err+"\n"+"\n".join(r["message"] for r in records),re.I)),
            "output_headers":artifacts}


def probe(sources,graph,scratch,source,pin,*,qemu_compare=None):
    if os.geteuid()==0:
        raise ValueError("Non-root execution required")
    qemu,bwrap=shutil.which("qemu-arm-static"),shutil.which("bwrap")
    if not qemu or not bwrap:
        raise ValueError("Isolated QEMU unavailable")
    if set(sources)-{"i18n"}!=set(PREFIX)-{"i18n"} or graph["status"]!="SELECTED_ART_DEPENDENCY_CANDIDATES_ONLY" or graph["review"]:
        raise ValueError("Incomplete ART candidate graph")
    if any(not e["eligible_candidates"] for e in graph["edges"]):
        raise ValueError("Missing eligible ART provider")
    objects=graph["objects"]
    if not {LINKER,DEX,STUB}<=set(objects) or not 1<=len(objects)<=MAX_OBJECTS:
        raise ValueError("Missing or excessive original objects")
    guest=scratch/"art-guest"
    guest.mkdir()
    for path in ("system/bin","system/lib","dev","proc","tmp","data","linkerconfig"):
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
                      ("dex2oat-help",[guest_path(DEX),"--help"]),
                      ("dex2oat-noargs",[guest_path(DEX)]),
                      ("dex2oat-invalid",[guest_path(DEX),INVALID_OPTION])):
        rows[name]=run_case(str(Path(qemu).resolve()),bwrap,guest,scratch,name,args,staged)
    passed=(rows["linker-list"]["status"]=="MARKER_PASS" and all(
        rows[name]["status"]=="ARGUMENT_HANDLER_OBSERVED"
        for name in ("dex2oat-help","dex2oat-noargs","dex2oat-invalid")))
    boot={"status":"NOT_TESTED"}
    baseline_qemu=str(Path(qemu).resolve())
    if passed:
        try:
            from r800_wear51_art_boot_probe import stage, arguments
            jars=stage(sources,guest)
            boot={"status":"REVIEW_REQUIRED","boot_jars":jars,"safe_to_flash":False}
            if jars["status"]=="SELECTED_ART_BOOT_JARS_ONLY":
                with tempfile.TemporaryDirectory(prefix="wear51-boot-",dir=scratch) as outdir:
                    result=run_case(str(Path(qemu).resolve()),bwrap,guest,scratch,"boot-image",
                                    arguments(jars["classpath"]),staged,boot_output=Path(outdir))
                    boot.update(status=result["status"],result=result,
                                baseline_qemu={"version":subprocess.check_output([baseline_qemu,"--version"],text=True,timeout=10).splitlines()[0],
                                               "sha256":sha(Path(baseline_qemu).read_bytes())})
                if qemu_compare is not None:
                    # Same guest, namespace, JARs, arguments and CPU model.
                    # Separate output and log directories, no retry fallback.
                    comparison={"status":"REVIEW_REQUIRED"}
                    boot["comparison"]=comparison
                    try:
                        work=Path(qemu_compare)
                        alternate=work/"extracted/usr/bin/qemu-arm-static"
                        meta=json.loads((work/"comparator.json").read_text())
                        if alternate.is_symlink() or not alternate.is_file() or sha(alternate.read_bytes())!=meta["qemu_sha256"]:
                            raise ValueError("Comparator binary digest mismatch")
                        version=subprocess.check_output([str(alternate),"--version"],text=True,timeout=10).splitlines()[0]
                        if version!=meta["qemu_version"] or not version.startswith("qemu-arm version 8.2.2") or meta["host_install_performed"] is not False:
                            raise ValueError("Unexpected comparator provenance")
                        with tempfile.TemporaryDirectory(prefix="wear51-compare-",dir=scratch) as compdir:
                            comp=Path(compdir)
                            (comp/"data").mkdir()
                            control=run_case(str(alternate),bwrap,guest,comp,"linker-list",
                                [guest_path(LINKER),"--list",guest_path(DEX)],staged)
                            comparison.update(qemu=meta,linker_control=control)
                            if control["status"]=="MARKER_PASS":
                                alternate_result=run_case(str(alternate),bwrap,guest,comp,"boot-image",
                                    arguments(jars["classpath"]),staged,boot_output=comp/"data")
                                comparison.update(status=alternate_result["status"],result=alternate_result)
                                if alternate_result["status"]=="BOOT_OUTPUT_HEADERS_OBSERVED":
                                    from r800_wear51_vm_probe import experiment
                                    comparison["java_vm"]=experiment(sources,guest,scratch,comp/"data",alternate_result,jars,str(alternate),bwrap)
                                if alternate_result["status"]=="BOOT_OUTPUT_HEADERS_OBSERVED":
                                    with tempfile.TemporaryDirectory(prefix="wear51-speed-",dir=scratch) as speed_dir:
                                        speed=Path(speed_dir)
                                        (speed/"data").mkdir()
                                        speed_args=arguments(jars["classpath"],compiler_filter="speed")
                                        speed_result=run_case(str(alternate),bwrap,guest,speed,"boot-image",
                                            speed_args,staged,boot_output=speed/"data")
                                        verify_bytes=alternate_result["output_headers"]["boot.oat"]["elf_segments"]["executable_file_bytes"]
                                        speed_bytes=speed_result.get("output_headers",{}).get("boot.oat",{}).get(
                                            "elf_segments",{}).get("executable_file_bytes")
                                        comparison["speed_experiment"]={"status":"SPEED_EXECUTABLE_SEGMENT_GROWTH_OBSERVED" if
                                            speed_result["status"]=="BOOT_OUTPUT_HEADERS_OBSERVED" and
                                            speed_bytes is not None and speed_bytes>verify_bytes else "REVIEW_REQUIRED",
                                            "compiler_filter":"speed","arguments":speed_args,
                                            "verify_executable_file_bytes":verify_bytes,
                                            "speed_executable_file_bytes":speed_bytes,
                                            "result":speed_result,"machine_code_validated":False,"safe_to_flash":False}
                        if comparison.get("speed_experiment",{}).get("status")=="SPEED_EXECUTABLE_SEGMENT_GROWTH_OBSERVED":
                            from r800_wear51_art_boot_probe import compare_runs, image_difference
                            deterministic_args=arguments(jars["classpath"],compiler_filter="verify",force_determinism=True)
                            repeats=[]
                            diff={"status":"NOT_TESTED"}
                            with tempfile.TemporaryDirectory(prefix="wear51-determinism-",dir=scratch) as tmp:
                                for index in range(2):
                                    repeat=Path(tmp)/str(index)
                                    (repeat/"data").mkdir(parents=True)
                                    repeats.append(run_case(str(alternate),bwrap,guest,repeat,"boot-image",
                                        deterministic_args,staged,boot_output=repeat/"data"))
                                if all(r["status"]=="BOOT_OUTPUT_HEADERS_OBSERVED" for r in repeats):
                                    diff=image_difference(Path(tmp)/"0/data/boot.art",Path(tmp)/"1/data/boot.art",
                                        [r["output_headers"]["boot.art"] for r in repeats])
                            comparison["determinism"]={**compare_runs(*repeats),"arguments":deterministic_args,
                                "compiler_filter":"verify","force_determinism":True,"runs":repeats,
                                "image_difference":diff,
                                "qemu_sha256":meta["qemu_sha256"],"synthetic_config_sha256":sha(cfg.encode()),
                                "jar_sha256":{n:v["sha256"] for n,v in jars["members"].items()},
                                "staged_sha256":staged,"source_sha":source,"system_sha256":pin}
                        if sha(alternate.read_bytes())!=meta["qemu_sha256"]:
                            raise ValueError("Comparator binary changed")
                    except (OSError,ValueError,RuntimeError,KeyError,subprocess.SubprocessError) as exc:
                        comparison.update(status="REVIEW_REQUIRED",reason=str(exc))
        except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
            boot.update(status="REVIEW_REQUIRED",reason=str(exc),safe_to_flash=False)
    return {"schema":"galwear-r800-wear51-art-startup-v2","source_sha":source,
            "system_sha256":pin,"qemu_cpu":"max","staged_sha256":staged,
            "excluded_system_ld_android_sha256":objects[STUB]["sha256"],
            "synthetic_config_sha256":sha(cfg.encode()),"synthetic_config":cfg,
            "results":rows,"boot_image_probe":boot,
            "status":"DEX2OAT_ARGUMENT_HANDLER_PROBE_ONLY" if passed else "REVIEW_REQUIRED",
            "android_namespace_runtime_verified":False,"art_initialized":False,
            "dex_compilation_verified":False,"hardware_tested":False,"safe_to_flash":False}
