#!/usr/bin/env python3
"""Compile synthetic graphics providers and test isolated ARM32 Bionic dlsym."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from r800_hal_dlopen_probe import (ROOT, RUNTIME, SYSTEM_RUNTIME_LIBS, check,
    sha, runtime_dependencies, HAL_COMPILE_LIBS)
from r800_android_userspace_preflight import read_regular
from r800_graphics_inventory import entrypoint_evidence

LIBS = {
    "libEGL_galwear_fixture.so": ("FIXTURE_EGL",),
    "libGLESv2_galwear_fixture.so": ("FIXTURE_GLES",),
    "libGLES_galwear_fixture.so": ("FIXTURE_EGL","FIXTURE_GLES"),
    "libGLESv2_galwear_incomplete.so": ("FIXTURE_GLES","FIXTURE_INCOMPLETE"),
    "libGLES_galwear_private.so": ("FIXTURE_EGL","FIXTURE_GLES"),
}
PRIVATE = "libGLES_galwear_private.so"
INCOMPLETE = "libGLESv2_galwear_incomplete.so"
MARKER = "EGL_LINK_FIXTURE_PASS cycles=4 split=1 combined=1 missing=1 private_denials=2 recovery=1 fd_stable=1"


def config():
    public = ":".join(name for name in LIBS if name != PRIVATE)
    return ("dir.fixture = /system/bin\n[fixture]\n"
            "additional.namespaces = vendor\n"
            "namespace.default.isolated = true\n"
            "namespace.default.search.paths = /apex/com.android.runtime/lib/bionic:/system/lib\n"
            "namespace.default.links = vendor\n"
            "namespace.default.link.vendor.shared_libs = "+public+"\n"
            "namespace.vendor.isolated = true\n"
            "namespace.vendor.search.paths = /vendor/lib/egl\n"
            "namespace.vendor.links = default\n"
            "namespace.vendor.link.default.shared_libs = libc.so:libdl.so:libm.so:liblog.so:libc++.so:ld-android.so\n")


def run(ndk, runtime, manifest, output, source_sha):
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("Expected exact source SHA")
    if os.geteuid() == 0:
        raise ValueError("Non-root execution required")
    if not re.search(r"^Pkg.Revision\s*=\s*27\.2\.12479018\s*$",
                     (ndk/"source.properties").read_text(), re.M):
        raise ValueError("Expected NDK r27c")
    qemu, bwrap = shutil.which("qemu-arm-static"), shutil.which("bwrap")
    if not qemu or not bwrap:
        raise ValueError("Static QEMU and bubblewrap required")
    pins = json.loads(read_regular(manifest,1024*1024))
    if set(pins) != set(RUNTIME) or any(not re.fullmatch(r"[0-9a-f]{64}",v) for v in pins.values()):
        raise ValueError("Invalid runtime manifest")
    output.mkdir(exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="r800-egl-link-") as tmp:
        root=Path(tmp)/"guest"
        for name in ("system/bin","system/lib","vendor/lib/egl","dev","proc","linkerconfig",
                     "apex/com.android.runtime/bin","apex/com.android.runtime/lib/bionic"):
            (root/name).mkdir(parents=True,exist_ok=True)
        (root/"qemu").touch()
        linker_soname=check(runtime/"linker")[1]["soname"]
        for name in RUNTIME:
            raw,info=check(runtime/name,name!="linker")
            if sha(raw)!=pins[name]:
                raise ValueError("Runtime digest mismatch: "+name)
            runtime_dependencies(name,info,linker_soname)
            rel=("apex/com.android.runtime/bin/linker" if name=="linker" else
                 "system/lib/"+name if name in SYSTEM_RUNTIME_LIBS else
                 "apex/com.android.runtime/lib/bionic/"+name)
            (root/rel).write_bytes(raw)
            (root/rel).chmod(0o555 if name=="linker" else 0o444)
        (root/"system/bin/linker").symlink_to("../../apex/com.android.runtime/bin/linker")
        cc=ndk/"toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi28-clang"
        flags=[str(cc),"-std=gnu11","-Wall","-Wextra","-Werror","-O2","-Wl,--no-undefined"]
        fixtures={}
        for name,defines in LIBS.items():
            target=root/"vendor/lib/egl"/name
            subprocess.run(flags+["-shared","-fPIC",*("-D"+d for d in defines),
                str(ROOT/"src/initramfs/r800-egl-fixture.c"),"-Wl,-soname,"+name,"-o",str(target)],
                check=True,timeout=60)
            raw,info=check(target,True)
            if not set(info["needed"])<=HAL_COMPILE_LIBS:
                raise ValueError("Unexpected graphics fixture dependencies")
            exports=entrypoint_evidence("/vendor/lib/egl/"+name,info)
            if name==INCOMPLETE:
                if exports["missing_or_unconfirmed"]!=["glUseProgram"]:
                    raise ValueError("Incomplete fixture identity mismatch")
            elif exports["status"]!="STATIC_MINIMUM_EXPORTS_ONLY":
                raise ValueError("Fixture exports incomplete: "+name)
            fixtures[name]={"sha256":sha(raw),"entrypoints":exports}
            target.chmod(0o444)
        probe=root/"system/bin/egl-probe"
        subprocess.run(flags+[str(ROOT/"src/initramfs/r800-egl-probe.c"),"-ldl","-o",str(probe)],
                       check=True,timeout=60)
        raw,info=check(probe)
        if not set(info["needed"])<=HAL_COMPILE_LIBS:
            raise ValueError("Unexpected probe dependencies")
        probe_sha=sha(raw)
        probe.chmod(0o555)
        cfg=root/"linkerconfig/ld.config.txt"
        cfg.write_text(config())
        result=subprocess.run([bwrap,"--unshare-all","--die-with-parent","--new-session",
            "--clearenv","--ro-bind",str(root),"/","--ro-bind",qemu,"/qemu",
            "--dev","/dev","--proc","/proc","--chdir","/",
            "/qemu","-cpu","cortex-a15","-L","/","/system/bin/egl-probe"],
            capture_output=True,text=True,timeout=60)
        if result.returncode or result.stdout.strip()!=MARKER:
            raise ValueError("Synthetic EGL link failed: "+str(result.returncode)+" "+result.stderr[:4000])
        report={"status":"ARM32_SYNTHETIC_EGL_LINK_ONLY","source_sha":source_sha,
                "runtime_sha256":pins,"fixture_libraries":fixtures,"probe_sha256":probe_sha,
                "namespace_config_sha256":sha(cfg.read_bytes()),"marker":MARKER,
                "synthetic_dlsym_verified":True,"donor_driver_loaded":False,
                "egl_initialized":False,"surfaceflinger_started":False,
                "gpu_hardware_verified":False,"safe_to_flash":False}
        (output/"egl-link-evidence.json").write_text(json.dumps(report,sort_keys=True)+"\n")
        print(json.dumps(report,sort_keys=True))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("ndk","runtime","runtime-manifest","output"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--source-sha",required=True)
    a=p.parse_args()
    run(a.ndk,a.runtime,a.runtime_manifest,a.output,a.source_sha)

if __name__=="__main__":
    main()
