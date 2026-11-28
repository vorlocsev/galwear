#!/usr/bin/env python3
"""Compare GalWear's legacy graphics header ABI to pinned Android 11 AOSP."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
LIBHARDWARE = "1ff69d7299fc441d03b77df5134f3e9bdae50622"
SYSTEM_CORE = "348efca472d810d3152568913da41a081893a4e3"
# Exact Git object IDs, independently retrieved from Android 11 r48.
HEADERS = {
    "hardware/hardware.h": ("hardware_libhardware", LIBHARDWARE, "include/hardware/hardware.h", "bf076f6c34cddcd352c241c93147d56604f4a581"),
    "hardware/hwcomposer.h": ("hardware_libhardware", LIBHARDWARE, "include/hardware/hwcomposer.h", "9eb1aafbed0c0cb4dbd5c71613c0dd179b4aead9"),
    "hardware/hwcomposer_defs.h": ("hardware_libhardware", LIBHARDWARE, "include/hardware/hwcomposer_defs.h", "3823765f8d23d1814c9f31603c3b07ed5fd456e1"),
    "hardware/gralloc.h": ("hardware_libhardware", LIBHARDWARE, "include/hardware/gralloc.h", "10a153c01217083a63f622cdc099f80745bf00d8"),
    "hardware/fb.h": ("hardware_libhardware", LIBHARDWARE, "include/hardware/fb.h", "65720a39316563638bb7a1390b561c4436bcccdf"),
    "cutils/native_handle.h": ("system_core", SYSTEM_CORE, "libcutils/include/cutils/native_handle.h", "4f07456054d0a35b17eddf64ff6b3ce49895672c"),
    "system/graphics.h": ("system_core", SYSTEM_CORE, "libsystem/include/system/graphics.h", "1b6060a4edc650bd98729e6f5a8282f94070f666"),
    "system/graphics-base.h": ("system_core", SYSTEM_CORE, "libsystem/include/system/graphics-base.h", "92ee077a65e5914ff9c9b8a35a84d0d92f4b0009"),
    "system/graphics-sw.h": ("system_core", SYSTEM_CORE, "libsystem/include/system/graphics-sw.h", "9e1a88e9e395b3068bf36d7a8a600932ad0efb39"),
    "system/graphics-base-v1.0.h": ("system_core", SYSTEM_CORE, "libsystem/include/system/graphics-base-v1.0.h", "44913cc61f25a1cdf7ac3d3413e049212569f08a"),
    "system/graphics-base-v1.1.h": ("system_core", SYSTEM_CORE, "libsystem/include/system/graphics-base-v1.1.h", "f95b9ba213f65cf924353fa9606592eb9e3189f3"),
    "system/graphics-base-v1.2.h": ("system_core", SYSTEM_CORE, "libsystem/include/system/graphics-base-v1.2.h", "2194f5ea8645953b55bdcbb2db2942853219697f"),
}
TYPES = {
    "native_handle_t": ("version","numFds","numInts","data"),
    "hw_module_t": ("tag","module_api_version","hal_api_version","id","methods","dso"),
    "hw_device_t": ("tag","version","module","close"),
    "hwc_layer_1_t": ("compositionType","hints","flags","handle","transform","blending",
                      "sourceCropf","displayFrame","visibleRegionScreen","acquireFenceFd",
                      "releaseFenceFd","planeAlpha","surfaceDamage"),
    "hwc_display_contents_1_t": ("retireFenceFd","outbuf","outbufAcquireFenceFd","flags","numHwLayers","hwLayers"),
    "hwc_composer_device_1_t": ("common","prepare","set","eventControl","setPowerMode","query",
                               "registerProcs","dump","getDisplayConfigs","getDisplayAttributes",
                               "getActiveConfig","setActiveConfig","setCursorPositionAsync"),
    "hwc_procs_t": ("invalidate","vsync","hotplug"),
    "gralloc_module_t": ("common","registerBuffer","unregisterBuffer","lock","unlock","perform",
                         "lock_ycbcr","lockAsync","unlockAsync","lockAsync_ycbcr"),
    "alloc_device_t": ("common","alloc","free","dump"),
}
CONSTANTS = ("HWC_DEVICE_API_VERSION_1_4","HWC_FRAMEBUFFER_TARGET","HWC_OVERLAY",
             "HWC_GEOMETRY_CHANGED","HWC_BLENDING_NONE","HWC_BLENDING_PREMULT",
             "HWC_BLENDING_COVERAGE","HWC_POWER_MODE_NORMAL","HWC_POWER_MODE_OFF",
             "HAL_PIXEL_FORMAT_RGBA_8888","HAL_PIXEL_FORMAT_RGBX_8888","HAL_PIXEL_FORMAT_BGRA_8888",
             "GRALLOC_USAGE_SW_READ_OFTEN","GRALLOC_USAGE_HW_COMPOSER","HARDWARE_MODULE_TAG")


def git_blob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()


def expressions():
    result = {"pointer_bytes": "sizeof(void*)"}
    for typ, members in TYPES.items():
        result[typ+".size"] = "sizeof("+typ+")"
        result[typ+".align"] = "_Alignof("+typ+")"
        for member in members:
            result[typ+"."+member] = "offsetof("+typ+","+member+")"
    result.update({name:name for name in CONSTANTS})
    return result


def compile_layout(cc, objcopy, include, work, name, expr):
    source, obj, raw = (work/(name+suffix) for suffix in (".c",".o",".bin"))
    source.write_text("#include <stddef.h>\n#include <stdint.h>\n#include <hardware/hwcomposer.h>\n"
                      "__attribute__((used,section(\".galwear_abi\"))) const uint32_t layout[]={\n"+
                      ",\n".join(expr.values())+"\n};\n")
    subprocess.run([str(cc),"-std=gnu11","-Werror=implicit-function-declaration",
                    "-I"+str(include),"-c",str(source),"-o",str(obj)],check=True,timeout=60)
    subprocess.run([str(objcopy),"--dump-section",".galwear_abi="+str(raw),str(obj),
                    str(work/(name+"-copy.o"))],check=True,timeout=30)
    values=struct.unpack("<"+"I"*len(expr),raw.read_bytes())
    return dict(zip(expr,values))


def run(ndk, output, source_sha):
    if not re.fullmatch("[0-9a-f]{40}",source_sha):
        raise ValueError("Exact source SHA required")
    if not re.search(r"^Pkg.Revision\s*=\s*27\.2\.12479018\s*$",
                     (ndk/"source.properties").read_text(),re.M):
        raise ValueError("Expected NDK r27c")
    output.mkdir(exist_ok=False)
    upstream=output/"upstream"
    local=ROOT/"src/hal/include"
    provenance={}
    for dest,(repo,commit,path,expected) in HEADERS.items():
        target=upstream/dest
        target.parent.mkdir(parents=True,exist_ok=True)
        url="https://raw.githubusercontent.com/aosp-mirror/platform_"+repo+"/"+commit+"/"+path
        subprocess.run(["curl","--fail","--location","--retry","3","--max-time","90",
                        "--max-filesize","1048576",url,"-o",str(target)],check=True,timeout=120)
        raw=target.read_bytes()
        if git_blob(raw)!=expected:
            raise ValueError("Pinned AOSP blob mismatch: "+dest)
        local_blob=git_blob((local/dest).read_bytes()) if (local/dest).is_file() else None
        provenance[dest]={"aosp_blob":expected,"local_blob":local_blob,"identical":local_blob==expected}
    bin_dir=ndk/"toolchains/llvm/prebuilt/linux-x86_64/bin"
    expr=expressions()
    results={}
    matched=True
    for abi,prefix,pointer in (("arm","armv7a-linux-androideabi28",4),
                               ("arm64","aarch64-linux-android28",8)):
        a=compile_layout(bin_dir/(prefix+"-clang"),bin_dir/"llvm-objcopy",upstream,output,abi+"-aosp",expr)
        b=compile_layout(bin_dir/(prefix+"-clang"),bin_dir/"llvm-objcopy",local,output,abi+"-local",expr)
        diffs={k:{"aosp":a[k],"local":b[k]} for k in expr if a[k]!=b[k]}
        if a["pointer_bytes"]!=pointer or b["pointer_bytes"]!=pointer:
            raise ValueError("Wrong target pointer size")
        if abi=="arm" and (a["hwc_layer_1_t.size"]!=96 or a["hwc_display_contents_1_t.hwLayers"]!=20):
            raise ValueError("Unexpected AOSP HWC ARM32 layout")
        results[abi]={"aosp":a,"local":b,"differences":diffs}
        matched=matched and not diffs
    report={"status":"AOSP11_LEGACY_GRAPHICS_LAYOUT_ONLY" if matched else "REVIEW_REQUIRED",
            "source_sha":source_sha,"aosp_libhardware_commit":LIBHARDWARE,"aosp_system_core_commit":SYSTEM_CORE,
            "header_provenance":provenance,"fields_per_abi":len(expr),"layouts":results,
            "donor_layer_stride_100_verified":False,"mapper_2_1_verified":False,
            "donor_runtime_verified":False,"hardware_tested":False,"safe_to_flash":False}
    (output/"graphics-abi-evidence.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(report["status"],"fields_per_abi="+str(len(expr)),
          "arm_diffs="+str(len(results["arm"]["differences"])),
          "arm64_diffs="+str(len(results["arm64"]["differences"])),
          "aosp_arm_layer="+str(results["arm"]["aosp"]["hwc_layer_1_t.size"]))
    if not matched:
        raise ValueError("Legacy graphics layout mismatch")


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--source-sha",required=True)
    args=parser.parse_args()
    run(args.ndk,args.output,args.source_sha)
