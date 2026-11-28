#!/usr/bin/env python3
"""Read-only pins for the NDK r27c tools actually used by GPSBridge.

No compiler execution or download. Observed hashes are not trusted upstream
checksums. Host libraries, other NDK files and the host environment are
outside this selected-tool contract.
"""
import argparse
import json
from pathlib import Path
import re
import stat

from r800_android_userspace_preflight import read_regular
from r800_donor_preflight import digest
from r800_extract_super import require
from r800_stage_adaptation_layer import valid_pin
from r800_gps_provenance import TOOLS, LIMIT

REVISION="27.2.12479018"
BIN=Path("toolchains/llvm/prebuilt/linux-x86_64/bin")
KEYS={"source.properties",*TOOLS}


def observe(root):
    root=Path(root).absolute()
    require(root.resolve(strict=True)==root and root.is_dir(),"Canonical NDK directory required")
    prop=root/"source.properties"
    require(prop.resolve(strict=True)==prop,"Canonical NDK revision file required")
    raw=read_regular(prop,64*1024)
    revisions=re.findall(r"^Pkg\.Revision\s*=\s*([^\r\n]+)$",raw.decode("utf-8"),re.M)
    require([v.strip() for v in revisions]==[REVISION],"Expected unique NDK r27c revision")
    rows={"source.properties":{**digest(prop,64*1024),"resolved":"source.properties"}}
    import hashlib
    require(rows["source.properties"]["sha256"]==hashlib.sha256(raw).hexdigest(),
            "NDK revision changed")
    for name in sorted(TOOLS):
        path=root/BIN/name
        target=path.resolve(strict=True)
        require(target.is_relative_to(root/BIN) and
                stat.S_ISREG(target.lstat().st_mode) and target.stat().st_mode&0o111,
                "NDK tool must resolve to an executable within bin: "+name)
        row=digest(target,LIMIT)
        require(path.resolve(strict=True)==target,"NDK tool target changed: "+name)
        rows[name]={**row,"resolved":target.relative_to(root).as_posix()}
    return rows


def verify(root,pins):
    require(isinstance(pins,dict) and set(pins)==KEYS and
            all(valid_pin(v) for v in pins.values()),"Four explicit NDK file SHA-256 pins required")
    rows=observe(root)
    require({n:r["sha256"] for n,r in rows.items()}==pins,"NDK selected file pin mismatch")
    require(observe(root)==rows,"NDK selected files changed during verification")
    return {"schema":"galwear-r800-ndk-selected-tools-v1",
            "status":"SELECTED_NDK_TOOL_PINS_MATCH_ONLY","revision":REVISION,
            "files":rows,"complete_ndk_verified":False,"host_libraries_verified":False,
            "upstream_authenticity_verified":False,"safe_to_flash":False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk",type=Path,required=True)
    a=parser.parse_args()
    rows=observe(a.ndk)
    print(json.dumps({"status":"OBSERVED_LOCAL_HASHES_ONLY","revision":REVISION,
                      "tools_sha256":{n:r["sha256"] for n,r in rows.items()},
                      "upstream_authenticity_verified":False,"safe_to_flash":False},
                     indent=2,sort_keys=True))


if __name__=="__main__":
    main()
