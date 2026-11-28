#!/usr/bin/env python3
"""Bind a complete local mkassets output to a development device layer."""
import hashlib
import json
from pathlib import Path
import re
import stat

from r800_android_userspace_preflight import read_regular
from r800_payload_candidate import ASSET_SIZES
from r800_verify_tizen_stage import unique_keys
from r800_extract_super import require

ASSETS={"r800dev/"+n:"0o644" for n in ASSET_SIZES}
MANIFEST="assets-evidence.json"


def pin_ok(value):
    return isinstance(value,str) and re.fullmatch(r"[a-f0-9]{64}",value) is not None


def load_assets(root,pin):
    root=Path(root).absolute()
    require(root.resolve(strict=True)==root and root.is_dir(),"Canonical asset directory required")
    require(pin_ok(pin),"Explicit asset manifest SHA-256 required")
    raw=read_regular(root/MANIFEST,1024*1024)
    require(hashlib.sha256(raw).hexdigest()==pin,"Asset manifest pin mismatch")
    rows=json.loads(raw,object_pairs_hook=unique_keys)
    require(set(rows)==set(ASSET_SIZES),"Asset inventory mismatch")
    seen=set()
    for path in root.rglob("*"):
        rel=path.relative_to(root).as_posix()
        st=path.lstat()
        if stat.S_ISDIR(st.st_mode):
            require(rel=="charger","Unexpected asset directory")
        else:
            require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
                    rel in set(ASSET_SIZES)|{MANIFEST},"Unexpected asset entry")
            seen.add(rel)
    require(seen==set(ASSET_SIZES)|{MANIFEST},"Incomplete asset tree")
    result={}
    for name,size in ASSET_SIZES.items():
        row=rows[name]
        data=read_regular(root/name,size)
        require(len(data)==size and row=={"bytes":size,"sha256":hashlib.sha256(data).hexdigest()},
                "Asset bytes or dimensions mismatch: "+name)
        if name=="splash.raw":
            require(all(v==255 for v in data[3::4]),"Splash BGRA alpha must be opaque")
        result["r800dev/"+name]=data
    require(read_regular(root/MANIFEST,1024*1024)==raw,"Asset manifest changed")
    return result


def asset_modes(report,files):
    """Optional legacy asset-free tree; never permit a partial asset inventory."""
    present=set(files)&set(ASSETS)
    pin=report.get("assets_manifest_sha256")
    require((not present and pin is None) or (present==set(ASSETS) and pin_ok(pin)),
            "Incomplete display asset binding")
    for path in present:
        row=files[path]
        require(row.get("mode")=="0o644" and row.get("bytes")==ASSET_SIZES[path.removeprefix("r800dev/")],
                "Invalid display asset metadata: "+path)
    return ASSETS if present else {}
