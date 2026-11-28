#!/usr/bin/env python3
"""Read-only intake of the selected Pixel Watch 1 Wear OS 5.1 factory ZIP."""
import argparse
import json
import os
from pathlib import Path
import tempfile
import zipfile

from r800_extract_pixel_factory import copy_member, digest, MAX_ARCHIVE, MAX_IMAGE

BUILD="bw1a.251005.003.w1"
DEVICE="r11btwifi"
FACTORY_SHA256="29f1da6fde448bd093160ed0cae0cc431b6647149f136b7bfbcd7fa0afe418e4"
NAMES=("system.img","super.img","vendor.img","product.img","system_ext.img","odm.img","boot.img","vendor_boot.img","init_boot.img","dtbo.img","vbmeta.img")


def extract(archive,output,expected=FACTORY_SHA256):
    archive,output=Path(archive).absolute(),Path(output).absolute()
    if output.exists() or output.is_symlink() or digest(archive)!=expected:
        raise ValueError("Fresh output and pinned factory ZIP required")
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        root=Path(tmp)
        stage=root/"images"
        stage.mkdir()
        inner=root/"inner.zip"
        basename=f"image-{DEVICE}-{BUILD}.zip"
        allowed={basename,f"{DEVICE}-{BUILD}/{basename}"}
        with zipfile.ZipFile(archive) as outer:
            matches=[m for m in outer.infolist() if m.filename.lower() in allowed]
            if len(matches)!=1:
                raise ValueError("Expected unique exact-build inner ZIP")
            nested=copy_member(outer,matches[0],inner,MAX_ARCHIVE)
        images={}
        with zipfile.ZipFile(inner) as z:
            for name in NAMES:
                matches=[m for m in z.infolist() if m.filename==name]
                if len(matches)>1:
                    raise ValueError("Duplicate selected image: "+name)
                if matches:
                    row=copy_member(z,matches[0],stage/name,MAX_IMAGE)
                    with (stage/name).open("rb") as f:
                        head=f.read(4096)
                    row["format"]=("android_sparse" if head[:4]==b"\x3a\xff\x26\xed" else
                                   "raw_ext4" if head[1080:1082]==b"\x53\xef" else
                                   "raw_erofs" if head[1024:1028]==b"\xe2\xe1\xf5\xe0" else
                                   "android_boot_container" if head[:8]==b"ANDROID!" else "unknown_or_container")
                    images[name]=row
        if not ({"system.img","super.img"} & images.keys()) or digest(archive)!=expected:
            raise ValueError("Missing System or changed factory ZIP")
        report={"schema":"galwear-r800-wear51-factory-v1","status":"WEAR51_FACTORY_SELECTED_IMAGES_ONLY",
                "device":DEVICE,"build":BUILD,"factory_sha256":expected,"nested_zip":nested,"images":images,
                "wear_os_version_catalog_target":"5.1","android_catalog_target":15,"api_catalog_target":35,
                "wear_os_runtime_verified":False,"r800_compatibility_verified":False,"hardware_tested":False,"safe_to_flash":False}
        (stage/"factory-evidence.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
        os.rename(stage,output)
    return report


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    a=p.parse_args()
    print(json.dumps(extract(a.archive,a.output),sort_keys=True))
