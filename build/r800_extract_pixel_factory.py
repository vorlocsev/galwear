#!/usr/bin/env python3
"""Extract only system/super/vendor donor images from a verified local Pixel factory ZIP."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import zipfile

FACTORY_SHA256 = "eb4977308b8fe6a25bbe0c4918d95e6e79b9f05ae608f48ac2f04b65c42f0b52"
MAX_ARCHIVE = 8 * 1024**3
MAX_IMAGE = 4 * 1024**3
NAMES = ("system.img", "super.img", "vendor.img")


def digest(path):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= MAX_ARCHIVE:
        raise ValueError("Expected bounded local archive")
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1024*1024), b""):
            h.update(b)
    return h.hexdigest()


def copy_member(z, member, dest, maximum):
    if member.is_dir() or not 0 < member.file_size <= maximum:
        raise ValueError("Invalid archive member size: " + member.filename)
    mode = member.external_attr >> 16
    if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
        raise ValueError("Nonregular archive member")
    h = hashlib.sha256()
    count = 0
    with z.open(member) as inp, dest.open("xb") as out:
        for b in iter(lambda: inp.read(1024*1024), b""):
            count += len(b)
            if count > member.file_size:
                raise ValueError("Member exceeds declared size")
            h.update(b)
            out.write(b)
    if count != member.file_size:
        raise ValueError("Truncated member")
    return {"bytes": count, "sha256": h.hexdigest()}


def extract(archive, output, expected=FACTORY_SHA256):
    archive = archive.absolute()
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists")
    if digest(archive) != expected:
        raise ValueError("Factory ZIP SHA-256 mismatch")
    with tempfile.TemporaryDirectory(dir=output.parent) as temp:
        tmp = Path(temp)
        tree = tmp / "images"
        tree.mkdir()
        inner = tmp / "inner.zip"
        with zipfile.ZipFile(archive) as outer:
            matches = [i for i in outer.infolist() if re.fullmatch(
                r"(?:r11btwifi-rwdc\.230905\.003/)?image-r11btwifi-rwdc\.230905\.003\.zip",
                i.filename, re.I)]
            if len(matches) != 1:
                raise ValueError("Expected unique Bluetooth/Wi-Fi RWDC factory image ZIP")
            nested = copy_member(outer, matches[0], inner, MAX_ARCHIVE)
        files = {}
        with zipfile.ZipFile(inner) as z:
            for name in NAMES:
                matches = [i for i in z.infolist() if i.filename == name]
                if len(matches) > 1:
                    raise ValueError("Duplicate donor image: " + name)
                if matches:
                    files[name] = copy_member(z, matches[0], tree/name, MAX_IMAGE)
                    with (tree/name).open("rb") as f:
                        head = f.read(1082)
                    files[name]["format"] = (
                        "android_sparse" if head[:4] == b"\x3a\xff\x26\xed"
                        else "raw_ext4" if head[1080:1082] == b"\x53\xef"
                        else "unknown_or_container")
        if not ({"system.img", "super.img"} & files.keys()):
            raise ValueError("No system or super donor image")
        if digest(archive) != expected:
            raise ValueError("Factory archive changed during extraction")
        report = {"status": "PIXEL_DONOR_EXTRACTED_ONLY",
                  "factory_sha256": expected, "nested_zip": nested,
                  "images": files, "system_adaptation_verified": False,
                  "vendor_compatibility_verified": False, "safe_to_flash": False}
        (tree/"pixel-evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True))
        os.rename(tree, output)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(extract(a.archive, a.output), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
