#!/usr/bin/env python3
"""Read selected donor files with debugfs, never mount or execute an image."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

from r800_vendor_inputs import image_info, MAX_IMAGE
from r800_peripheral_firmware import REQUIRED, check_bytes

MAX_FILE = 64 * 1024**2
HCD = "BCM43012B0_002.001.021.0153.0156.hcd"
# Resolved regular glibc files rather than guest symlinks. Candidate locations
# are explicit; different donor layouts are reported missing, not guessed.
TIZEN = {
    "tizen/libc.so.6": ("/lib/libc-2.24.so", "/usr/lib/libc-2.24.so"),
    "tizen/libdl.so.2": ("/lib/libdl-2.24.so", "/usr/lib/libdl-2.24.so"),
    "tizen/libpthread.so.0": ("/lib/libpthread-2.24.so", "/usr/lib/libpthread-2.24.so"),
    "tizen/ld-linux.so.3": ("/lib/ld-2.24.so", "/usr/lib/ld-2.24.so"),
    "payload/fw/bt/" + HCD: ("/usr/lib/firmware/" + HCD,),
    "payload/fw/bcmdhd_sta.bin": ("/usr/lib/firmware/bcmdhd_sta.bin",),
    "payload/fw/nvram_net.txt": ("/usr/lib/firmware/nvram_net.txt",),
    "payload/fw/bcmdhd_clm.blob": ("/usr/lib/firmware/bcmdhd_clm.blob",),
}
TIZEN.update({"payload/"+name: ("/usr/lib/firmware/"+name.removeprefix("fw/"),)
              for name in REQUIRED})
VENDOR_NAMES = (
    "lib/libeffectsconfig.so",
    "bin/hw/android.hardware.sensors@1.0-service",
    "lib/hw/android.hardware.sensors@1.0-impl.so",
    "lib/android.hardware.sensors@1.0.so",
    "bin/hw/android.hardware.gnss@1.0-service",
    "lib/hw/android.hardware.gnss@1.0-impl.so",
    "lib/android.hardware.gnss@1.0.so",
    "etc/init/android.hardware.gnss@1.0-service.rc",
    "bin/hw/android.hardware.wifi@1.0-service",
    "etc/init/android.hardware.wifi@1.0-service.rc",
    "bin/hw/wpa_supplicant", "etc/init/wpa_supplicant.rc",
    "lib/android.hardware.wifi@1.0.so",
    "lib/android.hardware.wifi.supplicant@1.0.so",
)
TIZEN_GPS = {name: paths for name, paths in TIZEN.items() if name.startswith("tizen/")}
PROFILES = {"tizen": TIZEN, "tizen-gps": TIZEN_GPS,
            "vendor": {"vendor/"+n: ("/"+n,) for n in VENDOR_NAMES}}


def command(tool, image, request, cwd=None):
    # debugfs opens read-only by default. No -w, no shell, no guest execution.
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run([tool, "-R", request, str(image)], cwd=cwd,
                          env=env, capture_output=True, text=True, timeout=60,
                          check=True)


def locate(tool, image, guest):
    if not re.fullmatch(r"/[A-Za-z0-9_./@+-]+", guest) or ".." in guest.split("/"):
        raise ValueError("Invalid guest path")
    result = command(tool, image, "stat " + guest)
    if "File not found" in result.stderr:
        return None
    match = re.search(r"Inode:\s+(\d+)\s+Type:\s+(\w+)", result.stdout)
    size = re.search(r"\bSize:\s+(\d+)", result.stdout)
    if not match or not size or match[2] != "regular":
        raise ValueError("Expected regular donor file: " + guest)
    length = int(size[1])
    if not 0 < length <= MAX_FILE:
        raise ValueError("Donor file size out of bounds: " + guest)
    return int(match[1]), length


def snapshot_image(image, snapshot, expected_sha):
    """Copy bounded bytes once; debugfs never reopens the mutable donor path."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    initial = image.lstat()
    if not stat.S_ISREG(initial.st_mode) or not 0 < initial.st_size <= MAX_IMAGE:
        raise ValueError("Expected bounded regular donor image")

    def identity(s):
        return (s.st_dev, s.st_ino, s.st_mode, s.st_size,
                s.st_mtime_ns, s.st_ctime_ns)

    digest = hashlib.sha256()
    count = 0
    with os.fdopen(os.open(image, flags), "rb") as src:
        if identity(os.fstat(src.fileno())) != identity(initial):
            raise ValueError("Donor changed before snapshot")
        with snapshot.open("xb") as dst:
            for block in iter(lambda: src.read(1024 * 1024), b""):
                count += len(block)
                if count > initial.st_size:
                    raise ValueError("Donor size changed")
                digest.update(block)
                dst.write(block)
        if identity(os.fstat(src.fileno())) != identity(initial):
            raise ValueError("Donor changed during snapshot")
    if count != initial.st_size or identity(image.lstat()) != identity(initial):
        raise ValueError("Donor changed during snapshot")
    if digest.hexdigest() != expected_sha:
        raise ValueError("Input image SHA-256 mismatch")
    snapshot.chmod(0o400)
    return identity(initial)


def extract(image, output, profile, expected_sha):
    image, output = Path(image).absolute(), Path(output).absolute()
    if profile not in PROFILES or not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise ValueError("Expected donor profile and SHA-256")
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists")
    tool = shutil.which("debugfs")
    if not tool:
        raise ValueError("Install e2fsprogs (debugfs)")
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        scratch = Path(tmp)
        snapshot = scratch/"donor.img"
        source_identity = snapshot_image(image, snapshot, expected_sha)
        before = image_info(snapshot)
        if before["sha256"] != expected_sha:
            raise ValueError("Snapshot SHA-256 mismatch")
        tree = scratch/"files"
        tree.mkdir()
        files = {}
        for dest, candidates in PROFILES[profile].items():
            matches = []
            for guest in candidates:
                found = locate(tool, snapshot, guest)
                if found is not None:
                    matches.append((guest, found))
            if not matches:
                files[dest] = {"status": "MISSING", "candidates": list(candidates)}
                continue
            if len({m[1][0] for m in matches}) > 1:
                files[dest] = {"status": "AMBIGUOUS", "candidates": [m[0] for m in matches]}
                continue
            guest, (inode, length) = matches[0]
            target = scratch/"member"
            command(tool, snapshot, "dump <%d> member" % inode, cwd=scratch)
            st = target.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_size != length:
                raise ValueError("Extracted donor size mismatch: " + guest)
            raw = target.read_bytes()
            if dest.removeprefix("payload/") in REQUIRED:
                check_bytes(dest.removeprefix("payload/"), raw)
            destpath = tree/dest
            destpath.parent.mkdir(parents=True, exist_ok=True)
            os.rename(target, destpath)
            destpath.chmod(0o644)
            files[dest] = {"status":"EXTRACTED", "source":guest,
                           "bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
        current = image.lstat()
        if (current.st_dev, current.st_ino, current.st_mode, current.st_size,
                current.st_mtime_ns, current.st_ctime_ns) != source_identity:
            raise ValueError("Donor image changed")
        if image_info(snapshot) != before:
            raise ValueError("Donor snapshot changed")
        report = {"status":"EXT4_DONOR_EXTRACTION_ONLY","profile":profile,
                  "image_sha256":expected_sha,"snapshot_verified":True,"files":files,
                  "missing_or_ambiguous":[n for n,v in files.items() if v["status"]!="EXTRACTED"],
                  "donor_compatibility_verified":False,"xattrs_preserved":False,
                  "safe_to_flash":False}
        (tree/"ext4-evidence.json").write_text(json.dumps(report,indent=2,sort_keys=True))
        os.rename(tree,output)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--profile",choices=PROFILES,required=True)
    p.add_argument("--sha256",required=True)
    a=p.parse_args()
    report=extract(a.image,a.output,a.profile,a.sha256)
    print(json.dumps(report,sort_keys=True))
    return 2 if report["missing_or_ambiguous"] else 0


if __name__=="__main__":
    raise SystemExit(main())
