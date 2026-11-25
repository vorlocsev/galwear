#!/usr/bin/env python3
"""Explicit peripheral firmware contract derived from R800 DTS and kernel patch."""
from pathlib import Path
import hashlib
import json
import argparse
import stat

# Active ABOX ext_bin@0 and @1, SRAM/DRAM names in src/dt/r800.dts.
# VTS and BBD names from src/kernel/r800-wearos.patch.
REQUIRED = {
    "fw/calliope_sram.bin": "ABOX SRAM",
    "fw/calliope_dram.bin": "ABOX DRAM",
    "fw/APDV_AUDIO_SLSI.bin": "ABOX ext_bin@0",
    "fw/APSV_AUDIO_SLSI.bin": "ABOX ext_bin@1",
    "fw/vts.bin": "VTS",
    "fw/bbd_patch_mainhub_21091500.txt": "BCM47758 BBD sensor hub",
}
# Disabled ABOX entries and touch-controller upgrade firmware are not copied
# or required by this contract.
EXCLUDED = ("AP_AUDIO_SLSI.bin", "SoundBoosterParam.bin", "dummy.bin", "ztm620.large.fw")
MAX_FILE = 64*1024**2


def check_bytes(name, raw):
    if name not in REQUIRED:
        raise ValueError("Unknown peripheral firmware name")
    if not 0 < len(raw) <= MAX_FILE:
        raise ValueError("Invalid peripheral firmware size")
    if name.endswith("bbd_patch_mainhub_21091500.txt"):
        # Kernel's legacy embedded representation includes the trailing NUL.
        # Do not add it automatically or try to reinterpret a different patch.
        if not raw.endswith(b"\0") or b"\0" in raw[:-1] or any(
                c not in (9,10,13) and not 32 <= c <= 126 for c in raw[:-1]):
            raise ValueError("BBD patch must be printable text with one trailing NUL")
        if len(raw) == 1:
            raise ValueError("Empty BBD patch")
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}


def audit(root):
    root = Path(root).resolve(strict=True)
    files = {}
    for name, purpose in REQUIRED.items():
        p = root/name
        try:
            if p.resolve(strict=False) != p:
                raise ValueError("Symlink in firmware path")
            s = p.lstat()
            if not stat.S_ISREG(s.st_mode) or not 0 < s.st_size <= MAX_FILE:
                raise ValueError("Expected bounded regular firmware")
            with p.open("rb") as stream:
                raw = stream.read(MAX_FILE+1)
            if len(raw) != s.st_size or p.stat().st_mtime_ns != s.st_mtime_ns:
                raise ValueError("Firmware changed during read")
            files[name] = {"purpose":purpose,"status":"STRUCTURE_PASS_ONLY",**check_bytes(name,raw)}
        except FileNotFoundError:
            files[name] = {"purpose":purpose,"status":"MISSING"}
        except (OSError,ValueError) as exc:
            files[name] = {"purpose":purpose,"status":"REJECTED","reason":str(exc)}
    blockers = [n for n,v in files.items() if v["status"]!="STRUCTURE_PASS_ONLY"]
    return {"status":"PERIPHERAL_FIRMWARE_INCOMPLETE" if blockers else "PERIPHERAL_FIRMWARE_STRUCTURE_ONLY",
            "files":files,"blockers":blockers,"excluded":list(EXCLUDED),
            "authenticity_verified":False,"hardware_compatibility_verified":False,
            "safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,required=True)
    a=p.parse_args()
    r=audit(a.root)
    print(json.dumps(r,indent=2,sort_keys=True))
    return 2 if r["blockers"] else 0


if __name__=="__main__":
    raise SystemExit(main())
