#!/usr/bin/env python3
"""Stage the same validated ARM32 HAL bytes for both candidate build trees."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import os
from r800_vendor_inputs import file_info

HALS = ("audio.primary.r800.so", "gps.r800.so", "hwcomposer.r800.so",
        "lights.r800.so", "sensors.r800.so")
PAYLOAD = tuple(name for name in HALS if name != "lights.r800.so")
CONFIGS = ("etc/init/init.r800.rc", "etc/fstab.r800", "ueventd.rc",
           "etc/vintf/manifest.xml", "audio/audio_policy_configuration.xml",
           "sensors/android.hardware.sensors@1.0-service.rc")


def stage(hal_dir, vendor_sources, output):
    hal_dir = hal_dir.resolve(strict=True)
    vendor_sources = vendor_sources.resolve(strict=True)
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists")
    if output.resolve().is_relative_to(hal_dir) or output.resolve().is_relative_to(vendor_sources):
        raise ValueError("Output must be outside input trees")
    manifest = {}
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        root = Path(tmp) / "stage"
        overlay = root / "vendor-overlay"
        hwc = root / "payload" / "hwc"
        overlay.mkdir(parents=True)
        hwc.mkdir(parents=True)
        for name in HALS:
            src = hal_dir / name
            info = file_info(src, True)
            data = src.read_bytes()
            if hashlib.sha256(data).hexdigest() != info["sha256"]:
                raise ValueError("HAL changed during staging: " + name)
            for dest in [overlay / name] + ([hwc / name] if name in PAYLOAD else []):
                dest.write_bytes(data)
                dest.chmod(0o644)
                if file_info(dest, True) != info:
                    raise ValueError("Staged HAL mismatch: " + name)
            manifest[name] = info
        for name in CONFIGS:
            src = vendor_sources / name
            if src.resolve(strict=True) != src:
                raise ValueError("Symlink in vendor configuration path: " + name)
            info = file_info(src)
            data = src.read_bytes()
            if hashlib.sha256(data).hexdigest() != info["sha256"]:
                raise ValueError("Vendor configuration changed: " + name)
            dest = overlay / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            dest.chmod(0o644)
        report = {"status": "HAL_STAGE_BYTES_MATCH", "modules": manifest,
                  "vendor_modules": list(HALS), "payload_modules": list(PAYLOAD),
                  "runtime_verified": False, "safe_to_flash": False}
        (root / "hal-stage-evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True))
        # The caller supplies a new, private working directory.
        os.rename(root, output)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ("hal-dir", "vendor-sources", "output"):
        p.add_argument("--" + arg, type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(stage(args.hal_dir, args.vendor_sources, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
