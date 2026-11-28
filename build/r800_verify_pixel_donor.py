#!/usr/bin/env python3
"""Re-extract pinned Pixel Watch factory images and verify local donor copies.

This proves byte correspondence to the supplied hash-pinned archive only.
No AVB signature validation, adaptation, device access or guest execution.
"""
import argparse
import json
from pathlib import Path
import tempfile

from r800_extract_pixel_factory import FACTORY_SHA256, MAX_IMAGE, NAMES, extract
from r800_donor_preflight import digest
from r800_android_userspace_preflight import read_regular
from r800_graphics_donor_binding import checkout_sha


def verify(archive, extracted, source_sha, expected=FACTORY_SHA256):
    checkout_sha(source_sha)
    extracted = Path(extracted)
    if extracted.is_symlink() or not extracted.is_dir():
        raise ValueError("Expected local nonsymlink extraction directory")
    with tempfile.TemporaryDirectory(prefix="r800-pixel-verify-") as temp:
        fresh = Path(temp) / "repeat"
        reference = extract(archive, fresh, expected)
        manifest_path = extracted / "pixel-evidence.json"
        if manifest_path.is_symlink():
            raise ValueError("Symlink in extracted manifest")
        recorded = json.loads(read_regular(manifest_path, 1024*1024))
        if recorded != reference:
            raise ValueError("Extracted manifest differs from repeat extraction")
        images = reference["images"]
        names = set(images)
        if not names <= set(NAMES) or not names & {"system.img", "super.img"}:
            raise ValueError("Invalid extracted partition inventory")
        if {p.name for p in extracted.iterdir()} != names | {"pixel-evidence.json"}:
            raise ValueError("Extracted directory inventory mismatch")
        for name, entry in images.items():
            wanted = {key: entry[key] for key in ("bytes", "sha256")}
            if digest(extracted / name, MAX_IMAGE) != wanted:
                raise ValueError("Extracted partition digest mismatch: " + name)
            if digest(fresh / name, MAX_IMAGE) != wanted:
                raise ValueError("Repeat partition digest mismatch: " + name)
        if json.loads(read_regular(manifest_path, 1024*1024)) != recorded:
            raise ValueError("Extracted manifest changed")
    checkout_sha(source_sha)
    return {
        "schema": "galwear-r800-pixel-donor-manifest-v1",
        "source_sha": source_sha,
        "status": "PIXEL_FACTORY_REPEAT_EXTRACTION_MATCH",
        "device": "r11btwifi", "build_id": "RWDC.230905.003",
        "factory_sha256": expected, "documented_factory_pin_matched": expected == FACTORY_SHA256,
        "nested_zip": reference["nested_zip"], "images": images,
        "repeat_extraction_matched": True,
        "archive_signature_verified": False, "avb_verified": False,
        "wear_os_runtime_verified": False, "r800_compatibility_verified": False,
        "hardware_tested": False, "safe_to_flash": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--extracted", type=Path, required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if a.output.resolve().is_relative_to(a.extracted.resolve()):
        p.error("Report must be outside extracted directory")
    report = verify(a.archive, a.extracted, a.source_sha)
    with a.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(report["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
