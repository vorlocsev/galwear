#!/usr/bin/env python3
"""Import the official Android 11 AOSP ARM64 GSI ZIP obtained by the operator.

No automatic acceptance of Google's download terms; no network, flashing,
redistribution or upload of donor data. The published ZIP hash is pinned.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat
import tempfile
import zipfile

from r800_android_runtime_extract import digest, extract, MAX_SYSTEM

BUILD = "RP1A.200720.009"
ZIP_NAME = "aosp_arm64-exp-RP1A.200720.009-6720564-019b517d.zip"
ZIP_SHA256 = "019b517dad4c3ee475302b4e8e96fe35934968a083c4edfe387611f08e2f71bc"
SOURCE = "https://developer.android.com/topic/generic-system-image/releases#android_11_gsis"
MAX_ZIP = 4 * 1024**3


def unpack_system(zip_path: Path, dest: Path) -> str:
    with zipfile.ZipFile(zip_path) as z:
        candidates = [e for e in z.infolist() if e.filename == "system.img"]
        if len(candidates) != 1:
            raise ValueError("Expected exactly one root system.img")
        entry = candidates[0]
        mode = entry.external_attr >> 16
        if entry.is_dir() or stat.S_IFMT(mode) not in (0, stat.S_IFREG):
            raise ValueError("system.img is not a regular ZIP member")
        if not 0 < entry.file_size <= MAX_SYSTEM:
            raise ValueError("system.img exceeds size bounds")
        h = hashlib.sha256()
        remaining = entry.file_size
        with z.open(entry) as src, dest.open("xb") as out:
            while remaining:
                block = src.read(min(1024 * 1024, remaining))
                if not block:
                    raise ValueError("Truncated system.img")
                out.write(block)
                h.update(block)
                remaining -= len(block)
            if src.read(1):
                raise ValueError("Unexpected system.img trailing bytes")
        return h.hexdigest()


def import_gsi(archive: Path, out: Path, readelf: str = "readelf") -> dict:
    if digest(archive, MAX_ZIP) != ZIP_SHA256:
        raise ValueError("Official GSI ZIP SHA-256 mismatch")
    with tempfile.TemporaryDirectory(prefix="galwear-gsi-") as temp:
        image = Path(temp) / "system.img"
        image_sha = unpack_system(archive, image)
        if digest(archive, MAX_ZIP) != ZIP_SHA256:
            raise ValueError("GSI ZIP changed during import")
        report = extract(image, image_sha, out, readelf)
    return {**report, "status": "PINNED_GSI_RUNTIME_EXTRACTED_STATIC_ONLY",
            "android_build": BUILD, "android_api": 30, "architecture": "arm64",
            "official_zip_name": ZIP_NAME, "official_zip_sha256": ZIP_SHA256,
            "published_zip_digest_matched": True, "source": SOURCE,
            "system_image_sha256": image_sha, "apex_signature_verified": False,
            "dynamic_android_linker_tested": False, "safe_to_flash": False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--readelf", default="readelf")
    a = p.parse_args()
    try:
        report = import_gsi(a.archive, a.out, a.readelf)
        rc = 0
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        report = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(report["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
