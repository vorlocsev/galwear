#!/usr/bin/env python3
"""Observe the immutable-ID phh v313 release asset, extract only ARM32 runtime.

No guest execution. Upstream does not publish a digest for this legacy asset;
the observed hash is evidence for later review, not independent verification.
"""
import argparse
import hashlib
import json
import lzma
from pathlib import Path
import stat
import tempfile

from r800_arm32_runtime_extract import extract

RELEASE_ID = 50839463
ASSET_ID = 46298761
ASSET_SIZE = 364782672
ASSET_NAME = "system-roar-arm32_binder64-ab-vanilla.img.xz"
SOURCE = "https://github.com/phhusson/treble_experimentations/releases/download/v313/" + ASSET_NAME
MAX_IMAGE = 4*1024**3


def expand(archive, output, expected_size=ASSET_SIZE, limit=MAX_IMAGE):
    initial = archive.lstat()
    if not stat.S_ISREG(initial.st_mode) or initial.st_size != expected_size:
        raise ValueError("Release asset size mismatch")
    compressed = hashlib.sha256()
    image = hashlib.sha256()
    total = 0
    # LZMAFile handles concatenated streams; the decompressed bytes are bounded.
    with archive.open("rb") as stream:
        for block in iter(lambda: stream.read(1024*1024), b""):
            compressed.update(block)
        stream.seek(0)
        with lzma.LZMAFile(stream) as src, output.open("xb") as dst:
            while block := src.read(1024*1024):
                total += len(block)
                if total > limit:
                    raise ValueError("Expanded system image exceeds limit")
                image.update(block)
                dst.write(block)
        stream.seek(0)
        after = hashlib.sha256()
        for block in iter(lambda: stream.read(1024*1024), b""):
            after.update(block)
    current = archive.lstat()
    if (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) != (
            current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns) or (
            after.digest() != compressed.digest()):
        raise ValueError("Release asset changed")
    if not total:
        raise ValueError("Empty expanded image")
    return {"asset_sha256_observed": compressed.hexdigest(), "system_sha256": image.hexdigest(),
            "system_bytes": total}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(exist_ok=False)
    report = {"status": "REFERENCE_ASSET_OBSERVATION_ONLY", "release_id": RELEASE_ID,
              "asset_id": ASSET_ID, "asset_name": ASSET_NAME, "asset_bytes": ASSET_SIZE,
              "source": SOURCE, "independent_asset_sha256_verified": False,
              "wear_os_donor": False, "runtime_executed": False, "safe_to_flash": False}
    rc = 0
    try:
        with tempfile.TemporaryDirectory(prefix="r800-phh-reference-") as tmp:
            image = Path(tmp)/"system.img"
            report.update(expand(a.archive, image))
            report["runtime"] = extract(image, report["system_sha256"], a.output/"runtime")
            report["status"] = "PHH_V313_ARM32_RUNTIME_STATIC_ONLY"
    except (OSError, ValueError, lzma.LZMAError, RuntimeError) as exc:
        report.update(status="REVIEW_REQUIRED", reason=str(exc))
        rc = 2
    finally:
        (a.output/"reference-evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
        print(json.dumps(report, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
