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
import re
import subprocess

from r800_arm32_runtime_extract import extract

RELEASE_ID = 50839463
ASSET_ID = 46298761
ASSET_SIZE = 364782672
ASSET_NAME = "system-roar-arm32_binder64-ab-vanilla.img.xz"
SOURCE = "https://github.com/phhusson/treble_experimentations/releases/download/v313/" + ASSET_NAME
MAX_IMAGE = 4*1024**3
# First observation: exact-head CI 46025153522, job 140594533250.
# These pins detect later changes; they are not an upstream signature.
OBSERVED_ASSET_SHA256 = "8685851758960e80110171249fd1ea005e88469457d31bd903a18ab1554eeb37"
OBSERVED_SYSTEM_SHA256 = "2bf6cd3fa34b01b7d38456f02e1cb4694da80b8d2cb585a2a5b13adc361c812d"
OBSERVED_SYSTEM_BYTES = 1014649136
# Successful extraction: CI 46029031849 / job 140607780855.
OBSERVED_RUNTIME_SHA256 = {
    "linker": "f3805ba092213553cef66ce750be6e63122a0f347872b360edf6da27b9e0c8f0",
    "libc.so": "90dc4679e8d6241823b24b1866bf53274f9e455ec84df028cd8952437cb88160",
    "libdl.so": "1eaa0a0deb5ba045f62ecca45585aecfcfa22d6ad8a59b3c0120cbf069a51fcd",
    "libm.so": "4f7fdec3746a77c55f61d0f9799792e730c76913ddc680e2f0e53459fd3c7358",
    "liblog.so": "8a6ccc6df8292962a1f87759371f9baa8fdef25c2279e2d100cd3b4ffaa849b4",
    "libc++.so": "12c5c803a751e04772ce04012edcd066c3cc52a2d31775ce38eba479352211ce",
}
OBSERVED_APEX_SHA256 = "790ad832c8aa4969132df13990f668a726529efd9b093eb0aa7c7a3363bcf622"
OBSERVED_APEX_PAYLOAD_SHA256 = "2cd795b542c924c759f270392918b46ee17399e2000f568735d7eadf42d364cc"
OBSERVED_RAW_SYSTEM_SHA256 = "2887b0b2941ceb0dddd806fa9568195516f1c8aec194510260485f3292c60099"


def verify_runtime_pins(report):
    actual = {name: row["sha256"] for name, row in report["files"].items()}
    if (actual != OBSERVED_RUNTIME_SHA256 or
            report["apex_sha256"] != OBSERVED_APEX_SHA256 or
            report["apex_payload_sha256"] != OBSERVED_APEX_PAYLOAD_SHA256 or
            report["raw_system_sha256"] != OBSERVED_RAW_SYSTEM_SHA256):
        raise ValueError("Extracted runtime differs from successful reference observation")



def expand(archive, output, expected_size=ASSET_SIZE, limit=MAX_IMAGE,
           expected_sha=None, expected_system_sha=None, expected_system_bytes=None):
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
        if expected_sha is not None and compressed.hexdigest() != expected_sha:
            raise ValueError("Reference asset SHA-256 differs from first observation")
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
    if expected_system_sha is not None and image.hexdigest() != expected_system_sha:
        raise ValueError("Expanded system SHA-256 differs from first observation")
    if expected_system_bytes is not None and total != expected_system_bytes:
        raise ValueError("Expanded system size differs from first observation")
    return {"asset_sha256_observed": compressed.hexdigest(), "system_sha256": image.hexdigest(),
            "system_bytes": total}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--source-sha", help="Bind evidence to exact checkout HEAD")
    a = p.parse_args()
    if a.source_sha is not None:
        repo = Path(__file__).resolve().parents[1]
        actual = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        if not re.fullmatch(r"[0-9a-f]{40}", a.source_sha) or a.source_sha != actual:
            p.error("Source SHA does not match checkout")
    a.output.mkdir(exist_ok=False)
    report = {"status": "REFERENCE_ASSET_OBSERVATION_ONLY", "release_id": RELEASE_ID,
              "asset_id": ASSET_ID, "asset_name": ASSET_NAME, "asset_bytes": ASSET_SIZE,
              "source": SOURCE, "source_sha": a.source_sha, "independent_asset_sha256_verified": False,
              "first_observation_run": 46025153522, "first_observation_pin_matched": False,
              "wear_os_donor": False, "runtime_executed": False, "safe_to_flash": False}
    rc = 0
    try:
        with tempfile.TemporaryDirectory(prefix="r800-phh-reference-") as tmp:
            image = Path(tmp)/"system.img"
            report.update(expand(a.archive, image, expected_sha=OBSERVED_ASSET_SHA256,
                                 expected_system_sha=OBSERVED_SYSTEM_SHA256,
                                 expected_system_bytes=OBSERVED_SYSTEM_BYTES))
            report["first_observation_pin_matched"] = True
            report["runtime"] = extract(image, report["system_sha256"], a.output/"runtime")
            verify_runtime_pins(report["runtime"])
            report["runtime_observation_pins_matched"] = True
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
