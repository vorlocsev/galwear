#!/usr/bin/env python3
"""Check exact standalone synthetic-HAL transcript; no hardware claims."""
import argparse
import hashlib
import json
from pathlib import Path
import re

FIX = "FIX flags=1f lat=12.5000000 lon=-34.2500000 alt=100.0 spd=1.50 brg=90.0 acc=5.0 t=1700000000000"
NMEA = "NMEA $GPGGA,MOCK*00"
MAX_LOG = 64 * 1024


def expected(stage):
    lines = [r"GpsInterface 0x[0-9a-fA-F]+ size 40"]
    if stage == 1:
        return lines + ["init -11"]
    lines += ["CAPS 1234", "init 0", r"inject_time [1-9][0-9]* ref [0-9]+ unc 500 -> 0"]
    if stage == 2:
        return lines + ["set_position_mode -12", "CAPS 4321"]
    lines += ["set_position_mode 0"]
    if stage == 3:
        return lines + [re.escape("start -13 (running 0 s)"), "CAPS 4321"]
    lines += ["STATUS 1", re.escape(FIX), re.escape(NMEA), re.escape("start 0 (running 0 s)")]
    if stage == 4:
        return lines + ["stop -14", "CAPS 4321"]
    return lines + ["STATUS 2", "stop 0", "CAPS 4321"]


def evaluate(raw, stage, rc):
    if type(stage) is not int or stage not in range(5) or type(rc) is not int or not 0 <= rc <= 255:
        raise ValueError("Invalid stage or exit code")
    if len(raw) > MAX_LOG:
        raise ValueError("Oversized mock HAL transcript")
    lines = raw.decode("ascii").splitlines()
    patterns = expected(stage)
    matched = len(lines) == len(patterns) and all(re.fullmatch(p, s) for p, s in zip(patterns, lines))
    problems = []
    if not matched:
        problems.append("TRANSCRIPT_MISMATCH")
    if rc != (0 if stage == 0 else 1):
        problems.append("EXIT_STATUS_MISMATCH")
    return {"status": "MOCK_HAL_TRANSCRIPT_MATCH" if not problems else "REVIEW_REQUIRED",
            "stage": stage, "exit_code": rc, "problems": problems,
            "log_sha256": hashlib.sha256(raw).hexdigest(),
            "synthetic_only": True, "vendor_abi_verified": False,
            "gnss_runtime_verified": False, "safe_to_flash": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", type=int, required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    parser.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    try:
        with args.log.open("rb") as stream:
            report = evaluate(stream.read(MAX_LOG + 1), args.stage, args.exit_code)
    except (OSError, ValueError) as exc:
        report = {"status": "REVIEW_REQUIRED", "problems": [str(exc)], "safe_to_flash": False}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "MOCK_HAL_TRANSCRIPT_MATCH" else 2


if __name__ == "__main__":
    raise SystemExit(main())
