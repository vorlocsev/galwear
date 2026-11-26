#!/usr/bin/env python3
"""Compare two independent local GPS bridge builds; no flashing or release."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_gps_donor_snapshot import DONORS, LIMIT


def normalize_argv(argv):
    staging = Path(argv[argv.index("-o") + 1]).parent
    normalized = []
    for arg in argv:
        if arg.startswith("--ld-path=" + str(staging) + "/"):
            normalized.append("--ld-path=$STAGING/" + str(Path(arg.split("=", 1)[1]).relative_to(staging)))
        elif arg.startswith(str(staging) + "/"):
            normalized.append("$STAGING/" + str(Path(arg).relative_to(staging)))
        else:
            normalized.append(arg)
    return normalized


def record(stdout, binary):
    records = []
    for line in stdout.splitlines():
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict) and obj.get("schema") == "galwear-r800-gps-evidence-v1":
                records.append(obj)
    if len(records) != 1:
        raise ValueError("Expected exactly one build evidence record")
    obj = records[0]
    if obj["safe_to_flash"] is not False or obj["signed_attestation"] is not False:
        raise ValueError("Invalid evidence scope")
    digest = hashlib.sha256(read_regular(binary, LIMIT)).hexdigest()
    if obj["binary_sha256"] != digest or set(obj["donor_sha256"]) != set(DONORS):
        raise ValueError("Evidence does not match the built binary or donor set")
    inputs = obj["inputs"]
    if (inputs["schema"] != "galwear-r800-gps-inputs-v1"
            or inputs["safe_to_flash"] is not False
            or inputs["signed_attestation"] is not False):
        raise ValueError("Invalid input evidence scope")
    return {"binary_sha256": digest, "donor_sha256": obj["donor_sha256"],
            "input_fingerprints": inputs["inputs"],
            "compiler_argv": normalize_argv(inputs["argv"]),
            "tizen_archive": obj.get("tizen_archive")}


def compare(builder, ndk, donor, abi, timeout=300):
    results = []
    # Both invocations use separate working and output directories.
    with tempfile.TemporaryDirectory(prefix="r800-gps-repro-") as tmp:
        for run in ("first", "second"):
            work = Path(tmp) / run
            work.mkdir()
            binary = work / "gpsbridge"
            result = subprocess.run(
                ["sh", str(builder), str(ndk), str(donor), str(binary)],
                cwd=work, env=dict(os.environ, R800_XTRA_ABI=str(abi), LC_ALL="C", TZ="UTC"),
                capture_output=True, text=True, timeout=timeout, check=False)
            if result.returncode:
                raise ValueError(run + " build failed: " + result.stderr[-4000:])
            results.append(record(result.stdout, binary))
    first, second = results
    differences = [key for key in first if first[key] != second[key]]
    return {"schema": "galwear-r800-gps-repeatability-v1",
            "status": "LOCAL_REPEATABILITY_PASS" if not differences else "LOCAL_REPEATABILITY_FAIL",
            "differences": differences, "runs": results, "xtra_abi": abi,
            "independent_hosts_tested": False, "runtime_verified": False,
            "safe_to_flash": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--donor", type=Path, required=True)
    parser.add_argument("--xtra-abi", type=int, choices=(0, 1, 2), default=0)
    args = parser.parse_args()
    builder = Path(__file__).resolve().parents[1] / "src/tools/gps/build.sh"
    try:
        report = compare(builder, args.ndk.resolve(strict=True),
                         args.donor.resolve(strict=True), args.xtra_abi)
    except (OSError, ValueError, KeyError, IndexError, TypeError, subprocess.TimeoutExpired) as exc:
        report = {"status": "LOCAL_REPEATABILITY_FAIL", "error": str(exc),
                  "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "LOCAL_REPEATABILITY_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
