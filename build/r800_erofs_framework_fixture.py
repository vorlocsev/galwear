#!/usr/bin/env python3
"""Exercise actual pinned erofs-utils against host-created synthetic images."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile

from r800_framework_inventory import audit, require
from r800_graphics_donor_binding import checkout_sha
from r800_donor_preflight import digest

EROFSPIN = "7bc147fafd53a2a9ff7c22399491079e5bfffafc"


def run(tool_root, output, source_sha):
    checkout_sha(source_sha)
    root = tool_root.resolve(strict=True)
    actual = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    require(actual == EROFSPIN, "Unexpected erofs-utils source checkout")
    mkfs, dump = root/"mkfs/mkfs.erofs", root/"dump/dump.erofs"
    pins = {p.name: digest(p, 32*1024**2)["sha256"] for p in (mkfs, dump)}
    results = {}
    with tempfile.TemporaryDirectory(prefix="r800-erofs-fixture-") as tmp:
        work = Path(tmp)
        tree = work/"root"
        (tree/"framework").mkdir(parents=True)
        props = ("ro.build.version.sdk=30\nro.build.version.release=11\n"
                 "ro.product.cpu.abilist=armeabi-v7a,armeabi\n"
                 "ro.build.characteristics=watch\n").encode()
        (tree/"build.prop").write_bytes(props)
        with zipfile.ZipFile(tree/"framework/framework.jar", "w", compression=zipfile.ZIP_STORED) as z:
            z.writestr("classes.dex", b"synthetic-dex-not-executed\n"*4096)
            z.writestr("classes2.dex", b"another-synthetic-member")
        (tree/"framework/services.jar").symlink_to("framework.jar")
        expected_members = {
            "/build.prop": hashlib.sha256(props).hexdigest(),
            "/framework/framework.jar": digest(tree/"framework/framework.jar")["sha256"],
        }
        for label, options in (("plain", []), ("lz4", ["-zlz4"])):
            image = work/(label+".img")
            subprocess.run([str(mkfs), "-T0", "--all-root", *options, str(image), str(tree)],
                           check=True, timeout=120)
            pin = digest(image)["sha256"]
            report = audit(image, pin, "system_a", source_sha, "",
                           ["build.prop", "framework/framework.jar"], dump, pins[dump.name])
            require(report["status"] == "SELECTED_FRAMEWORK_FILES_STATIC_ONLY",
                    label+": actual EROFS inventory rejected: "+json.dumps(report["members"]))
            require(report["filesystem"]["kind"] == "EROFS", "Wrong filesystem")
            for path, expected in expected_members.items():
                require(report["members"][path]["sha256"] == expected, "Member digest mismatch: "+path)
            for flag in ("literal_android_11_hint", "literal_arm32_hint", "literal_watch_hint"):
                require(report["properties"][flag] is True, "Missing literal hint: "+flag)
            require(report["members"]["/framework/framework.jar"]["dex_entries"] ==
                    ["classes.dex", "classes2.dex"], "Unexpected JAR entries")
            negative = audit(image, pin, "system_a", source_sha, "",
                             ["framework/services.jar", "framework/android.test.base.jar"],
                             dump, pins[dump.name])
            require(negative["status"] == "REVIEW_REQUIRED" and
                    all(row["status"] != "OBSERVED" for row in negative["members"].values()),
                    "Missing or symlink member was accepted")
            require(digest(image)["sha256"] == pin, "Fixture image changed")
            results[label] = {"positive": report, "negative": negative}
        for path in (mkfs, dump):
            require(digest(path, 32*1024**2)["sha256"] == pins[path.name], "Host tool changed")
    checkout_sha(source_sha)
    report = {"schema": "galwear-r800-erofs-tool-fixture-v1",
              "status": "REAL_EROFS_SYNTHETIC_FRAMEWORK_ONLY", "source_sha": source_sha,
              "erofs_source_commit": EROFSPIN, "tool_sha256": pins,
              "fixtures": results, "donor_image_tested": False, "dex_execution_verified": False,
              "wear_os_runtime_verified": False, "hardware_tested": False, "safe_to_flash": False}
    with output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(report["status"])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tool-root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--source-sha", required=True)
    a = p.parse_args()
    run(a.tool_root, a.output, a.source_sha)


if __name__ == "__main__":
    main()
