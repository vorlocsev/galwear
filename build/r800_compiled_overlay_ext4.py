#!/usr/bin/env python3
"""Rootless EXT4 packing experiment using only verified compiled overlay bytes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_donor_preflight import verify_components
from r800_extract_ext4 import locate, command
from r800_vendor_inputs import image_info, OVERLAY

IMAGE_BYTES = 64 * 1024**2
MAX_FILE = 64 * 1024**2


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def destination(name):
    if name.endswith(".so"):
        return "lib/hw/" + name
    if name == "audio/audio_policy_configuration.xml":
        return "etc/audio_policy_configuration.xml"
    if name == "sensors/android.hardware.sensors@1.0-service.rc":
        return "etc/init/android.hardware.sensors@1.0-service.rc"
    return name


def fixture_label(name, is_directory):
    # Historical vendor recipe labels, not a donor-policy-derived mapping.
    kind = "vendor_file" if is_directory or name.startswith("lib/hw/") else "vendor_configs_file"
    return "u:object_r:" + kind + ":s0"


def metadata_plan(tree, rows):
    entries = {"": (0o040755, b"", 0, 0)}
    for name in rows:
        data = read_regular(tree/name, MAX_FILE)
        if sha(data) != rows[name]["sha256"]:
            raise ValueError("Overlay tree changed")
        entries[name] = (0o100644, data, 0, 0)
        for parent in Path(name).parents:
            if str(parent) != ".":
                entries.setdefault(parent.as_posix(), (0o040755, b"", 0, 0))
    return entries


def apply_metadata(image, entries, scratch, debugfs):
    # debugfs is used only on the newly created private test image.
    for name, item in sorted(entries.items()):
        if name and (not re.fullmatch(r"[A-Za-z0-9_./@+-]+", name) or
                     any(part in (".", "..") for part in name.split("/"))):
            raise ValueError("Unexpected overlay path")
        guest = "/" + name
        mode = item[0]
        label = fixture_label(name, mode & 0o170000 == 0o040000)
        (scratch/"label-input").write_bytes(label.encode("ascii") + b"\0")
        for request in (
            f"set_inode_field {guest} mode {mode:07o}",
            f"set_inode_field {guest} uid 0",
            f"set_inode_field {guest} gid 0",
            f"ea_set -f label-input {guest} security.selinux",
        ):
            subprocess.run([debugfs, "-w", "-R", request, str(image)], cwd=scratch,
                           check=True, capture_output=True, timeout=30)


def verify_metadata(image, entries, scratch, debugfs):
    from r800_android_system_ext4 import inspect_inode
    # Existing debugfs inspector uses absolute scratch paths in its commands.
    if not re.fullmatch(r"[A-Za-z0-9_./+-]+", str(scratch)):
        raise ValueError("Unsupported scratch path for debugfs")
    result = {}
    for name, item in sorted(entries.items()):
        label = fixture_label(name, item[0] & 0o170000 == 0o040000)
        result["/" + name] = inspect_inode(
            image, "vendor" + ("/" + name if name else ""),
            item, label, scratch, debugfs, partition="vendor")
    return result


def build(components, source_sha, output):
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("Expected full source SHA")
    components = components.resolve(strict=True)
    output = output.absolute()
    if output.exists() or output.is_symlink() or output.resolve().is_relative_to(components):
        raise ValueError("Expected fresh output outside components")
    tools = {name: shutil.which(name) for name in ("mke2fs", "e2fsck", "debugfs")}
    if not all(tools.values()):
        raise ValueError("e2fsprogs tools required")
    verify_components(components, source_sha)
    manifest_raw = read_regular(components/"component-evidence.json", 1024*1024)
    manifest = json.loads(manifest_raw)["files"]
    rows = {}
    with tempfile.TemporaryDirectory(dir=output.parent, prefix="r800-overlay-") as tmp:
        root = Path(tmp)
        tree = root/"tree"
        tree.mkdir()
        result = root/"result"
        result.mkdir()
        for name in OVERLAY:
            src = "vendor-overlay/" + name
            expected = manifest[src]
            raw = read_regular(components/src, MAX_FILE)
            if sha(raw) != expected["sha256"] or len(raw) != expected["bytes"]:
                raise ValueError("Overlay changed: " + src)
            dest = destination(name)
            target = tree/dest
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as f:
                f.write(raw)
            target.chmod(0o644)
            rows[dest] = {"component": src, "sha256": sha(raw), "bytes": len(raw)}
        image = result/"overlay-test.ext4"
        with image.open("xb") as stream:
            stream.truncate(IMAGE_BYTES)
        subprocess.run([tools["mke2fs"], "-q", "-F", "-t", "ext4", "-b", "4096",
                        "-m", "0", "-I", "256", "-O", "^metadata_csum,^64bit",
                        "-L", "r800-overlay", "-d", str(tree), str(image)],
                       check=True, capture_output=True, timeout=60)
        entries = metadata_plan(tree, rows)
        apply_metadata(image, entries, root, tools["debugfs"])
        subprocess.run([tools["e2fsck"], "-fn", str(image)], check=True,
                       capture_output=True, timeout=60)
        before = image_info(image)
        if before["bytes"] != IMAGE_BYTES:
            raise ValueError("Unexpected test image size")
        for dest, row in rows.items():
            found = locate(tools["debugfs"], image, "/" + dest)
            if found is None or found[1] != row["bytes"]:
                raise ValueError("Missing or wrong-size EXT4 member: " + dest)
            target = root/"member"
            try:
                command(tools["debugfs"], image, "dump <%d> member" % found[0], cwd=root)
                raw = read_regular(target, MAX_FILE)
                if sha(raw) != row["sha256"]:
                    raise ValueError("EXT4 member hash mismatch: " + dest)
            finally:
                target.unlink(missing_ok=True)
        inode_metadata = verify_metadata(image, entries, root, tools["debugfs"])
        if image_info(image) != before:
            raise ValueError("Image changed during read-only validation")
        verify_components(components, source_sha)
        if read_regular(components/"component-evidence.json", 1024*1024) != manifest_raw:
            raise ValueError("Component manifest changed")
        report = {"status": "COMPILED_OVERLAY_EXT4_TEST_ONLY", "source_sha": source_sha,
                  "component_manifest_sha256": sha(manifest_raw), "image": before,
                  "members": rows, "e2fsck_read_only_pass": True,
                  "selected_member_bytes_match": True, "donor_images_used": False,
                  "complete_vendor_image_built": False, "selinux_labels_verified": False,
                  "fixture_metadata_verified": True, "fixture_label_origin": "HISTORICAL_VENDOR_RECIPE",
                  "inode_metadata": inode_metadata, "donor_policy_label_compatibility_verified": False,
                  "mount_tested": False, "runtime_verified": False, "safe_to_flash": False}
        (result/"overlay-ext4-evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
        os.rename(result, output)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--components", type=Path, required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(build(a.components, a.source_sha, a.output), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
