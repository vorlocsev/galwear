#!/usr/bin/env python3
"""Build a small pre-labeled /system ext4 fixture, never mount or flash it.

The source is the existing audited rootfs plan, not an entire Android image.
Only regular files, directories and the known linker alias are accepted.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from r800_android_rootfs_preflight import prepare_entries, snapshot, sha
from r800_android_sepolicy_audit import audit, MAX_POLICY
from r800_android_file_contexts import FILE_CONTEXTS, MAX_CONTEXTS
from r800_android_init_dependencies import regular
from r800_android_runtime_extract import digest, ext4
from r800_initramfs_spec import validate_init
from r800_qemu_guest_abi import read_bounded_json

IMAGE_SIZE = 128*1024*1024
PATH = re.compile(r"[A-Za-z0-9_./+-]+")
LABEL = re.compile(r"u:object_r:[A-Za-z0-9_]+:s0(?::[A-Za-z0-9_,.:-]+)?")
MODES = {0o040000: ("directory", "d"), 0o100000: ("regular", "f"),
         0o120000: ("symlink", "l")}


def system_entries(entries, contexts):
    result = {}
    for name, item in entries:
        if name != "system" and not name.startswith("system/"):
            continue
        if not PATH.fullmatch(name) or ".." in Path(name).parts:
            raise ValueError("Unexpected system entry")
        if item[0] & 0o170000 not in MODES:
            raise ValueError("Unsupported system inode type")
        if name in result:
            raise ValueError("Duplicate system entry")
        result[name] = item
    for rel, blob in contexts.items():
        if rel != FILE_CONTEXTS[0] or rel in result:
            raise ValueError("Unexpected platform file_contexts path")
        result[rel] = (0o100644, blob, 0, 0)
        for parent in Path(rel).parents:
            if str(parent) != ".":
                result.setdefault(str(parent), (0o040755, b"", 0, 0))
    if not {"system", "system/bin", "system/bin/galwear_property_service",
            "system/bin/galwear_property_client"} <= set(result):
        raise ValueError("Missing required system files")
    if result["system"][0] & 0o170000 != 0o040000:
        raise ValueError("System root must be a directory")
    for name, (mode, data, major, minor) in result.items():
        if major or minor:
            raise ValueError("Device node forbidden")
        if mode & 0o170000 == 0o120000:
            if name != "system/bin/linker64" or data not in (
                b"/apex/com.android.runtime/bin/linker64", b"/system/bin/bootstrap/linker64"):
                raise ValueError("Unsupported system symlink")
        if name != "system":
            parent = result.get(str(Path(name).parent))
            if parent is None or parent[0] & 0o170000 != 0o040000:
                raise ValueError("Missing regular parent directory")
    return result


def invoke(args, timeout=60):
    return subprocess.run([str(x) for x in args], check=True, capture_output=True,
                          timeout=timeout, env={**os.environ, "LC_ALL": "C"})


def expected_label(contexts, name, mode, matchpathcon):
    raw = invoke([matchpathcon, "-N", "-n", "-f", contexts, "-m",
                  MODES[mode & 0o170000][1], "/"+name]).stdout.decode("ascii").strip()
    if not LABEL.fullmatch(raw):
        raise ValueError("Missing or invalid expected context: "+name)
    return raw


def materialize(tree, entries):
    for name, (mode, data, _, _) in sorted(entries.items(), key=lambda x: (x[0].count("/"), x[0])):
        path = tree / name
        kind = mode & 0o170000
        if kind == 0o040000:
            path.mkdir(exist_ok=False)
        elif kind == 0o100000:
            path.write_bytes(data)
            path.chmod(mode & 0o777)
        else:
            # Preserve guest meaning using a relative link, confined to the
            # disposable staging parent even if a host tool resolves it.
            target = ("../../apex/com.android.runtime/bin/linker64"
                      if data.startswith(b"/apex/") else "bootstrap/linker64")
            path.symlink_to(target)


def inspect_inode(image, name, item, expected, scratch, debugfs, partition="system"):
    mode, data, _, _ = item
    kind = mode & 0o170000
    if name != partition and not name.startswith(partition + "/"):
        raise ValueError("Inode outside selected partition")
    rel = name[len(partition):] or "/"
    info = invoke([debugfs, "-R", "stat "+rel, image]).stdout.decode("utf-8")
    if not re.search(r"^Inode:\s+\d+\s+Type:\s+"+MODES[kind][0]+r"\b", info, re.M):
        raise ValueError("Unexpected inode type: "+name)
    m = re.search(r"\bMode:\s+0?([0-7]{3,4})\b", info)
    if not m or int(m[1], 8) & 0o7000:
        raise ValueError("Missing mode or unexpected special mode bits: "+name)
    label_file = scratch/"label"
    if label_file.exists():
        label_file.unlink()
    invoke([debugfs, "-R", f"ea_get -f {label_file} {rel} security.selinux", image])
    if snapshot(label_file, 1024) != expected.encode("ascii")+b"\0":
        raise ValueError("EXT4 SELinux xattr mismatch: "+name)
    result = {"context": expected, "mode": m[1], "type": MODES[kind][0]}
    if kind == 0o100000:
        target = scratch/"payload"
        if target.exists():
            target.unlink()
        invoke([debugfs, "-R", f"dump {rel} {target}", image])
        if snapshot(target, len(data)) != data:
            raise ValueError("EXT4 payload mismatch: "+name)
        if mode & 0o111 and int(m[1],8) & 0o111 != mode & 0o111:
            raise ValueError("Executable permission lost: "+name)
        result["sha256"] = sha(data)
    elif kind == 0o120000:
        target = ("../../apex/com.android.runtime/bin/linker64"
                  if data.startswith(b"/apex/") else "bootstrap/linker64")
        if f'Fast link dest: "{target}"' not in info:
            raise ValueError("Unexpected linker alias target")
        result["target"] = target
    return result


def build(a):
    root = a.product_out.resolve(strict=True)
    policy = audit(root, a.checkfc)
    policy_path = regular(root, policy["policy_path"])
    policy_data = snapshot(policy_path, MAX_POLICY)
    e2fsdroid_hash = digest(a.e2fsdroid, 128*1024*1024)
    if sha(policy_data) != policy["policy_sha256"]:
        raise ValueError("Policy changed")
    entries, rootfs = prepare_entries(a.staged, root, a.preflight_init, a.readelf)
    fc = snapshot(regular(root, FILE_CONTEXTS[0]), MAX_CONTEXTS)
    if b"\0" in fc:
        raise ValueError("Expected text file_contexts")
    fc.decode("utf-8")
    entries = system_entries(entries, {FILE_CONTEXTS[0]: fc})
    transition = None
    if a.transition_init is not None:
        if a.transition_compile_evidence is None:
            raise ValueError("Transition compile evidence required")
        info = validate_init(a.transition_init)
        spec = read_bounded_json(a.transition_compile_evidence)
        if spec.get("status") != "NON_RELEASE_INITRAMFS_SPEC_ONLY" or spec.get("init") != info:
            raise ValueError("Transition init compile evidence mismatch")
        binary = snapshot(a.transition_init, 2*1024*1024)
        if sha(binary) != info["sha256"]:
            raise ValueError("Transition init changed")
        if "system/bin/init" not in entries or entries["system/bin/init"][0] != 0o100755:
            raise ValueError("Canonical original /system/bin/init required")
        original = sha(entries["system/bin/init"][1])
        if original == sha(binary):
            raise ValueError("Diagnostic must differ from original init")
        entries["system/bin/init"] = (0o100755, binary, 0, 0)
        transition = {"path": "/system/bin/init", "original_sha256": original,
                      "diagnostic_sha256": sha(binary)}
    elif a.transition_compile_evidence is not None:
        raise ValueError("Unexpected transition compile evidence")
    if sum(len(v[1]) for v in entries.values()) > IMAGE_SIZE//2 or len(entries)>512:
        raise ValueError("System fixture outside bounds")
    if a.out.exists() or a.out.is_symlink():
        raise ValueError("Output must be new")
    # Keep scratch command arguments free of debugfs metacharacters.
    with tempfile.TemporaryDirectory(prefix="galwear-ext4-", dir="/tmp") as tmp:
        scratch = Path(tmp)
        ctx, pol = scratch/"file_contexts", scratch/"sepolicy"
        ctx.write_bytes(fc)
        pol.write_bytes(policy_data)
        invoke([a.checkfc.resolve(strict=True), pol, ctx])
        expected = {n: expected_label(ctx,n,v[0],a.matchpathcon) for n,v in entries.items()}
        if expected.get("system/bin/init") not in (None, "u:object_r:init_exec:s0"):
            raise ValueError("Unexpected original init label")
        materialize(scratch, entries)
        image = scratch/"system.ext4"
        with image.open("xb") as f:
            f.truncate(IMAGE_SIZE)
        invoke([a.mke2fs, "-F", "-t", "ext4", "-b", "4096", "-I", "256", "-m", "0",
                "-O", "none,extent,filetype,dir_index,ext_attr,sparse_super,large_file",
                image], timeout=120)
        invoke([a.e2fsdroid.resolve(strict=True), "-e", "-T", "0", "-S", ctx,
                "-a", "/system", "-f", scratch/"system", image], timeout=300)
        ext4(image)
        if image.stat().st_size != IMAGE_SIZE:
            raise ValueError("Unexpected EXT4 size")
        invoke([a.e2fsck, "-f", "-n", image], timeout=120)
        before = digest(image, IMAGE_SIZE)
        observed = {name: inspect_inode(image, name, item, expected[name], scratch, a.debugfs)
                    for name,item in sorted(entries.items())}
        if digest(image, IMAGE_SIZE) != before:
            raise ValueError("Image changed during read-only inspection")
        if digest(a.e2fsdroid, 128*1024*1024) != e2fsdroid_hash:
            raise ValueError("e2fsdroid changed during build")
        a.out.mkdir(exist_ok=False)
        dest = a.out/"system.ext4"
        with dest.open("xb") as dst, image.open("rb") as src:
            while chunk := src.read(1024*1024):
                dst.write(chunk)
        if digest(dest, IMAGE_SIZE) != before:
            raise ValueError("Image copy mismatch")
    return {"status": ("ANDROID_SYSTEM_EXT4_TRANSITION_STATIC_ONLY" if transition else
                       "ANDROID_SYSTEM_EXT4_LABELED_STATIC_ONLY"),
            "diagnostic_init_substitution": transition,
            "image_sha256": before, "image_bytes": IMAGE_SIZE,
            "e2fsdroid_sha256": e2fsdroid_hash,
            "policy_sha256": policy["policy_sha256"], "platform_file_contexts_sha256": sha(fc),
            "property_contexts_sha256": rootfs["property_contexts_sha256"],
            "verified_system_entries": observed, "e2fsck_read_only_passed": True,
            "full_android_partition": False, "other_partitions_labeled": False,
            "apex_labels_verified": False, "kernel_mount_tested": False,
            "android_init_started": False, "property_service_started": False,
            "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("staged", "product-out", "preflight-init", "checkfc", "e2fsdroid", "out", "report"):
        p.add_argument("--"+name, type=Path, required=True)
    p.add_argument("--transition-init", type=Path)
    p.add_argument("--transition-compile-evidence", type=Path)
    for name in ("mke2fs", "e2fsck", "debugfs", "matchpathcon", "readelf"):
        p.add_argument("--"+name, default=name)
    a = p.parse_args()
    try:
        report = build(a)
        rc = 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as exc:
        report = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    print(report["status"])
    return rc

if __name__ == "__main__":
    raise SystemExit(main())
