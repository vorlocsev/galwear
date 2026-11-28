#!/usr/bin/env python3
"""Bounded read-only selected Android framework file inventory.

EXT4 uses a private hash-pinned image and debugfs. EROFS optionally uses a
caller-supplied, hash-pinned host dump.erofs with --cat support. No mounts,
guest executable launch, APK/JAR execution or full filesystem extraction.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import resource
import shutil
import subprocess
import tempfile
import zipfile

from r800_extract_ext4 import snapshot_image, locate, command
from r800_android_userspace_preflight import read_regular
from r800_graphics_donor_binding import checkout_sha
from r800_extract_super import ALLOWED, require
from r800_partition_identity import filesystem, literal_properties, property_inventory
from r800_donor_preflight import digest
from r800_android_linker_audit import inspect
from r800_art_inventory import DEX_NAME, jar_inventory

MAX_PARTITION = 4*1024**3
MAX_MEMBER = 64*1024**2
MAX_TOTAL = 256*1024**2
MAX_TOOL = 32*1024**2
MAX_META = 64*1024
FRAMEWORK = {
    "build.prop": 1024*1024,
    "bin/app_process32": MAX_MEMBER,
    "bin/app_process64": MAX_MEMBER,
    "bin/surfaceflinger": MAX_MEMBER,
    "framework/framework.jar": MAX_MEMBER,
    "framework/services.jar": MAX_MEMBER,
    "framework/android.test.base.jar": MAX_MEMBER,
    "lib/libandroid_runtime.so": MAX_MEMBER,
    "lib64/libandroid_runtime.so": MAX_MEMBER,
    "lib/libgui.so": MAX_MEMBER,
    "lib64/libgui.so": MAX_MEMBER,
    "etc/permissions/android.hardware.type.watch.xml": 1024*1024,
}


def bounded_tool(argv, limit, scratch):
    """Bound both output streams on disk, and reject any diagnostic stderr."""
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit+1, limit+1))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with tempfile.TemporaryFile(dir=scratch) as out, tempfile.TemporaryFile(dir=scratch) as err:
        result = subprocess.run(argv, stdout=out, stderr=err, timeout=60,
                                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                                preexec_fn=limits, check=False)
        out.seek(0)
        err.seek(0)
        data, diagnostics = out.read(limit+1), err.read(limit+1)
        require(result.returncode == 0 and not diagnostics and len(data) <= limit,
                "EROFS tool failed or exceeded output budget")
        return data


def erofs_member(tool, image, path, limit, scratch):
    metadata = bounded_tool([str(tool), "--path="+path, str(image)], MAX_META, scratch)
    metadata = metadata.decode("utf-8")
    # dump.erofs may return 0 on a failed lookup. Require complete metadata
    # and explicit regular-file type; never treat empty output as success.
    row = re.search(r"^Size:\s+(\d+)\s+On-disk size:\s+\d+\s+regular file\s*$",
                    metadata, re.M | re.I)
    require(row is not None, "EROFS regular-file metadata not confirmed: "+path)
    length = int(row[1])
    require(0 < length <= limit, "EROFS member size outside budget")
    require(re.search(r"^Path\s*:\s*"+re.escape(path)+r"\s*$", metadata, re.M),
            "EROFS resolved path differs")
    data = bounded_tool([str(tool), "--cat", "--path="+path, str(image)], length, scratch)
    require(len(data) == length, "EROFS extracted member size mismatch")
    return data


def ext4_member(tool, image, path, limit, scratch):
    found = locate(tool, image, path, limit)
    if found is None:
        return None
    inode, size = found
    dest = scratch/"member"
    try:
        command(tool, image, "dump <%d> member" % inode, cwd=scratch)
        raw = read_regular(dest, limit)
        require(len(raw) == size, "EXT4 member size mismatch")
        return raw
    finally:
        dest.unlink(missing_ok=True)


def classify(path, raw, validate_dex=False, dex_budget=MAX_TOTAL):
    result = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    if path.endswith(".jar"):
        import io
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            require(len(entries) <= 65536, "JAR inventory exceeds entry budget")
            dex = [i.filename for i in entries if DEX_NAME.fullmatch(i.filename)]
            require(len(set(dex)) == len(dex), "Duplicate JAR DEX member")
            result.update(kind="JAR_DIRECTORY_ONLY", dex_entries=sorted(dex),
                          dex_contents_verified=False)
        if validate_dex:
            dex_report, used = jar_inventory(raw, dex_budget)
            require(dex_report["status"] == "DEX_HEADER_INVENTORY_ONLY",
                    "No embedded DEX; precompiled ART evidence required")
            result.update(kind="JAR_DEX_HEADER_INVENTORY_ONLY", dex_inventory=dex_report,
                          dex_bytes=used, dex_headers_checked=True)
    elif path.endswith(".so") or "/bin/" in path:
        elf = inspect(raw)
        result.update(kind="ELF_STATIC_ONLY", abi=elf["abi"], elf_type=elf["elf_type"],
                      needed=elf["needed"], soname=elf["soname"])
    else:
        result["kind"] = "REGULAR_FILE_ONLY"
    return result


def audit(image, expected, partition, source_sha, prefix, requested, erofs_tool=None,
          erofs_tool_sha=None, validate_dex=False):
    require(ALLOWED.fullmatch(partition), "Explicit allowed partition required")
    require(re.fullmatch(r"[0-9a-f]{64}", expected), "Expected image SHA-256")
    require(prefix in ("", "/system", "/vendor", "/product", "/system_ext", "/odm"),
            "Unsupported partition root prefix")
    base = re.sub(r"_[ab]$", "", partition)
    require(prefix in ("", "/"+base), "Prefix does not match partition")
    require(bool(requested) and len(set(requested)) == len(requested)
            and set(requested) <= set(FRAMEWORK), "Explicit allowed unique members required")
    require((erofs_tool is None) == (erofs_tool_sha is None), "EROFS tool and SHA required together")
    checkout_sha(source_sha)
    image = Path(image)
    rows, records, total = {}, [], 0
    with tempfile.TemporaryDirectory(prefix="r800-framework-") as tmp:
        scratch = Path(tmp)
        private = scratch/"image"
        snapshot_image(image, private, expected)
        fs = filesystem(private)
        if fs["kind"] == "EXT4":
            tool = shutil.which("debugfs")
            require(tool, "debugfs required")
            reader = ext4_member
        else:
            require(erofs_tool is not None and re.fullmatch(r"[0-9a-f]{64}", erofs_tool_sha),
                    "EROFS requires explicit hash-pinned host dump.erofs with --cat")
            tool = Path(erofs_tool).absolute()
            require(digest(tool, MAX_TOOL)["sha256"] == erofs_tool_sha, "EROFS tool SHA mismatch")
            help_text = bounded_tool([str(tool), "--help"], MAX_META, scratch)
            require(b"--cat" in help_text, "EROFS tool lacks --cat")
            reader = erofs_member
        for relative in requested:
            path = prefix+"/"+relative
            try:
                raw = reader(tool, private, path, min(FRAMEWORK[relative], MAX_TOTAL-total), scratch)
                if raw is None:
                    rows[path] = {"status": "NOT_FOUND"}
                    continue
                total += len(raw)
                require(total <= MAX_TOTAL, "Framework byte budget exceeded")
                row = classify(path, raw, validate_dex, MAX_TOTAL-total)
                total += row.get("dex_bytes", 0)
                if relative == "build.prop":
                    records.extend(literal_properties(raw, path))
                rows[path] = {"status": "OBSERVED", **row}
            except (ValueError, OSError, UnicodeError, RuntimeError, NotImplementedError,
                    zipfile.BadZipFile, subprocess.SubprocessError) as exc:
                rows[path] = {"status": "REVIEW_REQUIRED", "reason": str(exc)}
        require(digest(private, MAX_PARTITION)["sha256"] == expected and
                digest(image, MAX_PARTITION)["sha256"] == expected, "Partition input changed")
        if fs["kind"] == "EROFS":
            require(digest(tool, MAX_TOOL)["sha256"] == erofs_tool_sha, "EROFS tool changed")
    checkout_sha(source_sha)
    props = property_inventory(records)
    complete = all(row["status"] == "OBSERVED" for row in rows.values()) and not props["conflicts"]
    return {"schema": "galwear-r800-framework-inventory-v1",
            "status": "SELECTED_FRAMEWORK_FILES_STATIC_ONLY" if complete else "REVIEW_REQUIRED",
            "source_sha": source_sha, "partition": partition, "image_sha256": expected,
            "filesystem": fs, "root_prefix": prefix, "members": rows,
            "properties": props, "erofs_tool_sha256": erofs_tool_sha if fs["kind"] == "EROFS" else None,
            "dex_header_check_requested": validate_dex,
            "framework_complete": False, "dex_execution_verified": False,
            "wear_os_runtime_verified": False, "surfaceflinger_runtime_verified": False,
            "hardware_tested": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", type=Path, required=True)
    p.add_argument("--sha256", required=True)
    p.add_argument("--partition", required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--root-prefix", required=True)
    p.add_argument("--member", action="append", required=True)
    p.add_argument("--erofs-tool", type=Path)
    p.add_argument("--erofs-tool-sha256")
    p.add_argument("--validate-dex", action="store_true",
                   help="Validate embedded standard DEX headers using existing ART inventory")
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    report = audit(a.image, a.sha256, a.partition, a.source_sha, a.root_prefix,
                   a.member, a.erofs_tool, a.erofs_tool_sha256, a.validate_dex)
    with a.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(report["status"])
    return 0 if report["status"] == "SELECTED_FRAMEWORK_FILES_STATIC_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
