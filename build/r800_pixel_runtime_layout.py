#!/usr/bin/env python3
"""Locate actual selected Android runtime files in a pinned raw System.

Read-only debugfs directory listings and regular-file inspection. Symlinks
are recorded, never followed as host paths. No mounting or APEX activation.
"""
import hashlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
import zipfile

from r800_extract_ext4 import command, snapshot_image
from r800_framework_inventory import ext4_member, classify, MAX_MEMBER
from r800_donor_preflight import digest
from r800_graphics_donor_binding import checkout_sha
from r800_apex_inventory import protobuf_manifest, json_manifest, MAX_METADATA

NAME = re.compile(r"[A-Za-z0-9_.@+-]{1,255}")
MODULE = re.compile(r"com\.(?:google\.)?android\.(?:runtime|art|vndk\.(?:v[0-9]+|current))(?:[@.][A-Za-z0-9_.@+-]+)?")
WANTED = ("bin/linker", "bin/linker64", "bin/dex2oat", "bin/dex2oat32",
          "lib/libc.so", "lib/libm.so", "lib/libdl.so", "lib/libart.so",
          "lib/libartbase.so", "lib/libhidlbase.so", "lib/libutils.so",
          "lib/libcutils.so", "lib/bionic/libc.so", "lib/bionic/libm.so",
          "lib/bionic/libdl.so", "lib/bionic/ld-android.so", "lib/bionic/libdl_android.so",
          "lib/ld-android.so", "lib/libdl_android.so", "lib/libc++.so", "lib/libbase.so",
          "lib/liblog.so", "lib/libvndksupport.so",
          "lib/vndk/libhidlbase.so", "lib/vndk/libutils.so", "lib/vndk/libcutils.so",
          "lib/vndk-sp/libhidlbase.so", "lib/vndk-sp/libutils.so", "lib/vndk-sp/libcutils.so",
          "javalib/core-oj.jar", "javalib/core-libart.jar",
          "framework/core-oj.jar", "framework/core-libart.jar")


def parse_listing(text):
    if len(text) > 1024*1024:
        raise ValueError("Directory listing budget exceeded")
    entries = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split("/")
        if len(fields) != 8 or fields[0] or fields[-1]:
            raise ValueError("Unexpected debugfs directory record")
        _, inode, mode, uid, gid, name, size, _ = fields
        if not (inode.isdecimal() and re.fullmatch(r"[0-7]{6}", mode)
                and uid.isdecimal() and gid.isdecimal()
                and (not size or size.isdecimal()) and NAME.fullmatch(name)):
            raise ValueError("Invalid directory metadata")
        if name in (".", ".."):
            continue
        if name in entries or len(entries) >= 4096:
            raise ValueError("Duplicate or excessive directory entries")
        kind = int(mode, 8) & 0o170000
        entries[name] = {"inode": int(inode), "type":
                         {0o040000:"directory",0o100000:"regular",0o120000:"symlink"}.get(kind,"other"),
                         "bytes": int(size) if size else None}
    return entries


def list_directory(tool, image, path):
    stat = command(tool, image, "stat "+path)
    if "File not found" in stat.stderr:
        return {"status":"NOT_FOUND","entries":{}}
    match = re.search(r"Inode:\s+\d+\s+Type:\s+(\w+)", stat.stdout)
    if not match:
        raise ValueError("Directory type unavailable: "+path)
    if match[1] != "directory":
        return {"status":"NOT_DIRECTORY","type":match[1],"entries":{}}
    result = command(tool, image, "ls -p "+path)
    return {"status":"DIRECTORY_OBSERVED","entries":parse_listing(result.stdout)}


def audit(image, pin, source_sha):
    checkout_sha(source_sha)
    tool = shutil.which("debugfs")
    if tool is None:
        raise ValueError("debugfs required")
    image = Path(image)
    directories, modules, members = {}, {}, {}
    with tempfile.TemporaryDirectory(prefix="r800-runtime-layout-") as tmp:
        scratch = Path(tmp)
        private = scratch/"system.img"
        snapshot_image(image, private, pin)
        for directory in ("/", "/system", "/apex", "/system/apex",
                          "/system/product/apex", "/product/apex",
                          "/system/system_ext/apex", "/system_ext/apex"):
            try:
                directories[directory] = list_directory(tool, private, directory)
            except (ValueError, OSError, subprocess.SubprocessError) as exc:
                directories[directory] = {"status":"REVIEW_REQUIRED","reason":str(exc),"entries":{}}
        roots = ["/system", ""]
        for directory, listing in directories.items():
            if not directory.endswith("/apex"):
                continue
            for name, entry in listing["entries"].items():
                if not MODULE.fullmatch(name):
                    continue
                path = directory+"/"+name
                row = dict(entry)
                modules[path] = row
                if entry["type"] == "directory":
                    roots.append(path)
                    for filename, parser in (("apex_manifest.pb",protobuf_manifest),
                                             ("apex_manifest.json",json_manifest)):
                        try:
                            raw = ext4_member(tool,private,path+"/"+filename,MAX_METADATA,scratch)
                            if raw is not None:
                                row[filename] = {"identity":parser(raw),"sha256":hashlib.sha256(raw).hexdigest()}
                        except (OSError,ValueError,subprocess.SubprocessError) as exc:
                            row[filename] = {"status":"REVIEW_REQUIRED","reason":str(exc)}
        for root in roots:
            for relative in WANTED:
                path = root+"/"+relative
                try:
                    stat = command(tool, private, "stat "+path)
                    if "File not found" in stat.stderr:
                        continue
                    match = re.search(r"Inode:\s+\d+\s+Type:\s+(\w+)",stat.stdout)
                    if not match:
                        raise ValueError("Unknown member type")
                    if match[1] != "regular":
                        members[path] = {"status":"NONREGULAR","type":match[1]}
                        continue
                    raw = ext4_member(tool,private,path,MAX_MEMBER,scratch)
                    if raw is None:
                        raise ValueError("Member disappeared")
                    members[path] = {"status":"OBSERVED",**classify(path,raw)}
                except (OSError,ValueError,RuntimeError,zipfile.BadZipFile,subprocess.SubprocessError) as exc:
                    members[path] = {"status":"REVIEW_REQUIRED","reason":str(exc)}
        if digest(private,4*1024**3)["sha256"] != pin or digest(image,4*1024**3)["sha256"] != pin:
            raise ValueError("System bytes changed")
    checkout_sha(source_sha)
    return {"schema":"galwear-r800-pixel-runtime-layout-v1","source_sha":source_sha,
            "image_sha256":pin,"status":"SELECTED_RUNTIME_LAYOUT_OBSERVATIONS_ONLY",
            "directories":directories,"module_candidates":modules,"members":members,
            "apex_activation_verified":False,"bionic_runtime_verified":False,
            "art_initialization_verified":False,"hardware_tested":False,"safe_to_flash":False}
