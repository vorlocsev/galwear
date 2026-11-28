#!/usr/bin/env python3
"""Explicit plugin selection and canonical ELF byte binding to local stock EXT4.

A plugin root adds its DT_NEEDED closure, not proof of dlopen search order,
host exports, constructors, configuration completeness or hardware operation.
Do not infer plugins from filenames or select an entire directory blindly.
"""
import hashlib
from pathlib import Path
import re
import shutil
import tempfile

from r800_android_linker_audit import inspect
from r800_android_userspace_preflight import read_regular
from r800_extract_ext4 import snapshot_image
from r800_framework_inventory import ext4_member
from r800_stage_android_layer import directory
from r800_partition_identity import filesystem
from r800_donor_preflight import digest, MAX_DONOR
from r800_tizen_dependencies import review_loads, interpreter, MAX_FILE, MAX_TOTAL
from r800_extract_super import require

MAX_PLUGINS=32


def plugin_paths(paths):
    from r800_verify_tizen_stage import guest_name
    require(isinstance(paths,(list,tuple)) and len(paths)<=MAX_PLUGINS and
            len(paths)==len(set(paths)),"Explicit unique bounded plugin paths required")
    for path in paths:
        guest_name(path)
        require(path.startswith(("/usr/lib/","/lib/")) and
                re.fullmatch(r"[A-Za-z0-9_.+-]+\.so(?:\.[0-9]+)*",Path(path).name),
                "Expected explicit Tizen shared-library plugin path")
    return tuple(sorted(paths))


def plugin_elf(raw):
    info=inspect(raw)
    require(info["abi"]=="arm" and info["elf_type"]=="ET_DYN" and info["has_dynamic"] and
            interpreter(raw) is None and not info["custom_search_path"],
            "Expected ARM32 dynamic plugin without interpreter or custom search path")
    require(not int.from_bytes(raw[36:40],"little")&0x400,"Hard-float plugin not supported")
    review_loads(raw,strict_pages=True)
    return {"abi":info["abi"],"elf_type":info["elf_type"],"needed":info["needed"],
            "soname":info["soname"]}


def selected(root, paths, files):
    from r800_verify_tizen_stage import guest_name
    result={}
    for path in plugin_paths(paths):
        require(path in files,"Selected plugin absent from closure: "+path)
        row=files[path]
        raw=read_regular(root/guest_name(path),MAX_FILE)
        require(len(raw)==row["bytes"] and hashlib.sha256(raw).hexdigest()==row["sha256"],
                "Selected plugin bytes changed: "+path)
        result[path]={"source":row["source"],"sha256":row["sha256"],"bytes":row["bytes"],
                      **plugin_elf(raw)}
    return result


def bind_canonical_image(image,pin,files,scratch):
    """Match every canonical staged ELF to a regular member of one stock image.

    The staged aliases are not independently resolved in EXT4. Matching bytes
    is not signature verification or proof of the original alias topology.
    """
    from r800_verify_tizen_stage import guest_name
    tool=shutil.which("debugfs")
    require(tool,"debugfs required")
    canonical={row["source"] for row in files.values()}
    require(canonical and canonical<=set(files),"Canonical closure inventory missing")
    total=0
    checked={}
    with tempfile.TemporaryDirectory(dir=scratch,prefix="tizen-elf-origin-") as tmp:
        work=Path(tmp)
        copy=work/"rootfs.img"
        snapshot_image(Path(image),copy,pin)
        require(filesystem(copy)["kind"]=="EXT4","Raw Tizen EXT4 required")
        parents=set()
        for path in sorted(canonical):
            guest_name(path)
            row=files[path]
            require(row["source"]==path,"Canonical source must refer to itself")
            require(type(row["bytes"]) is int and 0<row["bytes"]<=MAX_FILE,
                    "Invalid canonical ELF size")
            total+=row["bytes"]
            require(total<=MAX_TOTAL,"Canonical ELF byte budget exceeded")
            for parent in reversed(Path(path).parents):
                name=str(parent)
                if name!="/" and name not in parents:
                    directory(tool,copy,name)
                    parents.add(name)
            raw=ext4_member(tool,copy,path,row["bytes"],work)
            require(raw is not None and len(raw)==row["bytes"] and
                    hashlib.sha256(raw).hexdigest()==row["sha256"],
                    "Canonical ELF differs from Tizen image: "+path)
            checked[path]={"sha256":row["sha256"],"bytes":row["bytes"]}
        require(digest(copy,MAX_DONOR)["sha256"]==pin and
                digest(Path(image),MAX_DONOR)["sha256"]==pin,"Tizen image changed")
    return {"canonical_members":checked,"canonical_bytes":total,
            "canonical_image_bytes_match":True,"image_alias_topology_verified":False,
            "dlopen_runtime_verified":False}
