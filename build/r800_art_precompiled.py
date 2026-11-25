#!/usr/bin/env python3
"""Read-only ART precompiled artifact inventory, not an ART compatibility check."""
from __future__ import annotations
import re
import stat
import struct

from r800_android_userspace_preflight import guest_path

MAX_BYTES = 512 * 1024 * 1024
MAX_FILES = 256
MAX_SCAN = 4096
ROOTS = ("/system/framework", "/system_ext/framework", "/product/framework",
         "/apex/com.android.art/javalib", "/apex/com.android.runtime/javalib")
ISAS = {"arm": (1, 40), "arm64": (2, 183)}
SUFFIXES = (".art", ".oat", ".odex", ".vdex")
MAGICS = {".art": b"art\n", ".oat": b"oat\n", ".odex": b"oat\n", ".vdex": b"vdex"}


def identity(header, magic):
    if len(header) < 8 or header[:4] != magic or not re.fullmatch(rb"[0-9]{3}\x00", header[4:8]):
        raise ValueError("Invalid ART artifact magic or version")
    return header[4:7].decode("ascii")


def inspect(path, suffix, isa):
    st = path.lstat()
    if suffix not in MAGICS or isa not in ISAS:
        raise ValueError("Unsupported artifact kind or ISA")
    if not stat.S_ISREG(st.st_mode) or not 8 <= st.st_size <= MAX_BYTES:
        raise ValueError("Invalid ART artifact file size or type")
    with path.open("rb") as stream:
        def read(off, size):
            if off < 0 or size < 0 or off + size > st.st_size or size > 1024 * 1024:
                raise ValueError("ART read exceeds file bounds")
            stream.seek(off)
            data = stream.read(size)
            if len(data) != size:
                raise ValueError("Truncated ART artifact")
            return data
        head = read(0, min(64, st.st_size))
        out = {"bytes": st.st_size, "isa_directory": isa, "kind": suffix[1:],
               "elf_wrapped": False, "isa_verified": False,
               "compatibility_verified": False}
        if suffix in (".oat", ".odex") and head[:4] == b"\x7fELF":
            cls, machine = ISAS[isa]
            need = 64 if cls == 2 else 52
            if (len(head) < need or head[4:7] != bytes((cls, 1, 1)) or
                    struct.unpack_from("<HH", head, 16) != (3, machine)):
                raise ValueError("OAT ELF ISA or type mismatch")
            if cls == 2:
                shoff = struct.unpack_from("<Q", head, 40)[0]
                ehsize, phentsize, phnum, shentsize, shnum, shstr = struct.unpack_from("<6H", head, 52)
                shfmt = "<IIQQQQIIQQ"
            else:
                shoff = struct.unpack_from("<I", head, 32)[0]
                ehsize, phentsize, phnum, shentsize, shnum, shstr = struct.unpack_from("<6H", head, 40)
                shfmt = "<10I"
            if ehsize != need or shentsize != struct.calcsize(shfmt) or not 1 <= shnum <= 4096 or not 0 < shstr < shnum:
                raise ValueError("Unsupported OAT ELF section layout")
            raw = read(shoff, shentsize * shnum)
            sections = list(struct.iter_unpack(shfmt, raw))
            strings_section = sections[shstr]
            if strings_section[1] != 3:
                raise ValueError("Invalid OAT ELF string table")
            strings = read(strings_section[4], strings_section[5])
            candidates = []
            for section in sections:
                name_off = section[0]
                if name_off >= len(strings):
                    raise ValueError("OAT ELF section name out of bounds")
                end = strings.find(b"\0", name_off)
                if end == -1:
                    raise ValueError("Unterminated OAT ELF section name")
                if strings[name_off:end] in (b".rodata", b".oatdata"):
                    if section[1] != 1 or section[5] < 8:
                        continue
                    magic = read(section[4], 8)
                    if magic[:4] == b"oat\n":
                        candidates.append((section[4], magic))
            if len(candidates) != 1:
                raise ValueError("OAT header not uniquely located in ELF sections")
            offset, head = candidates[0]
            out.update({"elf_wrapped": True, "isa_verified": True, "oat_offset": offset})
        out["version"] = identity(head, MAGICS[suffix])
        out["status"] = "HEADER_INVENTORY_ONLY"
        return out


def audit(root):
    artifacts, errors, groups = {}, [], {}
    scanned = 0
    for base in ROOTS:
        for isa in ISAS:
            for directory in (base + "/" + isa, base + "/oat/" + isa):
                try:
                    resolved = guest_path(root, directory)
                    if not resolved.is_dir():
                        raise ValueError("ART ISA path is not a directory")
                    names = []
                    for entry in resolved.iterdir():
                        scanned += 1
                        if scanned > MAX_SCAN:
                            raise ValueError("ART directory scan limit exceeded")
                        if entry.suffix in SUFFIXES:
                            names.append(entry.name)
                            if len(names) + len(artifacts) > MAX_FILES:
                                raise ValueError("ART artifact count limit exceeded")
                    for name in sorted(names):
                        guest = directory + "/" + name
                        suffix = "." + name.rsplit(".", 1)[1]
                        if len(artifacts) >= MAX_FILES:
                            raise ValueError("ART artifact count limit exceeded")
                        artifacts[guest] = None
                        try:
                            info = inspect(guest_path(root, guest), suffix, isa)
                            artifacts[guest] = info
                            stem = name[:-len(suffix)]
                            group = groups.setdefault(directory + "/" + stem,
                                {"isa": isa, "files": {}, "boot_image": stem == "boot" or stem.startswith("boot-")})
                            group["files"][suffix[1:]] = guest
                        except (OSError, ValueError) as exc:
                            errors.append(guest + ": " + str(exc))
                except FileNotFoundError:
                    continue
                except (OSError, ValueError) as exc:
                    errors.append(directory + ": " + str(exc))
    for group in groups.values():
        files = group["files"]
        group["companion_headers_present"] = ("vdex" in files and
            ("oat" in files or "odex" in files) and
            (not group["boot_image"] or "art" in files))
        group["cross_artifact_compatibility_verified"] = False
    return {"status": "PRECOMPILED_HEADER_INVENTORY_ONLY" if artifacts and not errors and
            all(g["companion_headers_present"] for g in groups.values()) else "REVIEW_REQUIRED",
            "artifacts": artifacts, "groups": groups, "errors": errors,
            "oat_verified": False, "vdex_verified": False, "boot_image_verified": False,
            "dex2oat_executed": False, "safe_to_flash": False}
