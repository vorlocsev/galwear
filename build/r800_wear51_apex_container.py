#!/usr/bin/env python3
"""Bounded observation of an APEX container and optional original_apex wrapper."""
import hashlib
import io
import re
import stat
import struct
import zipfile

from r800_apex_inventory import protobuf_manifest, json_manifest, MAX_METADATA
from r800_android_runtime_extract import MAX_APEX


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def inspect_container(raw, module):
    """Return metadata and optional decompressed nested APEX, not activation."""
    if not 22 <= len(raw) <= MAX_APEX:
        raise ValueError("APEX container outside byte budget")
    end=raw.rfind(b"PK\x05\x06",max(0,len(raw)-65557))
    if end<0 or len(raw)-end<22:
        raise ValueError("APEX ZIP end record missing")
    disk,cd_disk,disk_count,count,cd_size,cd_offset,comment=struct.unpack_from("<4H2IH",raw,end+4)
    if (disk or cd_disk or disk_count!=count or not 1<=count<=128 or
            cd_size>MAX_METADATA or cd_offset+cd_size!=end or end+22+comment!=len(raw)):
        raise ValueError("Unsupported APEX ZIP directory")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries=archive.infolist()
        by_name={i.filename:i for i in entries}
        if len(entries)!=count or len(by_name)!=count:
            raise ValueError("Duplicate or inconsistent APEX ZIP entries")
        for item in entries:
            if (not re.fullmatch(r"[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*",item.filename) or
                    any(p in (".","..") for p in item.filename.split("/")) or
                    item.flag_bits&1 or item.is_dir() or
                    stat.S_IFMT(item.external_attr>>16) not in (0,stat.S_IFREG)):
                raise ValueError("Unsafe APEX ZIP member")
        row={"container_sha256":sha(raw),"container_bytes":len(raw),
             "entries":[{"name":i.filename,"bytes":i.file_size,
                         "compressed_bytes":i.compress_size,"method":i.compress_type}
                        for i in entries],"layout":"DIRECT_OR_UNRECOGNIZED",
             "activation_verified":False,"safe_to_flash":False}
        if "original_apex" not in by_name:
            return row,None
        if "apex_payload.img" in by_name:
            raise ValueError("Ambiguous direct and nested APEX payload")
        manifests={}
        for name,parser in (("apex_manifest.pb",protobuf_manifest),("apex_manifest.json",json_manifest)):
            if name in by_name:
                item=by_name[name]
                if not 0<item.file_size<=MAX_METADATA:
                    raise ValueError("Wrapper manifest outside budget")
                manifests[name]=parser(archive.read(item))
        if not manifests or any(m["name"]!=module for m in manifests.values()) or len(
                {(m["name"],m["version"]) for m in manifests.values()})!=1:
            raise ValueError("Wrapper identity missing or inconsistent")
        item=by_name["original_apex"]
        if not 22<=item.file_size<=MAX_APEX or item.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):
            raise ValueError("Unsupported nested APEX size or compression")
        # Bounded by declared and actual length. zipfile validates CRC at EOF.
        with archive.open(item) as stream:
            nested=stream.read(item.file_size+1)
        if len(nested)!=item.file_size or not nested.startswith(b"PK\x03\x04"):
            raise ValueError("Invalid nested APEX")
        row.update(layout="ORIGINAL_APEX_WRAPPER",wrapper_identity=next(iter(manifests.values())),
                   nested_sha256=sha(nested),nested_bytes=len(nested))
        if "apex_pubkey" in by_name:
            item=by_name["apex_pubkey"]
            if not 0<item.file_size<=MAX_METADATA:
                raise ValueError("Wrapper public key outside budget")
            row["wrapper_pubkey_sha256"]=sha(archive.read(item))
        return row,nested
