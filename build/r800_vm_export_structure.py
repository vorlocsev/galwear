#!/usr/bin/env python3
"""Conservative structural review of flat OVF/OVA and embedded VMDK descriptors.

No extraction, disk mounting, VM import or guest execution. Only a narrow
self-contained streamOptimized VMDK profile is accepted; other formats need
review. This does not validate grain tables or all hypervisor settings.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import struct
import tarfile
import xml.etree.ElementTree as ET

from r800_vm_export_lock import inventory, pinned, MAX_BYTES, MAX_FILES
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha

OVF="http://schemas.dmtf.org/ovf/envelope/1"
Q=lambda n:"{"+OVF+"}"+n
MAX_XML=1024*1024
MAX_DESCRIPTOR=128*1024
FLAT=re.compile(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,254}")
EXTENT=re.compile(r'RW\s+([0-9]+)\s+SPARSE\s+"([^"]+)"')
VALUE=re.compile(r'([A-Za-z0-9_.]+)\s*=\s*(?:"([^"]*)"|([A-Za-z0-9_.+-]+))')


def flat(name):
    require(isinstance(name,str) and FLAT.fullmatch(name) and name not in (".",".."),
            "Unsafe or non-flat export name")
    return name


def descriptor(raw,name):
    require(0<len(raw)<=MAX_DESCRIPTOR,"VMDK descriptor exceeds budget")
    text=raw.rstrip(b"\0").decode("ascii")
    require("\0" not in text,"Unexpected embedded NUL in VMDK descriptor")
    fields={}
    extents=[]
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith("#"):
            continue
        match=EXTENT.fullmatch(line)
        if match:
            sectors,extent=match.groups()
            require(0<int(sectors)<=MAX_BYTES//512 and flat(extent)==name,
                    "External or invalid VMDK extent")
            extents.append(int(sectors))
            continue
        match=VALUE.fullmatch(line)
        require(match is not None,"Unsupported VMDK descriptor statement")
        key,quoted,bare=match.groups()
        require(key not in fields,"Duplicate VMDK descriptor key")
        require(key in ("version","encoding","CID","parentCID","createType") or key.startswith("ddb."),
                "Unsupported VMDK descriptor key")
        fields[key]=quoted if quoted is not None else bare
    require(fields.get("parentCID","").lower()=="ffffffff" and
            fields.get("createType")=="streamOptimized" and fields.get("version")=="1",
            "VMDK parent or unsupported disk format requires review")
    require(re.fullmatch(r"[0-9a-fA-F]{8}",fields.get("CID","")) is not None and
            len(extents)==1,"Expected one self-contained VMDK extent")
    return {"create_type":"streamOptimized","parent_cid":fields["parentCID"].lower(),
            "extent":name,"capacity_sectors":extents[0]}


def sparse_disk(read,size,name):
    header=read(0,512)
    require(len(header)==512 and header[:4]==b"KDMV","Expected sparse VMDK header")
    version,flags=struct.unpack_from("<II",header,4)
    capacity,grain,offset,count=struct.unpack_from("<QQQQ",header,12)
    require(version in (1,3) and flags&0x10000 and grain>0 and
            0<capacity<=MAX_BYTES//512,"Unsupported VMDK sparse header")
    require(offset>=1 and 0<count<=MAX_DESCRIPTOR//512 and
            (offset+count)*512<=size,"Invalid embedded VMDK descriptor bounds")
    raw=read(offset*512,count*512)
    require(len(raw)==count*512,"Truncated embedded VMDK descriptor")
    row=descriptor(raw,name)
    require(row["capacity_sectors"]==capacity,"VMDK header/descriptor capacity mismatch")
    return row


def ovf(raw,files):
    require(0<len(raw)<=MAX_XML and b"\0" not in raw and
            b"<!DOCTYPE" not in raw.upper() and b"<!ENTITY" not in raw.upper(),
            "Unsupported OVF XML encoding or declaration")
    text=raw.decode("utf-8")
    root=ET.fromstring(text)
    require(root.tag==Q("Envelope"),"Expected OVF envelope")
    require(sum(1 for _ in root.iter())<=4096,"OVF element budget exceeded")
    refs=root.findall(Q("References"))
    require(len(refs)==1,"Expected one OVF References section")
    rows={}
    for node in refs[0]:
        require(node.tag==Q("File"),"Unexpected OVF reference element")
        ident=node.get(Q("id"))
        href=flat(node.get(Q("href")))
        require(ident and ident not in rows and href not in rows.values() and href in files and
                Path(href).suffix.lower()==".vmdk","Missing, duplicate or unsupported OVF file reference")
        require(node.get(Q("compression")) is None and node.get(Q("chunkSize")) is None,
                "Compressed or chunked OVF reference requires review")
        size=node.get(Q("size"))
        require(size is None or (size.isascii() and size.isdecimal() and int(size)==files[href]),
                "OVF file size mismatch")
        rows[ident]=href
    disks={}
    sections=root.findall(Q("DiskSection"))
    require(len(sections)==1,"Expected one OVF DiskSection")
    for node in sections[0].findall(Q("Disk")):
        ident=node.get(Q("diskId"))
        ref=node.get(Q("fileRef"))
        require(ident and ident not in disks and ref in rows and rows[ref] not in disks.values(),
                "Invalid or external OVF disk reference")
        require(node.get(Q("parentRef")) is None,"OVF parent disk requires review")
        disks[ident]=rows[ref]
    require(disks and set(disks.values())==set(rows.values())==
            {n for n in files if Path(n).suffix.lower()==".vmdk"},"Unreferenced or missing VMDK")
    for node in root.iter():
        for key,value in node.attrib.items():
            local=key.rsplit("}",1)[-1].lower()
            if local in ("href","src","fileref","parentref"):
                require((node.tag==Q("File") and key==Q("href")) or
                        (node.tag==Q("Disk") and key==Q("fileRef")),
                        "Unexpected external-reference attribute")
        if node.tag.rsplit("}",1)[-1]=="HostResource":
            value=(node.text or "").strip()
            require(value.startswith("ovf:/disk/") and value[len("ovf:/disk/"):] in disks,
                    "Unsupported OVF HostResource")
    require(len(root.findall(Q("VirtualSystem")))==1 and
            not root.findall(Q("VirtualSystemCollection")),"Expected single virtual system")
    return {"references":rows,"disks":disks}


def examine(files,reader):
    names=[n for n in files if Path(n).suffix.lower()==".ovf"]
    require(len(names)==1 and all(Path(n).suffix.lower() in
            (".ovf",".vmdk",".mf",".cert",".nvram") for n in files),
            "Unexpected export member inventory")
    name=names[0]
    require(files[name]<=MAX_XML,"OVF descriptor exceeds budget")
    graph=ovf(reader(name,0,files[name]),files)
    disks={n:sparse_disk(lambda offset,count:reader(n,offset,count),files[n],n)
           for n in sorted(graph["disks"].values())}
    return {"ovf":name,**graph,"vmdk_descriptors":disks,
            "auxiliary_files":sorted(set(files)-set(disks)-{name})}


def read_at(stream,offset,count):
    require(0<=offset<=MAX_BYTES and 0<count<=MAX_XML,"Invalid bounded export read")
    stream.seek(offset)
    data=stream.read(count)
    require(len(data)==count,"Truncated export data")
    return data


def structural(root,observed):
    root=Path(root)
    if observed["format"]=="OPAQUE_OVA":
        name=next(iter(observed["files"]))
        path=root/name
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        with os.fdopen(fd,"rb") as stream:
            before=os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_size==observed["files"][name]["bytes"],
                    "OVA identity changed")
            with tarfile.open(fileobj=stream,mode="r:") as archive:
                members={}
                for member in archive:
                    require(len(members)<MAX_FILES and member.isreg() and
                            not member.issparse() and 0<member.size<=MAX_BYTES and
                            flat(member.name) not in members,"Unsupported or duplicate OVA member")
                    require(member.offset_data+member.size<=before.st_size,"OVA member exceeds file")
                    members[member.name]=member
                require(sum(m.size for m in members.values())<=MAX_BYTES,"OVA byte budget exceeded")
                files={n:m.size for n,m in members.items()}
                def reader(n,offset,count):
                    require(offset+count<=files[n],"OVA member read exceeds bounds")
                    return read_at(stream,members[n].offset_data+offset,count)
                return examine(files,reader)
    files={n:r["bytes"] for n,r in observed["files"].items()}
    def reader(n,offset,count):
        require(offset+count<=files[n],"Export read exceeds file bounds")
        fd=os.open(root/n,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        with os.fdopen(fd,"rb") as stream:
            st=os.fstat(stream.fileno())
            require(stat.S_ISREG(st.st_mode) and st.st_size==files[n],"Export identity changed")
            return read_at(stream,offset,count)
    return examine(files,reader)


def review(root,lock_path,lock_pin,source):
    checkout_sha(source)
    root=Path(root).absolute()
    raw,lock=pinned(lock_path,lock_pin)
    require(lock.get("schema")=="galwear-r800-vm-export-lock-v1" and
            lock.get("source_sha")==source and
            lock.get("status")=="VM_EXPORT_BYTES_MATCH_DECLARED_BASELINE_ONLY" and
            lock.get("safe_to_flash") is False,"Unexpected export lock scope")
    observed=inventory(root)
    require(observed==lock["export"],"VM export differs from pinned bytes")
    details=structural(root,observed)
    require(inventory(root)==observed and pinned(lock_path,lock_pin)[0]==raw,
            "Export or lock changed")
    checkout_sha(source)
    return {"schema":"galwear-r800-vm-export-structure-v1","source_sha":source,
            "status":"SELECTED_OVF_VMDK_REFERENCES_MATCH_ONLY","export_lock_sha256":lock_pin,
            "structure":details,"grain_tables_verified":False,"ovf_manifest_signature_verified":False,
            "hypervisor_configuration_verified":False,"guest_filesystem_verified":False,
            "vm_boot_verified":False,"donor_free_verified":False,"hardware_tested":False,
            "safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--export",type=Path,required=True)
    p.add_argument("--lock",type=Path,required=True)
    p.add_argument("--lock-sha256",required=True)
    p.add_argument("--source-sha",required=True)
    a=p.parse_args()
    print(json.dumps(review(a.export,a.lock,a.lock_sha256,a.source_sha),indent=2,sort_keys=True))


if __name__=="__main__":
    main()
