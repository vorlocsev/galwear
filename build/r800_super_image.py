#!/usr/bin/env python3
"""Read-only single-device Android super metadata inspection and donor extraction."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tempfile

MAX = 8*1024**3
SECTOR = 512
BASE = 12288

def read_at(f, off, size):
    f.seek(off)
    raw = f.read(size)
    if len(raw) != size:
        raise ValueError("Truncated super image")
    return raw

def hashed(raw, start):
    return hashlib.sha256(raw[:start]+bytes(32)+raw[start+32:]).digest()

def geometry(f, offset):
    raw = read_at(f, offset, 52)
    magic, size = struct.unpack_from("<II",raw)
    maximum, slots, block = struct.unpack_from("<III",raw,40)
    if (magic != 0x616c4467 or size != 52 or raw[8:40] != hashed(raw,8)
            or not 4096 <= maximum <= 1024*1024 or maximum%512
            or not 1 <= slots <= 4 or not 512 <= block <= 65536 or block%512):
        raise ValueError("Invalid super geometry")
    return maximum,slots,block

def name(raw):
    n = raw.split(b"\0",1)[0].decode("ascii")
    if not re.fullmatch(r"[A-Za-z0-9_]{1,36}",n):
        raise ValueError("Invalid logical partition name")
    return n

def metadata(f, offset, maximum):
    raw = read_at(f,offset,maximum)
    magic, major, minor, hs = struct.unpack_from("<IHHI",raw)
    if magic != 0x414c5030 or major != 10 or minor not in (0,1,2) or hs != (256 if minor==2 else 128):
        raise ValueError("Unsupported super metadata version")
    ts = struct.unpack_from("<I",raw,44)[0]
    if hs+ts > maximum or raw[12:44] != hashed(raw[:hs],12):
        raise ValueError("Invalid super header checksum or bounds")
    tables=raw[hs:hs+ts]
    if raw[48:80] != hashlib.sha256(tables).digest():
        raise ValueError("Invalid super tables checksum")
    result=[]
    ranges=[]
    for idx, entry in enumerate((52,24,48,64)):
        off,count,esize=struct.unpack_from("<III",raw,80+idx*12)
        end=off+count*esize
        if esize!=entry or count>65536 or end>ts:
            raise ValueError("Invalid super table descriptor")
        if count:
            ranges.append((off,end))
        result.append([tables[p:p+entry] for p in range(off,end,entry)])
    ranges.sort()
    if any(a[1]>b[0] for a,b in zip(ranges,ranges[1:])):
        raise ValueError("Overlapping metadata tables")
    return result, hashlib.sha256(raw[:hs+ts]).hexdigest()

def inspect(f,size,slot):
    maximum,slots,block=geometry(f,4096)
    if geometry(f,8192)!=(maximum,slots,block):
        raise ValueError("Super geometry copies differ")
    if not 0<=slot<slots:
        raise ValueError("Invalid metadata slot")
    tables,sha=metadata(f,BASE+slot*maximum,maximum)
    backup,bsha=metadata(f,BASE+(slots+slot)*maximum,maximum)
    if sha!=bsha:
        raise ValueError("Super metadata copies differ")
    partitions,extents,groups,devices=tables
    if len(devices)!=1 or not groups:
        raise ValueError("Only single-device super supported")
    first,align,off,capacity=struct.unpack_from("<QIIQ",devices[0])
    if not BASE+2*slots*maximum<=first*SECTOR<=capacity<=size or capacity%SECTOR:
        raise ValueError("Invalid super block device bounds")
    result={}
    used=set()
    physical=[]
    group_bytes=[0]*len(groups)
    for p in partitions:
        n=name(p[:36])
        attr,start,count,group=struct.unpack_from("<IIII",p,36)
        if n in result or attr&~15 or start+count>len(extents) or group>=len(groups):
            raise ValueError("Invalid partition descriptor")
        spans=[]
        total=0
        for i in range(start,start+count):
            if i in used:
                raise ValueError("Shared logical extent")
            used.add(i)
            sectors,kind,target,source=struct.unpack("<QIQI",extents[i])
            length=sectors*SECTOR
            if not length or total+length>MAX:
                raise ValueError("Invalid extent length")
            if kind==0 and source==0 and first<=target and target+sectors<=capacity//SECTOR:
                physical.append((target,target+sectors))
                spans.append((target*SECTOR,length))
            elif kind==1 and target==0 and source==0:
                spans.append((None,length))
            else:
                raise ValueError("Unsupported or out-of-range extent")
            total+=length
        group_bytes[group]+=total
        result[n]={"bytes":total,"attributes":attr,"extents":spans}
    physical.sort()
    if any(a[1]>b[0] for a,b in zip(physical,physical[1:])):
        raise ValueError("Overlapping physical extents")
    for i,g in enumerate(groups):
        limit=struct.unpack_from("<Q",g,40)[0]
        if limit and group_bytes[i]>limit:
            raise ValueError("Group size exceeded")
    return result,sha

def run(source,slot,partition=None,output=None):
    source=Path(source)
    st=source.lstat()
    if not stat.S_ISREG(st.st_mode) or not BASE<=st.st_size<=MAX:
        raise ValueError("Expected bounded raw super image")
    with source.open("rb") as f:
        parts,sha=inspect(f,st.st_size,slot)
        report={"status":"SUPER_METADATA_STRUCTURE_ONLY","slot":slot,"metadata_sha256":sha,
                "partitions":{n:{"bytes":v["bytes"],"extent_count":len(v["extents"])}
                              for n,v in parts.items()},"safe_to_flash":False}
        if partition is not None:
            if not re.fullmatch(r"(system|vendor|product|system_ext|odm)(_[ab])?",partition):
                raise ValueError("Partition outside donor allowlist")
            if partition not in parts or not parts[partition]["bytes"] or parts[partition]["attributes"]&8:
                raise ValueError("Missing, empty or disabled partition")
            output=Path(output)
            if output.exists() or output.is_symlink():
                raise ValueError("Output already exists")
            with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
                candidate=Path(tmp)/"image"
                h=hashlib.sha256()
                with candidate.open("xb") as out:
                    for offset,length in parts[partition]["extents"]:
                        while length:
                            n=min(length,1024*1024)
                            data=bytes(n) if offset is None else read_at(f,offset,n)
                            out.write(data)
                            h.update(data)
                            length-=n
                            if offset is not None:
                                offset+=n
                end=os.fstat(f.fileno())
                if (end.st_size,end.st_mtime_ns)!=(st.st_size,st.st_mtime_ns):
                    raise ValueError("Super input changed")
                os.link(candidate,output)
            report.update(status="SUPER_DONOR_EXTRACTED_ONLY",extracted=partition,
                          sha256=h.hexdigest())
        return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--slot",type=int,required=True)
    p.add_argument("--partition")
    p.add_argument("--output",type=Path)
    a=p.parse_args()
    if (a.partition is None)!=(a.output is None):
        p.error("partition and output must be supplied together")
    print(json.dumps(run(a.source,a.slot,a.partition,a.output),sort_keys=True))

if __name__=="__main__":
    main()
