#!/usr/bin/env python3
"""Generate a small original Java bytecode fixture, with no external build tools.

Class GalwearProbe has public static void main(String[] args) and prints a
fixed marker via System.out.println. Only standard DEX 035 instructions.
"""
import hashlib
import struct
import zlib

from r800_art_inventory import dex_inventory

MARKER="GALWEAR_JAVA_VM_PROBE_OK"
CLASS="GalwearProbe"
MISSING_CLASS="GalwearMissingProbe"


def uleb(n):
    if n<0:
        raise ValueError("Negative ULEB128")
    out=bytearray()
    while n>=128:
        out.append((n&127)|128)
        n>>=7
    out.append(n)
    return bytes(out)


def build():
    descriptors=("LGalwearProbe;","Ljava/io/PrintStream;","Ljava/lang/Object;",
                 "Ljava/lang/String;","Ljava/lang/System;","V","[Ljava/lang/String;")
    strings=sorted(set(descriptors)|{"VL","main","out","println",MARKER})
    si={s:i for i,s in enumerate(strings)}
    types=sorted(descriptors,key=si.get)
    ti={s:i for i,s in enumerate(types)}
    protos=sorted([("V","Ljava/lang/String;"),("V","[Ljava/lang/String;")],
                  key=lambda p:(ti[p[0]],ti[p[1]]))
    methods=sorted([("LGalwearProbe;","main",("V","[Ljava/lang/String;")),
                    ("Ljava/io/PrintStream;","println",("V","Ljava/lang/String;"))],
                   key=lambda m:(ti[m[0]],si[m[1]],protos.index(m[2])))
    main=next(i for i,m in enumerate(methods) if m[1]=="main")
    println=next(i for i,m in enumerate(methods) if m[1]=="println")
    counts=(len(strings),len(types),len(protos),1,len(methods),1)
    widths=(4,4,12,8,8,32)
    offsets=[]
    pos=112
    for n,w in zip(counts,widths):
        offsets.append(pos)
        pos+=n*w
    data_off=pos
    buf=bytearray(pos)
    sections=[(0,1,0)]+[(i+1,n,o) for i,(n,o) in enumerate(zip(counts,offsets))]
    def aligned():
        buf.extend(b"\0"*((-len(buf))%4))
    # type_list items
    type_list_off=len(buf)
    param_offsets=[]
    for _,p in protos:
        aligned()
        param_offsets.append(len(buf))
        buf.extend(struct.pack("<IH",1,ti[p]))
        aligned()
    sections.append((0x1001,len(protos),type_list_off))
    # string_data items
    start=len(buf)
    for i,s in enumerate(strings):
        struct.pack_into("<I",buf,offsets[0]+4*i,len(buf))
        buf.extend(uleb(len(s))+s.encode("ascii")+b"\0")
    sections.append((0x2002,len(strings),start))
    aligned()
    code_off=len(buf)
    insns=(0x0062,0,0x011a,si[MARKER],0x206e,println,0x0010,0x000e)
    buf.extend(struct.pack("<4H2I",3,1,2,0,0,len(insns)))
    buf.extend(struct.pack("<"+"H"*len(insns),*insns))
    sections.append((0x2001,1,code_off))
    class_data=len(buf)
    buf.extend(b"\0\0\1\0"+uleb(main)+uleb(9)+uleb(code_off))
    sections.append((0x2000,1,class_data))
    aligned()
    map_off=len(buf)
    sections.append((0x1000,1,map_off))
    sections.sort(key=lambda r:r[2])
    buf.extend(struct.pack("<I",len(sections)))
    for kind,n,off in sections:
        buf.extend(struct.pack("<HHII",kind,0,n,off))
    for i,t in enumerate(types):
        struct.pack_into("<I",buf,offsets[1]+4*i,si[t])
    for i,(ret,param) in enumerate(protos):
        struct.pack_into("<III",buf,offsets[2]+12*i,si["VL"],ti[ret],param_offsets[i])
    struct.pack_into("<HHI",buf,offsets[3],ti["Ljava/lang/System;"],
                     ti["Ljava/io/PrintStream;"],si["out"])
    for i,(cls,name,proto) in enumerate(methods):
        struct.pack_into("<HHI",buf,offsets[4]+8*i,ti[cls],protos.index(proto),si[name])
    struct.pack_into("<8I",buf,offsets[5],ti["LGalwearProbe;"],1,
                     ti["Ljava/lang/Object;"],0,0xffffffff,0,class_data,0)
    buf[:8]=b"dex\n035\0"
    struct.pack_into("<6I",buf,32,len(buf),112,0x12345678,0,0,map_off)
    for i,(n,off) in enumerate(zip(counts,offsets)):
        struct.pack_into("<II",buf,56+8*i,n,off)
    struct.pack_into("<II",buf,104,len(buf)-data_off,data_off)
    buf[12:32]=hashlib.sha1(buf[32:]).digest()
    struct.pack_into("<I",buf,8,zlib.adler32(buf[12:])&0xffffffff)
    result=bytes(buf)
    dex_inventory(result)
    return result
