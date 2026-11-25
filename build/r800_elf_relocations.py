#!/usr/bin/env python3
"""Bounded AArch64 ELF dynamic relocation inventory, without applying writes.

Only the Android 11 diagnostic ET_DYN subset is accepted. Parse PT_DYNAMIC
and PT_LOAD directly, independent of section names and readelf formatting.
"""
import struct
from collections import Counter

MAX = 32*1024*1024
COUNT = 1000000
U64 = (1<<64)-1
TYPES = {0:("NONE",0),257:("ABS64",8),1025:("GLOB_DAT",8),
         1026:("JUMP_SLOT",8),1027:("RELATIVE",8),1028:("TLS_DTPMOD",8),
         1029:("TLS_DTPREL",8),1030:("TLS_TPREL",8),1031:("TLSDESC",16),
         1032:("IRELATIVE",8)}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sleb(data, pos):
    value=0
    for i in range(10):
        require(pos<len(data),"Truncated APS2 SLEB128")
        byte=data[pos]
        pos+=1
        value|=(byte&127)<<(7*i)
        if not byte&128:
            if byte&64:
                value-=1<<(7*(i+1))
            require(-(1<<63)<=value<(1<<63),"APS2 signed integer overflow")
            return value,pos
    raise ValueError("Overlong APS2 SLEB128")


def aps2(data):
    require(data.startswith(b"APS2"),"Invalid APS2 magic")
    pos=4
    def pop():
        nonlocal pos
        value,pos=sleb(data,pos)
        return value
    count,offset=pop(),pop()
    require(0<=count<=COUNT and 0<=offset<=U64,"Invalid APS2 header")
    addend=0
    emitted=0
    while emitted<count:
        size,flags=pop(),pop()
        require(0<size<=count-emitted and 0<=flags<=15 and
                (not flags&4 or flags&8),"Invalid APS2 relocation group")
        delta=pop() if flags&2 else None
        info=pop() if flags&1 else None
        if flags&8:
            if flags&4:
                addend+=pop()
        else:
            addend=0
        for _ in range(size):
            offset+=delta if delta is not None else pop()
            value=info if info is not None else pop()
            if flags&8 and not flags&4:
                addend+=pop()
            require(0<=offset<=U64 and 0<=value<=U64 and
                    -(1<<63)<=addend<(1<<63),"APS2 relocation arithmetic overflow")
            emitted+=1
            yield offset,value,addend
    require(pos==len(data),"Unexpected trailing APS2 bytes")


def relr(data):
    require(len(data)%8==0 and len(data)//8<=COUNT,"Invalid RELR table size")
    base=None
    count=0
    for (entry,) in struct.iter_unpack("<Q",data):
        if not entry&1:
            require(entry%8==0 and entry<=U64-8,"Invalid RELR address")
            require(base is None or entry>=base,"Nonmonotonic RELR address")
            base=entry+8
            count+=1
            require(count<=COUNT,"RELR count exceeds limit")
            yield entry
        else:
            require(base is not None and base<=U64-504,"RELR bitmap without valid base")
            for bit in range(1,64):
                if entry&(1<<bit):
                    count+=1
                    require(count<=COUNT,"RELR count exceeds limit")
                    yield base+8*(bit-1)
            base+=504


def inspect(data, symbol_count):
    require(64<=len(data)<=MAX and data[:7]==b"\x7fELF\x02\x01\x01",
            "Expected bounded little-endian ELF64")
    require(0<symbol_count<=100000,"Invalid dynamic symbol count")
    et,machine,version,_,phoff,_,_,ehsize,phentsize,phnum,_,_,_=struct.unpack_from("<HHIQQQIHHHHHH",data,16)
    require((et,machine,version,ehsize,phentsize)==(3,183,1,64,56) and
            0<phnum<=256 and phoff>=64 and phoff+phnum*56<=len(data),"Invalid ELF program headers")
    loads=[]
    dynamic=[]
    for i in range(phnum):
        kind,flags,off,va,_,fs,ms,align=struct.unpack_from("<IIQQQQQQ",data,phoff+i*56)
        if kind not in (1,2):
            continue
        require(fs<=ms and off+fs<=len(data) and va+ms<=U64+1,"Invalid ELF segment bounds")
        if kind==1:
            loads.append((va,ms,off,fs,flags))
        else:
            dynamic.append((va,fs,off))
    require(loads and len(dynamic)==1,"Expected one PT_DYNAMIC and PT_LOAD")
    def file_range(addr,size):
        require(0<=addr<=U64 and 0<size<=MAX and addr+size<=U64+1,"Invalid table range")
        hits=[off+addr-va for va,_,off,fs,_ in loads if va<=addr and addr+size<=va+fs]
        require(len(hits)==1,"Relocation table not uniquely file-backed")
        return hits[0]
    va,size,off=dynamic[0]
    require(size%16==0 and file_range(va,size)==off,"Invalid PT_DYNAMIC mapping")
    tags={}
    relevant={2,7,8,9,17,18,19,20,22,23,30,35,36,37,
              0x6000000f,0x60000010,0x60000011,0x60000012,0x6fffe000,0x6fffe001,0x6fffe003}
    terminated=False
    for tag,val in struct.iter_unpack("<qQ",data[off:off+size]):
        if tag==0:
            terminated=True
            break
        if tag in relevant:
            require(tag not in tags,"Duplicate dynamic relocation tag")
            tags[tag]=val
    require(terminated,"Missing DT_NULL")
    require(not ({17,18,19,22,0x6000000f,0x60000010}&tags.keys()) and
            not tags.get(30,0)&4,"Unsupported REL or text relocations")
    require(9 not in tags or tags[9]==24,"Invalid DT_RELAENT")
    ranges=[]
    def table(address_tag,size_tag,entry_size=1):
        if address_tag not in tags and size_tag not in tags:
            return b""
        require(address_tag in tags and size_tag in tags,"Incomplete relocation table tags")
        n=tags[size_tag]
        require(n%entry_size==0 and n<=MAX,"Invalid relocation table size")
        if not n:
            return b""
        start=file_range(tags[address_tag],n)
        require(all(start+n<=a or start>=b for a,b in ranges),"Overlapping relocation tables")
        ranges.append((start,start+n))
        return data[start:start+n]
    counts=Counter()
    seen=[]
    total=0
    def check(address,info,source):
        nonlocal total
        total+=1
        require(total<=COUNT,"Combined relocation count exceeds limit")
        sym,kind=info>>32,info&0xffffffff
        require(kind in TYPES,"Unsupported AArch64 relocation type: "+str(kind))
        require(sym<symbol_count,"Relocation symbol index outside dynsym")
        require(kind not in (1027,1032) or sym==0,"Relative relocation has symbol")
        name,width=TYPES[kind]
        counts[source+":"+name]+=1
        if not width:
            return
        require(address+width<=U64+1 and any(va<=address and address+width<=va+ms and
                flags&2 and not flags&1 for va,ms,_,_,flags in loads),
                "Relocation target outside writable non-executable PT_LOAD")
        seen.append((address,address+width))
    for address,info,addend in struct.iter_unpack("<QQq",table(7,8,24)):
        check(address,info,"RELA")
    if 23 in tags or 2 in tags or 20 in tags:
        require(tags.get(20)==7 and 23 in tags and 2 in tags,"Expected RELA PLT table")
        for address,info,addend in struct.iter_unpack("<QQq",table(23,2,24)):
            check(address,info,"PLT")
    for address,info,addend in aps2(packed) if (packed:=table(0x60000011,0x60000012)) else ():
        check(address,info,"APS2")
    std={35,36,37}&tags.keys()
    android={0x6fffe000,0x6fffe001,0x6fffe003}&tags.keys()
    require(not (std and android),"Conflicting RELR encodings")
    if std or android:
        addr,sz,ent=(36,35,37) if std else (0x6fffe000,0x6fffe001,0x6fffe003)
        require(tags.get(ent)==8 and addr in tags and sz in tags,"Invalid RELR entry size/tags")
        for address in relr(table(addr,sz,8)):
            check(address,1027,"RELR")
    seen.sort()
    require(all(a[1]<=b[0] for a,b in zip(seen,seen[1:])),"Overlapping relocation targets")
    return {"relocation_count":total,"counts_by_encoding_and_type":dict(sorted(counts.items())),
            "write_target_bounds_verified":True,"symbol_index_bounds_verified":True,
            "packed_relocations_decoded":True,"relocations_applied":False,
            "stub_exclusion_proven":False}
