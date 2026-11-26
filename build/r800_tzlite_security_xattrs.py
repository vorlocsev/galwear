"""Bounded structural interpretation of selected Linux security xattrs."""
import hashlib
import struct

UNDEFINED=0xffffffff
ACL_NAMES=("system.posix_acl_access","system.posix_acl_default")
CAP_NAME="security.capability"
SELECTED=ACL_NAMES+(CAP_NAME,)
MAX_ACL_ENTRIES=256


def parse_acl(raw,mode,*,default=False,kind="regular"):
    if default and kind!="directory":
        raise ValueError("Default ACL on non-directory")
    if len(raw)<28 or (len(raw)-4)%8 or (len(raw)-4)//8>MAX_ACL_ENTRIES:
        raise ValueError("Invalid ACL entry count")
    if struct.unpack_from("<I",raw)[0]!=2:
        raise ValueError("Unsupported POSIX ACL version")
    entries=list(struct.iter_unpack("<HHI",raw[4:]))
    groups={tag:[] for tag in (1,2,4,8,16,32)}
    previous=0
    for tag,perm,ident in entries:
        if tag not in groups or tag<previous or perm>7:
            raise ValueError("Invalid ACL tag order or permission")
        previous=tag
        if tag in (2,8):
            if ident==UNDEFINED or (groups[tag] and ident<=groups[tag][-1][1]):
                raise ValueError("Invalid or duplicate named ACL identity")
        elif ident!=UNDEFINED or groups[tag]:
            raise ValueError("Invalid singleton ACL entry")
        groups[tag].append((perm,ident))
    if any(len(groups[tag])!=1 for tag in (1,4,32)):
        raise ValueError("Missing mandatory ACL entries")
    if (groups[2] or groups[8]) and not groups[16]:
        raise ValueError("Named ACL entries require mask")
    owner=groups[1][0][0]
    group=(groups[16] or groups[4])[0][0]
    other=groups[32][0][0]
    matches=(owner==(mode>>6)&7 and group==(mode>>3)&7 and other==mode&7)
    return {"format":"POSIX_ACL_XATTR_V2","entry_count":len(entries),
            "named_user_count":len(groups[2]),"named_group_count":len(groups[8]),
            "mask_present":bool(groups[16]),"mode_consistent":None if default else matches,
            "default_acl":default,"sha256":hashlib.sha256(raw).hexdigest(),
            "effective_access_verified":False}


def parse_disk_acl(raw,mode,*,default=False,kind="regular"):
    # ext4 disk ACL version 1: base/mask entries are 4 bytes,
    # named user/group entries 8 bytes. Normalize only in memory.
    if not 16<=len(raw)<=4+8*MAX_ACL_ENTRIES or struct.unpack_from("<I",raw)[0]!=1:
        raise ValueError("Invalid ext4 disk ACL version or size")
    offset=4
    entries=[]
    while offset<len(raw):
        if len(entries)>=MAX_ACL_ENTRIES or len(raw)-offset<4:
            raise ValueError("Truncated or excessive ext4 disk ACL entries")
        tag,perm=struct.unpack_from("<HH",raw,offset)
        offset+=4
        ident=UNDEFINED
        if tag in (2,8):
            if len(raw)-offset<4:
                raise ValueError("Truncated ext4 disk ACL identity")
            ident=struct.unpack_from("<I",raw,offset)[0]
            offset+=4
        elif tag not in (1,4,16,32):
            raise ValueError("Unknown ext4 disk ACL tag")
        entries.append((tag,perm,ident))
    normalized=struct.pack("<I",2)+b"".join(struct.pack("<HHI",*entry) for entry in entries)
    result=parse_acl(normalized,mode,default=default,kind=kind)
    result["format"]="EXT4_DISK_ACL_V1"
    result["sha256"]=hashlib.sha256(raw).hexdigest()
    result["disk_bytes"]=len(raw)
    return result


def parse_capability(raw,kind):
    if kind!="regular" or len(raw)<4:
        raise ValueError("Capability attribute requires regular file")
    magic=struct.unpack_from("<I",raw)[0]
    revision=magic>>24
    if revision not in (1,2,3) or len(raw)!={1:12,2:20,3:24}[revision] or magic&0x00fffffe:
        raise ValueError("Invalid capability revision, flags or size")
    permitted,inheritable=struct.unpack_from("<II",raw,4)
    if revision>=2:
        hi_p,hi_i=struct.unpack_from("<II",raw,12)
        permitted|=hi_p<<32
        inheritable|=hi_i<<32
    root_id=struct.unpack_from("<I",raw,20)[0] if revision==3 else None
    if root_id==UNDEFINED:
        raise ValueError("Invalid namespaced capability root ID")
    return {"format":"VFS_CAP_REVISION_"+str(revision),"effective_flag":bool(magic&1),
            "permitted_count":permitted.bit_count(),"inheritable_count":inheritable.bit_count(),
            "namespaced_root_id_present":root_id is not None,
            "sha256":hashlib.sha256(raw).hexdigest(),
            "effective_capabilities_verified":False}
