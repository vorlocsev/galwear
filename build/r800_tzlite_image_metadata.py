"""Read-only ext4 inode mode/ownership evidence for selected tzlite paths."""
import re
from pathlib import PurePosixPath

from r800_extract_ext4 import command


def parse_inode(text, inode, kind):
    head=re.findall(r"^Inode:\s+(\d+)\s+Type:\s+(\w+)\s+Mode:\s+([0-7]{3,4})\s+Flags:",text,re.M)
    owners=re.findall(r"^User:\s+(\d+)\s+Group:\s+(\d+)(?:\s|$)",text,re.M)
    links=re.findall(r"^Links:\s+(\d+)(?:\s|$)",text,re.M)
    if len(head)!=1 or len(owners)!=1 or len(links)!=1:
        raise ValueError("Unrecognized or ambiguous ext4 inode metadata")
    ino,actual,mode=head[0]
    uid,gid=map(int,owners[0])
    count=int(links[0])
    mode=int(mode,8)
    if int(ino)!=inode or actual!=kind or not 0<=uid<2**32 or not 0<=gid<2**32 or not 1<=count<2**32:
        raise ValueError("Invalid ext4 inode metadata")
    return {"inode":inode,"kind":kind,"uid":uid,"gid":gid,"mode":oct(mode),"links":count}


def inspect_metadata(resolver,files):
    # Include only audited files, their canonical parents and the symlink
    # components actually encountered by the bounded image resolver.
    wanted=set(files)
    for name in files:
        wanted.update(str(p) for p in PurePosixPath(name).parents)
    wanted.update(name for name,item in resolver.stats.items()
                  if item is not None and item[1]=="symlink")
    if len(wanted)>4096:
        raise ValueError("Metadata inode budget exceeded")
    result={}
    reviews=[]
    cache={}
    for name in sorted(wanted):
        item=resolver.stat_guest(name)
        if item is None:
            raise ValueError("Missing audited metadata:"+name)
        inode,kind,_,_=item
        if name in files and kind!="regular":
            raise ValueError("Expected regular audited file:"+name)
        if kind not in ("regular","directory","symlink"):
            raise ValueError("Unexpected audited inode type:"+name)
        if inode not in cache:
            response=command(resolver.tool,resolver.snapshot,"stat <%d>"%inode)
            cache[inode]=parse_inode(response.stdout,inode,kind)
        rec=cache[inode]
        if rec["kind"]!=kind:
            raise ValueError("Inconsistent inode type:"+name)
        result[name]=rec
        mode=int(rec["mode"],8)
        if kind!="symlink":
            if mode&0o6000:
                reviews.append("SPECIAL_PRIVILEGE_MODE:"+name)
            if mode&0o022:
                reviews.append("GROUP_OR_OTHER_WRITABLE:"+name)
        if kind=="regular" and rec["links"]!=1:
            reviews.append("MULTIPLE_HARDLINKS:"+name)
    return {"status":"ORIGINAL_METADATA_INVENTORY_ONLY",
            "entries":result,"review_candidates":reviews,
            "acl_verified":False,"xattrs_verified":False,"effective_access_verified":False,
            "ownership_restored":False,"permissions_restored":False}
