"""Inventory reported ext4 xattr names/sizes, not their values or effective permissions."""
import re
from r800_extract_ext4 import command

MAX_LIST=1024*1024
MAX_ATTRS=128
MAX_VALUE=65536
HEADER="Extended attributes:"


def parse_list(stdout,stderr):
    # debugfs can report command errors with process status zero.
    # Permit its version banner only; never include raw output in reports.
    if len(stdout)>MAX_LIST or len(stderr)>4096:
        raise ValueError("Extended attribute output exceeds budget")
    diagnostics=stderr.splitlines()
    if any(not re.fullmatch(r"debugfs [0-9][0-9A-Za-z.+~_-]* \([A-Za-z0-9-]+\)",line)
           for line in diagnostics if line.strip()):
        raise ValueError("Extended attribute diagnostics require review")
    lines=stdout.splitlines()
    if not stdout.strip():
        return {"status":"NONE_REPORTED","attributes":{},
                "absence_verified":False}
    if not lines or lines[0].strip()!=HEADER:
        raise ValueError("Unrecognized extended attribute listing")
    attrs={}
    for line in lines[1:]:
        match=re.fullmatch(r"[ \t]+([A-Za-z0-9_.+-]{1,255}) \(([0-9]{1,5})\)(?: = [^\r\n]*)?[ \t]*",line)
        if not match:
            raise ValueError("Unrecognized extended attribute entry")
        name,size=match[1],int(match[2])
        if "." not in name or name in attrs or size>MAX_VALUE or len(attrs)>=MAX_ATTRS:
            raise ValueError("Extended attribute entry exceeds contract")
        category=("posix_acl" if name in ("system.posix_acl_access","system.posix_acl_default")
                  else "linux_capability" if name=="security.capability"
                  else "selinux_label" if name=="security.selinux"
                  else "security_other" if name.startswith("security.")
                  else "other")
        attrs[name]={"reported_bytes":size,"category":category}
    if not attrs:
        raise ValueError("Empty extended attribute header")
    return {"status":"ATTRIBUTES_REPORTED","attributes":attrs,"absence_verified":False}


def inspect_xattrs(resolver, inode):
    if type(inode) is not int or not 1<=inode<2**32:
        raise ValueError("Invalid xattr inode")
    response=command(resolver.tool,resolver.snapshot,"ea_list <%d>"%inode)
    return parse_list(response.stdout,response.stderr)
