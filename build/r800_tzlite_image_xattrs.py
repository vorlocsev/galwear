"""Inventory reported ext4 xattr names/sizes, not their values or effective permissions."""
import re
import stat
from r800_extract_ext4 import command
from r800_tzlite_security_xattrs import SELECTED, ACL_NAMES, CAP_NAME, parse_acl, parse_capability

MAX_LIST=1024*1024
MAX_ATTRS=128
MAX_VALUE=65536
HEADER="Extended attributes:"


def check_diagnostics(stderr):
    if len(stderr)>4096 or any(
            not re.fullmatch(r"debugfs [0-9][0-9A-Za-z.+~_-]* \([A-Za-z0-9-]+\)",line)
            for line in stderr.splitlines() if line.strip()):
        raise ValueError("Extended attribute diagnostics require review")


def parse_list(stdout,stderr):
    # debugfs can report command errors with process status zero.
    # Permit its version banner only; never include raw output in reports.
    if len(stdout)>MAX_LIST or len(stderr)>4096:
        raise ValueError("Extended attribute output exceeds budget")
    check_diagnostics(stderr)
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


def inspect_xattrs(resolver, inode, mode, kind):
    if type(inode) is not int or not 1<=inode<2**32:
        raise ValueError("Invalid xattr inode")
    response=command(resolver.tool,resolver.snapshot,"ea_list <%d>"%inode)
    report=parse_list(response.stdout,response.stderr)
    for name in SELECTED:
        item=report["attributes"].get(name)
        if item is None:
            continue
        target=resolver.scratch/"security-attribute"
        if target.exists() or target.is_symlink():
            raise ValueError("Unexpected private attribute output")
        try:
            result=command(resolver.tool,resolver.snapshot,
                           "ea_get -f security-attribute <%d> %s"%(inode,name),
                           cwd=resolver.scratch)
            check_diagnostics(result.stderr)
            if result.stdout.strip():
                raise ValueError("Unexpected attribute extraction output")
            st=target.lstat()
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink!=1
                    or st.st_size!=item["reported_bytes"] or st.st_size>MAX_VALUE):
                raise ValueError("Attribute extraction size mismatch")
            raw=target.read_bytes()
            if name in ACL_NAMES:
                item["structure"]=parse_acl(raw,mode,default=name==ACL_NAMES[1],kind=kind)
            elif name==CAP_NAME:
                item["structure"]=parse_capability(raw,kind)
        finally:
            target.unlink(missing_ok=True)
    return report
