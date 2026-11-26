"""Compare original inode evidence with isolated staging metadata, never restore it."""
import os
import re
import stat
from pathlib import PurePosixPath

from r800_tzlite_dac import mode_bits, path_candidate
from r800_tzlite_manifest import fingerprint


def staged_metadata(root,tree,identity):
    result={}
    expected=dict(tree["entries"])
    expected["/"]={"kind":"directory","mode":tree["root_mode"]}
    for name,record in sorted(expected.items()):
        p=root/name.lstrip("/")
        st=p.lstat()
        kind=("directory" if stat.S_ISDIR(st.st_mode) else
              "regular" if stat.S_ISREG(st.st_mode) else
              "symlink" if stat.S_ISLNK(st.st_mode) else "other")
        expected_kind="regular" if record["kind"]=="file" else record["kind"]
        mode=oct(stat.S_IMODE(st.st_mode))
        if kind!=expected_kind or (kind!="symlink" and mode!=record["mode"]):
            raise ValueError("Staged metadata differs from manifest:"+name)
        if kind=="symlink" and os.readlink(p)!=record["target"]:
            raise ValueError("Staged symlink differs from manifest:"+name)
        attrs=sorted(os.listxattr(p,follow_symlinks=False))
        if len(attrs)>128 or any(not re.fullmatch(r"[A-Za-z0-9_.+-]{1,255}",v) for v in attrs):
            raise ValueError("Staged xattr names require review:"+name)
        if fingerprint(p.lstat())!=fingerprint(st):
            raise ValueError("Staged inode changed during scan:"+name)
        entry={"kind":kind,"uid":st.st_uid,"gid":st.st_gid,"mode":mode,
               "xattr_names":attrs}
        if kind=="symlink":
            entry["target"]=record["target"]
        elif "system.posix_acl_access" in attrs:
            entry["dac_candidate"]={"status":"REVIEW_REQUIRED_STAGED_ACL"}
        else:
            bits,selected=mode_bits(int(mode,8),identity,st.st_uid,st.st_gid)
            entry["dac_candidate"]={"status":"MODE_ONLY_ACL_ABSENCE_UNVERIFIED",
                                    "permission_bits":bits,"selected_class":selected}
        result[name]=entry
    return result


def metadata_differences(original,staged):
    changes={}
    for name in sorted(set(original)|set(staged)):
        src=original.get(name)
        dst=staged.get(name)
        if src is None or dst is None:
            changes[name]={"status":"STAGED_ONLY" if src is None else "ORIGINAL_ONLY"}
            continue
        fields={}
        for key in ("kind","uid","gid","mode"):
            if src[key]!=dst[key]:
                fields[key]={"original":src[key],"staged":dst[key]}
        if fields:
            changes[name]={"status":"METADATA_DIFFERS","fields":fields}
        old=set(src["xattr_inventory"]["attributes"])
        new=set(dst["xattr_names"])
        if old!=new:
            entry=changes.setdefault(name,{"status":"METADATA_DIFFERS","fields":{}})
            entry["reported_original_xattrs_not_staged"]=sorted(old-new)
            entry["staged_xattrs_not_reported_in_original"]=sorted(new-old)
        if src["kind"]==dst["kind"]=="symlink":
            changes.setdefault(name,{"status":"SYMLINK_LAYOUT_REVIEW","fields":{}})
    return changes


def staged_path(staged,alias,canonical,bit):
    if alias==canonical:
        dirs=[str(p) for p in reversed(PurePosixPath(canonical).parents)]
    else:
        # Stager flattens each audited alias into a relative link to a
        # canonical regular file. Validate each actual intermediate part.
        link=staged.get(alias,{})
        if link.get("kind")!="symlink":
            return {"status":"REVIEW_REQUIRED","reason":"Missing staged alias"}
        parts=alias.strip("/").split("/")[:-1]
        dirs=[str(p) for p in reversed(PurePosixPath(alias).parents)]
        for segment in link["target"].split("/"):
            if segment in ("","."):
                continue
            if segment=="..":
                if not parts:
                    return {"status":"REVIEW_REQUIRED","reason":"Staged link escapes root"}
                parts.pop()
            else:
                parts.append(segment)
                current="/"+"/".join(parts)
                if current!=canonical:
                    if staged.get(current,{}).get("kind")!="directory":
                        return {"status":"REVIEW_REQUIRED","reason":"Non-directory staged traversal"}
                    dirs.append(current)
        if "/"+"/".join(parts)!=canonical:
            return {"status":"REVIEW_REQUIRED","reason":"Staged alias target mismatch"}
        dirs.extend(str(p) for p in reversed(PurePosixPath(canonical).parents))
    return path_candidate(staged,canonical,bit,list(dict.fromkeys(dirs)))


def compare_access(original,staged,dac,closure):
    accesses={}
    for scope in ("files","aliases"):
        records={}
        for name,checks in sorted(dac[scope].items()):
            canonical=closure["aliases"].get(name,name) if scope=="aliases" else name
            for operation,source in checks.items():
                dest=staged_path(staged,name,canonical,source["requested_bit"])
                status=("REVIEW_REQUIRED" if "REVIEW_REQUIRED" in (source["status"],dest["status"])
                        else "DIFFERENT_CANDIDATE" if source["status"]!=dest["status"]
                        else "SAME_CANDIDATE_CLASS")
                records.setdefault(name,{})[operation]={"status":status,
                    "original":source["status"],"staged":dest["status"],
                    "staged_evidence":dest}
        accesses[scope]=records
    return {"status":"STATIC_METADATA_DIFFERENCES_ONLY",
            "metadata_differences":metadata_differences(original,staged),
            "access_comparison":accesses,
            "staged_metadata":staged,
            "runtime_identity_verified":False,"metadata_equivalence_verified":False,
            "xattr_values_compared":False,"effective_access_verified":False,
            "ownership_restored":False,"permission_changes_applied":False,
            "safe_to_flash":False}
