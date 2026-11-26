"""Non-executable, digest-bound review plan for tzlite deployment metadata."""
import hashlib
import json
import re

from r800_tzlite_audit import MOUNTPOINTS, REQUIRED_TREES


def digest(data):
    return hashlib.sha256(json.dumps(data,sort_keys=True,separators=(",",":"),
                                     ensure_ascii=True).encode("ascii")).hexdigest()


def plan(image_sha,manifest_sha,problems,original,comparison):
    if any(not re.fullmatch(r"[0-9a-f]{64}",v) for v in (image_sha,manifest_sha)):
        raise ValueError("Invalid review plan digest")
    report={"schema":"r800-tzlite-metadata-review-v1",
            "image_sha256":image_sha,"manifest_sha256":manifest_sha,
            "comparison_sha256":digest(comparison),
            "original_metadata_sha256":digest(original),
            "status":"BLOCKED_CONTENT_MISMATCH" if problems else "REVIEW_REQUIRED",
            "content_problems":list(problems),"items":[],
            "runtime_prerequisites":["Original donor authenticity",
                 "Complete configuration and plugin inventory",
                 "Actual process UID, GID and supplementary groups",
                 "Runtime mount layout and device access",
                 "SELinux enforcing policy and effective labels",
                 "Physical GNSS and Android location delivery"],
            "execution_authorized":False,"ownership_restoration_authorized":False,
            "privilege_restoration_authorized":False,"runtime_verified":False,
            "safe_to_flash":False}
    if problems:
        return report
    src=original["entries"]
    dst=comparison["staged_metadata"]
    differences=comparison["metadata_differences"]
    tasks={}
    def add(path,category,detail):
        tasks.setdefault((path,category),[]).append(detail)
    for name,change in sorted(differences.items()):
        status=change["status"]
        if status in ("STAGED_ONLY","ORIGINAL_ONLY"):
            add(name,"SCOPE_REVIEW","Path only present in one audited inventory; absence elsewhere unproven")
        fields=change.get("fields",{})
        if any(k in fields for k in ("uid","gid")):
            add(name,"OWNERSHIP_REVIEW","Resolve deployment identity independently of staging host")
        if "mode" in fields:
            add(name,"MODE_REVIEW","Review intended access; do not copy mode blindly")
        if "kind" in fields or status=="SYMLINK_LAYOUT_REVIEW":
            add(name,"PATH_LAYOUT_REVIEW","Validate deployed traversal and object type")
        if any(change.get(k) for k in ("reported_original_xattrs_not_staged",
                                       "staged_xattrs_not_reported_in_original")):
            add(name,"XATTR_REVIEW","Review reported attribute name differences; values not compared")
    for name in sorted(set(src)|set(dst)):
        old=src.get(name,{})
        new=dst.get(name,{})
        if any(rec.get("kind") in ("regular","directory") and
               int(rec["mode"],8)&0o6000 for rec in (old,new)):
            add(name,"PRIVILEGE_REVIEW","Special mode bits present; separate authorization required")
        if any(rec.get("kind") in ("regular","directory") and
               int(rec["mode"],8)&0o022 for rec in (old,new)):
            add(name,"WRITABLE_PATH_REVIEW","Group or other writable object")
        if old.get("kind")=="regular" and old.get("links",1)!=1:
            add(name,"PATH_LAYOUT_REVIEW","Original regular inode has multiple hardlinks")
        attrs=set(old.get("xattr_inventory",{}).get("attributes",{}))|set(new.get("xattr_names",[]))
        for attr in sorted(attrs):
            if attr.startswith("security.") or attr in ("system.posix_acl_access","system.posix_acl_default"):
                add(name,"PRIVILEGE_REVIEW","Security attribute requires separate review: "+attr)
    for scope in ("files","aliases"):
        for name,checks in sorted(comparison["access_comparison"][scope].items()):
            for operation,record in sorted(checks.items()):
                if (record["status"]!="SAME_CANDIDATE_CLASS"
                        or record["original"] in ("DENIED_CANDIDATE","REVIEW_REQUIRED")
                        or record["staged"] in ("DENIED_CANDIDATE","REVIEW_REQUIRED")):
                    add(name,"ACCESS_REVIEW",scope+":"+operation+":"+
                        record["original"]+"->"+record["staged"])
    for name in MOUNTPOINTS:
        add(name,"RUNTIME_MOUNT_REVIEW","Offline directory is not evidence of runtime mount")
    for name in REQUIRED_TREES:
        add(name,"SCOPE_REVIEW","Known directory only; complete contents unverified")
    add("/opt/usr/r800dev/gpsbridge","EXTERNAL_PAYLOAD_REVIEW",
        "External bridge not covered by donor component audit")
    report["items"]=[{"path":path,"category":category,"reasons":sorted(set(reasons)),
                      "disposition":"REVIEW_ONLY"}
                     for (path,category),reasons in sorted(tasks.items())]
    counts={}
    for item in report["items"]:
        cat=item["category"]
        counts[cat]=counts.get(cat,0)+1
    report["category_counts"]=counts
    return report
