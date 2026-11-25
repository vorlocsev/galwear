#!/usr/bin/env python3
"""Read-only GNSS identity and IPC layout audit. Never issues build credentials."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat

from r800_android_userspace_preflight import guest_path, read_regular
from r800_init_inventory import audit as init_audit
from r800_gnss_registration import SERVICE

ANDROID_DIR = "/oem/r800dev"
TIZEN_DIR = "/opt/usr/r800dev"
MAX_TEXT = 1024 * 1024
ID = re.compile(r"[1-9][0-9]{0,9}")


def number(value):
    if not ID.fullmatch(value) or int(value) > 2147483647:
        raise ValueError("Expected explicit non-root numeric ID")
    return int(value)


def account_candidates(root, kind):
    result = {}
    evidence = {}
    for part in ("system", "vendor", "odm", "product", "system_ext"):
        name = "/" + part + "/etc/" + kind
        try:
            raw = read_regular(guest_path(root, name), MAX_TEXT)
        except FileNotFoundError:
            continue
        evidence[name] = hashlib.sha256(raw).hexdigest()
        for line in raw.decode("utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            fields = line.split(":")
            if len(fields) != (7 if kind == "passwd" else 4) or not fields[0]:
                raise ValueError("Malformed account database: " + name)
            value = fields[2]
            if not re.fullmatch(r"0|[1-9][0-9]{0,9}", value) or int(value)>2147483647:
                raise ValueError("Invalid account ID: " + name)
            result.setdefault(fields[0], set()).add(int(value))
    return result, evidence


def resolve_id(token, accounts):
    if token.isdecimal():
        return number(token)
    values = accounts.get(token, set())
    if len(values) != 1 or 0 in values:
        raise ValueError("Unresolved, conflicting or root identity: " + token)
    return next(iter(values))


def identity(init, users, groups):
    services = [s for s in init["gnss_services"] if s["executable"] == SERVICE]
    if len(services) != 1 or init["errors"] or init["unresolved_imports"]:
        raise ValueError("GNSS service inventory incomplete or ambiguous")
    service = services[0]
    if any(d["name"] == service["name"] for d in init["duplicate_services"]):
        raise ValueError("Duplicate GNSS service")
    opts = service["options"]
    user = [o["args"] for o in opts if o["name"] == "user"]
    group = [o["args"] for o in opts if o["name"] == "group"]
    if len(user)!=1 or len(user[0])!=1 or len(group)!=1 or not group[0]:
        raise ValueError("Explicit unique user and group required")
    uid = resolve_id(user[0][0], users)
    gids = [resolve_id(g, groups) for g in group[0]]
    if len(set(gids)) != len(gids):
        raise ValueError("Duplicate GNSS group")
    return {"service":service["name"],"source":service["source"],
            "uid_candidate":uid,"primary_gid_candidate":gids[0],
            "supplementary_gid_candidates":gids[1:]}


def directory(root, guest):
    p = root
    for component in guest.strip("/").split("/"):
        p = p / component
        st = p.lstat()
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError("Non-directory or symbolic link in IPC path: " + guest)
        if stat.S_IMODE(st.st_mode) & 0o022:
            raise ValueError("Group/world-writable IPC ancestor: " + str(p.relative_to(root)))
        if st.st_uid != 0:
            raise ValueError("Non-root-owned IPC ancestor: " + str(p.relative_to(root)))
    return p, st


def mapping(android, tizen):
    ap, ast = directory(android, ANDROID_DIR)
    tp, tst = directory(tizen, TIZEN_DIR)
    if (ast.st_dev,ast.st_ino)!=(tst.st_dev,tst.st_ino):
        raise ValueError("IPC directories are not the same filesystem object")
    for name in ("gps.sock","gps.sock.owner"):
        for path in (ap/name,tp/name):
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            raise ValueError("Existing IPC entry needs separate ownership review: "+name)
    return {"device":ast.st_dev,"inode":ast.st_ino,
            "owner_uid":ast.st_uid,"group_gid":ast.st_gid,
            "mode":oct(stat.S_IMODE(ast.st_mode)),
            "same_directory_in_snapshot":True}


def label_evidence(root):
    # Evidence only. PCRE rules, precedence, type transitions and policy
    # access cannot be inferred by matching strings in a contexts file.
    out = {}
    for part in ("system","vendor","odm","product","system_ext"):
        for kind in ("file_contexts","hwservice_contexts"):
            name = f"/{part}/etc/selinux/{'plat' if part=='system' else part}_{kind}"
            try:
                raw = read_regular(guest_path(root,name),MAX_TEXT)
            except FileNotFoundError:
                continue
            out[name] = {"sha256":hashlib.sha256(raw).hexdigest(),
                "gnss_literal_mentioned":b"android.hardware.gnss" in raw,
                "ipc_path_literal_mentioned":b"/oem/r800dev" in raw}
    return out


def audit(android, tizen):
    android,tizen=android.resolve(strict=True),tizen.resolve(strict=True)
    if android==Path("/") or tizen==Path("/") or android==tizen:
        raise ValueError("Supply two distinct offline roots, not the host root")
    problems=[]
    report={"schema":"r800-gnss-ipc-layout-v1","identity":None,"mapping":None,
            "account_file_sha256":{},"label_evidence":{}}
    try:
        users,ue=account_candidates(android,"passwd")
        groups,ge=account_candidates(android,"group")
        report["account_file_sha256"]={**ue,**ge}
        report["identity"]=identity(init_audit(android),users,groups)
    except (OSError,ValueError) as exc:
        problems.append("IDENTITY: "+str(exc))
    try:
        report["mapping"]=mapping(android,tizen)
    except (OSError,ValueError) as exc:
        problems.append("MAPPING: "+str(exc))
    try:
        report["label_evidence"]=label_evidence(android)
    except (OSError,ValueError) as exc:
        problems.append("LABEL_EVIDENCE: "+str(exc))
    # Candidate IDs and static directory identity never authorize a daemon build.
    report.update({"status":"STATIC_CANDIDATES_ONLY" if not problems else "REVIEW_REQUIRED",
        "problems":problems,"effective_uid_gid_verified":False,
        "runtime_mount_identity_verified":False,"selinux_access_verified":False,
        "daemon_build_authorized":False,"safe_to_flash":False})
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--android-root",type=Path,required=True)
    p.add_argument("--tizen-root",type=Path,required=True)
    a=p.parse_args()
    try:
        report=audit(a.android_root,a.tizen_root)
    except (OSError,ValueError) as exc:
        report={"status":"REVIEW_REQUIRED","problems":[str(exc)],
                "daemon_build_authorized":False,"safe_to_flash":False}
    print(json.dumps(report,indent=2,sort_keys=True))
    return 2 if report["problems"] else 0


if __name__=="__main__":
    raise SystemExit(main())
