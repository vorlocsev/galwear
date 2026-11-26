"""Conditional DAC candidates for one non-root identity; not effective process access."""
from pathlib import PurePosixPath


def identity_candidates(account):
    uid=account.get("uid_candidate")
    gid=account.get("primary_gid_candidate")
    if any(type(v) is not int or not 1<=v<=2147483647 for v in (uid,gid)):
        raise ValueError("Invalid non-root location identity")
    return (uid,gid)


def acl_bits(groups,identity,owner_uid,owner_gid):
    uid,gid=identity
    if uid==owner_uid:
        return groups[1][0][0],"owner"
    mask=groups[16][0][0] if groups[16] else 7
    for perm,ident in groups[2]:
        if ident==uid:
            return perm&mask,"named_user"
    matching=[perm for perm,ident in groups[8] if ident==gid]
    if gid==owner_gid:
        matching.append(groups[4][0][0])
    if matching:
        # Individual permission bits only; not an assertion that a
        # combined multi-bit Linux access request will succeed.
        bits=0
        for perm in matching:
            bits|=perm
        return bits&mask,"matching_groups"
    return groups[32][0][0],"other"


def mode_bits(mode,identity,owner_uid,owner_gid):
    uid,gid=identity
    if uid==owner_uid:
        return (mode>>6)&7,"owner"
    if gid==owner_gid:
        return (mode>>3)&7,"owning_group"
    return mode&7,"other"


def inode_candidate(record,identity):
    if record["kind"] not in ("regular","directory"):
        return {"status":"NOT_TESTED_NONREGULAR"}
    attrs=record["xattr_inventory"]["attributes"]
    acl=attrs.get("system.posix_acl_access")
    if acl is not None:
        structure=acl.get("structure",{})
        result=structure.get("dac_candidate")
        if structure.get("mode_consistent") is not True or not isinstance(result,dict):
            return {"status":"REVIEW_REQUIRED_ACL"}
        return dict(result,status="ACL_PRIMARY_GROUP_CANDIDATE")
    bits,selected=mode_bits(int(record["mode"],8),identity,record["uid"],record["gid"])
    return {"status":"MODE_ONLY_ACL_ABSENCE_UNVERIFIED","permission_bits":bits,"selected_class":selected}


def path_candidate(entries,name,required_bit,directories):
    records={path:1 for path in directories}
    records[name]=required_bit
    denied=[]
    unknown=[]
    conditional=[]
    for path,bit in records.items():
        item=entries.get(path,{})
        expected="regular" if path==name else "directory"
        rec=item.get("dac_candidate",{})
        if item.get("kind")!=expected or type(rec.get("permission_bits")) is not int:
            unknown.append(path)
        elif not rec["permission_bits"]&bit:
            denied.append(path)
        elif rec["status"]=="MODE_ONLY_ACL_ABSENCE_UNVERIFIED":
            conditional.append(path)
    status=("REVIEW_REQUIRED" if unknown else "DENIED_CANDIDATE" if denied
            else "CONDITIONAL_MODE_CANDIDATE" if conditional else "ACL_CANDIDATE")
    return {"status":status,"requested_bit":required_bit,
            "denied_paths":denied,"unknown_paths":unknown,
            "mode_only_paths":conditional}


def canonical_path_candidate(entries,name,required_bit):
    result=path_candidate(entries,name,required_bit,
                          [str(p) for p in reversed(PurePosixPath(name).parents)])
    return dict(result,canonical_path_only=True)


def alias_path_candidate(entries,alias,canonical,trace,required_bit):
    if (not isinstance(trace,dict) or trace.get("canonical")!=canonical
            or not isinstance(trace.get("directories"),list)
            or not trace["directories"] or trace["directories"][0]!="/"
            or not isinstance(trace.get("symlinks"),list)):
        return {"status":"REVIEW_REQUIRED","reason":"Missing or mismatched resolver trace",
                "requested_bit":required_bit,"canonical_path_only":False}
    directories=trace["directories"]
    mandatory={str(p) for p in PurePosixPath(canonical).parents}
    if not mandatory.issubset(directories) or any(
            entries.get(link["path"],{}).get("kind")!="symlink"
            for link in trace["symlinks"]):
        return {"status":"REVIEW_REQUIRED","reason":"Incomplete resolver trace metadata",
                "requested_bit":required_bit,"canonical_path_only":False}
    result=path_candidate(entries,canonical,required_bit,directories)
    return dict(result,canonical_path_only=False,guest_alias=alias,canonical=canonical,
                traversed_directories=directories,symlink_count=len(trace["symlinks"]))


def summarize(entries,closure,configs,programs,identity,traces):
    files={}
    executable={closure["aliases"].get(p) for p in programs}
    for name in sorted(set(closure["files"])|set(configs)):
        files[name]={"read":canonical_path_candidate(entries,name,4)}
        if name in executable:
            files[name]["execute"]=canonical_path_candidate(entries,name,1)
    aliases={}
    interpreters={item.get("interpreter") for item in closure["files"].values()}
    for alias,canonical in sorted(closure["aliases"].items()):
        trace=traces.get(alias)
        aliases[alias]={"read":alias_path_candidate(entries,alias,canonical,trace,4)}
        if alias in programs or alias in interpreters:
            aliases[alias]["execute"]=alias_path_candidate(entries,alias,canonical,trace,1)
    return {"status":"CONDITIONAL_DAC_CANDIDATES_ONLY",
            "identity":"location","uid_candidate":identity[0],"primary_gid_candidate":identity[1],
            "supplementary_groups_verified":False,"process_identity_verified":False,
            "capability_bypass_modeled":False,"selinux_access_verified":False,
            "alias_traversal_scope":"STATIC_RESOLVER_TRACE_ONLY",
            "alias_traversal_verified":False,"runtime_mounts_verified":False,
            "gpsbridge_path_status":"NOT_TESTED_EXTERNAL_PAYLOAD",
            "effective_access_verified":False,"files":files,"aliases":aliases}
