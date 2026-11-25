#!/usr/bin/env python3
"""Conservative compiled-policy prerequisite audit for nosuid EXT4 exec.

The pinned kernel permits nosuid domain changes via process2 permission
with nnp_nosuid_transition or a typebounds ancestry relation. This
checks static TE prerequisites, not the complete kernel AVC decision,
MLS constraints, inherited descriptor permissions or runtime execution.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

from r800_android_sepolicy_audit import audit, MAX_POLICY, sha
from r800_android_rootfs_preflight import snapshot
from r800_android_init_dependencies import regular

CAP = "nnp_nosuid_transition"
READY = "EXT4_NOSUID_POLICY_PREREQUISITES_ONLY"
BLOCKED = "EXT4_NOSUID_POLICY_PREREQUISITES_NOT_MET"
TRANSITIONS = {
    "stock": (("kernel", "init_exec", "init"),),
    "fixture": (("kernel", "init_exec", "init"),
                ("init", "galwear_property_client_exec", "galwear_property_client")),
}
NAME = r"[A-Za-z0-9_]+"
ALLOW = re.compile(r"allow\s+("+NAME+r")\s+("+NAME+r"):("+NAME+r")\s+(\{[^{};]+\}|"+NAME+r")\s*;")
TRANS = re.compile(r"type_transition\s+"+NAME+r"\s+"+NAME+r":process\s+("+NAME+r")\s*;")
BOUND = re.compile(r"typebounds\s+("+NAME+r")\s+("+NAME+r")\s*;")


def query(tool, policy, *args):
    out = subprocess.run([str(tool), *args, str(policy)], check=True,
                         capture_output=True, text=True, timeout=30)
    if len(out.stdout) > 1024*1024:
        raise ValueError("Policy query output exceeds bounds")
    return [line.strip() for line in out.stdout.splitlines() if line.strip()]


def allow(policy, tool, source, target, klass, permission):
    rules = query(tool, policy, "--allow", "-s", source, "-t", target,
                  "-c", klass, "-p", permission)
    # sesearch resolves matching attributes. Only unconditional rules count;
    # do not accept output containing a conditional suffix or unrelated perms.
    matches = []
    for line in rules:
        match = ALLOW.fullmatch(line)
        if match and match[3] == klass and permission in match[4].strip("{} ").split():
            matches.append(line)
    return {"source": source, "target": target, "class": klass,
            "permission": permission, "unconditional_allow_found": bool(matches),
            "matching_rules": matches[:20]}


def bounds_ancestry(lines, source, target):
    parents = {}
    for line in lines:
        m = BOUND.fullmatch(line)
        if not m or m[2] in parents:
            raise ValueError("Unexpected or duplicate typebounds statement")
        parents[m[2]] = m[1]
    chain = [target]
    while chain[-1] in parents:
        parent = parents[chain[-1]]
        if parent in chain or len(chain) >= 256:
            raise ValueError("Invalid typebounds ancestry")
        chain.append(parent)
    return chain, source in chain[1:]


def evaluate(policy, profile, seinfo="seinfo", sesearch="sesearch"):
    if profile not in TRANSITIONS:
        raise ValueError("Unknown transition profile")
    cap_rows = query(seinfo, policy, "--flat", "--polcap")
    if any(not re.fullmatch(r"policycap\s+"+NAME+r"\s*;", row) for row in cap_rows):
        raise ValueError("Unexpected policy capability output")
    cap = "policycap "+CAP+";" in cap_rows
    bounds = query(seinfo, policy, "--flat", "--typebounds")
    checks = []
    for source, entry, target in TRANSITIONS[profile]:
        rows = query(sesearch, policy, "--type_transition", "-s", source,
                     "-t", entry, "-c", "process", "-D", target)
        defaults = [line for line in rows if (m := TRANS.fullmatch(line)) and m[1] == target]
        perms = [allow(policy, sesearch, *args) for args in (
            (source, entry, "file", "execute"),
            (source, target, "process", "transition"),
            (target, entry, "file", "entrypoint"))]
        nosuid = allow(policy, sesearch, source, target, "process2", "nosuid_transition") if cap else None
        chain, bounded = bounds_ancestry(bounds, source, target)
        permission_route = cap and nosuid["unconditional_allow_found"]
        missing = []
        if not defaults:
            missing.append("unconditional type_transition")
        missing += [p["source"]+" "+p["target"]+":"+p["class"]+" "+p["permission"]
                    for p in perms if not p["unconditional_allow_found"]]
        if not (permission_route or bounded):
            missing.append("nosuid_transition permission or typebounds ancestry")
        checks.append({"source":source,"entrypoint_type":entry,"target":target,
                       "type_transition_rules":defaults[:20],"permissions":perms,
                       "nosuid_permission":nosuid,"typebounds_ancestry":chain,
                       "nosuid_permission_route":bool(permission_route),
                       "typebounds_route":bounded,"missing_static_prerequisites":missing})
    return {"status": READY if all(not c["missing_static_prerequisites"] for c in checks) else BLOCKED,
            "profile":profile,"nnp_nosuid_transition_policycap":cap,
            "transitions":checks,"nosuid_retained":True,
            "conditional_rules_accepted":False,"full_avc_decision_proven":False,
            "runtime_transition_tested":False,"safe_to_flash":False}


def evaluate_blob(blob, profile, seinfo="seinfo", sesearch="sesearch"):
    with tempfile.TemporaryDirectory(prefix="galwear-nosuid-") as tmp:
        path = Path(tmp)/"sepolicy"
        path.write_bytes(blob)
        result = evaluate(path, profile, seinfo, sesearch)
        if snapshot(path, MAX_POLICY) != blob:
            raise ValueError("Policy snapshot changed during query")
    return {**result, "policy_sha256":sha(blob)}


def require_ready(blob, profile, seinfo="seinfo", sesearch="sesearch"):
    result = evaluate_blob(blob, profile, seinfo, sesearch)
    if result["status"] != READY:
        missing = [c["source"]+"->"+c["target"]+": "+", ".join(c["missing_static_prerequisites"])
                   for c in result["transitions"] if c["missing_static_prerequisites"]]
        raise ValueError("EXT4 nosuid static prerequisites not met: "+"; ".join(missing))
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("product-out","checkfc","report"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--profile",choices=tuple(TRANSITIONS),required=True)
    p.add_argument("--seinfo",default="seinfo")
    p.add_argument("--sesearch",default="sesearch")
    a = p.parse_args()
    try:
        audited = audit(a.product_out,a.checkfc)
        policy = regular(a.product_out.resolve(strict=True),audited["policy_path"])
        if policy is None:
            raise ValueError("Audited policy missing")
        blob = snapshot(policy,MAX_POLICY)
        if sha(blob) != audited["policy_sha256"]:
            raise ValueError("Policy changed since audit")
        result = evaluate_blob(blob,a.profile,a.seinfo,a.sesearch)
        if snapshot(policy,MAX_POLICY) != blob:
            raise ValueError("Policy changed during query")
        rc = 0 if result["status"] == READY else 3
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RuntimeError,subprocess.SubprocessError) as exc:
        result = {"status":"REJECT","reason":str(exc),"safe_to_flash":False}
        rc = 2
    a.report.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result["status"])
    return rc

if __name__ == "__main__":
    raise SystemExit(main())
