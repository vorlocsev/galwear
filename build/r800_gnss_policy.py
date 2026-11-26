#!/usr/bin/env python3
"""Inspect explicit GNSS SELinux type candidates in an offline binary policy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_selinux_inventory import policy_header, MAX_POLICY

TYPE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
BASE_KEYS = ("hal_domain","bridge_domain","oem_dir_type","ipc_dir_type",
             "socket_type","gnss_hwservice_type")
RULE = re.compile(r"allow\s+([A-Za-z0-9_]+)\s+([A-Za-z0-9_]+):"
                  r"([A-Za-z0-9_]+)\s+(\{[^{}]+\}|[A-Za-z0-9_]+)\s*;")
MAX_OUTPUT = 1024*1024


def requirements(types, samsung):
    keys=set(BASE_KEYS)
    if samsung:
        keys.add("sec_hwservice_type")
    if set(types)!=keys or not all(isinstance(v,str) and TYPE.fullmatch(v) for v in types.values()):
        raise ValueError("Expected explicit concrete type candidates for selected profile")
    hal=types["hal_domain"]
    # Necessary access-vector candidates, not sufficient runtime authorization.
    checks=[(hal,types["oem_dir_type"],"dir","search"),
            (hal,types["ipc_dir_type"],"dir","search"),
            (hal,types["socket_type"],"sock_file","write"),
            (hal,types["bridge_domain"],"unix_stream_socket","connectto"),
            (hal,types["gnss_hwservice_type"],"hwservice_manager","add")]
    if samsung:
        checks.append((hal,types["sec_hwservice_type"],"hwservice_manager","add"))
    return list(dict.fromkeys(checks))


def matching_rule(text, cls, perm):
    """Accept only unconditional allow output; never infer boolean state."""
    for line in text.splitlines():
        match=RULE.fullmatch(line.strip())
        if match and match[3]==cls and perm in match[4].strip("{}").split():
            return True
    return False


def query(tool,args):
    env=dict(os.environ,LC_ALL="C")
    result=subprocess.run([tool,*args],capture_output=True,timeout=30,check=True,env=env)
    if len(result.stdout)>MAX_OUTPUT or len(result.stderr)>MAX_OUTPUT:
        raise ValueError("SETools output exceeds budget")
    if result.stderr.strip():
        raise ValueError("SETools emitted diagnostics")
    return result.stdout.decode("utf-8")


def inspect(policy,expected_sha,types,samsung=False):
    if not re.fullmatch(r"[0-9a-f]{64}",expected_sha):
        raise ValueError("Expected policy SHA-256")
    checks=requirements(types,samsung)
    raw=read_regular(policy,MAX_POLICY)
    if hashlib.sha256(raw).hexdigest()!=expected_sha:
        raise ValueError("Policy SHA-256 mismatch")
    header=policy_header(raw)
    seinfo=shutil.which("seinfo")
    sesearch=shutil.which("sesearch")
    if not seinfo or not sesearch:
        raise ValueError("Install trusted SETools seinfo and sesearch")
    evidence=[]
    problems=[]
    with tempfile.TemporaryDirectory(prefix="r800-sepolicy-") as tmp:
        snapshot=Path(tmp)/"policy"
        snapshot.write_bytes(raw)
        snapshot.chmod(0o400)
        # Confirm each supplied name is a concrete type, not just an attribute.
        for typ in sorted(set(types.values())):
            output=query(seinfo,["-t",typ,str(snapshot)])
            if not any(line.strip()==typ for line in output.splitlines()):
                problems.append("CONCRETE_TYPE_NOT_CONFIRMED:"+typ)
        if not problems:
            for src,dst,cls,perm in checks:
                output=query(sesearch,["--allow","-s",src,"-t",dst,
                                      "-c",cls,"-p",perm,str(snapshot)])
                allowed=matching_rule(output,cls,perm)
                evidence.append({"source_type":src,"target_type":dst,"class":cls,
                                 "permission":perm,"unconditional_allow_candidate":allowed,
                                 "output_sha256":hashlib.sha256(output.encode()).hexdigest(),
                                 "rules":output.splitlines()})
                if not allowed:
                    problems.append("ALLOW_NOT_CONFIRMED:"+":".join((src,dst,cls,perm)))
        if hashlib.sha256(read_regular(snapshot,MAX_POLICY)).hexdigest()!=expected_sha:
            raise ValueError("Policy snapshot changed")
    if hashlib.sha256(read_regular(policy,MAX_POLICY)).hexdigest()!=expected_sha:
        raise ValueError("Policy input changed")
    return {"schema":"r800-gnss-policy-candidates-v1",
            "status":"STATIC_ALLOW_CANDIDATES_ONLY" if not problems else "REVIEW_REQUIRED",
            "problems":problems,"policy_sha256":expected_sha,"header":header,
            "profile":"samsung" if samsung else "aosp","types":types,"checks":evidence,
            "effective_labels_verified":False,"constraints_verified":False,
            "domain_transitions_verified":False,"policy_loaded_verified":False,
            "runtime_enforcing_verified":False,"selinux_access_verified":False,
            "safe_to_flash":False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy",type=Path,required=True)
    parser.add_argument("--sha256",required=True)
    parser.add_argument("--types",type=Path,required=True,
                        help="JSON object of explicit type candidates; no inferred labels")
    parser.add_argument("--samsung",action="store_true")
    args=parser.parse_args()
    try:
        types=json.loads(read_regular(args.types,16384))
        if not isinstance(types,dict):
            raise ValueError("Expected type candidate JSON object")
        report=inspect(args.policy,args.sha256,types,args.samsung)
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        report={"status":"REVIEW_REQUIRED","problems":[str(exc)],"safe_to_flash":False}
    print(json.dumps(report,indent=2,sort_keys=True))
    return 2 if report["problems"] else 0


if __name__=="__main__":
    raise SystemExit(main())
