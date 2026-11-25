#!/usr/bin/env python3
"""Derive a deliberately non-production test policy from pinned kernel mdp."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

MAX_POLICY = 1024 * 1024

def derive(source: str) -> str:
    for marker in ("type base_t;\n", "role base_r types { base_t };\n",
                   "user user_u roles { base_r };\n", "allow base_t base_t:file *;\n",
                   "fs_use_trans tmpfs user_u:base_r:base_t;\n"):
        if source.count(marker) != 1:
            raise ValueError("Unexpected kernel mdp template")
    return (source.replace("type base_t;\n", "type base_t;\ntype denied_t;\n")
            .replace("role base_r types { base_t };", "role base_r types { base_t denied_t };")
            .replace("user user_u roles { base_r };",
                     "allow base_t denied_t:file { getattr relabelto };\n"
                     "allow denied_t base_t:filesystem associate;\n"
                     "user user_u roles { base_r };"))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mdp", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    a.out.mkdir(exist_ok=False)
    original = a.out / "mdp.conf"
    contexts = a.out / "file_contexts"
    subprocess.run([str(a.mdp.resolve()), str(original), str(contexts)], check=True, timeout=30)
    policy = a.out / "diagnostic.conf"
    policy.write_text(derive(original.read_text()))
    binary = a.out / "policy.bin"
    subprocess.run(["checkpolicy", "-c", "31", "-o", str(binary), str(policy)], check=True, timeout=30)
    data = binary.read_bytes()
    if not 0 < len(data) <= MAX_POLICY:
        raise ValueError("Policy size outside bounds")
    (a.out / "policy_blob.h").write_text(
        "static const unsigned char policy_blob[] = {\n" +
        ",\n".join(",".join(str(x) for x in data[i:i+24]) for i in range(0,len(data),24)) +
        "\n};\n")
    (a.out / "policy-evidence.json").write_text(json.dumps({
        "status": "VIRT_TEST_POLICY_COMPILED_ONLY",
        "policy_version": 31, "policy_sha256": hashlib.sha256(data).hexdigest(),
        "source_sha256": hashlib.sha256(policy.read_bytes()).hexdigest(),
        "production_policy": False, "selinux_policy_loaded": False,
        "safe_to_flash": False}, indent=2) + "\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
