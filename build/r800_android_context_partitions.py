#!/usr/bin/env python3
"""Prepare small additional context partitions, bound to the same policy.

No vendor executable, hardware firmware, host mount, or flash packaging.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from r800_android_rootfs_preflight import CONTEXTS, snapshot, sha
from r800_android_file_contexts import FILE_CONTEXTS, MAX_CONTEXTS
from r800_android_sepolicy_audit import audit, MAX_POLICY
from r800_android_init_dependencies import regular
from r800_android_system_ext4 import expected_label, materialize, inspect_inode, invoke
from r800_android_runtime_extract import digest, ext4

PARTITIONS = ("system_ext", "product", "vendor", "odm")
SIZE = 32*1024*1024


def collect(root, hashes):
    result = {}
    for partition in PARTITIONS:
        paths = [p for p in CONTEXTS if p.startswith(partition+"/") and p in hashes]
        fc = next(p for p in FILE_CONTEXTS if p.startswith(partition+"/"))
        if not paths and regular(root, fc) is None:
            continue
        entries = {}
        for rel in paths+[fc]:
            source = regular(root, rel)
            if source is None:
                raise ValueError("Missing required partition context: "+rel)
            data = snapshot(source, MAX_CONTEXTS)
            data.decode("utf-8")
            if b"\0" in data or (rel in hashes and sha(data) != hashes[rel]):
                raise ValueError("Partition context identity mismatch: "+rel)
            entries[rel] = (0o100644, data, 0, 0)
            for parent in Path(rel).parents:
                if str(parent) != ".":
                    entries.setdefault(str(parent), (0o040755, b"", 0, 0))
        result[partition] = entries
    return result


def build(a):
    root = a.product_out.resolve(strict=True)
    policy = audit(root, a.checkfc)
    blob = snapshot(regular(root, policy["policy_path"]), MAX_POLICY)
    if sha(blob) != policy["policy_sha256"]:
        raise ValueError("Policy changed")
    partitions = collect(root, policy["property_contexts_sha256"])
    tool_sha = digest(a.e2fsdroid, 128*1024*1024)
    if a.out.exists() or a.out.is_symlink():
        raise ValueError("Output must be new")
    reports = {}
    with tempfile.TemporaryDirectory(prefix="galwear-partitions-", dir="/tmp") as tmp:
        scratch = Path(tmp)
        pol = scratch/"sepolicy"
        pol.write_bytes(blob)
        # Android file contexts from every available partition, in platform order.
        files = []
        for i, rel in enumerate(FILE_CONTEXTS):
            src = regular(root, rel)
            if src is None:
                if i == 0:
                    raise ValueError("Platform file_contexts missing")
                continue
            data = snapshot(src, MAX_CONTEXTS)
            data.decode("utf-8")
            if b"\0" in data:
                raise ValueError("Invalid file contexts")
            path = scratch/("contexts-"+str(i))
            path.write_bytes(data)
            invoke([a.checkfc.resolve(strict=True), pol, path])
            files.append((rel, path, sha(data)))
        merged = scratch/"file_contexts"
        merged.write_bytes(b"\n".join(p.read_bytes() for _,p,_ in files)+b"\n")
        for partition, entries in partitions.items():
            for rel, item in entries.items():
                if rel in FILE_CONTEXTS and not any(rel == p and sha(item[1]) == h for p,_,h in files):
                    raise ValueError("File context snapshot mismatch")
            expected = {n: expected_label(merged,n,v[0],a.matchpathcon) for n,v in entries.items()}
            materialize(scratch, entries)
            image = scratch/(partition+".ext4")
            with image.open("xb") as stream:
                stream.truncate(SIZE)
            invoke([a.mke2fs,"-F","-t","ext4","-b","4096","-I","256","-m","0",
                    "-O","none,extent,filetype,dir_index,ext_attr,sparse_super,large_file",image])
            invoke([a.e2fsdroid.resolve(strict=True),"-e","-T","0","-S",
                    ",".join(str(p) for _,p,_ in files),"-a","/"+partition,
                    "-f",scratch/partition,image], timeout=300)
            ext4(image)
            if image.stat().st_size != SIZE:
                raise ValueError("Unexpected partition image size")
            invoke([a.e2fsck,"-f","-n",image], timeout=120)
            before = digest(image,SIZE)
            observed = {n:inspect_inode(image,n,v,expected[n],scratch,a.debugfs,partition)
                        for n,v in sorted(entries.items())}
            if digest(image,SIZE) != before:
                raise ValueError("Partition changed during audit")
            reports[partition] = {"sha256":before,"bytes":SIZE,"entries":observed}
        if digest(a.e2fsdroid,128*1024*1024) != tool_sha:
            raise ValueError("Image builder changed")
        a.out.mkdir(exist_ok=False)
        for partition, report in reports.items():
            dest = a.out/(partition+".ext4")
            with dest.open("xb") as dst, (scratch/dest.name).open("rb") as src:
                while chunk := src.read(1024*1024):
                    dst.write(chunk)
            if digest(dest,SIZE) != report["sha256"]:
                raise ValueError("Partition copy mismatch")
    return {"status":"ANDROID_CONTEXT_PARTITIONS_STATIC_ONLY",
            "policy_sha256":policy["policy_sha256"],"e2fsdroid_sha256":tool_sha,
            "file_contexts_sha256":{p:h for p,_,h in files},
            "property_contexts_sha256":policy["property_contexts_sha256"],
            "partitions":reports,"absent_partitions":[p for p in PARTITIONS if p not in reports],
            "complete_android_partitions":False,"kernel_mount_tested":False,
            "android_init_started":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("product-out","checkfc","e2fsdroid","out","report"):
        p.add_argument("--"+name,type=Path,required=True)
    for name in ("mke2fs","e2fsck","debugfs","matchpathcon"):
        p.add_argument("--"+name,default=name)
    a=p.parse_args()
    try:
        report=build(a)
        rc=0
    except (OSError,ValueError,KeyError,TypeError,RuntimeError,subprocess.SubprocessError) as exc:
        report={"status":"REJECT","reason":str(exc),"safe_to_flash":False}
        rc=2
    a.report.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(report["status"])
    return rc

if __name__=="__main__":
    raise SystemExit(main())
