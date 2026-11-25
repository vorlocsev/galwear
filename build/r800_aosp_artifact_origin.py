#!/usr/bin/env python3
"""Verify selected installed AOSP artifacts against the recorded fresh build.

This is local build provenance, not signed attestation or proof that a
library implements its advertised API. No intermediate/SDK paths are used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

STATUS = "AOSP_SELECTED_ARTIFACT_ORIGIN_ONLY"
HEX = re.compile(r"[0-9a-f]{64}")
MANIFEST_LIMIT = 8*1024*1024
MANIFEST_PIN = "4466d48178452bf5ac136852bf2768af407a0584"
SYSTEM = re.compile(r"system/(?:bin/(?:bootstrap/)?(?:init|galwear_property_service|galwear_property_client|linker64)|lib64/(?:bootstrap/)?[A-Za-z0-9_.+-]+\.so)")
RUNTIME = "apex/com.android.runtime"
APEX = re.compile(r"apex/com\.android\.runtime/(?:bin/linker64|lib64/bionic/lib(?:c|dl|m)\.so)")


def manifest_digest(path):
    # Lazy import callers can use this helper without importing pipeline.
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing resolved manifest")
    with path.open("rb") as stream:
        data=stream.read(MANIFEST_LIMIT+1)
    if not 0<len(data)<=MANIFEST_LIMIT or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("Invalid resolved manifest size or XML declaration")
    try:
        root=ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError("Invalid resolved manifest XML") from exc
    projects=root.findall("project")
    if root.tag!="manifest" or not projects or any(not re.fullmatch(r"[0-9a-f]{40}",p.get("revision","")) for p in projects):
        raise ValueError("Expected fully resolved project revisions")
    paths=[p.get("path",p.get("name")) for p in projects]
    if any(not p for p in paths) or len(paths)!=len(set(paths)):
        raise ValueError("Invalid resolved project paths")
    return hashlib.sha256(data).hexdigest()


def selected(layout, graph, runtime):
    if layout.get("status")!="INIT_EXPERIMENTAL_ROOTFS_STAGED_ONLY":
        raise ValueError("Staged rootfs required")
    files=layout["files"]
    if not isinstance(files,dict) or not 1<=len(files)<=256:
        raise ValueError("Invalid selected file count")
    result={}
    for rel,entry in sorted(files.items()):
        source=entry["source"]
        origin,key=source.split(":",1)
        if key!=rel or not (origin=="product" and SYSTEM.fullmatch(rel)
                            or origin=="runtime" and APEX.fullmatch(rel)):
            raise ValueError("Non-installed or unsupported ELF source: "+source)
        node=graph["nodes"][source]
        if (not HEX.fullmatch(entry["sha256"]) or type(entry["size_bytes"]) is not int
                or not 0<entry["size_bytes"]<=32*1024*1024
                or any(node[field]!=entry[field] for field in ("sha256","size_bytes"))):
            raise ValueError("Selected ELF differs from recorded build graph: "+source)
        if origin=="runtime":
            member=rel[len(RUNTIME)+1:]
            info=runtime["files"][member]
            if info!=node:
                raise ValueError("Runtime ELF differs from recorded APEX extraction: "+source)
        result[rel]={"source":source,"sha256":entry["sha256"],"size_bytes":entry["size_bytes"]}
    return result


def evaluate(build_root, staged, source_commit):
    from r800_property_pipeline import verify_build, require_report, resolved_output, read_report
    from r800_android_init_dependencies import regular
    from r800_android_runtime_extract import digest, MAX_APEX, MAX_ELF
    from r800_android_init_rootfs import unique_object
    from r800_android_rootfs_preflight import snapshot
    root=build_root.resolve(strict=True)
    staged=staged.resolve(strict=True)
    verify_build(root,source_commit)
    product=resolved_output(root/"service","product")
    runtime_root=(root/"runtime/runtime-root").resolve(strict=True)
    if runtime_root!=root/"runtime/runtime-root":
        raise ValueError("Unexpected runtime extraction path")
    graph=require_report(root/"service/init-dependencies.json","INIT_DEPENDENCY_CANDIDATES_ONLY")
    runtime=require_report(root/"runtime/runtime-extraction.json","ANDROID_RUNTIME_EXTRACTED_STATIC_ONLY")
    rm=manifest_digest(root/"runtime/manifest-resolved.xml")
    sm=manifest_digest(root/"service/manifest-resolved.xml")
    if rm!=sm or graph.get("resolved_manifest_sha256")!=sm or runtime.get("resolved_manifest_sha256")!=rm:
        raise ValueError("Resolved source manifest identity mismatch")
    apex=Path(snapshot(root/"runtime/runtime-apex-path.txt",4096).decode().strip())
    if (not apex.is_absolute() or apex.resolve(strict=True)!=apex
            or not apex.is_relative_to((root/"runtime/aosp-out").resolve(strict=True))
            or apex.name!="com.android.runtime.apex"
            or digest(apex,MAX_APEX)!=runtime["apex_sha256"]):
        raise ValueError("Runtime APEX build identity mismatch")
    layout=json.loads(snapshot(regular(staged,"guest-layout.json"),262144),object_pairs_hook=unique_object)
    files=selected(layout,graph,runtime)
    for rel,entry in files.items():
        origin=entry["source"].split(":",1)[0]
        installed=regular(product if origin=="product" else runtime_root,rel)
        copied=regular(staged,rel)
        for path in (installed,copied):
            if path is None or path.stat().st_size!=entry["size_bytes"] or digest(path,MAX_ELF)!=entry["sha256"]:
                raise ValueError("Installed/staged ELF identity mismatch: "+rel)
    return {"status":STATUS,"source_commit":source_commit,
            "expected_manifest_pin":MANIFEST_PIN,"resolved_manifest_sha256":rm,
            "runtime_apex_sha256":runtime["apex_sha256"],"runtime_payload_sha256":runtime["payload_sha256"],
            "selected_files":files,"installed_output_paths_checked":True,
            "staged_bytes_match_build_graph":True,"intermediate_sdk_paths_allowed":False,
            "soong_variant_identity_independently_verified":False,
            "signed_build_attestation_verified":False,"stub_exclusion_proven":False,
            "runtime_behavior_tested":False,"safe_to_flash":False}


def bind_system(report, origin):
    if origin.get("status")!=STATUS or origin.get("safe_to_flash") is not False:
        raise ValueError("Invalid artifact origin evidence")
    expected={p:v["sha256"] for p,v in origin["selected_files"].items()}
    actual={p:v["sha256"] for p,v in report["staged_elf_metadata"].items()}
    if expected!=actual:
        raise ValueError("Image ELF inventory differs from recorded build origin")
    return {"resolved_manifest_sha256":origin["resolved_manifest_sha256"],
            "runtime_apex_sha256":origin["runtime_apex_sha256"],
            "runtime_payload_sha256":origin["runtime_payload_sha256"]}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("build-root","staged","report"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--source-commit",required=True)
    a=p.parse_args()
    try:
        result=evaluate(a.build_root,a.staged,a.source_commit)
        rc=0
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RuntimeError,subprocess.SubprocessError) as exc:
        result={"status":"REJECT","reason":str(exc),"safe_to_flash":False}
        rc=2
    a.report.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result["status"])
    return rc

if __name__=="__main__":
    raise SystemExit(main())
