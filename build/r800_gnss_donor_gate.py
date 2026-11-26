"""Run the local static donor pipeline and verify its freshly created evidence."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from r800_gps_link_gate import DONORS
from r800_stage_gps_donors import read_source


def digest(value):
    return isinstance(value,str) and re.fullmatch(r"[0-9a-f]{64}",value) is not None


def validate(report, source_sha, image_sha, output):
    if not isinstance(report,dict):
        raise ValueError("Expected donor report object")
    expected={"schema":"r800-tizen-glibc-check-v1",
              "source_sha":source_sha,"image_sha256":image_sha,
              "status":"STATIC_DONOR_LINK_ONLY",
              "donor_authenticity_verified":False,
              "gnss_runtime_verified":False,"safe_to_flash":False}
    for key,value in expected.items():
        if type(report.get(key)) is not type(value) or report.get(key)!=value:
            raise ValueError("Donor evidence mismatch: "+key)
    gates=report.get("gates")
    if not isinstance(gates,dict) or set(gates)!={"extraction","elf","link","qemu"}:
        raise ValueError("Unexpected donor gates")
    for name,status in (("extraction","PASS"),("elf","STATIC_PASS"),
                        ("link","STATIC_PASS"),("qemu","NOT_TESTED")):
        if not isinstance(gates[name],dict) or gates[name].get("status")!=status:
            raise ValueError("Donor gate not confirmed: "+name)
    hashes=gates["extraction"].get("donor_sha256")
    if not isinstance(hashes,dict) or set(hashes)!=set(DONORS) or not all(map(digest,hashes.values())):
        raise ValueError("Invalid donor hash inventory")
    extraction=gates["extraction"].get("detail")
    if (not isinstance(extraction,dict) or extraction.get("image_sha256")!=image_sha
            or extraction.get("snapshot_verified") is not True
            or extraction.get("profile")!="gps-glibc"
            or extraction.get("missing_or_ambiguous")!=[]
            or extraction.get("safe_to_flash") is not False):
        raise ValueError("Extraction evidence mismatch")
    files=extraction.get("files")
    if not isinstance(files,dict) or set(files)!={"tizen/"+n for n in DONORS}:
        raise ValueError("Invalid extraction inventory")
    for name in DONORS:
        item=files["tizen/"+name]
        if not isinstance(item,dict) or item.get("status")!="EXTRACTED" or item.get("sha256")!=hashes[name]:
            raise ValueError("Extraction hash mismatch: "+name)
    link=gates["link"]
    static=link.get("detail")
    if (not isinstance(static,dict) or static.get("status")!="STATIC_GLIBC_CLOSURE_ONLY"
            or static.get("static_closure_pass") is not True or static.get("problems")!=[]
            or static.get("donor_sha256")!=hashes or static.get("safe_to_flash") is not False
            or not digest(static.get("sha256"))):
        raise ValueError("Static link evidence mismatch")
    if type(link.get("exit_code")) is not int or link["exit_code"]!=0 or link.get("log_file")!="link.log":
        raise ValueError("Unexpected link execution evidence")
    if hashlib.sha256(read_source(output/"link.log")).hexdigest()!=link.get("log_sha256"):
        raise ValueError("Link log digest mismatch")
    if (output/"qemu.log").exists() or (output/"qemu.log").is_symlink():
        raise ValueError("Unexpected QEMU log in static-only run")
    return hashes


def run(root,source_sha,image,image_sha,ndk,output):
    output=output.parent.resolve(strict=True)/output.name
    if output.exists() or output.is_symlink() or output==root or root in output.parents:
        raise ValueError("Use a new evidence directory outside the checkout")
    args=[sys.executable,str(root/"build/r800_gps_donor_check.py"),
          "--image",str(image.absolute()),"--sha256",image_sha,
          "--ndk",str(ndk.absolute()),"--output",str(output)]
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1")
    proc=subprocess.run(args,cwd=root,env=env,capture_output=True,timeout=900)
    report=json.loads(proc.stdout)
    if proc.returncode!=0:
        return {"status":"REVIEW_REQUIRED","exit_code":proc.returncode,"detail":report}
    if output.is_symlink() or not output.is_dir():
        raise ValueError("Missing evidence directory")
    saved=read_source(output/"report.json")
    if json.loads(saved)!=report:
        raise ValueError("Saved donor report differs from subprocess output")
    hashes=validate(report,source_sha,image_sha,output)
    return {"status":"STATIC_PASS","exit_code":0,"detail":report,
            "report_sha256":hashlib.sha256(saved).hexdigest(),"donor_sha256":hashes}
