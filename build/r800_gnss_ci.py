#!/usr/bin/env python3
"""Read exact-head GitHub Actions metadata, never run jobs or download artifacts."""
import hashlib
import json
import re
import subprocess

REPO = "vorlocsev/galwear"
PREFIX = ".github/workflows/"
GPS = PREFIX+"r800-gps-host-integration.yml"
REQUIRED = tuple(PREFIX+x for x in (
    "r800-gps-host-integration.yml","r800-integrated-validation.yml",
    "r800-kernel-preflight.yml","r800-stage11-recovery.yml",
    "r800-stage10-provenance.yml","r800-stage12-power.yml","r800-gps-offline.yml"))
STEPS = {
    "host": ("Record exact source",
             "Complete GPS offline gate (native and ARM32 compile-only)",
             "Install SELinux policy compiler and SETools",
             "Audit real compiled synthetic SELinux policy"),
    "android-gps-hal": ("Record exact source","Install pinned Android NDK r27c",
                        "Compile and link Android GPS HAL IPC v1 and v2"),
    "arm-qemu-synthetic": ("Install ARM soft-float compiler and QEMU",
                           "Execute actual bridge ARM32 code with synthetic Broadcom",
                           "Execute freestanding bridge and custom CRT in QEMU"),
}


def api(endpoint):
    proc=subprocess.run(["gh","api","--hostname","github.com",endpoint],
                        capture_output=True,timeout=60,check=True)
    if len(proc.stdout)>8*1024**2:
        raise ValueError("GitHub metadata exceeds budget")
    data=json.loads(proc.stdout)
    if not isinstance(data,dict):
        raise ValueError("Expected GitHub metadata object")
    return data,hashlib.sha256(proc.stdout).hexdigest()


def collection(data,key):
    rows=data.get(key)
    if (not isinstance(rows,list) or type(data.get("total_count")) is not int
            or data["total_count"]!=len(rows) or len(rows)>100
            or not all(isinstance(row,dict) for row in rows)):
        raise ValueError("Incomplete GitHub metadata collection")
    return rows


def positive(value):
    return type(value) is int and value>0


def latest(data,sha):
    chosen={}
    seen=set()
    for run in collection(data,"workflow_runs"):
        path=run.get("path")
        if path not in REQUIRED:
            continue
        rid=run.get("id")
        attempt=run.get("run_attempt")
        if (not positive(rid) or not positive(attempt) or rid in seen
                or run.get("head_sha")!=sha
                or run.get("repository",{}).get("full_name")!=REPO
                or run.get("head_repository",{}).get("full_name")!=REPO
                or run.get("event") not in ("push","workflow_dispatch")):
            raise ValueError("Unexpected required workflow identity")
        seen.add(rid)
        if path not in chosen or rid>chosen[path]["id"]:
            chosen[path]=run
    return chosen


def success(item):
    return item.get("status")=="completed" and item.get("conclusion")=="success"


def gps_jobs(data,run,sha):
    jobs={}
    ids=set()
    for job in collection(data,"jobs"):
        name=job.get("name")
        jid=job.get("id")
        if (not isinstance(name,str) or name in jobs or not positive(jid) or jid in ids
                or job.get("head_sha")!=sha or job.get("run_id")!=run["id"]
                or job.get("run_attempt")!=run["run_attempt"]):
            raise ValueError("Mismatched or duplicate GNSS job")
        ids.add(jid)
        jobs[name]=job
    evidence={}
    problems=[]
    for name,required in STEPS.items():
        job=jobs.get(name)
        if job is None:
            problems.append("MISSING_JOB:"+name)
            continue
        steps=job.get("steps")
        if not isinstance(steps,list) or not all(isinstance(s,dict) for s in steps):
            raise ValueError("Missing job step metadata")
        states={}
        for step in required:
            found=[s for s in steps if s.get("name")==step]
            states[step]=len(found)==1 and success(found[0])
        evidence[name]={"id":job["id"],"status":job.get("status"),
                        "conclusion":job.get("conclusion"),"required_steps":states}
        if not success(job) or not all(states.values()):
            problems.append("GNSS_JOB_REVIEW:"+name)
    return evidence,problems


def check(sha, fetch=api):
    if not re.fullmatch(r"[0-9a-f]{40}",sha):
        raise ValueError("Expected exact commit SHA")
    endpoint=f"repos/{REPO}/actions/runs?head_sha={sha}&per_page=100"
    data,digest=fetch(endpoint)
    runs=latest(data,sha)
    problems=[]
    evidence={}
    for path in REQUIRED:
        run=runs.get(path)
        if run is None:
            problems.append("MISSING_WORKFLOW:"+path)
            continue
        evidence[path]={k:run.get(k) for k in ("id","run_attempt","head_sha","status","conclusion")}
        if not success(run):
            problems.append("WORKFLOW_REVIEW:"+path)
    job_evidence={}
    jobs_digest=None
    if GPS in runs and success(runs[GPS]):
        run=runs[GPS]
        jobs,jobs_digest=fetch(f"repos/{REPO}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100")
        job_evidence,issues=gps_jobs(jobs,run,sha)
        problems.extend(issues)
    # Reject changes in the selected runs while querying attempt-specific jobs.
    again,second_digest=fetch(endpoint)
    final=latest(again,sha)
    def selection(items):
        return {path:tuple(run.get(k) for k in ("id","run_attempt","status","conclusion"))
                for path,run in items.items()}
    if selection(runs)!=selection(final):
        problems.append("CI_SELECTION_CHANGED")
    return {"schema":"r800-gnss-ci-metadata-v1","source_sha":sha,"repository":REPO,
            "status":"CI_METADATA_PASS" if not problems else "REVIEW_REQUIRED",
            "problems":problems,"workflows":evidence,"gps_jobs":job_evidence,
            "metadata_sha256":{"runs":digest,"jobs":jobs_digest,"recheck":second_digest},
            "ci_logs_verified":False,"gnss_runtime_verified":False,"safe_to_flash":False}
