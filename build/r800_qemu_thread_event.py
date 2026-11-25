#!/usr/bin/env python3
"""Boot a bounded thread/event diagnostic before loading Android policy."""
import argparse
import json
from pathlib import Path
import subprocess

from r800_qemu_guest_abi import verify_baseline, read_bounded_json
from r800_qemu_system_init import run as boot
from r800_qemu_user_init import EXPECTED, HEARTBEAT_PREFIX

STATUS = "VIRT_BLOCK_THREAD_EVENT_ONLY"
PREFIX = b"r800-thread-event: "
MARKERS = [PREFIX+b"mmap-mprotect=PASS",
           PREFIX+b"futex-eagain-timeout-wake=PASS pthread-tls=PASS",
           PREFIX+b"epoll-eventfd=PASS", PREFIX+b"PASS"]
REQUIRED = {"MMU","FUTEX","POSIX_TIMERS","SMP","ARM64_4K_PAGES","EPOLL","EVENTFD"}


def inspect_console(log):
    lines = log.replace(b"\r\n", b"\n").splitlines()
    startup = EXPECTED.rstrip(b"\n")
    if [x for x in lines if x.startswith(PREFIX)] != MARKERS:
        raise ValueError("Unexpected thread/event diagnostic sequence")
    if lines.count(startup) != 1 or not lines.index(startup) < lines.index(MARKERS[0]):
        raise ValueError("Thread/event markers before guest startup")
    if any(x.startswith(HEARTBEAT_PREFIX) for x in lines[:lines.index(MARKERS[-1])]):
        raise ValueError("Heartbeat before thread/event completion")
    if any(x.startswith((b"r800-disk-label:",b"r800-property-service:",b"r800-bionic:")) for x in lines):
        raise ValueError("Unexpected Android diagnostics in pre-policy test")
    return {"mmap_mprotect_reported":True,"futex_eagain_timeout_wake_reported":True,
            "pthread_tls_reported":True,"epoll_eventfd_reported":True,
            "bionic_tested":False,"selinux_policy_loaded":False,
            "property_service_started":False,"safe_to_flash":False}


def verify_config(cfg, kernel_sha):
    if (cfg.get("status") != "VIRT_CONFIG_STATIC_ONLY"
            or cfg.get("profile") != "block"
            or cfg.get("virtio_block_profile") is not True
            or cfg.get("compiled_kernel_sha256") != kernel_sha
            or cfg.get("property_event_loop_configured") is not True
            or cfg.get("safe_to_flash") is not False
            or not REQUIRED <= set(cfg.get("required", []))):
        raise ValueError("Matching compiled block thread/event configuration required")


def run(a):
    digest=verify_baseline(a.baseline,a.kernel)
    cfg=read_bounded_json(a.config_evidence)
    verify_config(cfg,digest)
    evidence=boot(a.init,a.compile_evidence,a.kernel,a.out_dir)
    if evidence["generic_kernel_sha256"] != digest:
        raise ValueError("Kernel changed after baseline verification")
    observed=inspect_console((a.out_dir/"generic-console.log").read_bytes())
    return {**evidence,**observed,"status":STATUS,"profile":"block",
            "config_sha256":cfg["config_sha256"],"guest_kernel_syscalls_tested":True}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("init","compile-evidence","kernel","baseline","config-evidence","out-dir","report"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    try:
        result=run(a)
        rc=0
    except (OSError,ValueError,TypeError,KeyError,IndexError,EOFError,RuntimeError,subprocess.SubprocessError) as exc:
        result={"status":"REJECT","reason":str(exc),"guest_kernel_syscalls_tested":False,
                "safe_to_flash":False}
        rc=2
    a.report.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result["status"])
    return rc

if __name__=="__main__":
    raise SystemExit(main())
