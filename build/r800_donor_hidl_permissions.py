#!/usr/bin/env python3
"""Inspect selected HIDL SELinux permissions offline, without loading policy."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from r800_donor_cil_compile import compile_cil, FIXTURE, sha, MAX_POLICY
from r800_donor_domain_transition import TYPE
from r800_android_userspace_preflight import read_regular
from r800_android_sepolicy_audit import header


def required_rules(server, client, manager, service_type):
    return (
        (server, service_type, "hwservice_manager", "add"),
        (client, service_type, "hwservice_manager", "find"),
        (server, manager, "binder", "call"),
        (server, manager, "binder", "transfer"),
        (client, manager, "binder", "call"),
        (client, manager, "binder", "transfer"),
        (manager, server, "binder", "call"),
        (manager, server, "binder", "transfer"),
        (manager, client, "binder", "call"),
        (manager, client, "binder", "transfer"),
        (client, server, "binder", "call"),
        (client, server, "binder", "transfer"),
        (server, client, "binder", "transfer"),
    )


def device_rules(server, client, manager, device_type):
    """Selected character-device access prerequisites; not ioctl xperm or DAC."""
    return tuple((domain, device_type, "chr_file", perm)
                 for domain in (server, client, manager)
                 for perm in ("open", "read", "write", "ioctl", "map"))


def evaluate(policy, tool, server, client, manager, service_type, device_type=None, kernel=None):
    if not all(TYPE.fullmatch(t) for t in (server, client, manager, service_type)):
        raise ValueError("Invalid SELinux type")
    if len({server, client, manager, service_type}) != 4:
        raise ValueError("Expected distinct server, client, manager and service types")
    if device_type is not None and (not TYPE.fullmatch(device_type) or
                                    device_type in (server, client, manager, service_type)):
        raise ValueError("Invalid or reused Binder device type")
    tool = Path(tool).resolve(strict=True)
    tool_sha = sha(read_regular(tool, MAX_POLICY))
    blob = read_regular(policy, MAX_POLICY)
    header(blob)
    policy_sha = sha(blob)
    checks = []
    rules_to_check = required_rules(server, client, manager, service_type)
    if device_type is not None:
        rules_to_check += device_rules(server, client, manager, device_type)
    for src, dst, klass, perm in rules_to_check:
        result = subprocess.run([str(tool), "--allow", "-s", src, "-t", dst,
                                 "-c", klass, "-p", perm, str(policy)],
                                capture_output=True, text=True, timeout=30, check=True)
        # sesearch expands attributes; conditional rules do not count.
        rules = [line.strip() for line in result.stdout.splitlines()
                 if re.fullmatch(r"allow\s+\S+\s+\S+:\S+\s+[^;]+;", line.strip())]
        checks.append({"source": src, "target": dst, "class": klass, "permission": perm,
                       "unconditional_allow_found": bool(rules), "matching_rules": rules[:20]})
    if sha(read_regular(policy, MAX_POLICY)) != policy_sha or sha(read_regular(tool, MAX_POLICY)) != tool_sha:
        raise ValueError("Policy or sesearch changed")
    missing = [row for row in checks if not row["unconditional_allow_found"]]
    kernel_ok = kernel is None or kernel["status"] == "CONFIG_EVIDENCE_ONLY"
    return {"status": "HIDL_PERMISSION_RULES_ONLY" if not missing and kernel_ok else "REVIEW_REQUIRED",
            "device_type": device_type, "device_rule_count": 15 if device_type else 0,
            "kernel": kernel, "device_node_verified": False, "ueventd_dac_verified": False,
            "ioctl_xperms_verified": False,
            "server": server, "client": client, "manager": manager, "service_type": service_type,
            "checks": checks, "missing": missing, "policy_sha256": policy_sha,
            "sesearch_sha256": tool_sha, "all_permissions_verified": False,
            "hwservice_registration_verified": False, "binder_runtime_verified": False,
            "policy_loaded": False, "safe_to_flash": False}


def fixture(compiler, tool, include_device=False):
    server, client, manager, service = ("hal_fixture_t", "client_fixture_t",
                                        "manager_fixture_t", "hwservice_fixture_t")
    cil = FIXTURE.replace("(classorder (file))",
        "(class binder (call transfer))\n(class hwservice_manager (add find))\n"
        "(classorder (file binder hwservice_manager))")
    for t in (server, client, manager, service):
        cil += f"\n(type {t})\n(roletype object_r {t})\n"
    rules = required_rules(server, client, manager, service)
    denied = (client, service, "hwservice_manager", "find")
    device = None
    kernel = None
    if include_device:
        from r800_binder_inventory import kernel_evidence
        device = "hwbinder_fixture_device_t"
        cil = cil.replace("(classorder (file binder hwservice_manager))",
            "(class chr_file (open read write ioctl map))\n"
            "(classorder (file binder hwservice_manager chr_file))")
        cil += f"\n(type {device})\n(roletype object_r {device})\n"
        rules += device_rules(server, client, manager, device)
        denied = (client, device, "chr_file", "ioctl")
        kernel = kernel_evidence({"CONFIG_ANDROID_BINDER_IPC": "y", "CONFIG_COMPAT": "y",
                                  "CONFIG_ANDROID_BINDER_DEVICES": '"binder,hwbinder,vndbinder"'})
    with tempfile.TemporaryDirectory(prefix="r800-hidl-") as tmp:
        def run(name, omit):
            path = Path(tmp)/name
            path.write_text(cil + "".join(
                f"(allow {src} {dst} ({klass} ({perm})))\n"
                for src, dst, klass, perm in rules if (src, dst, klass, perm) != omit),
                encoding="utf-8")
            return compile_cil([(path, sha(path.read_bytes()))], compiler,
                               policy_probe=lambda policy: evaluate(
                                   policy, tool, server, client, manager, service, device, kernel))
        good, bad = run("positive.cil", None), run("negative.cil", denied)
        positive, negative = good.get("policy_probe", {}), bad.get("policy_probe", {})
        missing = negative.get("missing", [])
        passed = (positive.get("status") == "HIDL_PERMISSION_RULES_ONLY" and
                  negative.get("status") == "REVIEW_REQUIRED" and len(missing) == 1 and
                  tuple(missing[0][k] for k in ("source", "target", "class", "permission")) == denied)
        return {"status": ("SYNTHETIC_HWBINDER_DEVICE_RULES_PASS" if include_device else
                           "SYNTHETIC_HIDL_RULES_PASS") if passed else "REVIEW_REQUIRED",
                "positive": good, "negative": bad, "production_policy": False,
                "policy_loaded": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fixture", action="store_true")
    p.add_argument("--fixture-device", action="store_true")
    p.add_argument("--device-type")
    p.add_argument("--kernel-config", type=Path)
    p.add_argument("--kernel-config-sha256")
    p.add_argument("--compiler", type=Path, default=shutil.which("secilc"))
    p.add_argument("--sesearch", type=Path, default=shutil.which("sesearch"))
    p.add_argument("--policy", type=Path)
    p.add_argument("--policy-sha256")
    for name in ("server", "client", "manager", "service-type"):
        p.add_argument("--" + name)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    try:
        if not a.sesearch:
            raise ValueError("sesearch required")
        args = (a.policy, a.policy_sha256, a.server, a.client, a.manager, a.service_type)
        if a.fixture or a.fixture_device:
            if (a.fixture and a.fixture_device) or not a.compiler or any(args) or any(
                    (a.device_type, a.kernel_config, a.kernel_config_sha256)):
                raise ValueError("Invalid fixture arguments")
            report = fixture(a.compiler, a.sesearch, a.fixture_device)
        else:
            if not all(args):
                raise ValueError("Explicit policy digest and four types required")
            blob = read_regular(a.policy, MAX_POLICY)
            if sha(blob) != a.policy_sha256:
                raise ValueError("Policy SHA-256 mismatch")
            with tempfile.TemporaryDirectory(prefix="r800-hidl-policy-") as tmp:
                policy = Path(tmp)/"policy"
                policy.write_bytes(blob)
                kernel = None
                if bool(a.kernel_config) != bool(a.kernel_config_sha256):
                    raise ValueError("Kernel config and SHA-256 required together")
                if a.kernel_config is not None:
                    from r800_android_userspace_preflight import parse_kernel_config, MAX_CONFIG
                    from r800_binder_inventory import kernel_evidence
                    raw = read_regular(a.kernel_config, MAX_CONFIG)
                    if sha(raw) != a.kernel_config_sha256:
                        raise ValueError("Kernel config SHA-256 mismatch")
                    kernel = kernel_evidence(parse_kernel_config(raw))
                    kernel["sha256"] = a.kernel_config_sha256
                report = evaluate(policy, a.sesearch, a.server, a.client, a.manager, a.service_type,
                                  a.device_type, kernel)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        report = {"status": "REVIEW_REQUIRED", "reason": str(exc), "safe_to_flash": False}
    with a.report.open("x", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")
    print(report["status"])
    return 0 if report["status"] in ("SYNTHETIC_HIDL_RULES_PASS", "SYNTHETIC_HWBINDER_DEVICE_RULES_PASS", "HIDL_PERMISSION_RULES_ONLY") else 2


if __name__ == "__main__":
    raise SystemExit(main())
