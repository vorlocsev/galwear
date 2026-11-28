#!/usr/bin/env python3
"""Same-head graphics fixture evidence gate; not a donor or hardware test."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

HWC_FLAGS = tuple("hwc_synthetic_" + suffix + "_verified" for suffix in (
    "fb_lifecycle", "cpu_present", "imported_handle", "imported_overlay",
    "imported_zero_copy", "delayed_overlay_release", "imported_quarantine",
    "egl_acquire", "window_queue", "async_release", "decon_zero_copy",
    "decon_overlay", "overlay_recovery"))
EGL_FLAGS = ("synthetic_dlsym_verified", "synthetic_lifecycle_verified",
             "synthetic_context_gles_verified", "synthetic_extension_dispatch_verified",
             "synthetic_native_fence_eventfd_verified")
HWC_HOLDS = ("hardware_tested", "hwc_hardware_verified", "hwc_frame_present_verified",
             "android_async_buffer_release_verified", "android_native_window_verified",
             "android_bufferqueue_verified", "real_egl_sync_file_verified", "safe_to_flash")
EGL_HOLDS = ("real_native_fence_verified", "gpu_hardware_verified", "safe_to_flash")
HWC_MARKERS = (
    "HAL_HWC_IMPORTED_HANDLE_FIXTURE_PASS frames=8 imports=8 source_closed=8 freed=8 cloexec=8 fd_stable=1",
    "HAL_HWC_IMPORTED_OVERLAY_FIXTURE_PASS imports=3 source_closed=3 freed=3 overlay_release_handoff=1 fd_stable=1",
    "HAL_HWC_IMPORTED_ZERO_COPY_FIXTURE_PASS imports=1 source_closed=1 accepted=1 enotty=1 fallback=1 freed=1 fd_stable=1",
    "HAL_HWC_DELAYED_OVERLAY_RELEASE_FIXTURE_PASS unsignaled=1 blocked_reuse=1 signaled=1 reclaimed=1",
    "HAL_HWC_IMPORTED_QUARANTINE_FIXTURE_PASS cycles=4 retained=4 blocked_reuse=4 teardown=4 fd_stable=1",
)


def summarize(hwc, egl, source_sha):
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("Expected full source SHA")
    errors = []
    for name, report, status, positives, holds in (
        ("hwc", hwc, "ARM32_HWC_SYNTHETIC_FB_LIFECYCLE_ONLY", HWC_FLAGS, HWC_HOLDS),
        ("egl", egl, "ARM32_SYNTHETIC_EGL_LINK_ONLY", EGL_FLAGS, EGL_HOLDS),
    ):
        if report.get("source_sha") != source_sha:
            errors.append(name + ": source SHA mismatch")
        if report.get("status") != status:
            errors.append(name + ": unexpected evidence status")
        for flag in positives:
            if report.get(flag) is not True:
                errors.append(name + ": missing positive flag " + flag)
        for flag in holds:
            if report.get(flag) is not False:
                errors.append(name + ": missing or invalid hold " + flag)
    if hwc.get("hwc_fixture_requested") is not True:
        errors.append("HWC fixture not requested")
    results = hwc.get("results")
    result = results.get("hwcomposer.r800.so") if isinstance(results, dict) else None
    if (not isinstance(result, dict) or set(results) != {"hwcomposer.r800.so"} or
            result.get("status") != "HWC_FIXTURE_PASS" or
            type(result.get("exit_code")) is not int or result["exit_code"] != 0):
        errors.append("Missing successful isolated HWC result")
    log = result.get("log", "") if isinstance(result, dict) else ""
    lines = log.splitlines() if isinstance(log, str) else []
    for marker in HWC_MARKERS:
        if lines.count(marker) != 1:
            errors.append("Missing or duplicate marker: " + marker.split()[0])
    return {"schema": "galwear-r800-graphics-fixture-summary-v1",
            "source_sha": source_sha,
            "status": "SYNTHETIC_GRAPHICS_PIPELINE_ONLY" if not errors else "REVIEW_REQUIRED",
            "hwc_flags": {key: hwc.get(key) is True for key in HWC_FLAGS},
            "egl_flags": {key: egl.get(key) is True for key in EGL_FLAGS},
            "errors": errors, "donor_surfaceflinger_verified": False,
            "donor_mapper_verified": False, "donor_mali_verified": False,
            "real_sync_file_verified": False, "hardware_tested": False,
            "android_boot_tested": False, "safe_to_flash": False,
            "release_status": "HOLD_HARDWARE_UNVERIFIED"}


def read_report(path):
    with path.open("rb") as stream:
        raw = stream.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Evidence exceeds size budget")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Expected JSON evidence object")
    return data, hashlib.sha256(raw).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hwc", type=Path, required=True)
    p.add_argument("--egl", type=Path, required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    hwc, hwc_hash = read_report(a.hwc)
    egl, egl_hash = read_report(a.egl)
    report = summarize(hwc, egl, a.source_sha)
    report["input_sha256"] = {"hwc": hwc_hash, "egl": egl_hash}
    with a.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(report["status"])
    return 0 if not report["errors"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
