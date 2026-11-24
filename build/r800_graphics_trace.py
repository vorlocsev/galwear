#!/usr/bin/env python3
"""Offline graphics log correlation; never accesses live devices."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
from r800_android_userspace_preflight import read_regular

MAX_LOG = 16 * 1024 * 1024
MAX_EVENTS = 10000
KSTAMP = re.compile(r"^(?:<\d+>)?\s*\[\s*(\d+(?:\.\d+)?)\]\s*(.*)$")
PATTERNS = {
    "iommu_fault": re.compile(r"(?:sysmmu|iommu).*(?:fault|page fault)", re.I),
    "fence_wait": re.compile(r"(?:fence.*(?:timeout|timed out|wait failed)|(?:timeout|timed out).*fence)", re.I),
    "decon_timeout": re.compile(r"decon.*(?:timeout|timed out|underrun|underflow)", re.I),
    "dsim_timeout": re.compile(r"dsim.*(?:timeout|timed out|line count 0)", re.I),
    "gpu_fault": re.compile(r"(?:mali|gpu).*(?:fault|hang|timeout|timed out)", re.I),
}
IRQ = re.compile(r"^(\d+)\s+(\d+)\s*$")


def kernel_events(text):
    events, unparsed = [], 0
    previous = None
    for line in text.splitlines():
        m = KSTAMP.match(line)
        msg = m.group(2) if m else line
        kinds = [k for k, pattern in PATTERNS.items() if pattern.search(msg)]
        if not kinds:
            continue
        if not m:
            unparsed += 1
            continue
        stamp = float(m.group(1))
        if stamp > 1e9:
            raise ValueError("Unsupported kernel timestamp")
        if previous is not None and stamp < previous:
            raise ValueError("Kernel event clock regressed; separate boot sessions")
        previous = stamp
        events.append({"uptime_s": stamp, "kinds": kinds, "message": msg[:500]})
        if len(events) > MAX_EVENTS:
            raise ValueError("Too many graphics events")
    return events, unparsed


def frame_samples(text):
    """Two integer columns: uptime seconds and cumulative frame IRQ count."""
    samples = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        m = IRQ.fullmatch(line)
        if not m or max(map(len, m.groups())) > 12:
            raise ValueError("Invalid frame sample")
        now, count = map(int, m.groups())
        if samples and (now <= samples[-1][0] or count < samples[-1][1]):
            raise ValueError("IRQ sample reset or nonmonotonic time")
        samples.append((now, count))
        if len(samples) > MAX_EVENTS:
            raise ValueError("Too many frame samples")
    return samples


def gaps(samples, minimum=5, maximum_interval=4):
    result, start = [], None
    for (a, x), (b, y) in zip(samples, samples[1:]):
        if b - a > maximum_interval or y != x:
            if start is not None and a - start >= minimum:
                result.append({"start_s": start, "end_s": a})
            start = None
            continue
        if start is None:
            start = a
    if start is not None and samples[-1][0] - start >= minimum:
        result.append({"start_s": start, "end_s": samples[-1][0]})
    return result


def audit(kernel, frames):
    events, unparsed = kernel_events(kernel)
    samples = frame_samples(frames)
    intervals = gaps(samples)
    for interval in intervals:
        lo, hi = interval["start_s"], interval["end_s"]
        interval["coincident_event_indices"] = [i for i, e in enumerate(events)
                                               if lo <= e["uptime_s"] <= hi]
    return {"schema": "galwear-r800-graphics-trace-v1",
            "status": "OFFLINE_CORRELATION_ONLY",
            "kernel_events": events, "unparsed_matching_lines": unparsed,
            "frame_sample_count": len(samples), "no_frame_intervals": intervals,
            "clock_and_boot_identity_verified": False,
            "display_active_state_verified": False,
            "fence_lifetime_verified": False,
            "zero_copy_correctness_verified": False,
            "hardware_tested": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--kernel-log", type=Path, required=True)
    p.add_argument("--frame-samples", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if a.output.resolve() in (a.kernel_log.resolve(), a.frame_samples.resolve()):
        p.error("Report cannot overwrite input")
    try:
        out = audit(read_regular(a.kernel_log, MAX_LOG).decode("utf-8", errors="replace"),
                    read_regular(a.frame_samples, MAX_LOG).decode("utf-8"))
        rc = 0
    except (OSError, ValueError) as exc:
        out = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    a.output.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(out["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
