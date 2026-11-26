#!/usr/bin/env python3
"""Conditional XTRA dataflow over the partial textual ARM/Thumb CFG."""
import argparse
from collections import deque
import json
from pathlib import Path

from r800_gps_xtra_cfg import audit as cfg_audit, parse, CONDS
from r800_gps_xtra_disasm import trace_prefix, LIMIT
from r800_android_userspace_preflight import read_regular

MAX_STEPS = 65536


def merge(left, right):
    """Keep only identical facts; None is an entirely unknown incoming state."""
    if left is None or right is None or left[1] != right[1]:
        return None
    regs = {k: v for k, v in left[0].items() if right[0].get(k) == v}
    slots = {k: v for k, v in left[2].items()
             if v is not None and right[2].get(k) == v}
    return regs, left[1], slots


def transfer(address, instruction, state):
    if state is None:
        return None, []
    mnemonic, operands = instruction
    base = mnemonic.removesuffix(".w").removesuffix(".n")
    if (base in ("b", "cbz", "cbnz", "cmp", "cmn", "tst")
            or base.startswith("b") and base[1:] in CONDS):
        # Both branch outcomes are considered; condition values are not tracked.
        return state, []
    output = []
    trace = trace_prefix([f"{address:x}: {mnemonic} {operands}"], address,
                         initial=state, state_out=output)
    if not output:
        return None, trace["events"]
    regs, sp, slots = output[0]
    return (regs, sp, {k: v for k, v in slots.items() if v is not None}), trace["events"]


def solve(raw, function, isa, *, initial=None, resume_direct_calls=False):
    graph = cfg_audit(raw, function, isa, resume_direct_calls=resume_direct_calls)
    entry, instructions = parse(raw, function)
    nodes = {n["address"]: n for n in graph["nodes"]}
    incoming = {entry: ({"r0": ("argument", 0, None)}, 0, {}) if initial is None else initial}
    pending = deque([entry])
    queued = {entry}
    steps = 0
    while pending:
        address = pending.popleft()
        queued.remove(address)
        steps += 1
        if steps > MAX_STEPS:
            raise ValueError("Dataflow iteration budget exceeded")
        outgoing, _ = transfer(address, instructions[address], incoming[address])
        for edge in nodes[address]["edges"]:
            if edge["kind"] == "assumed_call_return":
                outgoing = after_aapcs_call(incoming[address])
            dest = edge["target"]
            new = merge(incoming[dest], outgoing) if dest in incoming else outgoing
            if dest not in incoming or incoming[dest] != new:
                incoming[dest] = new
                if dest not in queued:
                    pending.append(dest)
                    queued.add(dest)
    # Emit only after convergence; transient facts must not survive a join.
    events = []
    for address in sorted(incoming):
        _, clues = transfer(address, instructions[address], incoming[address])
        events.extend(clues)
    return {"schema": "galwear-r800-xtra-dataflow-clues-v1",
            "status": "CONDITIONAL_DATAFLOW_CLUES_ONLY",
            "function": function, "isa_assumption": isa,
            "disassembly_sha256": graph["disassembly_sha256"],
            "entry_argument_assumption": "r0", "events": events,
            "iterations": steps, "reached_nodes": len(incoming),
            "unknown_state_nodes": sorted(a for a, s in incoming.items() if s is None),
            "reachable_boundaries": [
                {"address": a, "reasons": nodes[a]["boundaries"]}
                for a in sorted(incoming) if nodes[a]["boundaries"]],
            "disassembly_origin_verified": False, "control_flow_verified": False,
            "register_provenance_verified": False, "callback_layout_verified": False,
            "selected_abi": None, "runtime_verified": False, "safe_to_flash": False}, incoming


def after_aapcs_call(state):
    if state is None:
        return None
    # r9 is platform-specific. Memory may be modified by the callee.
    preserved = {"r4", "r5", "r6", "r7", "r8", "r10", "r11"}
    return ({k: v for k, v in state[0].items() if k in preserved}, state[1], {})


def audit(raw, function, isa):
    return solve(raw, function, isa)[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disassembly", required=True, type=Path)
    parser.add_argument("--function", required=True)
    parser.add_argument("--isa", required=True, choices=("arm", "thumb"))
    args = parser.parse_args()
    try:
        report = audit(read_regular(args.disassembly, LIMIT), args.function, args.isa)
    except (OSError, ValueError) as exc:
        report = {"status": "REVIEW_REQUIRED", "error": str(exc),
                  "selected_abi": None, "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "CONDITIONAL_DATAFLOW_CLUES_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
