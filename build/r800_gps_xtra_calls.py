#!/usr/bin/env python3
"""One-level direct-call clues under explicit AAPCS and same-ISA assumptions."""
import argparse
import json
from pathlib import Path

from r800_gps_xtra_cfg import parse, TARGET
from r800_gps_xtra_dataflow import solve
from r800_gps_xtra_disasm import HEADER, LIMIT
from r800_android_userspace_preflight import read_regular

MAX_CALLEES = 32


def audit(raw, function, isa):
    report, incoming = solve(raw, function, isa, resume_direct_calls=True)
    _, instructions = parse(raw, function)
    labels = {}
    for line in raw.decode("utf-8").splitlines():
        header = HEADER.fullmatch(line)
        if header:
            labels.setdefault(int(header[1], 16), []).append(header[2])
    calls = []
    for address in sorted(incoming):
        mnemonic, operands = instructions[address]
        match = TARGET.fullmatch(operands)
        if mnemonic not in ("bl", "bl.w") or match is None:
            continue
        target = int(match[1], 16)
        if target in instructions:
            continue
        if len(calls) >= MAX_CALLEES:
            raise ValueError("Direct call evidence budget exceeded")
        state = incoming[address]
        # Only argument-derived values passed in argument registers enter the
        # callee model. Caller stack addresses are not callee-local addresses.
        args = {} if state is None else {
            k: v for k, v in state[0].items()
            if k in ("r0", "r1", "r2", "r3") and v[0] in ("argument", "field")}
        names = labels.get(target, [])
        row = {"address": address, "target": target,
               "argument_facts": args, "callee_status": "NOT_ANALYZED"}
        if len(names) == 1 and names[0] != function and args:
            try:
                callee, _ = solve(raw, names[0], isa, initial=(args, 0, {}))
                row.update(callee_status="CONDITIONAL_CLUES_ONLY", function=names[0],
                           events=callee["events"], boundaries=callee["reachable_boundaries"])
            except ValueError as exc:
                row.update(callee_status="REVIEW_REQUIRED", error=str(exc))
        calls.append(row)
    return {"schema": "galwear-r800-xtra-call-clues-v1",
            "status": "ASSUMED_AAPCS_CALL_CLUES_ONLY",
            "caller": report, "direct_calls": calls,
            "aapcs_assumed_not_verified": True, "same_isa_assumed": True,
            "callee_depth_limit": 1, "callee_return_values_verified": False,
            "control_flow_verified": False, "callback_layout_verified": False,
            "selected_abi": None, "runtime_verified": False, "safe_to_flash": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disassembly", required=True, type=Path)
    parser.add_argument("--function", required=True)
    parser.add_argument("--isa", required=True, choices=("arm", "thumb"))
    parser.add_argument("--assume-aapcs", required=True, action="store_true")
    args = parser.parse_args()
    try:
        report = audit(read_regular(args.disassembly, LIMIT), args.function, args.isa)
    except (OSError, ValueError) as exc:
        report = {"status": "REVIEW_REQUIRED", "error": str(exc),
                  "selected_abi": None, "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "ASSUMED_AAPCS_CALL_CLUES_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
