#!/usr/bin/env python3
"""Bounded nested XTRA call and conditional return-value clues."""
import argparse
import json
from pathlib import Path

from r800_gps_xtra_cfg import audit as cfg_audit, parse, TARGET
from r800_gps_xtra_dataflow import solve
from r800_gps_xtra_disasm import HEADER, LIMIT
from r800_android_userspace_preflight import read_regular

MAX_DEPTH = 4
MAX_CONTEXTS = 64
MAX_TOTAL_STEPS = 262144


def audit(raw, function, isa, depth=3):
    if type(depth) is not int or not 0 <= depth <= MAX_DEPTH:
        raise ValueError("Invalid call depth")
    labels = {}
    for line in raw.decode("utf-8").splitlines():
        header = HEADER.fullmatch(line)
        if header:
            labels.setdefault(int(header[1], 16), []).append(header[2])
    cache = {}
    contexts = 0
    total_steps = 0

    def visit(name, args, remaining, ancestors):
        nonlocal contexts, total_steps
        key = (name, tuple(sorted(args.items())), remaining, ancestors)
        if key in cache:
            return cache[key]
        contexts += 1
        if contexts > MAX_CONTEXTS:
            raise ValueError("Call context budget exceeded")
        entry, instructions = parse(raw, name)
        graph = cfg_audit(raw, name, isa, resume_direct_calls=True)
        nodes = {row["address"]: row for row in graph["nodes"]}

        def resolve(address, instruction, state):
            mnemonic, operands = instruction
            match = TARGET.fullmatch(operands)
            if mnemonic not in ("bl", "bl.w") or match is None:
                return None
            target = int(match[1], 16)
            row = {"address": address, "target": target, "status": "UNRESOLVED",
                   "callee": None}
            names = labels.get(target, [])
            if len(names) != 1:
                return row
            callee = names[0]
            if callee in ancestors + (name,):
                row["status"] = "RECURSION_BOUNDARY"
            elif target in instructions:
                row["status"] = "INTERNAL_TARGET_BOUNDARY"
            elif remaining == 0:
                row["status"] = "DEPTH_BOUNDARY"
            elif state is None:
                row["status"] = "UNKNOWN_ARGUMENT_STATE"
            else:
                passed = {k: v for k, v in state[0].items()
                          if k in ("r0", "r1", "r2", "r3")
                          and v[0] in ("argument", "field")}
                child = visit(callee, passed, remaining - 1, ancestors + (name,))
                row.update(status="ANALYZED_CONDITIONALLY", callee=child)
            return row

        def return_value(address, instruction, state):
            row = resolve(address, instruction, state)
            return (row["callee"]["return_fact"] if row and row["callee"]
                    and row["callee"]["return_paths_complete"] else None)

        report, incoming = solve(raw, name, isa, initial=(args, 0, {}),
                                 resume_direct_calls=True, call_return=return_value)
        total_steps += report["iterations"]
        if total_steps > MAX_TOTAL_STEPS:
            raise ValueError("Total dataflow iteration budget exceeded")
        calls = {}
        returns = []
        complete = True
        for address, state in sorted(incoming.items()):
            node = nodes[address]
            row = resolve(address, instructions[address], state)
            if row is not None:
                calls[address] = row
            if state is None or any(e["target"] <= address for e in node["edges"]):
                complete = False
            reasons = node["boundaries"]
            if reasons == ["return_candidate"]:
                if state is None or state[1] != 0:
                    complete = False
                else:
                    value = state[0].get("r0")
                    returns.append(value if value and value[0] in ("argument", "field") else None)
            elif reasons == ["assumed_aapcs_direct_call"]:
                if row is None or row["callee"] is None or not row["callee"]["return_paths_complete"]:
                    complete = False
            elif reasons:
                complete = False
        complete = complete and bool(returns)
        fact = returns[0] if complete and all(v == returns[0] for v in returns) else None
        result = {"function": name, "entry": entry, "argument_facts": args,
                  "events": report["events"], "calls": list(calls.values()),
                  "return_candidates": len(returns), "return_paths_complete": complete,
                  "return_fact": fact}
        cache[key] = result
        return result

    root = visit(function, {"r0": ("argument", 0, None)}, depth, ())
    return {"schema": "galwear-r800-xtra-nested-call-clues-v1",
            "status": "CONDITIONAL_NESTED_CALL_CLUES_ONLY", "root": root,
            "depth_limit": depth, "contexts_analyzed": contexts,
            "total_iterations": total_steps, "aapcs_assumed_not_verified": True,
            "same_isa_assumed": True, "return_address_not_verified": True,
            "control_flow_verified": False, "callback_layout_verified": False,
            "selected_abi": None, "runtime_verified": False, "safe_to_flash": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disassembly", required=True, type=Path)
    parser.add_argument("--function", required=True)
    parser.add_argument("--isa", required=True, choices=("arm", "thumb"))
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--assume-aapcs", required=True, action="store_true")
    args = parser.parse_args()
    try:
        report = audit(read_regular(args.disassembly, LIMIT), args.function, args.isa, args.depth)
    except (OSError, ValueError) as exc:
        report = {"status": "REVIEW_REQUIRED", "error": str(exc),
                  "selected_abi": None, "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "CONDITIONAL_NESTED_CALL_CLUES_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
