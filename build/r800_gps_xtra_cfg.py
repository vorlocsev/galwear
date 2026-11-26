#!/usr/bin/env python3
"""Conservative instruction-level CFG clues from ARM/Thumb objdump text."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from r800_gps_xtra_disasm import HEADER, INSN, LIMIT, REG, register_list
from r800_android_userspace_preflight import read_regular

MAX_NODES = 4096
CONDS = {"eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc",
         "hi", "ls", "ge", "lt", "gt", "le"}
TARGET = re.compile(r"(?:0x)?([0-9a-f]+)(?:\s+<[^>]+>)?$")
FIRST_REG = re.compile(r"^(" + REG + r"|sp),\s*.+$")
FALLTHROUGH = {"mov", "movs", "ldr", "str", "add", "adds", "sub", "subs",
               "cmp", "cmn", "tst"}


def parse(raw, function):
    if not function or len(function) > 256:
        raise ValueError("Invalid function label")
    nodes = {}
    entry = None
    active = False
    for line in raw.decode("utf-8").splitlines():
        header = HEADER.fullmatch(line)
        if header:
            active = header[2] == function
            if active:
                if entry is not None:
                    raise ValueError("Duplicate function label")
                entry = int(header[1], 16)
            continue
        if not active or not line.strip():
            continue
        match = INSN.fullmatch(line)
        if not match:
            raise ValueError("Unparsed function instruction")
        address, mnemonic, operands = match.groups()
        address = int(address, 16)
        if address & 1 or address > 0xffffffff or address in nodes:
            raise ValueError("Invalid or duplicate instruction address")
        if nodes and address <= next(reversed(nodes)):
            raise ValueError("Unordered instruction addresses")
        if len(nodes) >= MAX_NODES:
            raise ValueError("Instruction budget exceeded")
        operands = operands.split("@", 1)[0].split(";", 1)[0].strip().lower()
        nodes[address] = (mnemonic, re.sub(r"\bfp\b", "r11", operands))
    if entry is None or not nodes or next(iter(nodes)) != entry:
        raise ValueError("Missing function entry instructions")
    return entry, nodes


def audit(raw, function, isa, *, resume_direct_calls=False):
    if isa not in ("arm", "thumb"):
        raise ValueError("Explicit ARM or Thumb mode required")
    entry, nodes = parse(raw, function)
    if isa == "arm" and any(address % 4 for address in nodes):
        raise ValueError("ARM instruction alignment")
    ordered = list(nodes)
    edges, boundaries = {}, {}
    for i, (address, (mnemonic, operands)) in enumerate(nodes.items()):
        base = mnemonic.removesuffix(".w").removesuffix(".n")
        edges[address] = []
        def edge(kind, target):
            if target in nodes:
                edges[address].append({"kind": kind, "target": target})
            else:
                boundaries.setdefault(address, []).append(kind + "_outside_function")
        def fall():
            nxt = ordered[i + 1] if i + 1 < len(ordered) else None
            widths = (4,) if isa == "arm" or mnemonic.endswith(".w") else (
                (2,) if mnemonic.endswith(".n") else (2, 4))
            if nxt is not None and nxt - address in widths:
                edge("fallthrough", nxt)
            else:
                boundaries.setdefault(address, []).append("fallthrough_unresolved")
        conditional = base.startswith("b") and base[1:] in CONDS
        if base == "b" or conditional or base in ("cbz", "cbnz"):
            operand = operands
            if base in ("cbz", "cbnz"):
                pair = operands.split(",", 1)
                if isa != "thumb" or len(pair) != 2 or not re.fullmatch(REG, pair[0].strip()):
                    boundaries[address] = ["unsupported_branch"]
                    continue
                operand = pair[1].strip()
            target = TARGET.fullmatch(operand)
            if target is None:
                boundaries.setdefault(address, []).append("branch_target_unresolved")
            else:
                edge("branch", int(target[1], 16))
            if conditional or base in ("cbz", "cbnz"):
                fall()
        elif base == "bx" and operands == "lr":
            boundaries[address] = ["return_candidate"]
        elif (resume_direct_calls and base == "bl" and TARGET.fullmatch(operands)
              and int(TARGET.fullmatch(operands)[1], 16) not in nodes):
            boundaries[address] = ["assumed_aapcs_direct_call"]
            nxt = ordered[i + 1] if i + 1 < len(ordered) else None
            if nxt is not None and nxt - address == 4:
                edge("assumed_call_return", nxt)
            else:
                boundaries[address].append("call_return_unresolved")
        elif base in ("bl", "blx", "bx"):
            boundaries[address] = ["call_or_indirect_boundary"]
        elif base in FALLTHROUGH and FIRST_REG.fullmatch(operands):
            fall()
        elif base in ("push", "pop") and register_list(operands) is not None:
            fall()
        else:
            # IT blocks, PC writes, unknown opcodes, and return via POP PC stop.
            boundaries[address] = ["unsupported_instruction"]
    reached, pending = set(), [entry]
    while pending:
        address = pending.pop()
        if address in reached:
            continue
        reached.add(address)
        pending.extend(edge["target"] for edge in edges[address])
    return {"schema": "galwear-r800-xtra-cfg-clues-v1", "status": "CFG_CLUES_ONLY",
            "function": function, "isa_assumption": isa, "entry": entry,
            "disassembly_sha256": hashlib.sha256(raw).hexdigest(),
            "nodes": [{"address": a, "instruction": " ".join(nodes[a]),
                       "edges": edges[a], "boundaries": boundaries.get(a, []),
                       "reachable_in_partial_graph": a in reached} for a in ordered],
            "reachable_count": len(reached), "disassembly_origin_verified": False,
            "instruction_widths_verified": False, "control_flow_verified": False,
            "callback_layout_verified": False, "selected_abi": None,
            "runtime_verified": False, "safe_to_flash": False}


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
    return 0 if report["status"] == "CFG_CLUES_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
