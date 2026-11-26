#!/usr/bin/env python3
"""Locate lexical ARM/Thumb callback-access clues in analyst-supplied disassembly."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from r800_android_userspace_preflight import read_regular

LIMIT = 16 * 1024**2
HEADER = re.compile(r"^\s*([0-9a-fA-F]+)\s+<([^>]+)>:\s*$")
INSN = re.compile(r"^\s*([0-9a-fA-F]+):\s+([a-z][a-z0-9.]*)\s+(.*?)\s*$")
LOAD = re.compile(r"^r(?:1[0-2]|[0-9]),\s*\[r0(?:,\s*#(0x[0-9a-f]+|[0-9]+))?\]$", re.I)
CALL = re.compile(r"^r(?:1[0-2]|[0-9])$", re.I)


def audit(raw, function):
    """Exact function label; no inferred control flow or register provenance."""
    if not function or len(function) > 256:
        raise ValueError("Invalid function label")
    active = False
    matches = 0
    loads, calls = [], []
    for line in raw.decode("utf-8", errors="strict").splitlines():
        header = HEADER.fullmatch(line)
        if header:
            active = header[2] == function
            matches += int(active)
            continue
        if not active:
            continue
        insn = INSN.fullmatch(line)
        if not insn:
            continue
        addr, mnemonic, operands = insn.groups()
        operands = operands.split("@", 1)[0].split(";", 1)[0].strip()
        if mnemonic in ("ldr", "ldr.w", "ldr.n"):
            match = LOAD.fullmatch(operands)
            if match:
                value = match[1] or "0"
                offset = int(value, 16 if value.lower().startswith("0x") else 10)
                if offset in (0, 4, 8):
                    loads.append({"address": int(addr, 16), "offset": offset,
                                  "instruction": mnemonic + " " + operands})
        elif mnemonic in ("blx", "blx.w") and CALL.fullmatch(operands):
            calls.append({"address": int(addr, 16), "register": operands.lower()})
        if len(loads) + len(calls) > 4096:
            raise ValueError("Instruction evidence exceeds limit")
    if matches != 1:
        raise ValueError("Expected exactly one matching function label")
    return {"schema": "galwear-r800-xtra-disasm-clues-v1",
            "status": "LEXICAL_CLUES_ONLY", "function": function,
            "disassembly_sha256": hashlib.sha256(raw).hexdigest(),
            "r0_word_loads": loads, "indirect_calls": calls,
            "observed_offsets": sorted({item["offset"] for item in loads}),
            "candidate_layouts": {"1": {"download": 0, "thread": 4},
                                  "2": {"size": 0, "download": 4, "thread": 8}},
            "disassembly_origin_verified": False,
            "register_provenance_verified": False, "control_flow_verified": False,
            "callback_layout_verified": False, "selected_abi": None,
            "runtime_verified": False, "safe_to_flash": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disassembly", type=Path, required=True,
                        help="llvm-objdump -d --no-show-raw-insn text")
    parser.add_argument("--function", required=True, help="Exact reviewed function label")
    args = parser.parse_args()
    try:
        report = audit(read_regular(args.disassembly, LIMIT), args.function)
    except (OSError, ValueError) as exc:
        report = {"status": "REVIEW_REQUIRED", "error": str(exc),
                  "selected_abi": None, "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "LEXICAL_CLUES_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
