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



REG = r"r(?:1[0-2]|[0-9])"
MOVE = re.compile(r"^(" + REG + r"),\s*(" + REG + r")$")
FIELD = re.compile(r"^(" + REG + r"),\s*\[(" + REG +
                   r")(?:,\s*#(0x[0-9a-f]+|[0-9]+))?\]$")


STACK_WORD = re.compile(r"^(" + REG + r"),\s*\[sp(?:,\s*#(0x[0-9a-f]+|[0-9]+))?\]$")
STACK_ADJUST = re.compile(r"^sp,\s*(?:sp,\s*)?#(0x[0-9a-f]+|[0-9]+)$")
STACK_LIMIT = 4096


def register_list(operands):
    if not (operands.startswith("{") and operands.endswith("}")):
        return None
    names = operands[1:-1].split(",")
    expanded = []
    for item in names:
        item = item.strip()
        if item == "lr":
            expanded.append(14)
        elif re.fullmatch(REG, item):
            expanded.append(int(item[1:]))
        else:
            span = re.fullmatch(r"(" + REG + r")-(" + REG + r")", item)
            if not span:
                return None
            lo, hi = (int(v[1:]) for v in span.groups())
            if lo >= hi:
                return None
            expanded.extend(range(lo, hi + 1))
    if len(set(expanded)) != len(expanded) or not expanded:
        return None
    return ["lr" if i == 14 else "r" + str(i) for i in sorted(expanded)]


def immediate_value(value):
    return int(value, 16 if value.startswith("0x") else 10)


def trace_prefix(lines, entry):
    """Track only an uninterrupted, supported prefix under an r0 entry hypothesis."""
    regs = {"r0": ("argument", 0, None)}
    events = []
    sp = 0
    slots = {}
    previous = None
    reason = "end_of_function"
    for line in lines:
        if not line.strip():
            continue
        match = INSN.fullmatch(line)
        if match is None:
            reason = "unparsed_line"
            break
        address, mnemonic, operands = match.groups()
        address = int(address, 16)
        if (previous is None and address != entry
                or previous is not None and address - previous not in (2, 4)):
            reason = "address_discontinuity"
            break
        previous = address
        operands = operands.split("@", 1)[0].split(";", 1)[0].strip().lower()
        if mnemonic in ("push", "push.w", "push.n", "pop", "pop.w", "pop.n"):
            names = register_list(operands)
            if names is None:
                reason = "unsupported_stack_register_list"
                break
            size = 4 * len(names)
            if mnemonic.startswith("push"):
                if sp - size < -STACK_LIMIT:
                    reason = "stack_bounds"
                    break
                sp -= size
                for i, name in enumerate(names):
                    slots[sp + 4 * i] = regs.get(name)
            else:
                if sp + size > 0:
                    reason = "stack_bounds"
                    break
                for i, name in enumerate(names):
                    value = slots.pop(sp + 4 * i, None)
                    regs.pop(name, None)
                    if value is not None:
                        regs[name] = value
                sp += size
        elif mnemonic in ("sub", "sub.w", "sub.n", "add", "add.w", "add.n"):
            adjust = STACK_ADJUST.fullmatch(operands)
            if adjust is None:
                reason = "unsupported_instruction_or_control_flow"
                break
            size = immediate_value(adjust[1])
            new_sp = sp + (-size if mnemonic.startswith("sub") else size)
            if size % 4 or not -STACK_LIMIT <= new_sp <= 0:
                reason = "stack_bounds"
                break
            # Neither newly allocated nor released slots retain provenance.
            for pos in list(slots):
                if min(sp, new_sp) <= pos < max(sp, new_sp):
                    del slots[pos]
            sp = new_sp
        elif mnemonic in ("str", "str.w", "str.n", "ldr", "ldr.w", "ldr.n") and STACK_WORD.fullmatch(operands):
            name, immediate = STACK_WORD.fullmatch(operands).groups()
            pos = sp + immediate_value(immediate or "0")
            if pos % 4 or not sp <= pos <= -4:
                reason = "stack_bounds"
                break
            if mnemonic.startswith("str"):
                slots[pos] = regs.get(name)
            else:
                value = slots.get(pos)
                regs.pop(name, None)
                if value is not None:
                    regs[name] = value
        elif mnemonic in ("mov", "mov.w", "mov.n", "movs"):
            move = MOVE.fullmatch(operands)
            if move is None:
                reason = "unsupported_move"
                break
            dest, source = move.groups()
            value = regs.get(source)
            regs.pop(dest, None)
            if value is not None:
                regs[dest] = value
        elif mnemonic in ("ldr", "ldr.w", "ldr.n"):
            field = FIELD.fullmatch(operands)
            if field is None:
                reason = "unsupported_load"
                break
            dest, base, immediate = field.groups()
            value = regs.get(base)
            regs.pop(dest, None)
            immediate = immediate or "0"
            offset = int(immediate, 16 if immediate.startswith("0x") else 10)
            if value is not None and value[0] == "argument" and offset in (0, 4, 8):
                regs[dest] = ("field", offset, address)
                events.append({"kind": "argument_word_load", "address": address,
                               "base": base, "destination": dest, "offset": offset})
        elif mnemonic in ("blx", "blx.w") and CALL.fullmatch(operands):
            value = regs.get(operands)
            if value is not None and value[0] == "field":
                events.append({"kind": "loaded_word_indirect_call", "address": address,
                               "register": operands, "offset": value[1],
                               "load_address": value[2]})
            reason = "call_boundary"
            break
        else:
            reason = "unsupported_instruction_or_control_flow"
            break
        if len(events) > 4096:
            raise ValueError("Register trace exceeds limit")
    return {"entry_argument_assumption": "r0", "events": events,
            "stop_reason": reason, "stack_delta_at_stop": sp,
            "full_control_flow_analyzed": False}


def audit(raw, function):
    """Exact function label; conditional prefix clues, not verified provenance."""
    if not function or len(function) > 256:
        raise ValueError("Invalid function label")
    active = False
    matches = 0
    loads, calls = [], []
    prefix_lines = []
    entry = None
    for line in raw.decode("utf-8", errors="strict").splitlines():
        header = HEADER.fullmatch(line)
        if header:
            active = header[2] == function
            matches += int(active)
            if active:
                entry = int(header[1], 16)
            continue
        if not active:
            continue
        prefix_lines.append(line)
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
            "conditional_register_trace": trace_prefix(prefix_lines, entry),
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
