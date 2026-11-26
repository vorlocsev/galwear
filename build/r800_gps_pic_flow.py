"""Bounded ARM/Thumb address dataflow over a bounded, assumed code range."""
import struct
from collections import deque

MAX_STEPS = 524288


MAX_STACK = 256


def stack_transfer(state, op, arg):
    """Track word-aligned private frame slots relative to entry SP."""
    sp = state.get("sp")
    if sp is None:
        return False
    if op == "adjust":
        new = sp + arg
        if new % 4 or not -MAX_STACK <= new <= 0:
            return False
        for key in list(state):
            if isinstance(key, tuple) and key[1] < max(sp, new):
                state.pop(key)
        state["sp"] = new
    elif op in ("push", "pop"):
        regs = arg
        if not regs or 13 in regs or (op == "push" and 15 in regs) or (14 in regs and 15 in regs):
            return False
        if op == "push":
            if not stack_transfer(state, "adjust", -4 * len(regs)):
                return False
            for i, reg in enumerate(regs):
                if reg in state:
                    state[("slot", state["sp"] + 4 * i)] = state[reg]
        else:
            new = sp + 4 * len(regs)
            if new > 0 or (15 in regs and (new != 0 or state.get(("slot", new - 4)) != ("entry_lr", 0))):
                return False
            for i, reg in enumerate(regs):
                value = state.get(("slot", sp + 4 * i))
                state.pop(reg, None)
                if value is not None and reg != 15:
                    state[reg] = value
            return stack_transfer(state, "adjust", 4 * len(regs))
    elif op in ("store", "load"):
        reg, offset = arg
        addr = sp + offset
        if addr % 4 or not sp <= addr <= -4:
            return False
        key = ("slot", addr)
        dst, src = (key, reg) if op == "store" else (reg, key)
        value = state.get(src)
        state.pop(dst, None)
        if value is not None:
            state[dst] = value
    else:
        raise ValueError("Unknown stack operation")
    return True


def arm_stack(word):
    if word & 0xffff0000 in (0xe92d0000, 0xe8bd0000):
        return ("push" if word >> 16 == 0xe92d else "pop", [r for r in range(16) if word & (1 << r)])
    if word & 0xfffff000 in (0xe24dd000, 0xe28dd000):
        imm, shift = word & 255, 2 * ((word >> 8) & 15)
        imm = ((imm >> shift) | (imm << (32 - shift))) & 0xffffffff
        return "adjust", -imm if word & 0xfffff000 == 0xe24dd000 else imm
    if word & 0xff7f0000 in (0xe50d0000, 0xe51d0000) and (word >> 12) & 15 <= 12:
        delta = word & 0xfff
        return ("load" if word & (1 << 20) else "store",
                ((word >> 12) & 15, delta if word & (1 << 23) else -delta))
    return None


def thumb_stack(a, b, width):
    if width == 2 and a & 0xfe00 in (0xb400, 0xbc00):
        op = "pop" if a & 0x800 else "push"
        regs = [r for r in range(8) if a & (1 << r)]
        if a & 256:
            regs.append(15 if op == "pop" else 14)
        return op, regs
    if width == 2 and a & 0xff00 == 0xb000:
        return "adjust", 4 * (a & 127) * (-1 if a & 128 else 1)
    if width == 2 and a & 0xf000 == 0x9000:
        return ("load" if a & 0x800 else "store", ((a >> 8) & 7, 4 * (a & 255)))
    if width == 4 and a in (0xf8cd, 0xf8dd) and b >> 12 <= 12:
        return ("load" if a == 0xf8dd else "store", (b >> 12, b & 0xfff))
    return None


def sign_extend(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def arm_call(word, va):
    if word & 0xff000000 == 0xeb000000:
        return va + 8 + sign_extend((word & 0xffffff) << 2, 26), "arm", "BL"
    if word & 0xfe000000 == 0xfa000000:
        delta = ((word & 0xffffff) << 2) | ((word >> 23) & 2)
        return va + 8 + sign_extend(delta, 26), "thumb", "BLX"
    return None


def thumb_call(a, b, width, va):
    if width != 4 or a & 0xf800 != 0xf000:
        return None
    if b & 0xd000 == 0xd000:
        isa, base, kind = "thumb", va + 4, "BL"
    elif b & 0xd001 == 0xc000:
        isa, base, kind = "arm", (va + 4) & ~3, "BLX"
    else:
        return None
    s = (a >> 10) & 1
    i1 = 1 ^ (((b >> 13) & 1) ^ s)
    i2 = 1 ^ (((b >> 11) & 1) ^ s)
    delta = (s << 24) | (i1 << 23) | (i2 << 22) | ((a & 1023) << 12) | ((b & 2047) << 1)
    return base + sign_extend(delta, 25), isa, kind


def thumb_branch(a, b, width, va):
    """Decode only immediate B/B.W, not BL, BLX or reserved conditions."""
    if width == 2:
        if a & 0xf000 == 0xd000 and (a >> 8) & 15 < 14:
            return va + 4 + 2 * sign_extend(a & 255, 8), True
        if a & 0xf800 == 0xe000:
            return va + 4 + 2 * sign_extend(a & 2047, 11), False
        return None
    if width != 4 or a & 0xf800 != 0xf000:
        return None
    kind = b & 0xd000
    s = (a >> 10) & 1
    j1, j2 = (b >> 13) & 1, (b >> 11) & 1
    if kind == 0x8000 and (a >> 6) & 15 < 14:
        delta = (s << 20) | (j2 << 19) | (j1 << 18) | ((a & 63) << 12) | ((b & 2047) << 1)
        return va + 4 + sign_extend(delta, 21), True
    if kind == 0x9000:
        i1, i2 = 1 ^ (j1 ^ s), 1 ^ (j2 ^ s)
        delta = (s << 24) | (i1 << 23) | (i2 << 22) | ((a & 1023) << 12) | ((b & 2047) << 1)
        return va + 4 + sign_extend(delta, 25), False
    return None


def thumb_literal(a, b, width, va):
    """T16 and T32 word LDR literal to ordinary registers, no PC/SP/LR writes."""
    base = (va + 4) & ~3
    if width == 2 and a & 0xf800 == 0x4800:
        return (a >> 8) & 7, base + 4 * (a & 255)
    if width == 4 and a & 0xff7f == 0xf85f and b >> 12 <= 12:
        delta = b & 4095
        return b >> 12, base + (delta if a & 128 else -delta)
    return None


FLAG_KEYS = ("N", "Z", "C", "V")


def condition_value(state, cond):
    if cond == 14:
        return True
    if not 0 <= cond < 14:
        return None
    outcomes = set()
    for bits in range(16):
        n, z, c, v = (bool(bits & (1 << i)) for i in range(4))
        if any(k in state and state[k] != bit for k, bit in zip(FLAG_KEYS, (n, z, c, v))):
            continue
        base = (z, c, n, v, c and not z, n == v, not z and n == v)[cond // 2]
        outcomes.add(base != bool(cond & 1))
    return outcomes.pop() if len(outcomes) == 1 else None


def constant(state, reg):
    fact = state.get(reg)
    return fact[1] if fact and fact[0] == "constant" else None


def compare_flags(state, lhs, rhs, *, test=False, carry=None):
    for key in (("N", "Z") if test else FLAG_KEYS):
        state.pop(key, None)
    if test and carry is not None:
        state["C"] = carry
    if lhs is None or rhs is None:
        return
    result = (lhs & rhs) if test else (lhs - rhs) & 0xffffffff
    state.update(N=bool(result & 0x80000000), Z=result == 0)
    if not test:
        state.update(C=lhs >= rhs, V=bool((lhs ^ rhs) & (lhs ^ result) & 0x80000000))


def arm_compare(state, word):
    reg_form = word & 0xfff0fff0
    imm_form = word & 0xfff0f000
    rn = (word >> 16) & 15
    if rn > 12:
        return False
    if reg_form in (0xe1500000, 0xe1100000) and word & 15 <= 12:
        compare_flags(state, constant(state, rn), constant(state, word & 15), test=reg_form == 0xe1100000)
        return True
    if imm_form in (0xe3500000, 0xe3100000):
        imm, shift = word & 255, 2 * ((word >> 8) & 15)
        rhs = ((imm >> shift) | (imm << (32 - shift))) & 0xffffffff
        compare_flags(state, constant(state, rn), rhs, test=imm_form == 0xe3100000,
                      carry=bool(rhs & 0x80000000) if shift else None)
        return True
    return False


def thumb_compare(state, a, width):
    if width != 2:
        return False
    if a & 0xf800 == 0x2800:
        compare_flags(state, constant(state, (a >> 8) & 7), a & 255)
        return True
    if a & 0xffc0 in (0x4280, 0x4200):
        compare_flags(state, constant(state, a & 7), constant(state, (a >> 3) & 7),
                      test=a & 0xffc0 == 0x4200)
        return True
    return False


def shift_with_carry(value, kind, amount, carry):
    """ARM Shift_C for 32-bit operands; None denotes an unknown fact."""
    if amount is None:
        return None, None
    if kind == "rrx":
        return (None if value is None or carry is None else
                (int(carry) << 31) | (value >> 1)), (None if value is None else bool(value & 1))
    if amount == 0:
        return value, carry
    if kind == "lsl":
        if amount > 32:
            return 0, False
        if value is None:
            return (0 if amount == 32 else None), None
        return (value << amount) & 0xffffffff, bool(value & (1 << (32 - amount)))
    if kind == "lsr":
        if amount > 32:
            return 0, False
        if value is None:
            return (0 if amount == 32 else None), None
        return value >> amount, bool(value & (1 << (amount - 1)))
    if value is None:
        return None, None
    if kind == "asr":
        n = min(amount, 32)
        return (sign_extend(value, 32) >> n) & 0xffffffff, bool(value & (1 << (n - 1)))
    if kind == "ror":
        n = amount % 32
        result = ((value >> n) | (value << (32 - n))) & 0xffffffff
        return result, bool(result & 0x80000000)
    raise ValueError("Unknown shift kind")


def immediate_shift(kind, amount):
    if amount == 0 and kind in ("lsr", "asr"):
        return kind, 32
    if amount == 0 and kind == "ror":
        return "rrx", 1
    return kind, amount


def shifted_mov(state, rd, value, kind, amount):
    rhs, carry = shift_with_carry(value, kind, amount, state.get("C"))
    alu_flags(state, "mov", rd, None, rhs, carry)
    if carry is None:
        state.pop("C", None)


def alu_flags(state, op, rd, lhs, rhs, carry=None):
    """32-bit constant ALU; address-valued arithmetic remains unknown."""
    arithmetic = op in ("add", "sub", "adc", "sbc")
    carry_in = state.get("C")
    for key in (FLAG_KEYS if arithmetic else ("N", "Z")):
        state.pop(key, None)
    if not arithmetic and carry is not None:
        state["C"] = carry
    state.pop(rd, None)
    if rhs is None or (op not in ("mov", "mvn") and lhs is None):
        return
    if op == "mov":
        result = rhs
    elif op == "mvn":
        result = (~rhs) & 0xffffffff
    elif op == "bic":
        result = lhs & ~rhs
    elif op == "add":
        result = (lhs + rhs) & 0xffffffff
        state.update(C=lhs + rhs > 0xffffffff, V=bool(~(lhs ^ rhs) & (lhs ^ result) & 0x80000000))
    elif op == "sub":
        result = (lhs - rhs) & 0xffffffff
        state.update(C=lhs >= rhs, V=bool((lhs ^ rhs) & (lhs ^ result) & 0x80000000))
    elif op in ("adc", "sbc"):
        if carry_in is None:
            return
        delta = int(carry_in) if op == "adc" else int(carry_in) - 1
        total = lhs + rhs + delta if op == "adc" else lhs - rhs + delta
        signed = sign_extend(lhs, 32) + (sign_extend(rhs, 32) if op == "adc" else -sign_extend(rhs, 32)) + delta
        result = total & 0xffffffff
        state.update(C=total > 0xffffffff if op == "adc" else total >= 0,
                     V=not -(1 << 31) <= signed < (1 << 31))
    elif op == "and":
        result = lhs & rhs
    elif op == "orr":
        result = lhs | rhs
    elif op == "eor":
        result = lhs ^ rhs
    else:
        raise ValueError("Unknown ALU operation")
    state[rd] = ("constant", result)
    state.update(N=bool(result & 0x80000000), Z=result == 0)


def multiply(state, rd, lhs, rhs, setflags):
    state.pop(rd, None)
    if setflags:
        state.pop("N", None)
        state.pop("Z", None)
    if lhs is not None and rhs is not None:
        result = (lhs * rhs) & 0xffffffff
        state[rd] = ("constant", result)
        if setflags:
            state.update(N=bool(result & 0x80000000), Z=result == 0)


def arm_alu(state, word):
    if word & 0xffe0f0f0 == 0xe0000090:
        rd, rs, rm = (word >> 16) & 15, (word >> 8) & 15, word & 15
        if max(rd, rs, rm) > 12:
            return False
        multiply(state, rd, constant(state, rm), constant(state, rs), bool(word & (1 << 20)))
        return True
    # A32 unconditional data processing, S=1; immediate or shifted register.
    if word & 0xfc100000 != 0xe0100000:
        return False
    op = {0: "and", 1: "eor", 2: "sub", 3: "rsb", 4: "add", 5: "adc", 6: "sbc", 12: "orr", 13: "mov", 14: "bic", 15: "mvn"}.get((word >> 21) & 15)
    rn, rd = (word >> 16) & 15, (word >> 12) & 15
    if op is None or rd > 12 or rn > 12 or (op in ("mov", "mvn") and rn != 0):
        return False
    carry = None
    shifted = False
    if word & (1 << 25):
        imm, shift = word & 255, 2 * ((word >> 8) & 15)
        rhs = ((imm >> shift) | (imm << (32 - shift))) & 0xffffffff
        if shift:
            carry = bool(rhs & 0x80000000)
    elif word & 0x10 == 0 and word & 15 <= 12:
        kind, amount = immediate_shift(("lsl", "lsr", "asr", "ror")[(word >> 5) & 3], (word >> 7) & 31)
        rhs, carry = shift_with_carry(constant(state, word & 15), kind, amount, state.get("C"))
        shifted = True
    elif word & 0x90 == 0x10 and word & 15 <= 12 and (word >> 8) & 15 <= 12:
        kind = ("lsl", "lsr", "asr", "ror")[(word >> 5) & 3]
        amount = constant(state, (word >> 8) & 15)
        rhs, carry = shift_with_carry(constant(state, word & 15), kind,
                                      None if amount is None else amount & 255, state.get("C"))
        shifted = True
    else:
        return False
    lhs = constant(state, rn)
    if op == "rsb":
        op, lhs, rhs = "sub", rhs, lhs
    alu_flags(state, op, rd, lhs, rhs, carry)
    if shifted and op in ("mov", "mvn", "and", "orr", "eor", "bic") and carry is None:
        state.pop("C", None)
    return True


def thumb_alu(state, a, width):
    # T16 flag-setting encodings outside IT; immediate and register shift encodings.
    if width != 2:
        return False
    if a & 0xf800 in (0x0000, 0x0800, 0x1000):
        kind, amount = immediate_shift(("lsl", "lsr", "asr")[a >> 11], (a >> 6) & 31)
        shifted_mov(state, a & 7, constant(state, (a >> 3) & 7), kind, amount)
    elif a & 0xf800 == 0x2000:
        alu_flags(state, "mov", (a >> 8) & 7, None, a & 255)
    elif a & 0xf800 == 0x1800:
        rd, rn, operand = a & 7, (a >> 3) & 7, (a >> 6) & 7
        rhs = operand if a & 0x400 else constant(state, operand)
        alu_flags(state, "sub" if a & 0x200 else "add", rd, constant(state, rn), rhs)
    elif a & 0xf800 in (0x3000, 0x3800):
        rd = (a >> 8) & 7
        alu_flags(state, "sub" if a & 0x800 else "add", rd, constant(state, rd), a & 255)
    elif a & 0xffc0 in (0x4080, 0x40c0, 0x4100, 0x41c0):
        kind = {0x4080: "lsl", 0x40c0: "lsr", 0x4100: "asr", 0x41c0: "ror"}[a & 0xffc0]
        rd = a & 7
        amount = constant(state, (a >> 3) & 7)
        shifted_mov(state, rd, constant(state, rd), kind, None if amount is None else amount & 255)
    elif a & 0xffc0 == 0x4240:
        alu_flags(state, "sub", a & 7, 0, constant(state, (a >> 3) & 7))
    elif a & 0xffc0 == 0x43c0:
        alu_flags(state, "mvn", a & 7, None, constant(state, (a >> 3) & 7))
    elif a & 0xffc0 == 0x4340:
        multiply(state, a & 7, constant(state, a & 7), constant(state, (a >> 3) & 7), True)
    elif a & 0xffc0 in (0x4000, 0x4040, 0x4140, 0x4180, 0x4300, 0x4380):
        op = {0x4000: "and", 0x4040: "eor", 0x4140: "adc", 0x4180: "sbc", 0x4300: "orr", 0x4380: "bic"}[a & 0xffc0]
        rd = a & 7
        alu_flags(state, op, rd, constant(state, rd), constant(state, (a >> 3) & 7))
    else:
        return False
    return True


def thumb_wide_alu(state, a, b, width):
    if width != 4:
        return False
    rn, rd, rm = a & 15, (b >> 8) & 15, b & 15
    if a & 0xfff0 == 0xfb00 and b & 0xf0f0 == 0xf000:
        if max(rn, rd, rm) > 12:
            return False
        multiply(state, rd, constant(state, rn), constant(state, rm), False)
        return True
    # T32 data processing (shifted register), S=1 only.
    if a & 0xfe10 != 0xea10 or b & 0x8000 or max(rd, rm) > 12:
        return False
    op = {0: "and", 1: "bic", 2: "orr", 4: "eor", 8: "add", 10: "adc",
          11: "sbc", 13: "sub", 14: "rsb"}.get((a >> 5) & 15)
    if rn == 15 and (a >> 5) & 15 in (2, 3):
        op = "mov" if (a >> 5) & 15 == 2 else "mvn"
    elif rn > 12:
        return False
    if op is None:
        return False
    amount = ((b >> 12) & 7) * 4 + ((b >> 6) & 3)
    kind, amount = immediate_shift(("lsl", "lsr", "asr", "ror")[(b >> 4) & 3], amount)
    rhs, carry = shift_with_carry(constant(state, rm), kind, amount, state.get("C"))
    lhs = constant(state, rn)
    if op == "rsb":
        op, lhs, rhs = "sub", rhs, lhs
    alu_flags(state, op, rd, lhs, rhs, carry)
    if op in ("mov", "mvn", "and", "orr", "eor", "bic") and carry is None:
        state.pop("C", None)
    return True


def assumed_call(state, call, va, start, end, mapping, leaf=None):
    target, isa, kind = call
    align = 4 if isa == "arm" else 2
    if state.get("sp") is None or state["sp"] % 8:
        return None
    if mapping is None or not 0 <= target <= 0xffffffff or target % align or start <= target < end:
        return None
    try:
        _, flags = mapping(target, align)
    except ValueError:
        return None
    if not flags & 1 or flags & 2:
        return None
    row = {"address": va, "target_va": target, "target_isa": isa, "instruction": kind,
           "arguments": {"r" + str(r): {"kind": state[r][0], "value": state[r][1]}
                         for r in range(4) if r in state and state[r][0] in ("constant", "address")},
           "return_assumed": True, "callee_analyzed": False}
    if leaf is not None:
        summary = leaf(target, isa, state)
        if summary is not None:
            if not summary["accepted"]:
                return None
            for key in list(state):
                if key in FLAG_KEYS or (type(key) is int and key not in summary["preserved_registers"]):
                    state.pop(key)
            if summary["r0"] is not None:
                state[0] = summary["r0"]
            row.update(callee_analyzed=True, modeled_return_r0=summary["r0"],
                       modeled_return_count=summary["return_count"],
                       memory_preserved_by_model=True,
                       modeled_nested_depth=summary["nested_depth"])
            return row
    # Neither arbitrary memory nor the outgoing stack argument area is guaranteed
    # unchanged by an opaque callee. Do not preserve saved LR in memory either.
    for key in list(state):
        if key not in ("sp", 4, 5, 6, 7, 8, 10, 11):
            state.pop(key)
    return row


def code_spans(start, size, isa, data_ranges=()):
    """Return aligned code islands around explicitly marked data ranges."""
    end = start + size
    align = 4 if isa == "arm" else 2
    cursor = start
    spans = []
    for lo, hi in data_ranges:
        if not cursor <= lo < hi <= end or lo % align or hi % align:
            raise ValueError("Invalid or unaligned literal pool")
        if cursor < lo:
            spans.append((cursor, lo))
        cursor = hi
    if cursor < end:
        spans.append((cursor, end))
    if not spans or spans[0][0] != start:
        raise ValueError("Function entry is not code")
    return spans


def in_data(slot, data_ranges):
    return slot % 4 == 0 and any(lo <= slot and slot + 4 <= hi for lo, hi in data_ranges)


class Flow:
    """Must-fact intersection: unseen nodes are distinct from unknown facts."""
    def __init__(self, start, end, nodes, assume_aapcs=False, initial=None):
        self.end = end
        self.nodes = nodes
        self.incoming = {start: {"sp": 0, 14: ("entry_lr", 0), "memory_unchanged": True}}
        if initial is not None:
            self.incoming[start].update(initial)
        self.returns = []
        self.assume_aapcs = assume_aapcs
        self.calls = []
        self.pending = deque([start])
        self.queued = {start}
        self.events = []
        self.boundaries = []
        self.steps = 0
        self.emitting = False
        self.converged = False
        self.back_edges = set()
        self.current = start

    def enqueue(self, target, state):
        if target != self.end and target not in self.nodes:
            self.boundaries.append({"address": self.current if not self.emitting else self.report_va,
                                    "reason": "edge_into_data_or_noninstruction", "target_va": target})
            return
        if self.emitting:
            return
        if target <= self.current:
            self.back_edges.add((self.current, target))
        previous = self.incoming.get(target)
        merged = dict(state) if previous is None else {
            k: v for k, v in previous.items() if state.get(k) == v}
        if "sp" not in merged:
            merged = {k: v for k, v in merged.items() if not isinstance(k, tuple)}
        if previous == merged:
            return
        self.incoming[target] = merged
        if target != self.end and target not in self.queued:
            self.pending.append(target)
            self.queued.add(target)

    def walk(self):
        while self.pending:
            if self.steps >= MAX_STEPS:
                self.boundaries.append({"address": self.current, "reason": "iteration_budget_exceeded"})
                return
            self.current = self.pending.popleft()
            self.queued.remove(self.current)
            self.steps += 1
            yield self.current, dict(self.incoming[self.current])
            # Transient events must not survive until the reporting pass.
            self.events.clear()
            self.calls.clear()
            self.boundaries.clear()
        self.converged = True
        self.emitting = True
        for va in sorted(self.incoming):
            if va != self.end:
                self.report_va = va
                yield va, dict(self.incoming[va])

    def record_return(self, state):
        if self.emitting:
            self.returns.append(dict(state))

    def report(self):
        if self.converged and self.end in self.incoming and self.incoming[self.end].get("sp") != 0:
            self.boundaries.append({"address": self.end, "reason": "unbalanced_range_end"})
        accepted = (self.converged and not self.boundaries and self.end not in self.incoming
                    and not self.back_edges and bool(self.returns)
                    and all(c["callee_analyzed"] for c in self.calls))
        r0 = self.returns[0].get(0) if accepted else None
        if r0 is not None and (r0[0] not in ("constant", "address") or any(r.get(0) != r0 for r in self.returns)):
            r0 = None
        preserved = [reg for reg in (4, 5, 6, 7, 8, 10, 11)
                     if accepted and all(r.get(reg) == ("callee_saved", reg) for r in self.returns)]
        return {"leaf_summary": {"accepted": accepted, "r0": r0,
                                 "preserved_registers": preserved, "return_count": len(self.returns),
                                 "nested_depth": max((c.get("modeled_nested_depth", 0) + 1
                                                      for c in self.calls), default=0)},
                "status": "PARTIAL_FLOW_REVIEW_REQUIRED" if self.boundaries or not self.converged else "CONDITIONAL_FIXED_POINT_FLOW_ONLY",
                "events": self.events if self.converged and not self.boundaries else [],
                "boundaries": self.boundaries,
                "assume_aapcs": self.assume_aapcs,
                "assumed_calls": self.calls if self.converged and not self.boundaries else [],
                "callee_execution_verified": False, "memory_preservation_assumed": False,
                "reached_instructions": sum(va != self.end for va in self.incoming),
                "range_end_reached": self.end in self.incoming,
                "converged": self.converged, "iterations": self.steps,
                "back_edge_count": len(self.back_edges),
                "modeled_it_blocks": getattr(self, "it_blocks", 0), "flags_verified": False,
                "control_flow_verified": False, "safe_to_flash": False}


def audit(raw, off, start, size, relocations, tables, direct, *, assume_aapcs=False, mapping=None, initial=None, leaf=None, data_ranges=()):
    if size % 4 or start % 4 or not 0 < size <= 65536 or off < 0 or off + size > len(raw):
        raise ValueError("Invalid A32 flow range")
    end = start + size
    nodes = {va for lo, hi in code_spans(start, size, "arm", data_ranges) for va in range(lo, hi, 4)}
    flow = Flow(start, end, nodes, assume_aapcs, initial)
    enqueue, events, boundaries = flow.enqueue, flow.events, flow.boundaries
    for va, state in flow.walk():
        word, = struct.unpack_from("<I", raw, off + va - start)
        cond = word >> 28
        rd = (word >> 12) & 15
        rn = (word >> 16) & 15
        rm = word & 15
        def boundary(reason):
            boundaries.append({"address": va, "reason": reason})
        def set_reg(reg, value):
            state.pop(reg, None)
            if value is not None:
                state[reg] = value
        if "sp" not in state:
            boundary("ambiguous_stack_depth")
            continue
        if va in relocations:
            boundary("relocated_instruction")
            continue
        call = arm_call(word, va) if assume_aapcs else None
        if call is not None:
            row = assumed_call(state, call, va, start, end, mapping, leaf)
            if row is None:
                boundary("unresolved_or_unaligned_call")
            else:
                flow.calls.append(row)
                enqueue(va + 4, state)
            continue
        if cond <= 14 and word & 0x0f000000 == 0x0a000000:
            delta = word & 0xffffff
            if delta & 0x800000:
                delta -= 1 << 24
            target = va + 8 + 4 * delta
            decision = condition_value(state, cond)
            if decision is not False:
                if not start <= target < end:
                    boundary("external_branch")
                else:
                    enqueue(target, state)
            if decision is not True:
                enqueue(va + 4, state)
            continue
        if word == 0xe12fff1e:  # BX LR, candidate return only
            if state.get("sp") != 0 or state.get(14) != ("entry_lr", 0):
                boundary("unverified_stack_return")
            else:
                flow.record_return(state)
            continue
        if cond != 14:
            boundary("conditional_or_unknown_instruction")
            continue
        stack = arm_stack(word)
        if arm_compare(state, word) or arm_alu(state, word):
            pass
        elif stack is not None:
            if not stack_transfer(state, *stack):
                boundary("invalid_stack_access")
                continue
            if stack[0] == "pop" and 15 in stack[1]:
                flow.record_return(state)
                continue
        elif word & 0xfff00000 == 0xe3000000 and rd <= 12:
            imm = ((word >> 4) & 0xf000) | (word & 0xfff)
            set_reg(rd, ("constant", imm))
        elif word & 0xfff00000 == 0xe3400000 and rd <= 12:
            imm = ((word >> 4) & 0xf000) | (word & 0xfff)
            prev = state.get(rd)
            set_reg(rd, ("constant", (prev[1] & 0xffff) | (imm << 16))
                    if prev and prev[0] == "constant" else None)
        elif word & 0xffff0ff0 == 0xe1a00000 and rd in (*range(13), 14) and rm in (*range(13), 14):
            set_reg(rd, state.get(rm))
        elif word == 0xe320f000:  # NOP
            pass
        elif word & 0xfff00ff0 == 0xe0800000 and rd <= 12 and ((rn == 15 and rm <= 12) or (rm == 15 and rn <= 12)):
            prev = state.get(rm if rn == 15 else rn)
            address = None
            if prev and prev[0] == "constant":
                delta = prev[1] - (1 << 32) if prev[1] & 0x80000000 else prev[1]
                computed = va + 8 + delta
                if 0 <= computed <= 0xffffffff:
                    address = computed
            set_reg(rd, ("address", address) if address is not None else None)
            if address in tables:
                events.append({"address": va, "register": "r" + str(rd), "table_va": address,
                               "kind": "COMPUTED_TABLE_ADDRESS"})
        elif data_ranges and word & 0xff7f0000 == 0xe51f0000 and rd <= 12:
            delta = word & 0xfff
            slot = va + 8 + (delta if word & (1 << 23) else -delta)
            if not in_data(slot, data_ranges):
                boundary("literal_outside_marked_data")
                continue
            value = direct[slot]["table_va"] if slot in direct and state.get("memory_unchanged") else None
            set_reg(rd, ("address", value) if value is not None else None)
            if value is not None:
                events.append({"address": va, "register": "r" + str(rd), "slot_va": slot,
                               "table_va": value, "kind": "RELOCATED_LITERAL_LOAD"})
        elif word & 0xff700000 == 0xe5100000 and rd <= 12 and rn <= 12:
            prev = state.get(rn)
            slot = None
            if prev and prev[0] == "address":
                delta = word & 0xfff
                slot = prev[1] + (delta if word & (1 << 23) else -delta)
            value = direct[slot]["table_va"] if slot in direct and state.get("memory_unchanged") else None
            set_reg(rd, ("address", value) if value is not None else None)
            if value is not None:
                events.append({"address": va, "register": "r" + str(rd), "slot_va": slot,
                               "table_va": value, "kind": "RELOCATED_TABLE_LOAD"})
        else:
            boundary("unsupported_instruction")
            continue
        enqueue(va + 4, state)
    return flow.report()


def it_register_transfer(state, va, a, b, width):
    """Flag-neutral register subset; no branches, memory or SP/LR writes."""
    if width == 2 and a == 0xbf00:
        return True
    if width == 4 and a & 0xfbf0 in (0xf240, 0xf2c0) and not b & 0x8000 and (b >> 8) & 15 <= 12:
        rd = (b >> 8) & 15
        imm = ((a & 15) << 12) | ((a & 0x400) << 1) | ((b & 0x7000) >> 4) | (b & 255)
        prev = state.get(rd)
        value = (("constant", imm) if a & 0xfbf0 == 0xf240 else
                 ("constant", (prev[1] & 0xffff) | (imm << 16)) if prev and prev[0] == "constant" else None)
    elif width == 2 and a & 0xff00 == 0x4600 and (a & 7) + ((a >> 4) & 8) <= 12 and (a >> 3) & 15 <= 12:
        rd = (a & 7) + ((a >> 4) & 8)
        value = state.get((a >> 3) & 15)
    elif width == 2 and a & 0xff78 == 0x4478 and (a & 7) + ((a >> 4) & 8) <= 12:
        rd = (a & 7) + ((a >> 4) & 8)
        prev = state.get(rd)
        address = va + 4 + sign_extend(prev[1], 32) if prev and prev[0] == "constant" else None
        value = ("address", address) if address is not None and 0 <= address <= 0xffffffff else None
    else:
        return False
    state.pop(rd, None)
    if value is not None:
        state[rd] = value
    return True


def thumb_it_blocks(nodes, relocations):
    """Validate complete blocks and remove body entries from the CFG."""
    blocks, body, errors = {}, set(), []
    for va, (a, _, width) in nodes.items():
        if width != 2 or a & 0xff00 != 0xbf00 or not a & 15:
            continue
        itstate, first = a & 255, (a >> 4) & 15
        pos, steps = va + 2, []
        if first >= 14 or va in body or va & ~3 in relocations:
            errors.append({"address": va, "reason": "invalid_it_header"})
            continue
        while True:
            op = nodes.get(pos)
            if op is None or pos in body or not it_register_transfer({}, pos, *op):
                errors.append({"address": pos, "reason": "unsupported_it_body"})
                break
            if any(slot in relocations for slot in range(pos & ~3, ((pos + op[2] - 1) & ~3) + 1, 4)):
                errors.append({"address": pos, "reason": "relocated_it_body"})
                break
            steps.append((pos, (itstate >> 4) == first, op))
            body.add(pos)
            pos += op[2]
            if itstate & 7 == 0:
                blocks[va] = (pos, steps)
                break
            itstate = (itstate & 0xe0) | ((itstate << 1) & 0x1f)
    return blocks, body, errors


def transfer_it(state, steps, decision=None):
    # Flags are unchanged by the accepted subset. Keep the two correlated
    # predicate outcomes separate until the block exits.
    lanes = [dict(state), dict(state)]
    for va, then, op in steps:
        it_register_transfer(lanes[0 if then else 1], va, *op)
    if decision is not None:
        return lanes[0 if decision else 1]
    return {k: v for k, v in lanes[0].items() if lanes[1].get(k) == v}


def audit_thumb(raw, off, start, size, relocations, tables, direct, *, assume_aapcs=False, mapping=None, initial=None, leaf=None, data_ranges=()):
    """Bounded Thumb flow, with linear instruction-boundary assumptions."""
    if size % 2 or start % 2 or not 0 < size <= 65536 or off < 0 or off + size > len(raw):
        raise ValueError("Invalid Thumb flow range")
    end = start + size
    nodes = {}
    for lo, hi in code_spans(start, size, "thumb", data_ranges):
        pos = lo - start
        while pos < hi - start:
            a, = struct.unpack_from("<H", raw, off + pos)
            width = 4 if a >> 11 in (29, 30, 31) else 2
            if pos + width > hi - start:
                raise ValueError("Truncated Thumb flow range")
            b = struct.unpack_from("<H", raw, off + pos + 2)[0] if width == 4 else None
            nodes[start + pos] = (a, b, width)
            pos += width
    blocks, body, errors = thumb_it_blocks(nodes, relocations)
    flow = Flow(start, end, {va: op for va, op in nodes.items() if va not in body}, assume_aapcs, initial)
    enqueue, events, boundaries = flow.enqueue, flow.events, flow.boundaries
    flow.it_blocks = len(blocks)
    boundaries.extend(errors)
    if boundaries:
        return flow.report()
    for va, state in flow.walk():
        a, b, width = nodes[va]
        def boundary(reason):
            boundaries.append({"address": va, "reason": reason})
        def set_reg(reg, value):
            state.pop(reg, None)
            if value is not None:
                state[reg] = value
        def load(rd, rn, delta):
            prev = state.get(rn)
            slot = prev[1] + delta if prev and prev[0] == "address" else None
            value = direct[slot]["table_va"] if slot in direct and state.get("memory_unchanged") else None
            set_reg(rd, ("address", value) if value is not None else None)
            if value is not None:
                events.append({"address": va, "register": "r" + str(rd), "slot_va": slot,
                               "table_va": value, "kind": "RELOCATED_TABLE_LOAD"})
        if "sp" not in state:
            boundary("ambiguous_stack_depth")
            continue
        if any(slot in relocations for slot in range(va & ~3, ((va + width - 1) & ~3) + 1, 4)):
            boundary("relocated_instruction")
            continue
        if va in blocks:
            target, steps = blocks[va]
            enqueue(target, transfer_it(state, steps, condition_value(state, (a >> 4) & 15)))
            continue
        call = thumb_call(a, b, width, va) if assume_aapcs else None
        if call is not None:
            row = assumed_call(state, call, va, start, end, mapping, leaf)
            if row is None:
                boundary("unresolved_or_unaligned_call")
            else:
                flow.calls.append(row)
                enqueue(va + width, state)
            continue
        branch = thumb_branch(a, b, width, va)
        if branch is not None:
            target, conditional = branch
            cond = ((a >> (8 if width == 2 else 6)) & 15) if conditional else 14
            decision = condition_value(state, cond)
            if decision is not False:
                if target not in flow.nodes:
                    boundary("invalid_branch")
                else:
                    enqueue(target, state)
            if decision is not True:
                enqueue(va + width, state)
            continue
        if a == 0x4770 and width == 2:
            if state.get("sp") != 0 or state.get(14) != ("entry_lr", 0):
                boundary("unverified_stack_return")
            else:
                flow.record_return(state)
            continue
        stack = thumb_stack(a, b, width)
        if thumb_compare(state, a, width) or thumb_alu(state, a, width) or thumb_wide_alu(state, a, b, width):
            pass
        elif stack is not None:
            if not stack_transfer(state, *stack):
                boundary("invalid_stack_access")
                continue
            if stack[0] == "pop" and 15 in stack[1]:
                flow.record_return(state)
                continue
        elif width == 4 and a & 0xfbf0 in (0xf240, 0xf2c0) and not b & 0x8000 and (b >> 8) & 15 <= 12:
            rd = (b >> 8) & 15
            imm = ((a & 15) << 12) | ((a & 0x400) << 1) | ((b & 0x7000) >> 4) | (b & 255)
            if a & 0xfbf0 == 0xf240:
                set_reg(rd, ("constant", imm))
            else:
                prev = state.get(rd)
                set_reg(rd, ("constant", (prev[1] & 0xffff) | (imm << 16))
                        if prev and prev[0] == "constant" else None)
        elif width == 2 and a & 0xff00 == 0x4600 and (a & 7) + ((a >> 4) & 8) in (*range(13), 14) and (a >> 3) & 15 in (*range(13), 14):
            set_reg((a & 7) + ((a >> 4) & 8), state.get((a >> 3) & 15))
        elif width == 2 and a == 0xbf00:
            pass
        elif width == 2 and a & 0xff78 == 0x4478 and (a & 7) + ((a >> 4) & 8) <= 12:
            rd = (a & 7) + ((a >> 4) & 8)
            prev = state.get(rd)
            address = None
            if prev and prev[0] == "constant":
                delta = prev[1] - (1 << 32) if prev[1] & 0x80000000 else prev[1]
                computed = va + 4 + delta
                if 0 <= computed <= 0xffffffff:
                    address = computed
            set_reg(rd, ("address", address) if address is not None else None)
            if address in tables:
                events.append({"address": va, "register": "r" + str(rd), "table_va": address,
                               "kind": "COMPUTED_TABLE_ADDRESS"})
        elif data_ranges and thumb_literal(a, b, width, va) is not None:
            rd, slot = thumb_literal(a, b, width, va)
            if not in_data(slot, data_ranges):
                boundary("literal_outside_marked_data")
                continue
            value = direct[slot]["table_va"] if slot in direct and state.get("memory_unchanged") else None
            set_reg(rd, ("address", value) if value is not None else None)
            if value is not None:
                events.append({"address": va, "register": "r" + str(rd), "slot_va": slot,
                               "table_va": value, "kind": "RELOCATED_LITERAL_LOAD"})
        elif width == 2 and a & 0xf800 == 0x6800:
            load(a & 7, (a >> 3) & 7, 4 * ((a >> 6) & 31))
        elif width == 4 and a & 0xfff0 == 0xf8d0 and a & 15 <= 12 and b >> 12 <= 12:
            load(b >> 12, a & 15, b & 0xfff)
        elif width == 4 and a & 0xfff0 == 0xf850 and a & 15 <= 12 and b >> 12 <= 12 and b & 0xf00 == 0xc00:
            load(b >> 12, a & 15, -(b & 255))
        else:
            boundary("unsupported_instruction")
            continue
        enqueue(va + width, state)
    return flow.report()


def leaf_analyzer(raw, mapping, relocations, tables, direct, ranges, *, max_depth=1, data_by_range=None):
    """Explicit bounded callee ranges, no inferred entry points or recursion."""
    if type(max_depth) is not int or not 1 <= max_depth <= 4:
        raise ValueError("Callee depth must be between 1 and 4")
    data_by_range = data_by_range or {}
    cache = {}
    rejected = {"accepted": False}

    def resolve(target, isa, state, path=()):
        entry = (target, isa)
        if entry not in ranges:
            return rejected if path else None
        if entry in path or len(path) >= max_depth:
            return rejected
        initial = {reg: state[reg] for reg in range(4)
                   if reg in state and state[reg][0] in ("constant", "address")}
        initial.update({reg: ("callee_saved", reg) for reg in (4, 5, 6, 7, 8, 10, 11)})
        initial["memory_unchanged"] = bool(state.get("memory_unchanged"))
        key = (path, entry, tuple(sorted((r, v) for r, v in initial.items() if type(r) is int)), initial["memory_unchanged"])
        if key not in cache:
            if len(cache) >= 32:
                return rejected
            # Reserve the context before descent; nested analysis shares the budget.
            cache[key] = rejected
            size = ranges[entry]
            try:
                off, _ = mapping(target, size)
                def nested(t, i, st):
                    return resolve(t, i, st, path + (entry,))
                report = (audit if isa == "arm" else audit_thumb)(
                    raw, off, target, size, relocations, tables, direct,
                    initial=initial, assume_aapcs=len(path) + 1 < max_depth,
                    mapping=mapping, leaf=nested, data_ranges=data_by_range.get(entry, ()))
            except (ValueError, struct.error):
                return rejected
            cache[key] = report["leaf_summary"]
        return cache[key]
    return resolve
