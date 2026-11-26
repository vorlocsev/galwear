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


def assumed_call(state, call, va, start, end, mapping):
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
    # Neither arbitrary memory nor the outgoing stack argument area is guaranteed
    # unchanged by an opaque callee. Do not preserve saved LR in memory either.
    for key in list(state):
        if key not in ("sp", 4, 5, 6, 7, 8, 10, 11):
            state.pop(key)
    return row


class Flow:
    """Must-fact intersection: unseen nodes are distinct from unknown facts."""
    def __init__(self, start, end, nodes, assume_aapcs=False):
        self.end = end
        self.nodes = nodes
        self.incoming = {start: {"sp": 0, 14: ("entry_lr", 0), "memory_unchanged": True}}
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
                yield va, dict(self.incoming[va])

    def report(self):
        if self.converged and self.end in self.incoming and self.incoming[self.end].get("sp") != 0:
            self.boundaries.append({"address": self.end, "reason": "unbalanced_range_end"})
        return {"status": "PARTIAL_FLOW_REVIEW_REQUIRED" if self.boundaries or not self.converged else "CONDITIONAL_FIXED_POINT_FLOW_ONLY",
                "events": self.events if self.converged and not self.boundaries else [],
                "boundaries": self.boundaries,
                "assume_aapcs": self.assume_aapcs,
                "assumed_calls": self.calls if self.converged and not self.boundaries else [],
                "callee_execution_verified": False, "memory_preservation_assumed": False,
                "reached_instructions": sum(va != self.end for va in self.incoming),
                "range_end_reached": self.end in self.incoming,
                "converged": self.converged, "iterations": self.steps,
                "back_edge_count": len(self.back_edges),
                "control_flow_verified": False, "safe_to_flash": False}


def audit(raw, off, start, size, relocations, tables, direct, *, assume_aapcs=False, mapping=None):
    if size % 4 or start % 4 or not 0 < size <= 65536 or off < 0 or off + size > len(raw):
        raise ValueError("Invalid A32 flow range")
    end = start + size
    flow = Flow(start, end, range(start, end, 4), assume_aapcs)
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
            row = assumed_call(state, call, va, start, end, mapping)
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
            if not start <= target < end:
                boundary("external_branch")
            else:
                enqueue(target, state)
            if cond != 14:
                enqueue(va + 4, state)
            continue
        if word == 0xe12fff1e:  # BX LR, candidate return only
            if state.get("sp") != 0 or state.get(14) != ("entry_lr", 0):
                boundary("unverified_stack_return")
            continue
        if cond != 14:
            boundary("conditional_or_unknown_instruction")
            continue
        stack = arm_stack(word)
        if stack is not None:
            if not stack_transfer(state, *stack):
                boundary("invalid_stack_access")
                continue
            if stack[0] == "pop" and 15 in stack[1]:
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


def audit_thumb(raw, off, start, size, relocations, tables, direct, *, assume_aapcs=False, mapping=None):
    """Bounded Thumb flow, with linear instruction-boundary assumptions."""
    if size % 2 or start % 2 or not 0 < size <= 65536 or off < 0 or off + size > len(raw):
        raise ValueError("Invalid Thumb flow range")
    end = start + size
    nodes = {}
    pos = 0
    while pos < size:
        a, = struct.unpack_from("<H", raw, off + pos)
        width = 4 if a >> 11 in (29, 30, 31) else 2
        if pos + width > size:
            raise ValueError("Truncated Thumb flow range")
        b = struct.unpack_from("<H", raw, off + pos + 2)[0] if width == 4 else None
        nodes[start + pos] = (a, b, width)
        pos += width
    flow = Flow(start, end, nodes, assume_aapcs)
    enqueue, events, boundaries = flow.enqueue, flow.events, flow.boundaries

    # Reject even an unreachable IT encoding: a branch into its body could
    # otherwise be mistaken for an unconditional instruction sequence.
    for va, (a, _, width) in nodes.items():
        if width == 2 and a & 0xff00 == 0xbf00 and a & 15:
            boundaries.append({"address": va, "reason": "it_block_not_modeled"})
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
        call = thumb_call(a, b, width, va) if assume_aapcs else None
        if call is not None:
            row = assumed_call(state, call, va, start, end, mapping)
            if row is None:
                boundary("unresolved_or_unaligned_call")
            else:
                flow.calls.append(row)
                enqueue(va + width, state)
            continue
        conditional = width == 2 and a & 0xf000 == 0xd000 and (a >> 8) & 15 < 14
        unconditional = width == 2 and a & 0xf800 == 0xe000
        if conditional or unconditional:
            bits = 8 if conditional else 11
            delta = a & ((1 << bits) - 1)
            if delta & (1 << (bits - 1)):
                delta -= 1 << bits
            target = va + 4 + 2 * delta
            if target not in nodes:
                boundary("invalid_branch")
            else:
                enqueue(target, state)
            if conditional:
                enqueue(va + width, state)
            continue
        if a == 0x4770 and width == 2:
            if state.get("sp") != 0 or state.get(14) != ("entry_lr", 0):
                boundary("unverified_stack_return")
            continue
        stack = thumb_stack(a, b, width)
        if stack is not None:
            if not stack_transfer(state, *stack):
                boundary("invalid_stack_access")
                continue
            if stack[0] == "pop" and 15 in stack[1]:
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
