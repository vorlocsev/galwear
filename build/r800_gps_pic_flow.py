"""Bounded ARM/Thumb address dataflow over a bounded, assumed code range."""
import struct
from collections import deque

MAX_STEPS = 524288


class Flow:
    """Must-fact intersection: unseen nodes are distinct from unknown facts."""
    def __init__(self, start, end, nodes):
        self.end = end
        self.nodes = nodes
        self.incoming = {start: {}}
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
            self.boundaries.clear()
        self.converged = True
        self.emitting = True
        for va in sorted(self.incoming):
            if va != self.end:
                yield va, dict(self.incoming[va])

    def report(self):
        return {"status": "PARTIAL_FLOW_REVIEW_REQUIRED" if self.boundaries or not self.converged else "CONDITIONAL_FIXED_POINT_FLOW_ONLY",
                "events": self.events if self.converged and not self.boundaries else [],
                "boundaries": self.boundaries,
                "reached_instructions": sum(va != self.end for va in self.incoming),
                "range_end_reached": self.end in self.incoming,
                "converged": self.converged, "iterations": self.steps,
                "back_edge_count": len(self.back_edges),
                "control_flow_verified": False, "safe_to_flash": False}


def audit(raw, off, start, size, relocations, tables, direct):
    if size % 4 or start % 4 or not 0 < size <= 65536 or off < 0 or off + size > len(raw):
        raise ValueError("Invalid A32 flow range")
    end = start + size
    flow = Flow(start, end, range(start, end, 4))
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
        if va in relocations:
            boundary("relocated_instruction")
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
            continue
        if cond != 14:
            boundary("conditional_or_unknown_instruction")
            continue
        if word & 0xfff00000 == 0xe3000000 and rd <= 12:
            imm = ((word >> 4) & 0xf000) | (word & 0xfff)
            set_reg(rd, ("constant", imm))
        elif word & 0xfff00000 == 0xe3400000 and rd <= 12:
            imm = ((word >> 4) & 0xf000) | (word & 0xfff)
            prev = state.get(rd)
            set_reg(rd, ("constant", (prev[1] & 0xffff) | (imm << 16))
                    if prev and prev[0] == "constant" else None)
        elif word & 0xffff0ff0 == 0xe1a00000 and rd <= 12 and rm <= 12:
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
            value = direct[slot]["table_va"] if slot in direct else None
            set_reg(rd, ("address", value) if value is not None else None)
            if value is not None:
                events.append({"address": va, "register": "r" + str(rd), "slot_va": slot,
                               "table_va": value, "kind": "RELOCATED_TABLE_LOAD"})
        else:
            boundary("unsupported_instruction")
            continue
        enqueue(va + 4, state)
    return flow.report()


def audit_thumb(raw, off, start, size, relocations, tables, direct):
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
    flow = Flow(start, end, nodes)
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
            value = direct[slot]["table_va"] if slot in direct else None
            set_reg(rd, ("address", value) if value is not None else None)
            if value is not None:
                events.append({"address": va, "register": "r" + str(rd), "slot_va": slot,
                               "table_va": value, "kind": "RELOCATED_TABLE_LOAD"})
        if any(slot in relocations for slot in range(va & ~3, ((va + width - 1) & ~3) + 1, 4)):
            boundary("relocated_instruction")
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
            continue
        if width == 4 and a & 0xfbf0 in (0xf240, 0xf2c0) and not b & 0x8000 and (b >> 8) & 15 <= 12:
            rd = (b >> 8) & 15
            imm = ((a & 15) << 12) | ((a & 0x400) << 1) | ((b & 0x7000) >> 4) | (b & 255)
            if a & 0xfbf0 == 0xf240:
                set_reg(rd, ("constant", imm))
            else:
                prev = state.get(rd)
                set_reg(rd, ("constant", (prev[1] & 0xffff) | (imm << 16))
                        if prev and prev[0] == "constant" else None)
        elif width == 2 and a & 0xff00 == 0x4600 and (a & 7) + ((a >> 4) & 8) <= 12 and (a >> 3) & 15 <= 12:
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
