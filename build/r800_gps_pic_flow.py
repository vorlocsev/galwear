"""Forward-only A32 address dataflow over a bounded, assumed code range."""
import struct


def audit(raw, off, start, size, relocations, tables, direct):
    if size % 4 or start % 4 or not 0 < size <= 65536 or off < 0 or off + size > len(raw):
        raise ValueError("Invalid A32 flow range")
    end = start + size
    incoming = {start: {}}
    events, boundaries = [], []

    def enqueue(target, state):
        if target in incoming:
            incoming[target] = {k: v for k, v in incoming[target].items() if state.get(k) == v}
        else:
            incoming[target] = dict(state)

    for va in range(start, end, 4):
        if va not in incoming:
            continue
        state = dict(incoming[va])
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
            if not va < target < end:
                boundary("nonforward_or_external_branch")
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
    # An unresolved path may reenter the modeled range. Suppress all facts.
    return {"status": "PARTIAL_FLOW_REVIEW_REQUIRED" if boundaries else "CONDITIONAL_FORWARD_FLOW_ONLY",
            "events": [] if boundaries else events, "boundaries": boundaries,
            "reached_instructions": sum(va < end for va in incoming),
            "range_end_reached": end in incoming, "control_flow_verified": False,
            "safe_to_flash": False}
