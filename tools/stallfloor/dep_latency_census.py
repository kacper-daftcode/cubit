#!/usr/bin/env python3
"""ptxas's practice as a PAIR matrix — minimum issue distance (stall units) from a fixed-latency producer to a
consumer, keyed by (producer class, consumer class, operand role). T-26's adjacent-pair census (2026-11-10) showed the
latency is a property of the pair (IADD3 -> ALU 4, IADD3 -> IMAD 5, IMAD -> ALU 5, IMAD -> IMAD 4, MOV -> ALU 5): a table
keyed by the producer alone takes the minimum over consumers and is unsafe for the slower pairs.

role: r<k> = register operand at position k among the non-predicate operands (dest = 0), a<k> = address base of a
memory operand, u<k> uniform register, p = predicate operand (SEL / FSEL / PLOP3 input), g = guard, gc = guard of a
control-flow instruction.  Linear walk as practice.py (reset at unconditional transfers).

usage: dep_latency_census.py out.json file.dep.jsonl [...]      (the .dep.jsonl files: `cargo run --example depdump`)
"""
import sys, json, collections


def klass(j):
    op, mods = j["op"], j["mods"]
    has = lambda m: m in mods
    if op == "F2FP":
        if any(m.startswith(".PACK") for m in mods):
            return "F2FP.PACK"
        if any(m.startswith(".UNPACK") for m in mods):
            return "F2FP.UNPACK"
    if op in ("IADD3", "UIADD3") and has(".X"):
        return op + ".X"
    if op == "IMAD":
        if has(".WIDE"):
            return "IMAD.WIDE"
        if has(".HI"):
            return "IMAD.HI"
        # .MOV / .IADD / .SHL / .SHR are nvdisasm's display aliases of the same IMAD word (the assembler's
        # source text `IMAD R5, R5, 0x4, RZ` disassembles as IMAD.SHL): one class, as measured on B300
    if op == "HADD2" and has(".F32"):
        return "HADD2.F32"
    if op == "MOV" and has(".64"):
        return "MOV.64"
    if op in ("LDG", "LDS", "STS", "STG", "LDSM", "LDL", "STL"):
        return op
    return op


CTRL = {"BRA", "JMP", "RET", "EXIT", "BRX", "JMX", "CALL", "BREAK", "BSSY", "BSYNC", "CONT", "KILL"}


def uses(j):
    """[(cls, reg, role)] of every register / predicate read by j."""
    out = []
    g = j["guard"]
    gp = None
    if g and g["pred"] < 7:
        gp = (g["uniform"], g["pred"])
        out.append((("UP" if g["uniform"] else "P"), g["pred"], "gc" if j["op"] in CTRL else "g"))
    width = {}
    for base, w, is_def in j["spans"]:
        if not is_def:
            width[base] = max(width.get(base, 1), w)
    ru = set(j["ru"]); uu = set(j["uu"]); pu = set(j["pu"]); upu = set(j["upu"])
    seen_r = set()
    rd = set(j["rd"])
    for pos, kind, base in j["slots"]:
        if kind == "r" and pos == 0 and base in rd:
            continue                                   # the destination slot (dest == source reads appear at pos > 0)
        if kind in ("r", "a"):
            for r in range(base, base + width.get(base, 1)):
                if r in ru and (r, kind, pos) not in seen_r:
                    seen_r.add((r, kind, pos))
                    # the upper registers of a multi-register operand (the high half of a 64-bit addend / address) are
                    # their own role: ptxas schedules a producer of the high half of an IMAD.WIDE addend 3 cycles in front
                    # of it and never closer than 5 to the low half (silicon 2026-11-10: the low half fails at 4)
                    out.append(("R", r, f"{kind}{pos}" + ("h" if r > base else "")))
        elif kind == "u":
            if base in uu:
                out.append(("U", base, f"u{pos}"))
        elif kind == "p":
            if base in pu and gp != (False, base):
                out.append(("P", base, "p"))
        elif kind == "q":
            if base in upu and gp != (True, base):
                out.append(("UP", base, "p"))
    covered = {r for (_, r, _) in [(c, r, ro) for c, r, ro in out if c == "R"]}
    for r in ru - covered:
        out.append(("R", r, "r?"))
    return out


def mine(path, agg, ex):
    D = {}
    clock = 0
    for line in open(path):
        j = json.loads(line)
        if j["i"] == 0:
            D.clear(); clock = 0
        cc = klass(j)
        seen = set()
        for cls, r, role in uses(j):
            d = D.get((cls, r))
            if d is None:
                continue
            pj, pclock = d
            if pj["wb"] != 7:
                continue
            key = (klass(pj), cc, role)
            if (key, pj["i"]) in seen:
                continue
            seen.add((key, pj["i"]))
            dist = clock - pclock
            agg[key][min(dist, 40)] += 1
            e = ex.get(key)
            if e is None or dist < e[0]:
                ex[key] = (dist, path.split("/")[-1], pj["i"], pj["text"], j["i"], j["text"])
        d = (j, clock)
        for r in j["rd"]:
            D[("R", r)] = d
        for u in j["ud"]:
            D[("U", u)] = d
        for p in j["pd"]:
            D[("P", p)] = d
        for p in j["upd"]:
            D[("UP", p)] = d
        clock += j["s"]
        g = j["guard"]
        if j["op"] in ("BRA", "JMP", "RET", "EXIT", "BRX", "JMX") and not (g and g["pred"] < 7):
            D.clear()


def main():
    out = sys.argv[1]
    agg = collections.defaultdict(collections.Counter)
    ex = {}
    for p in sys.argv[2:]:
        mine(p, agg, ex)
    rows = []
    for key, hist in agg.items():
        n = sum(hist.values()); mn = min(hist)
        rows.append(dict(prod=key[0], cons=key[1], role=key[2], n=n, min=mn, n_min=hist[mn],
                         hist={str(k): v for k, v in sorted(hist.items())}, example=ex[key]))
    rows.sort(key=lambda r: -r["n"])
    json.dump(rows, open(out, "w"))
    print(f"{len(rows)} cells, {sum(r['n'] for r in rows)} pairs")


if __name__ == "__main__":
    main()
