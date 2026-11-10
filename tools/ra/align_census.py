#!/usr/bin/env python3
"""Where does ptxas put multi-register operands on sm_120? Mined from frozen disassemblies of nvcc / ptxas cubins
(`cubit disassemble --frozen`, one `*.frozen.sass` per cubin). For every operand that names more than one 32-bit register
(64-bit pairs, 128-bit quads, MMA tuples, 64-bit addresses and descriptors) the residue of its base register modulo its
width is counted. Output: one line per shape with the `base % align` histogram and the first few off-grid sites.

    align_census.py <dir with *.frozen.sass> [out.json]

Result of 2026-11-10 on the sm_120 census (166 cubins, 1 811 600 instructions): `align_census_sm120.json` -- no operand of
any shape is off its grid. It is the vendor-practice half of the evidence behind `cubit ra --target sm120`
(src/ra_target.rs); the silicon half is KNOWN_ISSUES A2 (BUG-008) and BUG-037.
"""
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict

RE_INS = re.compile(r"^\s*(?:[A-Za-z_][A-Za-z0-9_.$]*:\s*)*(?:\[[^\]]*\]\s*)?(?:@!?U?P[0-7T]\s+)?([A-Z][A-Z0-9_.]*)\s*(.*?)\s*(?:!rsd\[[^\]]*\])?\s*;")
RE_BARE = re.compile(r"^[-~|]*(UR|R)(\d+)\|?(?:\.[A-Za-z0-9_]+)*$")


def split_ops(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "[(":
            depth += 1
        elif ch in "])":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip()); cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def main():
    d = sys.argv[1]
    hist = defaultdict(Counter)        # shape -> residue -> count
    sites = defaultdict(list)
    files = sorted(glob.glob(os.path.join(d, "*.frozen.sass")))
    nins = 0

    def rec(shape, base, mod, where):
        r = base % mod
        hist[shape][r] += 1
        if r and len(sites[shape]) < 4:
            sites[shape].append(where)

    for f in files:
        name = os.path.basename(f)
        for ln, raw in enumerate(open(f, errors="replace"), 1):
            m = RE_INS.match(raw)
            if not m:
                continue
            full, rest = m.group(1), m.group(2)
            if full.startswith("__raw__"):
                continue
            nins += 1
            op = full.split(".")[0]
            mods = full.split(".")[1:]
            ops = split_ops(rest)
            where = f"{name}:{ln}: {full} {rest}"

            def bare(k):
                if k < len(ops):
                    mm = RE_BARE.match(ops[k])
                    if mm:
                        return mm.group(1), int(mm.group(2))
                return None
            # 64-bit address pairs and descriptors
            for o in ops:
                mm = re.search(r"desc\[UR(\d+)\]\[R(\d+)\.64", o)
                if mm:
                    rec(f"{op} desc[UR].. descriptor pair", int(mm.group(1)), 2, where)
                    rec(f"{op} desc[..][R.64] address pair", int(mm.group(2)), 2, where)
                else:
                    mm = re.search(r"(?<!c)\[R(\d+)\.64", o)
                    if mm:
                        rec(f"{op} [R.64] address pair", int(mm.group(1)), 2, where)
            w = 8 if "256" in mods else 4 if "128" in mods else 2 if "64" in mods else 1
            if op in ("LDG", "LDS", "LDL", "LDC", "LD"):
                b = bare(0)
                if b and b[0] == "R" and w > 1:
                    rec(f"{op}.{w * 32} dest", b[1], min(w, 4), where)
            elif op == "LDCU":
                b = bare(0)
                if b and b[0] == "UR" and w > 1:
                    rec(f"LDCU.{w * 32} dest (UR)", b[1], 2, where)
            elif op in ("STG", "STS", "STL", "ST"):
                b = bare(len(ops) - 1)
                if b and b[0] == "R" and w > 1:
                    rec(f"{op}.{w * 32} data", b[1], min(w, 4), where)
            elif op == "IMAD" and "WIDE" in mods:
                b = bare(0)
                if b:
                    rec("IMAD.WIDE dest pair", b[1], 2, where)
                c = [o for o in ops[1:] if not re.fullmatch(r"!?U?P[0-7T]", o)]
                mm = RE_BARE.match(c[-1]) if c else None
                if mm and mm.group(1) == "R" and len(c) >= 3:
                    rec("IMAD.WIDE addend pair (c)", int(mm.group(2)), 2, where)
            elif op == "CS2R":
                b = bare(0)
                if b and "32" not in mods:
                    rec("CS2R dest (64-bit)", b[1], 2, where)
            elif op == "LDSM":
                b = bare(0)
                if b:
                    n = 4 if mods[-1] == "4" else 2 if mods[-1] == "2" else 1
                    if n > 1:
                        rec(f"LDSM x{n} dest", b[1], n, where)
            elif op in ("HMMA", "IMMA", "QMMA"):
                for k, (nm, al) in enumerate((("D", 4), ("A", 4), ("B", 2), ("C", 4))):
                    b = bare(k)
                    if b and b[0] == "R":
                        rec(f"{op} {nm}", b[1], al, where)
            elif op in ("DADD", "DMUL", "DFMA", "F2F", "I2F", "F2I") and ("F64" in mods or op.startswith("D")):
                b = bare(0)
                if b and (op.startswith("D") or mods[:1] == ["F64"]):
                    rec(f"{op} f64 dest pair", b[1], 2, where)
            elif op == "MOV" and "64" in mods:
                b = bare(0)
                if b:
                    rec("MOV.64 dest", b[1], 2, where)
    print(f"{len(files)} frozen sources, {nins} instructions")
    out = {}
    for shape in sorted(hist):
        h = hist[shape]
        tot = sum(h.values())
        off = tot - h[0]
        print(f"  {shape:42s} n={tot:7d}  on the grid {h[0]:7d}  off the grid {off:6d}  residues {dict(sorted(h.items()))}")
        for s in sites[shape]:
            print(f"        off-grid: {s[:170]}")
        out[shape] = {"n": tot, "on_grid": h[0], "off_grid": off, "residues": dict(sorted(h.items())), "first_off_grid": sites[shape]}
    if len(sys.argv) > 2:
        json.dump({"sources": len(files), "instructions": nins, "shapes": out}, open(sys.argv[2], "w"), indent=1)


if __name__ == "__main__":
    main()
