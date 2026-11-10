#!/usr/bin/env python3
"""SM120 stall-floor harness v6, CPU side: POPULATIONS of kernels per table cell.

v5 measured one kernel per (pair, distance, stall). v6 asks the question the table is used for: "is the cell's latency L
enough for the pair in any neighbourhood?" -- per cell (producer class -> consumer class, operand role) of
tables/dep_latency_sm120.json, N kernels at the producer stall S = L (must all PASS) and N at S = L - 1 (the sensitivity
side: FAIL where the silicon floor is L, PASS where the vendor's practice has a cycle of margin), every kernel a random
draw of
  * the four registers (inputs A, B, the producer's result D, the consumer's result E: distinct even registers),
  * the yield flag on the producer's stall,
  * 0..3 unrelated ALU instructions at S01 in front of the producer (the producer issues one cycle behind its neighbour,
    as in real code; v5 always had 15 idle cycles in front of it).
The oracle is the GPU's own safe schedule: per cell one reference kernel (producer at S15, default registers) -- the
checksum does not depend on the register names. All kernels of one (cell, stall) are entries of ONE cubin.

    python3 cellfloor_gen.py --cubit <cubit> --table <sm120.json> --lat <dep_latency_sm120.json> --out kernels_cell/
        [--n 64] [--cells "IADD3 -> IADD3 r1,..."] [--used cells_used.json ...] [--per-class 512] [--seed 1]
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import pathlib
import random
import subprocess

SAFE = "[B------:R-:W-:-:S15]"
REPEAT = 256
POOL = [4, 6, 16, 18, 20, 22, 24, 26]          # even registers (a 64-bit result owns R and R+1)

PROD = {
    "IADD3": "IADD3 {D}, PT, PT, {A}, {B}, RZ",
    "IMAD": "IMAD {D}, {A}, {B}, RZ",
    "IMAD.WIDE": "IMAD.WIDE.U32 {D}, {A}, {B}, RZ",
    "LOP3": "LOP3.LUT {D}, {A}, {B}, RZ, 0x3c, !PT",
    "SHF": "SHF.R.U32.HI {D}, RZ, 0x3, {A}",
    "MOV": "MOV {D}, {A}",
    "SEL": "SEL {D}, {A}, {B}, P2",
    "VIMNMX": "VIMNMX.S32 {D}, {A}, {B}, PT",
    "FADD": "FADD.FTZ {D}, {A}, {B}",
    "FMUL": "FMUL.FTZ {D}, {A}, {B}",
    "FFMA": "FFMA.FTZ {D}, {A}, {B}, {A}",
    "FMNMX": "FMNMX.FTZ {D}, {A}, {B}, !PT",
    "FSEL": "FSEL {D}, {A}, {B}, P2",
    "F2FP.UNPACK": "F2FP.F16.E4M3.UNPACK_B {D}, {A}",
    "F2FP.UNPACK/E8": "F2FP.BF16.E8.UNPACK_B {D}, {A}",
    "F2FP.PACK": "F2FP.BF16.F32.PACK_AB {D}, {A}, {B}",
    "HADD2.F32": "HADD2.F32 {D}, -RZ, {A}.H0_H0",
    "HMUL2": "HMUL2.BF16_V2 {D}, {A}, {B}",
    "ISETP": "ISETP.LT.U32.AND P0, PT, {A}, {B}, PT",
    "FSETP": "FSETP.GT.FTZ.AND P0, PT, {A}, {B}, PT",
}
# (consumer class, role) -> (text, effect, consumer sets a write barrier)
CONS = {
    ("IADD3", "r1"): ("IADD3 {E}, PT, PT, {D}, {B}, RZ", "E", False),
    ("IADD3", "r2"): ("IADD3 {E}, PT, PT, {B}, {D}, RZ", "E", False),
    ("IADD3", "r3"): ("IADD3 {E}, PT, PT, {A}, {B}, {D}", "E", False),
    ("IMAD", "r1"): ("IMAD {E}, {D}, {B}, RZ", "E", False),
    ("IMAD", "r2"): ("IMAD {E}, {B}, {D}, RZ", "E", False),
    ("IMAD", "r3"): ("IMAD {E}, {A}, {B}, {D}", "E", False),
    ("IMAD.WIDE", "r1"): ("IMAD.WIDE.U32 {E}, {D}, 0x3, RZ", "E", False),
    ("IMAD.WIDE", "r3"): ("IMAD.WIDE.U32 {E}, {B}, 0x3, {D}", "E", False),
    ("SHF", "r1"): ("SHF.L.U32 {E}, {D}, 0x3, RZ", "E", False),
    ("SHF", "r3"): ("SHF.R.U32.HI {E}, RZ, 0x3, {D}", "E", False),
    ("LOP3", "r1"): ("LOP3.LUT {E}, {D}, {B}, RZ, 0x3c, !PT", "E", False),
    ("LOP3", "r2"): ("LOP3.LUT {E}, {B}, {D}, RZ, 0x3c, !PT", "E", False),
    ("SEL", "r1"): ("SEL {E}, {D}, {B}, P2", "E", False),
    ("SEL", "r2"): ("SEL {E}, {B}, {D}, P3", "E", False),
    ("SEL", "p"): ("SEL {E}, {A}, {B}, P0", "E", False),
    ("ISETP", "r0"): ("ISETP.LT.U32.AND P4, PT, {D}, {B}, PT", "P4", False),
    ("ISETP", "r1"): ("ISETP.LT.U32.AND P4, PT, {B}, {D}, PT", "P4", False),
    ("VIMNMX", "r1"): ("VIMNMX.S32 {E}, {D}, {B}, PT", "E", False),
    ("F2FP.UNPACK", "r1"): ("F2FP.F16.E4M3.UNPACK_B {E}, {D}", "E", False),
    ("F2FP.PACK", "r1"): ("F2FP.BF16.F32.PACK_AB {E}, {D}, {B}", "E", False),
    ("F2FP.PACK", "r2"): ("F2FP.BF16.F32.PACK_AB {E}, {B}, {D}", "E", False),
    ("HADD2.F32", "r2"): ("HADD2.F32 {E}, -RZ, {D}.H0_H0", "E", False),
    ("HMUL2", "r1"): ("HMUL2.BF16_V2 {E}, {D}, {B}", "E", False),
    ("HMUL2", "r2"): ("HMUL2.BF16_V2 {E}, {B}, {D}", "E", False),
    ("FADD", "r1"): ("FADD.FTZ {E}, {D}, {B}", "E", False),
    ("FADD", "r2"): ("FADD.FTZ {E}, {B}, {D}", "E", False),
    ("FMUL", "r1"): ("FMUL.FTZ {E}, {D}, {B}", "E", False),
    ("FMUL", "r2"): ("FMUL.FTZ {E}, {B}, {D}", "E", False),
    ("FFMA", "r1"): ("FFMA.FTZ {E}, {D}, {B}, {A}", "E", False),
    ("FFMA", "r3"): ("FFMA.FTZ {E}, {A}, {B}, {D}", "E", False),
    ("FMNMX", "r1"): ("FMNMX.FTZ {E}, {D}, {B}, !PT", "E", False),
    ("FMNMX", "r2"): ("FMNMX.FTZ {E}, {B}, {D}, !PT", "E", False),
    ("FSEL", "r1"): ("FSEL {E}, {D}, {B}, P2", "E", False),
    ("FSEL", "r2"): ("FSEL {E}, {B}, {D}, P3", "E", False),
    ("FSEL", "p"): ("FSEL {E}, {A}, {B}, P0", "E", False),
    ("MUFU", "r1"): ("MUFU.EX2 {E}, {D}", "E", True),
    ("IADD3", "g"): ("@P0 IADD3 {E}, PT, PT, {A}, {B}, RZ", "E", False),
    ("MOV", "g"): ("@P0 MOV {E}, {A}", "E", False),
    ("FADD", "g"): ("@P0 FADD.FTZ {E}, {A}, {B}", "E", False),
    ("BRA", "gc"): ("@P0 BRA {LBL}", "E", False),            # + a skipped IADD3 (see body)
}


def body_of(pc_key, cc, role, regs, s, y, pre, uid, reference=False):
    A, B, D, E = (f"R{r}" for r in regs)
    prod = PROD[pc_key].format(A=A, B=B, D=D)
    text, eff, bar = CONS[(cc, role)]
    lbl = f"L_s{uid}"
    cons = text.format(A=A, B=B, D=D, E=E, LBL=lbl)
    pctrl = SAFE if reference else f"[B------:R-:W-:{'Y' if (y and s < 12) else '-'}:S{s:02d}]"
    out = []
    for _ in range(0 if reference else pre):
        out.append("[B------:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;")
    out.append(f"{pctrl} {prod} ;")
    out.append(f"[B------:R-:W{'1' if bar else '-'}:-:S15] {cons} ;")
    if cc == "BRA":
        out.append(f"{SAFE} IADD3 {E}, PT, PT, {E}, {A}, RZ ;")
        out.append(f"{lbl}:")
        out.append(f"{SAFE} IADD3 {E}, PT, PT, {E}, 0x1, RZ ;")
    effr = E
    if eff.startswith("P"):
        out.append(f"{SAFE} SEL {E}, {A}, {B}, {eff} ;")
    out.append(f"[{'B-1----' if bar else 'B------'}:R-:W-:-:S15] IADD3 R10, PT, PT, R10, {effr}, RZ ;")
    return out


def kernel_text(name, pc_key, cc, role, regs, s, y, pre, uid, reference=False):
    A, B, D, E = (f"R{r}" for r in regs)
    lines = [f".entry {name}", "    .reg R0-R27", "    .regcount 32", "    .param ptr out", "    .param u32 seed",
             "    [B------:R-:W0:-:S04] LDCU.64 UR4, c[0x0][0x358] ;",
             "    [B------:R-:W1:-:S04] S2R R0, SR_TID.X ;",
             "    [B------:R-:W2:-:S04] S2R R1, SR_CTAID.X ;",
             "    [B------:R-:W3:-:S04] LDC.64 R2, c[0x0][0x380] ;",
             "    [B------:R-:W4:-:S08] LDC R14, c[0x0][0x388] ;",
             "    [B01234-:R-:W-:-:S15] IMAD R1, R1, 0x400, R0 ;",
             f"    {SAFE} MOV R12, R1 ;"]
    for r in sorted(set(POOL)):
        lines.append(f"    {SAFE} MOV R{r}, RZ ;")
        lines.append(f"    {SAFE} MOV R{r + 1}, RZ ;")
    lines += [f"    {SAFE} IADD3 {A}, PT, PT, R14, R12, RZ ;",
              f"    {SAFE} LOP3.LUT {B}, R12, 0x5bd1e995, RZ, 0x3c, !PT ;",
              f"    {SAFE} MOV R10, RZ ;", f"    {SAFE} MOV R11, RZ ;", f"    {SAFE} MOV R15, RZ ;",
              f"    {SAFE} ISETP.LT.U32.AND P0, PT, RZ, RZ, PT ;",
              f"    {SAFE} ISETP.EQ.U32.AND P2, PT, RZ, RZ, PT ;",             # P2 = true
              f"    {SAFE} ISETP.LT.U32.AND P3, PT, RZ, RZ, PT ;",             # P3 = false
              f"    {SAFE} ISETP.LT.U32.AND P4, PT, RZ, RZ, PT ;",
              f"L_loop{uid}:"]
    lines += [f"    {l}" if not l.endswith(":") else l for l in body_of(pc_key, cc, role, regs, s, y, pre, uid, reference)]
    lines += [f"    {SAFE} IADD3 {A}, PT, PT, {A}, 0x9e3779b9, RZ ;",
              f"    {SAFE} IADD3 {B}, PT, PT, {B}, 0x7f4a7c15, RZ ;",
              f"    {SAFE} IADD3 R11, PT, PT, R11, 0x1, RZ ;",
              f"    {SAFE} ISETP.LT.U32.AND P1, PT, R11, 0x{REPEAT:x}, PT ;",
              f"    {SAFE} @P1 BRA L_loop{uid} ;",
              f"    {SAFE} IMAD.WIDE.U32 R2, R1, 0x4, R2 ;",
              f"    {SAFE} STG.E desc[UR4][R2.64], R10 ;",
              f"    {SAFE} EXIT ;", ".endentry", ""]
    return "\n".join(lines)


def prod_key(pc, cc):
    if pc == "F2FP.UNPACK" and cc == "HMUL2":
        return "F2FP.UNPACK/E8"
    return pc


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cubit", required=True)
    ap.add_argument("--table", required=True)
    ap.add_argument("--lat", required=True, help="tables/dep_latency_sm120.json")
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--used", nargs="*", default=[], help="cells_used.json of candidates: the binding cells come first")
    ap.add_argument("--cells", default="")
    ap.add_argument("--n", type=int, default=64, help="kernels per (cell, stall), at least")
    ap.add_argument("--per-class", type=int, default=512, help="kernels per producer class and stall side, at least")
    ap.add_argument("--extra-stalls", default="", help="more stalls relative to L, e.g. -2,1")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--jobs", type=int, default=24)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    lat = json.load(open(args.lat))
    cellL = {(c["producer"], c["consumer"], c["role"]): c["L"] for c in lat["cells"]}
    dflt = lat["defaults"]

    def L_of(pc, cc, role):
        if (pc, cc, role) in cellL:
            return cellL[(pc, cc, role)], False
        if role in ("g", "gc"):
            return dflt["guard"], True
        if role == "p":
            return dflt["pred_operand"], True
        return dflt["data"], True

    # which cells: named, or every binding cell of the candidates that the templates can build, or all buildable cells
    want = []
    if args.cells:
        for c in args.cells.split(","):
            p, rest = c.strip().split(" -> ")
            cc, role = rest.rsplit(" ", 1)
            want.append((p, cc, role))
    else:
        seen = set()
        for fp in args.used:
            for u in json.load(open(fp)):
                if u["kind"] != "raw" or not u["binding"]:
                    continue
                for role in u["role"].split("+"):
                    k = (u["pc"], u["cc"], role)
                    if k not in seen:
                        seen.add(k); want.append(k)
        for (p, cc, role) in sorted(cellL):
            if (p, cc, role) not in seen:
                seen.add((p, cc, role)); want.append((p, cc, role))
    cells, unbuilt = [], []
    for (p, cc, role) in want:
        if prod_key(p, cc) in PROD and (cc, role) in CONS and not (cc == "ISETP" and role == "p"):
            if (p in ("ISETP", "FSETP")) != (role in ("p", "g", "gc")):
                unbuilt.append((p, cc, role)); continue
            cells.append((p, cc, role))
        else:
            unbuilt.append((p, cc, role))
    by_class = collections.Counter(p for p, _, _ in cells)
    rng = random.Random(args.seed)
    groups = []       # (group name, [(kernel name, text, meta)])
    uid = 0
    extra = [int(x) for x in args.extra_stalls.split(",") if x.strip()]
    for ci, (p, cc, role) in enumerate(cells):
        L, defaulted = L_of(p, cc, role)
        n = max(args.n, -(-args.per_class // by_class[p]))
        cname = f"c{ci:03d}"
        cell = f"{p} -> {cc} {role}"
        pk = prod_key(p, cc)
        uid += 1
        ref = (f"{cname}_ref", kernel_text(f"{cname}_ref", pk, cc, role, (4, 6, 16, 18), 15, False, 0, uid, reference=True),
               dict(cell=cell, cls=p, L=L, defaulted=defaulted, stall=-1, reference=True))
        groups.append((f"{cname}_ref", [ref]))
        for rel in sorted(set([-1, 0] + extra)):
            s = L + rel
            if s < 1 or s > 15:
                continue
            ks = []
            for k in range(n):
                regs = tuple(rng.sample(POOL, 4))
                y = rng.random() < 0.5
                pre = rng.choice([0, 0, 1, 2, 3])
                uid += 1
                name = f"{cname}_s{s:02d}_{k:03d}"
                ks.append((name, kernel_text(name, pk, cc, role, regs, s, y, pre, uid),
                           dict(cell=cell, cls=p, L=L, defaulted=defaulted, stall=s, rel=rel, reference=False,
                                regs=list(regs), y=bool(y and s < 12), pre=pre)))
            groups.append((f"{cname}_s{s:02d}", ks))

    def build(group):
        gname, ks = group
        src = args.out / f"{gname}.sass"
        src.write_text("\n".join(t for _, t, _ in ks))
        cubin = args.out / f"{gname}.cubin"
        r = subprocess.run([args.cubit, "asm", "-t", args.table, str(src), "-o", str(cubin)], capture_output=True, text=True)
        if r.returncode or not cubin.is_file():
            return None, (gname, (r.stderr or r.stdout).strip().splitlines()[-1][:300] if (r.stderr or r.stdout).strip() else "no output")
        return [dict(name=n, cubin=cubin.name, repeat=REPEAT, **m) for n, _, m in ks], None

    index, failed = [], []
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as ex:
        for ok, bad in ex.map(build, groups):
            if ok:
                index.extend(ok)
            else:
                failed.append(bad)
    (args.out / "index.json").write_text(json.dumps(index) + "\n")
    (args.out / "cells.json").write_text(json.dumps(dict(cells=[" -> ".join([p, f"{cc} {role}"]) for p, cc, role in cells],
                                                          unbuilt=[" -> ".join([p, f"{cc} {role}"]) for p, cc, role in unbuilt]), indent=1))
    print(f"{len(cells)} cells of {len(by_class)} producer classes, {len(index)} kernels in {len(groups) - len(failed)} cubins, "
          f"{len(failed)} groups failed; {len(unbuilt)} wanted cells have no template")
    for c, n in sorted(by_class.items()):
        nk = sum(1 for e in index if e["cls"] == c and not e["reference"])
        print(f"  class {c:12s}: {n:3d} cells, {nk} kernels")
    for name, err in failed[:20]:
        print("  FAILED", name, err)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
