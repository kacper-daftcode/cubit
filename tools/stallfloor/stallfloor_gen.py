#!/usr/bin/env python3
"""SM120 stall-floor measurement harness, CPU side (cubit docs/SM120_STALLFIX_PLAN.md, GPU item D1), v3.

v3 (2026-11-04, after the 2026-11-03 run on 4x RTX PRO 6000 Server Edition): every path but r2ur passed
its model check and 23 floors were read (docs/SM120_STALLFIX_PLAN.md §4). r2ur failed the model check
(24 576 of 32 768 threads): `R2UR UR9, R6` broadcasts ONE lane's R6 to the whole warp, while the v2
model summed every thread's own a+b. v3 makes the r2ur inputs warp-uniform (a = seed + warp id,
b = warp id ^ const; the tested edge - a vector-ALU R write consumed by R2UR at distance d - is
unchanged) and the model follows. Regenerate only this path: `--paths r2ur` (other kernels are kept).

v1 (night 2026-11-02/03) failed on every path with 100 % mismatches: the kernels were wrong, not only
the model. The fold `IADD3 R10 += R7` sat one cycle (S01) after the consumer that wrote R7, the
rotation lines ran at S01, R7 was never initialised, R2UR had no scoreboard - every non-tested
dependency of the loop was itself a hazard, so the checksum could not be right at any S. v2 freezes
every non-tested edge far above any plausible floor (S15 = the maximum of the 4-bit field) or behind
a scoreboard (R2UR, MUFU reference), initialises every register the model assumes zero, and adds a
reference kernel per path (producer with write barrier 0 + S15, consumer waiting on it) whose output
must equal the CPU model - the model is proven by the silicon before any floor is read from it.

For every dependency path the SM103a `stallfix` rule set names (and the SM120 `stallfix` section
will name), one hand-scheduled kernel per (path, distance d, producer stall S): the producer and the
consumer sit d filler instructions apart with every control code frozen (`[B:R:W:Y:S]`), the pair is
repeated 256 times per thread with a running checksum, and the kernel stores the checksum per
thread. The GPU harness (`stallfloor_run.py`) launches each kernel with 1 024 threads x 32 CTAs
20 times and compares every checksum with the reference: the minimum S with 0 mismatches over all
repetitions (and all larger S also clean) is the floor of that (path, d).

    python3 stallfloor_gen.py --cubit <cubit> --table <sm120.json> --out kernels_stall/
      -> kernels_stall/sf_<path>_d<d>_s<S>.cubin (+ .sass), sf_<path>_ref.cubin, index.json

Paths (names follow tables/sm103a.json `stallfix`): rpath (IADD3 -> IADD3), pcarry (ISETP -> SEL),
guard (ISETP -> @P consumer), dmix (IMAD.WIDE.U32 cout -> IADD3.X cin), xchain (IADD3.X -> IADD3.X),
mufu (MUFU.RCP -> FFMA consumer; variable latency: the control path, expected to need the scoreboard
at every S), urpath (UIADD3 -> UIADD3), xread (UIADD3 UR -> vector IADD3 reading the UR), r2ur
(IADD3 -> R2UR -> UIADD3), uguard (UISETP -> @UP consumer). Distances 0..2, stalls 0..11.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess

SAFE = "[B------:R-:W-:-:S15]"           # non-tested edge: maximum stall, no barrier
NOP_FILL = "[B------:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;"  # independent filler between producer and consumer
REPEAT = 256

# producer, consumer, effect register folded into the checksum R10, consumer needs a write barrier
# (variable latency: the fold then waits on it). R4/R5 = per-thread inputs, R6/R7 producer results,
# R8 consumer result, R10 checksum, R11 loop counter, R15 filler, UR8/UR9 uniform values.
PATHS = {
    "rpath": ("IADD3 R6, PT, PT, R4, R5, RZ ;", "IADD3 R8, PT, PT, R6, R5, RZ ;", "R8", False),
    "pcarry": ("ISETP.LT.U32.AND P0, PT, R4, R5, PT ;", "SEL R8, R4, R5, P0 ;", "R8", False),
    "guard": ("ISETP.LT.U32.AND P0, PT, R4, R5, PT ;", "@P0 IADD3 R8, PT, PT, R4, R5, RZ ;", "R8", False),
    "dmix": ("IMAD.WIDE.U32 R6, P0, R4, R5, RZ ;", "IADD3.X R8, PT, PT, R6, R5, RZ, P0, !PT ;", "R8", False),
    "xchain": ("IADD3.X R6, P0, PT, R4, R5, RZ, PT, !PT ;", "IADD3.X R8, PT, PT, R6, R5, RZ, P0, !PT ;", "R8", False),
    "mufu": ("MUFU.RCP R6, R4 ;", "FFMA R8, R6, R5, RZ ;", "R8", False),
    "urpath": ("UIADD3 UR8, UPT, UPT, UR8, 0x3, URZ ;", "UIADD3 UR9, UPT, UPT, UR8, 0x5, URZ ;", "UR9", False),
    "xread": ("UIADD3 UR8, UPT, UPT, UR8, 0x3, URZ ;", "IADD3 R8, PT, PT, R4, UR8, RZ ;", "R8", False),
    "r2ur": ("IADD3 R6, PT, PT, R4, R5, RZ ;", "R2UR UR9, R6 ;", "UR9", True),
    "uguard": ("UISETP.LT.U32.AND UP0, UPT, UR8, 0x80000000, UPT ;", "@UP0 UIADD3 UR9, UPT, UPT, UR9, 0x5, URZ ;", "UR9", False),
}


def kernel_text(name, path, d, s, reference=False):
    prod, cons, eff, cons_barrier = PATHS[path]
    if reference:
        # tested edge behind scoreboard 0 as well: the kernel whose result must equal the CPU model
        prod_ctrl = "[B------:R-:W0:-:S15]"
        cons_wait = "B0-----"
    else:
        prod_ctrl = f"[B------:R-:W-:-:S{s:02d}]"
        cons_wait = "B------"
    cons_ctrl = f"[{cons_wait}:R-:W{'1' if cons_barrier else '-'}:-:S15]"
    fold_ctrl = f"[{'B-1----' if cons_barrier else 'B------'}:R-:W-:-:S15]"
    body = [f"    {prod_ctrl} {prod}"]
    body += [f"    {NOP_FILL}"] * d
    body.append(f"    {cons_ctrl} {cons}")
    body.append(f"    {fold_ctrl} IADD3 R10, PT, PT, R10, {eff}, RZ ;")
    # rotate the inputs so every iteration differs (far from their readers: S15 each)
    body.append(f"    {SAFE} IADD3 R4, PT, PT, R4, 0x9e3779b9, RZ ;")
    body.append(f"    {SAFE} IADD3 R5, PT, PT, R5, 0x7f4a7c15, RZ ;")
    if path == "uguard":
        body.append(f"    {SAFE} UIADD3 UR8, UPT, UPT, UR8, 0x40000001, URZ ;")
    lines = [f".entry {name}", "    .reg R0-R20", "    .regcount 32", "    .param ptr out", "    .param u32 seed",
             "    [B------:R-:W0:-:S01] LDCU.64 UR4, c[0x0][0x358] ;",
             "    [B------:R-:W1:-:S01] S2R R0, SR_TID.X ;",
             "    [B------:R-:W2:-:S01] S2R R1, SR_CTAID.X ;",
             "    [B------:R-:W3:-:S01] LDC.64 R2, c[0x0][0x380] ;",
             "    [B------:R-:W4:-:S01] LDC R4, c[0x0][0x388] ;",
             f"    [B01234-:R-:W-:-:S15] IMAD R1, R1, 0x400, R0 ;",          # global thread id
             # v3: r2ur takes warp-uniform inputs (R2UR broadcasts one lane); every other path per-thread
             f"    {SAFE} SHF.R.U32.HI R12, RZ, 0x5, R1 ;" if path == "r2ur" else f"    {SAFE} MOV R12, R1 ;",
             f"    {SAFE} IADD3 R4, PT, PT, R4, R12, RZ ;",                   # input a = seed + (gid | warp id)
             f"    {SAFE} LOP3.LUT R5, R12, 0x5bd1e995, RZ, 0x3c, !PT ;",     # input b = (gid | warp id) ^ const
             f"    {SAFE} MOV R6, RZ ;", f"    {SAFE} MOV R7, RZ ;", f"    {SAFE} MOV R8, RZ ;",
             f"    {SAFE} MOV R10, RZ ;", f"    {SAFE} MOV R11, RZ ;", f"    {SAFE} MOV R15, RZ ;",
             f"    {SAFE} UMOV UR8, 0x1 ;", f"    {SAFE} UMOV UR9, 0x0 ;",
             f"    {SAFE} ISETP.LT.U32.AND P0, PT, RZ, RZ, PT ;",             # P0 = false
             f"    {SAFE} UISETP.LT.U32.AND UP0, UPT, URZ, URZ, UPT ;",       # UP0 = false
             "L_loop:"]
    lines += body
    lines += [f"    {SAFE} IADD3 R11, PT, PT, R11, 0x1, RZ ;",
              f"    {SAFE} ISETP.LT.U32.AND P1, PT, R11, 0x{REPEAT:x}, PT ;",
              f"    {SAFE} @P1 BRA L_loop ;",
              f"    {SAFE} IMAD.WIDE.U32 R2, R1, 0x4, R2 ;",
              f"    {SAFE} STG.E desc[UR4][R2.64], R10 ;",
              f"    {SAFE} EXIT ;", ".endentry", ""]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cubit", required=True)
    ap.add_argument("--table", required=True)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--paths", default=",".join(PATHS))
    ap.add_argument("--stalls", default="0,1,2,3,4,5,6,7,8,9,10,11")
    ap.add_argument("--distances", default="0,1,2")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for path in args.paths.split(","):
        for old in args.out.glob(f"sf_{path}_*"):
            old.unlink()
    index = []
    failed = []

    def build(name, text, meta):
        src = args.out / f"{name}.sass"
        src.write_text(text)
        cubin = args.out / f"{name}.cubin"
        r = subprocess.run([args.cubit, "asm", "-t", args.table, str(src), "-o", str(cubin)],
                           capture_output=True, text=True)
        if r.returncode or not cubin.is_file():
            failed.append((name, (r.stderr or r.stdout).strip().splitlines()[-1][:160]))
            return
        index.append(dict(name=name, cubin=cubin.name, repeat=REPEAT, **meta))

    for path in args.paths.split(","):
        build(f"sf_{path}_ref", kernel_text(f"sf_{path}_ref", path, 0, 15, reference=True),
              {"path": path, "distance": -1, "stall": -1, "effect": PATHS[path][2], "reference": True})
        for d in map(int, args.distances.split(",")):
            for s in map(int, args.stalls.split(",")):
                name = f"sf_{path}_d{d}_s{s:02d}"
                build(name, kernel_text(name, path, d, s),
                      {"path": path, "distance": d, "stall": s, "effect": PATHS[path][2], "reference": False})
    idx_path = args.out / "index.json"
    if idx_path.is_file():
        kept = [e for e in json.loads(idx_path.read_text()) if e["path"] not in args.paths.split(",")]
        index = kept + index
    idx_path.write_text(json.dumps(index, indent=1) + "\n")
    print(f"{len(index)} kernels assembled into {args.out}, {len(failed)} failed")
    for name, err in failed[:10]:
        print("  FAILED", name, err)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
