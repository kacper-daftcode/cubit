#!/usr/bin/env python3
"""SM120 pair stall-floor harness, CPU side (v5; extends cubit tools/stallfloor/stallfloor_gen.py v3).

The 2026-11-03 harness measured ten dependency paths with a CPU model each. v5 measures PAIRS (producer class ->
consumer class [operand role]) with the GPU's own safe schedule as the oracle: per pair one reference kernel (producer
at S15 — above every fixed latency of the table — in front of the consumer) whose output is the expected checksum, and
one kernel per (distance d, producer stall S, yield y). Everything else is the v3 skeleton: every non-tested edge frozen
at S15 or behind a scoreboard, 256 iterations per thread with a running checksum, 32 CTAs x 1 024 threads.

Floor of (pair, d) = the smallest S with 0 mismatching threads over all repetitions such that every larger S is clean.
At d0 it is the pair's latency in issue cycles — a count of synchronous pipeline stages (the same at any core clock).

    python3 pairfloor_gen.py --cubit <cubit> --table <sm120.json> --out kernels_pair/ [--pairs a,b] [--jobs N]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import pathlib
import subprocess

SAFE = "[B------:R-:W-:-:S15]"
NOP_FILL = "[B------:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;"
REPEAT = 256

# name: (producer, consumer, effect register, consumer needs a write barrier, table cell "producer -> consumer role")
# R4 / R5 = per-thread inputs (rotated every iteration), R6 = the producer's result, R8 = the consumer's, R10 checksum,
# R11 loop counter, R15 filler, P2 = constant true, P3 = constant false (set in the prologue).
PAIRS = {
    # ---- integer ALU: same unit / cross unit (T-26's adjacent-pair census: 4 / 5)
    "iadd3_iadd3": ("IADD3 R6, PT, PT, R4, R5, RZ ;", "IADD3 R8, PT, PT, R6, R5, RZ ;", "R8", False, "IADD3 -> IADD3 r1"),
    "iadd3_imad": ("IADD3 R6, PT, PT, R4, R5, RZ ;", "IMAD R8, R6, R5, RZ ;", "R8", False, "IADD3 -> IMAD r1"),
    "iadd3_imad_c": ("IADD3 R6, PT, PT, R4, R5, RZ ;", "IMAD R8, R4, R5, R6 ;", "R8", False, "IADD3 -> IMAD r3"),
    "imad_iadd3": ("IMAD R6, R4, R5, RZ ;", "IADD3 R8, PT, PT, R6, R5, RZ ;", "R8", False, "IMAD -> IADD3 r1"),
    "imad_imad": ("IMAD R6, R4, R5, RZ ;", "IMAD R8, R6, R5, RZ ;", "R8", False, "IMAD -> IMAD r1"),
    "imad_imad_c": ("IMAD R6, R4, R5, RZ ;", "IMAD R8, R4, R5, R6 ;", "R8", False, "IMAD -> IMAD r3"),
    "lop3_shf": ("LOP3.LUT R6, R4, R5, RZ, 0x3c, !PT ;", "SHF.R.U32.HI R8, RZ, 0x3, R6 ;", "R8", False, "LOP3 -> SHF r3"),
    "shf_lop3": ("SHF.R.U32.HI R6, RZ, 0x3, R4 ;", "LOP3.LUT R8, R6, R5, RZ, 0x3c, !PT ;", "R8", False, "SHF -> LOP3 r1"),
    "shf_imad": ("SHF.R.U32.HI R6, RZ, 0x3, R4 ;", "IMAD R8, R6, R5, RZ ;", "R8", False, "SHF -> IMAD r1"),
    "mov_iadd3": ("MOV R6, R4 ;", "IADD3 R8, PT, PT, R6, R5, RZ ;", "R8", False, "MOV -> IADD3 r1"),
    "mov_sel_t": ("MOV R6, R4 ;", "SEL R8, R6, R5, P2 ;", "R8", False, "MOV -> SEL r1"),
    "mov_sel_f": ("MOV R6, R4 ;", "SEL R8, R5, R6, P3 ;", "R8", False, "MOV -> SEL r2"),
    "sel_iadd3": ("SEL R6, R4, R5, P2 ;", "IADD3 R8, PT, PT, R6, R5, RZ ;", "R8", False, "SEL -> IADD3 r1"),
    "sel_shf": ("SEL R6, R4, R5, P2 ;", "SHF.R.U32.HI R8, RZ, 0x3, R6 ;", "R8", False, "SEL -> SHF r3"),
    "sel_imadw_c": ("SEL R6, R4, R5, P2 ;", "IMAD.WIDE.U32 R8, R4, 0x3, R6 ;", "R8", False, "SEL -> IMAD.WIDE r3"),
    "imadw_imadw_c": ("IMAD.WIDE.U32 R6, R4, R5, RZ ;", "IMAD.WIDE.U32 R8, R5, 0x3, R6 ;", "R8", False, "IMAD.WIDE -> IMAD.WIDE r3"),
    "iadd3_isetp": ("IADD3 R6, PT, PT, R4, R5, RZ ;", "ISETP.LT.U32.AND P0, PT, R6, R5, PT ;", "P0", False, "IADD3 -> ISETP r0"),
    # ---- the dequant chain (fp8 / fp4 -> f16 -> f32 -> bf16 x scale)
    "shf_f2fpu": ("SHF.R.U32.HI R6, RZ, 0x8, R4 ;", "F2FP.F16.E2M1.UNPACK_B R8, R6 ;", "R8", False, "SHF -> F2FP.UNPACK r1"),
    "sel_f2fpu": ("SEL R6, R4, R5, P2 ;", "F2FP.F16.E2M1.UNPACK_B R8, R6 ;", "R8", False, "SEL -> F2FP.UNPACK r1"),
    "imad_f2fpu": ("IMAD R6, R4, 0x101, RZ ;", "F2FP.F16.E4M3.UNPACK_B R8, R6 ;", "R8", False, "IMAD -> F2FP.UNPACK r1"),
    "f2fpu_hadd": ("F2FP.F16.E4M3.UNPACK_B R6, R4 ;", "HADD2.F32 R8, -RZ, R6.H0_H0 ;", "R8", False, "F2FP.UNPACK -> HADD2.F32 r2"),
    "f2fpu_hmul": ("F2FP.BF16.E8.UNPACK_B R6, R4 ;", "HMUL2.BF16_V2 R8, R5, R6 ;", "R8", False, "F2FP.UNPACK -> HMUL2 r2"),
    "hadd_f2fpp_a": ("HADD2.F32 R6, -RZ, R4.H0_H0 ;", "F2FP.BF16.F32.PACK_AB R8, R6, R5 ;", "R8", False, "HADD2.F32 -> F2FP.PACK r1"),
    "hadd_f2fpp_b": ("HADD2.F32 R6, -RZ, R4.H0_H0 ;", "F2FP.BF16.F32.PACK_AB R8, R5, R6 ;", "R8", False, "HADD2.F32 -> F2FP.PACK r2"),
    "f2fpp_hmul": ("F2FP.BF16.F32.PACK_AB R6, R4, R5 ;", "HMUL2.BF16_V2 R8, R6, R5 ;", "R8", False, "F2FP.PACK -> HMUL2 r1"),
    "fmul_f2fpp": ("FMUL.FTZ R6, R4, R5 ;", "F2FP.BF16.F32.PACK_AB R8, R5, R6 ;", "R8", False, "FMUL -> F2FP.PACK r2"),
    # ---- fp32 (softmax / epilogue chains)
    "fmul_fadd": ("FMUL.FTZ R6, R4, R5 ;", "FADD.FTZ R8, R6, R5 ;", "R8", False, "FMUL -> FADD r1"),
    "fadd_fadd": ("FADD.FTZ R6, R4, R5 ;", "FADD.FTZ R8, R6, R5 ;", "R8", False, "FADD -> FADD r1"),
    "fadd_fmul": ("FADD.FTZ R6, R4, R5 ;", "FMUL.FTZ R8, R6, R5 ;", "R8", False, "FADD -> FMUL r1"),
    "ffma_fadd": ("FFMA.FTZ R6, R4, R5, R4 ;", "FADD.FTZ R8, R6, R5 ;", "R8", False, "FFMA -> FADD r1"),
    "fmul_fsel": ("FMUL.FTZ R6, R4, R5 ;", "FSEL R8, R6, R5, P2 ;", "R8", False, "FMUL -> FSEL r1"),
    "fmul_fmnmx": ("FMUL.FTZ R6, R4, R5 ;", "FMNMX.FTZ R8, R6, R5, !PT ;", "R8", False, "FMUL -> FMNMX r1"),
    "fmnmx_fmnmx": ("FMNMX.FTZ R6, R4, R5, !PT ;", "FMNMX.FTZ R8, R6, R5, !PT ;", "R8", False, "FMNMX -> FMNMX r1"),
    "fsel_fmul": ("FSEL R6, R4, R5, P2 ;", "FMUL.FTZ R8, R6, R5 ;", "R8", False, "FSEL -> FMUL r1"),
    "fsel_fmnmx": ("FSEL R6, R4, R5, P2 ;", "FMNMX.FTZ R8, R6, R5, !PT ;", "R8", False, "FSEL -> FMNMX r1"),
    "fadd_fsel": ("FADD.FTZ R6, R4, R5 ;", "FSEL R8, R6, R5, P2 ;", "R8", False, "FADD -> FSEL r1"),
    "mov_fsel_f": ("MOV R6, R4 ;", "FSEL R8, R5, R6, P3 ;", "R8", False, "MOV -> FSEL r2"),
    "fadd_mufu": ("FADD.FTZ R6, R4, R5 ;", "MUFU.EX2 R8, R6 ;", "R8", True, "FADD -> MUFU r1"),
    # ---- predicates: into a select (5 by the census) and into a guard (13)
    "isetp_sel": ("ISETP.LT.U32.AND P0, PT, R4, R5, PT ;", "SEL R8, R4, R5, P0 ;", "R8", False, "ISETP -> SEL p"),
    "isetp_fsel": ("ISETP.LT.U32.AND P0, PT, R4, R5, PT ;", "FSEL R8, R4, R5, P0 ;", "R8", False, "ISETP -> FSEL p"),
    "fsetp_fsel": ("FSETP.GT.FTZ.AND P0, PT, R4, R5, PT ;", "FSEL R8, R4, R5, P0 ;", "R8", False, "FSETP -> FSEL p"),
    "fsetp_sel": ("FSETP.GT.FTZ.AND P0, PT, R4, R5, PT ;", "SEL R8, R4, R5, P0 ;", "R8", False, "FSETP -> SEL p"),
    "isetp_guard": ("ISETP.LT.U32.AND P0, PT, R4, R5, PT ;", "@P0 IADD3 R8, PT, PT, R4, R5, RZ ;", "R8", False, "ISETP -> IADD3 g"),
    "fsetp_guard": ("FSETP.GT.FTZ.AND P0, PT, R4, R5, PT ;", "@P0 IADD3 R8, PT, PT, R4, R5, RZ ;", "R8", False, "FSETP -> IADD3 g"),
    "isetp_isetp": ("ISETP.LT.U32.AND P0, PT, R4, R5, PT ;", "ISETP.NE.U32.OR P4, PT, R5, RZ, P0 ;", "P4", False, "ISETP -> ISETP p"),
}
# pairs also measured with the yield flag on the producer's stall (does yield change what a stall guarantees?)
YIELD_PAIRS = ("iadd3_iadd3", "imad_iadd3", "fmul_fadd", "f2fpu_hadd", "isetp_sel", "isetp_guard")


def kernel_text(name, pair, d, s, y=False, reference=False):
    prod, cons, eff, cons_barrier, _cell = PAIRS[pair]
    if reference:
        prod_ctrl = "[B------:R-:W-:-:S15]"
    else:
        prod_ctrl = f"[B------:R-:W-:{'Y' if y else '-'}:S{s:02d}]"
    cons_ctrl = f"[B------:R-:W{'1' if cons_barrier else '-'}:-:S15]"
    fold_wait = "B-1----" if cons_barrier else "B------"
    body = [f"    {prod_ctrl} {prod}"]
    body += [f"    {NOP_FILL}"] * (0 if reference else d)
    body.append(f"    {cons_ctrl} {cons}")
    if eff.startswith("P"):
        # a predicate effect: materialise it far behind the consumer (S15 = above the guard latency)
        body.append(f"    {SAFE} SEL R8, R4, R5, {eff} ;")
        eff = "R8"
    body.append(f"    [{fold_wait}:R-:W-:-:S15] IADD3 R10, PT, PT, R10, {eff}, RZ ;")
    body.append(f"    {SAFE} IADD3 R4, PT, PT, R4, 0x9e3779b9, RZ ;")
    body.append(f"    {SAFE} IADD3 R5, PT, PT, R5, 0x7f4a7c15, RZ ;")
    lines = [f".entry {name}", "    .reg R0-R20", "    .regcount 32", "    .param ptr out", "    .param u32 seed",
             "    [B------:R-:W0:-:S01] LDCU.64 UR4, c[0x0][0x358] ;",
             "    [B------:R-:W1:-:S01] S2R R0, SR_TID.X ;",
             "    [B------:R-:W2:-:S01] S2R R1, SR_CTAID.X ;",
             "    [B------:R-:W3:-:S01] LDC.64 R2, c[0x0][0x380] ;",
             "    [B------:R-:W4:-:S01] LDC R4, c[0x0][0x388] ;",
             "    [B01234-:R-:W-:-:S15] IMAD R1, R1, 0x400, R0 ;",
             f"    {SAFE} MOV R12, R1 ;",
             f"    {SAFE} IADD3 R4, PT, PT, R4, R12, RZ ;",
             f"    {SAFE} LOP3.LUT R5, R12, 0x5bd1e995, RZ, 0x3c, !PT ;",
             f"    {SAFE} MOV R6, RZ ;", f"    {SAFE} MOV R7, RZ ;", f"    {SAFE} MOV R8, RZ ;", f"    {SAFE} MOV R9, RZ ;",
             f"    {SAFE} MOV R10, RZ ;", f"    {SAFE} MOV R11, RZ ;", f"    {SAFE} MOV R15, RZ ;",
             f"    {SAFE} ISETP.LT.U32.AND P0, PT, RZ, RZ, PT ;",
             f"    {SAFE} ISETP.EQ.U32.AND P2, PT, RZ, RZ, PT ;",             # P2 = true
             f"    {SAFE} ISETP.LT.U32.AND P3, PT, RZ, RZ, PT ;",             # P3 = false
             f"    {SAFE} ISETP.LT.U32.AND P4, PT, RZ, RZ, PT ;",
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
    ap.add_argument("--pairs", default=",".join(PAIRS))
    ap.add_argument("--stalls", default="1,2,3,4,5,6,7,8")
    ap.add_argument("--guard-stalls", default="1,2,3,4,5,6,7,8,9,10,11,12,13,14,15")
    ap.add_argument("--distances", default="0,1,2")
    ap.add_argument("--jobs", type=int, default=16)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    jobs = []
    for pair in args.pairs.split(","):
        cell = PAIRS[pair][4]
        guard = cell.endswith(" g")
        stalls = [int(x) for x in (args.guard_stalls if guard else args.stalls).split(",")]
        jobs.append((f"pf_{pair}_ref", kernel_text(f"pf_{pair}_ref", pair, 0, 15, reference=True),
                     {"pair": pair, "cell": cell, "distance": -1, "stall": -1, "yield": False, "reference": True}))
        for d in map(int, args.distances.split(",")):
            for s in stalls:
                name = f"pf_{pair}_d{d}_s{s:02d}"
                jobs.append((name, kernel_text(name, pair, d, s),
                             {"pair": pair, "cell": cell, "distance": d, "stall": s, "yield": False, "reference": False}))
        if pair in YIELD_PAIRS:
            for s in [x for x in stalls if x <= 11]:
                name = f"pf_{pair}_d0_s{s:02d}y"
                jobs.append((name, kernel_text(name, pair, 0, s, y=True),
                             {"pair": pair + "+Y", "cell": cell + " (yield on the stall)", "distance": 0, "stall": s, "yield": True,
                              "reference": False, "ref_pair": pair}))

    def build(job):
        name, text, meta = job
        src = args.out / f"{name}.sass"
        src.write_text(text)
        cubin = args.out / f"{name}.cubin"
        r = subprocess.run([args.cubit, "asm", "-t", args.table, str(src), "-o", str(cubin)], capture_output=True, text=True)
        if r.returncode or not cubin.is_file():
            return None, (name, (r.stderr or r.stdout).strip().splitlines()[-1][:200])
        return dict(name=name, cubin=cubin.name, repeat=REPEAT, **meta), None

    index, failed = [], []
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as ex:
        for ok, bad in ex.map(build, jobs):
            if ok:
                index.append(ok)
            else:
                failed.append(bad)
    (args.out / "index.json").write_text(json.dumps(index, indent=1) + "\n")
    print(f"{len(index)} kernels assembled into {args.out}, {len(failed)} failed")
    for name, err in failed[:20]:
        print("  FAILED", name, err)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
