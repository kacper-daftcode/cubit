#!/usr/bin/env python3
"""SM120 pair stall-floor harness v5c, CPU side: the cells of the dependency-latency table that the attention kernel's
candidate binds on and that had no silicon run -- address operands, -> SHFL, STG data, guards of memory instructions,
the high half of an IMAD.WIDE addend. Skeleton, oracle and index layout of pairfloor_gen_b.py.

What v5b got wrong and v5c does differently (both lessons are silicon results of 2026-11-10):
  * a stale ADDRESS must still be an address: every address register is initialised with a valid address of the
    thread's own slot / of the table before the loop, and the index never lives in a register of the address pair
    (v5b's IMAD.WIDE -> LDG probe kept the index in the high half of the address pair: a stale read faulted);
  * a bare store's operand registers are never rewritten behind it (the store latch: a bare store reads its operands
    when the memory pipe serves it): set-up stores use registers that are never written again, tested stores carry a
    read barrier that the fold waits on;
  * indices come from the LOW bits of the per-thread input (v5b took the top bits: nearly the same sequence in every
    thread, 9 distinct checksums in 32 768 threads).

    python3 pairfloor_gen_c.py --cubit <cubit> --table <sm120.json> --out kernels_pair_c/ [--pairs a,b]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import pathlib
import subprocess

import pairfloor_gen_b as B

SAFE, FILL = B.SAFE, B.FILL
W1 = "[B------:R-:W1:-:S15]"
RB2 = "[B------:R2:W-:-:S15]"            # a store with read barrier 2
FOLD = "IADD3 R10, PT, PT, R10, R8, RZ ;"
MIX = "LOP3.LUT R13, R12, 0x6b43a9b5, RZ, 0x3c, !PT ;"      # a per-thread word (R12 = the global thread id)
OUTW = "IMAD.WIDE.U32 R18, R1, 0x4, R2 ;"                    # R18:R19 = the thread's private word of the output buffer

# The store under test and the read-back of the thread's four words, POSITION-WEIGHTED (w0 + 3 w1 + 5 w2 + 7 w3): a store
# that always lands one word late leaves the same four values in the slot, one position off -- a plain sum cannot see
# it (the first version of this probe: "clean at S01", void).
STS_READBACK = [f"{RB2} STS [R6], R4 ;", f"{W1} LDS R8, [R9] ;", "[B------:R-:W3:-:S15] LDS R13, [R9+0x4] ;",
                "[B------:R-:W4:-:S15] LDS R14, [R9+0x8] ;", "[B------:R-:W5:-:S15] LDS R17, [R9+0xc] ;",
                "[B-12345:R-:W-:-:S15] IMAD R8, R13, 0x3, R8 ;", f"{SAFE} IMAD R8, R14, 0x5, R8 ;",
                f"{SAFE} IMAD R8, R17, 0x7, R8 ;"]

# name: dict(cell, prologue (S15 each), pre (S15 each, per iteration), prod, cons (lines with their control), fold wait,
#            optional: guard (stall sweep to 15), table (third kernel parameter), smem, regs)
PAIRS = {
    # ---- the high half of a 64-bit addend: R19 = high(R5 * 3 + R6:R7) sees R7 and the carry out of R6
    "imadw_imadw_ch": dict(cell="IMAD.WIDE -> IMAD.WIDE r3h", prologue=[], pre=[],
                           prod="IMAD.WIDE.U32 R6, R4, R5, RZ ;",
                           cons=[f"{SAFE} IMAD.WIDE.U32 R18, R5, 0x3, R6 ;", f"{SAFE} MOV R8, R19 ;"], wait="B------"),
    # ---- a default-priced pair of the candidate (second addend)
    "shf_iadd3_b": dict(cell="SHF -> IADD3 r2", prologue=[], pre=[],
                        prod="SHF.R.U32.HI R6, RZ, 0x3, R4 ;",
                        cons=[f"{SAFE} IADD3 R8, PT, PT, R5, R6, RZ ;"], wait="B------"),
    # ---- shared-memory address operands: four distinct words per thread, the index walks them (R4 & 3 steps by one)
    "imad_lds_a": dict(cell="IMAD -> LDS a1", smem=16384,
                       prologue=[f"{SAFE} {MIX}", f"{SAFE} IADD3 R14, PT, PT, R13, 0x1234567, RZ ;",
                                 f"{SAFE} IADD3 R17, PT, PT, R14, 0x1234567, RZ ;", f"{SAFE} IADD3 R18, PT, PT, R17, 0x1234567, RZ ;",
                                 f"{SAFE} STS [R9], R13 ;", f"{SAFE} STS [R9+0x4], R14 ;", f"{SAFE} STS [R9+0x8], R17 ;",
                                 f"{SAFE} STS [R9+0xc], R18 ;", f"{SAFE} MOV R6, R9 ;"],
                       pre=[f"{SAFE} LOP3.LUT R7, R4, 0x3, RZ, 0xc0, !PT ;"],
                       prod="IMAD R6, R7, 0x4, R9 ;", cons=[f"{W1} LDS R8, [R6] ;"], wait="B-1----"),
    "iadd3_lds_a": dict(cell="IADD3 -> LDS a1", smem=16384,
                        prologue=[f"{SAFE} {MIX}", f"{SAFE} IADD3 R14, PT, PT, R13, 0x1234567, RZ ;",
                                  f"{SAFE} IADD3 R17, PT, PT, R14, 0x1234567, RZ ;", f"{SAFE} IADD3 R18, PT, PT, R17, 0x1234567, RZ ;",
                                  f"{SAFE} STS [R9], R13 ;", f"{SAFE} STS [R9+0x4], R14 ;", f"{SAFE} STS [R9+0x8], R17 ;",
                                  f"{SAFE} STS [R9+0xc], R18 ;", f"{SAFE} MOV R6, R9 ;"],
                        pre=[f"{SAFE} LOP3.LUT R7, R4, 0x3, RZ, 0xc0, !PT ;", f"{SAFE} SHF.L.U32 R7, R7, 0x2, RZ ;"],
                        prod="IADD3 R6, PT, PT, R7, R9, RZ ;", cons=[f"{W1} LDS R8, [R6] ;"], wait="B-1----"),
    "imad_sts_a": dict(cell="IMAD -> STS a0", smem=16384,
                       prologue=[f"{SAFE} MOV R19, RZ ;", f"{SAFE} STS [R9], R19 ;", f"{SAFE} STS [R9+0x4], R19 ;",
                                 f"{SAFE} STS [R9+0x8], R19 ;", f"{SAFE} STS [R9+0xc], R19 ;", f"{SAFE} MOV R6, R9 ;"],
                       pre=[f"{SAFE} LOP3.LUT R7, R4, 0x3, RZ, 0xc0, !PT ;"],
                       prod="IMAD R6, R7, 0x4, R9 ;",
                       cons=STS_READBACK, wait="B------"),
    "iadd3_sts_a": dict(cell="IADD3 -> STS a0", smem=16384,
                        prologue=[f"{SAFE} MOV R19, RZ ;", f"{SAFE} STS [R9], R19 ;", f"{SAFE} STS [R9+0x4], R19 ;",
                                  f"{SAFE} STS [R9+0x8], R19 ;", f"{SAFE} STS [R9+0xc], R19 ;", f"{SAFE} MOV R6, R9 ;"],
                        pre=[f"{SAFE} LOP3.LUT R7, R4, 0x3, RZ, 0xc0, !PT ;", f"{SAFE} SHF.L.U32 R7, R7, 0x2, RZ ;"],
                        prod="IADD3 R6, PT, PT, R7, R9, RZ ;", cons=STS_READBACK, wait="B------"),
    # ---- a global address: 4 096 random words (third kernel parameter), the pair R6:R7 always holds a table address
    "imadw_ldg_a": dict(cell="IMAD.WIDE -> LDG a1", table=True,
                        prologue=[f"{SAFE} MOV R6, R16 ;", f"{SAFE} MOV R7, R17 ;"],
                        pre=[f"{SAFE} LOP3.LUT R13, R4, 0xfff, RZ, 0xc0, !PT ;"],
                        prod="IMAD.WIDE.U32 R6, R13, 0x4, R16 ;",
                        cons=[f"{W1} LDG.E R8, desc[UR4][R6.64] ;"], wait="B-1----"),
    # ---- -> SHFL (the lane's neighbour reads the fresh value)
    "fadd_shfl": dict(cell="FADD -> SHFL r1", prologue=[], pre=[], prod="FADD.FTZ R6, R4, R5 ;",
                      cons=[f"{W1} SHFL.BFLY PT, R8, R6, 0x1, 0x1f ;"], wait="B-1----"),
    "fmnmx_shfl": dict(cell="FMNMX -> SHFL r1", prologue=[], pre=[], prod="FMNMX.FTZ R6, R4, R5, !PT ;",
                       cons=[f"{W1} SHFL.BFLY PT, R8, R6, 0x1, 0x1f ;"], wait="B-1----"),
    # ---- STG data (the thread's private word of the output buffer; the store carries a read barrier)
    "f2fpp_stg_d": dict(cell="F2FP.PACK -> STG r1", prologue=[f"{SAFE} {OUTW}"], pre=[],
                        prod="F2FP.BF16.F32.PACK_AB R6, R4, R5 ;",
                        cons=[f"{RB2} STG.E desc[UR4][R18.64], R6 ;", f"{W1} LDG.E R8, desc[UR4][R18.64] ;"], wait="B-12---"),
    "fsel_stg_d": dict(cell="FSEL -> STG r1", prologue=[f"{SAFE} {OUTW}"], pre=[],
                       prod="FSEL R6, R4, R5, P2 ;",
                       cons=[f"{RB2} STG.E desc[UR4][R18.64], R6 ;", f"{W1} LDG.E R8, desc[UR4][R18.64] ;"], wait="B-12---"),
    # ---- the guard of a memory instruction (a stale guard stores / loads in the wrong iterations)
    "isetp_gsts": dict(cell="ISETP -> STS g", smem=16384, guard=True,
                       prologue=[f"{SAFE} MOV R19, RZ ;", f"{SAFE} STS [R9], R19 ;", f"{SAFE} ISETP.LT.U32.AND P0, PT, RZ, RZ, PT ;"], pre=[],
                       prod="ISETP.LT.U32.AND P0, PT, R4, R5, PT ;",
                       cons=[f"{RB2} @P0 STS [R9], R4 ;", f"{W1} LDS R8, [R9] ;"], wait="B-12---"),
    "isetp_gldg": dict(cell="ISETP -> LDG g", guard=True,
                       prologue=[f"{SAFE} {OUTW}", f"{SAFE} {MIX}", f"{SAFE} STG.E desc[UR4][R18.64], R13 ;",
                                 f"{SAFE} ISETP.LT.U32.AND P0, PT, RZ, RZ, PT ;"],
                       pre=[f"{SAFE} MOV R8, R5 ;"],
                       prod="ISETP.LT.U32.AND P0, PT, R4, R5, PT ;",
                       cons=[f"{W1} @P0 LDG.E R8, desc[UR4][R18.64] ;"], wait="B-1----"),
}


def text(name, pair, d, s, reference=False):
    p = PAIRS[pair]
    body = list(p["pre"])
    body.append(f"{B.ctrl(15 if reference else s)} {p['prod']}")
    body += [FILL] * (0 if reference else d)
    body += p["cons"]
    body.append(f"[{p['wait']}:R-:W-:-:S15] {FOLD}")
    return B.skeleton(name, body, regs=20, regcount=32, smem=p.get("smem", 0), table=p.get("table", False), prologue=p["prologue"])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cubit", required=True)
    ap.add_argument("--table", required=True)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--pairs", default=",".join(PAIRS))
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    jobs = []
    for pair in args.pairs.split(","):
        p = PAIRS[pair]
        meta = dict(pair=pair, cell=p["cell"], table=p.get("table", False))
        jobs.append((f"pf_{pair}_ref", text(f"pf_{pair}_ref", pair, 0, 15, True), dict(meta, distance=-1, stall=-1, reference=True)))
        for d in (0, 1, 2):
            for s in range(1, 16 if p.get("guard") else 9):
                nm = f"pf_{pair}_d{d}_s{s:02d}"
                jobs.append((nm, text(nm, pair, d, s), dict(meta, distance=d, stall=s, reference=False)))

    def build(job):
        name, t, meta = job
        src = args.out / f"{name}.sass"
        src.write_text(t)
        cubin = args.out / f"{name}.cubin"
        r = subprocess.run([args.cubit, "asm", "-t", args.table, str(src), "-o", str(cubin)], capture_output=True, text=True)
        if r.returncode or not cubin.is_file():
            return None, (name, (r.stderr or r.stdout).strip().splitlines()[-1][:300])
        return dict(name=name, cubin=cubin.name, repeat=B.REPEAT, **{"yield": False, **meta}), None

    index, failed = [], []
    with concurrent.futures.ThreadPoolExecutor(16) as ex:
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
