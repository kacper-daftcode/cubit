#!/usr/bin/env python3
"""SM120 pair stall-floor harness v5e, CPU side: the pairs the hand-written MoE GEMM kernels (2-bit / FP4 / quintal planes,
QMMA.SF) and the state-prefill kernel bind on under CUBIT_SCHED2_LAT that had no silicon run -- most of them priced with a
default of tables/dep_latency_sm120.json because the ptxas census has no dense cell for them, and every QMMA row (the
census miner sees no operand of the 7-operand QMMA.SF form, so the table's MMA rows were measured for HMMA only).
Skeleton, oracle and index layout of pairfloor_gen_b.py / pairfloor_gen_c.py (one S15 reference kernel per pair).

  alu     IMAD -> PRMT selector, PRMT -> LOP3, LOP3 -> PRMT selector (the LUT decode of the weight planes),
          SHF -> IMAD.WIDE multiplier, IMAD / SHF / MOV / IADD3 / IMAD.WIDE / IADD.64 -> IADD.64, SHF -> HADD2.F32
  mem     IADD.64 -> the address of STG (per-thread scratch words, position-weighted read-back) and of LDG (table);
          store data: SHF -> STS, FMUL -> STG, FFMA -> the upper register of STG.64
  uniform UIADD3 -> UISETP, UMOV -> UIADD3, R2UR -> UIADD3 (the uniform loop counters of the state-prefill kernel)
  guard   ISETP -> the guard of BRA and of EXIT
  qmma    QMMA result -> FFMA, -> the accumulate operand of the next QMMA, two QMMAs back to back
          (distance = S + 15 * NPAD, as the HMMA rows of v5b)
  input   MOV -> the accumulate operand of a QMMA (first register and an upper one), PRMT -> its B fragment,
          LOP3 -> its B scale byte, F2FP.PACK / LOP3 -> the upper register of an HMMA B fragment

    python3 pairfloor_gen_e.py --cubit <cubit> --table <sm120.json> --out kernels_pair_e/ [--pairs a,b]

Kernel parameters: out, seed, and for `table` / `scratch` kernels a third buffer (4 096 random words / 16 zeroed bytes
per thread -- pairfloor_run_e.py allocates them when the index entry says `table` / `scratch`).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import pathlib
import subprocess

import pairfloor_gen_b as B

SAFE, FILL, PAD15 = B.SAFE, B.FILL, B.PAD15
W1 = "[B------:R-:W1:-:S15]"
RB2 = "[B------:R2:W-:-:S15]"
FOLD = "IADD3 R10, PT, PT, R10, R8, RZ ;"
FOLD64 = "IADD3 R8, PT, PT, R18, R19, RZ ;"                    # both halves of a 64-bit result into the checksum
OUTW = "IMAD.WIDE.U32 R18, R1, 0x4, R2 ;"                      # R18:R19 = the thread's word of the output buffer
QMMA = "QMMA.SF.16832.F32.E4M3.E4M3.E8"

# name: dict(cell, prologue (S15 each), pre (S15 each, per iteration), prod, cons (lines with their control), wait,
#            optional: guard (stall sweep to 15), table, scratch, regs)
PAIRS = {
    # ---- the LUT decode of the weight planes
    "imad_prmt_sel": dict(cell="IMAD -> PRMT r2", prologue=[], pre=[],
                          prod="IMAD R6, R4, 0x40, R5 ;", cons=[f"{SAFE} PRMT R8, R5, R6, RZ ;"], wait="B------"),
    "prmt_lop3_b": dict(cell="PRMT -> LOP3 r2", prologue=[], pre=[],
                        prod="PRMT R6, R4, R5, RZ ;", cons=[f"{SAFE} LOP3.LUT R8, R5, R6, RZ, 0x3c, !PT ;"], wait="B------"),
    "lop3_prmt_sel": dict(cell="LOP3 -> PRMT r2", prologue=[], pre=[],
                          prod="LOP3.LUT R6, R4, 0x7777, RZ, 0xc0, !PT ;", cons=[f"{SAFE} PRMT R8, R5, R6, R4 ;"], wait="B------"),
    # ---- 64-bit address arithmetic
    "shf_imadw_b": dict(cell="SHF -> IMAD.WIDE r2", prologue=[f"{SAFE} MOV R13, RZ ;"], pre=[],
                        prod="SHF.L.U32 R6, R4, 0x2, RZ ;",
                        cons=[f"{SAFE} IMAD.WIDE.U32 R18, R5, R6, R12 ;", f"{SAFE} {FOLD64}"], wait="B------"),
    "imad_iadd64_a": dict(cell="IMAD -> IADD r1", prologue=[f"{SAFE} MOV R13, RZ ;"], pre=[],
                          prod="IMAD R6, R4, 0x2, R5 ;",
                          cons=[f"{SAFE} IADD.64 R18, R6, R12 ;", f"{SAFE} {FOLD64}"], wait="B------"),
    "shf_iadd64_b": dict(cell="SHF -> IADD r2", prologue=[f"{SAFE} MOV R13, RZ ;"], pre=[],
                         prod="SHF.L.U32 R6, R4, 0x4, RZ ;",
                         cons=[f"{SAFE} IADD.64 R18, R12, R6 ;", f"{SAFE} {FOLD64}"], wait="B------"),
    "iadd64_iadd64_a": dict(cell="IADD -> IADD r1", prologue=[f"{SAFE} MOV R13, RZ ;"], pre=[],
                            prod="IADD.64 R6, R4, R12 ;",
                            cons=[f"{SAFE} IADD.64 R18, R6, 0x1c0 ;", f"{SAFE} {FOLD64}"], wait="B------"),
    "shf_hadd2_b": dict(cell="SHF -> HADD2.F32 r2", prologue=[], pre=[],
                        prod="SHF.R.U32.HI R6, RZ, 0x10, R4 ;", cons=[f"{SAFE} HADD2.F32 R8, -RZ, R6.H0_H0 ;"], wait="B------"),
    # ---- a global store's address: four zeroed words per thread (third parameter), the index walks them; the pair
    #      R6:R7 always holds an address of the thread's words; the store carries a read barrier the fold waits on
    "iadd64_stg_a": dict(cell="IADD -> STG a0", scratch=16, regs=24,
                         prologue=[f"{SAFE} IMAD.WIDE.U32 R18, R1, 0x10, R16 ;", f"{SAFE} MOV R14, RZ ;",
                                   f"{SAFE} STG.E desc[UR4][R18.64], R14 ;", f"{SAFE} STG.E desc[UR4][R18.64+0x4], R14 ;",
                                   f"{SAFE} STG.E desc[UR4][R18.64+0x8], R14 ;", f"{SAFE} STG.E desc[UR4][R18.64+0xc], R14 ;",
                                   f"{SAFE} MOV R6, R18 ;", f"{SAFE} MOV R7, R19 ;", f"{SAFE} MOV R21, RZ ;"],
                         pre=[f"{SAFE} LOP3.LUT R20, R4, 0x3, RZ, 0xc0, !PT ;", f"{SAFE} SHF.L.U32 R20, R20, 0x2, RZ ;"],
                         prod="IADD.64 R6, R18, R20 ;",
                         cons=[f"{RB2} STG.E desc[UR4][R6.64], R4 ;", f"{W1} LDG.E R8, desc[UR4][R18.64] ;",
                               "[B------:R-:W3:-:S15] LDG.E R13, desc[UR4][R18.64+0x4] ;",
                               "[B------:R-:W4:-:S15] LDG.E R22, desc[UR4][R18.64+0x8] ;",
                               "[B------:R-:W5:-:S15] LDG.E R23, desc[UR4][R18.64+0xc] ;",
                               "[B-12345:R-:W-:-:S15] IMAD R8, R13, 0x3, R8 ;", f"{SAFE} IMAD R8, R22, 0x5, R8 ;",
                               f"{SAFE} IMAD R8, R23, 0x7, R8 ;"], wait="B------"),
    # ---- a global load's address: 4 096 random words (third parameter), R6:R7 always a table address
    "iadd64_ldg_a": dict(cell="IADD -> LDG a1", table=True, regs=24,
                         prologue=[f"{SAFE} MOV R6, R16 ;", f"{SAFE} MOV R7, R17 ;", f"{SAFE} MOV R21, RZ ;"],
                         pre=[f"{SAFE} LOP3.LUT R20, R4, 0xfff, RZ, 0xc0, !PT ;", f"{SAFE} SHF.L.U32 R20, R20, 0x2, RZ ;"],
                         prod="IADD.64 R6, R16, R20 ;",
                         cons=[f"{W1} LDG.E R8, desc[UR4][R6.64] ;"], wait="B-1----"),
    # ---- guards of control flow: a stale guard takes the other path / leaves one iteration late
    "isetp_gbra": dict(cell="ISETP -> BRA gc", guard=True, prologue=[f"{SAFE} ISETP.LT.U32.AND P0, PT, RZ, RZ, PT ;"], pre=[],
                       prod="ISETP.LT.U32.AND P0, PT, R4, R5, PT ;",
                       cons=[f"{SAFE} @P0 BRA L_skip ;", f"{SAFE} IADD3 R8, PT, PT, R8, R4, RZ ;", "L_skip:",
                             f"{SAFE} IADD3 R8, PT, PT, R8, 0x1, RZ ;"], wait="B------"),
    "isetp_gexit": dict(cell="ISETP -> EXIT gc", guard=True,
                        prologue=[f"{SAFE} {OUTW}", f"{SAFE} LOP3.LUT R13, R12, 0x3f, RZ, 0xc0, !PT ;",
                                  f"{SAFE} IADD3 R13, PT, PT, R13, 0x40, RZ ;", f"{SAFE} ISETP.LT.U32.AND P0, PT, RZ, RZ, PT ;"],
                        pre=[f"{RB2} STG.E desc[UR4][R18.64], R10 ;"],
                        prod="ISETP.EQ.U32.AND P0, PT, R11, R13, PT ;",
                        cons=["[B--2---:R-:W-:-:S15] @P0 EXIT ;", f"{SAFE} IADD3 R8, PT, PT, R4, R5, RZ ;"], wait="B--2---"),
    # ---- the remaining pairs of the state-prefill kernel (second set, same skeleton)
    "mov_iadd64_b": dict(cell="MOV -> IADD r2", prologue=[f"{SAFE} MOV R13, RZ ;"], pre=[],
                         prod="MOV R6, R4 ;", cons=[f"{SAFE} IADD.64 R18, R12, R6 ;", f"{SAFE} {FOLD64}"], wait="B------"),
    "iadd3_iadd64_b": dict(cell="IADD3 -> IADD r2", prologue=[f"{SAFE} MOV R13, RZ ;"], pre=[],
                           prod="IADD3 R6, PT, PT, R4, R5, RZ ;", cons=[f"{SAFE} IADD.64 R18, R12, R6 ;", f"{SAFE} {FOLD64}"], wait="B------"),
    "imad_iadd64_b": dict(cell="IMAD -> IADD r2", prologue=[f"{SAFE} MOV R13, RZ ;"], pre=[],
                          prod="IMAD R6, R4, 0x8, R5 ;", cons=[f"{SAFE} IADD.64 R18, R12, R6 ;", f"{SAFE} {FOLD64}"], wait="B------"),
    "imadw_iadd64_a": dict(cell="IMAD.WIDE -> IADD r1", prologue=[f"{SAFE} MOV R13, RZ ;"], pre=[],
                           prod="IMAD.WIDE.U32 R6, R4, 0x240, R12 ;", cons=[f"{SAFE} IADD.64 R18, R6, R12 ;", f"{SAFE} {FOLD64}"], wait="B------"),
    # store data: a shared store of a shifted word, a global store of an fp32 product, the upper register of a 64-bit
    # global store (per-thread scratch words); every tested store carries a read barrier the fold waits on
    "shf_sts_d": dict(cell="SHF -> STS r1", smem=16384, prologue=[], pre=[],
                      prod="SHF.L.U32 R6, R4, 0x17, RZ ;",
                      cons=[f"{RB2} STS [R9], R6 ;", f"{W1} LDS R8, [R9] ;"], wait="B-12---"),
    "fmul_stg_d": dict(cell="FMUL -> STG r1", prologue=[f"{SAFE} {OUTW}"], pre=[],
                       prod="FMUL.FTZ R6, R4, R5 ;",
                       cons=[f"{RB2} STG.E desc[UR4][R18.64], R6 ;", f"{W1} LDG.E R8, desc[UR4][R18.64] ;"], wait="B-12---"),
    "ffma_stg_dh": dict(cell="FFMA -> STG r1h", scratch=16,
                        prologue=[f"{SAFE} IMAD.WIDE.U32 R18, R1, 0x10, R16 ;", f"{SAFE} MOV R6, RZ ;"], pre=[],
                        prod="FFMA R7, R4, R5, R4 ;",
                        cons=[f"{RB2} STG.E.64 desc[UR4][R18.64], R6 ;", f"{W1} LDG.E R8, desc[UR4][R18.64+0x4] ;"], wait="B-12---"),
    # ---- uniform registers (the loop counters of the state-prefill kernel). Every thread of a warp computes the same
    #      values; the uniform predicate is materialised through a forward BRA.U (a stale value adds another iteration's
    #      word to the checksum -- no loop depends on the tested value)
    "uiadd3_uisetp": dict(cell="UIADD3 -> UISETP u0", uniform=True, prologue=[], pre=[],
                          prod="UIADD3 UR8, UPT, UPT, UR8, 0x1, URZ ;",
                          cons=[f"{SAFE} UISETP.NE.AND UP0, UPT, UR8, UR11, UPT ;", f"{SAFE} BRA.U UP0, L_skip ;",
                                f"{SAFE} IADD3 R8, PT, PT, R8, R4, RZ ;", "L_skip:", f"{SAFE} IADD3 R8, PT, PT, R8, 0x1, RZ ;"], wait="B------"),
    "umov_uiadd3": dict(cell="UMOV -> UIADD3 u1", uniform=True, prologue=[],
                        pre=[f"{SAFE} UIADD3 UR9, UPT, UPT, UR9, 0x1, URZ ;"],
                        prod="UMOV UR8, UR9 ;",
                        cons=[f"{SAFE} UIADD3 UR12, UPT, UPT, UR8, 0x5, URZ ;", f"{SAFE} UISETP.NE.AND UP0, UPT, UR12, UR11, UPT ;",
                              f"{SAFE} BRA.U UP0, L_skip ;", f"{SAFE} IADD3 R8, PT, PT, R8, R4, RZ ;", "L_skip:",
                              f"{SAFE} IADD3 R8, PT, PT, R8, 0x1, RZ ;"], wait="B------"),
    "r2ur_uiadd3": dict(cell="R2UR -> UIADD3 u1", uniform=True, guard=True, prologue=[], pre=[],
                        prod="R2UR UR8, R11 ;",
                        cons=[f"{SAFE} UIADD3 UR12, UPT, UPT, UR8, 0x5, URZ ;", f"{SAFE} UISETP.NE.AND UP0, UPT, UR12, UR11, UPT ;",
                              f"{SAFE} BRA.U UP0, L_skip ;", f"{SAFE} IADD3 R8, PT, PT, R8, R4, RZ ;", "L_skip:",
                              f"{SAFE} IADD3 R8, PT, PT, R8, 0x1, RZ ;"], wait="B------"),
}
UNIFORM_PROLOGUE = [f"{SAFE} UMOV UR8, 0x0 ;", f"{SAFE} UMOV UR9, 0x0 ;", f"{SAFE} UMOV UR11, 0x69 ;", f"{SAFE} UMOV UR12, 0x0 ;"]

# ---------------------------------------------------------------- QMMA
E4M3 = "0xfefefefe"                      # every byte a finite e4m3 code (0x7f / 0xff are the NaN codes)
QPRO = [f"{SAFE} UMOV UR6, 0x0 ;", f"{SAFE} MOV R26, 0x7f7f7f7f ;", f"{SAFE} MOV R27, 0x7f ;", f"{SAFE} MOV R14, 0x3f800000 ;",
        f"{SAFE} MOV R29, 0x4838b8c8 ;"]


def qfrag():
    """A fragment R20..R23 and B fragment R24 / R25 of this iteration: e4m3 bytes from the per-thread inputs."""
    return [f"{SAFE} LOP3.LUT R20, R4, {E4M3}, RZ, 0xc0, !PT ;", f"{SAFE} LOP3.LUT R21, R5, {E4M3}, RZ, 0xc0, !PT ;",
            f"{SAFE} LOP3.LUT R22, R4, R5, RZ, 0x3c, !PT ;", f"{SAFE} LOP3.LUT R22, R22, {E4M3}, RZ, 0xc0, !PT ;",
            f"{SAFE} LOP3.LUT R23, R5, 0x7e7e7e7e, RZ, 0xc0, !PT ;",
            f"{SAFE} LOP3.LUT R24, R4, 0x7c7c7c7c, RZ, 0xc0, !PT ;", f"{SAFE} LOP3.LUT R25, R5, {E4M3}, RZ, 0xc0, !PT ;"]


def qmma_text(name, pair, s, npad, reference=False):
    body = qfrag()
    pads = [PAD15] * (3 if reference else npad)
    st = 15 if reference else s
    if pair == "qmma_data":            # QMMA result -> FFMA (the fold of the MoE kernels: masters += acc * As)
        body.append(f"{B.ctrl(st)} {QMMA} R16, R20, R24, RZ, R26, R27, UR6 ;")
        body += pads
        body.append(f"{SAFE} FFMA R8, R16, R14, RZ ;")
        body.append(f"{SAFE} {FOLD}")
    elif pair == "qmma_acc":           # QMMA result -> the accumulate operand of the next QMMA
        body.append(f"{B.ctrl(st)} {QMMA} R16, R20, R24, RZ, R26, R27, UR6 ;")
        body += pads
        body.append(f"{SAFE} {QMMA} R16, R20, R24, R16, R26, R27, UR6 ;")
        body += [PAD15] * 3
        body.append(f"{SAFE} IADD3 R10, PT, PT, R10, R16, RZ ;")
        body.append(f"{SAFE} IADD3 R10, PT, PT, R10, R17, RZ ;")
    elif pair == "qmma_any":           # two independent QMMAs: both results must be right
        body.append(f"{B.ctrl(st)} {QMMA} R16, R20, R24, RZ, R26, R27, UR6 ;")
        body += pads
        body.append(f"{SAFE} {QMMA} R28, R20, R24, RZ, R26, R27, UR6 ;")
        body += [PAD15] * 3
        body.append(f"{SAFE} IADD3 R10, PT, PT, R10, R28, RZ ;")
        body.append(f"{SAFE} IADD3 R10, PT, PT, R10, R16, RZ ;")
        body.append(f"{SAFE} IADD3 R10, PT, PT, R10, R31, RZ ;")
    prologue = QPRO if pair != "qmma_any" else QPRO[:4]        # R29 is a result register of qmma_any
    return B.skeleton(name, body, regs=31, regcount=40, prologue=prologue)


# name: (cell, pre (S15, per iteration), producer, consumer)
FLOAT12 = [f"{SAFE} LOP3.LUT R13, R4, 0x007fffff, RZ, 0xc0, !PT ;", f"{SAFE} LOP3.LUT R13, R13, 0x3f800000, RZ, 0xfc, !PT ;"]
ZERO_ACC = [f"{SAFE} MOV R16, RZ ;", f"{SAFE} MOV R17, RZ ;", f"{SAFE} MOV R18, RZ ;", f"{SAFE} MOV R19, RZ ;"]
QIN = {
    "mov_qmma_acc": ("MOV -> QMMA r3", qfrag() + ZERO_ACC + FLOAT12, "MOV R16, R13 ;",
                     f"{QMMA} R16, R20, R24, R16, R26, R27, UR6 ;"),
    "mov_qmma_acch": ("MOV -> QMMA r3h", qfrag() + ZERO_ACC + FLOAT12, "MOV R17, R13 ;",
                      f"{QMMA} R16, R20, R24, R16, R26, R27, UR6 ;"),
    "prmt_qmma_b": ("PRMT -> QMMA r2", qfrag() + [f"{SAFE} LOP3.LUT R7, R4, 0x3333, RZ, 0xc0, !PT ;"], "PRMT R24, R29, R7, RZ ;",
                    f"{QMMA} R16, R20, R24, RZ, R26, R27, UR6 ;"),
    "lop3_qmma_sfb": ("LOP3 -> QMMA r5", qfrag() + [f"{SAFE} LOP3.LUT R7, R4, 0x3, RZ, 0xc0, !PT ;"],
                      "LOP3.LUT R27, R7, 0x7c, RZ, 0xfc, !PT ;", f"{QMMA} R16, R20, R24, RZ, R26, R27, UR6 ;"),
    # the upper register of an HMMA B fragment from a bf16 pack (the state-prefill kernel's inline dequant)
    "lop3_hmma_bh": ("LOP3 -> HMMA r2h",
                     sum((B.frag(r, s_) for r, s_ in ((20, 4), (21, 5), (22, 4), (23, 5), (24, 5), (25, 4))), []),
                     "LOP3.LUT R25, R25, 0x00010001, RZ, 0x3c, !PT ;", "HMMA.16816.F32.BF16 R16, R20, R24, RZ ;"),
    "f2fpp_hmma_bh": ("F2FP.PACK -> HMMA r2h",
                      sum((B.frag(r, s_) for r, s_ in ((20, 4), (21, 5), (22, 4), (23, 5), (24, 5))), [])
                      + FLOAT12 + [f"{SAFE} LOP3.LUT R7, R5, 0x007fffff, RZ, 0xc0, !PT ;", f"{SAFE} LOP3.LUT R7, R7, 0x3f800000, RZ, 0xfc, !PT ;"],
                      "F2FP.BF16.F32.PACK_AB R25, R13, R7 ;", "HMMA.16816.F32.BF16 R16, R20, R24, RZ ;"),
}


def qin_text(name, pair, d, s, reference=False):
    _cell, pre, prod, cons = QIN[pair]
    body = list(pre)
    body.append(f"{B.ctrl(15 if reference else s)} {prod}")
    body += [FILL] * (0 if reference else d)
    body.append(f"{SAFE} {cons}")
    body += [PAD15] * 3
    body.append(f"{SAFE} IADD3 R10, PT, PT, R10, R16, RZ ;")
    body.append(f"{SAFE} IADD3 R10, PT, PT, R10, R17, RZ ;")
    return B.skeleton(name, body, regs=31, regcount=40, prologue=QPRO)


def text(name, pair, d, s, reference=False):
    p = PAIRS[pair]
    body = list(p["pre"])
    body.append(f"{B.ctrl(15 if reference else s)} {p['prod']}")
    body += [FILL] * (0 if reference else d)
    body += p["cons"]
    body.append(f"[{p['wait']}:R-:W-:-:S15] {FOLD}")
    t = B.skeleton(name, body, regs=p.get("regs", 20), regcount=32, smem=p.get("smem", 0),
                   table=bool(p.get("table") or p.get("scratch")), prologue=(UNIFORM_PROLOGUE if p.get("uniform") else []) + p["prologue"])
    return t.replace("    L_skip:", "L_skip:")


def jobs_of(pairs):
    jobs = []
    for pair in pairs:
        if pair in PAIRS:
            p = PAIRS[pair]
            meta = dict(pair=pair, cell=p["cell"], table=bool(p.get("table")), scratch=p.get("scratch", 0))
            jobs.append((f"pf_{pair}_ref", text(f"pf_{pair}_ref", pair, 0, 15, True), dict(meta, distance=-1, stall=-1, reference=True)))
            for d in (0, 1, 2):
                for s in range(1, 16 if p.get("guard") else 9):
                    nm = f"pf_{pair}_d{d}_s{s:02d}"
                    jobs.append((nm, text(nm, pair, d, s), dict(meta, distance=d, stall=s, reference=False)))
        elif pair in ("qmma_data", "qmma_acc", "qmma_any"):
            cell = {"qmma_data": "QMMA -> FFMA r1", "qmma_acc": "QMMA -> QMMA r3", "qmma_any": "QMMA -> QMMA (issue spacing)"}[pair]
            jobs.append((f"pf_{pair}_ref", qmma_text(f"pf_{pair}_ref", pair, 15, 3, True),
                         dict(pair=pair, cell=cell, distance=-1, stall=-1, reference=True)))
            for npad in (0, 1):
                for s in range(1, 16):
                    nm = f"pf_{pair}_p{npad}_s{s:02d}"
                    jobs.append((nm, qmma_text(nm, pair, s, npad),
                                 dict(pair=pair + f"/pad{npad}", cell=cell + f" (distance = S + {15 * npad})", distance=npad, stall=s,
                                      reference=False, ref_pair=pair)))
        elif pair in QIN:
            cell = QIN[pair][0]
            jobs.append((f"pf_{pair}_ref", qin_text(f"pf_{pair}_ref", pair, 0, 15, True),
                         dict(pair=pair, cell=cell, distance=-1, stall=-1, reference=True)))
            for d in (0, 1, 2):
                for s in range(1, 10):
                    nm = f"pf_{pair}_d{d}_s{s:02d}"
                    jobs.append((nm, qin_text(nm, pair, d, s), dict(pair=pair, cell=cell, distance=d, stall=s, reference=False)))
        else:
            raise SystemExit(f"unknown pair {pair}")
    return jobs


ALL = list(PAIRS) + ["qmma_data", "qmma_acc", "qmma_any"] + list(QIN)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cubit", required=True)
    ap.add_argument("--table", required=True)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--pairs", default=",".join(ALL))
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    jobs = jobs_of(args.pairs.split(","))

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
    with concurrent.futures.ThreadPoolExecutor(12) as ex:
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
