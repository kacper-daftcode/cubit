#!/usr/bin/env python3
"""SM120 pair stall-floor harness v5d, CPU side: the scaled BF16 unpack (`F2FP.BF16.<E4M3|E2M1>.UNPACK_B Rd, Rs[.sel],
Rscale.B0`, opcode 0x63e; class F2FP.UNPACK of the dependency table) as a producer and as a consumer -- the pairs a
dequant written with it is made of: its result -> the data of a store, -> the last register of STS.128, -> HMUL2 either
operand; SEL / SHF -> its source, MOV -> its scale register. Skeleton, oracle (an S15 reference per pair) and index
layout of pairfloor_gen_c.py; pairfloor_run.py reads the output.

    python3 pairfloor_gen_d.py --cubit <cubit> --table <sm120.json> --out kernels_pair_d/ [--pairs a,b]
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
RB2 = "[B------:R2:W-:-:S15]"
FOLD = "IADD3 R10, PT, PT, R10, R8, RZ ;"
# a UE8M0 scale byte 124..131 per iteration (R5 changes every iteration), and the unit scale code
SC = [f"{SAFE} LOP3.LUT R17, R5, 0x7, RZ, 0xc0, !PT ;", f"{SAFE} IADD3 R17, PT, PT, R17, 0x7c, RZ ;"]
ONE = f"{SAFE} MOV R18, 0x7f ;"


def unpack(fmt, rd, rs, rsc):
    return f"F2FP.BF16.{fmt}.UNPACK_B R{rd}, R{rs}, R{rsc}.B0 ;"


# name: dict(cell, prologue, pre, prod, cons (lines with their control), wait, smem)
PAIRS = {
    # ---- the unpack's result -> a store's data (an fp8 dequant: 8 unpacks, 2 x STS.128)
    "unp_sts_d": dict(cell="F2FP.UNPACK -> STS r1", smem=16384, prologue=[], pre=SC,
                      prod=unpack("E4M3", 6, 4, 17),
                      cons=[f"{RB2} STS [R9], R6 ;", f"{W1} LDS R8, [R9] ;"], wait="B-12---"),
    "unp_sts128_h": dict(cell="F2FP.UNPACK -> STS r1h", smem=16384, prologue=[],
                         pre=SC + [f"{SAFE} MOV R24, R4 ;", f"{SAFE} MOV R25, R5 ;", f"{SAFE} MOV R26, R4 ;"],
                         prod=unpack("E4M3", 27, 4, 17),
                         cons=[f"{RB2} STS.128 [R9], R24 ;", f"{W1} LDS R8, [R9+0xc] ;"], wait="B-12---"),
    # ---- -> HMUL2 (an fp4 dequant: value x block scale)
    "unp_hmul_a": dict(cell="F2FP.UNPACK -> HMUL2 r1", prologue=[ONE], pre=[],
                       prod=unpack("E2M1", 6, 4, 18),
                       cons=[f"{SAFE} HMUL2.BF16_V2 R8, R6, R5 ;"], wait="B------"),
    "unp_hmul_b": dict(cell="F2FP.UNPACK -> HMUL2 r2", prologue=[ONE], pre=[],
                       prod=unpack("E4M3", 6, 4, 18),
                       cons=[f"{SAFE} HMUL2.BF16_V2 R8, R5, R6.H0_H0 ;"], wait="B------"),
    # ---- producers of its operands
    "sel_unp": dict(cell="SEL -> F2FP.UNPACK r1", prologue=[ONE], pre=[],
                    prod="SEL R6, R4, R5, P2 ;", cons=[f"{SAFE} {unpack('E2M1', 8, 6, 18)}"], wait="B------"),
    "shf_unp": dict(cell="SHF -> F2FP.UNPACK r1", prologue=[ONE], pre=[],
                    prod="SHF.R.U32.HI R6, RZ, 0x8, R4 ;", cons=[f"{SAFE} {unpack('E2M1', 8, 6, 18)}"], wait="B------"),
    "mov_unp_sc": dict(cell="MOV -> F2FP.UNPACK r2", prologue=[f"{SAFE} MOV R17, 0x7f ;"],
                       pre=[f"{SAFE} LOP3.LUT R19, R5, 0x7, RZ, 0xc0, !PT ;", f"{SAFE} IADD3 R19, PT, PT, R19, 0x7c, RZ ;"],
                       prod="MOV R17, R19 ;", cons=[f"{SAFE} {unpack('E4M3', 8, 4, 17)}"], wait="B------"),
}


def text(name, pair, d, s, reference=False):
    p = PAIRS[pair]
    body = list(p["pre"])
    body.append(f"{B.ctrl(15 if reference else s)} {p['prod']}")
    body += [FILL] * (0 if reference else d)
    body += p["cons"]
    body.append(f"[{p['wait']}:R-:W-:-:S15] {FOLD}")
    return B.skeleton(name, body, regs=29, regcount=32, smem=p.get("smem", 0), prologue=p["prologue"])


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
        meta = dict(pair=pair, cell=p["cell"], table=False)
        jobs.append((f"pf_{pair}_ref", text(f"pf_{pair}_ref", pair, 0, 15, True), dict(meta, distance=-1, stall=-1, reference=True)))
        for d in (0, 1, 2):
            for s in range(1, 9):
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
