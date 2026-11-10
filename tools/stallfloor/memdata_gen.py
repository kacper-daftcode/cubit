#!/usr/bin/env python3
"""SM120 pair stall-floor harness v5b, more store-data pairs (the cells the attention kernel's candidate binds on):
producer -> the data operand of a shared-memory store, read back through the scoreboard. Same skeleton, oracle and index
layout as pairfloor_gen_b.py (`mem_hmul_sts_d` there measured HMUL2 -> STS data).

    python3 memdata_gen.py --cubit <cubit> --table <sm120.json> --out kernels_memdata/
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import pathlib
import subprocess

import pairfloor_gen_b as B

SAFE, FILL = B.SAFE, B.FILL
RD = "[B------:R-:W1:-:S15]"
# name: (pre lines (S15), producer, consumer lines, cell)
PAIRS = {
    "mem_f2fpp_sts_d": ([], "F2FP.BF16.F32.PACK_AB R6, R4, R5 ;", [f"{SAFE} STS [R9], R6 ;", f"{RD} LDS R8, [R9] ;"], "F2FP.PACK -> STS r1"),
    "mem_fadd_sts_d": ([], "FADD.FTZ R6, R4, R5 ;", [f"{SAFE} STS [R9], R6 ;", f"{RD} LDS R8, [R9] ;"], "FADD -> STS r1"),
    "mem_fsel_sts_d": ([], "FSEL R6, R4, R5, P2 ;", [f"{SAFE} STS [R9], R6 ;", f"{RD} LDS R8, [R9] ;"], "FSEL -> STS r1"),
    "mem_iadd3_sts_d": ([], "IADD3 R6, PT, PT, R4, R5, RZ ;", [f"{SAFE} STS [R9], R6 ;", f"{RD} LDS R8, [R9] ;"], "IADD3 -> STS r1"),
    # the LAST data register of a 128-bit store (role r1h): the producer rewrites R27 right in front of STS.128 [R9], R24
    "mem_hmul_sts128_h": ([f"{SAFE} MOV R24, R4 ;", f"{SAFE} MOV R25, R5 ;", f"{SAFE} MOV R26, R4 ;"],
                          "HMUL2.BF16_V2 R27, R4, R5 ;", [f"{SAFE} STS.128 [R9], R24 ;", f"{RD} LDS R8, [R9+0xc] ;"], "HMUL2 -> STS r1h"),
    "mem_f2fpp_sts128_h": ([f"{SAFE} MOV R24, R4 ;", f"{SAFE} MOV R25, R5 ;", f"{SAFE} MOV R26, R4 ;"],
                           "F2FP.BF16.F32.PACK_AB R27, R4, R5 ;", [f"{SAFE} STS.128 [R9], R24 ;", f"{RD} LDS R8, [R9+0xc] ;"], "F2FP.PACK -> STS r1h"),
}


def text(name, pair, d, s, reference=False):
    pre, prod, cons, _cell = PAIRS[pair]
    body = list(pre)
    body.append(f"{B.ctrl(15 if reference else s)} {prod}")
    body += [FILL] * (0 if reference else d)
    body += cons
    body.append("[B-1----:R-:W-:-:S15] IADD3 R10, PT, PT, R10, R8, RZ ;")
    return B.skeleton(name, body, regs=29, regcount=32, smem=16384)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cubit", required=True)
    ap.add_argument("--table", required=True)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    jobs = []
    for pair, spec in PAIRS.items():
        cell = spec[3]
        jobs.append((f"pf_{pair}_ref", text(f"pf_{pair}_ref", pair, 0, 15, True),
                     dict(pair=pair, cell=cell, distance=-1, stall=-1, reference=True)))
        for d in (0, 1, 2):
            for s in range(1, 9):
                nm = f"pf_{pair}_d{d}_s{s:02d}"
                jobs.append((nm, text(nm, pair, d, s), dict(pair=pair, cell=cell, distance=d, stall=s, reference=False)))

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
