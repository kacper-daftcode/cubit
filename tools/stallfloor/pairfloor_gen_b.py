#!/usr/bin/env python3
"""SM120 pair stall-floor harness v5b, CPU side: the kernels pairfloor_gen.py's skeleton does not cover.

  arm_*   scoreboard ARMING: a producer that sets write barrier 0 at stall S (with / without yield), its waiter d
          fillers behind it. A waiter that passes before the barrier is armed reads the stale register.
          (reference: the producer at S15, no yield.)
  mma_*   the warp-cooperative MMA: result -> FMUL (data), -> the accumulate operand of the next MMA, two independent
          MMAs back to back, LOP3 -> B fragment. The MMA's stall S plus NPAD fillers of S15 give the distance S + 15 * NPAD.
  mem_*   memory operands: IMAD -> LDS address, IMAD.WIDE -> LDG address, HMUL2 -> STS data, IADD3 -> STS address.

Same oracle as v5: one reference kernel per pair with the tested edge far above any latency; index.json in the layout
pairfloor_run.py reads (`table` = the kernel takes a third parameter, a 16-KB table of random words).

    python3 pairfloor_gen_b.py --cubit <cubit> --table <sm120.json> --out kernels_pair_b/
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import pathlib
import subprocess

SAFE = "[B------:R-:W-:-:S15]"
FILL = "[B------:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;"
PAD15 = "[B------:R-:W-:-:S15] IADD3 R15, PT, PT, R15, 0x1, RZ ;"
REPEAT = 256


def skeleton(name, body, *, regs=20, regcount=32, smem=0, table=False, prologue=()):
    lines = [f".entry {name}", f"    .reg R0-R{regs}", f"    .regcount {regcount}", "    .param ptr out", "    .param u32 seed"]
    if table:
        lines.append("    .param ptr tab")
    if smem:
        lines.append(f"    .shared smem[{smem}]")
    lines += ["    [B------:R-:W0:-:S04] LDCU.64 UR4, c[0x0][0x358] ;",
              "    [B------:R-:W1:-:S04] S2R R0, SR_TID.X ;",
              "    [B------:R-:W2:-:S04] S2R R1, SR_CTAID.X ;",
              "    [B------:R-:W3:-:S04] LDC.64 R2, c[0x0][0x380] ;",
              "    [B------:R-:W4:-:S08] LDC R4, c[0x0][0x388] ;"]
    if table:
        lines.append("    [B------:R-:W5:-:S08] LDC.64 R16, c[0x0][0x390] ;")
    lines += [f"    [B01234{'5' if table else '-'}:R-:W-:-:S15] IMAD R1, R1, 0x400, R0 ;",
              f"    {SAFE} MOV R12, R1 ;",
              f"    {SAFE} IADD3 R4, PT, PT, R4, R12, RZ ;",
              f"    {SAFE} LOP3.LUT R5, R12, 0x5bd1e995, RZ, 0x3c, !PT ;",
              f"    {SAFE} MOV R6, RZ ;", f"    {SAFE} MOV R7, RZ ;", f"    {SAFE} MOV R8, RZ ;",
              f"    {SAFE} MOV R10, RZ ;", f"    {SAFE} MOV R11, RZ ;", f"    {SAFE} MOV R15, RZ ;",
              f"    {SAFE} IMAD R9, R0, 0x10, RZ ;",                               # smem base of the thread: tid * 16
              f"    {SAFE} ISETP.EQ.U32.AND P2, PT, RZ, RZ, PT ;",
              f"    {SAFE} ISETP.LT.U32.AND P3, PT, RZ, RZ, PT ;"]
    lines += [f"    {l}" for l in prologue]
    lines.append("L_loop:")
    lines += [f"    {l}" for l in body]
    lines += [f"    {SAFE} IADD3 R4, PT, PT, R4, 0x9e3779b9, RZ ;",
              f"    {SAFE} IADD3 R5, PT, PT, R5, 0x7f4a7c15, RZ ;",
              f"    {SAFE} IADD3 R11, PT, PT, R11, 0x1, RZ ;",
              f"    {SAFE} ISETP.LT.U32.AND P1, PT, R11, 0x{REPEAT:x}, PT ;",
              f"    {SAFE} @P1 BRA L_loop ;",
              f"    {SAFE} IMAD.WIDE.U32 R2, R1, 0x4, R2 ;",
              f"    {SAFE} STG.E desc[UR4][R2.64], R10 ;",
              f"    {SAFE} EXIT ;", ".endentry", ""]
    return "\n".join(lines)


def ctrl(s, y=False, wb="-", wait="B------"):
    return f"[{wait}:R-:W{wb}:{'Y' if y else '-'}:S{s:02d}]"


# ------------------------------------------------------------------ scoreboard arming
ARM = {
    # name: (smem bytes, pre lines (S15, make the stale value differ), producer text, waiter text)
    "arm_mufu": (0, [], "MUFU.EX2 R6, R4 ;", "FADD.FTZ R8, R6, R5 ;"),
    "arm_shfl": (0, [], "SHFL.BFLY PT, R6, R4, 0x1, 0x1f ;", "IADD3 R8, PT, PT, R6, R5, RZ ;"),
    "arm_ldc": (0, [f"{SAFE} MOV R6, R4 ;"], "LDC R6, c[0x0][0x388] ;", "IADD3 R8, PT, PT, R6, R4, RZ ;"),
    "arm_lds": (16384, [f"{SAFE} STS [R9], R4 ;", f"{SAFE} MOV R6, R5 ;"], "LDS R6, [R9] ;", "IADD3 R8, PT, PT, R6, R5, RZ ;"),
}


def arm_text(name, pair, d, s, y, reference=False):
    smem, pre, prod, cons = ARM[pair]
    body = list(pre)
    body.append(f"{ctrl(15 if reference else s, False if reference else y, wb='0')} {prod}")
    body += [FILL] * (0 if reference else d)
    body.append(f"{ctrl(15, wait='B0-----')} {cons}")
    body.append(f"{SAFE} IADD3 R10, PT, PT, R10, R8, RZ ;")
    return skeleton(name, body, smem=smem)


# ------------------------------------------------------------------ MMA
def frag(reg, src):
    # two bf16 per register: random sign and mantissa, exponent of 1.0 (finite, moderate)
    return [f"{SAFE} LOP3.LUT R{reg}, R{src}, 0x807f807f, RZ, 0xc0, !PT ;",
            f"{SAFE} LOP3.LUT R{reg}, R{reg}, 0x3f803f80, RZ, 0xfc, !PT ;"]


def mma_text(name, pair, s, npad, reference=False):
    pre = []
    for reg, src in ((20, 4), (21, 5), (22, 4), (23, 5), (24, 5), (25, 4)):
        pre += frag(reg, src)
    body = list(pre)
    pads = [PAD15] * (3 if reference else npad)
    st = 15 if reference else s
    if pair == "mma_data":            # MMA result -> FMUL
        body.append(f"{ctrl(st)} HMMA.16816.F32.BF16 R16, R20, R24, RZ ;")
        body += pads
        body.append(f"{SAFE} FMUL.FTZ R8, R16, R5 ;")
        body.append(f"{SAFE} IADD3 R10, PT, PT, R10, R8, RZ ;")
    elif pair == "mma_acc":           # MMA result -> the accumulate operand of the next MMA
        body.append(f"{ctrl(st)} HMMA.16816.F32.BF16 R16, R20, R24, RZ ;")
        body += pads
        body.append(f"{SAFE} HMMA.16816.F32.BF16 R16, R20, R24, R16 ;")
        body += [PAD15] * 3
        body.append(f"{SAFE} IADD3 R10, PT, PT, R10, R16, RZ ;")
        body.append(f"{SAFE} IADD3 R10, PT, PT, R10, R17, RZ ;")
    elif pair == "mma_any":           # two independent MMAs: the second one's result must be right
        body.append(f"{ctrl(st)} HMMA.16816.F32.BF16 R16, R20, R24, RZ ;")
        body += pads
        body.append(f"{SAFE} HMMA.16816.F32.BF16 R28, R20, R24, RZ ;")
        body += [PAD15] * 3
        body.append(f"{SAFE} IADD3 R10, PT, PT, R10, R28, RZ ;")
        body.append(f"{SAFE} IADD3 R10, PT, PT, R10, R16, RZ ;")
        body.append(f"{SAFE} IADD3 R10, PT, PT, R10, R29, RZ ;")
    elif pair == "lop3_mma_b":        # ALU result -> B fragment of an MMA (the tested producer rewrites R24)
        body.append(f"{ctrl(st)} LOP3.LUT R24, R24, 0x00010001, RZ, 0x3c, !PT ;")
        body += pads
        body.append(f"{SAFE} HMMA.16816.F32.BF16 R16, R20, R24, RZ ;")
        body += [PAD15] * 3
        body.append(f"{SAFE} IADD3 R10, PT, PT, R10, R16, RZ ;")
    return skeleton(name, body, regs=31, regcount=40)


# ------------------------------------------------------------------ memory operands
MEM = {
    # name: (smem, table, prologue, pre (S15), producer, consumer incl. its control, fold wait, cell)
    "mem_imad_lds_a": (16384, False,
                       [f"{SAFE} LOP3.LUT R13, R12, 0x6b43a9b5, RZ, 0x3c, !PT ;", f"{SAFE} STS [R9], R13 ;",
                        f"{SAFE} IADD3 R13, PT, PT, R13, 0x1234567, RZ ;", f"{SAFE} STS [R9+0x4], R13 ;",
                        f"{SAFE} IADD3 R13, PT, PT, R13, 0x1234567, RZ ;", f"{SAFE} STS [R9+0x8], R13 ;",
                        f"{SAFE} IADD3 R13, PT, PT, R13, 0x1234567, RZ ;", f"{SAFE} STS [R9+0xc], R13 ;"],
                       [f"{SAFE} SHF.R.U32.HI R7, RZ, 0x1e, R4 ;"],
                       "IMAD R6, R7, 0x4, R9 ;", "[B------:R-:W1:-:S15] LDS R8, [R6] ;", "B-1----", "IMAD -> LDS a1"),
    "mem_imadw_ldg_a": (0, True, [],
                        [f"{SAFE} SHF.R.U32.HI R7, RZ, 0x14, R4 ;"],
                        "IMAD.WIDE.U32 R6, R7, 0x4, R16 ;", "[B------:R-:W1:-:S15] LDG.E R8, desc[UR4][R6.64] ;", "B-1----",
                        "IMAD.WIDE -> LDG a1"),
    "mem_hmul_sts_d": (16384, False, [], [],
                       "HMUL2.BF16_V2 R6, R4, R5 ;", f"{SAFE} STS [R9], R6 ;\n    [B------:R-:W1:-:S15] LDS R8, [R9] ;", "B-1----",
                       "HMUL2 -> STS r1"),
    "mem_iadd3_sts_a": (16384, False, [],
                        [f"{SAFE} SHF.R.U32.HI R7, RZ, 0x1e, R4 ;", f"{SAFE} SHF.L.U32 R7, R7, 0x2, RZ ;"],
                        "IADD3 R6, PT, PT, R7, R9, RZ ;",
                        f"{SAFE} STS [R6], R4 ;\n    [B------:R-:W1:-:S15] LDS R8, [R9] ;\n    [B-1----:R-:W1:-:S15] LDS R13, [R9+0x8] ;\n"
                        f"    [B-1----:R-:W-:-:S15] IADD3 R8, PT, PT, R8, R13, RZ ;", "B------", "IADD3 -> STS a0"),
}


def mem_text(name, pair, d, s, reference=False):
    smem, table, prologue, pre, prod, cons, fold_wait, _cell = MEM[pair]
    body = list(pre)
    body.append(f"{ctrl(15 if reference else s)} {prod}")
    body += [FILL] * (0 if reference else d)
    body += cons.split("\n    ")
    body.append(f"[{fold_wait}:R-:W-:-:S15] IADD3 R10, PT, PT, R10, R8, RZ ;")
    return skeleton(name, body, smem=smem, table=table, prologue=prologue)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cubit", required=True)
    ap.add_argument("--table", required=True)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--jobs", type=int, default=16)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    jobs = []
    for pair in ARM:
        cell = f"{pair[4:].upper()} [W0] -> waiter"
        jobs.append((f"pf_{pair}_ref", arm_text(f"pf_{pair}_ref", pair, 0, 15, False, True),
                     dict(pair=pair, cell=cell, distance=-1, stall=-1, reference=True)))
        for y in (False, True):
            for d in (0, 1, 2):
                for s in (1, 2, 3, 4, 5, 6):
                    nm = f"pf_{pair}_d{d}_s{s:02d}{'y' if y else ''}"
                    jobs.append((nm, arm_text(nm, pair, d, s, y),
                                 dict(pair=pair + ("+Y" if y else ""), cell=cell + (" (yield)" if y else ""), distance=d, stall=s,
                                      reference=False, ref_pair=pair)))
    for pair, cell in (("mma_data", "HMMA -> FMUL r1"), ("mma_acc", "HMMA -> HMMA r3"), ("mma_any", "HMMA -> HMMA (issue spacing)"),
                       ("lop3_mma_b", "LOP3 -> HMMA r2")):
        jobs.append((f"pf_{pair}_ref", mma_text(f"pf_{pair}_ref", pair, 15, 3, True),
                     dict(pair=pair, cell=cell, distance=-1, stall=-1, reference=True)))
        for npad in (0, 1):
            for s in range(1, 16):
                nm = f"pf_{pair}_p{npad}_s{s:02d}"
                jobs.append((nm, mma_text(nm, pair, s, npad),
                             dict(pair=pair + f"/pad{npad}", cell=cell + f" (distance = S + {15 * npad})", distance=npad, stall=s,
                                  reference=False, ref_pair=pair)))
    for pair, spec in MEM.items():
        cell = spec[7]
        jobs.append((f"pf_{pair}_ref", mem_text(f"pf_{pair}_ref", pair, 0, 15, True),
                     dict(pair=pair, cell=cell, distance=-1, stall=-1, reference=True, table=spec[1])))
        for d in (0, 1, 2):
            for s in range(1, 9):
                nm = f"pf_{pair}_d{d}_s{s:02d}"
                jobs.append((nm, mem_text(nm, pair, d, s),
                             dict(pair=pair, cell=cell, distance=d, stall=s, reference=False, table=spec[1])))

    def build(job):
        name, text, meta = job
        src = args.out / f"{name}.sass"
        src.write_text(text)
        cubin = args.out / f"{name}.cubin"
        r = subprocess.run([args.cubit, "asm", "-t", args.table, str(src), "-o", str(cubin)], capture_output=True, text=True)
        if r.returncode or not cubin.is_file():
            return None, (name, (r.stderr or r.stdout).strip().splitlines()[-1][:300])
        return dict(name=name, cubin=cubin.name, repeat=REPEAT, **{"yield": False, **meta}), None

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
