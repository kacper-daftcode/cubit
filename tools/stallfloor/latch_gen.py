#!/usr/bin/env python3
"""SM120 store-latch probe (harness v5 skeleton), CPU side: from which issue distance may a BARE store's operand
registers be overwritten? (cubit never covers a store by distance: its allocator sets a read barrier and the overwriter
waits; ptxas overwrites a bare store's registers from 20 issue cycles on. The open half of the scheduler-vs-ptxas list.)

Per kernel, 256 iterations per thread:
    data  = a + b                              (S15)
    STORE [slot A], data                       bare: no read barrier; stall S, then NPAD fillers of S15
    OVERWRITE                                  the tested instruction, S + 15 * NPAD issue cycles behind the store:
        *_d   the data register                (LOP3 data ^= const)
        *_a   the address register             (:= the thread's second slot B -- valid and private, so a store that
                                                latched its address late lands in B, never outside the buffers)
    LOAD  r <- [slot A]   (write barrier 0, waited by the fold)        checksum += r
Kinds: `stg` (STG.E, a private word of the output buffer per thread; B = the same word of the buffer's second half),
`sts` (STS, the thread's 16 bytes of shared memory), `sts128` (STS.128: the LAST of the four data registers is
overwritten). Controls, same timing: `ctl_*` = NO overwriter (an unrelated instruction in its place: a mismatch there
is the store -> load order, not the latch), `rb_*` = the store carries a read barrier and the overwriter waits on it
(the scheduler's protection: must be clean at every distance). Reference per (kind, geometry): the overwriter REF_PADS
fillers behind the store.
Geometries (CTAs x threads per CTA): g32 = 32 x 1 024 (32 warps on each of 32 SMs), g376 = 376 x 1 024 (2 CTAs on every
SM of a 188-SM device: 64 warps per SM, the occupancy the 2026-06 store race was seen at), w188 = 188 x 32 (one warp
per SM: no other warp competes for the memory pipe), w2 / w4 / w8 / w16 / w32 = 188 x 64 ... 1 024 (2 ... 32 warps on
every SM: how the latch delay grows with the number of warps storing at once).

    python3 latch_gen.py --cubit <cubit> --table <sm120.json> --out kernels_latch/
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import pathlib
import subprocess

SAFE = "[B------:R-:W-:-:S15]"
PAD15 = "[B------:R-:W-:-:S15] IADD3 R15, PT, PT, R15, 0x1, RZ ;"
REPEAT = 256
THREADS = 1024
GEOM = {"g32": (32, 1024), "g376": (376, 1024), "w188": (188, 32),
        # the load series: 188 CTAs (one per SM of a 188-SM device) x 2 / 4 / 8 / 16 / 32 warps
        "w2": (188, 64), "w4": (188, 128), "w8": (188, 256), "w16": (188, 512), "w32": (188, 1024)}
REF_PADS = 6


def skeleton(name, body, *, smem=0, prologue=()):
    lines = [f".entry {name}", "    .reg R0-R29", "    .regcount 32", "    .param ptr out", "    .param u32 seed"]
    if smem:
        lines.append(f"    .shared smem[{smem}]")
    lines += ["    [B------:R-:W0:-:S04] LDCU.64 UR4, c[0x0][0x358] ;",
              "    [B------:R-:W1:-:S04] S2R R0, SR_TID.X ;",
              "    [B------:R-:W2:-:S04] S2R R1, SR_CTAID.X ;",
              "    [B------:R-:W3:-:S04] LDC.64 R2, c[0x0][0x380] ;",
              "    [B------:R-:W4:-:S08] LDC R4, c[0x0][0x388] ;",
              "    [B01234-:R-:W-:-:S15] IMAD R1, R1, 0x400, R0 ;",              # global thread id
              f"    {SAFE} MOV R12, R1 ;",
              f"    {SAFE} IADD3 R4, PT, PT, R4, R12, RZ ;",
              f"    {SAFE} LOP3.LUT R5, R12, 0x5bd1e995, RZ, 0x3c, !PT ;",
              f"    {SAFE} MOV R6, RZ ;", f"    {SAFE} MOV R7, RZ ;", f"    {SAFE} MOV R8, RZ ;",
              f"    {SAFE} MOV R10, RZ ;", f"    {SAFE} MOV R11, RZ ;", f"    {SAFE} MOV R15, RZ ;",
              f"    {SAFE} IMAD R9, R0, 0x10, RZ ;"]                             # smem base of the thread: tid * 16
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


def latch_text(name, kind, ctas, s, npad, reference=False):
    # (the output buffer always holds 1 024 words per CTA: the global thread id is ctaid * 1024 + tid)
    st = 15 if reference else s
    pads = [PAD15] * (REF_PADS if reference else npad)
    base = kind.split("_", 1)[1] if kind.startswith(("ctl_", "rb_")) else kind      # the store form under test
    ctl, rb = kind.startswith("ctl_"), kind.startswith("rb_")
    assert not rb or base.endswith("_d"), "rb_* exists for the data kinds only (their overwriter can carry the wait)"
    half = THREADS * ctas * 4                      # bytes of the output buffer's first half (one word per thread)
    store = f"[B------:R{'1' if rb else '-'}:W-:-:S{st:02d}]"
    over = "[B-1----:R-:W-:-:S15]" if rb else SAFE                # the overwriter (waits the store's read barrier in rb_*)
    load = "[B------:R-:W0:-:S15]"
    fold = "[B0-----:R-:W-:-:S15] IADD3 R10, PT, PT, R10, R8, RZ ;"
    pro, smem = [], 0
    body = [f"{SAFE} IADD3 R6, PT, PT, R4, R5, RZ ;"]            # the data of this iteration
    if base.startswith("stg"):
        pro = [f"{SAFE} IMAD.WIDE.U32 R16, R1, 0x4, R2 ;",        # A = &out[gid]
               f"{SAFE} MOV R14, 0x{half:x} ;",
               f"{SAFE} IMAD.WIDE.U32 R18, R14, 0x1, R16 ;"]      # B = A + half
        if base == "stg_d":
            body.append(f"{store} STG.E desc[UR4][R16.64], R6 ;")
            body += pads
            body.append(PAD15 if ctl else f"{over} LOP3.LUT R6, R6, 0x5a5a5a5a, RZ, 0x3c, !PT ;")
        else:                                                      # stg_a
            body += [f"{SAFE} MOV R20, R16 ;", f"{SAFE} MOV R21, R17 ;"]
            body.append(f"{store} STG.E desc[UR4][R20.64], R6 ;")
            body += pads
            body += [PAD15, PAD15] if ctl else [f"{over} MOV R20, R18 ;", f"{SAFE} MOV R21, R19 ;"]
        body.append(f"{load} LDG.E R8, desc[UR4][R16.64] ;")
    else:
        smem = 16384
        if base == "sts_d":
            body.append(f"{store} STS [R9], R6 ;")
            body += pads
            body.append(PAD15 if ctl else f"{over} LOP3.LUT R6, R6, 0x5a5a5a5a, RZ, 0x3c, !PT ;")
            body.append(f"{load} LDS R8, [R9] ;")
        elif base == "sts_a":
            body.append(f"{SAFE} MOV R20, R9 ;")
            body.append(f"{store} STS [R20], R6 ;")
            body += pads
            body.append(PAD15 if ctl else f"{SAFE} IADD3 R20, PT, PT, R9, 0x4, RZ ;")
            body.append(f"{load} LDS R8, [R9] ;")
        else:                                                      # sts128_d: the last of the four data registers
            body += [f"{SAFE} MOV R24, R6 ;", f"{SAFE} MOV R25, R4 ;", f"{SAFE} MOV R26, R5 ;",
                     f"{SAFE} LOP3.LUT R27, R6, 0x33cc33cc, RZ, 0x3c, !PT ;"]
            body.append(f"{store} STS.128 [R9], R24 ;")
            body += pads
            body.append(PAD15 if ctl else f"{over} LOP3.LUT R27, R27, 0x5a5a5a5a, RZ, 0x3c, !PT ;")
            body.append(f"{load} LDS R8, [R9+0xc] ;")
    body.append(fold)
    return skeleton(name, body, smem=smem, prologue=pro)


CELL = {"stg_d": "STG data register overwritten", "stg_a": "STG address register overwritten",
        "sts_d": "STS data register overwritten", "sts_a": "STS address register overwritten",
        "sts128_d": "STS.128 last data register overwritten"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cubit", required=True)
    ap.add_argument("--table", required=True)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--jobs", type=int, default=16)
    ap.add_argument("--kinds", default="stg_d,stg_a,sts_d,sts_a,sts128_d")
    ap.add_argument("--geoms", default="g32,g376")
    ap.add_argument("--pads", type=int, default=3, help="fillers 0 .. pads-1 of 15 cycles each (distance S + 15 * k)")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    jobs = []
    kinds = [k for k in args.kinds.split(",") if k]
    for g in [x for x in args.geoms.split(",") if x]:
        ctas, threads = GEOM[g]
        for kind in kinds:
            basek = kind.split("_", 1)[1] if kind.startswith(("ctl_", "rb_")) else kind
            cell = CELL[basek]
            if kind.startswith("ctl_"):
                cell = cell.replace("overwritten", "NOT overwritten (control)").replace("register ", "")
            if kind.startswith("rb_"):
                cell += " behind the store's read barrier"
            pair = f"latch_{kind}_{g}"
            scale = 2 if basek.startswith("stg") else 1
            common = dict(ctas=ctas, threads=threads, out_scale=scale)
            jobs.append((f"lt_{kind}_{g}_ref", latch_text(f"lt_{kind}_{g}_ref", kind, ctas, 15, 0, True),
                         dict(pair=pair, cell=f"{cell} ({ctas} CTAs x {threads})", distance=-1, stall=-1, reference=True, **common)))
            for npad in range(args.pads):
                for s in range(1, 16):
                    nm = f"lt_{kind}_{g}_p{npad}_s{s:02d}"
                    jobs.append((nm, latch_text(nm, kind, ctas, s, npad),
                                 dict(pair=pair + f"/pad{npad}", cell=f"{cell} ({ctas} CTAs x {threads}; distance = S + {15 * npad})",
                                      distance=npad, stall=s, reference=False, ref_pair=pair, **common)))

    def build(job):
        name, text, meta = job
        src = args.out / f"{name}.sass"
        src.write_text(text)
        cubin = args.out / f"{name}.cubin"
        r = subprocess.run([args.cubit, "asm", "-t", args.table, str(src), "-o", str(cubin)], capture_output=True, text=True)
        if r.returncode or not cubin.is_file():
            return None, (name, (r.stderr or r.stdout).strip().splitlines()[-1][:300])
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
