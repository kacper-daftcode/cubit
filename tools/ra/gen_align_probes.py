#!/usr/bin/env python3
"""Probe kernels for the register grid of sm_120: which multi-register operand shapes need their base register on a
multiple of their width? One tiny kernel per (shape, base register): the on-grid base is the control, the off-grid
bases are the question. Vendor practice (ptxas, 1.8 M census instructions; align_census.py): never off the grid.

Every kernel: 1 CTA x 32 threads (one warp). Thread t reads the 16 bytes inp[16 t .. 16 t + 15] (4 words w0..w3), does
the shaped instruction and stores up to 8 words at out[32 t ..]. `expect` names what the 8 words must be; `ctl` = "the
same words as the control kernel of this shape" (LDSM: the control is the oracle).

    gen_align_probes.py <outdir>      -> <outdir>/<name>.sass + index.json;  assemble each with `cubit asm`
    probe_run.py <outdir>             -> on the GPU: OK / WRONG / FAULT per kernel

Footprint side results: `cs2r_*` shows whether CS2R writes one register or the pair; `ldsm2_*` whether .2 writes two.
Result of 2026-11-10 (RTX PRO 6000 Blackwell Server Edition): align_probes_sm120_20261110.json -- 15 of 15 controls
exact, 23 of 23 off-grid kernels end the launch with CUDA_ERROR_ILLEGAL_INSTRUCTION (715).
"""
import json
import os
import sys

PRO = """.entry {name}
    .reg R0-R31
    .param u64 out
    .param u64 inp
    S2R R0, SR_TID.X ;
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    LDC.64 R4, c[0x0][0x388] ;
    IMAD.WIDE.U32 R2, PT, R0, 0x20, R2 ;
    IMAD.WIDE.U32 R4, PT, R0, 0x10, R4 ;
    IMAD R1, R0, 0x10, RZ ;
"""
EPI = "    EXIT ;\n.endentry\n"


def store(regs, off=0):
    return "".join(f"    STG.E desc[UR4][R2.64+{off + 4 * k:#x}], R{r} ;\n" for k, r in enumerate(regs))


def load_words(b, n=4):
    return "".join(f"    LDG.E R{b + k}, desc[UR4][R4.64+{4 * k:#x}] ;\n" for k in range(n))


PROBES = []


def probe(shape, base, grid, body, expect, note):
    PROBES.append(dict(name=f"{shape}_b{base}", shape=shape, base=base, on_grid=base % grid == 0, grid=grid, body=body,
                       expect=expect, note=note))


for b in (8, 9, 10, 11):
    probe("ldg128_dst", b, 4, f"    LDG.E.128 R{b}, desc[UR4][R4.64] ;\n" + store(range(b, b + 4)), ["w0", "w1", "w2", "w3"],
          "LDG.E.128 destination quad")
for b in (8, 9, 10, 11):
    probe("sts128_data", b, 4, load_words(b) + f"    STS.128 [R1], R{b} ;\n    LDS.128 R16, [R1] ;\n" + store(range(16, 20)),
          ["w0", "w1", "w2", "w3"], "STS.128 data quad")
for b in (16, 17, 18, 19):
    probe("lds128_dst", b, 4, "    LDG.E.128 R8, desc[UR4][R4.64] ;\n    STS.128 [R1], R8 ;\n" + f"    LDS.128 R{b}, [R1] ;\n" + store(range(b, b + 4)),
          ["w0", "w1", "w2", "w3"], "LDS.128 destination quad")
for b in (8, 9):
    probe("ldg64_dst", b, 2, f"    LDG.E.64 R{b}, desc[UR4][R4.64] ;\n" + store(range(b, b + 2)), ["w0", "w1"], "LDG.E.64 destination pair")
for b in (8, 9):
    probe("sts64_data", b, 2, load_words(b, 2) + f"    STS.64 [R1], R{b} ;\n    LDS.64 R16, [R1] ;\n" + store(range(16, 18)), ["w0", "w1"],
          "STS.64 data pair")
for b in (16, 17):
    probe("lds64_dst", b, 2, "    LDG.E.64 R8, desc[UR4][R4.64] ;\n    STS.64 [R1], R8 ;\n" + f"    LDS.64 R{b}, [R1] ;\n" + store(range(b, b + 2)),
          ["w0", "w1"], "LDS.64 destination pair")
for b in (8, 9):
    probe("ldc64_dst", b, 2, f"    LDC.64 R{b}, c[0x0][0x388] ;\n" + store(range(b, b + 2)), ["inp_lo", "inp_hi"], "LDC.64 destination pair")
for b in (8, 9):
    probe("ldg_addr", b, 2, f"    MOV R{b}, R4 ;\n    MOV R{b + 1}, R5 ;\n    LDG.E R12, desc[UR4][R{b}.64] ;\n" + store([12]), ["w0"],
          "LDG 64-bit address pair")
for b in (8, 9):
    probe("stg_addr", b, 2, f"    LDG.E R12, desc[UR4][R4.64] ;\n    MOV R{b}, R2 ;\n    MOV R{b + 1}, R3 ;\n    STG.E desc[UR4][R{b}.64], R12 ;\n",
          ["w0"], "STG 64-bit address pair")
for b in (8, 9):
    probe("imadw_c", b, 2, load_words(b, 2) + f"    IMAD.WIDE.U32 R12, PT, R0, 0x10000, R{b} ;\n" + store([12, 13]), ["mad_lo", "mad_hi"],
          "IMAD.WIDE addend pair, 5-operand spelling (odd = the BUG-008 word)")
for b in (12, 13):
    probe("imadw_d", b, 2, load_words(8, 2) + f"    IMAD.WIDE.U32 R{b}, PT, R0, 0x10000, R8 ;\n" + store([b, b + 1]), ["mad_lo", "mad_hi"],
          "IMAD.WIDE destination pair")
for b in (8, 9):
    probe("cs2r", b, 2, f"    MOV R{b}, 0x11111111 ;\n    MOV R{b + 1}, 0x22222222 ;\n    MOV R{b + 2}, 0x33333333 ;\n    CS2R R{b}, SRZ ;\n"
          + store(range(b, b + 3)), ["0", "0", "0x33333333"], "CS2R Rd, SRZ: writes the pair Rd:Rd+1 (0, 0, marker) or one register (0, 0x22222222, marker)?")
SMEM = "    LDG.E.128 R20, desc[UR4][R4.64] ;\n    STS.128 [R1], R20 ;\n    BAR.SYNC.DEFER_BLOCKING 0x0 ;\n"
for b in (8, 9):
    probe("ldsm2", b, 2, SMEM + f"    MOV R{b}, 0x11111111 ;\n    MOV R{b + 1}, 0x22222222 ;\n    MOV R{b + 2}, 0x33333333 ;\n"
          f"    LDSM.16.MT88.2 R{b}, [R1] ;\n" + store(range(b, b + 3)), "ctl", "LDSM.16.MT88.2 destination pair (third word = marker: .2 writes two registers)")
for b in (8, 9, 10, 11):
    probe("ldsm4", b, 4, SMEM + f"    LDSM.16.M88.4 R{b}, [R1] ;\n" + store(range(b, b + 4)), "ctl", "LDSM.16.M88.4 destination quad")
for b in (4, 5):
    body = f"    LDCU.64 UR{b}, c[0x0][0x358] ;\n    LDG.E R12, desc[UR{b}][R4.64] ;\n" + store([12])
    probe("ldcu64_desc", b, 2, body, ["w0"], "LDCU.64 destination pair in the uniform file + the descriptor pair of desc[UR]")


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    index = []
    for p in PROBES:
        with open(os.path.join(out, p["name"] + ".sass"), "w") as f:
            f.write(f"// register-grid probe: {p['note']}; base register {p['base']} ({'on' if p['on_grid'] else 'OFF'} the grid of {p['grid']})\n")
            f.write(PRO.format(name=p["name"]) + p["body"] + EPI)
        index.append({k: p[k] for k in ("name", "shape", "base", "on_grid", "grid", "expect", "note")})
    json.dump(index, open(os.path.join(out, "index.json"), "w"), indent=1)
    print(f"{len(PROBES)} probe kernels in {out}")


if __name__ == "__main__":
    main()
