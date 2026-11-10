#!/usr/bin/env python3
"""Probe kernels for BUG-008, second and third set: the wide IMAD's 64-bit pairs in the forms the register-grid probes
(gen_align_probes.py) did not measure. That set measured the word WITHOUT a carry-out predicate
(`IMAD.WIDE.U32 Rd, PT, Ra, imm, Rc`): an odd addend pair and an odd destination pair fault (CUDA 715). Here:

  imadwp_c / imadwp_d   a REAL carry-out predicate (`IMAD.WIDE.U32 Rd, P0, Ra, imm, Rc`): odd addend / destination pair
  imadwx_c / imadwx_d   the carry-in form (`IMAD.WIDE.U32.X Rd, Ra, imm, Rc, P0`)
  imadwu_d              the uniform addend (`IMAD.WIDE.U32 Rd, Ra, Rb, URc`) with an odd destination
  imadwu_c              the uniform addend pair itself on an odd uniform register
  imadw_c               the first set's pair b8 (exact) / b9 (715), copied: the run's proof that the harness sees a fault

Values are constants, the same in every thread: addend pair = 0xffffffff_ffff0000, a = 0x12345, b = 0x10000, so
pair + a*b = 0x1_00000001_23440000: low word 0x23440000, high word 0x1, carry-out 1. The carry word is R20 (0, set to 1
under @P0). `imadwp_nc` has no overflow and P0 set before; `imadwx_c0` has the carry-in clear.

Result of 2026-11-10 (RTX PRO 6000 Blackwell Server Edition; carry_probes_sm120_20261110.json): **every kernel with a
pair on an odd register ends the launch with CUDA_ERROR_ILLEGAL_INSTRUCTION (715) -- 7 of 7, in every form**; the nine
controls return the right sum (the carry-in controls: + 1 with the carry-in set, + 0 with it clear). The three controls
with a carry-out predicate are reported WRONG for their third word only: the `@P0` guard sits 6 issue cycles behind the
IMAD and saw the predicate's value from BEFORE it -- that set does not decide whether the predicate is the carry.
`--set3` is the four kernels that do (the guard 21 issue cycles behind, both polarities, with and without overflow:
"carry" reads 1 1 0 0, "not written" 0 1 0 1, "inverted" 0 0 1 1).

    gen_align_probes.py <first>                          the first set (its imadw_c pair is copied from there)
    gen_carry_probes.py <outdir> <first>                 -> <outdir>/<name>.sass + index.json;  assemble each with
                                                            `cubit asm` (the odd ones need CUBIT_DISABLE_ERRATA=1: the
                                                            BUG-008 guard refuses their text since this measurement)
    gen_carry_probes.py <outdir> <first> --set3          -> the four carry-semantics kernels (+ the proof pair)
    probe_run.py <outdir>                                -> on the GPU: OK / WRONG / FAULT per kernel
"""
import json
import os
import shutil
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
    MOV R6, 0x12345 ;
    MOV R7, 0x10000 ;
    MOV R20, 0x0 ;
"""
EPI = "    EXIT ;\n.endentry\n"
LO, HI = "0x23440000", "0x1"


def store(regs):
    return "".join(f"    STG.E desc[UR4][R2.64+{4 * k:#x}], R{r} ;\n" for k, r in enumerate(regs))


def pair(b, hi="0xffffffff"):
    return f"    MOV R{b}, 0xffff0000 ;\n    MOV R{b + 1}, {hi} ;\n"


def p0(value):
    return f"    ISETP.{'EQ' if value else 'NE'}.AND P0, PT, R6, R6, PT ;\n"


CARRY = "    @P0 MOV R20, 0x1 ;\n"
PROBES = []


def probe(shape, base, on_grid, body, expect, note):
    PROBES.append(dict(name=f"{shape}_b{base}", shape=shape, base=base, on_grid=on_grid, grid=2, body=body, expect=expect, note=note))


# ---- a real carry-out predicate
for b in (8, 9):
    probe("imadwp_c", b, b % 2 == 0, pair(b) + p0(False) + f"    IMAD.WIDE.U32 R12, P0, R6, 0x10000, R{b} ;\n" + CARRY + store([12, 13, 20]),
          [LO, HI, "0x1"], "IMAD.WIDE with a real carry-out predicate: the addend pair")
for d in (12, 13):
    probe("imadwp_d", d, d % 2 == 0, pair(8) + p0(False) + f"    IMAD.WIDE.U32 R{d}, P0, R6, 0x10000, R8 ;\n" + CARRY + store([d, d + 1, 20]),
          [LO, HI, "0x1"], "IMAD.WIDE with a real carry-out predicate: the destination pair")
# no overflow, P0 set before: the instruction must clear it (the predicate is the carry, not a leftover)
probe("imadwp_nc", 8, True, pair(8, "0x0") + p0(True) + "    IMAD.WIDE.U32 R12, P0, R6, 0x10000, R8 ;\n" + CARRY + store([12, 13, 20]),
      [LO, "0x2", "0x0"], "IMAD.WIDE with a real carry-out predicate, no overflow: P0 (set before) is cleared")
# ---- the carry-in form
for b in (8, 9):
    probe("imadwx_c", b, b % 2 == 0, pair(b) + p0(True) + f"    IMAD.WIDE.U32.X R12, R6, 0x10000, R{b}, P0 ;\n" + store([12, 13, 20]),
          ["0x23440001", HI, "0x0"], "IMAD.WIDE.X (carry-in P0 = 1): the addend pair")
for d in (12, 13):
    probe("imadwx_d", d, d % 2 == 0, pair(8) + p0(True) + f"    IMAD.WIDE.U32.X R{d}, R6, 0x10000, R8, P0 ;\n" + store([d, d + 1, 20]),
          ["0x23440001", HI, "0x0"], "IMAD.WIDE.X (carry-in P0 = 1): the destination pair")
probe("imadwx_c0", 8, True, pair(8) + p0(False) + "    IMAD.WIDE.U32.X R12, R6, 0x10000, R8, P0 ;\n" + store([12, 13, 20]),
      [LO, HI, "0x0"], "IMAD.WIDE.X with carry-in P0 = 0: no +1")
# ---- the uniform addend
# three fillers behind the R2UR pair: the dependency verifier has no cell for R2UR -> IMAD (its default asks for 13)
UPAIR = "    R2UR UR{u}, R8 ;\n    R2UR UR{v}, R9 ;\n    MOV R21, 0x0 ;\n    MOV R22, 0x0 ;\n    MOV R23, 0x0 ;\n"
for d in (12, 13):
    probe("imadwu_d", d, d % 2 == 0, pair(8) + UPAIR.format(u=6, v=7) + f"    IMAD.WIDE.U32 R{d}, R6, R7, UR6 ;\n" + store([d, d + 1, 20]),
          [LO, HI, "0x0"], "IMAD.WIDE with a uniform addend pair: the destination pair")
for u in (6, 7):
    probe("imadwu_c", u, u % 2 == 0, pair(8) + UPAIR.format(u=u, v=u + 1) + f"    IMAD.WIDE.U32 R12, R6, R7, UR{u} ;\n" + store([12, 13, 20]),
          [LO, HI, "0x0"], "IMAD.WIDE with a uniform addend pair: the uniform pair's base")

# ---- set 3: IS the predicate behind Rd the carry of the 64-bit sum? In set 2 the guard sat 6 issue cycles behind the
# IMAD and saw the predicate's old value. Here three fillers (15 issue cycles) stand between them, and both
# polarities of the predicate before the IMAD are tried with and without an overflow: the four answers tell
# "carry" (1 1 0 0), "not written" (0 1 0 1) and "inverted" (0 0 1 1) apart. All four are on the grid.
FILL = "".join(f"    MOV R{21 + k}, 0x0 ;\n" for k in range(3))
SET3 = []
for tag, hi, before, want_hi, want_carry in (("ov_p0", "0xffffffff", False, HI, "0x1"), ("ov_p1", "0xffffffff", True, HI, "0x1"),
                                             ("no_p0", "0x0", False, "0x2", "0x0"), ("no_p1", "0x0", True, "0x2", "0x0")):
    SET3.append(dict(name=f"imadwq_{tag}_b8", shape=f"imadwq_{tag}", base=8, on_grid=True, grid=2,
                     body=pair(8, hi) + p0(before) + "    IMAD.WIDE.U32 R12, P0, R6, 0x10000, R8 ;\n" + FILL + CARRY + store([12, 13, 20]),
                     expect=[LO, want_hi, want_carry],
                     note=f"the carry-out predicate read 21 issue cycles behind the IMAD: {'overflow' if tag.startswith('ov') else 'no overflow'}, P0 {'set' if before else 'clear'} before"))


def main():
    if len(sys.argv) > 3 and sys.argv[3] == "--set3":
        PROBES[:] = SET3
    out, first = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    index = []
    for p in PROBES:
        with open(os.path.join(out, p["name"] + ".sass"), "w") as f:
            f.write(f"// BUG-008 probe: {p['note']}; base {p['base']} ({'on' if p['on_grid'] else 'OFF'} the grid of 2)\n")
            f.write(PRO.format(name=p["name"]) + p["body"] + EPI)
        index.append({k: p[k] for k in ("name", "shape", "base", "on_grid", "grid", "expect", "note")})
    # the harness's proof in this run: the first set's measured pair, byte for byte
    old = {p["name"]: p for p in json.load(open(os.path.join(first, "index.json")))}
    for n in ("imadw_c_b8", "imadw_c_b9"):
        shutil.copy(os.path.join(first, n + ".sass"), os.path.join(out, n + ".sass"))
        index.append(old[n])
    json.dump(index, open(os.path.join(out, "index.json"), "w"), indent=1)
    print(f"{len(index)} probe kernels in {out}")


if __name__ == "__main__":
    main()
