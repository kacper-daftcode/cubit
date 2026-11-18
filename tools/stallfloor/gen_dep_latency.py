#!/usr/bin/env python3
"""Build cubit's sm_120 dependency-latency table (tables/dep_latency_sm120.json) from
  (1) ptxas's practice: the pair matrix mined from the frozen sm_120 census (dep_latency_census.py) — for every dense cell
      (producer class, consumer class, operand role) the minimum issue distance ptxas ever schedules, and
  (2) stall floors measured on sm_120 silicon (tools/stallfloor): a measured floor above the census minimum raises the cell;
      a measured floor below it is recorded (`silicon`) but the cell keeps ptxas's value (never below the vendor's practice).

  (3) the result register read (--result-census, --result-floors): the upper register of a multi-register result is priced
      apart for the producers of RESULT_HIGH. Its readers get their own cells (`result_high.cells`), mined from the census
      split by result register (result_register_census.py) with the rule of (1); a reader without such a cell keeps the
      pair's cell but never less than the largest floor measured for an upper register (`result_high.floor`). The cells
      of (1) and (2) are not touched by it: a binary that does not know `result_high` reads the table as before.
  (4) producer FORMS priced apart from their class (PRODUCER_FORMS -> `producer_forms`): the result of such a form is never
      read closer than the entry's L in any register / address role, except in the (consumer, role) pairs the entry names.
      It is written as it stands here (no census input); the cells of (1) - (3) are not touched by it.
  (5) cells written out (WRITTEN_CELLS): a pair the census walk does not see (the certified operand sets have no rule for
      the producer) and that is priced by ptxas's distance and a measured floor -- the cell stands here with its evidence.
  (6) cells on a measured floor (MEASURED_MIN_CELLS): ptxas's census MINIMUM of a pair to which rule (1) gives no cell
      (fewer than MIN_AT pairs at the minimum) or a clamped one (a minimum below the global floor of 4) -- taken only where
      a probe of this directory measured the pair's floor at or below that minimum on BOTH card models. The cell is the
      census minimum, never the floor: cubit does not stand closer than ptxas ever does. The generator reads the census row
      and the probe's result files and refuses an entry they do not carry. A pair with a word of the uniform datapath that
      the certified operand sets do not know (`ULEA`, `USHF`, the uniform result of `VOTEU`) has no row in the census pairs:
      its minimum is read from the verifier's census (`census_pairs_uniform_sm120.json`, uniform_pairs_census.py), which has
      it per SET of roles the register has in the consumer -- the cell of a role is the smallest minimum of the sets that
      hold the role, and the run stops when the cells of a pair would put any role set of that census below ptxas's own
      minimum for the set (an in-place form needs the cells of two roles; a form that has only one of them rides along).
  (7) a pair row of a --floors file that names what superseded it (key `superseded`: the pair's own kernels measured
      nothing, its `floor_d0` is another measurement's): the cell's `silicon` sentence is the one written here
      (SUPERSEDED_SILICON), not `floor d0 S<nn>`; such a row without a sentence stops the run.

usage: gen_dep_latency.py census_pairs.json out.json [--floors pair_floors.json ...] [--v6 cells.json ...]
                          [--mma-registers file] [--result-census census_pairs_result.json --result-floors floors.json]
"""
import sys, json, argparse, collections, os

VARIABLE = ["LDG", "LDS", "LDSM", "LDL", "LDC", "LDCU", "LD", "LDGSTS", "S2R", "S2UR", "MUFU", "SHFL", "ATOM", "ATOMG", "ATOMS",
            "RED", "REDG", "REDUX", "I2F", "F2I", "FLO", "POPC", "B2R", "TEX", "TLD", "TXQ", "LEPC", "GETLMEMBASE", "LDTM",
            "UTCATOMSWS"]
MMA = ["HMMA", "QMMA", "IMMA", "DMMA"]
MIN_N, MIN_AT = 50, 8
MAX_TIGHT = 7     # a fixed-latency ALU pair is never above 7 (-> MMA fragment) in the census' dense spikes
# producers whose upper result register is priced apart: the two halves of a 64-bit product are not ready together
# (silicon: the low register is readable from 1-3 issue cycles, the high one from 3-5; ptxas: low from 3, high from 4 / 5)
RESULT_HIGH = ["IMAD.WIDE"]
# producer FORMS priced apart from their class: the class of the table plus the modifiers the form does NOT carry. The
# class `CS2R` does not tell the 64-bit form (a register pair) from `CS2R.32`; silicon reads the pair form's result right
# from 6 issue cycles with one cycle closer wrong -- the table's default, with no margin --, and ptxas never reads it
# closer than 7: the form takes ptxas's 7 in every register / address role. The data of a shared-memory store (floor 3)
# keeps the default, and the 32-bit form keeps the class's cell, until their forms are measured.
PRODUCER_FORMS = [
    {"producer": "CS2R", "without": [".32"], "L": 7,
     "except": [{"consumer": "STS", "role": "r1"}],
     "basis": "ptxas: 22 116 of the census's 22 140 CS2R words are the 64-bit form (`CS2R Rn, <SR>` without `.32`: a "
              "register pair); no reader of either result register stands closer than 7 behind one (188 readers within 12 "
              "issue cycles: 26 at exactly 7 -- IMAD 20, STS 4, MUFU 2 --, 36 at 8); the other 24 words are the 32-bit form "
              "(`CS2R.32 Rn, SR_CgaSize` -> IMAD at 5), which is not this form and keeps the cell of the class",
     "silicon": "floor 6 into FMUL r2, FADD r1, LOP3 r1 (either result register), MOV r1, SHF r3 (the second register) "
                "and IADD r1 (the first) -- tools/stallfloor probe_sm120_20261111_b33 and its two _ws_ files: a Server "
                "Edition card, a Workstation Edition card alone and at its 400-W limit, 6 | 6 | 6, right at 6 / 7 / 8 / 11 / 26 "
                "on every grid, not right at 5 -- and into IMAD r1 / IADD3 r1 / LOP3 r1 (probe_sm120_20261110_b3, Server): the "
                "default 6 is the floor itself, without a margin -- a trial floor, not a number of this table; -> STS data "
                "floor 3 | 3 | 3 (probe_sm120_20261111_b35 and its _ws_ files): the exception keeps the default 6"},
    {"producer": "CS2UR", "without": [], "L": 6, "except": [],
     "basis": "ptxas: the 190 CS2UR words of the census (each a read of the global timer in the timeout check "
              "of a spin-wait) carry no write barrier and have their first reader 6 issue cycles behind them "
              "(184) or 16 (6), never closer",
     "silicon": "a reader closer than 6 takes the register's old content: `CS2UR UR6, SRZ` and `CS2UR.32` into "
                "MOV and into the low word of IADD.64 not right at 1 .. 5, right from 6 (two card models -- a "
                "Server Edition card, tools/stallfloor/probe_sm120_20261112_b53.json, and a Workstation "
                "Edition card alone and at its 400-W limit, "
                "probe_sm120_20261112_b53_ws_2eabe5dcdba4_alone.json / "
                "probe_sm120_20261112_b53_ws_2eabe5dcdba4_capped.json, the same floors; six grids, with and "
                "without the yield flag; the high word from 5, UIADD3 from 4 -- measurements, not numbers of "
                "this table); a write barrier on the word and a wait on its reader change no count: the word "
                "has no scoreboard result"},
]
# cells written out as they stand: the census walk has no row for the pair (the certified operand sets do not know the
# producer), ptxas's distance and the measured floor are the evidence
WRITTEN_CELLS = [
    {"producer": "CS2UR", "consumer": "IADD", "role": "u2", "L": 6,
     "basis": "ptxas: every CS2UR word of the vendor's sm_120 kernels is a read of the global timer for the "
              "timeout check of a spin-wait, none carries a write barrier, and its first reader -- `IADD.64 R, "
              "-R, UR` -- stands 6 issue cycles behind it or later, never closer",
     "silicon": "floor 6 on two card models (a Server Edition card, "
                "tools/stallfloor/probe_sm120_20261112_b53.json, six grids, with and without the yield flag; a "
                "Workstation Edition card alone and at its 400-W limit, "
                "probe_sm120_20261112_b53_ws_2eabe5dcdba4_alone.json / "
                "probe_sm120_20261112_b53_ws_2eabe5dcdba4_capped.json: the same floor): the low word into "
                "IADD.64 and the result into MOV not right at 1 .. 5, right from 6; a write barrier on the "
                "word and a wait on its reader change no count -- the cell is the floor itself, without a "
                "margin"},
]
# cells on a measured floor: ptxas's census MINIMUM of a pair that the dense-cell rule leaves to a default (fewer than MIN_AT
# pairs at the minimum) or clamps (a minimum below 4), where a probe measured the pair's floor at or below that minimum on
# both card models (`request` in every file of `probe_files`: a Server Edition card, a Workstation Edition card alone and
# at its power limit). The number of the cell is read off the census row; an entry the files do not carry stops the run.
# the `silicon` sentence of a cell whose pair row carries the key `superseded` (rule (7)): what the newer measurement says
SUPERSEDED_SILICON = {
    ("ISETP", "ISETP", "p"): (
        "a prohibition below 5 on two card models (a Server Edition card and a Workstation Edition card, "
        "tools/stallfloor/probe_sm120_20261112_b61.json and its two _ws_ files: the consumer takes the old "
        "predicate -- at 1 ... 3 issue cycles no thread-launch is right, at 4 at most 7264 of 73584640, from "
        "5 every one); the pair isetp_isetp of stall_floors_sm120_20261110_pairs.json (floor 1) measured "
        "nothing"),
}
B63 = ["probe_sm120_20261113_b63.json", "probe_sm120_20261113_b63_ws_2eabe5dcdba4_alone.json"]
MEASURED_MIN_CELLS = [
    {"producer": "UMOV", "consumer": "MOV", "role": "u1", "request": "pu_umov_mov_u1",
     "probe_files": ["probe_sm120_20261111_b46.json", "probe_sm120_20261111_b46_ws_2eabe5dcdba4_alone.json",
                     "probe_sm120_20261111_b46_ws_2eabe5dcdba4_capped.json"],
     "form": "`UMOV UR, imm` -> `MOV R, UR`"},
    # the pairs of the batch b63, each with the roles of its measured form (`census`: where ptxas's minimum is read)
    {"producer": "UIADD3", "consumer": "ULEA", "role": "u0", "request": "u01_uiadd3_ulea", "probe_files": B63, "census": "uniform",
     "form": "`UIADD3 UR, UPT, UPT, UR, imm, URZ` -> `ULEA UR, URb, UR, imm` (in place: roles u0 and u2)"},
    {"producer": "UIADD3", "consumer": "ULEA", "role": "u2", "request": "u01_uiadd3_ulea", "probe_files": B63, "census": "uniform",
     "form": "`UIADD3 UR, UPT, UPT, UR, imm, URZ` -> `ULEA UR, URb, UR, imm` (in place: roles u0 and u2)"},
    {"producer": "UMOV", "consumer": "ULEA", "role": "u0", "request": "u02_umov_ulea", "probe_files": B63, "census": "uniform",
     "form": "`UMOV UR, imm` -> `ULEA UR, URb, UR, imm` (in place: roles u0 and u2)"},
    {"producer": "UMOV", "consumer": "ULEA", "role": "u2", "request": "u02_umov_ulea", "probe_files": B63, "census": "uniform",
     "form": "`UMOV UR, imm` -> `ULEA UR, URb, UR, imm` (in place: roles u0 and u2)"},
    {"producer": "ULEA", "consumer": "ULEA", "role": "u0", "request": "u03_ulea_ulea", "probe_files": B63, "census": "uniform",
     "form": "`ULEA UR, URb, UR, 0x18` -> `ULEA UR, URc, UR, 0x3` (in place: roles u0 and u2)"},
    {"producer": "ULEA", "consumer": "ULEA", "role": "u2", "request": "u03_ulea_ulea", "probe_files": B63, "census": "uniform",
     "form": "`ULEA UR, URb, UR, 0x18` -> `ULEA UR, URc, UR, 0x3` (in place: roles u0 and u2)"},
    {"producer": "ULEA", "consumer": "LEA", "role": "u2", "request": "u04_ulea_lea", "probe_files": B63, "census": "uniform",
     "form": "`ULEA UR, URb, UR, imm` -> `LEA R, R, UR, imm`"},
    {"producer": "ULEA", "consumer": "IADD3", "role": "u2", "request": "u05_ulea_iadd3", "probe_files": B63, "census": "uniform",
     "form": "`ULEA UR, URb, UR, imm` -> `IADD3 R, PT, PT, R, UR, RZ`"},
    {"producer": "ULEA", "consumer": "STS", "role": "u0", "request": "u06_ulea_sts", "also": ["u06_ulea_sts128"], "probe_files": B63, "census": "uniform",
     "form": "`ULEA UR, URb, UR, imm` -> the uniform base of `STS [UR+imm], R` and of `@!P0 STS.128 [UR+imm], R`"},
    {"producer": "VOTEU", "consumer": "FLO", "role": "u1", "request": "u11_voteu_flo", "probe_files": B63, "census": "uniform",
     "form": "`VOTEU.ANY UR, UP, P` -> `FLO.U32 R, UR`"},
    {"producer": "VOTEU", "consumer": "POPC", "role": "u1", "request": "u12_voteu_popc", "probe_files": B63, "census": "uniform",
     "form": "`VOTEU.ANY UR, UP, P` -> `POPC R, UR`"},
    {"producer": "USHF", "consumer": "ULOP3", "role": "u3", "request": "u14_ushf_ulop3", "probe_files": B63, "census": "uniform",
     "form": "`USHF.R.U32 UR, URa, imm, URZ` -> the third source of `ULOP3.LUT URd, URa, imm, UR, lut, !UPT`"},
    {"producer": "ULOP3", "consumer": "USHF", "role": "u0", "request": "u16_ulop3_ushf", "probe_files": B63, "census": "uniform",
     "form": "`ULOP3.LUT UR, ...` -> `USHF.L.U32 UR, UR, imm, URZ` (in place: roles u0 and u1)"},
    {"producer": "ULOP3", "consumer": "USHF", "role": "u1", "request": "u16_ulop3_ushf", "probe_files": B63, "census": "uniform",
     "form": "`ULOP3.LUT UR, ...` -> `USHF.L.U32 UR, UR, imm, URZ` (in place: roles u0 and u1)"},
    # the dense-cell rule clamps these two at the global floor of 4; ptxas stands at 2 (the census pairs have the rows)
    {"producer": "UMOV", "consumer": "UIADD3", "role": "u0", "request": "ua_umov_uiadd3i", "probe_files": B63,
     "form": "`UMOV UR, imm` -> `UIADD3 UR, UPT, UPT, UR, imm, URZ` (in place: roles u0 and u1)"},
    {"producer": "UMOV", "consumer": "UIADD3", "role": "u1", "request": "ua_umov_uiadd3", "also": ["ua_umov_uiadd3i"], "probe_files": B63,
     "form": "`UMOV UR, imm` -> `UIADD3 URd, UPT, UPT, UR, imm, URZ` (into a second register, and in place)"},
]
PRODUCER_FORMS_COMMENT = (" `producer_forms`: the result of a producer FORM named there -- the class plus the modifiers the form"
                          " does not carry (`CS2R` without `.32` = the 64-bit form, a register pair) -- is never read closer than"
                          " the entry's L in any register or address role: the larger of L and the pair's cell or default; the"
                          " (consumer, role) pairs of `except` keep their cell or default (a trailing h of the role is ignored).")


# The members `setter_flag`, `wait_forms` and `waiter_flag` of the row `barrier_arm` (tools/stallfloor/probe.py 34; every row
# says on how many card models it stands - `card_models`: two, or one where the second model's column is still to come;
# the words are the probe kernels' own, the numbers those of the result files the rows name). `cycles` is the one member
# the scheduler reads.
BARRIER_ARM_MEASURED = json.loads(r'''{
 "setter_flag": {
  "law": "a word that waits on a write barrier as the NEXT word behind the barrier's setter (the setter's stall count is their distance): behind a setter WITHOUT the yield flag the wait holds from stall count 1, behind a setter WITH the yield flag only from stall count 2 - floor 2 with the flag on the setter, floor 1 without it, for each of the fourteen setters, in every cell, on both card models",
  "prohibition": "a setter that carries the yield flag at stall count 1 with the word that waits on its barrier as the next word: right in 0 | 0 of 168 cells, 431 226 880 | 431 226 880 of 431 226 880 thread-launches not right",
  "flag": "in the measured kernels the yield flag stands on the SETTER and on no other word (the two variants of a setter differ in that one field of that one word); the waiting word carries no flag. NOT MEASURED by these rows: the yield flag on the WAITING word one cycle behind a setter (a waiting word may carry the flag: the event word of `w_yil_b` in the `_b71` files carries the wait and the flag 7 cycles behind the last setter and is right in 24 | 24 of 24 cells)",
  "cycles": "`cycles` stays 2: the distance that is right with the flag on the setter",
  "words": "a setter's row quotes the kernel without the flag at one warp per SM, no front, stall count 1 (f_<x>_bare_w1_f0_d0001), as the listing prints it: the setter, the word that waits (the next word) and the first reader of the setter's register; the flag variant prints `Y` in the setter's fourth field and is the same text otherwise; `floor` = the first stall count of the setter from which every swept count is right, [Server Edition, Workstation Edition]",
  "columns": ["a card of the Server Edition", "a card of the Workstation Edition"],
  "conditions": {"driver": "610.43.02", "state": "each card with the probe alone, no power limit; the Workstation Edition card with its standing memory clock offset of +5000 MHz (the Server Edition model takes no offset)", "busy_clock_p50_mhz": {"_b71": [2370.0, 2872.0], "_b72": [2370.0, 2887.0]}, "grids": "1, 8, 9, 12 and 16 warps per SM; 2 CTAs of 9 warps per SM", "fronts": "none; fifteen `STS.128` at stall 4", "launches": 40, "distances": "the setter's stall count 1 ... 8"},
  "cells": {"what": "setter x grid x front = 14 x 6 x 2; right = every thread-launch of the cell right; [Server Edition, Workstation Edition, of]", "no_flag_right_at_1": [168, 168, 168], "flag_right_at_1": [0, 0, 168], "flag_right_at_2": [168, 168, 168], "no_flag_thread_launches_not_right_at_1_to_8": [0, 0, 3449815040], "flag_thread_launches_not_right_at_1": [431226880, 431226880, 431226880], "controls_without_barrier_and_wait_right_at_1_to_8": [0, 0, 624]},
  "files": {"_b71": ["probe_sm120_20261113_b71.json", "probe_sm120_20261118_b71_ws_2eabe5dcdba4_alone.json", "probe_sm120_20261118_b71_ws_2eabe5dcdba4_alone_2.json"], "_b72": ["probe_sm120_20261113_b72.json", "probe_sm120_20261118_b72_ws_2eabe5dcdba4_alone.json"]},
  "card_models": 2,
  "one_card_model": {
   "standing": "measured on ONE card model (a card of the Server Edition): not a law; the PROHIBITION binds from one card model",
   "prohibition": "the prohibition holds behind three more setters, each with ITS FIRST READER AS A SERVED KERNEL HOLDS IT as the word that waits (the next word): with the yield flag on the setter at stall count 1 right in 0 of 36 cells, 92405760 of 92405760 thread-launches not right; with the reference setter of this diagnostic in the same file (`MUFU.EX2`, one of the fourteen) 0 of 48 cells",
   "measured": "behind each of the three setters the served reader is right from stall count 1 without the yield flag on the setter (96 of 96 cells each) and from stall count 2 with it (84 of 84 cells each): floor 1 without the flag, floor 2 with it - on one card model",
   "flag": "the yield flag stands on the setter; where the served kernel carries it on the reader too (the readers of `MUFU.LG2` and `SHFL.BFLY`), the flagged variant carries it there and the reader's stall count is the served one",
   "columns": ["a card of the Server Edition"],
   "conditions": {"driver": "610.43.02", "state": "the card with the probe alone, no power limit (the Server Edition model takes no clock offset)", "busy_clock_p50_mhz": [2370.0], "grids": "1, 8, 9, 12 and 16 warps per SM; 2 CTAs of 9 warps per SM", "fronts": "none; fifteen `STS.128` at stall 4", "launches": 40, "distances": "the setter's stall count 1 ... 8"},
   "cells": {"what": "setter x grid x front = 3 x 6 x 2; right = every thread-launch of the cell right; [Server Edition, of]", "no_flag_right_at_1": [36, 36], "flag_right_at_1": [0, 36], "flag_right_at_2": [36, 36], "no_flag_thread_launches_not_right_at_1_to_8": [0, 739246080], "flag_thread_launches_not_right_at_1": [92405760, 92405760], "controls_without_barrier_and_wait_right_at_1_to_8": [0, 144]},
   "files": ["probe_sm120_20261118_b73.json"],
   "setters": [
    {"setter": "[B------:R-:W1:-:S01] MUFU.LG2 R32, R21 ;", "waiter": "[B-1----:R-:W-:-:S06] FADD.FTZ R32, R32, R26 ;", "first_reader": "the waiter, as a served kernel holds it: read IN PLACE (the reader overwrites the setter's register)", "waiter_with_the_flag_on_the_setter": "[B-1----:R-:W-:Y:S01] FADD.FTZ R32, R32, R26 ;", "floor": {"no_flag": [1], "flag": [2]}, "requests": ["f_mlg", "f_mlg_y", "f_mlg_n"]},
    {"setter": "[B------:R-:W1:-:S01] S2R R32, SR_TID.X ;", "waiter": "[B-1----:R-:W-:-:S06] SHF.R.U32.HI R24, RZ, 0x5, R32 ;", "first_reader": "the waiter, as a served kernel holds it: read into another register", "floor": {"no_flag": [1], "flag": [2]}, "requests": ["f_tid", "f_tid_y", "f_tid_n"]},
    {"setter": "[B------:R-:W1:-:S01] SHFL.BFLY PT, R32, R21, 0x2, 0x1f ;", "waiter": "[B-1----:R-:W-:-:S01] SEL R24, R21, R32, !P0 ;", "first_reader": "the waiter, as a served kernel holds it: read under a negated predicate", "waiter_with_the_flag_on_the_setter": "[B-1----:R-:W-:Y:S01] SEL R24, R21, R32, !P0 ;", "floor": {"no_flag": [1], "flag": [2]}, "requests": ["f_bfl", "f_bfl_y", "f_bfl_n"]}
   ]
  },
  "setters": [
   {"setter": "[B------:R-:W1:-:S01] MUFU.EX2 R32, R21 ;", "waiter": "[B-1----:R-:W-:-:S01] MOV R24, R32 ;", "first_reader": "the waiter", "floor": {"no_flag": [1, 1], "flag": [2, 2]}, "requests": ["f_mex", "f_mex_y", "f_mex_n"], "files": "_b71"},
   {"setter": "[B------:R-:W1:-:S01] MUFU.RCP R32, R21 ;", "waiter": "[B-1----:R-:W-:-:S01] MOV R24, R32 ;", "first_reader": "the waiter", "floor": {"no_flag": [1, 1], "flag": [2, 2]}, "requests": ["f_mrc", "f_mrc_y", "f_mrc_n"], "files": "_b71"},
   {"setter": "[B------:R-:W1:-:S01] I2F.RP R32, R21 ;", "waiter": "[B-1----:R-:W-:-:S01] MOV R24, R32 ;", "first_reader": "the waiter", "floor": {"no_flag": [1, 1], "flag": [2, 2]}, "requests": ["f_i2f", "f_i2f_y", "f_i2f_n"], "files": "_b71"},
   {"setter": "[B------:R-:W1:-:S01] F2I.FTZ.U32.TRUNC.NTZ R32, R21 ;", "waiter": "[B-1----:R-:W-:-:S01] MOV R24, R32 ;", "first_reader": "the waiter", "floor": {"no_flag": [1, 1], "flag": [2, 2]}, "requests": ["f_f2i", "f_f2i_y", "f_f2i_n"], "files": "_b71"},
   {"setter": "[B------:R-:W1:-:S01] F2F.BF16.F32 R32, R21 ;", "waiter": "[B-1----:R-:W-:-:S01] MOV R24, R32 ;", "first_reader": "the waiter", "floor": {"no_flag": [1, 1], "flag": [2, 2]}, "requests": ["f_f2f", "f_f2f_y", "f_f2f_n"], "files": "_b71"},
   {"setter": "[B------:R2:W1:-:S01] SHFL.IDX PT, R32, R21, RZ, 0x1f ;", "waiter": "[B-1----:R-:W-:-:S01] MOV R24, R32 ;", "first_reader": "the waiter", "floor": {"no_flag": [1, 1], "flag": [2, 2]}, "requests": ["f_shx", "f_shx_y", "f_shx_n"], "files": "_b71"},
   {"setter": "[B------:R-:W1:-:S01] S2R R32, SR_LTMASK ;", "waiter": "[B-1----:R-:W-:-:S01] MOV R24, R32 ;", "first_reader": "the waiter", "floor": {"no_flag": [1, 1], "flag": [2, 2]}, "requests": ["f_ltm", "f_ltm_y", "f_ltm_n"], "files": "_b71"},
   {"setter": "[B------:R-:W1:-:S01] LDCU UR12, c[0x0][0x388] ;", "waiter": "[B-1----:R-:W-:-:S01] MOV R24, UR12 ;", "first_reader": "the waiter", "floor": {"no_flag": [1, 1], "flag": [2, 2]}, "requests": ["f_lcu", "f_lcu_y", "f_lcu_n"], "files": "_b71"},
   {"setter": "[B------:R-:W1:-:S01] LDC.64 R32, c[0x0][0x380] ;", "waiter": "[B-1----:R-:W-:-:S01] MOV R24, R32 ;", "first_reader": "the waiter", "floor": {"no_flag": [1, 1], "flag": [2, 2]}, "requests": ["f_lc64", "f_lc64_y", "f_lc64_n"], "files": "_b71"},
   {"setter": "[B------:R-:W1:-:S01] LDC R32, c[0x0][R13+0x388] ;", "waiter": "[B-1----:R-:W-:-:S01] MOV R24, R32 ;", "first_reader": "the waiter", "floor": {"no_flag": [1, 1], "flag": [2, 2]}, "requests": ["f_lcx", "f_lcx_y", "f_lcx_n"], "files": "_b71"},
   {"setter": "[B------:R-:W1:-:S01] @P0 LDG.E.CONSTANT R32, desc[UR4][R18.64] ;", "waiter": "[B-1----:R-:W-:-:S01] MOV R24, R32 ;", "first_reader": "the waiter", "floor": {"no_flag": [1, 1], "flag": [2, 2]}, "requests": ["f_pld", "f_pld_y", "f_pld_n"], "files": "_b71"},
   {"setter": "[B------:R-:W1:-:S01] LDG.E R32, desc[UR4][R18.64] ;", "waiter": "[B-1----:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;", "first_reader": "[B------:R-:W-:-:S01] MOV R24, R32 ;", "floor": {"no_flag": [1, 1], "flag": [2, 2]}, "requests": ["f_wld", "f_wld_y"], "files": "_b71"},
   {"setter": "[B------:R-:W1:-:S01] LDS.128 R32, [R9+0x20] ;", "waiter": "[B-1----:R-:W-:-:S01] MOV R24, R34 ;", "first_reader": "the waiter", "floor": {"no_flag": [1, 1], "flag": [2, 2]}, "requests": ["f_l128", "f_l128_y", "f_l128_n"], "files": "_b72"},
   {"setter": "[B------:R-:W1:-:S01] LDCU.64 UR12, c[0x0][0x380] ;", "waiter": "[B-1----:R-:W-:-:S01] MOV R24, UR12 ;", "first_reader": "the waiter", "floor": {"no_flag": [1, 1], "flag": [2, 2]}, "requests": ["f_lcu64", "f_lcu64_y", "f_lcu64_n"], "files": "_b72"}
  ]
 },
 "wait_forms": [
  {
   "card_models": 2,
   "form": "the reader into ANOTHER predicate behind the third write of the set's predicate",
   "what": "a set of producers of one thread in flight under ONE predicate, every member on one write barrier with the yield flag, the last member at stall 2; the third write of that predicate, from the lane, stands one cycle in front of the word that carries the set's one wait (a word that reads no member), and the FIRST reader word behind the wait is `ISETP.GE.AND` of a guarded load's register into another predicate; the members 1 and 4 cycles apart; the sets N,gN,gN and N,i,gN,gN (N = `LDG.E.CONSTANT`, gN = `@!P0 LDG.E.CONSTANT`, i = `SHFL.IDX`), the guards a bit of the iteration counter or false in every lane",
   "words_of": "the kernel s_nigg_p_cc_l_bare_w1_f0_d0001 (one warp per SM, the members 1 cycle apart), from the set's first member to the first reader word",
   "words": [
    "[B------:R1:W1:Y:S01] LDG.E.CONSTANT R32, desc[UR4][R18.64] ;",
    "[B------:R2:W1:Y:S01] SHFL.IDX PT, R33, R73, 0x1, 0x1f ;",
    "[B------:R1:W1:Y:S01] @!P0 LDG.E.CONSTANT R34, desc[UR4][R18.64] ;",
    "[B------:R-:W-:-:S13] ISETP.GE.AND P0, PT, R7, RZ, PT ;",
    "[B------:R1:W1:Y:S02] @!P0 LDG.E.CONSTANT R35, desc[UR4][R18.64] ;",
    "[B------:R-:W-:-:S01] ISETP.NE.AND P0, PT, R31, RZ, PT ;",
    "[B-1----:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:-:S01] ISETP.GE.AND P3, PT, R35, RZ, PT ;"
   ],
   "cells": {"what": "request x grid x distance; [Server Edition, Workstation Edition, of]", "measured": {"right": [48, 48, 48], "thread_launches_not_right": [0, 0, 123207680]}, "reference_without_the_lane_write": {"right": [12, 12, 12], "thread_launches_not_right": [0, 0, 30801920]}, "control_the_wait_behind_the_reader_words": {"right": [0, 0, 6], "thread_launches_not_right": [15400960, 15400960, 15400960]}},
   "requests": ["s_ngg_p_cc_l", "s_ngg_p_ff_l", "s_nigg_p_cc_l", "s_nigg_p_ff_l", "s_ngg_p_cc", "s_ngg_p_cc_ew"],
   "files": ["probe_sm120_20261118_b74.json", "probe_sm120_20261118_b74_ws_2eabe5dcdba4_alone.json"]
  },
  {
   "card_models": 2,
   "form": "the reader into the set's OWN predicate",
   "what": "the same set N,i,gN,gN with the third write of its predicate from the lane one cycle in front of the waiting word; the FIRST reader word behind the wait is `ISETP.GE.AND` of THE SHUFFLE's register and writes the predicate the guarded loads stand under; the members 1 and 4 cycles apart, the guards a bit of the iteration counter or false in every lane",
   "words_of": "the kernel s_nigg_o_cc_l_bare_w1_f0_d0001 (one warp per SM, the members 1 cycle apart), from the set's first member to the first reader word",
   "words": [
    "[B------:R1:W1:Y:S01] LDG.E.CONSTANT R32, desc[UR4][R18.64] ;",
    "[B------:R2:W1:Y:S01] SHFL.IDX PT, R33, R73, 0x1, 0x1f ;",
    "[B------:R1:W1:Y:S01] @!P0 LDG.E.CONSTANT R34, desc[UR4][R18.64] ;",
    "[B------:R-:W-:-:S13] ISETP.GE.AND P0, PT, R7, RZ, PT ;",
    "[B------:R1:W1:Y:S02] @!P0 LDG.E.CONSTANT R35, desc[UR4][R18.64] ;",
    "[B------:R-:W-:-:S01] ISETP.NE.AND P0, PT, R31, RZ, PT ;",
    "[B-1----:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:-:S01] ISETP.GE.AND P0, PT, R33, RZ, PT ;"
   ],
   "cells": {"what": "request x grid x distance; [Server Edition, Workstation Edition, of]", "measured": {"right": [24, 24, 24], "thread_launches_not_right": [0, 0, 61603840]}, "reference_the_reader_into_another_predicate": {"right": [12, 12, 12], "thread_launches_not_right": [0, 0, 30801920]}, "control_the_wait_behind_the_reader_words": {"right": [0, 0, 6], "thread_launches_not_right": [15400960, 15400960, 15400960]}},
   "requests": ["s_nigg_o_cc_l", "s_nigg_o_ff_l", "s_nigg_p_cc_l", "s_nigg_o_cc_ew"],
   "files": ["probe_sm120_20261118_b75.json", "probe_sm120_20261118_b75_ws_2eabe5dcdba4_alone.json"]
  },
  {
   "card_models": 2,
   "form": "two waiting words on one barrier",
   "what": "a set `SYNCS.CCTL.IVALL`, `SHFL.IDX`, `LDCU.64` on one write barrier with the yield flag, the last member at stall 2; a word that reads no member carries the wait first and the first reader word (of the load) stands one cycle behind it; then the event word `BAR.SYNC.DEFER_BLOCKING 0x0` (the yield flag, stall 6; behind `WARPSYNC.ALL`, the yield flag, stall 5) waits the SAME barrier again, 7 cycles (`words`) and 101 cycles (seven filler words more) behind the first waiting word, and the second reader word (of the shuffle) stands 6 cycles behind it; the members 1 and 4 cycles apart; a kernel with this word holds a named barrier: a launch of such a kernel may not return",
   "words_of": "the kernel w_yil_d_bare_w1_f0_d0001 (one warp per SM, no front, the members 1 cycle apart), from the set's first member to the second reader word",
   "words": [
    "[B------:R-:W1:Y:S01] SYNCS.CCTL.IVALL ;",
    "[B------:R1:W1:Y:S01] SHFL.IDX PT, R32, R73, 0x1, 0x1f ;",
    "[B------:R-:W1:Y:S02] LDCU.64 UR6, c[0x0][0x380] ;",
    "[B-1----:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:-:S01] IADD.64 R24, -R2, UR6 ;",
    "[B------:R-:W-:Y:S05] WARPSYNC.ALL ;",
    "[B-1----:R-:W-:Y:S06] BAR.SYNC.DEFER_BLOCKING 0x0 ;",
    "[B------:R-:W-:-:S01] MOV R6, R32 ;"
   ],
   "cells": {"what": "grid x front x distance, the set's text and the text with every member on its own barrier and wait; [Server Edition, Workstation Edition, of]", "measured_7_cycles": {"right": [24, 24, 24], "thread_launches_not_right": [0, 0, 61603840]}, "measured_7_cycles_own_barriers": {"right": [24, 24, 24], "thread_launches_not_right": [0, 0, 61603840]}, "measured_101_cycles": {"right": [24, 24, 24], "thread_launches_not_right": [0, 0, 61603840]}, "measured_101_cycles_own_barriers": {"right": [24, 24, 24], "thread_launches_not_right": [0, 0, 61603840]}, "reference_one_waiting_word": {"right": [24, 24, 24], "thread_launches_not_right": [0, 0, 61603840]}, "control_no_barrier_and_no_wait": {"right": [0, 0, 36], "thread_launches_not_right": [92405760, 92405760, 92405760]}},
   "requests": ["w_yil_d", "w_yil_t", "w_yil_f", "w_yil_d_n"],
   "files": ["probe_sm120_20261118_b75.json", "probe_sm120_20261118_b75_ws_2eabe5dcdba4_alone.json"]
  },
  {
   "card_models": 1,
   "form": "the yield flag on the data word that carries the set's one wait",
   "what": "a set `SYNCS.CCTL.IVALL`, `SHFL.IDX`, `LDCU.64` on one write barrier with the yield flag, the last member at stall 2; the one wait stands on a word that reads no member, one cycle in front of the first reader word (of the load) - and THAT WORD CARRIES THE YIELD FLAG; the reference is the same text without the flag on it",
   "words_of": "the kernel w_yil_fy_bare_w1_f0_d0001 (one warp per SM, no front, the members 1 cycle apart), from the set's first member to the second reader word",
   "words": [
    "[B------:R-:W1:Y:S01] SYNCS.CCTL.IVALL ;",
    "[B------:R1:W1:Y:S01] SHFL.IDX PT, R32, R73, 0x1, 0x1f ;",
    "[B------:R-:W1:Y:S02] LDCU.64 UR6, c[0x0][0x380] ;",
    "[B-1----:R-:W-:Y:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:-:S01] IADD.64 R24, -R2, UR6 ;",
    "[B------:R-:W-:-:S01] MOV R6, R32 ;"
   ],
   "cells": {"what": "grid x front x distance (the members 1 and 4 cycles apart), the set's text and the text with every member on its own barrier and wait; [Server Edition, of]", "measured": {"right": [24, 24], "thread_launches_not_right": [0, 61603840]}, "measured_own_barriers": {"right": [24, 24], "thread_launches_not_right": [0, 61603840]}, "reference_no_flag_on_the_waiting_word": {"right": [24, 24], "thread_launches_not_right": [0, 61603840]}},
   "requests": ["w_yil_fy", "w_yil_f"],
   "files": ["probe_sm120_20261118_b76.json"]
  },
  {
   "card_models": 1,
   "form": "two barriers in the wait mask of the data waiting word",
   "what": "a set `SYNCS.CCTL.IVALL`, `SHFL.IDX`, `LDCU.64` on one write barrier with the yield flag; a shuffle outside the set, on READ barrier 2 and write barrier 3 (the yield flag, stall 4), pends in front of it; the data waiting word `MOV R73, R5` overwrites the shuffles' source register and waits the set's barrier AND read barrier 2; the pending shuffle's register joins the fold behind a word that waits barrier 3",
   "words_of": "the kernel w_yil_f2_bare_w1_f0_d0001 (one warp per SM, no front, the members 1 cycle apart), from the pending shuffle to the second reader word",
   "words": [
    "[B------:R2:W3:Y:S04] SHFL.IDX PT, R71, R73, RZ, 0x1f ;",
    "[B------:R-:W1:Y:S01] SYNCS.CCTL.IVALL ;",
    "[B------:R1:W1:Y:S01] SHFL.IDX PT, R32, R73, 0x1, 0x1f ;",
    "[B------:R-:W1:Y:S02] LDCU.64 UR6, c[0x0][0x380] ;",
    "[B-12---:R-:W-:-:S01] MOV R73, R5 ;",
    "[B------:R-:W-:-:S01] IADD.64 R24, -R2, UR6 ;",
    "[B------:R-:W-:-:S01] MOV R6, R32 ;"
   ],
   "cells": {"what": "grid x front x distance (the members 1 and 4 cycles apart), the set's text and the text with every member on its own barrier and wait; [Server Edition, of]", "measured": {"right": [24, 24], "thread_launches_not_right": [0, 61603840]}, "measured_own_barriers": {"right": [24, 24], "thread_launches_not_right": [0, 61603840]}},
   "requests": ["w_yil_f2"],
   "files": ["probe_sm120_20261118_b76.json"]
  },
  {
   "card_models": 1,
   "form": "the data waiting word in the place cubit's own builds give it, the event pair 101 cycles behind it",
   "what": "a set `SYNCS.CCTL.IVALL`, `SHFL.IDX`, `LDCU.64` on one write barrier with the yield flag, the youngest member at stall 1; the data waiting word `MOV R73, R5` carries the yield flag and waits two barriers, one cycle behind a flagged word that sets no barrier and 4 cycles behind the load; its first reader word (of the load) stands 12 cycles behind it and carries a wait bit of its own; the event word `BAR.SYNC.DEFER_BLOCKING 0x0` (the yield flag, stall 6; behind `WARPSYNC.ALL`, the yield flag, stall 5) waits the SAME barrier again 101 cycles behind the data word; the control holds the same words with no barrier and no wait; a kernel with this word holds a named barrier: a launch of such a kernel may not return",
   "words_of": "the kernel w_yil_ty2_bare_w1_f0_d0001 (one warp per SM, no front, the members 1 cycle apart), from the pending shuffle to the second reader word",
   "words": [
    "[B------:R2:W3:Y:S04] SHFL.IDX PT, R71, R73, RZ, 0x1f ;",
    "[B------:R-:W-:Y:S04] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:Y:S03] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W1:Y:S01] SYNCS.CCTL.IVALL ;",
    "[B------:R1:W1:Y:S01] SHFL.IDX PT, R32, R73, 0x1, 0x1f ;",
    "[B------:R-:W1:Y:S01] LDCU.64 UR6, c[0x0][0x380] ;",
    "[B------:R-:W-:Y:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:Y:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:Y:S01] MOV R72, RZ ;",
    "[B-12---:R-:W-:Y:S01] MOV R73, R5 ;",
    "[B------:R-:W-:Y:S02] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:-:S03] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:Y:S02] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:Y:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:Y:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:Y:S02] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B-1----:R-:W-:-:S06] IADD.64 R24, -R2, UR6 ;",
    "[B------:R-:W-:-:S15] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:-:S15] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:-:S15] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:-:S15] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:-:S15] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:-:S03] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:Y:S05] WARPSYNC.ALL ;",
    "[B-1----:R-:W-:Y:S06] BAR.SYNC.DEFER_BLOCKING 0x0 ;",
    "[B------:R-:W-:-:S01] MOV R6, R32 ;"
   ],
   "cells": {"what": "grid x front x distance (the members 1 and 4 cycles apart), the set's text and the text with every member on its own barrier and wait; [Server Edition, of]", "measured": {"right": [24, 24], "thread_launches_not_right": [0, 61603840]}, "measured_own_barriers": {"right": [24, 24], "thread_launches_not_right": [0, 61603840]}, "control_no_barrier_and_no_wait": {"right": [0, 36], "thread_launches_not_right": [80507136, 92405760]}},
   "requests": ["w_yil_ty2", "w_yil_ty2_n"],
   "files": ["probe_sm120_20261118_b76.json"]
  },
  {
   "card_models": 1,
   "form": "the same data waiting word, the event pair 7 cycles behind it",
   "what": "the text of the form above with the first reader word one cycle behind the data word and the event pair 7 cycles behind it",
   "words_of": "the kernel w_yil_dy2_bare_w1_f0_d0001 (one warp per SM, no front, the members 1 cycle apart), from the pending shuffle to the second reader word",
   "words": [
    "[B------:R2:W3:Y:S04] SHFL.IDX PT, R71, R73, RZ, 0x1f ;",
    "[B------:R-:W-:Y:S04] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:Y:S03] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W1:Y:S01] SYNCS.CCTL.IVALL ;",
    "[B------:R1:W1:Y:S01] SHFL.IDX PT, R32, R73, 0x1, 0x1f ;",
    "[B------:R-:W1:Y:S01] LDCU.64 UR6, c[0x0][0x380] ;",
    "[B------:R-:W-:Y:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:Y:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:Y:S01] MOV R72, RZ ;",
    "[B-12---:R-:W-:Y:S01] MOV R73, R5 ;",
    "[B-1----:R-:W-:-:S01] IADD.64 R24, -R2, UR6 ;",
    "[B------:R-:W-:Y:S05] WARPSYNC.ALL ;",
    "[B-1----:R-:W-:Y:S06] BAR.SYNC.DEFER_BLOCKING 0x0 ;",
    "[B------:R-:W-:-:S01] MOV R6, R32 ;"
   ],
   "cells": {"what": "grid x front x distance (the members 1 and 4 cycles apart), the set's text and the text with every member on its own barrier and wait; [Server Edition, of]", "measured": {"right": [24, 24], "thread_launches_not_right": [0, 61603840]}, "measured_own_barriers": {"right": [24, 24], "thread_launches_not_right": [0, 61603840]}},
   "requests": ["w_yil_dy2"],
   "files": ["probe_sm120_20261118_b76.json"]
  },
  {
   "card_models": 1,
   "form": "the reader into the set's own predicate with a wait bit of its own",
   "what": "a set N,i,gN,gN (an unguarded `LDG.E.CONSTANT`, a `SHFL.IDX`, two guarded `LDG.E.CONSTANT` under ONE predicate) on one write barrier with the yield flag, the third write of the predicate from the lane one cycle in front of the waiting word; the reader of the shuffle's register into the set's own predicate, `ISETP.GE.AND P0`, stands behind the waiting word and carries A WAIT BIT OF ITS OWN (the set's barrier), the yield flag and a register as comparand; the reference is the reader on the one wait, without them",
   "words_of": "the kernel s_nigg_o_cc_ly_bare_w1_f0_d0001 (one warp per SM, no front, the members 1 cycle apart), from the set's first member to the word that folds the predicate",
   "words": [
    "[B------:R1:W1:Y:S01] LDG.E.CONSTANT R32, desc[UR4][R18.64] ;",
    "[B------:R2:W1:Y:S01] SHFL.IDX PT, R33, R73, 0x1, 0x1f ;",
    "[B------:R1:W1:Y:S01] @!P0 LDG.E.CONSTANT R34, desc[UR4][R18.64] ;",
    "[B------:R-:W-:-:S13] ISETP.GE.AND P0, PT, R7, RZ, PT ;",
    "[B------:R1:W1:Y:S02] @!P0 LDG.E.CONSTANT R35, desc[UR4][R18.64] ;",
    "[B------:R-:W-:-:S01] ISETP.NE.AND P0, PT, R31, RZ, PT ;",
    "[B-1----:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B-1----:R-:W-:Y:S01] ISETP.GE.AND P0, PT, R33, R72, PT ;",
    "[B------:R-:W-:-:S01] IADD3 R6, PT, PT, R35, R34, R33 ;",
    "[B------:R-:W-:-:S01] MOV R8, R32 ;",
    "[B------:R-:W-:-:S15] IADD3 R15, PT, PT, R15, 0x1, RZ ;",
    "[B------:R-:W-:-:S15] SEL R24, R4, R5, P0 ;"
   ],
   "cells": {"what": "grid x front x distance (the members 1 and 4 cycles apart), the set's text and the text with every member on its own barrier and wait; [Server Edition, of]", "measured": {"right": [12, 12], "thread_launches_not_right": [0, 30801920]}, "reference_reader_on_the_one_wait": {"right": [12, 12], "thread_launches_not_right": [0, 30801920]}},
   "requests": ["s_nigg_o_cc_ly", "s_nigg_o_cc_l"],
   "files": ["probe_sm120_20261118_b76.json"]
  }
 ],
 "waiter_flag": {
  "measured": "the yield flag on the FIRST WAITING WORD behind a single setter that carries no flag does not change what the word reads: behind each of twenty-one setters of ten kinds the word that carries the wait is right at stall count 1 and at 2 of the setter, with the flag on that word (504 of 504 cells) and without it (504 of 504)",
  "standing": "measured on ONE card model (a card of the Server Edition): not a law",
  "card_models": 1,
  "flag": "the yield flag stands on the word that carries the wait and on no other word; the setter carries none (the member `setter_flag` holds the other case)",
  "controls": "without barrier and wait the reader is not right 1 and 2 cycles behind the setter: for `LDS`, `LDC`, `LDG.E` (the setter of two rows) and `POPC` in probe_sm120_20261118_b79.json (0 of 48 cells at 1 cycle, 0 of 48 at 2); for fourteen setters in the result files of the earlier batches of this diagnostic (probe_sm120_20261113_b71.json, probe_sm120_20261113_b72.json, probe_sm120_20261118_b73.json); for the two special-register words `S2R R32, SR_CgaCtaId` and `S2UR UR12, SR_CgaCtaId` in a batch whose result file is not published here",
  "popc_at_three_cycles": "`POPC R32, R21` with its waiting word at stall count 3: right in 12 of 12 cells with the flag on the waiting word and in 12 of 12 without it",
  "not_measured": "`SYNCS`, `ATOMG` and `F2F` as single setters; distances above 2 behind the twenty setters other than `POPC`",
  "columns": ["a card of the Server Edition"],
  "conditions": {"driver": "610.43.02", "state": "the card with the probe alone, no power limit (the Server Edition model takes no clock offset)", "busy_clock_p50_mhz": {"_b77": [2370.0], "_b79": [2370.0]}, "grids": "1, 8, 9, 12 and 16 warps per SM; 2 CTAs of 9 warps per SM", "fronts": "none; fifteen `STS.128` at stall 4", "launches": 40, "distances": "the setter's stall count 1 and 2 (`POPC` also 3)"},
  "cells": {"what": "setter x grid x front x distance = 21 x 6 x 2 x 2; right = every thread-launch of the cell right; [Server Edition, of]", "flag_right": [504, 504], "no_flag_right": [504, 504], "thread_launches_not_right": [0, 2587361280], "controls_right_at_1": [0, 48], "controls_right_at_2": [0, 48], "popc_at_3_flag_right": [12, 12], "popc_at_3_no_flag_right": [12, 12]},
  "files": ["probe_sm120_20261118_b77.json", "probe_sm120_20261118_b79.json"],
  "setters": [
   {"setter": "[B------:R2:W1:-:S01] SHFL.IDX PT, R32, R21, RZ, 0x1f ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, R32 ;", "requests": ["y_shi", "y_shi_0"]},
   {"setter": "[B------:R-:W1:-:S01] SHFL.BFLY PT, R32, R21, 0x2, 0x1f ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] SEL R24, R21, R32, !P0 ;", "requests": ["y_sbf", "y_sbf_0"]},
   {"setter": "[B------:R-:W1:-:S01] MUFU.EX2 R32, R21 ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, R32 ;", "requests": ["y_mex", "y_mex_0"]},
   {"setter": "[B------:R-:W1:-:S01] MUFU.RCP R32, R21 ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, R32 ;", "requests": ["y_mrc", "y_mrc_0"]},
   {"setter": "[B------:R-:W1:-:S01] MUFU.LG2 R32, R21 ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] FADD.FTZ R32, R32, R26 ;", "waiter_without_the_flag": "[B-1----:R-:W-:-:S06] FADD.FTZ R32, R32, R26 ;", "requests": ["y_mlg", "y_mlg_0"]},
   {"setter": "[B------:R-:W1:-:S01] LDS R32, [R9+0x20] ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, R32 ;", "requests": ["y_lds", "y_lds_0"]},
   {"setter": "[B------:R-:W1:-:S01] LDS.128 R32, [R9+0x20] ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, R34 ;", "requests": ["y_l128", "y_l128_0"]},
   {"setter": "[B------:R-:W1:-:S01] LDC R32, c[0x0][0x388] ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, R32 ;", "requests": ["y_ldc", "y_ldc_0"]},
   {"setter": "[B------:R-:W1:-:S01] LDC.64 R32, c[0x0][0x380] ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, R32 ;", "requests": ["y_lc64", "y_lc64_0"]},
   {"setter": "[B------:R-:W1:-:S01] LDC R32, c[0x0][R13+0x388] ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, R32 ;", "requests": ["y_lcx", "y_lcx_0"]},
   {"setter": "[B------:R-:W1:-:S01] LDG.E R32, desc[UR4][R18.64] ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, R32 ;", "requests": ["y_ldg", "y_ldg_0"]},
   {"setter": "[B------:R-:W1:-:S01] @P0 LDG.E.CONSTANT R32, desc[UR4][R18.64] ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, R32 ;", "requests": ["y_lgc", "y_lgc_0"]},
   {"setter": "[B------:R-:W1:-:S01] LDG.E R32, desc[UR4][R18.64] ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] IADD3 R15, PT, PT, R15, 0x1, RZ ;", "requests": ["y_lgo", "y_lgo_0"]},
   {"setter": "[B------:R-:W1:-:S01] LDCU UR12, c[0x0][0x388] ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, UR12 ;", "requests": ["y_lcu", "y_lcu_0"]},
   {"setter": "[B------:R-:W1:-:S01] LDCU.64 UR12, c[0x0][0x380] ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, UR12 ;", "requests": ["y_lcu64", "y_lcu64_0"]},
   {"setter": "[B------:R-:W1:-:S01] S2R R32, SR_CgaCtaId ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, R32 ;", "requests": ["y_s2r", "y_s2r_0"]},
   {"setter": "[B------:R-:W1:-:S01] S2R R32, SR_LTMASK ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, R32 ;", "requests": ["y_ltm", "y_ltm_0"]},
   {"setter": "[B------:R-:W1:-:S01] S2R R32, SR_TID.X ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S06] SHF.R.U32.HI R24, RZ, 0x5, R32 ;", "requests": ["y_tid", "y_tid_0"]},
   {"setter": "[B------:R-:W1:-:S01] I2F.RP R32, R21 ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, R32 ;", "requests": ["y_i2f", "y_i2f_0"]},
   {"setter": "[B------:R-:W1:-:S01] S2UR UR12, SR_CgaCtaId ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, UR12 ;", "requests": ["y_s2ur", "y_s2ur_0"]},
   {"setter": "[B------:R-:W1:-:S01] POPC R32, R21 ;", "waiter_with_the_flag": "[B-1----:R-:W-:Y:S01] MOV R24, R32 ;", "requests": ["y_popc", "y_popc_0"]}
  ]
 }
}''')
BARRIER_ARM_BASIS_2 = (". On two card models (2026-11-13 and 2026-11-18, tools/stallfloor/probe.py 34; the members `setter_flag` and "
                       "`wait_forms`): behind each of fourteen setters a waiter that is the next word is right from stall count 2 with the "
                       "yield flag on the SETTER and from stall count 1 without it - the flag stands on the setter, the waiter carries none; "
                       "`cycles` stays 2")
BARRIER_ARM_BASIS_3 = (". On ONE card model (2026-11-18, the builds ten to twelve of tools/stallfloor/probe.py 34; every row of the "
                       "members says on how many card models it stands, `card_models`): the prohibition binds behind three more "
                       "setters read by their served first readers (`setter_flag`), five more forms of a set's waits are right in "
                       "every measured cell (`wait_forms`), and the yield flag on the first waiting word behind a single setter "
                       "without the flag does not change what the word reads at stall count 1 and 2 (`waiter_flag`, twenty-one "
                       "setters) - measurements, a law only with a second card model's column; `cycles` stays 2")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("census")
    ap.add_argument("out")
    ap.add_argument("--floors", nargs="*", default=[])
    ap.add_argument("--census-desc", default="166 nvcc / ptxas cubins of the production sm_120 census (FlashInfer, DeepGEMM, "
                    "b12x, CUTLASS MXFP8), 1 811 600 instructions, cubit disassemble --frozen; fixed-latency producer -> "
                    "consumer pairs on fall-through paths")
    ap.add_argument("--v6", nargs="*", default=[], help="results of the population harness (cellfloor_run.py cells.json)")
    ap.add_argument("--mma-registers", help="MMA result register k -> an ordinary reader, per register "
                    "(mma_result_registers_sm120_*.json): the `to_data` row must hold every register's floor")
    ap.add_argument("--result-census", help="the census split by RESULT register (result_register_census.py): "
                    "cells for the readers of an upper register of the producers in RESULT_HIGH")
    ap.add_argument("--result-floors", help="silicon by result register (stall_floors_sm120_20261110_em_blk3.json: "
                    "IMAD.WIDE low / high register -> reader, either register of the pair form of CS2R -> reader)")
    a = ap.parse_args()
    assert bool(a.result_census) == bool(a.result_floors), "--result-census and --result-floors go together"
    rows = json.load(open(a.census))
    cells = {}
    skipped = collections.Counter()
    for r in rows:
        p, c, role = r["prod"], r["cons"], r["role"]
        if p in VARIABLE or p in MMA:
            skipped["variable/mma producer"] += 1
            continue
        if role == "r?":
            skipped["unknown role"] += 1
            continue
        if r["n"] < MIN_N or r["n_min"] < MIN_AT:
            skipped["sparse"] += 1
            continue
        L = r["min"]
        if role in ("g", "gc"):
            if L > 15:
                skipped["never tight"] += 1
                continue
            L = max(L, 5)
        else:
            if L > MAX_TIGHT:
                # the pair never occurs tightly in the census: its minimum is the shape of the code, not a latency -> default
                skipped["never tight"] += 1
                continue
            L = max(L, 4)                  # floor_global of the 2026-11-03 silicon run; late-read operands are not modelled
        cells[(p, c, role)] = dict(L=L, n=r["n"], n_min=r["n_min"], census_min=r["min"])
    # cells on a measured floor (MEASURED_MIN_CELLS): the census minimum, checked against the census row and the probe's files
    by_key = {(r["prod"], r["cons"], r["role"]): r for r in rows}
    here = os.path.dirname(os.path.abspath(__file__))
    uniform = json.load(open(os.path.join(here, "census_pairs_uniform_sm120.json")))["rows"]
    measured_min = {}
    for m in MEASURED_MIN_CELLS:
        key = (m["producer"], m["consumer"], m["role"])
        if m.get("census") == "uniform":
            # the verifier's census: the role's minimum over the role sets that hold it
            assert key not in by_key, f"{key}: the census pairs have a row -- read it there"
            sets = [u for u in uniform if (u["producer"], u["consumer"]) == key[:2] and key[2] in u["roles"].split("+") and u["below"] == "uniform"]
            assert sets, f"{key}: no role set of the uniform census holds the role"
            mn = min(u["min"] for u in sets)
            r = {"min": mn, "n_min": sum(u["n_min"] for u in sets if u["min"] == mn), "n": sum(u["n_below"] for u in sets)}
        else:
            r = by_key[key]
        assert key not in cells or cells[key]["L"] > r["min"], f"{key}: the dense-cell rule gives {cells.get(key)} already"
        floors, models = [], set()
        for fn in m["probe_files"]:
            for rq in [m["request"]] + m.get("also", []):
                req = [q for q in json.load(open(os.path.join(here, fn)))["requests"] if q["id"] == rq]
                assert len(req) == 1, f"{key}: {fn} has {len(req)} requests `{rq}`"
                fl = req[0]["floor"]
                assert isinstance(fl["binding"], int) and fl["binding"] <= r["min"] and not fl["oracle_failures"] and not req[0]["errors"], \
                    f"{key}: {fn} does not carry a floor at or below the census minimum {r['min']}: {fl}"
                if rq == m["request"]:
                    floors.append(fl["binding"])
            models.add("workstation" if "_ws_" in fn else "server")
        assert models == {"server", "workstation"}, f"{key}: a cell on a measured floor needs both card models, not {models}"
        capped = any(fn.endswith("_capped.json") for fn in m["probe_files"])
        cards = ("its _ws_ files: a Server Edition card, a Workstation Edition card alone and at its 400-W limit" if capped
                 else "its _ws_ file: a Server Edition card and a Workstation Edition card, each with the probe alone")
        if m.get("census") == "uniform":
            basis = (f"ptxas census min {r['min']} x {r['n_min']} of {r['n']} pairs below the default -- the verifier's reading of the frozen census "
                     f"(tools/stallfloor/census_pairs_uniform_sm120.json: the certified operand sets have no row for the pair, it took the default); ")
        else:
            why = (f"fewer than {MIN_AT} pairs at the minimum" if r["n_min"] < MIN_AT else "fewer pairs than a dense cell needs" if r["n"] < MIN_N
                   else "a minimum below the global floor of 4")
            took = "the cell was clamped to 4" if key in cells else "the pair took the default"
            basis = f"ptxas census min {r['min']} x {r['n_min']} of {r['n']} pairs -- no dense cell ({why}: {took}); "
        measured_min[key] = {
            "producer": key[0], "consumer": key[1], "role": key[2], "L": r["min"],
            "basis": basis + "the census minimum is the cell because the pair's floor is measured at or below it on both card models "
                             "(never closer than ptxas ever stands)",
            "silicon": f"floor {' | '.join(str(f) for f in floors)} for the form {m['form']} -- tools/stallfloor "
                       f"{m['probe_files'][0][:-len('.json')]} (request `{m['request']}`) and {cards}; the cell is ptxas's minimum, not the floor"}
        cells.pop(key, None)
    # no role set of the verifier's census may come out below ptxas's own minimum for the set: the distance the table asks of a
    # set is the largest of its roles' cells; a set with a role that has no cell keeps a default
    final = {k: v["L"] for k, v in cells.items()}
    final.update({k: v["L"] for k, v in measured_min.items()})
    for u in uniform:
        if not any((u["producer"], u["consumer"]) == k[:2] for k in measured_min):
            continue
        ls = [final.get((u["producer"], u["consumer"], x)) for x in u["roles"].split("+")]
        assert any(l is None for l in ls) or max(ls) >= u["min"], \
            f"the cells of {u['producer']} -> {u['consumer']} put the role set {u['roles']} at {max(ls)} where ptxas's own minimum is {u['min']} ({u['forms_at_min']})"
    # MMA rows, written out explicitly (census: HMMA -> HMMA accumulate 29 x 2 368, HMMA -> FADD / FMUL 28; any MMA -> MMA 16)
    out_cells = []
    for (p, c, role), v in sorted(cells.items()):
        out_cells.append({"producer": p, "consumer": c, "role": role, "L": v["L"],
                          "basis": f"ptxas census min {v['census_min']} x {v['n_min']} of {v['n']} pairs"})
    for w in WRITTEN_CELLS:
        assert (w["producer"], w["consumer"], w["role"]) not in cells and (w["producer"], w["consumer"], w["role"]) not in measured_min
        out_cells.append(dict(w))
    out_cells += [measured_min[k] for k in sorted(measured_min)]
    doc = {
        "arch": "sm_120",
        "schema": 1,
        "comment": "Fixed-latency dependency table of cubit's opt-in dependency-aware stall model (CUBIT_SCHED2_LAT). L = "
                   "minimum issue distance in stall units (sum of the stall counts from the producer to the consumer on "
                   "every control-flow path) between a producer WITHOUT a write barrier and a consumer reading its result "
                   "in the given operand role. role: r<k> / a<k> = register / address-base operand at position k among the "
                   "non-predicate operands (destination = 0), u<k> = uniform register, p = predicate operand, g = guard, "
                   "gc = guard of a control-flow instruction, * = any role; a trailing h = a register above the named one of a "
                   "multi-register operand (the high half of a 64-bit addend / address: read later than the low half).",
        "provenance": {
            "census": a.census_desc,
            "dense_cell": f">= {MIN_N} pairs, >= {MIN_AT} at the minimum, minimum <= {MAX_TIGHT} (guards <= 15); every other pair takes a default",
            "silicon": [],
        },
        "defaults": {
            "data": 6, "mma_input": 7, "guard": 13, "pred_operand": 6, "uniform": 13,
            "comment": "cells the census does not show densely: the largest dense value of the kind (ALU data 6 = MOV -> SEL "
                       "false operand / SEL -> IMAD.WIDE addend; -> MMA fragment 7; predicate -> guard 13; uniform 13 = R2UR)",
        },
        "mma": {"classes": MMA, "to_mma_accumulate": 29, "to_data": 28,
                "comment": "MMA result (never scoreboarded): -> the C operand of an MMA 29 (census 2 368 at 29, never less on a "
                           "chain), -> any other consumer 28 (census: HMMA -> FADD / FMUL 28). Silicon 2026-11-10 (harness "
                           "v5b, 20 launches): HMMA -> FMUL floor 20; the accumulate operand of the next HMMA and two "
                           "HMMAs back to back are clean at every distance 1..30 (the tensor pipe interlocks them) -- "
                           "the rows keep ptxas's spacing"},
        "resources": [
            {"name": "mma", "members": MMA, "spacing": 16, "basis": "census: two MMAs never closer than 16 (7 060 HMMA / 5 351 QMMA pairs at 16)"},
            {"name": "mem", "members": ["LDS", "LDSM", "STS", "STSM", "LDG", "STG", "LDL", "STL", "LD", "ST", "LDGSTS", "SHFL",
                                        "ATOM", "ATOMG", "ATOMS", "RED", "REDG"], "spacing": 4,
             "basis": "census: memory-pipe instructions with anything between them never closer than 4 (47 975 at 4)"},
            {"name": "ldc", "members": ["LDC"], "spacing": 8, "basis": "census: LDC -> LDC 8 (1 209 adjacent, 2 172 non-adjacent at 8, never less)"},
            {"name": "mul", "members": ["IMAD", "IMAD.WIDE", "IMAD.HI"], "spacing_by_first": {"IMAD": 2, "IMAD.HI": 2, "IMAD.WIDE": 4},
             "basis": "census: IMAD -> IMAD / IMAD.WIDE 2 (5 345 / 3 678 adjacent at 2), IMAD.WIDE -> IMAD / IMAD.WIDE 4"},
            {"name": "bar", "members": ["BAR"], "then": {"mem": 6, "bar": 8},
             "basis": "census: BAR -> shared / global memory 6 (BUG-479: S05 fails on silicon), BAR -> BAR 8"},
        ],
        "barrier_arm": {"cycles": 2, "basis": "census: 0 of ~70 000 scoreboard setter -> first waiter pairs closer than 2 "
                        "(write barriers: MUFU 5 989 at 2, SHFL 10 096, LDS 3 360, I2F 2 520 ...; read barriers 3 443 at 2); an adjacent "
                        "waiter always finds the setter at S02 or more. Silicon 2026-11-10: `MUFU [W:Y:S01]` + waiter at S01 reads the "
                        "stale register (sparse_mla_prefill_v41 under CUBIT_SCHED2: softmax exp2, epilogue log2); in isolation "
                        "(harness v5b): MUFU / SHFL / LDC / LDS setter with yield at S01 and its waiter next = every thread wrong, "
                        "without yield, at S02 or with one instruction between = clean" + BARRIER_ARM_BASIS_2 + BARRIER_ARM_BASIS_3,
                        "setter_flag": BARRIER_ARM_MEASURED["setter_flag"], "wait_forms": BARRIER_ARM_MEASURED["wait_forms"],
                        "waiter_flag": BARRIER_ARM_MEASURED["waiter_flag"]},
        "variable_latency": VARIABLE,
        "cells": out_cells,
    }
    # silicon floors: {"cells": [{"producer","consumer","role","floor_d0", ...}], "run": "..."}
    idx = {(c["producer"], c["consumer"], c["role"]): c for c in out_cells}
    for fp in a.floors:
        fl = json.load(open(fp))
        doc["provenance"]["silicon"].append(fl.get("run", fp))
        for f in fl["cells"]:
            key = (f["producer"], f["consumer"], f["role"])
            floor = f["floor_d0"]
            c = idx.get(key)
            if c is None:
                # no dense census cell: the pair keeps the default; the floor is on record only
                doc["provenance"].setdefault("measured_without_cell", []).append(
                    {"producer": key[0], "consumer": key[1], "role": key[2], "floor_d0": floor})
                continue
            elif isinstance(floor, int) and floor > c["L"]:
                c["basis"] += f"; RAISED from {c['L']} by the silicon floor"
                c["L"] = floor
            if f.get("superseded"):
                if key not in SUPERSEDED_SILICON:
                    raise SystemExit(f"{fp}: the row of {' / '.join(key)} names what superseded it and SUPERSEDED_SILICON has no sentence for its cell")
                c["silicon"] = SUPERSEDED_SILICON[key]
                continue
            c["silicon"] = (f"floor d0 S{floor:02d}" if isinstance(floor, int) else str(floor)) + (f" ({f['note']})" if f.get("note") else "")
    # population harness v6: per cell, kernels at the tested latency Lt and at Lt - 1 (random registers / yield / neighbours)
    for fp in a.v6:
        v6 = json.load(open(fp))
        doc["provenance"]["silicon"].append(v6.get("run", fp))
        per = collections.defaultdict(dict)
        for c in v6["cells"]:
            per[c["cell"]][c["rel"]] = c
        for cell, d in per.items():
            p, rest = cell.split(" -> ")
            cc, role = rest.rsplit(" ", 1)
            c = idx.get((p, cc, role))
            at, below = d.get(0), d.get(-1)
            if at is None:
                continue
            Lt = at["L"]
            note = f"v6 S{Lt:02d}: {at['failing']}/{at['kernels']} kernels fail"
            if below is not None:
                note += f", S{Lt - 1:02d}: {below['failing']}/{below['kernels']}"
            if c is None:
                # a defaulted pair: the default was tested, no cell is created from it; the floor the sweep shows (the
                # smallest tested stall that is clean with every larger one clean) goes on record
                clean = sorted(Lt + rel for rel, x in d.items() if x["failing"] == 0)
                dirty = [Lt + rel for rel, x in d.items() if x["failing"]]
                floor = min((st for st in clean if all(st > b for b in dirty)), default=None)
                if floor is not None and dirty:
                    doc["provenance"].setdefault("measured_without_cell", []).append(
                        {"producer": p, "consumer": cc, "role": role, "floor_d0": floor, "harness": "v6"})
                continue
            if at["failing"] and c["L"] <= Lt:
                # the tested latency fails on silicon and the cell is not above it: never ship that
                c["basis"] += f"; RAISED from {c['L']} (fails on silicon at S{Lt:02d}) to the data default"
                c["L"] = max(Lt + 1, doc["defaults"]["data"])
            c["silicon"] = (c.get("silicon", "") + "; " if c.get("silicon") else "") + note
    if a.result_census:
        result_high(a, doc, idx)
    doc["comment"] += PRODUCER_FORMS_COMMENT
    doc["producer_forms"] = PRODUCER_FORMS
    out_cells.sort(key=lambda c: (c["producer"], c["consumer"], c["role"]))
    if a.mma_registers:
        mr = json.load(open(a.mma_registers))
        # floor of a result register = one above the last distance at which a reader saw a wrong value
        floors = collections.defaultdict(int)
        for fl in mr["floors"]:
            if fl["last_wrong"] is not None:
                floors[fl["result_register"]] = max(floors[fl["result_register"]], fl["last_wrong"] + 1)
        worst = max(floors.values())
        assert doc["mma"]["to_data"] >= worst, f"MMA -> reader row {doc['mma']['to_data']} below a measured floor {worst}"
        by_floor = collections.defaultdict(list)
        for r, fl in sorted(floors.items()):
            by_floor[fl].append(str(r))
        per = "; ".join(f"result register{'s' if len(rs) > 1 else ''} {' / '.join(rs)}: wrong up to {fl - 1}, clean from {fl}"
                        for fl, rs in sorted(by_floor.items()))
        old = "HMMA -> FMUL floor 20; "
        assert old in doc["mma"]["comment"]
        doc["mma"]["comment"] = doc["mma"]["comment"].replace(
            old, f"HMMA -> FMUL floor 20 on result registers 0 and 1; a second probe (result register k -> FMUL / FADD, "
                 f"nothing waited, distances 23..32): {per} -- `to_data` is the floor of the upper registers, without a "
                 f"margin; ")
        doc["provenance"]["silicon"].append(
            f"MMA result registers ({mr['what']}), {mr['geometry']}, core clock <= 2 370 MHz, 2026-11-10: "
            f"{len(mr['kernels'])} kernels")
    with open(a.out, "w") as f:
        f.write("{\n")
        keys = [k for k in doc if k != "cells"]
        for k in keys:
            f.write(f" {json.dumps(k)}: {json.dumps(doc[k])},\n")
        f.write(' "cells": [\n')
        f.write(",\n".join("  " + json.dumps(c) for c in out_cells))
        f.write("\n ]\n}\n")
    print(f"{len(out_cells)} cells; skipped {dict(skipped)}")
    by = collections.Counter(c["L"] for c in out_cells)
    print("L histogram:", sorted(by.items()))


def result_high(a, doc, idx):
    """`result_high`: the cells of the readers of an UPPER register of a multi-register result (RESULT_HIGH), the floor of
    such a reader without a cell, and the silicon of --result-floors on the cells of the producers it measured."""
    hidx = {}
    for r in json.load(open(a.result_census)):
        p, c, role = r["prod"], r["cons"], r["role"]
        if r["part"] != "high" or p not in RESULT_HIGH or role == "r?":
            continue
        if r["n"] < MIN_N or r["n_min"] < MIN_AT or r["min"] > MAX_TIGHT:
            continue                       # not dense, or never tight: no cell of its own (the rule of the ordinary cells)
        hidx[(p, c, role)] = {"producer": p, "consumer": c, "role": role, "L": max(r["min"], 4),
                              "basis": f"ptxas census min {r['min']} x {r['n_min']} of {r['n']} readers of the result's upper register"}
    fl = json.load(open(a.result_floors))
    hi, lo, pair = {}, {}, {}
    for f in fl["floors"]:
        if f["family"] not in ("wh", "cs"):
            continue
        p, rest = f["what"].split(" -> ")
        c, role = rest.rsplit(" ", 1)
        floor = max(f[g]["clean_from"] for g in fl["geometries"])      # the strictest geometry of the run
        d = {"hi": hi, "lo": lo}.get(f["which"], pair)
        d[(p, c, role)] = max(d.get((p, c, role), 0), floor)
    assert hi and all(k[0] in RESULT_HIGH for k in hi), "the result-register floors are of the producers in RESULT_HIGH"
    doc["comment"] += (" `result_high`: a reader of an UPPER register of a multi-register result of the producers named there"
                       " (the high half of a 64-bit product is ready later than its low half) takes the larger of the pair's"
                       " cell and the cell of `result_high.cells` for it; where the census has no dense cell for the upper"
                       " register it takes the pair's cell, but never less than `result_high.floor`.")
    doc["provenance"]["silicon"].append(
        f"result registers ({fl['run']}; {', '.join(fl['geometries'].values())}; 20 launches per kernel, S15 reference): "
        f"IMAD.WIDE low / high register -> reader, {len(lo)} + {len(hi)} pairs; either register of the pair form "
        f"`CS2R Rn, SRZ` -> reader, {len(pair)} pairs")
    # the pair form of CS2R: one number for both registers; a floor above the cell raises it (the rule of --floors)
    for key, floor in sorted(pair.items()):
        c = idx.get(key)
        if c is None:
            doc["provenance"].setdefault("measured_without_cell", []).append(
                {"producer": key[0], "consumer": key[1], "role": key[2], "floor_d0": floor, "harness": "pr-em-3"})
            continue
        if floor > c["L"]:
            c["basis"] += f"; RAISED from {c['L']} by the silicon floor"
            c["L"] = floor
        c["silicon"] = ((c["silicon"] + "; ") if c.get("silicon") else "") + (
            f"floor d0 S{floor:02d} on either register of the pair form `CS2R Rn, SRZ` (the census pairs are the 32-bit form)")
    measured = []
    for key in sorted(set(hi) | set(lo)):
        c, h = idx.get(key), hidx.get(key)
        if c is not None and key in lo:
            assert lo[key] <= c["L"], f"{key}: the cell {c['L']} is below the low register's floor {lo[key]}"
        if h is not None and key in hi:
            assert hi[key] <= h["L"], f"{key}: the upper register's cell {h['L']} is below its floor {hi[key]}"
            h["silicon"] = f"floor d0 S{hi[key]:02d}"
        measured.append({"producer": key[0], "consumer": key[1], "role": key[2], "floor_low": lo.get(key),
                         "floor_high": hi.get(key), "cell": c["L"] if c else None, "cell_high": h["L"] if h else None})
    floor = max(hi.values())
    for m in measured:                     # what a reader of the upper register is charged, pair by pair
        if m["floor_high"] is None:
            continue
        dflt = doc["defaults"]["data"]
        price = max(m["cell"], m["cell_high"]) if m["cell_high"] is not None and m["cell"] is not None else (
            m["cell_high"] if m["cell_high"] is not None else (max(m["cell"], floor) if m["cell"] is not None else dflt))
        assert price >= m["floor_high"], f"{m}: an upper-register reader is charged {price}"
        m["charged_high"] = price
    doc["result_high"] = {
        "producers": RESULT_HIGH, "floor": floor,
        "basis": "the largest floor measured for a reader of the upper register of an IMAD.WIDE result (silicon: -> IADD3 / LEA / "
                 "LOP3 / SHF / MOV / SEL 5, -> ISETP / IMAD 4, -> STS data 3; the low register 3 / 3 / 3 / 3 / 2 / 2 / 2 / 1 / 1); "
                 "ptxas reads the upper register never closer than 5, or 4 into the multiplier (census split by result register)",
        "cells": [hidx[k] for k in sorted(hidx)],
        "measured": measured,
    }


if __name__ == "__main__":
    main()
