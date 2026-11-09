#!/usr/bin/env python3
"""The long tail of KNOWN_ISSUES T1: verify the remaining harvest rows of sm120 field by field over the whole
128-bit word with nvdisasm 13.1 and tag the ones that hold (session G run 5, 2026-11-07).

The 2026-06..08 harvest learned its rows from compiler output. The lattice families (LDG.256 / STG.256 / REDG /
the compare, FP32 and conversion families) were rebuilt whole by their own probes; what is left is ~1 400 rows on
~500 keys of ~110 mnemonics, mostly one or two rows per key -- too heterogeneous for one law per family. This
probe measures each row on its own terms:

  1. the row's canonical word: `and_base` with every field at a value whose single-bit flips all change the
     printed operand (distinct register numbers, a 0x5a5a.. immediate pattern, `PT` predicates, the guard at 7),
     checked legal with nvdisasm (two fallback value sets);
  2. the full circumference: every bit 0..104 and the four `.reuse` bits 122..125 flipped one at a time, each
     word named by nvdisasm; the texts are diffed token by token against the canonical text and every bit gets
     a class: `field` (moves exactly the operand token the declared field names), `guard` (the guard token),
     `modifier` (changes the mnemonic / modifier token only: another group's word), `operand_other` (changes an
     operand the row has no field for: a neighbouring form, a sign or `.reuse` bit the harvest never declared),
     `inert` (same text), `illegal` (nvdisasm rejects), `complex` (several tokens move);
  3. cubit's own decode / print / re-encode of every word (`examples/audit_words.rs`) and the keys cubit would
     look the vendor texts up under (`examples/text_keys.rs`);
  4. the census witnesses of the row (T-10's 249 929 distinct production words, `--census`), up to three per row,
     named by nvdisasm with their own control code.

A row is **measured** when every declared field bit moves its own token (bits whose flip nvdisasm rejects are
allowed inside a field: value-range limits), no bit outside the fields moves an operand of the same form, the
canonical word decodes in cubit to the row itself with the vendor's text and re-encodes bit-exact, and every
census witness does too. `apply` then tags the row (`_src`, `_note`), sets `variable_mask` to exactly the field
bits (fail closed on the text-inert bits, the convention of every measured family), adds the `.reuse` fields the
sweep found (bits 122..125 printing `.reuse` on a register operand of the row) and retires the keys the verdict
names (`key_aliases` to the key cubit already decodes the canonical word through -- the shadowed dotted twins --
or documented deletions of keys whose canonical word nvdisasm rejects). Everything else stays a harvest row and is
listed in the verdict with its reason (the named exceptions of `G/NEEDS_OWNER.md`).

Fixture (`tests/fixtures/sm120_rows_<family>_nvdisasm.jsonl`): one header line (`nvdisasm`, its sha256, the
arch, the family, the control code used) and one line per row:
  {"key", "group", "w0", "t0", "fields": [[shift, bits, tok, ext], ...],
   "field": [[bit, text], ...], "guard": [[bit, text], ...], "modifier": [[bit, text], ...],
   "operand_other": [[bit, text], ...], "complex": [[bit, text], ...], "inert": [bits], "illegal": [bits],
   "witnesses": [[word, text], ...], "status": "measured" | "<reason>"}
The probe words are `w0 ^ (1 << bit)` (or-ed with the header's control code); the witnesses carry their own.

    probe --family <name> [--table tables/sm120.json] [--census G/census/words_out_main.jsonl] [--jobs 24]
    apply <sm120.json> --family <name> [--verdict <probe's verdict.json>]
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import difflib
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

CTRL = 0x000f_e200 << 96
SCHEDULE = nvprobe.SCHEDULE
SWEEP_BITS = list(range(0, 105)) + [122, 123, 124, 125]
DATE = "2026-11-07"
NVDISASM = "/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm"

# family -> base mnemonics (the key's first dotted part before the operand signature)
FAMILIES = {
    "tensor": ["QMMA", "HMMA", "OMMA", "DMMA", "IMMA"],
    "half": ["HFMA2", "HMNMX2", "HADD2", "HSET2", "F2FP", "I2FP", "F2IP", "I2IP", "UF2FP", "UI2FP", "F2F", "UF2I", "UI2F"],
    "intalu": ["VIMNMX", "VIMNMX3", "IADD", "IMAD", "IADD3", "IMNMX", "IABS", "VIADD", "SGXT", "BMSK", "PRMT", "LOP3", "SEL", "MOV",
               "FLO", "POPC", "BREV", "R2UR", "LDC", "S2R", "CS2R", "MOV64IUR", "LDCU", "S2UR", "FHADD", "DMUL", "DADD"],
    "uniform": ["USHF", "ULEA", "ULOP3", "UFLO", "UMOV", "UIADD3", "UIMAD", "USEL", "UIMNMX", "UBMSK", "UVIMNMX", "UPRMT",
                "UCLEA", "UBREV", "UPOPC", "UISETP", "REDUX", "ELECT"],
    "memory": ["LDG", "STG", "LD", "ST", "LDS", "STS", "LDL", "STL", "LDGSTS", "LDGMC", "LDSM", "STSM", "MOVM", "CCTL",
               "QSPC", "LDGDEPBAR", "UTMALDG", "UTMASTG", "UTMACCTL", "UTMACMDFLUSH", "UBLKCP", "UBLKRED", "UBLKPF"],
    "atomic": ["ATOMG", "ATOM", "ATOMS", "REDG"],
    "control": ["WARPSYNC", "CALL", "BSSY", "BSYNC", "EXIT", "BREAK", "BAR", "MEMBAR", "NOP", "YIELD", "PREEXIT", "ERRBAR",
                "CGAERRBAR", "ACQBULK", "ACQSHMINIT", "NANOSLEEP", "BMOV", "UCGABAR"],
    # T-23 (2026-11-08): the mnemonics of sm121a's / sm103a's long tail that no family above and no family probe covers
    # (the TMA reduce / prefetch, the warp-level shuffles / votes / match, the fences, the double-precision FMA, the
    # leftover rows of mnemonics whose sm120 family probes measured other keys)
    "misc": ["UTMAREDG", "UTMAPF", "SHFL", "VOTE", "VOTEU", "MATCH", "B2R", "CS2UR", "SYNCS", "FENCE", "BPT", "SULD", "USETMAXREG",
             "DFMA", "FFMA", "FMNMX", "HMUL2", "PLOP3", "UPLOP3", "UFSETP", "UFFMA", "UFSEL", "UFADD", "UFMUL", "FSEL", "FSET",
             "FCHK", "HSETP2", "UTCCP", "UTCQMMA", "UTCHMMA", "VIADDMNMX", "CREDUX", "LDTM", "STTM",
             # SHF / LEA have sm120 family probes (rebuilt whole there); on the other tables their rows are verified per row
             "SHF", "LEA"],
}


# (key, group) -> reason: rows whose structure nvdisasm confirms but which stay harvest on purpose (named in
# G/NEEDS_OWNER.md): the probe reports them as `exception`, apply leaves them, the test lists them
EXCEPTIONS: dict[str, dict[tuple[str, str], str]] = {
    # (the four PT-elided `IMAD.HI` / `R2UR.FILL` rows of G's NEEDS 11 -- the carry-out / predicate at PT is elided by
    # the vendor, a spelling whose plain key had no `HI` / `HI,X` / `FILL` group -- left this table on 2026-11-08:
    # session T-19 added the four plain groups (R's decision, the ISETP precedent: PT baked at [83:81]); the shorter plain
    # key wins the PT words, the `_P_` rows keep the explicit-predicate words, both measured)
    "control": {
        ("WARPSYNC.COLLECTIVE_R_II", ""): "the immediate is a 50-bit field the vendor prints whole (0x169696969696978 for the "
                                         "probe's pattern); cubit's row reads 20 bits of it -- the collective mask / target law "
                                         "needs its own probe (G/NEEDS_OWNER.md 10)",
    },
}
# key prefix -> reason: whole mnemonics / keys left harvest on purpose although the probe verifies them. Run 5
# (2026-11-07) kept 192 rows of HFMA2 / HADD2 / F2IP / F2F / I2IP / LDGSTS / LDS / STS / LDL / STL / MOVM / LDC / ATOMS
# here because the 2026-08/09 bug-wave tests (bug148 / 163 / 164 / 167 / 172 / 188 / 204 / 226e / 265 / 271 / 274 /
# 279 / 285 / 288 / 311 / 330 / 340 / 359 / 360 / 413ii / 415 / 419 / 420 / 425 / 425b, 46 binaries / 67 tests) pinned
# their harvest structure or their tolerant decode of text-inert bits (status `exception` in the fixtures, G/NEEDS_OWNER.md
# 12). Session T-18 (2026-11-08) re-pinned those suites to the measured doctrine and lifted the pin: the table is empty,
# the rows take the status their measurement gives them (measured / alias / dead / harvest, like every other row).
EXCEPTION_PREFIXES: dict[str, dict[str, str]] = {}
# hand decisions the shadow rule cannot make on its own (each one measured in the family's note):
#   MANUAL_ALIAS: key -> target. The integer spelling `S2R_R_II` of the system-register read (nvdisasm prints `SR90`
#   for an unnamed code, cubit decodes that spelling through the junk key) -> `S2R_R_L`; the dotted `UBMSK.W_*` twins
#   of `UBMSK_*`'s `W` group (same text, one text-inert bit apart: the encoder mints the plain row's word).
#   MANUAL_DEAD: (key, group) -> the key whose row decodes the group's words afterwards. The harvest named the `!` of
#   IMAD.X's carry-in predicate a modifier (`B90`); the `U32,WIDE,X` row of the same key carries bit 90 as a field.
#   The integer spelling `HFMA2_R_R_II_II_R` of the f16-pair immediate form -> `HFMA2_R_R_FI_FI_R` (the FMUL_R_R_II
#   precedent: the hexadecimal literal still encodes through the alias; its RELU groups' words have the dotted
#   `HFMA2.*.RELU_R_R_FI_FI_R_P` rows).
#   `ATOMS_R_ARI` (one group, `32,INC,POPC`, URZ baked at [71:64]) -> `ATOMS_R_ARURI`: the vendor spells the word
#   `[R16+URZ+imm]`, the uniform-indexed form with URZ, which the measured `_ARURI` row's UR field covers (0 census
#   witnesses on either; the harvest `_ARI` row claimed the inert-bit neighbours the measured row fails closed on and
#   printed them `[imm]`, bug188's pin).
#   T-19 (2026-11-08): `IADD.X_R_P_R_R_R` -> `IADD_R_P_R_R_P` (a one-sample harvest row -- P2 / P2 / ~Ra baked, only the
#   registers variable -- whose word is the measured `X` group's of the plain key with the carry-in predicate spelled; no
#   test names the key).
MANUAL_ALIAS: dict[str, dict[str, str]] = {
    "intalu": {"S2R_R_II": "S2R_R_L", "IADD.X_R_P_R_R_R": "IADD_R_P_R_R_P"},
    "uniform": {"UBMSK.W_UR_UR_II": "UBMSK_UR_UR_II", "UBMSK.W_UR_UR_UR": "UBMSK_UR_UR_UR"},
    "half": {"HFMA2_R_R_II_II_R": "HFMA2_R_R_FI_FI_R",
             # T-19: the five `_P_R_R_R` PACK_AB keys -- a phantom predicate token (no text of the form carries one); the
             # words are the plain key's `*,F32,PACK_AB` groups' (dsv41 / wave-11 rows), which keep RZ in the unused byte
             # [71:64] where the harvest rows kept 0 (text-inert: the alias is hand-retired, the twin rule's bit-exact
             # re-encode does not hold on that byte)
             "F2FP.BF16.F32.PACK_AB_P_R_R_R": "F2FP_R_R_R", "F2FP.RELU.BF16.F32.PACK_AB_P_R_R_R": "F2FP_R_R_R",
             "F2FP.SATFINITE.BF16.F32.PACK_AB_P_R_R_R": "F2FP_R_R_R", "F2FP.SATFINITE.F16.F32.PACK_AB_P_R_R_R": "F2FP_R_R_R",
             "F2FP.SATFINITE.RELU.F16.F32.PACK_AB_P_R_R_R": "F2FP_R_R_R"},
    "atomic": {"ATOMS_R_ARI": "ATOMS_R_ARURI"},
}
#   MANUAL_FIELDS: key prefix -> fields cubit keeps on the rows although nvdisasm 13.1 prints nothing for the bit
#   ([extraction, bit, bits, the slot shift whose token takes the field, excluded modifier tokens]). Empty since T-20
#   (2026-11-08). Its one entry was IMAD's bit 72 -- text-inert for nvdisasm on every IMAD form on all four targets
#   (`IMAD R32, R48, R80, R24` with 72 set prints the same), kept by cubit as the negation of Ra (`IMAD R5, -R4, R3, R2`;
#   BUG-296, re-affirmed by T-3 on 2026-11-04 with the U32 twins) and carried by the 24 measured non-HI IMAD rows as a
#   `neg@72` field (class `cubit_law`) until the silicon measurement of NEEDS 53 (session T-19, 2026-11-08, test host
#   GPU 0, `pt-needs53`: plain `IMAD` and the same word with bit 72 set both compute a.b+c; the -Rc control, bit 75,
#   computes a.b-c; `IMAD.U32` the same). The bit has no vendor text and no silicon effect, so it is a text-inert bit
#   like any other: the field is gone (session T-20), the rows fail closed on it, and cubit's encoder refuses `-Ra` /
#   `|Ra|` / `-Rb` / `|Rb|` on IMAD (no field -> no bit) instead of minting a bit the hardware ignores.
MANUAL_FIELDS: dict[str, dict[str, list]] = {}
#   RETIRED_FIELDS: family -> {key prefix: [[extraction, bit, bits], ...]} -- the inverse of MANUAL_FIELDS: declared fields
#   the probe drops from a row's field list before the canonical word is built, so the sweep classifies the bit on its own
#   evidence (text-inert here) and `apply` rewrites the row without the field (the mask narrows to the fields that remain).
#   IMAD's `neg@72` (session T-20, 2026-11-08): retired by the silicon measurement of NEEDS 53 above.
RETIRED_FIELDS: dict[str, dict[str, list]] = {
    "intalu": {"IMAD_": [["neg", 72, 1]]},
}
MANUAL_DEAD: dict[str, dict[tuple[str, str], str]] = {
    "intalu": {("IMAD_R_P_R_II_R_P", "B90,U32,WIDE,X"): "IMAD_R_P_R_II_R_P",
               # the harvest read the special register `SRZ` of `CS2R.32 R32, SRZ` as a second register: the word is the
               # measured `CS2R_R_L` `32` row's (sysreg field at [79:72])
               ("CS2R_R_R", ""): "CS2R_R_L"},
    "control": {
        # `WARPSYNC.ALL` prints no register: the `_R` key's `ALL` row is the bit-identical twin of `WARPSYNC` `ALL` (the live
        # row, 19 census witnesses) with a phantom operand token
        ("WARPSYNC_R", "ALL"): "WARPSYNC",
    },
    "memory": {
        # `STSM.8.MT168.2 [R32], R0`: the `_AR_R` harvest key (a bogus register field at [23:16], no offset field) is the
        # measured `STSM_ARI_R` `2,8,MT168` row's word (stsm8-mt168-sm120-2026-10-29) with the offset 0
        ("STSM.8.MT168.2_AR_R", ""): "STSM_ARI_R",
        # the `CCTL.E.PF2_AR` harvest row's canonical word prints `CCTL.PF1` -- a duplicate of the `CCTL.E.PF1_AR` row
        # (renamed `CCTL_ARI` `PF1` by T-19; the and_bases differ only in text-inert bits)
        ("CCTL.E.PF2_AR", ""): "CCTL_ARI",
    },
}

# --- T-19 (2026-11-08): the last 111 harvest rows (T/NEEDS_OWNER.md 55, R's decisions of 03:05Z) ---------------------
# MANUAL_ROW_FIELDS: family -> {(key, group) | key: [[shift, bits, extraction, token_idx], ...]} -- the complete measured
#   field list that replaces the harvest's declared fields before the canonical word is built (the field-narrowing pass of
#   NEEDS 55a: the over-wide predicate windows (a destination predicate has no `!` bit), the 9-bit `sub_ur` of STS / STL
#   reading the text-inert bit 72, the undeclared second carry-out predicate of IADD3 at [86:84], the undeclared UR / LUT /
#   predicate operands of ULOP3 and UIADD3.64, the BSSY target (`imm_shr2` at [63:34], the harvest had an unnamed field),
#   the `.H1` merge selector of F2FP at bit 72, the widened UI2F / UI2FP register fields, the measured branch-target layout
#   of CALL.REL.NOINC, the `.reuse` slot of HFMA2's third register). A key maps to every harvest row of the key. The sweep
#   then verifies the list like any other row: every field bit must move its own token, nothing outside the fields may
#   move an operand of the same form, the census witnesses must fit, cubit must decode / print / re-encode.
MANUAL_ROW_FIELDS: dict[str, dict] = {
    "control": {
        "BSSY_B_II": [[12, 4, "guard", 0], [16, 4, "barrier", 1], [34, 30, "imm_shr2", 2]],
        "CALL.REL.NOINC_II": [[12, 4, "guard", 0], [16, 8, "imm_shr2", 1], [34, 48, "imm_shr10", 1]],
        "CALL.REL.NOINC_II_II": [[12, 4, "guard", 0], [16, 8, "imm_shr2", 1], [34, 48, "imm_shr10", 1]],
        "CALL.REL.NOINC_II_II_?": [[12, 4, "guard", 0], [16, 8, "imm_shr2", 1], [34, 48, "imm_shr10", 1]],
        "CALL.REL.NOINC_II_II_II_?": [[12, 4, "guard", 0], [16, 8, "imm_shr2", 1], [34, 48, "imm_shr10", 1]],
        "CALL.REL.NOINC_II_II_II_II_?": [[12, 4, "guard", 0], [16, 8, "imm_shr2", 1], [34, 48, "imm_shr10", 1]],
        ("WARPSYNC", "ALL"): [[12, 4, "guard", 0]],
        ("WARPSYNC_R", "ALL"): [[12, 4, "guard", 0]],
    },
    "intalu": {
        ("IADD3_R_P_P_R_R_R", ""): [[12, 4, "guard", 0], [16, 8, "reg", 1], [81, 3, "pred", 2], [84, 3, "pred", 3],
                                    [24, 8, "reg", 4], [72, 1, "neg", 4], [122, 1, "reuse", 4], [32, 8, "reg", 5],
                                    [63, 1, "neg", 5], [123, 1, "reuse", 5], [64, 8, "reg", 6], [75, 1, "neg", 6],
                                    [124, 1, "reuse", 6]],
        ("IADD3_R_P_P_R_R_R_P_P", "X"): [[12, 4, "guard", 0], [16, 8, "reg", 1], [81, 3, "pred", 2], [84, 3, "pred", 3],
                                         [24, 8, "reg", 4], [72, 1, "inv", 4], [122, 1, "reuse", 4], [32, 8, "reg", 5],
                                         [63, 1, "inv", 5], [123, 1, "reuse", 5], [64, 8, "reg", 6], [75, 1, "inv", 6],
                                         [124, 1, "reuse", 6], [87, 3, "pred", 7], [90, 1, "neg", 7], [77, 3, "pred", 8],
                                         [80, 1, "inv", 8]],
        ("IADD3_R_P_P_R_II_R", "X"): [[12, 4, "guard", 0], [16, 8, "reg", 1], [81, 3, "pred", 2], [84, 3, "pred", 3],
                                      [24, 8, "reg", 4], [72, 1, "inv", 4], [122, 1, "reuse", 4], [32, 32, "imm", 5],
                                      [64, 8, "reg", 6], [75, 1, "inv", 6], [124, 1, "reuse", 6], [87, 3, "pred", 7],
                                      [90, 1, "neg", 7], [77, 3, "pred", 8], [80, 1, "inv", 8]],
        # T-22 (2026-11-08, NEEDS 59a; sm103a / sm100a only -- sm120 / sm121a have no VIMNMX3 key): the three-input
        # integer min / max. The harvest declared the fifth operand's predicate as a 4-bit `pred` field at shift 1 -- inside
        # the opcode nibble -- so the row's match ignored opcode bits 1..4 and claimed FMNMX (0x209) words (batch 7's lattice
        # test: `FMNMX R4, R2, R3, PT` decoded as `VIMNMX3 R4, R2, R3, R1, P4`). The predicate sits at [89:87] with its sign
        # at 90 (the canonical word `@P0 VIMNMX3 R0, R0, R0, R0, PT` carries 0b111 there), like IADD3's; the UR form had
        # neither the guard nor the predicate declared. 0 witnesses in the B300 publish corpus for either key.
        "VIMNMX3_R_R_R_R_P": [[12, 4, "guard", 0], [16, 8, "reg", 1], [24, 8, "reg", 2], [122, 1, "reuse", 2],
                              [32, 8, "reg", 3], [123, 1, "reuse", 3], [64, 8, "reg", 4], [124, 1, "reuse", 4],
                              [87, 3, "pred", 5], [90, 1, "neg", 5]],
        "VIMNMX3_R_R_UR_R_P": [[12, 4, "guard", 0], [16, 8, "reg", 1], [24, 8, "reg", 2], [122, 1, "reuse", 2],
                               [32, 8, "ureg", 3], [64, 8, "reg", 4], [124, 1, "reuse", 4], [87, 3, "pred", 5],
                               [90, 1, "neg", 5]],
        ("IMAD_R_P_R_R_R", "HI,U32"): [[12, 4, "guard", 0], [16, 8, "reg", 1], [81, 3, "pred", 2], [24, 8, "reg", 3],
                                       [122, 1, "reuse", 3], [32, 8, "reg", 4], [123, 1, "reuse", 4], [64, 8, "reg", 5],
                                       [75, 1, "neg", 5], [124, 1, "reuse", 5]],
        ("IMAD_R_P_R_R_R", "U32,WIDE"): [[12, 4, "guard", 0], [16, 8, "reg", 1], [81, 3, "pred", 2], [24, 8, "reg", 3],
                                         [122, 1, "reuse", 3], [32, 8, "reg", 4], [123, 1, "reuse", 4], [64, 8, "reg", 5],
                                         [75, 1, "neg", 5], [124, 1, "reuse", 5]],
        ("IMAD_R_P_R_II_R", "U32,WIDE"): [[12, 4, "guard", 0], [16, 8, "reg", 1], [81, 3, "pred", 2], [24, 8, "reg", 3],
                                          [122, 1, "reuse", 3], [32, 32, "imm", 4], [64, 8, "reg", 5], [75, 1, "neg", 5],
                                          [124, 1, "reuse", 5]],
        ("VIADD.32_R_R_R", ""): [[12, 4, "guard", 0], [16, 8, "reg", 1], [24, 8, "reg", 2], [72, 1, "neg", 2],
                                 [122, 1, "reuse", 2], [32, 8, "reg", 3], [63, 1, "neg", 3], [123, 1, "reuse", 3]],
    },
    "half": {
        ("F2IP.S8.F32.NTZ_R_R_R_R", ""): [[12, 4, "guard", 0], [16, 8, "reg", 1], [24, 8, "reg", 2], [122, 1, "reuse", 2],
                                          [32, 8, "reg", 3], [123, 1, "reuse", 3], [64, 8, "reg", 4], [72, 1, "opmod:H1", 4],
                                          [124, 1, "reuse", 4]],
        ("F2FP.F16.F32.MERGE_C_R_R_R", ""): [[12, 4, "guard", 0], [16, 8, "reg", 1], [32, 8, "reg", 2], [123, 1, "reuse", 2],
                                             [64, 8, "reg", 3], [72, 1, "opmod:H1", 3], [124, 1, "reuse", 3]],
        "F2FP_R_R_R_R": [[12, 4, "guard", 0], [16, 8, "reg", 1], [24, 8, "reg", 2], [122, 1, "reuse", 2], [32, 8, "reg", 3],
                         [123, 1, "reuse", 3], [64, 8, "reg", 4], [72, 1, "opmod:H1", 4], [124, 1, "reuse", 4]],
        ("HFMA2_R_R_R_UR", ""): [[12, 4, "guard", 0], [16, 8, "reg", 1], [24, 8, "reg", 2], [72, 1, "neg", 2], [73, 1, "abs", 2],
                                 [74, 2, "hsel", 2], [122, 1, "reuse", 2], [64, 8, "reg", 3], [81, 2, "hsel", 3], [83, 1, "abs", 3],
                                 [84, 1, "neg", 3], [86, 1, "h0nh1", 3], [123, 1, "reuse", 3], [32, 8, "ureg", 4], [60, 2, "hsel", 4],
                                 [62, 1, "abs", 4], [63, 1, "neg", 4]],
        ("HSET2_R_R_FI_FI_P", "AND,EQ"): [[12, 4, "guard", 0], [16, 8, "reg", 1], [24, 8, "reg", 2], [72, 1, "neg", 2],
                                          [73, 1, "abs", 2], [74, 2, "hsel", 2], [122, 1, "reuse", 2], [48, 16, "f16", 3],
                                          [32, 16, "f16", 4], [87, 3, "pred", 5], [90, 1, "neg", 5]],
        "UF2FP_UR_UR_UR_UR": [[12, 4, "guard", 0], [16, 8, "ureg", 1], [24, 8, "ureg", 2], [32, 8, "ureg", 3], [64, 8, "ureg", 4],
                              [72, 1, "opmod:H1", 4]],
        ("UI2F_UR_UR", "RP"): [[12, 4, "guard", 0], [16, 8, "ureg", 1], [32, 8, "ureg", 2]],
        ("UI2FP_UR_UR", "F32,S32"): [[12, 4, "guard", 0], [16, 8, "ureg", 1], [32, 8, "ureg", 2]],
    },
    "memory": {
        # T-25 (2026-11-09): the plain `LDG_R_ARURI` `E` row of sm103a / sm100a (bug099 harvest) read the uniform register
        # as a 6-bit field [37:32] -- nvdisasm prints `UR64` for bit 38 and `UR128` for bit 39 (the T-23 sweep: "bit 38
        # outside the fields moves operand 2"), cubit printed `UR0` for `UR64`. The field is 8 bits like on every other
        # LDG row (sm120's measured row of the same key and group has this list).
        ("LDG_R_ARURI", "E"): [[12, 4, "guard", 0], [16, 8, "reg", 1], [24, 8, "sub_r0", 2], [32, 8, "sub_ur1", 2],
                               [40, 24, "sub_imm2", 2]],
        "STS_ARURI_R": [[12, 4, "guard", 0], [24, 8, "sub_r0", 1], [64, 8, "sub_ur1", 1], [40, 24, "sub_imm1", 1],
                        [78, 2, "addr_scale", 1], [32, 8, "reg", 2]],
        "STL_AURI_R": [[12, 4, "guard", 0], [64, 8, "sub_ur0", 1], [40, 24, "sub_imm1", 1], [32, 8, "reg", 2]],
        ("LD_R_dARI", "E,STRONG,SYS"): [[12, 4, "guard", 0], [16, 8, "reg", 1], [24, 8, "sub_r1", 2], [32, 8, "sub_ur0", 2],
                                        [40, 24, "sub_imm2", 2]],
        ("STL_ARI_R", "EF,U8"): [[12, 4, "guard", 0], [24, 8, "sub_r0", 1], [40, 24, "sub_imm1", 1], [32, 8, "reg", 2]],
        ("STSM.8.MT168.2_AR_R", ""): [[12, 4, "guard", 0], [24, 8, "sub_r0", 1], [40, 24, "sub_imm1", 1], [32, 8, "reg", 2]],
        "CCTL.E.PF2_AR": [[12, 4, "guard", 0], [24, 8, "sub_r0", 1], [32, 32, "sub_imm1", 1]],
        ("CCTL_ARI", "PF1"): [[12, 4, "guard", 0], [24, 8, "sub_r0", 1], [32, 32, "sub_imm1", 1]],
        ("CCTL_ARI", "PF2"): [[12, 4, "guard", 0], [24, 8, "sub_r0", 1], [32, 32, "sub_imm1", 1]],
        ("UBLKCP_AURI_AURI_UR", "G,G"): [[12, 4, "guard", 0], [32, 8, "sub_ur0", 1], [24, 8, "sub_ur0", 2], [64, 8, "ureg", 3]],
        "UBLKRED_AURI_AURI_UR": [[12, 4, "guard", 0], [32, 8, "sub_ur0", 1], [24, 8, "sub_ur0", 2], [64, 8, "ureg", 3]],
    },
    "uniform": {
        # T-22 (2026-11-08): the UIADD3 `.X` rows of sm121a / sm103a / sm100a get sm120's measured field lists (G run 5, rows-uniform):
        # the harvest rows read the two carry-in predicates as `pred` / `neg` (sm121a) or a 4-bit `pred@87` (sm103a / sm100a: `UP15` for
        # the vendor's `!UPT`) and claimed the plain form's text-inert words [90:77] through the sign-tolerant fallback (bug459a's
        # "x3 overprint"). Carry-in predicates at [79:77] + inv 80 and [89:87] + inv 90, the operand signs as `inv` (the `.X` form).
        "UIADD3_UR_UP_UP_UR_II_UR_UP_UP": [[12, 4, "guard", 0], [16, 8, "ureg", 1], [81, 3, "upred", 2], [84, 3, "upred", 3],
                                          [24, 8, "ureg", 4], [72, 1, "inv", 4], [32, 32, "imm", 5], [64, 8, "ureg", 6],
                                          [75, 1, "inv", 6], [87, 3, "upred", 7], [90, 1, "inv", 7], [77, 3, "upred", 8],
                                          [80, 1, "inv", 8]],
        "UIADD3_UR_UP_UP_UR_UR_UR_UP_UP": [[12, 4, "guard", 0], [16, 8, "ureg", 1], [81, 3, "upred", 2], [84, 3, "upred", 3],
                                          [24, 8, "ureg", 4], [72, 1, "inv", 4], [32, 8, "ureg", 5], [63, 1, "inv", 5],
                                          [64, 8, "ureg", 6], [75, 1, "inv", 6], [87, 3, "upred", 7], [90, 1, "inv", 7],
                                          [77, 3, "upred", 8], [80, 1, "inv", 8]],
        ("UIADD3_UR_UP_UP_UR_II_UR", "64"): [[12, 4, "guard", 0], [16, 8, "ureg", 1], [81, 3, "upred", 2], [84, 3, "upred", 3],
                                             [24, 8, "ureg", 4], [72, 1, "neg", 4], [32, 32, "imm", 5], [64, 8, "ureg", 6],
                                             [75, 1, "neg", 6]],
        ("ULEA_UR_UP_UR_UR_II", ""): [[12, 4, "guard", 0], [16, 8, "ureg_ff", 1], [81, 3, "upred", 2], [24, 8, "ureg", 3],
                                      [72, 1, "neg", 3], [32, 8, "ureg_ff", 4], [63, 1, "neg", 4], [75, 5, "imm", 5]],
        ("ULEA_UR_UP_UR_II_II", ""): [[12, 4, "guard", 0], [16, 8, "ureg", 1], [81, 3, "upred", 2], [24, 8, "ureg", 3],
                                      [72, 1, "neg", 3], [32, 32, "imm", 4], [75, 5, "imm", 5]],
        ("ULEA_UR_UP_UR_UR_UR_II", "HI"): [[12, 4, "guard", 0], [16, 8, "ureg", 1], [81, 3, "upred", 2], [24, 8, "ureg", 3],
                                           [72, 1, "neg", 3], [32, 8, "ureg", 4], [63, 1, "neg", 4], [64, 8, "ureg_ff", 5],
                                           [75, 5, "imm", 6]],
        ("ULOP3_UP_UR_UR_II_UR_II_UP", "LUT"): [[12, 4, "guard", 0], [81, 3, "upred", 1], [16, 8, "ureg", 2], [24, 8, "ureg", 3],
                                                [32, 32, "imm", 4], [64, 8, "ureg", 5], [72, 8, "imm", 6], [87, 3, "upred", 7],
                                                [90, 1, "inv", 7]],
        ("ULOP3_UR_UR_UR_UR_II_UP", "LUT"): [[12, 4, "guard", 0], [16, 8, "ureg", 1], [24, 8, "ureg", 2], [32, 8, "ureg", 3],
                                             [64, 8, "ureg", 4], [72, 8, "imm", 5], [87, 3, "upred", 6], [90, 1, "inv", 6]],
        ("UIMNMX_UP_UP_UR_UR_UR_UP_UP", "U32"): [[12, 4, "guard", 0], [81, 3, "upred", 1], [84, 3, "upred", 2], [16, 8, "ureg", 3],
                                                 [24, 8, "ureg", 4], [32, 8, "ureg", 5], [87, 3, "upred", 6], [90, 1, "inv", 6],
                                                 [77, 3, "upred", 7], [80, 1, "inv", 7]],
    },
}
# MANUAL_SPELLING_OK: family -> {(key, group): why} -- rows whose vendor text derives to another key by the project's
#   design; the probe accepts the spelling and verifies the structure like any other row.
MANUAL_SPELLING_OK: dict[str, dict[tuple[str, str], str]] = {
    "intalu": {
        # the constant-bank keys `_cAI` (no index register) and `_cARI` share their words at RZ: each key is the encoder's
        # path for its own spelling, both carry the index field, the printer elides RZ -- the probe's canonical word puts a
        # register into the field, so the text derives to the `_cARI` key (the bug165 / bug152 convention of the family)
        ("LDC_R_cAI", "64"): "the `_cAI` key is the encoder's path for the RZ-indexed spelling `c[bank][imm]`; the row carries "
                             "the index field like its bug165 siblings, the register-indexed words print vendor-true through it too",
        ("LDCU_UR_cAI", "64"): "the `_cAI` key is the encoder's path for the URZ-indexed spelling `c[bank][imm]`; the row carries "
                               "the index field like its bug152 sibling, the register-indexed words print vendor-true through it too",
    },
}
# PAIRED_TYPE_BITS: family -> {mnemonic: bit} -- a modifier bit that re-types both packed-half immediates of the word at
#   once (`BF16_V2`: the same 16-bit patterns print as bf16 instead of f16 literals). A flip that changes the mnemonic token
#   and only the float-immediate tokens is the other group's word -- a modifier bit, not a complex change (NEEDS 55b).
PAIRED_TYPE_BITS: dict[str, dict[str, int]] = {"half": {"HADD2": 85, "HFMA2": 85, "HSET2": 65}}
# MODELLED: family -> {(key, group): (the test that pins it, why)} -- rows the project keeps on purpose (R, 2026-11-08):
#   `_src: "modelled"` (design, not harvest; the T1 counter does not count them), the note names the test.
MODELLED: dict[str, dict[tuple[str, str], tuple[str, str]]] = {
    "intalu": {
        ("IADD3.X_R_P_P_R_II_R_P_P", ""): ("tests/bug089_iadd3x_tailpred.rs, tests/bug012_encodeverify50.rs",
            "the encoder's key for the 8-operand `IADD3.X Rd, Pc1, Pc2, Ra, imm, Rc, Pin1, Pin2` spelling (bug089's round "
            "trips, bug012's opex-0x51 re-encode); its words decode through `IADD3_R_P_P_R_II_R` `X` (the project's 6-token "
            "decode row whose printer path renders the two carry-in predicates) -- an encode-only design row, 0 census witnesses"),
        ("IADD3_R_P_P_R_II_R", "X"): ("tests/bug089_iadd3x_tailpred.rs (bug089_junk_key_variant_absent_and_iir_fields_present), "
            "tests/bug012_encodeverify50.rs",
            "the project's decode row for the IADD3.X immediate form: the 6-token key carries the vendor's 8-operand text through "
            "the printer's trailing-predicate path (the tok7 neg@90 / tok8 inv@80 fields are BUG-089's fix, pinned by name); the "
            "sweep adds the second carry-out predicate [86:84] (tok 3) the harvest never declared and drops the duplicate `reg_ff` "
            "at bit 80 -- the mask stays the harvest's (bug012's relaxed decode of a vendor-unknown word with bit 123 set)"),
    },
    "half": {
        # the plain group of the 36-group `HFMA2_R_R_R_II_FI` key: the 2026-08/09 waves built the key as the guard-capable
        # twin of `HFMA2_R_R_R_FI_FI` (whose rows have no guard field) with `f16_d` immediates, and pin its structure
        # (bug265 / 270 / 274 / 279 / 285 / 288 / 330 / 354 name the key and its `` group); the sweep verifies the row
        # (bit 85 = the paired BF16_V2 type), its canonical word decodes through `HFMA2_R_R_R_FI_FI` `` -- design, not harvest
        ("HFMA2_R_R_R_II_FI", ""): ("tests/bug274_opsuffix.rs, tests/bug279_ftzsigns.rs, tests/bug285_bf16v2_mods.rs, "
            "tests/bug330_iifi_tok4.rs, tests/bug354_hfma2_sparse_modlane.rs, tests/bug265_junkrows.rs, tests/bug270_multibit_resid.rs, "
            "tests/bug288_hfma2_immfam_tok2_bf16.rs",
            "the plain group of the wave-built `HFMA2_R_R_R_II_FI` key (36 groups, `f16_d` immediates, a guard field the "
            "`HFMA2_R_R_R_FI_FI` rows lack): the 2026-08/09 tests pin the key's structure and its tolerant decode of the "
            "text-inert bits [90:87]; its canonical word is the `HFMA2_R_R_R_FI_FI` `` word (0 census witnesses)"),
    },
    "memory": {
        ("UBLKPF.L2_AUR_UR", ""): ("tests/sm120_ublkpf_l2.rs",
            "the harvest-era spelling of the bulk L2 prefetch, kept by the test as the superseded key (operand_sig `AUR_UR` "
            "pinned); its canonical word decodes through the measured `UBLKPF_AURI_UR` `L2` row (ublkpf-l2-sm120-2026-10-29) "
            "vendor-true -- 0 census witnesses"),
    },
    "uniform": {
        # the two `encode_only` retention rows of the uniform datapath (the decoder skips them: `encode_only` groups are the
        # encoder's compatibility paths for texts the vendor never prints)
        ("REDUX_UR_R", "AND"): ("tests/bug193_redux_and_elision.rs",
            "an `encode_only` retention row (BUG-193): the vendor elides `.AND` on sm_120 (op 0 prints bare `REDUX`, the measured "
            "`` row); the legacy text `REDUX.AND URd, Ra` still encodes byte-exact through this row, the decoder skips it"),
        ("UISETP_UP_UP_UR_UR_UP", ""): ("tests/bug092_uisetp_legacy_retention.rs",
            "an `encode_only` retention row (BUG-092): the pre-086 legacy `` group with `opaque_mod` fields keeps the frozen-era "
            "render `UISETP.?GT.?S32.?OR UP0, UPT, URa, URb, UPT` re-encoding byte-exact; the decoder skips it (the measured "
            "`AND,GT` / `AND,LT,U32` groups own the decode)"),
    },
}
# DELETE: family -> {key: why} -- keys deleted whole (R's class (d) of NEEDS 55: every canonical word nvdisasm rejects --
#   the lattice doctrine never claims an illegal plane -- and three junk keys whose only words are another form's; 0 census
#   witnesses each; a CHANGELOG line per key). Status `deleted` in the fixture.
DELETE: dict[str, dict[str, str]] = {
    "control": {
        "BAR.RED.POPC.DEFER_BLOCKING_II_II_P": "nvdisasm rejects every canonical word of the row (bit 9 / 11 / 54 immediate "
                                               "fields on a junk opcode plane)",
        "BAR.SYNC.DEFER_BLOCKING_P_II": "the row's words are the register form `BAR.SYNC Ra, Rb` (bits [39:32] move both printed "
                                        "registers, bit 11 flips the immediate form) that no row models; the key spelled a "
                                        "predicate + immediate and the word decoded through the `BAR.RED.POPC` junk row with the "
                                        "wrong text -- deleted, the register forms of BAR are a documented hole (0 census witnesses)",
    },
    "intalu": {
        "IADD.64.X_R_P_R_II_P": "nvdisasm rejects every canonical word of the row",
        "IADD.64.X_R_R_II_P": "nvdisasm rejects every canonical word of the row",
        "IADD.64_R_P_R_UR": "nvdisasm rejects every canonical word of the row",
        "IADD.64_R_R_UR_II_II_?": "nvdisasm rejects every canonical word of the row",
        "IADD.64_R_R_UR_II_II_II_?": "nvdisasm rejects every canonical word of the row",
        "IADD.64_R_R_UR_UR": "nvdisasm rejects every canonical word of the row",
        "SEL.64_R_R_R_P": "nvdisasm rejects every canonical word of the row",
        "MOV_P_R_II": "the row's words are `UMOV URd, imm` words (opcode 0x882, measured `UMOV_UR_II`) carrying text-inert "
                      "bits [75:72]; a cross-mnemonic junk key, 0 census witnesses",
        "VIMNMX.S32_R_R_UR_P": "the row's words are `VIMNMX.U32 Rd, Ra, imm, Pp` words (opcode 0x848, the immediate form) with "
                               "the text-inert bits [86:81] clear -- a plane the measured `VIMNMX_R_R_II_P` `U32` row fails "
                               "closed on; the key is wrong in every token (S32, UR) and cubit decodes none of its words, 0 "
                               "census witnesses",
    },
    "atomic": {
        "ATOMG.E.ADD.F64.RN.STRONG.GPU_P_R_AR_R": "count 0: the harvest never saw the row's word; its canonical word is an "
                                                   "`ATOMG.ADD.EF.F16x2.RN Pd, Rd, [Ra], Rb` word (opcode 0x3a3, the EF F16x2 "
                                                   "plane) -- another form's, the F64 form is the measured `ATOMG_P_R_ARI_R` row",
    },
}
# RENAMED_FROM: family -> {(key, group): "old key / old group"} -- rows renamed by T-19 to the vendor's spelling (R's rule for
#   a mis-named key without census witnesses whose word no other key decodes: rename, do not alias); for the note.
RENAMED_FROM: dict[str, dict[tuple[str, str], str]] = {
    "intalu": {
        ("VIADD.32_R_R_R", ""): "VIADD.U8x4_R_R_R (bit 75, the U8x4 code, is clear in the row: its words print `VIADD.32`)",
    },
    "half": {
        ("F2IP.S8.F32.NTZ_R_R_R_R", ""): "F2IP.S8.F32.NTZ_R_R_R_II (the fourth operand is a register, the harvest called it an immediate)",
        ("HSET2_R_R_FI_FI_P", "AND,EQ"): "HSET2_R_R_II_II_P (the integer spelling of two f16 immediates; the FMUL_R_R_II precedent)",
        ("UF2FP_UR_UR_UR_UR", "E4M3,F32,PACK_AB_MERGE_C,SATFINITE"): "UF2FP.SATFINITE.E4M3.F32.PACK_AB_MERGE_C_UR_?_?_? (a partial "
            "`?` key: the three source UR fields were URZ constants of the compiler sample)",
        ("UF2FP_UR_UR_UR_UR", "E5M2,F32,PACK_AB_MERGE_C,SATFINITE"): "UF2FP.SATFINITE.E5M2.F32.PACK_AB_MERGE_C_UR_?_?_? (a partial "
            "`?` key: the three source UR fields were URZ constants of the compiler sample)",
        ("UI2F_UR_UR", "RP"): "UI2F.RP_UR_UR (dotted twin of the plain key's group; the 4- and 5-bit register fields widened to 8)",
        ("UI2FP_UR_UR", "F32,S32"): "UI2FP.F32.S32_UR_UR (dotted twin of the plain key's group; the 4- and 5-bit register fields widened to 8)",
    },
    "memory": {
        ("STL_ARI_R", "EF,U8"): "STL_P_ARI_R (a phantom predicate token; the row's bits are the `STL.EF.U8 [Ra+imm], Rb` word)",
        ("CCTL_ARI", "PF1"): "CCTL.E.PF1_AR (the row's words print `CCTL.PF1 [Ra+imm]`: no `.E`, with an offset)",
        ("CCTL_ARI", "PF2"): "CCTL.E.PML2_AR (the row's words print `CCTL.PF2 [Ra+imm]`: no `.E`, not PML2, with an offset)",
        ("UBLKCP_AURI_AURI_UR", "G,G"): "UBLKCP.S.G_AUR_AUR_UR (the direction code [74:73] is 0 in the row: its words print `UBLKCP.G.G`)",
        ("UBLKRED_AURI_AURI_UR", "ADD,G,S"): "UBLKRED.G.S.ADD_AUR_AUR_UR (the harvest baked the direction code 0, which nvdisasm "
            "prints `UBLKRED.G.INVALID0.ADD`; the sweep names bit 74 as the `.S` source code -- set in the renamed row)",
        ("UBLKRED_AURI_AURI_UR", "ADD,G,S,S32"): "UBLKRED.G.S.ADD.S32_AUR_AUR_UR (as `ADD,G,S`, plus bit 81 = `.S32`)",
    },
    "uniform": {
        ("UIADD3_UR_UP_UP_UR_II_UR", "64"): "UIADD3.64_UR_UP_UP_UR_II_UR (dotted twin of the plain measured key; the URZ third "
            "source at [71:64] was baked, now the `ureg` field of the sibling row)",
        ("UIMNMX_UP_UP_UR_UR_UR_UP_UP", "U32"): "UIMNMX_P_P_UR_UR_UR_P_P `S64` (vector predicate tokens for uniform predicates and "
            "the wrong width: the row's words print `UIMNMX.U32`)",
    },
    "control": {
        ("UCGABAR_ARV", ""): "UCGABAR_ARV `_ARV` (the group token `_ARV` doubled the vendor's underscore mnemonic in cubit's print)",
        ("UCGABAR_WAIT", ""): "UCGABAR_WAIT `_WAIT` (the group token `_WAIT` doubled the vendor's underscore mnemonic in cubit's print)",
    },
}


def tag_of(family: str) -> str:
    return f"rows-{family}-{DATE}"


def manual_law_field(family: str, key: str, group: str, f) -> bool:
    """A field cubit keeps by its own law although nvdisasm prints nothing for the bit (MANUAL_FIELDS): on an applied
    table the row already declares it, and a re-probe must read it as `cubit_law`, not as a text-inert defect."""
    for prefix, extra in MANUAL_FIELDS.get(family, {}).items():
        if not key.startswith(prefix):
            continue
        for ext, bit, nb, _slot, *excluded in extra:
            if excluded and any(m in group.split(",") for m in excluded[0]):
                continue
            if f["extraction"] == ext and f["shift"] == bit and f["bits"] == nb:
                return True
    return False


def mnemonic_of(key: str) -> str:
    return key.split("_")[0].split(".")[0]


def field_mask(f) -> int:
    return ((1 << f["bits"]) - 1) << f["shift"]


def fields_mask(fields) -> int:
    m = 0
    for f in fields:
        m |= field_mask(f)
    return m


# --- canonical words -------------------------------------------------------------------------------------------

# register numbers 8-aligned (the multi-register MMA operands must start at reg % 4 == 0 on silicon, BUG-037) and
# with few bits set (no single-bit flip reaches 255 = RZ / URZ)
REG_VALUES = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x18, 0x28, 0x38, 0x48]
PATTERN = 0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
REG_EXTRACTIONS = ("reg", "ureg", "reg_ff", "ureg_ff", "sub_r", "sub_ur", "ureg_shr", "reg_shr")


def is_reg(e: str) -> bool:
    return e.startswith(REG_EXTRACTIONS)


def is_pred(e: str) -> bool:
    return e.startswith("pred") or e.startswith("upred")


def value_for(f, token_order: int, variant: int, pred: int) -> int:
    """A field value whose single-bit flips all change the printed operand (variant 0), or a fallback."""
    e, bits = f["extraction"], f["bits"]
    full = (1 << bits) - 1
    if e == "guard":
        return 7
    if is_pred(e):
        return pred & full  # 7 = PT (elided by some forms), 3 = P3 (the `!` bit of pred_inv4 clear)
    if is_reg(e):
        v = REG_VALUES[token_order % len(REG_VALUES)] if variant == 0 else (8 * token_order + 8)
        return v & full if bits >= 6 else (1 if variant == 0 else 0)
    if e in ("f32", "f64hi"):
        return 0x5a5a5a5a & full if variant == 0 else 0x3f800000 & full
    if e in ("f16", "f16_d", "bf16"):
        return 0x5a5a & full if variant == 0 else 0x3c00 & full
    if bits == 1:
        return 0
    if e.startswith("imm") or e.startswith("sub_imm") or e.startswith("cm16") or e.startswith("cm17"):
        if variant == 0:
            return PATTERN & full if bits > 3 else (1 & full)
        if variant == 1:
            return 0x10 & full if bits > 5 else 1
        return 0
    if e == "barrier":
        return 1
    # enum-like small fields (hsel, byte_sel, addr_scale, ...): keep the group's own constant on the first try
    return 0 if variant < 2 else 1


def canonical_candidates(row) -> list[int]:
    """Candidate canonical words, most informative first: registers 8-aligned and distinct, immediates on the
    0x5a.. pattern, predicates PT then P3 (forms that elide PT need the explicit spelling to show the operand),
    then the smaller fallbacks."""
    fields = row.get("fields", [])
    base = int(row["and_base"], 16) & ~SCHEDULE & ~fields_mask(fields)
    out = []
    for variant in (0, 1, 2):
        for pred in (7, 3):
            w = base
            for order, f in enumerate(fields):
                w |= (value_for(f, order, variant, pred) & ((1 << f["bits"]) - 1)) << f["shift"]
            if w not in out:
                out.append(w)
    return out


# --- text tokens -----------------------------------------------------------------------------------------------

def tokens(text: str) -> list[str]:
    """[guard, mnemonic.mods, operand1, operand2, ...] -- the table's token_idx k is operand k (guard = 0)."""
    t = text.strip()
    guard = ""
    if t.startswith("@"):
        guard, _, t = t.partition(" ")
    op, _, rest = t.partition(" ")
    ops = [o.strip() for o in rest.split(", ")] if rest.strip() else []
    return [guard, op] + ops


def diff_class(t0: str, t: str):
    """('modifier', None) | ('operand', token_idx) | ('guard', 0) | ('complex', None) for t vs the canonical t0."""
    a, b = tokens(t0), tokens(t)
    if len(a) == len(b):
        # same shape: compare position by position (a sequence matcher would re-align equal register names)
        changed = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        if len(changed) != 1:
            return "complex", None
        i = changed[0]
        return ("guard", 0) if i == 0 else (("modifier", None) if i == 1 else ("operand", i - 1))
    changes = [(tag, i1, i2, j1, j2) for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes()
               if tag != "equal"]
    if len(changes) != 1:
        return "complex", None
    tag, i1, i2, j1, j2 = changes[0]
    if tag == "replace" and i2 - i1 == 1 and j2 - j1 == 1:
        if i1 == 0:
            return "guard", 0
        if i1 == 1:
            return "modifier", None
        return "operand", i1 - 1
    if tag in ("insert", "delete") and max(i2 - i1, j2 - j1) == 1 and i1 >= 2:
        # an operand elided / un-elided (PT, RZ, a zero offset): the token index of the moved operand
        return "operand", i1 - 1
    if a[1] != b[1] and a[0] == b[0] and a[2:] == b[2:]:
        return "modifier", None
    return "complex", None


def paired_type_change(t0: str, t: str, fields) -> bool:
    """T-19 (NEEDS 55b): the flip toggles `BF16_V2` in the mnemonic and re-types the packed-half immediates of the word
    at once (the same 16-bit patterns print as bf16 instead of f16 literals) -- the other group's word, nothing else
    moves. The immediate tokens are the ones whose declared field is a 16-bit half (`f16` / `bf16`, or the harvest's
    integer spelling `imm` / `f16_d` of one)."""
    a, b = tokens(t0), tokens(t)
    if len(a) != len(b) or a[1] == b[1] or set(a[1].split(".")) ^ set(b[1].split(".")) != {"BF16_V2"}:
        return False
    halves = {f["token_idx"] for f in fields if f["bits"] == 16 and f["extraction"] in ("f16", "bf16", "imm", "f16_d")}
    changed = {i for i, (x, y) in enumerate(zip(a, b)) if x != y} - {1}
    return bool(changed) and all(i - 1 in halves for i in changed)


# --- oracles ---------------------------------------------------------------------------------------------------

class Nvdisasm:
    def __init__(self, nvdisasm: str, arch: str, jobs: int, cache_file: pathlib.Path | None = None):
        self.nv, self.arch, self.jobs = nvdisasm, arch, jobs
        self.version, self.digest = nvprobe.nvdisasm_identity(nvdisasm)
        self.cache: dict[int, str | None] = {}
        self.local = threading.local()
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix=f"re_rows_{arch.lower()}_"))
        # an on-disk memo of (word -> text) for this nvdisasm build and target: a session convenience (the probe
        # re-runs after a cubit rebuild without re-spawning 40 000 nvdisasm processes); never read by the tests
        self.cache_file = cache_file
        if cache_file is not None and cache_file.exists():
            with cache_file.open() as fh:
                for line in fh:
                    d = json.loads(line)
                    if d.get("nvdisasm_sha256") == self.digest and d.get("arch") == arch:
                        self.cache[int(d["word"], 16)] = d["text"]

    def save(self):
        if self.cache_file is None:
            return
        with self.cache_file.open("w") as fh:
            for w, t in self.cache.items():
                fh.write(json.dumps({"word": f"{w:032x}", "text": t, "arch": self.arch, "nvdisasm_sha256": self.digest}) + "\n")

    def _one(self, word: int):
        scratch = getattr(self.local, "scratch", None)
        if scratch is None:
            scratch = self.tmp / f"{threading.get_ident()}.bin"
            self.local.scratch = scratch
        scratch.write_bytes(word.to_bytes(16, "little"))
        r = subprocess.run([self.nv, "-b", self.arch, "-hex", str(scratch)], capture_output=True, text=True)
        if r.returncode:
            if "Illegal instruction" in r.stderr or "undefined value" in r.stderr:
                return None  # `undefined value for table TABLES_opex`: a reuse bit on a slot without a register
            raise RuntimeError(f"nvdisasm failed on {word:032x}: {r.stderr.strip()[:200]}")
        m = nvprobe._TEXT.search(r.stdout)
        return m.group(1).strip() if m else None

    def texts(self, words) -> list:
        """Vendor texts of full words (control code included); None where nvdisasm rejects the word."""
        todo = [w for w in dict.fromkeys(words) if w not in self.cache]
        if todo:
            with concurrent.futures.ThreadPoolExecutor(self.jobs) as pool:
                for w, t in zip(todo, pool.map(self._one, todo)):
                    self.cache[w] = t
            self.save()
        return [self.cache[w] for w in words]


def run_example(binary: str, items: list[dict], *extra) -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="re_rows_cubit_") as d:
        inp, out = pathlib.Path(d) / "in.jsonl", pathlib.Path(d) / "out.jsonl"
        inp.write_text("".join(json.dumps(i) + "\n" for i in items))
        subprocess.run([binary, str(inp), *extra, str(out)], check=True, capture_output=True, text=True)
        return [json.loads(line) for line in out.read_text().splitlines() if line.strip()]


# --- the probe -------------------------------------------------------------------------------------------------

def select_rows(table: dict, family: str, only_keys=None, also_in: dict | None = None):
    """The family's harvest rows (and, on an applied table, the rows this family tagged). `also_in` = another table
    the row must be a harvest row of as well -- the rows another batch measures or retires on a branch not yet on
    the base (the LDG.256 / STG.256 / REDG lattices of batches 12-14) are not probed again."""
    mns = set(FAMILIES[family])
    rows = []
    for key, entry in table["instructions"].items():
        if mnemonic_of(key) not in mns or (only_keys and key not in only_keys):
            continue
        for group, row in entry.get("mod_groups", {}).items():
            if row.get("_src") not in (None, tag_of(family)):
                continue
            if also_in is not None:
                other = also_in["instructions"].get(key, {}).get("mod_groups", {}).get(group)
                if other is None or other.get("_src") not in (None, tag_of(family)):
                    continue
            rows.append((key, group, row))
    return rows


def load_census(path: pathlib.Path | None):
    by_row = collections.defaultdict(list)
    if path is None or not path.exists():
        return by_row
    with path.open() as fh:
        for line in fh:
            d = json.loads(line)
            if "cubit_key" in d:
                by_row[(d["cubit_key"], d["cubit_group"])].append(int(d["word"], 16))
    return by_row


def probe(args):
    table = nvprobe.load_table(pathlib.Path(args.table))
    also = nvprobe.load_table(pathlib.Path(args.also_harvest_in)) if args.also_harvest_in else None
    rows = select_rows(table, args.family, set(args.keys) if args.keys else None, also)
    # T-19: the field-narrowing pass -- the rows named in MANUAL_ROW_FIELDS are probed with their corrected field list
    # (a copy of the row; the table itself changes in `apply`)
    overrides = MANUAL_ROW_FIELDS.get(args.family, {})
    retired = RETIRED_FIELDS.get(args.family, {})
    narrowed = []
    for key, group, row in rows:
        spec = overrides.get((key, group), overrides.get(key))
        if spec is not None:
            row = dict(row)
            row["fields"] = [{"shift": s, "bits": b, "extraction": e, "token_idx": t} for s, b, e, t in spec]
        # T-20: a declared field retired by a later measurement (RETIRED_FIELDS) is dropped before the sweep
        gone = [g for prefix, gs in retired.items() if key.startswith(prefix) for g in gs]
        if gone and any(f["extraction"] == e and f["shift"] == s and f["bits"] == b for f in row.get("fields", []) for e, s, b in gone):
            row = dict(row)
            row["fields"] = [f for f in row["fields"]
                             if not any(f["extraction"] == e and f["shift"] == s and f["bits"] == b for e, s, b in gone)]
        narrowed.append((key, group, row))
    rows = narrowed
    census = load_census(pathlib.Path(args.census) if args.census else None)
    nv = Nvdisasm(args.nvdisasm, args.arch, args.jobs, pathlib.Path(args.nv_cache) if args.nv_cache else None)
    print(f"{len(rows)} harvest rows of family {args.family} ({', '.join(FAMILIES[args.family])}); nvdisasm {nv.version}")

    # 1. canonical words: the first legal candidate whose vendor text the key spells (else the first legal one)
    cands = {(k, g): canonical_candidates(r) for k, g, r in rows}
    flat = [w | CTRL for c in cands.values() for w in c]
    nv.texts(flat)
    cand_texts = sorted({nv.cache[w] for w in flat if nv.cache[w]})
    key_of_text = {r["text"]: r for r in run_example(args.text_keys, [{"text": t} for t in cand_texts])}

    def spelled_by(key, group, text):
        if (key, group) in MANUAL_SPELLING_OK.get(args.family, {}):
            return True  # T-19: the vendor text derives to another key by the project's design (see the table)
        kt = key_of_text.get(text, {})
        return (kt.get("base_key") == key and kt.get("mod_group") == group) or \
               (kt.get("full_key") == key and group in ("", kt.get("mod_group")))

    w0_of = {}
    for (k, g), c in cands.items():
        legal = [w for w in c if nv.cache[w | CTRL] is not None]
        w0_of[(k, g)] = next((w for w in legal if spelled_by(k, g, nv.cache[w | CTRL])), legal[0] if legal else None)

    # 2. the sweep + the witnesses
    sweep_words = []
    for (k, g), w0 in w0_of.items():
        if w0 is not None:
            sweep_words += [(w0 ^ (1 << b)) | CTRL for b in SWEEP_BITS]
    witness_of = {(k, g): census.get((k, g), [])[: args.witnesses] for k, g, _ in rows}
    nv.texts(sweep_words + [w for ws in witness_of.values() for w in ws])
    print(f"nvdisasm: {len(nv.cache)} distinct words named")

    # 3. cubit's view of every word, the keys of every vendor text
    all_words = sorted({w for w in nv.cache})
    cubit_rows = run_example(args.audit_words, [{"word": f"{w:032x}", "nvidia_sass": nv.cache[w]} for w in all_words],
                             args.table)
    cubit = {int(r["word"], 16): r for r in cubit_rows}
    texts = sorted({t for t in nv.cache.values() if t} - set(key_of_text))
    key_of_text.update({r["text"]: r for r in run_example(args.text_keys, [{"text": t} for t in texts])})

    # 4. classify
    verdict = {"family": args.family, "tag": tag_of(args.family), "arch": args.arch, "nvdisasm": nv.version, "rows": []}
    fixture = [{"nvdisasm": nv.version, "nvdisasm_sha256": nv.digest, "arch": args.arch, "family": args.family,
                "ctrl": f"{CTRL >> 96:08x}", "tool": "tools/probes/re_sm120_rows.py", "table": args.table}]
    stats = collections.Counter()
    for key, group, row in rows:
        fields = row.get("fields", [])
        w0 = w0_of[(key, group)]
        rec = {"key": key, "group": group, "fields": [[f["shift"], f["bits"], f["token_idx"], f["extraction"]] for f in fields]}
        v = {"key": key, "group": group, "count": row.get("count"), "problems": [], "reuse_add": [], "cubit": {}}
        if w0 is None:
            if key in DELETE.get(args.family, {}):
                # T-19: class (d) -- the key goes (R's decision; the lattice doctrine never claims an illegal plane)
                rec.update(w0=None, t0=None, status="deleted", reason=DELETE[args.family][key])
            else:
                rec.update(w0=None, t0=None, status="canonical_illegal", reason="nvdisasm rejects every canonical word of the row")
            v["status"] = rec["status"]
            v["problems"].append("nvdisasm rejects every canonical word of the row")
            stats[rec["status"]] += 1
            fixture.append(rec)
            verdict["rows"].append(v)
            continue
        t0 = nv.cache[w0 | CTRL]
        rec.update(w0=f"{w0:032x}", t0=t0)
        kt = key_of_text.get(t0, {})
        v["vendor_keys"] = {k: kt.get(k) for k in ("base_key", "full_key", "mod_group", "parse_error") if k in kt}
        # the key + group name the vendor's text (two accepted spellings: plain key + group, or the dotted key)
        if not spelled_by(key, group, t0):
            v["problems"].append(f"the key does not spell the vendor text: {t0!r} -> {kt.get('full_key')} / {kt.get('mod_group')!r}")
        # bit classes
        by_class = collections.defaultdict(list)
        field_of_bit = {}
        for f in fields:
            for b in range(f["shift"], f["shift"] + f["bits"]):
                field_of_bit[b] = f
        toks0 = tokens(t0)
        for b in SWEEP_BITS:
            t = nv.cache[(w0 ^ (1 << b)) | CTRL]
            f = field_of_bit.get(b)
            if t is None:
                by_class["illegal"].append(b)
                if f is not None:
                    # value-range limits inside a field; for `.reuse` fields nvdisasm's "undefined opex value": the
                    # bit is inert on silicon (KNOWN_ISSUES A12 / BUG-362a), the field stays (never a defect)
                    v.setdefault("field_illegal_bits", []).append(b)
                continue
            if t == t0:
                if f is not None and manual_law_field(args.family, key, group, f):
                    by_class["cubit_law"].append([b, t])  # a field cubit keeps by its own law (MANUAL_FIELDS; empty since T-20, NEEDS 53)
                    continue
                by_class["inert"].append(b)
                if f is not None:
                    if f["extraction"] == "reuse":
                        v.setdefault("reuse_inert", []).append(b)  # kept (A12 doctrine); not a form word
                    else:
                        v["problems"].append(f"field bit {b} ({f['extraction']} tok {f['token_idx']}) is text-inert")
                continue
            cls, tok = diff_class(t0, t)
            # the flip introduces a vendor-invalid marker the canonical text does not carry (the INVALIDn-keyed
            # harvest rows print their own glyph on every word: a faithful rendering, owner 2026-11-03); inside a
            # field it is an invalid value of the field (`.INVALID1` half selector) -- a lattice plane, not a form word
            glyph = (t.count("???") > t0.count("???")) or (t.count("INVALID") > t0.count("INVALID"))
            if glyph:
                by_class["glyph"].append([b, t])
                if f is not None:
                    v.setdefault("field_glyph_bits", []).append(b)
            elif f is not None:
                want = 0 if f["extraction"] == "guard" else f["token_idx"]
                if (cls == "guard" and want == 0) or (cls == "operand" and tok == want):
                    by_class["field"].append([b, t])
                    # a declared `neg` the vendor prints as the ones' complement `~X` (the carry forms of IADD3.X /
                    # UIMAD.X / IADD.X): the extraction is `inv`
                    toks = tokens(t)
                    if f["extraction"] == "neg" and tok is not None and tok + 1 < len(toks) and toks[tok + 1] == "~" + toks0[tok + 1]:
                        v.setdefault("ext_fix", {})[f["shift"]] = "inv"
                else:
                    by_class["complex" if cls == "complex" else "field_wrong"].append([b, t])
                    v["problems"].append(f"field bit {b} ({f['extraction']} tok {f['token_idx']}) moves {cls} {tok}: {t!r}")
            elif cls == "modifier":
                by_class["modifier"].append([b, t])
            elif cls == "guard":
                # the guard the harvest row never declared: a 4-bit field at 12 (added by apply)
                by_class["field"].append([b, t])
                if ["guard", 12, 4, 0] not in v.setdefault("fields_add", []):
                    v["fields_add"].append(["guard", 12, 4, 0])
            elif cls == "operand":
                kt2 = key_of_text.get(t, {})
                same_form = kt2.get("base_key") == kt.get("base_key")
                toks = tokens(t)
                old, new = (toks0[tok + 1], toks[tok + 1]) if tok + 1 < len(toks0) and tok + 1 < len(toks) else ("", "")
                added = None
                if same_form and b in (122, 123, 124, 125) and new == old + ".reuse":
                    added = ["reuse", b, 1, tok]
                elif same_form and new == "-" + old:
                    added = ["neg", b, 1, tok]
                elif same_form and new == "~" + old:
                    added = ["inv", b, 1, tok]
                elif same_form and new == f"|{old}|":
                    added = ["abs", b, 1, tok]
                elif same_form and new == "!" + old and (old.startswith("P") or old.startswith("UP")):
                    added = ["neg", b, 1, tok]  # the predicate's `!` is spelled `neg` on the measured rows (bug247's pin)
                # an address whose base register gains / loses a width or scale suffix (`[R48.64+UR64]`, `[R2.X4+0x10]`,
                # `[RZ.U32+UR4]`): the vendor spells another address form -- another row's word (a coverage gap when
                # the table has none), never this row's operand
                strip = lambda s: re.sub(r"\.(64|U32|X4|X8|X16)(?=[+\]])", "", s)  # noqa: E731
                form_neighbour = old.startswith("[") and new.startswith("[") and strip(old) == strip(new) and old != new
                if added is not None:
                    # a sign / abs / reuse bit on an operand of this row the harvest never declared: a field
                    by_class["field"].append([b, t])
                    v.setdefault("fields_add", []).append(added)
                elif form_neighbour:
                    by_class["operand_other"].append([b, t])
                elif same_form:
                    by_class["operand_other"].append([b, t])
                    v["problems"].append(f"bit {b} outside the fields moves operand {tok} of the same form: {t!r}")
                else:
                    by_class["operand_other"].append([b, t])  # a neighbouring form (another key): lattice
            elif PAIRED_TYPE_BITS.get(args.family, {}).get(mnemonic_of(key)) == b and paired_type_change(t0, t, fields):
                # T-19 (NEEDS 55b): the `BF16_V2` bit re-types both half immediates with the modifier -- the other
                # group's word (its row carries the immediates as bf16 / f16 fields), a modifier bit
                by_class["modifier"].append([b, t])
                v.setdefault("paired_type", []).append(b)
            else:
                kt2 = key_of_text.get(t, {})
                landing = table["instructions"].get(kt2.get("base_key") or "", {}).get("mod_groups", {}).get(kt2.get("mod_group"))
                if landing is not None and tokens(t)[1] != toks0[1] and kt2.get("mod_group") != group:
                    # T-19: the flip changes the mnemonic and re-reads the operands -- and the text it produces is the
                    # spelling of an existing row of the table (F2FP's bit 78: `PACK_AB` <-> `MERGE_C`, a different
                    # operand layout of the same key): another group's word, a modifier bit
                    by_class["modifier"].append([b, t])
                    v.setdefault("modifier_rows", []).append(b)
                    continue
                by_class["complex"].append([b, t])
                if kt2.get("base_key") == kt.get("base_key"):
                    v["problems"].append(f"bit {b} outside the fields moves several tokens of the same form: {t!r}")
        for f in fields:
            fb = [b for b, _ in by_class["field"] if f["shift"] <= b < f["shift"] + f["bits"]]
            if not fb and f["extraction"] != "reuse" and not manual_law_field(args.family, key, group, f):
                v["problems"].append(f"field {f['extraction']} [{f['shift'] + f['bits'] - 1}:{f['shift']}] tok {f['token_idx']}: no bit moves its token")
        # the measured field list: the declared fields (an integer `imm` whose operand the vendor prints as a float
        # becomes the float extraction of its width -- the harvest spelled f16 pairs as hex) plus the added ones
        target_fields = []
        for f in fields:
            nf = {k: f[k] for k in ("bits", "extraction", "shift", "token_idx")}
            tok_text = toks0[f["token_idx"] + 1] if 0 <= f["token_idx"] + 1 < len(toks0) else ""
            if f["extraction"] == "imm" and re.fullmatch(r"[-+]?(\d+\.\d+(e[-+]\d+)?|\d+|INF|QNAN|SNAN)", tok_text) \
                    and ("." in tok_text or "e" in tok_text or tok_text.endswith(("INF", "NAN"))) and f["bits"] in (16, 32):
                nf["extraction"] = ("bf16" if "BF16" in (key + group) else "f16") if f["bits"] == 16 else "f32"
                v.setdefault("fields_fix", []).append([f["shift"], f["extraction"], nf["extraction"]])
            if f["shift"] in v.get("ext_fix", {}):
                nf["extraction"] = v["ext_fix"][f["shift"]]
                v.setdefault("fields_fix", []).append([f["shift"], f["extraction"], nf["extraction"]])
            if f["extraction"] in ("pred", "upred") and f["bits"] == 4:
                # a 4-bit predicate window is the 3-bit predicate plus its `!` bit (the vendor prints `!PT` for 15; a
                # plain `pred` of 4 bits printed `P15`): split into the measured rows' `pred` + `neg` pair
                nf["bits"] = 3
                target_fields.append(nf)
                target_fields.append({"bits": 1, "extraction": "neg", "shift": f["shift"] + 3, "token_idx": f["token_idx"]})
                v.setdefault("fields_fix", []).append([f["shift"], f["extraction"] + "4", f["extraction"] + "3+neg"])
                continue
            target_fields.append(nf)
        for ext, shift, nb, tok in v.get("fields_add", []):
            if not any(tf["shift"] == shift for tf in target_fields):
                target_fields.append({"bits": nb, "extraction": ext, "shift": shift, "token_idx": tok})
        for prefix, extra in MANUAL_FIELDS.get(args.family, {}).items():
            if key.startswith(prefix):
                for ext, bit, nb, slot, *excluded in extra:
                    if excluded and any(m in group.split(",") for m in excluded[0]):
                        continue
                    tok_slot = next((tf["token_idx"] for tf in target_fields if tf["shift"] == slot and is_reg(tf["extraction"])), None)
                    if tok_slot is None or any(tf["shift"] == bit for tf in target_fields):
                        continue
                    target_fields.append({"bits": nb, "extraction": ext, "shift": bit, "token_idx": tok_slot})
                    if bit in by_class["inert"]:
                        by_class["inert"].remove(bit)
                    by_class["cubit_law"].append([bit, nv.cache[(w0 ^ (1 << bit)) | CTRL]])
                    v.setdefault("fields_add", []).append([ext, bit, nb, tok_slot])
        rec["fields"] = [[tf["shift"], tf["bits"], tf["token_idx"], tf["extraction"]] for tf in target_fields]
        for c in ("field", "modifier", "operand_other", "glyph", "complex", "field_wrong", "cubit_law"):
            if by_class[c]:
                rec[c] = by_class[c]
        rec["inert"] = by_class["inert"]
        rec["illegal"] = by_class["illegal"]
        if v.get("fields_add"):
            rec["fields_add"] = v["fields_add"]
        if v.get("fields_fix"):
            rec["fields_fix"] = v["fields_fix"]
        if v.get("reuse_inert"):
            rec["reuse_inert"] = v["reuse_inert"]
        if v.get("paired_type"):
            rec["paired_type"] = v["paired_type"]
        # cubit on the canonical word
        c0 = cubit[w0 | CTRL]
        v["cubit"] = {k: c0.get(k) for k in ("cubit_key", "cubit_group", "cubit_text_lossless", "reencode", "cubit_error", "vendor_encode") if k in c0}
        # a re-encode the encoder refuses on a silicon law (BUG-037: multi-register MMA operands off their alignment)
        # is the `silicon_illegal` class of tools/audit_dynamic.py: the text is the vendor's, the word is not mintable
        # an encoder refusal that cites a silicon measurement, not a table gap: "silicon" (BUG-037 / 008 on sm120), and
        # on sm_103a / sm_100a (T-23) "SILICON-ILLEGAL" (BUG-077 / 088: the odd 64-bit base of a descriptor pair, the
        # LDS / STS / LDC .64 / .128 register alignment) and BUG-080's "SILENTLY BROKEN" guarded non-EL atomics
        def silicon(c):
            e = str(c.get("reencode", ""))
            return e.startswith("error:") and ("silicon" in e.lower() or "violates the sm_10" in e
                                               or ("SILENTLY BROKEN on sm_" in e and "BUG-080" in e))
        # cubit-side findings are kept apart from the vendor-side ones: the row's structure is decided by nvdisasm; a
        # cubit text / re-encode difference is either healed by the structure apply writes (the fixed field types,
        # the added fields -- checked by re-running the probe on the applied table) or a cubit defect to fix
        cp = v["cubit_problems"] = []
        if "cubit_error" in c0:
            cp.append(f"cubit does not decode the canonical word: {c0['cubit_error'][:80]}")
        else:
            if (c0["cubit_key"], c0["cubit_group"]) != (key, group):
                cp.append(f"cubit decodes the canonical word through {c0['cubit_key']} / {c0['cubit_group']!r} (shadowed)")
                v["shadowed_by"] = [c0["cubit_key"], c0["cubit_group"]]
            if c0["cubit_text_lossless"] != t0:
                cp.append(f"cubit prints {c0['cubit_text_lossless']!r} for {t0!r}")
            if c0["reencode"] != "ok" and not silicon(c0):
                cp.append(f"re-encode {c0['reencode']}")
            if silicon(c0):
                rec["silicon"] = True
        # the field words in cubit: every one must decode to the row with the vendor text and re-encode (or be
        # refused on the silicon law)
        bad_field_words = 0
        silicon_words = []
        for b, t in by_class["field"]:
            c = cubit[(w0 ^ (1 << b)) | CTRL]
            if silicon(c) and c.get("cubit_text_lossless") == t:
                silicon_words.append(b)
                continue
            if "cubit_error" in c or c.get("cubit_text_lossless") != t or c.get("reencode") != "ok":
                bad_field_words += 1
                if bad_field_words <= 3:
                    cp.append(f"field word bit {b}: cubit {c.get('cubit_text_lossless', c.get('cubit_error', ''))[:60]!r} "
                              f"re-encode {c.get('reencode')} for {t!r}")
        if silicon_words:
            rec["silicon_bits"] = silicon_words
        # a row none of whose own words cubit decodes through it, every one printed vendor-true by a sibling key that
        # spells an elided operand (`[UR4+0x10]` is the `[RZ+UR4+0x10]` word): an encoder-only row -- its fields are
        # the vendor's, the test does not ask the decoder to reach it
        own_words = [w0 | CTRL] + [(w0 ^ (1 << b)) | CTRL for b, _ in by_class["field"]]
        if own_words and all("cubit_error" not in cubit[w] and (cubit[w]["cubit_key"], cubit[w]["cubit_group"]) != (key, group)
                             for w in own_words):
            rec["shadow_only"] = True
        # witnesses
        rec["witnesses"] = []
        fm = sum(((1 << tf["bits"]) - 1) << tf["shift"] for tf in target_fields)
        for w in witness_of[(key, group)]:
            t = nv.cache[w]
            rec["witnesses"].append([f"{w:032x}", t])
            c = cubit[w]
            if t is None:
                v["problems"].append(f"census witness {w:032x} is illegal for nvdisasm")
            elif "cubit_error" in c or c.get("cubit_text_lossless") != t or (c.get("reencode") != "ok" and not silicon(c)):
                cp.append(f"census witness {w:032x}: cubit {c.get('cubit_text_lossless', c.get('cubit_error', ''))[:60]!r} for {t!r}")
            # the witness must lie inside the row's measured shape: its constant bits equal and_base's
            if (w & ~SCHEDULE & ~fm) != (int(row["and_base"], 16) & ~SCHEDULE & ~fm):
                v["problems"].append(f"census witness {w:032x} carries bits outside the fields")
        wave = next((r for pfx, r in EXCEPTION_PREFIXES.get(args.family, {}).items() if key.startswith(pfx)), None)
        if key in DELETE.get(args.family, {}):
            # T-19: a junk key deleted whole (its words are another form's or an illegal plane; 0 census witnesses)
            v["status"] = "deleted"
            rec["reason"] = DELETE[args.family][key]
        elif (key, group) in MODELLED.get(args.family, {}):
            # T-19: a row the project keeps on purpose -- `_src: "modelled"`, the pinning test named
            v["status"] = "modelled"
            rec["test"], rec["reason"] = MODELLED[args.family][(key, group)]
            if v["problems"]:
                rec["sweep_findings"] = v["problems"]
        elif (key, group) in EXCEPTIONS.get(args.family, {}):
            v["status"] = "exception"
            rec["reason"] = EXCEPTIONS[args.family][(key, group)]
        elif wave is not None:
            v["status"] = "exception"
            rec["reason"] = wave
        elif v["problems"]:
            v["status"] = "harvest"
            rec["reason"] = v["problems"][0][:200]  # the first vendor-side finding: the row stays harvest, named
        else:
            v["status"] = "measured"
        # a row whose canonical word cubit already decodes through another key that prints the vendor's text and
        # re-encodes it bit-exact is unreachable (a byte-identical `_P_` twin, a `_?` junk spelling, a dotted twin of a
        # plain key's group, the integer spelling of a float-immediate form): it retires as a `_meta.key_aliases`
        # entry -- whatever else is wrong with its structure
        # (a row the census reaches -- production words cubit decodes through it -- is alive whatever its canonical
        # word does: S2R_R_L's `SR_TID.X` words vs the `SR90` spelling of the probe's immediate)
        # ... and only when the shadowing key is a twin of this one: the same operand signature (a dotted twin), the
        # integer spelling of a float-immediate form (`_II` for `_FI`), a junk spelling (`?`, or more operand tokens
        # than the vendor's text has), or a byte-identical row structure (the `_P_` tensor twins). A key that prints
        # the same text with an operand elided (`[UR4+0x10]` for `[RZ+UR4+0x10]`, `LDC` without its register, the
        # explicit-predicate `_P` variants, IADD3's carry-in predicates) is NOT a twin: it is the encoder's path for
        # the other spelling (the BUG-464 pattern) and stays, measured or named.
        def twin_ok(target_key):
            if target_key == key:
                return False
            sig_k, sig_t = key.split("_", 1)[1] if "_" in key else "", target_key.split("_", 1)[1] if "_" in target_key else ""
            if "?" in key or sig_k == sig_t or sig_k.replace("II", "FI") == sig_t.replace("II", "FI"):
                return True
            vendor_sig = (kt.get("base_key") or "").split("_", 1)[1] if "_" in (kt.get("base_key") or "") else ""
            if sig_k.count("_") + 1 > vendor_sig.count("_") + 1 and vendor_sig:
                return True  # phantom operand tokens in the harvest key (the `_P_` tensor twins: no P in any text)
            # (a byte-identical row under a different signature is NOT a twin: `LDC_R_cARI` / `LDC_R_cAI` share
            # their words at RZ, but each key is the encoder's path for its own spelling -- the census writes both)
            return False
        if v["status"] not in ("exception", "modelled", "deleted") and "shadowed_by" in v and c0["cubit_text_lossless"] == t0 \
                and (c0["reencode"] == "ok" or silicon(c0)) and not witness_of[(key, group)] and twin_ok(v["shadowed_by"][0]):
            if mnemonic_of(v["shadowed_by"][0]) == mnemonic_of(key):
                v["status"] = "alias"
            else:
                # a harvest key named after one mnemonic whose bits are another's (`F2IP.U8.F32.NTZ_P_R_R_R_R` is an
                # HMMA word): no alias across mnemonics -- the row is dead, the key empties and goes
                v["status"] = "dead"
            rec["target"] = v["shadowed_by"][0]
        if key in MANUAL_ALIAS.get(args.family, {}) and wave is None:
            v["status"] = "alias"
            rec["target"] = v.get("shadowed_by", [MANUAL_ALIAS[args.family][key]])[0]
            rec["manual"] = True
        if (key, group) in MANUAL_DEAD.get(args.family, {}) and wave is None:
            v["status"] = "dead"
            rec["target"] = MANUAL_DEAD[args.family][(key, group)]
            rec["manual"] = True
        rec["status"] = v["status"]
        stats[v["status"]] += 1
        fixture.append(rec)
        verdict["rows"].append(v)
    # a key retires only whole: every row of the key must be an alias (none may stay) and the target must be a key
    # that stays; the key's alias target is the target of its most-witnessed row (the rows of a junk key may be
    # decoded by different real keys -- the alias is the name's forwarding address, the words have their own rows)
    rows_of_key = {k: list(e.get("mod_groups", {})) for k, e in table["instructions"].items()}
    by_key = collections.defaultdict(list)
    for rec, v in zip(fixture[1:], verdict["rows"]):
        by_key[rec["key"]].append((rec, v))
    retiring = {}
    for k, pairs in by_key.items():
        if all(r["status"] == "alias" for r, _ in pairs) and len(pairs) == len(rows_of_key[k]):
            best = max(pairs, key=lambda p: (p[1].get("count") or 0))
            retiring[k] = best[0]["target"]
    # a target that retires itself forwards to its own target (resolved to a fixpoint; a cycle keeps the keys)
    for k in list(retiring):
        seen, t = {k}, retiring[k]
        while t in retiring and t not in seen:
            seen.add(t)
            t = retiring[t]
        if t in seen:
            del retiring[k]
        else:
            retiring[k] = t
    for rec in fixture[1:]:
        # a row target that retires itself forwards to its own alias target (the `S2R_R_L_II` -> `S2R_R_II` ->
        # `S2R_R_L` chain): the test decodes the word through the key that stays
        if rec.get("target") in retiring:
            rec["target"] = retiring[rec["target"]]
    for rec, v in zip(fixture[1:], verdict["rows"]):
        if rec["status"] == "alias":
            if rec["key"] in retiring:
                rec["alias_target"] = retiring[rec["key"]]
            else:
                # an unreachable row of a key that stays (its other rows are live): cubit decodes its canonical word
                # through another key with the vendor text -- the row is dead and is deleted (documented here and
                # asserted by the test: the key keeps its live rows, the word keeps its real row)
                stats["alias"] -= 1
                stats["dead"] += 1
                rec["status"] = v["status"] = "dead"
    n_cubit = sum(1 for v in verdict["rows"] if v["status"] == "measured" and v["cubit_problems"])
    stats["measured_with_cubit_problems"] = n_cubit

    out = pathlib.Path(args.out) if args.out else nvprobe.FIXTURES / f"sm120_rows_{args.family}_nvdisasm.jsonl"
    nvprobe.write_fixture(out, fixture)
    vpath = pathlib.Path(args.verdict) if args.verdict else out.with_name(f"rows_{args.family}_verdict.json")
    vpath.write_text(json.dumps(verdict, indent=1) + "\n")
    print(f"{out}: {len(rows)} rows; {dict(stats)}; verdict {vpath}")
    per_key = collections.defaultdict(collections.Counter)
    for v in verdict["rows"]:
        per_key[v["key"]][v["status"]] += 1
    for k in sorted(per_key):
        print(f"  {k:52s} {dict(per_key[k])}")


# --- apply -----------------------------------------------------------------------------------------------------

def note_for(family: str, rec: dict, arch: str = "SM120", session: str | None = None) -> str:
    inert = rec.get("inert", [])
    illegal = rec.get("illegal", [])
    mods = [b for b, _ in rec.get("modifier", [])]
    other = [b for b, _ in rec.get("operand_other", [])]
    glyph = [b for b, _ in rec.get("glyph", [])]
    added = "; ".join(f"{e} {s} tok {t}" for e, s, _n, t in rec.get("fields_add", []))
    extra = f" Fields the harvest never declared, added from the sweep: {added}." if added else ""
    reuse = rec.get("reuse_inert", [])
    extra += f" Declared .reuse bits {reuse} are text-inert for nvdisasm (kept: inert on silicon, KNOWN_ISSUES A12)." if reuse else ""
    paired = rec.get("paired_type", [])
    extra += (f" Bit {paired} re-types both packed-half immediates together with the `BF16_V2` modifier (the other group's "
              f"word: the same 16-bit patterns print as bf16 / f16 literals) -- a modifier bit, measured by T-19 (NEEDS 55b).") if paired else ""
    renamed = RENAMED_FROM.get(family, {}).get((rec["key"], rec["group"]))
    extra += (f" Renamed by session T-19 (2026-11-08) from the harvest key `{renamed}`: the old name did not spell the vendor "
              f"text of the row's own word (R's key-naming rule: rename to the vendor's spelling; 0 census witnesses).") if renamed else ""
    who = f"session G run 5, {DATE}" if arch == "SM120" and session is None else (session or f"session T-23, 2026-11-08")
    tool = f"tools/probes/re_sm120_rows.py --family {family}" + ("" if arch == "SM120" else f" --arch {arch}")
    return (f"Row verified field by field with nvdisasm 13.1 (-b {arch}; {who}, "
            f"{tool}): canonical word {rec['w0']} = `{rec['t0']}`; every field bit "
            f"moves its own operand token; bits outside the fields: modifier bits {mods} (other groups' words), "
            f"neighbouring-form bits {other}, vendor-invalid glyph planes {glyph}, illegal {illegal}, text-inert {inert} "
            f"(fail closed: the mask is the fields).{extra}")


def apply(args):
    path = pathlib.Path(args.table)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    family = args.family
    src = tag_of(family)
    fixture_path = pathlib.Path(args.fixture) if args.fixture else nvprobe.FIXTURES / f"sm120_rows_{family}_nvdisasm.jsonl"
    recs = [json.loads(l) for l in fixture_path.read_text().splitlines() if l.strip()][1:]
    tagged = added = 0
    for rec in recs:
        if rec["status"] != "measured":
            continue
        entry = ins.get(rec["key"])
        if entry is None or rec["group"] not in entry.get("mod_groups", {}):
            continue  # retired / renamed on this base
        row = entry["mod_groups"][rec["group"]]
        if row.get("_src") is not None and row.get("_src") != src:
            continue  # measured by someone else meanwhile
        # the measured field list: the declared fields (float extractions where the harvest spelled a float immediate
        # as an integer) plus the guard / sign / abs / reuse bits the sweep found on this row's operands
        old = {(f["shift"], f["bits"]): f for f in row.get("fields", [])}
        fields = []
        new_fields = 0
        for shift, bits, tok, ext in rec["fields"]:
            f = dict(old.get((shift, bits), {}))
            if not f or f.get("extraction") != ext or f.get("token_idx") != tok:
                new_fields += 1
            f.update({"bits": bits, "extraction": ext, "shift": shift, "token_idx": tok})
            f.setdefault("_src", src)
            fields.append(f)
        mask = fields_mask(fields)
        base = int(row["and_base"], 16) & ~SCHEDULE & ~mask
        if row.get("_src") == src and new_fields == 0 and len(fields) == len(old) \
                and int(row["and_base"], 16) == base and int(row["variable_mask"], 16) == mask:
            continue  # already applied with this structure: the row (and a hand-extended `_note`) stays as it is
        added += new_fields
        row["fields"] = fields
        row["and_base"] = f"0x{base:032x}"
        row["variable_mask"] = f"0x{mask:032x}"
        row["_src"] = src
        row["_note"] = note_for(family, rec, getattr(args, "arch", "SM120"), getattr(args, "session", None)) \
            + (f" {args.note_suffix}" if args.note_suffix else "")
        tagged += 1
    # T-19: the modelled rows -- `_src: "modelled"`, the pinning test in the note; a field list the sweep corrected is
    # written (fields only: the mask widens to cover the added fields, nothing narrows -- bug012's relaxed decode)
    modelled = 0
    for rec in recs:
        if rec["status"] != "modelled":
            continue
        entry = ins.get(rec["key"])
        if entry is None or rec["group"] not in entry.get("mod_groups", {}):
            continue
        row = entry["mod_groups"][rec["group"]]
        spec = MANUAL_ROW_FIELDS.get(family, {}).get((rec["key"], rec["group"]))
        if spec is not None:
            # an explicit corrected field list (the sweep's finding on a design row): written, the mask widened to cover it
            old = {(f["shift"], f["bits"], f["extraction"], f["token_idx"]): f for f in row.get("fields", [])}
            fields = []
            for s, b, e, t in spec:
                f = dict(old.get((s, b, e, t), {"_src": "modelled"}))
                f.update({"bits": b, "extraction": e, "shift": s, "token_idx": t})
                fields.append(f)
            row["fields"] = fields
            row["variable_mask"] = f"0x{int(row['variable_mask'], 16) | fields_mask(fields):032x}"
            row["and_base"] = f"0x{int(row['and_base'], 16) & ~fields_mask(fields):032x}"
        row["_src"] = "modelled"
        findings = rec.get("sweep_findings")
        row["_note"] = (f"Kept by the project's design (session T-19, 2026-11-08, R's decision): {rec['reason']}. Pinned by "
                        f"{rec['test']}. The row probe (tools/probes/re_sm120_rows.py --family {family}) swept it like every other "
                        f"row: canonical word {rec['w0']} = `{rec['t0']}`" + (f"; findings outside the design: {findings}" if findings else "") + ".")
        modelled += 1
    retired, deleted = [], []
    dead = 0
    alias_targets = set(table["_meta"].get("key_aliases", {}).values()) | {rec.get("alias_target") for rec in recs}
    for rec in recs:
        if rec["status"] == "deleted" and rec["key"] in ins:
            del ins[rec["key"]]
            deleted.append(rec["key"])
    for rec in recs:
        if rec["status"] == "dead" and rec["key"] in ins and rec["group"] in ins[rec["key"]].get("mod_groups", {}):
            if len(ins[rec["key"]]["mod_groups"]) == 1 and rec["key"] in alias_targets:
                print(f"  keeping the last row of alias target {rec['key']} ({rec['group']!r}) -- dead by the probe, needed by the aliases")
                continue
            del ins[rec["key"]]["mod_groups"][rec["group"]]
            dead += 1
            if not ins[rec["key"]]["mod_groups"]:
                del ins[rec["key"]]
                deleted.append(rec["key"])
    aliases = sorted({(rec["key"], rec["alias_target"]) for rec in recs if rec["status"] == "alias"}) + list(args.alias or [])
    for junk, target in aliases:
        if junk in ins and target in ins:
            del ins[junk]
            table["_meta"].setdefault("key_aliases", {})[junk] = target
            retired.append(junk)
    for junk in (args.delete or []):
        if junk in ins:
            del ins[junk]
            deleted.append(junk)
    prov = table["_meta"]["provenance"]
    rows = [g for e in ins.values() for g in e.get("mod_groups", {}).values()]
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    arch = getattr(args, "arch", "SM120")
    prov["sources"][src] = {"rows": sum(1 for g in rows if g.get("_src") == src),
                            "kind": f"nvdisasm 13.1 per-row field verification over the whole word (-b {arch})",
                            "date": DATE if arch == "SM120" else "2026-11-08",
                            "tool": f"tools/probes/re_sm120_rows.py --family {family}" + ("" if arch == "SM120" else f" --arch {arch}"),
                            "test": getattr(args, "test", None) or f"tests/sm120_rows_{family}.rs"}
    n_modelled = sum(1 for g in rows if g.get("_src") == "modelled")
    if n_modelled:
        prov["sources"]["modelled"] = {"rows": n_modelled, "kind": "kept by the project's design, not a measurement: the row's "
                                       "`_note` names the cubit test that pins it (session T-19, 2026-11-08; KNOWN_ISSUES T1)",
                                       "date": "2026-11-08", "tool": "tools/probes/re_sm120_rows.py (MODELLED)",
                                       "test": "tests/sm120_rows_<family>.rs"}
    nvprobe.save_table(path, table)
    print(f"{path}: {tagged} rows tagged {src} ({added} fields added / retyped), {modelled} rows marked modelled, {len(retired)} keys "
          f"retired as aliases {retired}, {dead} dead rows deleted ({len(deleted)} keys emptied or deleted {deleted}); rows without "
          f"_src now {prov['rows_without_src']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--family", required=True, choices=sorted(FAMILIES))
    p.add_argument("--table", default=str(nvprobe.REPO / "tables" / "sm120.json"))
    p.add_argument("--census", default=None)
    p.add_argument("--witnesses", type=int, default=3)
    p.add_argument("--keys", nargs="*", default=None)
    p.add_argument("--also-harvest-in", default=None,
                   help="a second table the row must be a harvest row of too (skip rows another batch handles elsewhere)")
    p.add_argument("--nvdisasm", default=NVDISASM)
    p.add_argument("--arch", default="SM120")
    p.add_argument("--jobs", type=int, default=24)
    p.add_argument("--audit-words", default=str(nvprobe.REPO / "target" / "release" / "examples" / "audit_words"))
    p.add_argument("--text-keys", default=str(nvprobe.REPO / "target" / "release" / "examples" / "text_keys"))
    p.add_argument("--out", default=None)
    p.add_argument("--verdict", default=None)
    p.add_argument("--nv-cache", default=None, help="on-disk nvdisasm memo (session convenience, not read by tests)")
    a = sub.add_parser("apply")
    a.add_argument("table")
    a.add_argument("--family", required=True, choices=sorted(FAMILIES))
    a.add_argument("--fixture", default=None)
    a.add_argument("--verdict", default=None)
    a.add_argument("--alias", nargs=2, action="append", metavar=("JUNK", "TARGET"))
    a.add_argument("--delete", nargs="*")
    a.add_argument("--note-suffix", default=None, help="appended to the `_note` of every row this run tags")
    a.add_argument("--arch", default="SM120", help="the nvdisasm target the fixture was measured on (the provenance entry)")
    a.add_argument("--test", default=None, help="the cubit test that pins the rows (default tests/sm120_rows_<family>.rs)")
    a.add_argument("--session", default=None, help="who measured (written into the rows' `_note`; default: the T-23 passes)")
    args = parser.parse_args()
    if args.command == "probe":
        probe(args)
    else:
        apply(args)


if __name__ == "__main__":
    main()
