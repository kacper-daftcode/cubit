#!/usr/bin/env python3
"""Synchronize cubit's vendored ISA tables from blackwell-isa (O2 layout).

One table per architecture, vendored byte-exact, plus a single manifest at
tables/SOURCE.json pinning every table to the canonical revision:

  * default mode: copy tables/<arch>.json from the canonical checkout and
    rewrite the manifest (runs the test suite as a fail-closed gate),
  * --check: verify tables/*.json byte-match the manifest pins (CI byte-pin;
    with --source-repo present, also byte-compares against the canonical
    checkout at the pinned revisions),
  * --validate-only: structural validation of the vendored tables only
    (pre-check; no canonical repo needed).

The vendored files are generated data: never edit them by hand (rule R1).
Fixes go to the canonical database or to the export pipeline, then land here
through a new canonical revision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_REPO = ROOT.parent / "blackwell-isa"
TABLES_DIR = ROOT / "tables"
MANIFEST = TABLES_DIR / "SOURCE.json"

# arch name -> canonical _meta.architecture value
ARCH_TABLES = {
    "sm120.json": "SM120",
    "sm103a.json": "SM103a",
    "sm100a.json": "SM100a",
    "sm121a.json": "SM121A",
}

# Top-level records a canonical table may carry. The aux sections are O2
# layout payloads (single table per arch; no cubit sidecar data files).
ALLOWED_TOP_LEVEL = {
    "_meta", "instructions", "sched_only", "pipeline_config",
    "cost_model", "stallfix", "operand_roles",
}
AUX_SECTIONS = ("cost_model", "stallfix", "operand_roles")


class SyncError(RuntimeError):
    """A provenance or synchronization invariant failed."""


# Ratchet baselines for the baked control/reuse-bit check
# (and_base bits [127:105] set). Lower only on purpose, together with a
# silicon-verified canonical hygiene wave.
# 2026-08-26 fleet branch-landing wave (canonical cut f4dd6d6): SM120
# 456->519 (new silicon-verified ATOMS/ATOMG ARI rows bake the canonical
# control template, same convention as the pre-existing entries), SM103a
# 1269->1260 and SM100a 1257->1260 (dead-row/junk cleanup; lowered on
# purpose where the wave removed baked rows).
# same-day stack wave (27 1a891, BUG-195..206): SM120 519->653, SM103a
# 1260->1369, SM100a 1260->1373 -- witness-first dARI/scope rows carry the
# canonical control template like the rest of the family.
# 2026-08-27 BUG-215 (canonical b3efa8f): '64,EXCH' donor-clone of the
# bug204 EXCH row bakes the same b109 control bit as the donor -- +1 per
# table (SM120 659->660, SM103a 1388->1389, SM100a 1392->1393).
# 2026-08-27 BUG-221 (canonical 53d7c35): SYNCS family donor-clones from
# canonical sm100a (4 keys + 5 mg) carry the era-2aE control template like
# the rest of the family -- SM120 660->676 (16 donor-baked rows).
# 2026-08-27 BUG-224 (canonical ae6b248): base key SYNCS
# (mg CCTL,IVALL) donor bakes the same era-2aE template -- SM120 676->677.
# 2026-08-27 BUG-226 (canonical 091f993): FSETP/IADD3 donor-clones from
# canonical sm100a (15 R_R mgs + 4 IADD3 rows + II repairs) carry the era
# control template -- SM120 677->695.
# 2026-08-27 BUG-226 patch 2 (canonical 980e5cd): LEA/SHF int-shift block
# donor-clones from canonical sm100a (1 key + 7 mgs added, 2 rows replaced;
# every new row bakes the era-2aE control template) -- SM120 695->705.
# 2026-08-27 BUG-229 (canonical 68c352b): LEA .HI UR-row donor replacement
# bakes the donor template -- SM120 705->706.
# 2026-08-27 BUG-229b (canonical 35da13b): SHFL/USHF donor-law rewrite;
# 37 USHF + 4 SHFL R_R donor rows carry the era template (24 era scaffold
# keys deleted, none baked) -- SM120 706->747.
# 2026-08-28 BUG-234 (canonical 2aa6514): FFMA2_R_R_R_R donor clone bakes
# the donor ctrl[19:14]=0x3f template -- SM120 758->759.
# 2026-08-28 BUG-226d (canonical b2e5227): donor-law family closure
# (DFMA/UIMAD/FCHK/MUFU/VOTE/IDP/HMUL2) imports 44 net donor-era ctrl
# templates (42 era keys deleted, few baked; 22 replaced + 6 added carry
# donor envelopes) -- SM120 759->803.
# bug226e I2F/FENCE/USETMAXREG/F2F_R_UR donor rows bake the donor ctrl
# templates -- SM120 803->823->825 (+2 alias clones of the baked graft
# row on F2F.F64.F32_R_UR, BUG-240 2026-08-28).
# bug241 (canonical 8eaea28): donor-law HADD2_R_R_R wholesale clone (3
# rows) + SHF per-mg donor clones (14 rows replacing era/unbaked, 1 donor
# template added) carry baked ctrl templates; IMNMX II cell rows unbaked;
# LOP3 PAND clones +3 (sm120) / +2 (donors) -- SM120 825->844,
# SM103a 1389->1391, SM100a 1393->1395.
# 2026-09-02 BUG-343/344 (canonical a013f88): HFMA2 pure-reg krata 0x231
# mod-window closure -- 30 new base-key mgs + 12 RELU _P dotted keys per
# dense leg clone the plain/BF16_V2 parents of HFMA2_R_R_R_R and inherit
# the era donor ctrl template baked in their and_base [115:110] (same
# convention as the 274/279/285 FI_FI wave) -- SM120 981->1023,
# SM121A 499->541. Donors sm100a/sm103a untouched (owner scope).
# bug243 (canonical 0b6a753): HFMA2 wave -- 4 keys (RRRR x2 mg, UR x2 mg,
# FI_FI_R x2 mg, FI_FI x1 mg) wholesale from rebuilt donor rows carry the
# era-2aE ctrl template like the rest of the family -- SM120 844->851.
# 2026-08-28 BUG-244 (canonical 00c3fd2): donor F2F.F64.F32 closure --
# 3 rows carry the proven 226e/240 baked ctrl template per donor
# (F2F_R_UR[F64,F32] graft + F2F.F64.F32_R_UR {""/F32,F64} typed rows);
# typed F2F.F64.F32_R_R rows carry no baked ctrl bits -- SM103a
# 1391->1394, SM100a 1395->1398.
# 2026-08-28 BUG-247 (canonical b00b4eb): FMNMX tail-pred closure -- sm120/
# sm121a graft the 5 fixed donor FMNMX rows (R_R_R_P{'',FTZ,NAN} +
# R_R_UR_P{'',NAN}) carrying the proven era-2aE donor ctrl template
# (replaces un-baked era shells); donor row edits touch guard/pred bits
# only (no [127:105] delta) -- SM120 851->856, SM121A 458->463.
# 2026-08-28 BUG-249 (canonical 755183c): FSEL closure -- sm120/sm121a graft
# the 4 donor FSEL rows (R_R_R_P/R_R_FI_P/R_R_UR_P [''] + R_R_II_P
# [''] donor-clone) carrying the proven era-2aE donor ctrl template (era
# shells un-baked); donor UR-row rebuild touches guard/sign bits only (no
# [127:105] delta) -- SM120 856->860, SM121A 463->467.
# 2026-08-28 BUG-254 (canonical 9fd3368): sm121a DSETP donor-structure
# replacement -- 55 grafted DSETP mgs (R_R_P 25 + R_UR_P 16 + R_FI_P 14)
# carry the proven era-2aE donor ctrl template (31 of them), era keys
# deleted carried NONE -- SM121A 467->498.
# 2026-08-29 BUG-274 (canonical 740b225): HFMA2 packed-f16 op-suffix
# window [79:76] closure -- the FI_FI parent on sm120 bakes the era-243
# donor ctrl template (0x3f ctrl[19:14]) and its 11 new suffix mgs + 4
# RELU _P keys inherit the same and_base convention -- SM120 860->875.
# sm121a family rows carry no template (SM121A 498 unchanged).
# 2026-08-29 BUG-279 (canonical e819129): same family, FTZ/OOB graft --
# sm120: 8 new suffix mgs on the template-carrying FI_FI parent + 4 new
# RELU _P keys inherit the era-243 donor ctrl convention (SM120 875->891);
# sm121a/sm100a/sm103a unchanged.
# 2026-08-30 BUG-285 (canonical e41a438): same family, b85 BF16_V2
# cross-key graft -- sm120: 12 new mgs on the template-carrying FI_FI
# parent + 4 new RELU _P keys inherit the era-243 convention
# (SM120 891->907); sm121a/sm100a/sm103a unchanged.
# 2026-09-01 BUG-311 (canonical 8fc8395): sm120 LDGSTS desc '128,E'
# (L1-allocate) rows on LDGSTS_ARI_dARI{,_P} -- clones of the BYPASS
# donors; inherit the donor ctrl template (SM120 907->909);
# sm121a/sm100a/sm103a unchanged.
# 2026-09-01 BUG-320/321 (canonical 1e2b7ba): sm120 HFMA2_R_R_R_R pure-reg
# residuum closure -- 4 new mg lanes (F32/FMZ/F32,FMZ/BF16_V2,FMZ) clone
# the template-carrying ''/BF16_V2 donors (SM120 909->913);
# sm121a/sm100a/sm103a unchanged (sm121a rows carry no ctl template).
# 2026-09-01 BUG-324 (canonical a0dbda7): sm120 pure-reg/clustered R-form
# suffix-window closure -- 35 mgs + 12 RELU _P keys on the template-carrying
# donors HFMA2_R_R_UR_R / HMUL2_R_R_R / HMUL2_R_R_UR inherit era ctrl
# (SM120 913->979); sm121a/sm100a/sm103a unchanged (no ctl template there).
# 2026-09-01 BUG-334 (canonical bfc8480): sm100a/sm103a LDGSTS desc
# L1-allocate '128,E' rows on LDGSTS_ARI_dARI{,_P} -- clones of the BYPASS
# donors; inherit the donor ctrl template (SM103a 1394->1396, SM100a
# 1398->1400); sm100a donor imm2 flip 21/19->12b@32 touches extraction
# bits only (no [127:105] delta); sm120/sm121a unchanged.
# 2026-09-02 BUG-339/340 (canonical 02c147d): sm120 F2I generic clones
# 'S64,TRUNC' (donor sm103a) + 'F64,TRUNC' (121a) inherit donor-era baked
# ctrl in and_base (SM120 979->981); era-key clones + sm121a grafts carry
# none in the baked window; SM121A 498->499 for its generic S64,TRUNC
# donor clone (era-key grafts carry none); donors untouched.
# 2026-09-02 BUG-354 (canonical 5c12995): HFMA2 sparse-leg FI/II lattice
# mod-lane closure -- 11 new mgs + 6 dotted _P keys per sparse leg clone
# the plain/BF16 donors of HFMA2_R_R_R_FI_FI and inherit the 2aE-era donor
# ctrl template baked in their and_base [127:105] (same convention as the
# 274/279/285 FI_FI wave and the 343/344 dense graft) -- SM100a
# 1400->1416 (true 1399+17), SM103a 1396->1412 (true 1395+17). Dense legs
# untouched (SM120/SM121A ratchets stand).
# 2026-09-03 BUG-348: SM121A 499->511 (true 511 = 499+12) -- the 12 grafted
# HMUL2_R_R_R rows are a strict clone of the post-324 sm120 donor set and
# inherit the canonical 226d-era control template baked in and_base
# [127:105] (same convention as the 274/279/285/324/343/344/354 waves);
# the 2 deleted era squatter rows baked no [127:105] bits (net +12).
# 2026-09-03 BUG-359: SM100a 1416->1420, SM103a 1412->1416, SM120
# 1023->1029 -- 6 grafted LDGSTS_ARI_dARI{,_P} '128,E' x {LTC128B,ZFILL,
# both} rows per leg clone in-key donors and inherit the donor's baked
# control template in and_base[127:105]: 4/6 on sm100a/sm103a (the dARI_P
# ZFILL chain donors '128,BYPASS,E,*ZFILL' bake no [127:105] bits), 6/6
# on sm120 (chain donors post-311 '128,E'/'128,E,LTC128B' bake). True
# 1420/1416/1029. SM121A ratchet stands (dotted keys untouched).
# 2026-09-03 BUG-360 (canonical 32cde7a): SM100a 1420->1423, SM103a
# 1416->1419, SM120 1029->1033 -- grafted LTC256B rows clone the LTC128B
# donors and inherit their baked control template in and_base[127:105]:
# 3/leg on 100a/103a (dARI 'E,LTC256B' + dARI_P x2; the dARI
# '64,E,LTC256B' era row was already counted), 4 on sm120 (dARI
# '64,E,LTC256B' additionally grafted -- era row absent there; first-run
# pin t360_5 evidence). Part A imm2 flips + Part B/C ur0 9b->8b touch
# extraction bits / field masks only (no [127:105] delta). SM121A
# ratchet stands (dotted keys untouched).
# 2026-09-04 BUG-363 (canonical fbcef1c, AMEND of 53f897c): the two deleted
# legacy F2I_R_R FTZ mgs (lane 0x31 'FTZ,NTZ' dst@15 sev-A corrupt + lane
# 0xf0 'FTZ,NTZ,TRUNC,U32' guard-pinned) carried one baked donor-era ctrl
# template each on the 100a/103a legs -- lowered where the wave removed
# them: SM103a 1419->1418, SM100a 1423->1422. The 96+96 keyed era
# replacements bake no [127:105] bits (ab=0x0305|lane<<72|byte10<<80);
# SM120/SM121A stand (their deleted twins carried no baked template).
# 2026-09-04 BUG-367 (canonical 0933cf6): SM100a 1422->1452, SM103a
# 1418->1448 -- 30 grafted rows/leg (12 DIRECT + 6 BF16 + 6 RELU base
# mgs + 6 RELU _P dotted keys on HFMA2_R_R_R_FI_FI) clone the local
# sparse '' donor and inherit its baked control template in
# and_base[127:105] (same convention as the 354 wave, true
# 1422+30/1418+30). SM120 1033 / SM121A 511 stand (dense legs
# untouched, graft corpus-invisible).
# 2026-09-04 BUG-373+374+375 (canonical 883323c): SM120 1033->1036 --
# 3 grafted LDGSTS desc rows (np '128,BYPASS,E,ZFILL' + _P '128,BYPASS,E'
# + _P '128,BYPASS,E,ZFILL') clone era donors and inherit the baked ctrl
# template in and_base[127:105]. SM100a 1452->1454, SM103a 1448->1450
# (np + _P '128,BYPASS,E' grafts, same donor inheritance). SM121A 511
# stands (dotted-family donors carry no baked [127:105] bits).
# 2026-09-04 BUG-376 (canonical c574778): SM100a 1454->1471, SM103a
# 1450->1467, SM120 1036->1058 -- grafted LDGSTS desc LTC-lattice rows
# (LTC64B x6 bases + LTC256B x4 bases + code-2 BYPASS.ZFILL cross,
# np/_P donor clones) inherit their in-leg in-side donor's baked
# control template in and_base[127:105] VERBATIM: true counts 17/17/22/0
# (era: non-ZFILL row-donors bake the plain-era template; on 100a/103a
# the _P ZFILL donors bake none, on sm120 all _P donors bake; measured,
# not assumed). SM121A 511 stands (dotted-key donors hi32==0 asserted in
# patch376.py).
# 2026-09-05 BUG-380 (canonical a53eb20): SM100a 1471->1487, SM103a
# 1467->1483, SM120 1058->1063, SM121A 511->516 -- the F2I F64-src
# lattice-completion rows (88 clones per the dst-class TRUNC donors)
# inherit the donor's baked ctrl template in and_base[127:105]
# VERBATIM: true counts +16/+16/+5/+5 (era: F64-dst clones carry the
# 0x000e2-era template of 'F64,TRUNC', U64/S64 clones the U64/S64-dst
# donor templates, U32-side clone donors bake none; dense legs: the 5
# 2026-09-05 BUG-381 (canonical 3cb31e4): HFMA2 0x231/0x7c31 sparse-leg
# lattice completion -- 22+12 mgs + 12 dotted keys per family per leg clone
# the local ''/BF16_V2 donors of HFMA2_R_R_R_R / HFMA2_R_R_UR_R and inherit
# the era donor ctrl template baked in and_base [127:105] (same convention
# as the 274/279/285/324/343/344/354/367 waves; true 1487+92 / 1483+92) --
# SM100a 1487->1579, SM103a 1483->1575. Dense legs untouched (SM120/SM121A
# ratchets stand).
# F64-dst keyed clones of F2I.F64.TRUNC_R_R bake its 0x000e62..).
# 2026-09-05 BUG-386 (canonical dbe5e91): SM100a 1579->1587, SM103a
# 1575->1583, SM120 1063->1075 -- the 12 grafted LDGSTS desc base-gap rows
# per era leg (6 np + 6 _P) clone in-side in-ZFILL-carrier donors and inherit
# the donor's baked control template in and_base[127:105] VERBATIM: true
# counts +8/+8/+12 (on 100a/103a the _P ZFILL-row donors carry none -> only
# the 6 np + 2 _P BYPASS grafts bake; sm120 _P donors uniform -> all 12
# bake). SM121A 516 stands (dotted-key grafts hi32==0 asserted in
# patch386.py).
# 2026-09-06 BUG-390 (canonical a10350c): SM100a 1587->1611, SM103a
# 1583->1607 (+24 per era leg: the 3 of 4 wide-family donor classes
# F64,TRUNC / F64,TRUNC,U64 / F64,S64,TRUNC bake the era-2aE template and
# the narrow clones inherit it verbatim x8 axes; U32-donor class unbaked),
# SM120 1075->1083, SM121A 516->524 (+8 per dense leg: only the
# F2I.S64.F64.TRUNC_R_R donor carries baked hi bits).
# 2026-09-06 BUG-403 (canonical 2285a05): SM100a 1611->1614, SM103a
# 1607->1610 (+3 per era leg: donor class shapes as 380/390 --
# 'F64,NTZ,TRUNC' / 'F64,NTZ,TRUNC,U64' / 'F64,NTZ,S64,TRUNC' inherit
# their wide TRUNC donors' baked era template, U32-side donor unbaked),
# SM120 1083->1084, SM121A 524->525 (+1 per dense leg: only the
# F2I.F64.TRUNC.NTZ_R_R clone of the baked F2I.F64.TRUNC_R_R donor
# 2026-09-07 BUG-400 (canonical 19363f6): SM100a 1614->1628, SM103a
# 1610->1624, SM120 1084->1098 (+14 per leg), SM121A 525->532 (+7) --
# the grafted pred/LTC window [64:72) rows clone the in-key donors of
# LDG_R_dARI (STRONG.U16 / 128,STRONG.SYS / 128,GPU.STRONG mgs) and
# LD_R_ARI|128,E and inherit their baked ctrl template in
# and_base[127:105] VERBATIM (same convention as the 274..390 waves);
# LD_R_dARI|E,S8 donors bake none (hi32==0 asserted) -> SM121A +7.
# MEASURED on the post-graft canonical (count of and_base>>105 entries),
# 2026-09-08 BUG-419 (canonical 2ae87b3): SM100a 1628->1677 (+49),
# SM103a 1624->1673 (+49), SM120 1098->1137 (+39), SM121A 532 (STOIC --
# the 121a FI_FI_R era row bakes hi32==0) -- the HADD2 0x430-route rows
# (7 mgs + 3 F32 dotted keys) and the HFMA2 0x7831-route rows (dotted mgs
# + RELU _P dotted keys) clone their FI FI / two-imm R-final parents'
# era ctrl template VERBATIM like the whole family convention; the
# and_base deltas of the graft are EXACTLY the measured route bits
# ([76:86) window) -- the extra [127:105) count comes from row COUNT,
# not new template bits.
# 2026-09-09 BUG-421+422 (canonical 13e13b6): SM120 1138->1139, SM103a
# 1674->1675, SM100a 1678->1679, SM121A 534->535 -- +1 ROW per leg =
# LDS_R_AURI|S16 inherits the U16/S8 high-band class verbatim
# (and_base[127:105] lineage U16_AB d96=0x000e2000, vm verbatim;
# the count is ROW count, not new template bits). The 14 LDSM enum
# mgs (M816/M832/MT1616) bake ZERO at [127:105) (d96=0 donor class).
# MEASURED post-graft (sync staging error sm120 1139 vs baseline).
# 2026-09-08 BUG-412+413(i) (canonical e4f0915): SM121A 532->533 --
# the STS_ARURI_R '' era row cloned to the sm100a/103a/120 donor shape
# inherits the donors' baked ctrl template in and_base[127:105]
# VERBATIM (donor shape identical x3, asserted in patch412413.py; era
# row had fake reuse@122/123 fields + 0x7988-era shape baking none).
# 2026-09-09 BUG-427 (canonical a5e6d0a): LDS_R_ARI|S16 +
# LDS_R_ARURI|S16 donor-clones of the frame-own U16 rows carry the U16
# donor's baked b109 control bit (same convention as the standing LDS
# family) -- +2 per leg (SM120 1139->1141, SM103a 1675->1677,
# SM100a 1679->1681, SM121A 535->537; measured, INC-233 norm).
# 2026-09-09 BUG-425 (canonical 3f6ca6f): SM121A 537->540 MEASURED
# (machine-diff pre_tabs vs canonical): + STS_ARURI_R|U8 (cross-leg donor
# = canonical sm103a row VERBATIM, norma patch412413 -- carries the donor
# family's baked ctrl template), + STS_AURI_R|U16 + STS_AURI_R|U8 (loose-''
# clones inherit the '' and_base [127:105) bits verbatim). STS_AURI_R|128
# clone does NOT join (width delta flips one baked-window bit OFF, delta
# machine-asserted). Sibling legs STOIC (1141/1677/1681 stand).
# 2026-09-10 BUG-425b (canonical 52cb73c): SM121A 540->541 MEASURED --
# R6 zastepuje 121a-era STS_ARURI_R|U16 (bez sub_imm1, baked ctl-val == 0)
# kanonicznym klonem sm103a VERBATIM; donor niesie [127:105) bake 0x1c000
# (b109-111 epoch/reuse shoulder) -- +1 STS_ARURI_R|U16 do rodziny
# baked-ctrl 121a (machine-diff pre_tabs vs sandbox; era row mial
# care-ctrl e3ffffff z 0x0 bake). Sibling legs STOIC; R7/R8v2/R9 nie
# dodaja baked (vm-care narrowing + field-decl removal, bez nowych wierszy
# z ctrl-wartosciami).
BAKED_CTRL_BASELINE = {"SM120": 1141, "SM103a": 1677, "SM100a": 1681,
                       "SM121A": 541}

FIXED_EXTRACTIONS = {
    "",
    "abs",
    "addr_scale",
    "barrier",
    "byte_sel",
    "cm16_off",
    "cm17_off",
    "bf16",
    "desc_ur",
    "dsel2",
    "f16",
    "f16_d",
    "f32",
    "f32cast",
    "f64hi",
    "gdesc_off",
    "gdesc_ur",
    "hsel",
    "h0nh1",  # BUG-271: b86 .H0_NH1 tok3 third-bit window (arb271 x4)
    "guard",
    "guard_lo3",
    "guard_neg",
    "imm",
    "imm_dec",
    "imm_dec_u32",
    "inv",
    "neg",
    "neg_abs",
    "neg_f32",
    "neg_shl1",
    "opaque_mod",
    "pred",
    "pred_inv4",
    "upred_gate",
    "urz_expl",
    "urz_expl_inv",
    "reg",
    "reg_ff",
    "reuse",
    "sub_imm0",
    "sub_imm0_s24",
    "sub_imm1",
    "sub_imm1_s24",
    "sub_imm2",
    "sub_r0",
    "sub_r1",
    "sub_r2",
    "sub_ur0",
    "sub_ur1",
    "sysreg",
    "sysreg_hi1",
    "sysreg_hi4",
    "sysreg_lo4",
    "sysreg_lo7",
    "upred",
    "ureg",
    "ureg_ff",
}

EXTRACTION_PATTERN = re.compile(
    r"(?:reg|ureg|imm)_shr\d+|"
    r"sub_(?:r|ur|imm)\d+(?:_m1)?(?:_shr\d+u?)?|"  # unsigned sub variants (BUG-070)
    r"opmod:[A-Za-z0-9_]+|"
    r"mnemod1:[A-Za-z0-9_]+|"
    r"t(?:desc|mem)_(?:off|ur)"
)
U128_MAX = (1 << 128) - 1


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SyncError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_u128(value: Any, context: str) -> int:
    if not isinstance(value, str):
        raise SyncError(f"{context} must be a hexadecimal string")
    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise SyncError(f"{context} is not valid hexadecimal: {value}") from exc
    if parsed < 0 or parsed > U128_MAX:
        raise SyncError(f"{context} does not fit in 128 bits: {value}")
    return parsed


def known_extraction(value: Any) -> bool:
    return isinstance(value, str) and (
        value in FIXED_EXTRACTIONS or EXTRACTION_PATTERN.fullmatch(value) is not None
    )


def run_git(repo: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False, capture_output=True, text=True,
    )
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise SyncError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()


def run_git_bytes(repo: Path, *args: str) -> bytes:
    """Binary-safe git read (no strip/newline mangling)."""
    result = subprocess.run(
        ["git", "-C", str(repo), *args], check=False, capture_output=True,
    )
    if result.returncode:
        raise SyncError(f"git {' '.join(args)} failed: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout


def canonical_revision(repo: Path, relative: str) -> str:
    repo_file = repo / relative
    run_git(repo, "ls-files", "--error-unmatch", "--", relative)
    dirty = run_git(repo, "status", "--porcelain", "--", relative)
    if dirty:
        raise SyncError(
            f"canonical source is not committed: {relative}\n{dirty}\n"
            "Commit blackwell-isa first so the vendored table has immutable provenance."
        )
    if not repo_file.is_file():
        raise SyncError(f"canonical table is missing: {repo_file}")
    # Pin the commit that last changed the table, not an unrelated newer docs
    # commit at repository HEAD. The clean-file check above guarantees that
    # this revision still describes the bytes being synchronized.
    return run_git(repo, "log", "-1", "--format=%H", "--", relative)


def canonical_repository_url(repo: Path) -> str:
    remote = run_git(repo, "remote", "get-url", "origin")
    if remote.startswith("git@github.com:"):
        remote = "https://github.com/" + remote.removeprefix("git@github.com:")
    if remote.endswith(".git"):
        remote = remote[:-4]
    return remote


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_aux_sections(table: dict[str, Any], arch_meta: str) -> None:
    cost = table.get("cost_model")
    if cost is not None:
        if not isinstance(cost, dict) or not cost.get("arch") \
                or "quantum_cy" not in cost or "dep_link_latency_slots" not in cost:
            raise SyncError("cost_model section fails sanity (arch/quantum/dep_link)")
        norm = lambda s: str(s).lower().replace("_", "")
        if norm(cost["arch"]) != norm(arch_meta):
            raise SyncError(
                f"cost_model arch {cost['arch']!r} mismatches table arch {arch_meta!r}")
    stall = table.get("stallfix")
    if stall is not None:
        if not isinstance(stall, dict) or "rules_version" not in stall \
                or "floor_global" not in stall:
            raise SyncError("stallfix section fails sanity (rules_version/floor_global)")
    roles = table.get("operand_roles")
    if roles is not None:
        if not isinstance(roles, dict) or not isinstance(roles.get("base_ops"), dict) \
                or not roles["base_ops"]:
            raise SyncError("operand_roles section fails sanity (base_ops)")


def validate_table(data: bytes, arch: str) -> dict[str, Any]:
    try:
        table: dict[str, Any] = json.loads(data, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SyncError(f"canonical table is not valid UTF-8 JSON: {exc}") from exc

    extra_top_level = sorted(set(table) - ALLOWED_TOP_LEVEL)
    # underscore-prefixed top-level keys are the reserved annotation zone
    # (sm121a carries the 121a lane's `_errata_*` evidence notes by design)
    soft_annotations = [k for k in extra_top_level if k.startswith("_")]
    hard_junk = [k for k in extra_top_level if not k.startswith("_")]
    if hard_junk:
        raise SyncError(f"unexpected top-level records: {', '.join(hard_junk)}")
    if soft_annotations:
        print(f"note: {len(soft_annotations)} reserved top-level annotations "
              f"(^-prefixed) tolerated ({extra_top_level[0]}, …)")

    meta = table.get("_meta", {})
    if meta.get("architecture") != arch or meta.get("instruction_width") != 128:
        raise SyncError(f"canonical table is not an {arch} 128-bit ISA database")

    instructions = table.get("instructions")
    if not isinstance(instructions, dict) or not instructions:
        raise SyncError("canonical table has no instruction map")

    validate_aux_sections(table, arch)

    ctrl_classes = set(meta.get("ctrl_classes", {}))
    legacy_ctrl_classes = {"none", "static_ctrl", "unknown"}
    variants = 0
    high_bit_entries: list[str] = []
    for key, entry in instructions.items():
        if not isinstance(entry, dict):
            raise SyncError(f"{key} must be an object")
        ctrl_class = entry.get("ctrl_class")
        if (
            ctrl_class is not None
            and ctrl_class not in ctrl_classes
            and ctrl_class not in legacy_ctrl_classes
        ):
            raise SyncError(f"{key} references unknown ctrl_class {ctrl_class!r}")
        groups = entry.get("mod_groups", {})
        if not isinstance(groups, dict):
            raise SyncError(f"{key}.mod_groups must be an object")

        for group, variant in groups.items():
            variants += 1
            context = f"{key}::{group}"
            if not isinstance(variant, dict):
                raise SyncError(f"{context} must be an object")
            and_base = parse_u128(variant.get("and_base"), f"{context}.and_base")
            if and_base >> 105:
                high_bit_entries.append(context)

            variable_mask = variant.get("variable_mask")
            if variable_mask is not None:
                parse_u128(variable_mask, f"{context}.variable_mask")

            fields = variant.get("fields", [])
            if not isinstance(fields, list):
                raise SyncError(f"{context}.fields must be an array")
            for index, field in enumerate(fields):
                field_context = f"{context}.fields[{index}]"
                if not isinstance(field, dict):
                    raise SyncError(f"{field_context} must be an object")
                shift = field.get("shift")
                bits = field.get("bits")
                token_idx = field.get("token_idx")
                if not isinstance(shift, int) or not isinstance(bits, int):
                    raise SyncError(f"{field_context} shift/bits must be integers")
                if shift < 0 or bits <= 0 or shift + bits > 128:
                    raise SyncError(
                        f"{field_context} exceeds the 128-bit instruction: "
                        f"shift={shift}, bits={bits}"
                    )
                if not isinstance(token_idx, int) or token_idx < 0:
                    raise SyncError(f"{field_context}.token_idx must be non-negative")
                extraction = field.get("extraction", "")
                if not known_extraction(extraction):
                    raise SyncError(
                        f"{field_context} uses unknown extraction {extraction!r}"
                    )

    baseline = BAKED_CTRL_BASELINE[arch]
    if len(high_bit_entries) > baseline:
        sample = ", ".join(high_bit_entries[:5])
        raise SyncError(
            f"{len(high_bit_entries)} templates bake control/reuse bits "
            f"[127:105] (baseline {baseline}): {sample}"
        )
    if high_bit_entries:
        print(
            f"note: {len(high_bit_entries)}/{baseline} baked-ctrl "
            f"templates (allowed by ratchet, {arch})"
        )

    return {
        "instruction_forms": len(instructions),
        "encoding_variants": variants,
        "sched_only_entries": len(table.get("sched_only", {})),
        "sections": sorted(
            k for k in table
            if k not in ("_meta", "instructions", "sched_only", "pipeline_config")
        ),
    }


def load_manifest() -> dict[str, Any]:
    if not MANIFEST.is_file():
        raise SyncError(f"manifest is missing: {MANIFEST}")
    try:
        manifest = json.loads(MANIFEST.read_text())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SyncError(f"invalid manifest {MANIFEST}: {exc}") from exc
    if manifest.get("schema") != 2 or not isinstance(manifest.get("tables"), dict):
        raise SyncError(f"{MANIFEST}: expected schema 2 with a 'tables' map")
    unknown = sorted(set(manifest["tables"]) - set(ARCH_TABLES))
    if unknown:
        raise SyncError(f"manifest lists unknown tables: {', '.join(unknown)}")
    return manifest


def sync_tables(source_repo: Path) -> None:
    source_repo = source_repo.resolve()
    repo_text = run_git(source_repo, "rev-parse", "--show-toplevel")
    repo = Path(repo_text).resolve()
    repository = canonical_repository_url(repo)

    staged: dict[str, tuple[bytes, dict[str, Any], str]] = {}
    for name, arch in ARCH_TABLES.items():
        data = (repo / name).read_bytes() if (repo / name).is_file() else None
        if data is None:
            raise SyncError(f"canonical table is missing: {repo / name}")
        summary = validate_table(data, arch)
        revision = canonical_revision(repo, name)
        staged[name] = (data, summary, revision)

    TABLES_DIR.mkdir(exist_ok=True)
    for name, (data, _summary, _rev) in staged.items():
        (TABLES_DIR / name).write_bytes(data)

    # 2026-08-26: write the manifest BEFORE the cargo gate. The gate's
    # arch_vendoring manifest_pin test compares vendored tables against the
    # manifest, so gating on a stale manifest made count-changing canonical
    # waves unlandable. The manifest pins exactly the bytes staged above.
    # One canonical revision for the whole vendoring (owner layout decision
    # 2026-08-25: a single base_revision for the manifest).  All tables must
    # carry their pinned bytes at that revision; canonical updates touching a
    # single table first, so table revisions are allowed to be older than the
    # newest one as long as the bytes match at the pinned revision.
    by_date = sorted(
        {rev for _d, _s, rev in staged.values()},
        key=lambda r: int(run_git(repo, "show", "-s", "--format=%ct", r)),
    )
    base_revision = None
    for rev in reversed(by_date):  # newest first
        if all(
            digest(run_git_bytes(repo, "show", f"{rev}:{name}")) == digest(data)
            for name, (data, _s, _r) in staged.items()
        ):
            base_revision = rev
            break
    if base_revision is None:
        raise SyncError(
            "canonical tables sit at divergent revisions with no common "
            "revision carrying the pinned bytes; make one canonical cut first")

    manifest: dict[str, Any] = {
        "schema": 2,
        "repository": repository,
        "base_revision": base_revision,
        "tables": {},
    }
    for name, (data, summary, _rev) in staged.items():
        manifest["tables"][name] = {
            "arch": ARCH_TABLES[name],
            "base_sha256": digest(data),
            **summary,
        }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")

    print("running cargo test gate on the vendored candidates...")
    result = subprocess.run(["cargo", "test", "--quiet"], cwd=ROOT, check=False)
    if result.returncode:
        raise SyncError(
            "candidate tables failed cargo test; vendored tables and the "
            "manifest were written (pin consistent with the tables)")
    for name, (_d, summary, _rev) in staged.items():
        print(
            f"synchronized {name}: {summary['instruction_forms']} forms / "
            f"{summary['encoding_variants']} variants from {base_revision[:12]}"
        )


def check_tables(source_repo: Path | None) -> None:
    manifest = load_manifest()
    base_revision = manifest.get("base_revision")
    for name, entry in manifest["tables"].items():
        entry.setdefault("base_revision", base_revision)  # schema-2 top-level pin
        dest = TABLES_DIR / name
        if not dest.is_file():
            raise SyncError(f"vendored table is missing: {dest}")
        actual = digest(dest.read_bytes())
        if actual != entry.get("base_sha256"):
            raise SyncError(
                f"{dest} does not match the manifest pin; "
                "run tools/sync_table.py after updating the canonical revision"
            )
        validate_table(dest.read_bytes(), ARCH_TABLES[name])
        print(f"pinned {name}: sha256 {actual[:16]}… ({entry['base_revision'][:12]})")
    if source_repo is not None:
        repo = source_repo.resolve()
        for name, entry in manifest["tables"].items():
            src = repo / name
            if not src.is_file():
                raise SyncError(f"--source-repo checkout lacks {src}")
            if digest(src.read_bytes()) != entry["base_sha256"]:
                raise SyncError(
                    f"{src} differs from the pinned bytes; bump the canonical "
                    "revision or re-sync"
                )
            # Immutable provenance: the pinned revision must carry exactly
            # the pinned bytes for this table.
            try:
                raw = run_git_bytes(repo, "show", f"{entry['base_revision']}:{name}")
            except SyncError:
                raw = b""
            if digest(raw) != entry["base_sha256"]:
                raise SyncError(
                    f"canonical revision {entry['base_revision'][:12]} does not "
                    f"carry the pinned bytes for {name}"
                )
        print(f"canonical checkout {repo} matches all pins")


def validate_only() -> None:
    for name, arch in ARCH_TABLES.items():
        dest = TABLES_DIR / name
        if not dest.is_file():
            raise SyncError(f"vendored table is missing: {dest}")
        summary = validate_table(dest.read_bytes(), arch)
        print(
            f"validated {name}: {summary['instruction_forms']} forms / "
            f"{summary['encoding_variants']} variants (structure, no pin)"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", type=Path, default=None,
                        help="canonical blackwell-isa checkout "
                             f"(default: {DEFAULT_SOURCE_REPO} when it exists)")
    parser.add_argument("--check", action="store_true",
                        help="verify manifest byte-pins without writing files")
    parser.add_argument("--validate-only", action="store_true",
                        help="structurally validate the vendored tables "
                             "(no canonical repo needed)")
    args = parser.parse_args()

    source_repo = args.source_repo
    if source_repo is None and DEFAULT_SOURCE_REPO.is_dir():
        source_repo = DEFAULT_SOURCE_REPO

    if args.validate_only:
        validate_only()
        return 0
    if args.check:
        check_tables(source_repo)
        return 0
    if source_repo is None:
        raise SyncError("no canonical checkout found (use --source-repo)")
    sync_tables(source_repo)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SyncError as exc:
        print(f"sync_table.py: error: {exc}", file=sys.stderr)
        raise SystemExit(1)
