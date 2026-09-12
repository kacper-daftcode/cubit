//! BUG-176 (F2-iter83b, front2/blind; queue = fleet note 158 sec.5
//! "P_-junk REDG (b11/F2 higiena)"): junk REDG `*_P_dARI_R` keys deleted
//! (data-only hygiene, 165/173-style).
//!
//! Class: REDG (reduction-to-global) has NO result operand in the vendor
//! ISA -- a `P` destination token in operand_sig is geometric nonsense.
//! 10 such keys sat in the tables: sm120: REDG.E.{ADD,AND,MAX.S32,MIN.S32,
//! OR,ADD.S32}[.STRONG.GPU]_P_dARI_R; sm103a: REDG_P_dARI_R (13 groups),
//! REDG.E.{ADD,AND,OR}.EL.STRONG.GPU_P_dARI_R.
//!
//! Census-first (work/bug176/census176.json, hexdb 32.2M): every junk group
//! 0 real anchors EXCEPT sm103a REDG_P_dARI_R::"E,GPU,MIN,STRONG" which
//! loose-matches 130 real vendor words `@P0 REDG.E.MIN.STRONG.GPU
//! desc[URn][R2.64], R5` (sm_100) — winner census pre-fix binary-driven:
//! 130/130 decoded by the honest REDG_dARI_R key (never-winner, same proof
//! shape as 173's shells).  Encode of a P-dest REDG text form was ALREADY
//! fail-closed on both tables ("operand 1 (P0) has no field able to encode
//! it").  => zero behavior change on every real population; hazard removed
//! (same as 173: a loose shell could start winning after future mask edits).
//!
//! Fix = data-only (work/bug176/patch176.py, replayable, state asserts):
//! DELETE the 10 keys; sm120 1549->1543 keys, sm103a 400->396 keys.
//! Compose: disjoint from all parked patches (155/156/158/161 REDG work
//! touches REDG_dARI_R / REDG_ARI_R / junk non-P dARI; 154 = SYNCS_P_dARI_R
//! = different family) — machine-checked.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    let d = idx.decode(w, 0, t).expect("decode");
    cubit::printer::to_sass(&d)
        .split("/* @sched")
        .next()
        .unwrap()
        .trim()
        .to_string()
}
fn enc_res(t: &IsaTable, text: &str) -> bool {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).is_ok()
}
fn w(hex: &str) -> u128 {
    u128::from_str_radix(hex, 16).unwrap()
}

/// t176_1: the 10 junk keys are gone; honest siblings stay.
#[test]
fn t176_1_junk_absent_honest_keep() {
    let t2 = t120();
    for k in [
        "REDG.E.ADD.S32.STRONG.GPU_P_dARI_R",
        "REDG.E.ADD.STRONG.GPU_P_dARI_R",
        "REDG.E.AND.STRONG.GPU_P_dARI_R",
        "REDG.E.MAX.S32.STRONG.GPU_P_dARI_R",
        "REDG.E.MIN.S32.STRONG.GPU_P_dARI_R",
        "REDG.E.OR.STRONG.GPU_P_dARI_R",
    ] {
        assert!(t2.entries.get(k).is_none(), "{k} must be deleted");
    }
    for k in [
        "REDG.E.MIN.STRONG.GPU_dARI_R",
        "REDG.E.MAX.S32.STRONG.GPU_dARI_R",
        "REDG_dARI_R",
    ] {
        assert!(t2.entries.get(k).is_some(), "{k} must remain");
    }
    // sm103a stays untouched: REDG_P_dARI_R there is NOT junk -- it is the
    // vendor-true PT-sink form family (tests/bug128_redg_pt_alias.rs: 13
    // groups, word-equality pins vs the unguarded form, real HW anchor),
    // and the 3 EL keys carry era goldens (b4fill2_rows.rs).
    let t3 = t103();
    for k in [
        "REDG_P_dARI_R",
        "REDG.E.ADD.EL.STRONG.GPU_P_dARI_R",
        "REDG.E.AND.EL.STRONG.GPU_P_dARI_R",
        "REDG.E.OR.EL.STRONG.GPU_P_dARI_R",
        "REDG_dARI_R",
    ] {
        assert!(
            t3.entries.get(k).is_some(),
            "{k} must remain (sm103a out of scope)"
        );
    }
}

/// t176_2: the 130-word loose-match population decodes vendor-exact through
/// the honest key (never-winner holds post-delete).
#[test]
fn t176_2_population_vendor_exact() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    for (hx, want) in [
        (
            "000000000c92e108000000050200098e",
            "@P0 REDG.E.MIN.STRONG.GPU desc[UR8][R2.64], R5",
        ),
        (
            "000000000c92e106000000050200098e",
            "@P0 REDG.E.MIN.STRONG.GPU desc[UR6][R2.64], R5",
        ),
    ] {
        assert_eq!(dec(&idx, w(hx), &t), want, "population {hx}");
    }
}

/// t176_3: encode of a P-dest REDG text form is fail-closed on both tables
/// (pre-existing posture kept; no span of accepted junk text is created).
#[test]
fn t176_3_encode_p_dest_fail_closed() {
    let t2 = t120();
    assert!(!enc_res(
        &t2,
        "REDG.E.MIN.STRONG.GPU P0, desc[UR8][R2.64], R5 ;"
    ));
    let t3 = t103();
    assert!(!enc_res(
        &t3,
        "REDG.E.MIN.STRONG.GPU P0, desc[UR8][R2.64], R5 ;"
    ));
}

/// t176_4: honest REDG anchors are untouched (decode == vendor, both tables).
#[test]
fn t176_4_honest_anchors_untouched() {
    let t3 = t103();
    let idx3 = DecodeIndex::build(&t3);
    assert_eq!(
        dec(&idx3, w("000000000c12e108000000112c00798e"), &t3),
        "REDG.E.ADD.STRONG.GPU desc[UR8][R44.64], R17"
    );
    assert_eq!(
        dec(&idx3, w("000000000d12e306000000050200098e"), &t3),
        "@P0 REDG.E.MAX.S32.STRONG.GPU desc[UR6][R2.64], R5"
    );
    // sm120-side honesty is covered by the corpus A/B gate (392/392 0-diff);
    // the desc-UR window quirks on arch-mixed words belong to parked-160.
}

/// t176_5: table shapes after the hygiene (pin the key counts).
#[test]
fn t176_5_table_shapes() {
    // 2026-08-26 compose: 1543 was the 176-era count; the landing wave moved
    // it further (ATOMS adds +12 REDG fabrication deletions +REDG_ARI_R
    // restore = 1535; each move has its own canon commit + suite pin).
    // 2026-08-27 BUG-221: +4 sm120 keys (SYNCS_{P_ARURI_R,R_ARI_R,
    // R_ARURI_R,UR_AURI_UR} donor-clones, canonical 53d7c35) = 1539.
    // 2026-08-27 BUG-224: +1 sm120 key (SYNCS base, mg CCTL,IVALL
    // donor-clone, canonical ae6b248) = 1540.
    // 2026-08-27 BUG-226 patch 2: +1 sm120 key (LEA_R_R_UR_II_P donor-clone,
    // canonical 980e5cd) = 1541.
    // 2026-08-27 BUG-229: -1 sm120 key (era LEA_R_R_II_R deletion, imm5==0x1e
    // baked constant row; canonical 68c352b) = 1540.
    // 2026-08-27 BUG-229b: -24 sm120 era scaffold keys (8 SHFL.{BFLY,IDX,UP}_*
    // + 16 USHF dotted/mod keys; donor-law rewrite, canonical 35da13b) = 1516.
    // 2026-08-28 BUG-230: -1 sm120 key (era phantom LEA_P0_R_R_R_II
    // deletion, sign bits restored to plain LEA row; canonical f34abc0) = 1515.
    // 2026-08-28 BUG-226c: -10 sm120 era phantom keys (FFMA_P_* x4,
    // FFMA_R_R_UR_R_R / FFMA_R_R_R_R_R 5-token dups, '_?' x4) +1 donor key
    // FFMA_R_R_R_UR; era UR_R[RM]/[RP] + R_R_R_II[RP] mgs dropped
    // fail-closed (canonical cb44e0b) = 1506.
    // 2026-08-28 BUG-234: +1 sm120 donor key FFMA2_R_R_R_R (graft-extended
    // t4 abs@74/neg@75/reuse@124; default lane mods in printer arm;
    // canonical 2aa6514) = 1507.
    // 2026-08-28 BUG-226d: -42 sm120 era phantom keys (DFMA x9, UIMAD x7,
    // MUFU x8, VOTE x6, HMUL2 x3, IDP x9) +6 donor keys (FCHK_P_R_UR,
    // IDP_R_R_R_R, IDP_R_R_UR_R, MUFU_R_FI, UIMAD_UR_UR_UR_UR_UP,
    // VOTE_P_P); donor-law family closure, canonical b2e5227) = 1471.
    // 2026-08-28 BUG-226e: -15 sm120 era phantom/typed keys (I2F x12: S8,
    // S16, U16, F64.U32, F64, U32.RP, U64.RP typed zoo; FENCE.VIEW.ASYNC.S;
    // USETMAXREG.DEALLOC/TRY_ALLOC pair) +4 donor keys (FENCE, USETMAXREG_II,
    // USETMAXREG_UP_II, F2F_R_UR); 226-forward sev-B tail closure, canonical
    // 6ba6ca4) = 1460.
    // 2026-08-28 BUG-240: +1 typed key (F2F.F64.F32_R_UR, clone of the
    // arb226e_c graft row) alias-mg wrong-route closure = 1461.
    // 2026-08-29 BUG-265: -11 sm120 junk keys +1 renamed (net -10;
    // junk-rows b3-line closure: FMNMX-'?', I2I.S16/U16.S32.SAT_P0 x2,
    // I2IP.U8.S32_{P0,P2,P5} x3, HFMA2_R_R_R_R_?, FRND.F16 C/F/T phantoms
    // x3 deleted; FSET.BF.GT.AND -> F.AND rename; canonical pending) = 1451.
    // 2026-08-29 BUG-274: +12 sm120 keys (HFMA2 packed-f16 family RELU
    // trailing dst-pred -- 4 dotted keys per parent x 3 parents
    // (R_R_R_II_FI / R_R_R_FI_FI / R_R_R_II_II): HFMA2[.F32][.FMZ].RELU_*_P
    // with pred 3b@87+inv@90, canonical 740b225) = 1463.
    // 2026-08-29 BUG-276: -20 sm120 junk keys (head-drift family: 13 shared
    // I2I/I2IP/P2R/F2FP + 7 sm120-only F2IP era rows; canonical pending)
    // = 1443.
    // BUG-282 flip (2026-08-29): +2 full keys I2IP.U8.S32{.SAT,.SATRELU}_R_R_R_R
    // (mg '' sibling shape, canonical pending v2) = 1445.
    // 2026-08-29 BUG-279: +12 sm120 keys (HFMA2 packed-f16 family FTZ/OOB
    // RELU trailing dst-pred -- 4 dotted keys per parent x 3 parents:
    // HFMA2.{FTZ|OOB|F32.FTZ|F32.OOB}.RELU_*_P, canonical e819129) = 1457.
    // 2026-08-30 BUG-281: -3 sm120 keys (era guard-clone deletes
    // I2I.U8.S32.SAT{,_P0,_P2,_P5}_R_R -> +1 survived as the armed ''
    // family row; i.e. -3 net; 2-op lattice closure, canonical pending)
    // = 1454.
    // 2026-08-30 BUG-294/295: +3 sm120 keys (armed .S8/.U16/.S16 variants
    // of the same 0x238 2-op lattice; arb294/294b x4; canonical 99bbde1)
    // = 1457.
    // 2026-08-30 BUG-283: -4 sm120 keys (era MOVM.16.MT88_{P0,P2,P5,P}_R_R
    // guard-clone deletions + R_R lane rewrite; canonical 1beab0f) = 1453.
    // 2026-08-30 BUG-285: +12 sm120 keys (HFMA2.BF16_V2{.FMZ,.FTZ,.OOB}.RELU
    // dotted trailing-pred keys, 4 per parent x 3 parents of the packed-f16
    // imm family; canonical e41a438) = 1465.
    // 2026-09-01 BUG-316: +4 sm120 keys (MOVM name-space sibling closure on
    // the 0x23a lattice: U4TO8.MT88, 16.M832, 16.M864, U4TO8.M864 strict
    // clones of the verified BUG-283 MT88 geometry; the U4TO8.M832 phantom
    // was rewritten under its existing key; canonical 0821445) = 1469.
    // 2026-09-01 BUG-324: +24 sm120 keys (suffix-window-carrier closure on
    // pure-reg/clustered R-forms: 12 RELU _P trailing dst-pred dotted keys
    // per parent x 2 parents (HFMA2_R_R_R_UR / HFMA2_R_R_UR_R); HMUL2
    // (0x232/0xc32) carrier lanes live inside mod-groups of existing keys;
    // canonical a0dbda7) = 1493.
    // 2026-09-02 BUG-339/340: +7 sm120 keys (F2I era closure: F64.FLOOR /
    // F64.TRUNC / S64.F64 / S64.F64.TRUNC / U32.F64.TRUNC / U64.F64.TRUNC
    // / S64.TRUNC _R_R clones of the 121a surface + U/S64 siblings;
    // +2 generic mg inside F2I_R_R don't move the counter;
    // canonical 02c147d) = 1500.
    // 2026-09-02 BUG-341: +42 sm120 keys (F2I small-int R_R lattice op
    // 0x0305 normalisation+closure: era-style vendor-named rows for all
    // lanes without a name-true owner + 2 era mirrors of mg-owned lanes
    // 0x30/0xb1; mg '' plain lane + normalized owners don't move the
    // counter; canonical 337e21e) = 1542.
    // 2026-09-02 BUG-343/344: +12 sm120 keys (HFMA2 pure-reg krata 0x231
    // mod-window closure: 12 RELU _P trailing dst-pred dotted keys on
    // HFMA2_R_R_R_R; the 30 new mod-lane rows + N1 neg-field closure live
    // inside mod_groups of the existing key and do not move the counter;
    // canonical a013f88) = 1554.
    // 2026-09-03 BUG-363: +95 sm120 keys (F2I R_R FTZ + BF16 lattice
    // closure: 48+48 keyed era rows; F2I.FTZ.U32.TRUNC.NTZ_R_R normalized
    // in place and does not move the counter; the 2 deleted legacy FTZ mgs
    // lived inside F2I_R_R/F2I_R_UR mod_groups; canonical fbcef1c) = 1649.
    // 2026-09-05 BUG-380: +22 sm120 keys (F2I F64-src lattice completion
    // keyed rows, per-dst TRUNC donor clones; the 22 era mgs live inside
    // F2I_R_R mod_groups; canonical a53eb20) = 1671.
    // 2026-09-05 BUG-384: -2 sm120 keys (harvest-junk dense era keys
    // HFMA2.BF16_V2_R_R_R_R + HFMA2_R_R_R_R_R deleted; claim space subsumed
    // by the main rows; canonical 9713fd6) = 1669.
    // 2026-09-06 BUG-390: +32 sm120 keys (F2I.{U8,S8,U16,S16}.F64[.*]_R_R
    // keyed narrow-dst lattice rows, canonical a10350c) = 1701.
    // 2026-09-06 BUG-403: +4 sm120 keys (F2I[.U32/.U64/.S64].F64.TRUNC.NTZ
    // _R_R keyed wide TRUNC.NTZ donor-closure rows, canonical 2285a05) = 1705.
    // 2026-09-07 BUG-400: +1 sm120 key (LDG_R_dARI_P trailing-pred key of the
    // pred/LTC window [64:72) graft; the 20 new mgs live inside mod_groups of
    // LDG_R_dARI{,_P} and do not move the counter; canonical 19363f6) = 1706.
    // 2026-09-08 BUG-419: +23 sm120 keys (route closure on the 0x430/0x7831
    // frames: 3 HADD2.F32[.SAT/.FTZ] + 10 HFMA2*RELU _P dotted FI_FI_R + 10
    // _II_II_R; canonical 2ae87b3) = 1729.
    // FLIP (BUG-413(ii), F2-iter231, canonical 487757b): +1 LDSM_R_AURI.
    // 2026-09-10 BUG-435+434: +3 sm120 keys (LD_R_dARI_P LD-E/128 trailing-pred
    // key + LDG_P_R_dARI{,_P} pred-output A-lane keys; the 33 new mgs live
    // inside mod_groups of the existing keys; canonical 0a6b178) = 1733.
    // 2026-09-10 BUG-433: +1 sm120 key (STSM_ARI_R clone of the sm103a
    // geometry, 3 mgs = M88 count closure; canonical 61858fb) = 1734.
    // 2026-09-12 BUG-443: +19 sm120 keys (8 T2 other-family enum keys
    // STG.E.{U8,CONSTANT.PRIVATE,CONSTANT.CTA,STRONG.SM.PRIVATE,MMIO.GPU,
    // EF,LU,NA}_ARURI_R + 11 T3 cross keys; noE family + STS S8/S16 widths
    // land as mgs inside STG_ARURI_R/STS_* and do not move the counter;
    // canonical e8d1af3) = 1753.
    // 2026-09-12 BUG-447: +20 sm120 keys (donor-clone sm121a NA-ARURI
    // LDG.E.NA.EFL2.256 x16 + STG.E.NA.EFL2.256 x4; era dARI mg delete
    // nie rusza countera; canonical 099faa0) = 1773.
    // 2026-09-12 BUG-450: +3 sm120 keys (donor-clone sm121a non-NA dARI
    // EFL2.256 x3; LDG.E.EFL2.256_R_R_dARI{,_P} + STG.E.EFL2.256_dARI_R_R;
    // canonical 589be87) = 1776.
    assert_eq!(t120().num_keys(), 1776);
    // 2026-08-28 BUG-244: +2 sm103a/sm100a typed keys (F2F.F64.F32_R_R,
    // F2F.F64.F32_R_UR; donor F64-dst closure, canonical 00c3fd2) = 402.
    // 2026-09-02 BUG-341: +41 sm103a keys (F2I small-int R_R lattice
    // normalisation+closure, era-style vendor-named rows; the 7 mg-owned
    // lanes {29,31,70,71,f0,f1}+'' stay mgs; the plain lane lands as mg ''
    // inside F2I_R_R so it does not move the counter; canonical dda1a85)
    // = 443.
    // 2026-09-02 BUG-354: +6 sm103a keys (HFMA2 sparse-leg FI/II lattice
    // mod-lane closure: 6 RELU _P dotted keys HFMA2[.<mods>]
    // .RELU_R_R_R_FI_FI_P; the 11 new mod-lane mgs live inside
    // mod_groups of the existing key and do not move the counter;
    // canonical 5c12995) = 449.
    // 2026-09-03 BUG-363: +96 sm103a keys (same closure; canonical
    // fbcef1c) = 545.
    // 2026-09-04 BUG-367: +6 sm103a keys (HFMA2 sparse-leg FI/II lattice
    // SAT/FTZ/OOB lane closure: 6 RELU _P dotted keys; the 24 new mgs
    // live inside mod_groups of the existing key; canonical 0933cf6)
    // = 551.
    // 2026-09-05 BUG-381: +24 sm103a keys (HFMA2 0x231/0x7c31 sparse-leg
    // lattice completion: 12 RELU _P dotted keys per family on
    // HFMA2_R_R_R_R + HFMA2_R_R_UR_R; the 68 new mgs live inside
    // mod_groups of the existing keys; canonical 3cb31e4) = 575.
    // 2026-09-07 BUG-400: +1 sm103a key (LDG_R_dARI_P, jak t120; canonical
    // 19363f6) = 576.
    // 2026-09-08 BUG-419: +13 sm103a keys (3 HADD2.F32[.SAT/.FTZ] + 10
    // HFMA2*RELU _P dotted R-final; canonical 2ae87b3) = 589.
    // FLIP (BUG-413(ii), F2-iter231, canonical 487757b): +1 LDSM_R_AURI.
    // 2026-09-10 BUG-435+434: +3 sm103a keys (jak t120; canonical 0a6b178)
    // = 593.
    // 2026-09-12 BUG-443: +19 sm103a/sm100a keys (jak t120; canonical
    // e8d1af3) = 612.
    // 2026-09-12 BUG-447: +20 sm103a/sm100a keys (jak t120; canonical
    // 099faa0) = 632.
    // 2026-09-12 BUG-450: +3 sm103a/sm100a keys (donor-clone sm121a
    // non-NA dARI EFL2.256 x3; canonical 589be87) = 635.
    assert_eq!(t103().num_keys(), 635);
}
