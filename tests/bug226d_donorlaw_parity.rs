//! BUG-226d (F2-iter117, front2/blind, 2026-08-28): sm120 vendor-parity
//! patch 7 — donor-law closure of the 226-forward residuum block
//! (canonical b2e5227; patch226d.py replayable+idempotent).
//!
//! Measured defect census (pop226d full-population, 2,406-file battery,
//! true-ctrl (word96,ctrl) pairing per BUG-236, nvdisasm 13.3.73):
//! 104,376 DIFF words across 7 era-vs-donor divergent families:
//!  DFMA 79,173 (FI int-imm misprint `5.877e-39` vs `8`; 5-token UR
//!    phantom dup; RP/RM rows missing neg@72; UR-reuse sideband ghost),
//!  VIMNMX 24,940 NOT in scope (arch-split textual contract: vendor
//!    sm_120a prints legacy SHORT form for identical word bits vs
//!    sm_100a/103a R_P_P LONG -> 238-kand owner decision),
//!  UIMAD 11,595 (era `.v2` ghost mod; 5-token arity dup; WIDE UP hole),
//!  FCHK 5,228 (P-dest phantom `PT` for field values 0/1; FCHK_P_R_UR
//!    key absent -> 1,282 HOLEs),
//!  I2F 5,415 / F2F 4,201 NOT in scope (donor partial, graft -> 226e),
//!  IDP 3,581 (neg@?c erasure, URZ/RZ tail mixup, U8/S8 mod misroute,
//!    IDP.2A.LO print order),
//!  HMUL2 2,600 (R-form H0_H0 family -> 882 HOLEs; UR hsel corner),
//!  VOTE 1,591 (PT/!PT phantom on the shared P field), MUFU 608.
//!
//! Law: donor sm100a == sm103a byte-identical per cloned key; donor-table
//! true-ctrl decode == vendor on 104,376/104,376 DIFF words after grafts
//! (DFMA tok2 neg@72 on RM/RP rows, HMUL2_R_R_UR hsel@74/@60); zero
//! regressions among 391,459 MATCH words; post-patch full-pop EQ
//! 495,208/495,208 (post226d). Strict-route WARN documented: 76 DFMA
//! abs@62 tok3 words heal via the engine prio-3 post-pass (same class as
//! 226c class-11); 6,657 key-level multi-hits are donor-inherent overlaps
//! (UIMAD/MUFU/FCHK shared and_base), engine-prio resolved.
//!
//! Fix (data-only + 2 printer arms): DELETE 42 era phantom keys; REPLACE
//! mod_groups from donor on 22 shared keys (envelopes sm120 kept); ADD 6
//! donor keys (FCHK_P_R_UR, IDP_R_R_R_R, IDP_R_R_UR_R, MUFU_R_FI,
//! UIMAD_UR_UR_UR_UR_UP, VOTE_P_P); grafts: DFMA_R_R_R_R[RM/RP] +
//! DFMA_R_R_R_UR[RP] gain neg@72 tok2, HMUL2_R_R_UR[''] gains hsel@74/@60.
//! Printer arms: IDP `2A`/`4A` before `LO` (27 witnesses); reuse sideband
//! yields to inline row reuse fields (38 DFMA_R_R_R_UR witnesses: inline
//! b123->tok3 reg@64, sideband window hit ureg@32 => ghost `UR12.reuse`).
//! forms 1507->1471, variants 2684->2623, baked-ctrl 759->803 (+44 donor
//! templates).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const T120: &str = "tables/sm120.json";
const M96: u128 = (1u128 << 96) - 1;
fn tab(p: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(p)).unwrap()
}
fn decode(t: &IsaTable, w128: u128) -> Result<String, String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w128, 0, t)
        .map(|d| to_sass(&d))
        .map_err(|e| format!("{e}"))
}
fn mk(w96: u128, ctrl: u64) -> u128 {
    (w96 & ((1 << 96) - 1)) | ((ctrl as u128) << 96)
}

/// Cured anchors: (vendor glyph, word96, ctrl32) — occurrence-paired corpus
/// hits (pop226d), one per cured class.
const CURED: &[(&str, u128, u64)] = &[
    // DFMA: R-form neg lattice (era dropped signs)
    (
        "DFMA R8, -R22, R16, -R4",
        0x00000904000000101608722b,
        0x001e0800,
    ),
    // DFMA: .RP + neg@72 (era-only law, union-grafted onto donor RM/RP rows)
    (
        "DFMA.RP R4, -R6, R8, R4",
        0x00008104000000080604722b,
        0x000e1000,
    ),
    // DFMA: 5-token UR phantom dup (era printed tok5 ghost dst)
    (
        "DFMA R2, R2, UR8, -R16",
        0x080008100000000802027c2b,
        0x002e6400,
    ),
    // DFMA: reuse sideband yielded to inline row field (ghost `UR12.reuse`)
    (
        "DFMA R16, R16, R2.reuse, UR12",
        0x080000020000000c10107e2b,
        0x082e6200,
    ),
    // DFMA: FI int-imm print (`8`, not `5.877e-39`)
    (
        "DFMA R2, R16, 8, |R2|",
        0x00000402402000001002782b,
        0x00306400,
    ),
    // DFMA: era HOLE .RP-UR + neg (grafted DFMA_R_R_R_UR[RP])
    (
        "DFMA.RP R16, -R8, R10, UR6",
        0x0800810a0000000608107e2b,
        0x001e1e00,
    ),
    // DFMA: abs@62 tok3 via engine prio-3 post-pass (76 strict-miss words)
    (
        "DFMA R28, R34.reuse, |R2|, R28",
        0x0000001c40000002221c722b,
        0x042e2200,
    ),
    // UIMAD: era `.v2` ghost mod
    (
        "UIMAD UR4, UR4, UR6, URZ",
        0x0f8e02ff00000006040472a4,
        0x000fe200,
    ),
    // UIMAD: 5-token arity dup (era printed tok5 ghost)
    (
        "UIMAD UR13, UR7, -0x3, UR13",
        0x0f8e020dfffffffd070d78a4,
        0x000fd800,
    ),
    // UIMAD: era HOLE WIDE UP-form (donor UIMAD_UR_UR_UR_UR_UP key)
    (
        "UIMAD.WIDE.U32 UR12, UP0, UR4, UR11, UR12",
        0x0f80000c0000000b040c72a5,
        0x000fc800,
    ),
    // FCHK: P-dest phantom -> real field
    ("FCHK P0, R7, R12", 0x000000000000000c07007302, 0x000e6200),
    // FCHK: era HOLE (P1 dest) cured
    ("FCHK P1, R2, R19", 0x000200000000001302007302, 0x000ea200),
    // FCHK: FI abs tok2
    ("FCHK P0, |R4|, R48", 0x000002000000003004007302, 0x000ee200),
    // MUFU: era HOLE RCP64H imm-form (donor MUFU_R_FI key)
    (
        "MUFU.RCP64H R15, 4.29496524800000000000e+09",
        0x0000180041efffff000f7908,
        0x000e2200,
    ),
    // MUFU: -QNAN operand (donor MUFU_R_L-class law)
    ("MUFU.RSQ R7, -QNAN", 0x00001400ffc0000000077908, 0x000e2200),
    // MUFU: RSQ64H vs RCP mod misroute (era)
    (
        "MUFU.RSQ64H R9, UR5",
        0x08001c000000000500097d08,
        0x001e2200,
    ),
    // VOTE: shared P-field prints PT (guard form donor VOTE_P_P)
    ("VOTE.ALL P0, P0", 0x000000000000000000ff7806, 0x000fe400),
    // VOTE.ANY R-form: !PT phantom was era's, PT is real
    (
        "VOTE.ANY R14, PT, !P0",
        0x040e010000000000000e7806,
        0x000fe200,
    ),
    // IDP: neg erasure cured (era printed plain R32)
    (
        "IDP.4A.S8.S8 R34, R34, R32.reuse, R23",
        0x000006170000002022227226,
        0x081fe400,
    ),
    // IDP: UR tail vs RZ mixup
    (
        "IDP.4A.S8.S8 R48, R54.reuse, UR13, RZ",
        0x080006ff0000000d36307c26,
        0x050fe400,
    ),
    // IDP: U8/S8 mod misroute
    (
        "IDP.4A.S8.S8 R3, R38.reuse, UR21, RZ",
        0x080006ff0000001526037c26,
        0x060fe400,
    ),
    // IDP: 2A.LO print order (printer arm)
    (
        "IDP.2A.LO.U16.U8 R7, R60, R7, RZ",
        0x000010ff000000073c077226,
        0x000fe400,
    ),
    // HMUL2: era HOLE R-form H0_H0 family
    (
        "HMUL2 R2, R0.reuse.H0_H0, R27",
        0x000008000000001b00027232,
        0x040fe400,
    ),
    // HMUL2: UR hsel corner (grafted hsel@60 -> .H1_H1)
    (
        "HMUL2 R11, R12, UR8.H1_H1",
        0x08000000300000080c0b7c32,
        0x010fc800,
    ),
    // HMUL2.BF16_V2: UR hsel H0_H0
    (
        "HMUL2.BF16_V2 R3, R4.H0_H0, UR4.H0_H0",
        0x082008002000000404037c32,
        0x001fca00,
    ),
];

#[test]
fn t226d_1_phantoms_absent_donor_law_present() {
    let raw = std::fs::read_to_string(T120).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let ins = v["instructions"].as_object().unwrap();
    for k in [
        // DFMA era phantoms
        "DFMA_R_R_R_R_R",
        "DFMA_R_R_UR_R_R",
        "DFMA_R_R_R_R_II_?",
        // UIMAD era phantoms (dotted era keys + arity dups)
        "UIMAD.WIDE.U32_UR_UR_II_UR",
        "UIMAD_UR_UR_UR_UR_UR",
        // MUFU era single-mod keys (merged into donor MUFU_R_R mg set)
        "MUFU.RCP64H_R_R",
        "MUFU.TANH_R_R",
        "MUFU_R_L",
        // VOTE era phantom keys
        "VOTE.ANY_R_P_P",
        "VOTEU.ANY_UP_P",
        // HMUL2 era arity phantom + dotted
        "HMUL2_R_R_R_R",
        "HMUL2.BF16_V2_R_R_R",
        // IDP era dotted phantoms
        "IDP.4A.S8.S8_R_R_R_R",
        "IDP.2A.LO.U16.U8_R_R_R_R",
    ] {
        assert!(ins.get(k).is_none(), "phantom key survived: {k}");
    }
    // donor keys added
    for k in [
        "FCHK_P_R_UR",
        "IDP_R_R_R_R",
        "IDP_R_R_UR_R",
        "MUFU_R_FI",
        "UIMAD_UR_UR_UR_UR_UP",
        "VOTE_P_P",
    ] {
        assert!(ins.get(k).is_some(), "donor key missing: {k}");
    }
    // grafts landed on donor rows
    let hasf = |k: &str, mg: &str, e: &str, s: u64, t: u64| {
        ins[k]["mod_groups"][mg]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["extraction"] == e && f["shift"] == s && f["token_idx"] == t)
    };
    assert!(hasf("DFMA_R_R_R_R", "RP", "neg", 72, 2), "DFMA RP neg@72");
    assert!(hasf("DFMA_R_R_R_R", "RM", "neg", 72, 2), "DFMA RM neg@72");
    assert!(
        hasf("DFMA_R_R_R_UR", "RP", "neg", 72, 2),
        "DFMA R_UR RP neg@72"
    );
    assert!(hasf("HMUL2_R_R_UR", "", "hsel", 74, 2), "HMUL2 UR hsel@74");
    assert!(hasf("HMUL2_R_R_UR", "", "hsel", 60, 3), "HMUL2 UR hsel@60");
    // donor FCHK rows carry the real P dest (5 bits field, not phantom PT)
    let r = &ins["FCHK_P_R_R"]["mod_groups"][""];
    let fs = r["fields"].as_array().unwrap();
    assert!(
        fs.iter()
            .any(|f| f["extraction"] == "pred" && f["token_idx"] == 1),
        "FCHK dest must be a real pred field"
    );
}

#[test]
fn t226d_2_cured_anchors_sm120() {
    let t = tab(T120);
    for (glyph, w96, ctl) in CURED {
        let got = decode(&t, mk(*w96, *ctl)).unwrap_or_else(|e| panic!("HOLE {glyph}: {e}"));
        assert_eq!(&got, glyph, "cure broke @{ctl:#x}");
    }
}

#[test]
fn t226d_3_fail_closed_and_stability_sm120() {
    let t = tab(T120);
    // deleted-era ghost texts must be unencodable
    if let Ok(insn) = parse_sass("UIMAD.v2 UR4, UR4, UR6, URZ ;", 0) {
        let _ = encode_instruction(&insn, &t).expect_err("ghost .v2 must be fail-closed");
    }
    if let Ok(insn) = parse_sass("DFMA R1, R1, UR4, R8, R2 ;", 0) {
        let _ =
            encode_instruction(&insn, &t).expect_err("ghost 5-token DFMA UR must be fail-closed");
    }
    // IDP wrong mod order is normalized by the encoder to the vendor order
    let insn = parse_sass("IDP.LO.2A.U16.U8 R7, R60, R7, RZ ;", 0).expect("parse");
    let w = encode_instruction(&insn, &t).expect("IDP order-normalizing encode");
    let idx = DecodeIndex::build(&t);
    let got = to_sass(&idx.decode(w & M96, 0, &t).unwrap());
    assert_eq!(got, "IDP.2A.LO.U16.U8 R7, R60, R7, RZ");
    // cross-patch stability: 226c/234/230/229b anchors must not drift
    for (glyph, w96, ctl) in [
        (
            "FFMA R27, R19, -R17.reuse, R36",
            0x0000002480000011131b7223u128,
            0x080fe200u64,
        ),
        (
            "FFMA2 R70, -R64.reuse.F32x2.LO_HI.NP, R39.reuse.F32, R58.F32x2.HI_LO",
            0x010a013a0000002740467249u128,
            0x0d0fe200u64,
        ),
        (
            "LEA R4, R3.reuse, -R4, 0x3",
            0x078e18ff8000000403047211u128,
            0x040fe200u64,
        ),
        (
            "SHFL.DOWN P1, R17, R41, R40, R23",
            0x000200170800002829117389u128,
            0x00006400u64,
        ),
    ] {
        let got = decode(&t, mk(w96, ctl)).unwrap_or_else(|e| panic!("HOLE {glyph}: {e}"));
        assert_eq!(&got, glyph, "stability broke @{ctl:#x}");
    }
}

#[test]
fn t226d_4_encode_roundtrip_low96_sm120() {
    let t = tab(T120);
    for (text, lo96) in [
        ("DFMA R8, -R22, R16, -R4 ;", 0x00000904000000101608722bu128),
        ("DFMA.RP R4, -R6, R8, R4 ;", 0x00008104000000080604722bu128),
        ("DFMA R2, R2, UR8, -R16 ;", 0x080008100000000802027c2bu128),
        ("DFMA R2, R16, 8, |R2| ;", 0x00000402402000001002782bu128),
        ("UIMAD UR4, UR4, UR6, URZ ;", 0x0f8e02ff00000006040472a4u128),
        (
            "UIMAD UR13, UR7, -0x3, UR13 ;",
            0x0f8e020dfffffffd070d78a4u128,
        ),
        ("FCHK P0, R7, R12 ;", 0x000000000000000c07007302u128),
        ("FCHK P1, R2, R19 ;", 0x000200000000001302007302u128),
        ("MUFU.RSQ R7, -QNAN ;", 0x00001400ffc0000000077908u128),
        ("MUFU.RSQ64H R9, UR5 ;", 0x08001c000000000500097d08u128),
        ("VOTE.ANY R14, PT, !P0 ;", 0x040e010000000000000e7806u128),
        (
            "IDP.4A.S8.S8 R34, R34, R32.reuse, R23 ;",
            0x000006170000002022227226u128,
        ),
        (
            "IDP.2A.LO.U16.U8 R7, R60, R7, RZ ;",
            0x000010ff000000073c077226u128,
        ),
        (
            "HMUL2 R11, R12, UR8.H1_H1 ;",
            0x08000000300000080c0b7c32u128,
        ),
        (
            "HMUL2 R2, R0.reuse.H0_H0, R27 ;",
            0x000008000000001b00027232u128,
        ),
    ] {
        let insn = parse_sass(text, 0).expect("parse");
        let w = encode_instruction(&insn, &t).unwrap_or_else(|_| panic!("encode HOLE: {text}"));
        assert_eq!(w & M96, lo96 & M96, "encode drift: {text}");
    }
}
