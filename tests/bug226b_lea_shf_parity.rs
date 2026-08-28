//! BUG-226 patch 2 (F2-iter111, front2/blind, 2026-08-27): sm120 vendor-parity
//! int-shift block — LEA .SX32/.HI[.X] mg family + SHF width/sign rows
//! (canonical 980e5cd; patch226b.py replayable+idempotent).
//!
//! Defect (measured, work/bug226b): 4,496 corpus sm120 words across 12
//! (key,mg) classes decoded ONLY via the prio-3 sign-tolerant tier and
//! rendered WRONG vs nvdisasm 13.3.73 (truth226b.json, occurrence-paired
//! hit226b.json). All 4,496 decode vendor-exact under the canonical sm100a
//! table with true per-occurrence ctrl (donor226b_ctrl_decodes.json) =>
//! donor-clone lawful. Graft arb226b x{100a,120a}: 7/7 LEA clusters
//! print-identical over bits [10,11]+[62..95]; 5/5 SHF identical EXCEPT b77
//! (100a = SHF.XOR pivot, 120a = inert; donor rows pin b77=0 and corpus
//! exposure of b77-set words is ZERO => fail-closed clone, the 120-only lax
//! semantics parked as 228-kand LOW).
//!
//! Repairs: key LEA_R_R_UR_II_P donor-cloned whole (2,062 words: vendor
//! LEA.HI.X.SX32 5-operand was absorbed by the 6-operand LEA_R_R_UR_R_II_P
//! [HI,X] row printing junk abs + a spurious RZ slot, no .SX32); mg HI,SX32
//! added to LEA_R_R_II_II/LEA_R_R_R_II/LEA_R_R_UR_II (430 words; sm120
//! carried a uniform {'','HI','HI,SX32,X','HI,X'} mg set per key, the plain
//! SX32 mg never existed); LEA_R_R_R_II_P[HI,SX32,X] replaced with the donor
//! row (sm120 lacked inv@63 -> printed -R17 for vendor ~R17, and its vm
//! rejected 764 sibling words into the spurious-RZ row); SHF mg-adds
//! R,S64 x2 / R,U32 / HI,L,U64 (1,036 words printed U64 and .W.U32 junk:
//! sm120 SHF generic keys share one uniform mg list missing exactly those);
//! SHF_R_R_UR_R[HI,R,S32] replaced (sm120 row had imm32@32 for ureg@32).
//!
//! Zero-mismatch rows (sm120-specific era keys LEA.HI.SX32_* / SHF.R.S64_*,
//! uniform-mg siblings) intentionally untouched. Battery gold gate:
//! verify226b_gold.py occurrence-paired over hit226b.json.

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

/// Cured anchors: (vendor glyph, word96, ctrl observations). Every (word,
/// ctrl) pair is gold-verified occurrence-paired in verify226b_gold.py.
const CURED: &[(&str, u128, &[u64])] = &[
    // A: key-add LEA_R_R_UR_II_P[HI,SX32,X]
    (
        "LEA.HI.X.SX32 R8, R4, UR4, 0x1, P0",
        0x080f0eff0000000404087c11,
        &[0x000fe400],
    ),
    (
        "LEA.HI.X.SX32 R13, R0, UR5, 0x1, P0",
        0x080f0eff00000005000d7c11,
        &[0x000fc600],
    ),
    // B: mg HI,SX32 adds
    (
        "LEA.HI.SX32 R0, R0, 0x1, 0x2",
        0x078f12ff0000000100007811,
        &[0x000fc600],
    ),
    (
        "LEA.HI.SX32 R65, R33, 0xffffffe0, 0x1c",
        0x078fe2ffffffffe021417811,
        &[0x000fce00],
    ),
    (
        "LEA.HI.SX32 R14, R7, R4, 0x1",
        0x078f0aff00000004070e7211,
        &[0x008fe400],
    ),
    (
        "LEA.HI.SX32 R18, R5, UR16, 0x1a",
        0x0f8fd2ff0000001005127c11,
        &[0x000fe200],
    ),
    (
        "LEA.HI.SX32 R16, R16, UR16, 0x1a",
        0x0f8fd2ff0000001010107c11,
        &[0x000fe400],
    ),
    (
        "LEA.HI.SX32 R82, R82, UR16, 0x1a",
        0x0f8fd2ff0000001052527c11,
        &[0x000fe200],
    ),
    // C: LEA_R_R_R_II_P[HI,SX32,X] replace (inv@63 -> ~Rb; sibling 5-op landing)
    (
        "LEA.HI.X.SX32 R2, R9, ~R2, 0x1, P0",
        0x000f0eff8000000209027211,
        &[0x000fe400],
    ),
    (
        "LEA.HI.X.SX32 R2, R7, ~R3, 0x1, P0",
        0x000f0eff8000000307027211,
        &[0x000fe400],
    ),
    (
        "LEA.HI.X.SX32 R5, R2, R5, 0x2, P0",
        0x000f16ff0000000502057211,
        &[0x000fea00, 0x000fec00],
    ),
    (
        "LEA.HI.X.SX32 R7, R2, R7, 0x2, P0",
        0x000f16ff0000000702077211,
        &[0x000fea00],
    ),
    // D: SHF mg-adds (S64 sign enum, no-.W form, U64.HI)
    (
        "SHF.R.U32 R0, R0, 0x10, RZ",
        0x000016ff0000001000007819,
        &[0x002fc800, 0x004fc800],
    ),
    (
        "SHF.R.U32 R2, R2, 0x10, RZ",
        0x000016ff0000001002027819,
        &[0x002fc800, 0x004fc800, 0x008fc800],
    ),
    (
        "SHF.R.S64 R3, R3, 0x1, R0.reuse",
        0x000010000000000103037819,
        &[0x100fe400],
    ),
    (
        "SHF.R.S64 R55, R2, UR5, RZ",
        0x080010ff0000000502377c19,
        &[0x000fe200],
    ),
    (
        "SHF.L.U64.HI R18, R2, R15, R3",
        0x000102030000000f02127219,
        &[0x000fe200],
    ),
    // E: SHF_R_R_UR_R[HI,R,S32] replace
    (
        "SHF.R.S32.HI R0, RZ, UR4, R0",
        0x0801140000000004ff007c19,
        &[0x000fcc00],
    ),
    (
        "SHF.R.S32.HI R3, RZ, UR4, R3",
        0x0801140300000004ff037c19,
        &[0x000fcc00],
    ),
];

/// Cross-key stability anchors (BUG-226 patch-1 cured classes): must stay
/// byte-identical after the LEA/SHF donor-clones (row-theft tripwire).
const STABLE: &[(&str, u128, u64)] = &[
    (
        "FSETP.EQ.OR P0, PT, R7, RZ, P0",
        0x00702400000000ff0700720b,
        0x000fda00,
    ),
    (
        "IADD3 R10, P1, P0, R5, UR4, R128",
        0x0f83e08000000004050a7c10,
        0x002fe200,
    ),
    (
        "FSETP.NE.AND P0, PT, |R40|, +INF , PT",
        0x03f052007f8000002800780b,
        0x000fe200,
    ),
];

#[test]
fn t226b_1_cured_anchors_decode_exact_sm120() {
    let t = tab(T120);
    let mut n = 0;
    for (glyph, w96, ctrls) in CURED {
        for ctl in ctrls.iter() {
            let got = decode(&t, mk(*w96, *ctl)).unwrap_or_else(|e| panic!("HOLE {glyph}: {e}"));
            assert_eq!(&got, glyph, "sm120 drift @{ctl:#x}");
            n += 1;
        }
    }
    assert!(n >= 22);
}

#[test]
fn t226b_2_stable_anchors_unchanged_sm120() {
    let t = tab(T120);
    for (glyph, w96, ctl) in STABLE {
        let got = decode(&t, mk(*w96, *ctl)).unwrap_or_else(|e| panic!("HOLE {glyph}: {e}"));
        assert_eq!(&got, glyph, "sm120 stability broke @{ctl:#x}");
    }
    // structural: donated rows carry the donor field law (inv@63 on the LEA
    // Rb token; ureg@32 on the SHF HI,R,S32 row; imm@75 present).
    let j: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(T120).unwrap()).unwrap();
    let lea = &j["instructions"]["LEA_R_R_R_II_P"]["mod_groups"]["HI,SX32,X"];
    let fs = lea["fields"].as_array().unwrap();
    assert!(
        fs.iter()
            .any(|f| f["extraction"] == "inv" && f["shift"] == 63)
    );
    assert!(
        fs.iter()
            .any(|f| f["extraction"] == "imm" && f["shift"] == 75)
    );
    let shf = &j["instructions"]["SHF_R_R_UR_R"]["mod_groups"]["HI,R,S32"];
    let fs = shf["fields"].as_array().unwrap();
    assert!(
        fs.iter()
            .any(|f| f["extraction"] == "ureg" && f["shift"] == 32)
    );
    assert!(j["instructions"]["LEA_R_R_UR_II_P"]["mod_groups"]["HI,SX32,X"].is_object());
}

#[test]
fn t226b_3_fail_closed_boundaries_sm120() {
    let t = tab(T120);
    // b91 is BAKED=1 on this LEA family (corpus anchor has it set; graft
    // arb226b: clearing it is vendor-NOGLYPH on both arch). The cleared word
    // must fall out of every strict row; if a relaxed tier still absorbs it,
    // the bug089-class contract holds: text re-encode must not reproduce the
    // crafted (b91-cleared) word.
    let b91 = 0x080f0eff0000000a152d7c11u128 ^ (1u128 << 91);
    let r = decode(&t, mk(b91, 0x000fe400));
    if let Ok(got) = &r {
        // absorbed by the relaxed tier: the rendered text must NOT re-encode
        // to the crafted word (bug089-class __raw__ keeps the bits).
        let insn = parse_sass(got, 0).unwrap();
        let re = encode_instruction(&insn, &t).map(|x| x & M96).ok();
        assert_ne!(re, Some(b91 & M96), "b91 word must not survive round-trip");
    }
    // SHF b77 arch pivot (100a=SHF.XOR, 120a=inert-unwitnessed): donor rows
    // pin b77=0, so the flip must not ride the new rows; if a relaxed tier
    // absorbs it, text re-encode must not reproduce the crafted word.
    for base in [0x000010310000001eff397819u128, 0x080010ff0000000534387c19] {
        let w = base ^ (1u128 << 77);
        if let Ok(got) = decode(&t, mk(w, 0x000fe400)) {
            assert_ne!(got, "SHF.R.S64 R57, RZ, 0x1e, R49");
            assert_ne!(got, "SHF.R.S64 R56, R52, UR5, RZ");
            let insn = parse_sass(&got, 0).unwrap();
            let re = encode_instruction(&insn, &t).map(|x| x & M96).ok();
            assert_ne!(re, Some(w & M96), "b77 word must not survive round-trip");
        }
    }
}

#[test]
fn t226b_4_encode_roundtrip_low96_sm120() {
    let t = tab(T120);
    for (text, lo96) in [
        (
            "LEA.HI.X.SX32 R5, R2, R5, 0x2, P0 ;",
            0x000f16ff0000000502057211u128,
        ),
        ("LEA.HI.SX32 R14, R7, R4, 0x1 ;", 0x078f0aff00000004070e7211),
        ("SHF.R.S64 R3, R3, 0x1, R0 ;", 0x000010000000000103037819),
        ("SHF.R.U32 R0, R0, 0x10, RZ ;", 0x000016ff0000001000007819),
    ] {
        let insn = parse_sass(text, 0).expect("parse");
        let w = encode_instruction(&insn, &t).unwrap_or_else(|_| panic!("encode HOLE: {text}"));
        assert_eq!(w & M96, lo96 & M96, "encode drift: {text}");
    }
}
