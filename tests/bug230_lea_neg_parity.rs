//! BUG-230 (F2-iter114, front2/blind, 2026-08-28): sm120 vendor-parity
//! patch 4 — LEA_P0 neg-position era key closure (canonical f34abc0;
//! patch230.py replayable+idempotent).
//!
//! Defect (measured, work/bug230 + downstream of 229's popdiff229 cls 'neg',
//! 234 occurrence-paired lines): every LEA word with the true sign bits
//! b63 (tok3, reg@32) or b72 (tok2, reg@24) set was captured by era phantom
//! key LEA_P0_R_R_R_II. Its and_base/vm tolerate the sign bits while the
//! lawful plain row pinned them to 0; the key name then folds 'P0' into the
//! printed opcode and the negation is DROPPED from the operand text:
//!   ours   `LEA_P0 R17, R2, R17, 0x3`
//!   vendor `LEA R17, R2, -R17, 0x3`
//! — a silent sign-erasure class in RE output. The era row also mislabels
//! the reuse sideband b122/b123 as neg: b122=1 witness printed
//! `LEA_P0 R4, -R3.reuse, R4, 0x3` (double glyph) vs vendor
//! `LEA R4, R3.reuse, -R4, 0x3`.
//!
//! Law (graft arb230: 3 witness words x walks {63,72,62,73} x{100a,103a,
//! 120a}, all cells print-identical; nvdisasm 13.3.73): b63 = neg of tok3,
//! b72 = neg of tok2, b62 flip inert on these cells, b73 flip = vendor
//! illegal cell x3 arch. Donor sm100a/sm103a carry exactly these neg fields
//! on their plain LEA row (imm6@75 there absorbs the b80 .HI pivot — donor's
//! own 231-kand divergence, deliberately NOT cloned; sm120 keeps imm5@75).
//!
//! Fix (data-only): DELETE era key LEA_P0_R_R_R_II; EXTEND
//! LEA_R_R_R_II[''] with neg@72 tok2 + neg@63 tok3 (donor-ordered; reuse
//! @122/123 kept). Population route 234/234 strict-matched with true ctrl;
//! baked-ctrl 747 -> 747. sm121a still carries the sibling phantom key
//! (own stream; listed LOW).

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

/// Cured anchors: (vendor glyph, word96, ctrl32) — every triple is an
/// occurrence-paired corpus hit (popdiff229 cls 'neg'), spanning both neg
/// positions and the reuse-sideband mislabel subclass.
const CURED: &[(&str, u128, u64)] = &[
    // negA: b72 -> -Ra (tok2, reg@24)
    (
        "LEA R5, -R6, RZ, 0x5",
        0x078e29ff000000ff06057211u128,
        0x002fe200u64,
    ),
    (
        "LEA R7, -R8, RZ, 0x6",
        0x078e31ff000000ff08077211u128,
        0x002fe200u64,
    ),
    // reuse sideband b122 (tok2) + neg b63 (tok3) — era row mislabeled b122
    // as neg and printed a double glyph `-R3.reuse`
    (
        "LEA R4, R3.reuse, -R4, 0x3",
        0x078e18ff8000000403047211u128,
        0x040fe200u64,
    ),
    (
        "LEA R3, R6.reuse, -R6, 0x3",
        0x078e18ff8000000606037211u128,
        0x042fe200u64,
    ),
    // negC: b63 -> -Rb/Rc (tok3, reg@32)
    (
        "LEA R17, R2, -R17, 0x3",
        0x078e18ff8000001102117211u128,
        0x000fe200u64,
    ),
    (
        "LEA R16, R0, -R29, 0x3",
        0x078e18ff8000001d00107211u128,
        0x000fe200u64,
    ),
    (
        "LEA R10, R5, -R10, 0x2",
        0x078e10ff8000000a050a7211u128,
        0x000fe200u64,
    ),
    (
        "LEA R24, R5, -R24, 0x2",
        0x078e10ff8000001805187211u128,
        0x000fe200u64,
    ),
];

#[test]
fn t230_1_structure_sm120() {
    let j: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(T120).unwrap()).unwrap();
    let ins = &j["instructions"];
    // era phantom gone, no LEA_P0* anywhere
    for (k, _) in ins.as_object().unwrap() {
        assert!(!k.contains("LEA_P0"), "era glyph key residue: {k}");
    }
    // plain row carries the true sign fields, donor-ordered, imm5@75 kept
    let r = &ins["LEA_R_R_R_II"]["mod_groups"][""];
    let fs = r["fields"].as_array().unwrap();
    let has = |e: &str, b: u64, s: u64, t: u64| {
        fs.iter().any(|f| {
            f["extraction"] == e && f["bits"] == b && f["shift"] == s && f["token_idx"] == t
        })
    };
    assert!(has("neg", 1, 72, 2), "neg@72 tok2 missing");
    assert!(has("neg", 1, 63, 3), "neg@63 tok3 missing");
    assert!(has("reuse", 1, 122, 2) && has("reuse", 1, 123, 3));
    assert!(
        has("imm", 5, 75, 4),
        "imm must stay 5b@75 (231-kand: donor imm6 diverges)"
    );
    assert!(
        !has("imm", 6, 75, 4),
        "6b imm read absorbs the b80 .HI pivot"
    );
    // zero baked ctrl growth from the fix
    let ab =
        u128::from_str_radix(r["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    assert_eq!(
        (ab >> 105) & ((1 << 23) - 1),
        0,
        "plain row must stay ctrl-bake-free"
    );
}

#[test]
fn t230_2_cured_anchors_sm120() {
    let t = tab(T120);
    for (glyph, w96, ctl) in CURED {
        let got = decode(&t, mk(*w96, *ctl)).unwrap_or_else(|e| panic!("HOLE {glyph}: {e}"));
        assert_eq!(&got, glyph, "cure broke @{ctl:#x}");
        assert!(!got.contains("LEA_P0"), "phantom glyph survived: {got}");
    }
}

#[test]
fn t230_3_fail_closed_and_stability_sm120() {
    let t = tab(T120);
    // the phantom opcode must now be unencodable (ghost form deleted)
    let insn = parse_sass("LEA_P0 R17, R2, R17, 0x3 ;", 0).expect("parse");
    assert!(
        encode_instruction(&insn, &t).is_err(),
        "ghost LEA_P0 must be fail-closed"
    );
    // same-word/b63-cleared twin decodes plain (no spurious neg)
    let got = decode(
        &t,
        mk(0x078e18ff8000001102117211u128 ^ (1 << 63), 0x000fe200),
    )
    .unwrap();
    assert_eq!(got, "LEA R17, R2, R17, 0x3");
    // cross-patch stability: 226b/229/229b anchors must not drift
    for (glyph, w96, ctl) in [
        (
            "LEA.HI R55, R57, 0x1, RZ, 0x17",
            0x078fb8ff0000000139377811u128,
            0x000fe400u64,
        ),
        (
            "LEA.HI.X.SX32 R5, R2, R5, 0x2, P0",
            0x000f16ff0000000502057211u128,
            0x000fea00u64,
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
fn t230_4_encode_roundtrip_low96_sm120() {
    let t = tab(T120);
    for (text, lo96) in [
        ("LEA R17, R2, -R17, 0x3 ;", 0x078e18ff8000001102117211u128),
        ("LEA R5, -R6, RZ, 0x5 ;", 0x078e29ff000000ff06057211u128),
        (
            "LEA R4, R3.reuse, -R4, 0x3 ;",
            0x078e18ff8000000403047211u128,
        ),
        ("LEA R16, R0, -R29, 0x3 ;", 0x078e18ff8000001d00107211u128),
        // no-neg plain regression
        (
            "LEA R17, R2, R17, 0x3 ;",
            0x078e18ff8000001102117211u128 ^ (1 << 63),
        ),
    ] {
        let insn = parse_sass(text, 0).expect("parse");
        let w = encode_instruction(&insn, &t).unwrap_or_else(|_| panic!("encode HOLE: {text}"));
        assert_eq!(w & M96, lo96 & M96, "encode drift: {text}");
    }
}
