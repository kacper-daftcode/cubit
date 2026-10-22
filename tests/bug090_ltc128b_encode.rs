//! Historical BUG-090 residue fixtures are retained as strict-negative input.
//! The old encode-only scout captured genuine NVIDIA LDG.E.LTC128B.128
//! source and emitted LD.E words. Native capture RE retires that shadow;
//! normal text is now owned by the independently verified native row.
//! Original era bytes and residue strings below remain unchanged evidence.

#[path = "support/sm120_ldg_bit92.rs"]
mod ldg_bit92;

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
const M96: u128 = (1u128 << 96) - 1;

/// BE-hex string of the 128-bit slot value (slot bytes reversed), as used by
/// `DecodeIndex::decode` / `encode_instruction` u128 codes.
fn hexw(s: &str) -> u128 { u128::from_str_radix(s, 16).unwrap() }

/// (frozen era text incl !rsd, published silicon-proven word, vendor render
/// of the published word) — one representative per drift byte-mask class:
/// {9,10,11} x190, {9} x56, {9,11} x3 (full 249-slot map in
/// work/f2-090/attr090_rows.json).
const ERA_PINS: &[(u128, &str, &str)] = &[
    (0x000e2400181e0b000000000806087981u128,
     "LDG.E.LTC128B.128 R8, desc[UR8][R6.64] !rsd[0:1,73:1,76:0,81:1,82:1,83:1,90:0,92:1]",
     "LDG.E.64 R8, [R6.U32+UR8]"),
    (0x000e64000000cc000000000003587984u128,
     "LDG.E.LTC128B.128 R88, desc[UR0][R3.64] !rsd[2:1,72:0,74:1,76:0,78:1,79:1,84:0,90:0,91:0]",
     "LDS.128 R88, [R3.X16]"),
    (0x0009e4000820e9140024003f3c005986u128,
     "@P5 LDG.E.LTC128B.128 R0, desc[UR63][R60.64+0x2400] !rsd[1:1,2:1,66:1,68:1,76:0,77:1,78:1,79:1,84:0,85:1,90:0]",
     "@P5 STG.E.EL.STRONG.GPU [R60.U32+UR20+0x2400], R63"),
];

#[test]
fn bug090_legacy_residue_source_is_rejected_by_strict_contract() {
    for &(word, text, _) in ERA_PINS {
        assert_ne!(word, 0, "original binary fixture stays present");
        let error = cubit::roundtrip_audit::check_semantic_source(text).unwrap_err().to_string();
        assert!(error.contains("residue"), "{error}");
    }
}

#[test]
fn bug090_decode_of_published_word_is_canonical_raw_form() {
    // Decode surface must stay on the canonical rows (raw-address render,
    // vendor-exact) and must NOT resolve to the restored encode_only key.
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for &(w, _text, vendor) in ERA_PINS {
        if ldg_bit92::unsupported(w) {
            assert!(idx.decode(w, 0, &t).is_err(), "historical bit92 alias must fail closed: {w:032x}");
            continue;
        }
        let d = idx.decode(w, 0, &t).unwrap();
        assert_ne!(d.key, "LDG.E.LTC128B.128_R_dARI",
            "encode_only key must be decoder-invisible (word {w:032x})");
        assert_eq!(cubit::printer::to_sass(&d), vendor, "decode render {w:032x}");
    }
    ldg_bit92::assert_native_roundtrips(&t, &idx);
}

#[test]
fn bug090_retired_scout_cannot_steal_native_text() {
    let t = t120();
    assert!(t.get_key("LDG.E.LTC128B.128_R_dARI").is_none());
    let row = &t.entries["LDG_R_dARI"].mod_groups["128,E,LTC128B"];
    assert_eq!(row.and_base & 0xfff, 0x981, "native text must select LDG opcode");
    let text = "@P0 LDG.E.LTC128B.128 R64, desc[UR6][R24.64]";
    cubit::roundtrip_audit::check_semantic_source(text).unwrap();
    let insn = parse_sass(text, 0).unwrap();
    assert_eq!(encode_instruction(&insn, &t).unwrap() & M96,
               0x000ea8000c1e1d200000000618400981u128 & M96);
}

#[test]
fn bug090_canonical_ltc128b_plain_corpus_form_not_captured() {
    // Genuine corpus LTC128B-desc words render canonically (NOT `.128`):
    // `LDG.E.LTC128B Rn, desc[URm][Rx.64]` (135 corpus anchors). The
    // restored era key must not capture their re-encode; canon bytes kept.
    let t = t120();
    // corpus slot 81090a0c1000000020191e0c00e20000 (LE) -> code value:
    let w: u128 = hexw("0000e2000c1e1920000000100c0a0981");
    let idx = DecodeIndex::build(&t);
    let d = idx.decode(w, 0, &t).unwrap();
    let text = cubit::printer::to_sass(&d);
    assert_eq!(text, "@P0 LDG.E.LTC128B R10, desc[UR16][R12.64]");
    let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
    let enc = encode_instruction(&insn, &t)
        .unwrap_or_else(|e| panic!("encode failed: {e}"));
    assert_eq!(enc & M96, w & M96, "canon LTC128B plain form must keep canon bytes");
}
