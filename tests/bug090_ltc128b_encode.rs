//! BUG-090 (F2Q, 2026-08-23; sm120 cubit-bugs/090, silicon trap i192):
//! the 084 re-canon removed the legacy `LDG_R_dARI["128,E,LTC128B"]` sm120
//! geometry from the ENCODE surface, so the frozen pinned publish text
//! (sass98 md5 1912dae9; 249 lines `LDG.E.LTC128B.128 Rn, desc[URm][Rx.64]
//! !rsd[...]`) fell through to the wide low-constant canon mg and produced
//! words with bytes 9-11 zeroed of legacy constant bits -> deterministic
//! silicon trap (4/4) on rt98_pub (CUDA 130, warmup, KA/KB bisected).
//!
//! Vendor truth (nvdisasm 13.3 probes of the 249 published slot words,
//! work/f2-090/nvprobe090.py): every published word is the RAW-address
//! form (`LDG.E.64 Rn, [Rm.U32+URk]`, `STG.E*`, `LDS.*`) — the era
//! `LTC128B` glyph is a legacy-decoder artifact, NOT vendor nomenclature.
//! Decode of those words is owned (correctly) by the canonical ARURI rows.
//!
//! Fix: legacy mg geometry restored VERBATIM as a dedicated
//! `encode_only` key `LDG.E.LTC128B.128_R_dARI` (mod group `128,E,LTC128B`
//! = exact full-key hit, outranking base-key canon for the era text form;
//! decoder skips encode_only keys so the BUG-038 shadow cannot return).
//! Collision census: 0/678,608 family-corpus words decode (post-084 HEAD)
//! to any `LDG.E.LTC128B.128` render, so the restored key captures no
//! canonical re-encode (work/f2-090 collision census).

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
     "@P5 LDG.E.LTC128B.128 R0, desc[URZ][R60.64+0x2400] !rsd[1:1,2:1,66:1,68:1,76:0,77:1,78:1,79:1,84:0,85:1,90:0]",
     "@P5 STG.E.EL.STRONG.GPU [R60.U32+UR20+0x2400], R63"),
];

#[test]
fn bug090_frozen_era_text_encodes_to_published_words() {
    // The publish contract: pinned sass98 lines must re-encode to the
    // silicon-proven published bytes (payload 96 bits).
    let t = t120();
    for &(w, text, _) in ERA_PINS {
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let enc = encode_instruction(&insn, &t)
            .unwrap_or_else(|e| panic!("encode failed for {text}: {e}"));
        assert_eq!(enc & M96, w & M96, "era text must encode to published bytes: {text}");
    }
}

#[test]
fn bug090_decode_of_published_word_is_canonical_raw_form() {
    // Decode surface must stay on the canonical rows (raw-address render,
    // vendor-exact) and must NOT resolve to the restored encode_only key.
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for &(w, _text, vendor) in ERA_PINS {
        let d = idx.decode(w, 0, &t).unwrap();
        assert_ne!(d.key, "LDG.E.LTC128B.128_R_dARI",
            "encode_only key must be decoder-invisible (word {w:032x})");
        assert_eq!(cubit::printer::to_sass(&d), vendor, "decode render {w:032x}");
    }
}

#[test]
fn bug090_restored_key_is_encode_only_in_table() {
    let t = t120();
    let k = t.get_key("LDG.E.LTC128B.128_R_dARI")
        .expect("restored key present");
    assert!(k.encode_only, "restored key must carry encode_only");
    assert!(k.mod_groups.contains_key("128,E,LTC128B"));
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
