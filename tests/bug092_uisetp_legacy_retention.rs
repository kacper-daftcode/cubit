//! BUG-092 (F2Q, 2026-08-23; sm120 cubit-bugs/092, i213): adoption gates on
//! the BUG-086 UISETP/UISETP re-canon flagged two holes on vendor words.
//!
//! Slot A (sm120_kernel_sm120.cubin .text.KernelB @0x29a0, published word
//! 0x000fe2000bf062700000000b1300788c): pure-upstream table decode is
//! canonical and nvdisasm 13.3 SM120 renders the identical string
//! (`UISETP.GE.AND UP0, UPT, UR19, 0xb, UPT`) -- the reported misdecode via
//! `UISETP_UP_UP_UR_R_UP` comes from a legacy overlay key that only exists in
//! the fleet-side merged v-table (never in upstream). Pins keep the canonical
//! coverage honest.
//!
//! Slot B (pinned publish text, rt98_pub KernelA @0x1af0, word
//! 0x000fe2000bf042700000000f3f00728c; same legacy line present in
//! rt98_v2.sass:2288): the 086 re-canon removed the pre-086 "" mod group of
//! `UISETP_UP_UP_UR_UR_UP`, so frozen-era text
//! `UISETP.?GT.?S32.?OR UP0, UPT, UR63, UR15, UPT` failed rc=1 on the pure
//! upstream table. Fix = the BUG-090 encode_only mechanism pushed one level
//! down: mod-group-level `encode_only` rows are decoder-invisible (canonical
//! groups on the same key keep owning decode: vendor truth is
//! `UISETP.GT.AND ...`) while the encoder sees the verbatim pre-086 ""
//! geometry, so pinned legacy text re-encodes byte-exact (parity proven
//! against the pre-086 table 2c76e16 itself).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
const M96: u128 = (1u128 << 96) - 1;

/// Published words (low96), vendor nvdisasm 13.3 SM120 render.
const WORD_A: u128 = 0x000fe2000bf062700000000b1300788c;
const WORD_B: u128 = 0x000fe2000bf042700000000f3f00728c;
const VENDOR_A: &str = "UISETP.GE.AND UP0, UPT, UR19, 0xb, UPT";
const VENDOR_B: &str = "UISETP.GT.AND UP0, UPT, UR63, UR15, UPT";
const LEGACY_B: &str = "UISETP.?GT.?S32.?OR UP0, UPT, UR63, UR15, UPT";

#[test]
fn bug092_decode_vendor_exact_both_slots() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let d = idx.decode(WORD_A, 0, &t).unwrap();
    assert_eq!(cubit::printer::to_sass(&d), VENDOR_A);
    assert_eq!(d.mod_group, "AND,GE", "slot A must stay on the canonical group");
    let d = idx.decode(WORD_B, 0, &t).unwrap();
    assert_eq!(cubit::printer::to_sass(&d), VENDOR_B);
    assert_eq!(d.mod_group, "AND,GT", "slot B decode must NOT route into the encode_only retention");
}

#[test]
fn bug092_retention_decode_invisible_encode_visible() {
    let t = t120();
    let e = t.get("UISETP_UP_UP_UR_UR_UP", "").expect("retention row present");
    assert!(e.encode_only, "retention must carry the encode_only flag");
    // canonical groups untouched on the same key
    assert!(t.get("UISETP_UP_UP_UR_UR_UP", "AND,GT").is_some());
}

#[test]
fn bug092_legacy_text_encodes_published_word() {
    let t = t120();
    let insn = parse_sass(&format!("{LEGACY_B} ;"), 0).unwrap();
    let w = encode_instruction(&insn, &t).unwrap();
    assert_eq!(w & M96, WORD_B & M96, "legacy frozen-era text must re-encode the published payload");
}

#[test]
fn bug092_canon_texts_roundtrip_both_slots() {
    let t = t120();
    for (w, text) in [(WORD_A, VENDOR_A), (WORD_B, VENDOR_B)] {
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        assert_eq!(w2 & M96, w & M96, "canon encode {text}");
        // full loop: decode -> print -> encode == payload-exact
        let idx = DecodeIndex::build(&t);
        let d = idx.decode(w2, 0, &t).unwrap();
        let t2 = cubit::printer::to_sass(&d);
        let insn2 = parse_sass(&format!("{t2} ;"), 0).unwrap();
        let w3 = encode_instruction(&insn2, &t).unwrap();
        assert_eq!(w3 & M96, w & M96, "roundtrip {text}");
    }
}
