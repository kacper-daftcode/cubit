//! B300-4 (2026-11-05, order R 22:10Z C3): the three unowned forms of the
//! B300-1 opcode region, added as count_null rows on the owner's order
//! (NEEDS_OWNER 30, the LEA-family audit).
//!
//! Measured by the nvdisasm-13.3 single-bit + value sweeps in
//! `pubwave/wave11/b300/` (zero corpus witnesses): bit 76 selects the
//! one-predicate `IADD.XOR` rendering, bit 74 the `.X` carry-in forms. On
//! the sm120 table only `LEA.HI.X_*` exists structurally sound (mirrored);
//! its `IADD3.X_*` row is junk (T1) and `IADD.XOR` is absent even there.
//!
//! Notes pinned by this test:
//! * the era group `IADD3_R_P_P_R_UR_R_P_P / X` (count 20 864) is retired to
//!   encode-only retention: its 4-bit pred @87 swallowed the neg bit (P15) and
//!   its `pred @77` sat inside the imm window -- decode moves to the measured
//!   row, round-trip bits identical;
//! * the second trailing `, !PT` of the vendor `IADD3.X` text is a constant
//!   of the family (bits 91..121 probed, nothing drives it): the cubit text
//!   carries one carry-in token, `LEA.HI.X` matches nvdisasm token for token.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const NOSCHED: u128 = !(0xFFFF_FFFFu128 << 96);

/// vendor base of the whole B300-1/B300-4 probe family
const W_IADD3: u128 = 0x040fe2000f83e0100000000427287c10; // IADD3 R40, P1, P0, R39.reuse, UR4, R16
const W_IADD_XOR: u128 = 0x040fe2000f83f0100000000427287c10; // ^ (1<<76)
const W_IADD3_X: u128 = 0x040fe2000f83e4100000000427287c10; // ^ (1<<74)
const W_LEA_HI_X: u128 = 0x040fe2000f83e4100000000427287c11; // (|1) ^ (1<<74)

fn table(name: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(name)).unwrap()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text:?}: {e}"))
}
fn dec(t: &IsaTable, word: u128) -> String {
    let idx = DecodeIndex::build(t);
    to_sass(&idx.decode(word, 0, t).unwrap_or_else(|e| panic!("decode {word:032x}: {e}")))
}
fn key(t: &IsaTable, word: u128) -> String {
    let idx = DecodeIndex::build(t);
    let i = idx.decode(word, 0, t).unwrap();
    format!("{}", i.key)
}
fn clean(s: &str) -> &str {
    s.trim_end_matches([' ', ';'])
}

#[test]
fn b3004_iadd_xor_decodes_as_the_one_predicate_form() {
    for name in ["tables/sm103a.json", "tables/sm100a.json"] {
        let t = table(name);
        assert_eq!(clean(&dec(&t, W_IADD_XOR)), "IADD.XOR R40, P1, R39.reuse, UR4, R16", "{name}");
        let text = dec(&t, W_IADD_XOR);
        assert_eq!(enc(&t, &text) & NOSCHED, W_IADD_XOR & NOSCHED, "{name}: round trip");
        // no shadowing: the base IADD3 word keeps its own row
        assert!(key(&t, W_IADD3).starts_with("IADD3_R_P_P_R_UR_R"), "{name}: {}", key(&t, W_IADD3));
    }
}

#[test]
fn b3004_iadd3_x_decodes_via_the_measured_row_not_the_retired_era_group() {
    for name in ["tables/sm103a.json", "tables/sm100a.json"] {
        let t = table(name);
        assert_eq!(key(&t, W_IADD3_X), "IADD3.X_R_P_P_R_UR_R_P", "{name}");
        // one carry-in token (the second vendor !PT is a family constant -- see the module doc)
        assert_eq!(clean(&dec(&t, W_IADD3_X)),
                   "IADD3.X R40, P1, P0, R39.reuse, UR4, R16, !PT", "{name}");
        let text = dec(&t, W_IADD3_X);
        assert_eq!(enc(&t, &text) & NOSCHED, W_IADD3_X & NOSCHED, "{name}: round trip");
        assert_eq!(key(&t, W_IADD3), "IADD3_R_P_P_R_UR_R", "{name}");
    }
}

#[test]
fn b3004_lea_hi_x_matches_the_vendor_text_token_for_token() {
    for name in ["tables/sm103a.json", "tables/sm100a.json"] {
        let t = table(name);
        assert_eq!(clean(&dec(&t, W_LEA_HI_X)),
                   "LEA.HI.X R40, P1, R39.reuse, UR4, R16, 0x1c, !PT", "{name}");
        let text = dec(&t, W_LEA_HI_X);
        assert_eq!(enc(&t, &text) & NOSCHED, W_LEA_HI_X & NOSCHED, "{name}: round trip");
        // the .X word must not fall into the HI group of the plain LEA row
        assert_eq!(key(&t, W_LEA_HI_X), "LEA.HI.X_R_P_R_UR_R_II_P", "{name}");
        // and the plain LEA.HI mode is untouched (B300-1 regression guard)
        assert_eq!(key(&t, W_IADD3 | 1), "LEA_R_P_R_UR_R_II", "{name}");
    }
}
