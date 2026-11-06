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
//! * IADD.XOR and LEA.HI.X as coldface measured them (taken by T-7 after re-measuring every field on
//!   nvdisasm 13.1 `-b SM103` / `SM100` / `SM120`);
//! * IADD3.X -- REPLACED by T-7 (2026-11-06): the proposal baked the second trailing predicate as a
//!   constant `!PT` ("bits 91..121 probed, nothing drives it" -- the wrong window) and printed `-R`
//!   for the inverted operands. Measured: the vendor text carries TWO carry-in predicates, Pc at
//!   [89:87] with its negation at bit 90 and Pd at [79:77] with its negation at bit 80 (`pred@77`
//!   0..7 with bit 80 -> `!P0`..`!PT`, bit 80 clear -> `PT`), and the `~` glyph for bits 72 / 63 / 75.
//!   The harvest row `IADD3_R_P_P_R_UR_R_P_P / X` (count 20 864) already modelled both carry-ins; its
//!   one defect -- a 4-bit `pred @87` swallowing the negation bit 90 (coldface's diagnosis, P8..P15 for
//!   negated words) -- is repaired in blackwell-isa (3-bit pred + `neg @90`, tag
//!   iadd3x-urform-carry-neg-2026-11-06) on sm120 / sm103a / sm100a, and the row stays decode-live.

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
fn b3004_iadd3_x_two_carry_ins_through_the_repaired_harvest_row() {
    // T-7 (2026-11-06): both carry-in predicates are operands; the first one's negation is bit 90.
    for name in ["tables/sm120.json", "tables/sm103a.json", "tables/sm100a.json"] {
        let t = table(name);
        assert_eq!(key(&t, W_IADD3_X), "IADD3_R_P_P_R_UR_R_P_P", "{name}");
        assert_eq!(clean(&dec(&t, W_IADD3_X)),
                   "IADD3.X R40, P1, P0, R39.reuse, UR4, R16, !PT, !PT", "{name}");
        let text = dec(&t, W_IADD3_X);
        assert_eq!(enc(&t, &text) & NOSCHED, W_IADD3_X & NOSCHED, "{name}: round trip");
        // a non-PT second carry-in (pred@77 = 5, bit 80 clear -> `P5`) and a negated first one
        // (pred@87 = 5, bit 90 set -> `!P5`): the proposal's baked `!PT` could not decode this word.
        let w2 = (W_IADD3_X & !((7u128 << 77) | (1u128 << 80) | (7u128 << 87))) | (5u128 << 77) | (5u128 << 87) | (1u128 << 90);
        assert_eq!(clean(&dec(&t, w2)), "IADD3.X R40, P1, P0, R39.reuse, UR4, R16, !P5, P5", "{name}");
        assert_eq!(enc(&t, &dec(&t, w2)) & NOSCHED, w2 & NOSCHED, "{name}: round trip of the two-predicate word");
        // the inverted operands print with the `~` glyph (bits 72 / 63 / 75)
        let w3 = W_IADD3_X | (1u128 << 72) | (1u128 << 63) | (1u128 << 75);
        assert_eq!(clean(&dec(&t, w3)), "IADD3.X R40, P1, P0, ~R39.reuse, ~UR4, ~R16, !PT, !PT", "{name}");
        assert_eq!(enc(&t, &dec(&t, w3)) & NOSCHED, w3 & NOSCHED, "{name}: round trip of the ~ word");
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
        // the .X word must not fall into the HI group of the plain LEA row (2026-11-06 T-8: the family
        // rebuilt from measurement, tools/probes/re_sm120_lea.py -- the `.X` row is the `HI,X` group of the
        // carry-in key `LEA_R_P_R_UR_R_II_P`, the dotted B300-4 key is retired)
        assert_eq!(key(&t, W_LEA_HI_X), "LEA_R_P_R_UR_R_II_P", "{name}");
        // and the plain LEA.HI mode is untouched (B300-1 regression guard)
        assert_eq!(key(&t, W_IADD3 | 1), "LEA_R_P_R_UR_R_II", "{name}");
    }
}
