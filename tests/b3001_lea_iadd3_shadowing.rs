//! B300-1 (2026-11-05): `LEA_R_P_R_UR_R_II` mod group `HI` rebuilt from measurement.
//!
//! The pre-B300-1 row declared pred at [3:0] (opcode garbage) and reuse at
//! [75]/[76] — inside the imm field [79:75] — so (a) bits [3:0] were never
//! and_base-checked and vendor IADD3 words (bit 0 = 0) shadowed into the LEA
//! row, (b) encode(decode(w)) was not a fixed point (imm 0x1c -> 0x1e).
//! 31 words per arch in the vendor census corpus were re-encoded as
//! `IADD.XOR` (losing the P0 carry predicate and, in the cusparse.923
//! variant, the `-R8` negation). Rebuild from the nvdisasm-13.3 field sweep
//! (pubwave/wave11/b300/: single-bit + imm[79:75] 32-value probes, both
//! modes; 62/62 fixture words are IADD3):
//!   guard [15:12] tok 0, pred [83:81] tok 2, neg UR [63] tok 4,
//!   neg Ra [72] tok 3, reuse Ra [122] tok 3, reuse Rc [124] tok 5,
//!   imm [79:75] tok 6 (unchanged), and_base unchanged (bit 0 = 1 now
//! enforced), variable_mask = field-span union + IADD3 ctrl bank.
//! Healed (roundtrip-strict, sm103a): cusolver.994 123->111, cusparse.119
//! 33->26, cusparse.923 36->24 fails — exactly the 12/7/12 LEA words.
//!
//! Oracle: nvdisasm-13.3 `-b SM103a/SM100a -hex` per flipped bit (see
//! b3001_fixture_and_sweep.py / b3001_lea_mode_probe.py).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const NOSCHED: u128 = !(0xFFFF_FFFFu128 << 96);

/// corpus word, sm103a libcusolver.so.994 sec50 @0x10660 (census LEA class)
const W_IADD3: u128 = 0x040fe2000f83e0100000000427287c10;
/// corpus word, sm103a libcusparse.so.923 sec20 @0x017e0 — the `-R8` variant
const W_IADD3_NEG: u128 = 0x002fc8000f83e8080000000817127c10;

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
fn clean(s: &str) -> &str {
    s.trim_end_matches([' ', ';'])
}

#[test]
fn b3001_vendor_iadd3_words_decode_as_iadd3_not_lea() {
    for name in ["tables/sm103a.json", "tables/sm100a.json"] {
        let t = table(name);
        let text = dec(&t, W_IADD3);
        assert_eq!(clean(&text), "IADD3 R40, P1, P0, R39.reuse, UR4, R16", "{name}");
        assert_eq!(enc(&t, &text) & NOSCHED, W_IADD3 & NOSCHED, "{name}: round trip");
        let text = dec(&t, W_IADD3_NEG);
        assert_eq!(clean(&text), "IADD3 R18, P1, P0, R23, UR8, -R8", "{name}");
        assert_eq!(enc(&t, &text) & NOSCHED, W_IADD3_NEG & NOSCHED, "{name}: -R8 survives");
    }
}

#[test]
fn b3001_lea_mode_is_a_fixed_point() {
    for name in ["tables/sm103a.json", "tables/sm100a.json"] {
        let t = table(name);
        let w = W_IADD3 | 1; // bit 0 = 1: the LEA.HI mode (nvdisasm oracle)
        let text = dec(&t, w);
        assert_eq!(clean(&text), "LEA.HI R40, P1, R39.reuse, UR4, R16, 0x1c", "{name}");
        assert_eq!(enc(&t, &text) & NOSCHED, w & NOSCHED, "{name}: LEA.HI round trip");
        // guard field [15:12]: bit-12 flip renders @P6 and re-bakes
        let g = dec(&t, w ^ (1 << 12));
        assert!(clean(&g).starts_with("@P6 LEA.HI"), "{name}: guard render {g}");
        assert_eq!(enc(&t, &g) & NOSCHED, (w ^ (1 << 12)) & NOSCHED, "{name}: guard round trip");
        // imm [79:75] is five real bits (bit 76 included — no XOR here in LEA mode)
        let w30 = (w & !(0x1Fu128 << 75)) | (30u128 << 75);
        let text = dec(&t, w30);
        assert_eq!(clean(&text), "LEA.HI R40, P1, R39.reuse, UR4, R16, 0x1e", "{name}");
        assert_eq!(enc(&t, &text) & NOSCHED, w30 & NOSCHED, "{name}: imm 0x1e round trip");
    }
}
