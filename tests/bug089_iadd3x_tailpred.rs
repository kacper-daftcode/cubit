//! BUG-089 (F2Q, 2026-08-23; sm120 cubit-bugs/089, i172/i173): IADD3.X imm
//! words with tail preds decoded through the harvest-junk key
//! `IADD3_R_P_P_R_R_R` mg X (sig token5 'R' but field imm@[63:32], and_base
//! pinned bit64=1). The junk key hid the true form
//! `IADD3_R_P_P_R_II_R_P_P` (2 operands longer) at the adjusted-length
//! tiebreak and forced the extra-trailing-pred printer path, whose hardcoded
//! "pred==7 && bit80" negation rendered the tok7 combine pred as `!PT`
//! whenever the tok8 carry pred was negated (vendor: `PT, !PT`).
//!
//! Fix at source (three layers):
//!   1. tables/sm120.json: junk `IADD3_R_P_P_R_R_R` mod_groups.X deleted
//!      (its slice is a strict subset of `IADD3_R_P_P_R_II_R` X coverage,
//!      which prints the identical operand lattice);
//!   2. tables/sm120.json: `IADD3_R_P_P_R_II_R` X gained the per-slot
//!      negation fields tok7 neg@90 + tok8 inv@80 (mirror of the
//!      `R_II_R_P_P` X sibling and the sm103a canon);
//!   3. printer extra-trailing-pred negation consults an explicit neg/inv
//!      field on that token first and only then falls back to the legacy
//!      bit80 heuristic (correct solely for the carry-pred slot).
//! Anchors: the two vendor words of cubit-bugs/089/repro089 (hopb @0370 /
//! @d710), nvdisasm 13.3 render as golden.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn t103() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }
const M96: u128 = (1u128 << 96) - 1;

/// (word low96, vendor canonical text) — cubit-bugs/089 repro pair.
const GOLD: &[(u128, &str)] = &[
    (0x0fca0003f1e4ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, PT, !PT"),
    (0x11c80003f1ec40fffffc2fff405810, "@P5 IADD3.X R64, P0, PT, RZ, -0x3d1, ~R64, PT, !PT"),
];

#[test]
fn bug089_decode_vendor_exact() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for &(w, golden) in GOLD {
        let d = idx.decode(w, 0, &t).unwrap();
        let text = cubit::printer::to_sass(&d);
        assert_eq!(text, golden, "word {w:024x}");
        // must route through the II form, not a register-sig key
        assert!(d.key.contains("_II_"), "winner key = {}", d.key);
        assert!(!d.key.ends_with("_R_R_R"), "junk key survived: {}", d.key);
    }
}

#[test]
fn bug089_roundtrip_word_exact() {
    // encode(decode(w)) == w on low96 for both anchors (rsd must vanish)
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for &(w, golden) in GOLD {
        let d = idx.decode(w, 0, &t).unwrap();
        let text = cubit::printer::to_sass(&d);
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        assert_eq!(w2 & M96, w & M96, "loop {golden}");
    }
}

#[test]
fn bug089_negated_tok7_still_renders_bang_pt() {
    // Control: tok7 neg@90=1 must round-trip as `!PT` (negativity of the
    // fallback removal). Synthesize from anchor #1 by flipping b90 and
    // clearing the b90-neighbour junk bits only where the row is variable:
    // b90 lives inside the II_R X variable mask post-fix.
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let w = GOLD[0].0 | (1u128 << 90);
    let d = idx.decode(w, 0, &t).unwrap();
    let text = cubit::printer::to_sass(&d);
    assert_eq!(text, "IADD3.X R40, P0, PT, R40, 0x1, RZ, !PT, !PT");
    let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
    let w2 = encode_instruction(&insn, &t).unwrap();
    assert_eq!(w2 & M96, w & M96, "negated tok7 loop");
}

#[test]
fn bug089_rcneg_keeps_inv_rc_and_tail() {
    // RCNEG class (~Rc via inv@75) must keep `~R64` AND the `PT, !PT` tail.
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let d = idx.decode(GOLD[1].0, 0, &t).unwrap();
    let text = cubit::printer::to_sass(&d);
    assert!(text.contains("~R64"), "{text}");
    assert!(text.ends_with("PT, !PT"), "{text}");
    assert!(text.starts_with("@P5 "), "{text}");
}

#[test]
fn bug089_junk_key_variant_absent_and_iir_fields_present() {
    let t = t120();
    assert!(t.get("IADD3_R_P_P_R_R_R", "X").is_none(), "junk mod group still present");
    let e = t.get("IADD3_R_P_P_R_II_R", "X").expect("II_R X row");
    let has = |shift: u32, tok: i32, ext: &str| e.fields.iter().any(|f| {
        f.shift == shift && f.token_idx == tok
            && format!("{:?}", f.extraction).to_lowercase() == ext
    });
    assert!(has(90, 7, "neg"), "tok7 neg@90 missing");
    assert!(has(80, 8, "inv"), "tok8 inv@80 missing");
    // variable mask must cover both negation bits now
    let vm: u128 = e.variable_mask;
    assert!(vm & (1u128 << 90) != 0, "bit90 not variable");
    assert!(vm & (1u128 << 80) != 0, "bit80 not variable");
    // sm103a table was already canonical and stays untouched
    let t3 = t103();
    assert!(t3.get("IADD3_R_P_P_R_II_R", "X").is_none(),
        "sm103a has no II_R X row — do not port this bug there");
    assert!(t3.get("IADD3_R_P_P_R_II_R_P_P", "X").is_some());
}

/// Full negation lattice on the tok7/tok8 tail preds of IADD3.X imm form:
/// tok7 pred @87 + neg @90, tok8 pred @77 + inv @80, synthesized on the
/// hopb @0370 anchor. Vendor parity (nvdisasm 13.3, sm120): 16/16 exact
/// renders, 16/16 byte-exact re-encodes (work/f2-089/sweep089/).
const SWEEP16: &[(u128, &str)] = &[
    (0x000fca0003f0e4ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, PT, PT"),
    (0x000fca0003f1e4ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, PT, !PT"),
    (0x000fca0003f004ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, PT, P0"),
    (0x000fca0003f104ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, PT, !P0"),
    (0x000fca0007f0e4ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, !PT, PT"),
    (0x000fca0007f1e4ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, !PT, !PT"),
    (0x000fca0007f004ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, !PT, P0"),
    (0x000fca0007f104ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, !PT, !P0"),
    (0x000fca000070e4ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, P0, PT"),
    (0x000fca000071e4ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, P0, !PT"),
    (0x000fca00007004ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, P0, P0"),
    (0x000fca00007104ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, P0, !P0"),
    (0x000fca000470e4ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, !P0, PT"),
    (0x000fca000471e4ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, !P0, !PT"),
    (0x000fca00047004ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, !P0, P0"),
    (0x000fca00047104ff0000000128287810, "IADD3.X R40, P0, PT, R40, 0x1, RZ, !P0, !P0"),
];

#[test]
fn bug089_sweep16_vendor_exact_bothways() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for &(w, golden) in SWEEP16 {
        let d = idx.decode(w, 0, &t).unwrap();
        let text = cubit::printer::to_sass(&d);
        assert_eq!(text, golden, "word {w:024x}");
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        assert_eq!(w2 & M96, w & M96, "loop {golden}");
    }
}
