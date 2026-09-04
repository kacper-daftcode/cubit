//! BUG-340 (F2-iter180, loop5/blind front2, 2026-09-02): sm120 F2IP.U8.F32*
//! era rows retag neg@72 tok4 -> opmod:H1 + b63 text-inert decode-relax
//! (canonical 02c147d; ENGINE untouched).
//!
//! PRE (publish f1e894a; 308.md sec.6 ghost residuum + arb340 mint-space):
//!   rows F2IP.U8.F32{,_P0,_P2,_P5,RELU_P0}_R_R_R_R carried extraction
//!   'neg' 1b@72 tok4. Vendor reads b72 as hsel '.H1' on the 4th operand
//!   (arb339 D1/D5 + measure_pre339 mint-space: 5 text-shapes x {base, b72,
//!   b63, b73, b72b63} x4 legs AGREE) and b63 as TEXT-INERT. Ghost words
//!   printed '-R10' where vendor prints 'R10.H1' (wrong render, corpus-zero;
//!   encoder side already bail-loud via BUG-308).
//! MIRROR: err221/err222 (sm121a F2IP opmod:H1 @72 tok4) + bug265 (I2IP).
//! FIX: extraction -> 'opmod:H1' (same bits/token), vm |= b63 decode-relax
//!   (316/320 text-inert band doctrine). Authored '.H1' mints b72 and
//!   round-trips; authored '-R10' stays LOUD REFUSE (BUG-308 bail).
//! NOT GRAFTED: F2IP.U8.F32.NTZ_P (measured HMMA.1688 dead-shadow in its
//!   ab space -- engine == vendor there; its neg@72/tok2 + neg@63/tok3 are
//!   the REAL vendor neg law; shadow-note registered).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).unwrap();
    encode_instruction(&insn, t).map_err(|e| format!("{e}"))
}
const KEYS: [&str; 5] = [
    "F2IP.U8.F32_R_R_R_R",
    "F2IP.U8.F32_P0_R_R_R_R",
    "F2IP.U8.F32_P2_R_R_R_R",
    "F2IP.U8.F32_P5_R_R_R_R",
    "F2IP.U8.F32.RELU_P0_R_R_R_R",
];

#[test]
fn t340_1_structure_retag_and_relax() {
    let t = tab("sm120");
    for k in KEYS {
        let g = &t.entries[k].mod_groups[""];
        let h1 = g
            .fields
            .iter()
            .find(|f| f.shift == 72 && f.token_idx == 4)
            .unwrap_or_else(|| panic!("{k}: b72/tok4 field missing"));
        assert!(
            matches!(&h1.extraction, Extraction::OpModFlag(n) if n == "H1"),
            "{k}: b72 tok4 must be opmod:H1"
        );
        assert!(
            !g.fields
                .iter()
                .any(|f| matches!(f.extraction, Extraction::Neg)),
            "{k}: no 'neg' field left"
        );
        assert_eq!((g.variable_mask >> 63) & 1, 1, "{k}: b63 decode-relaxed");
    }
    // NTZ_P shadow row untouched (neg@72 tok2 + neg@63 tok3 kept as-is)
    let g = &tab("sm120").entries["F2IP.U8.F32.NTZ_P_R_R_R_R"].mod_groups[""];
    assert!(
        g.fields
            .iter()
            .any(|f| f.shift == 72 && matches!(f.extraction, Extraction::Neg)),
        "NTZ_P shadow keeps its (dead) neg field"
    );
    // other legs do not grow the era-key form
    for leg in ["sm100a", "sm103a", "sm121a"] {
        assert!(!tab(leg).entries.contains_key("F2IP.U8.F32_P0_R_R_R_R"));
    }
}

#[test]
fn t340_2_decode_law_vendor_exact() {
    // base word = F2IP.U8.F32_R_R_R_R space, R4/R6/R8/R10 (arb339 D0 lane)
    let base: u128 = (0x7243) | (4u128 << 16) | (6u128 << 24) | (8u128 << 32) | (10u128 << 64);
    let t = tab("sm120");
    assert_eq!(
        dec(&t, base).as_deref(),
        Some("F2IP.U8.F32 R4, R6, R8, R10")
    );
    assert_eq!(
        dec(&t, base ^ (1u128 << 72)).as_deref(),
        Some("F2IP.U8.F32 R4, R6, R8, R10.H1"),
        "b72 = .H1 (vendor law)"
    );
    assert_eq!(
        dec(&t, base ^ (1u128 << 63)).as_deref(),
        Some("F2IP.U8.F32 R4, R6, R8, R10"),
        "b63 text-inert (decode-relax 316/320)"
    );
    assert_eq!(
        dec(&t, base ^ (1u128 << 72) ^ (1u128 << 63)).as_deref(),
        Some("F2IP.U8.F32 R4, R6, R8, R10.H1")
    );
    // b73 text-inert (arb339 D4): pinned 0 by the row -- stays HOLE
    assert!(dec(&t, base ^ (2u128 << 72)).is_none(), "b73 junk claims");
}

#[test]
fn t340_3_authored_mint_and_refuse() {
    let t = tab("sm120");
    let w = enc(&t, "F2IP.U8.F32 R4, R6, R8, R10.H1").unwrap();
    let base: u128 = (0x7243) | (4u128 << 16) | (6u128 << 24) | (8u128 << 32) | (10u128 << 64);
    assert_eq!(w & M96, (base ^ (1u128 << 72)) & M96, ".H1 mints b72");
    assert_eq!(
        dec(&t, w).as_deref(),
        Some("F2IP.U8.F32 R4, R6, R8, R10.H1"),
        "roundtrip"
    );
    // BUG-308 bail: signed register on F2IP stays LOUD REFUSE (was a silent
    // wrong-code mint pre-308).
    let e = enc(&t, "F2IP.U8.F32 R4, R6, R8, -R10").unwrap_err();
    assert!(e.contains("BUG-308"), "{e}");
}

#[test]
fn t340_4_ntz_p_shadow_note() {
    // the NTZ_P ab space decodes as HMMA.1688 on engine == vendor (shadow);
    // the F2IP.NTZ_P row never wins election there (like BUG-333's dup).
    let w: u128 =
        (0x023c) | (1u128 << 12) | (4u128 << 16) | (6u128 << 24) | (8u128 << 32) | (10u128 << 64);
    let t = tab("sm120");
    assert_eq!(
        dec(&t, w).as_deref(),
        Some("@P1 HMMA.1688.F16 R4, R6, R8, R10")
    );
}
