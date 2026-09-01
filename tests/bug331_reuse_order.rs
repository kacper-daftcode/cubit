//! BUG-331 (F2-iter177, loop5/blind front2, 2026-09-01): the raw-bit
//! `.reuse` sideband must print the suffix immediately after the register
//! core, BEFORE lane/type mods -- vendor order is 'R6.reuse.F32x2.HI_LO',
//! never 'R6.F32x2.HI_LO.reuse'. Vendor law measured (arb331c: nvdisasm
//! 13.3.73 raw -b, FFMA2 anchors on tok2 b122 / tok3 b123 / tok4 b124 +
//! base + all-clear, x2 models SM100a/SM103a AGREE on every probe;
//! SM120/SM121a vendor-reject FFMA2 outright [BUG-234 comment];
//! work/bug331/arb331c_verdicts.json + arb331d run). Complements the
//! corpus-proven hsel form 'R12.reuse.H0_H0' / '-R11.reuse.H1_H1'
//! (t243/t261 anchors, field-driven rows).
//!
//! Root cause: on winning rows whose reuse bit carries an explicit row
//! field, format_reg composes `{s}.reuse{mods}` = vendor order; rows
//! WITHOUT the field (census331 of the 4 tables: 30/30/119/181 row-tokens
//! with printable mods but no reuse field, e.g. FFMA2 tok2/3/4 donors)
//! fell to the raw-bit sideband, which appended `.reuse` at the END of
//! the operand string. Pre-fix publish (cubit-ad70966) measured:
//!   sm100a 'R6.F32x2.HI_LO.reuse' / sm103a same (WRONG),
//!   sm120 'R6.reuse.F32x2.HI_LO' (fielded row, already vendor),
//!   sm121a hole (stays hole).
//!
//! FIX (engine only, src/printer.rs raw-bit sideband): insert `.reuse`
//! before the first '.' mod segment of the operand instead of appending
//! at the end. Tables untouched (canonical 4a46e95 stays).
//!
//! Registration source: 331-kand LOW (F2-iter166, witness family t264
//! W_HMB reported with engine order 'R12.H0_H0.reuse'; on publish
//! e8426d9/3e415bb the W_HMB row decodes field-driven vendor-ordered, so
//! the live residual was the no-row-field sideband class measured here).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> Option<u128> {
    let insn = parse_sass(&format!("{text};"), 0).ok()?;
    encode_instruction(&insn, t).ok()
}

/// FFMA2 R5, R3, R4, R6 ; ctrl yield=1 (arb331c anchors):
const FFMA2_BASE: u128 = 0x000fe200000000060000000403057249;
const FFMA2_R2: u128 = 0x040fe200000000060000000403057249; // b122 -> tok2 (R3)
const FFMA2_R3: u128 = 0x080fe200000000060000000403057249; // b123 -> tok3 (R4)
const FFMA2_R4: u128 = 0x100fe200000000060000000403057249; // b124 -> tok4 (R6)
const FFMA2_RALL: u128 = 0x1c0fe200000000060000000403057249;
/// Field-driven anchor (BUG-243/261 witnesses): row-carried reuse fields
/// already printed vendor order pre-fix -- regression coverage.
const W_HMB: u128 = 0x140fe4000816080b200000080c097c31;

#[test]
fn t331_1_sideband_vendor_order_donors() {
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert_eq!(
            dec(&t, FFMA2_BASE).as_deref(),
            Some("FFMA2 R5, R3.F32x2.HI_LO, R4.F32x2.HI_LO, R6.F32x2.HI_LO"),
            "{leg}: base"
        );
        assert_eq!(
            dec(&t, FFMA2_R2).as_deref(),
            Some("FFMA2 R5, R3.reuse.F32x2.HI_LO, R4.F32x2.HI_LO, R6.F32x2.HI_LO"),
            "{leg}: tok2 reuse precedes lane mods (vendor order)"
        );
        assert_eq!(
            dec(&t, FFMA2_R3).as_deref(),
            Some("FFMA2 R5, R3.F32x2.HI_LO, R4.reuse.F32x2.HI_LO, R6.F32x2.HI_LO"),
            "{leg}: tok3 reuse precedes lane mods (vendor order)"
        );
        assert_eq!(
            dec(&t, FFMA2_R4).as_deref(),
            Some("FFMA2 R5, R3.F32x2.HI_LO, R4.F32x2.HI_LO, R6.reuse.F32x2.HI_LO"),
            "{leg}: tok4 reuse precedes lane mods (vendor order)"
        );
        assert_eq!(
            dec(&t, FFMA2_RALL).as_deref(),
            Some("FFMA2 R5, R3.reuse.F32x2.HI_LO, R4.reuse.F32x2.HI_LO, R6.reuse.F32x2.HI_LO"),
            "{leg}: all-slots vendor order"
        );
    }
}

#[test]
fn t331_2_field_driven_order_unchanged() {
    // Rows WITH an explicit reuse field keep their vendor order everywhere.
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        assert_eq!(
            dec(&t, W_HMB).as_deref(),
            Some("HFMA2 R9, R12.reuse.H0_H0, UR8.H0_H0, -R11.reuse.H1_H1"),
            "{leg}: field-driven anchor regressed"
        );
    }
}

#[test]
fn t331_3_sm120_stay_green_sm121a_stay_hole() {
    // sm120 carries the tok4 reuse field on FFMA2_R_R_R_R and printed
    // vendor order pre-fix; sm121a does not route the opcode (hole). Both
    // behaviors must be byte-stable across the fix.
    let t120 = tab("sm120");
    assert_eq!(
        dec(&t120, FFMA2_R4).as_deref(),
        Some("FFMA2 R5, R3.F32x2.HI_LO, R4.F32x2.HI_LO, R6.reuse.F32x2.HI_LO"),
        "sm120: field-driven row must not double-print or reorder"
    );
    let t121 = tab("sm121a");
    assert!(
        dec(&t121, FFMA2_R4).is_none(),
        "sm121a: FFMA2 stays a hole (pre-fix behavior)"
    );
}

#[test]
fn t331_4_roundtrip_anchor_words() {
    // Mint path: authored PLAIN spelling with an explicitly-spelled
    // `.reuse` on the target token must mint exactly base|reuse-bit
    // (yield stays 0 -- schedule-owned). Decode of the same word with
    // yield=1 must print the vendor-order text (defaults included).
    // NOTE: the explicit default-lane spelling ('R4.F32x2.HI_LO' on tok3)
    // mints b88 ('.F32' readback) -- pre-existing mint quirk registered
    // separately (357-kand); excluded from the mint pin here.
    const B109: u128 = 1 << 109;
    const BASE_NOY: u128 = 0x000fc200000000060000000403057249; // yield=0 mint
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        for (w_noy, authored, vendor_txt) in [
            (
                BASE_NOY | (1 << 122),
                "FFMA2 R5, R3.reuse, R4, R6",
                "FFMA2 R5, R3.reuse.F32x2.HI_LO, R4.F32x2.HI_LO, R6.F32x2.HI_LO",
            ),
            (
                BASE_NOY | (1 << 123),
                "FFMA2 R5, R3, R4.reuse, R6",
                "FFMA2 R5, R3.F32x2.HI_LO, R4.reuse.F32x2.HI_LO, R6.F32x2.HI_LO",
            ),
            (
                BASE_NOY | (1 << 124),
                "FFMA2 R5, R3, R4, R6.reuse",
                "FFMA2 R5, R3.F32x2.HI_LO, R4.F32x2.HI_LO, R6.reuse.F32x2.HI_LO",
            ),
        ] {
            let minted = enc(&t, authored).unwrap_or_else(|| panic!("{leg}: encode {authored}"));
            assert_eq!(
                minted, w_noy,
                "{leg}: {authored} must mint base|bit, yield=0"
            );
            assert_eq!(
                dec(&t, minted | B109).as_deref(),
                Some(vendor_txt),
                "{leg}: minted word decode (yield=1) == vendor order"
            );
            // and the vendor-order text decodes to itself through the pipeline
            assert_eq!(
                dec(&t, w_noy | B109).as_deref(),
                Some(vendor_txt),
                "{leg}: anchor decode"
            );
        }
    }
}

#[test]
fn t331_5_no_mod_plain_case_unchanged() {
    // No-mods sideband insertion keeps the simple 'Rn.reuse' shape
    // (BUG-326 anchor, yield=1): 'R30.reuse' on the IMAD.WIDE row.
    const W_WIDE_Y1: u128 = 0x040fe80002080442000000781e427225; // yield=1
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        assert_eq!(
            dec(&t, W_WIDE_Y1).as_deref(),
            Some("IMAD.WIDE.U32.X R66, P4, R30.reuse, R120, R66, P4"),
            "{leg}: plain .reuse print regressed"
        );
    }
}
