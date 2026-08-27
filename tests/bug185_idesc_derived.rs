//! BUG-185 — tcgen05 UTC*MMA idesc/baked lane (owner: front2/blind F2-iter88).
//! Found as kand-185 in fleet note 178 sec.5(b): `idesc[UR9]` vs `idesc[UR5]`
//! encode to byte-identical words (the rows carry no idesc_ur field).
//!
//! Vendor arbitration (nvdisasm 13.3.73, 2026-08-26,
//! work/bug185/arb/arb185{a,b,c}.py):
//!   - idesc[URn] is a DERIVED glyph == tok4 tmem UR + 1 (run27 rule):
//!     8/8 single-bit probes on a gold UTCQMMA '' anchor, the same on 2CTA;
//!     no bit outside the tok4 window moves the printed idesc; hexdb census
//!     1,362/1,362 anchors derived-consistent (sm103a+sm100a).
//!   - [48:56) IS a real 8-bit window: the trailing explicit-UR form
//!     (`..., idesc[UR11], UR6, !UPT`) = the *_UR_ table rows; 0xff elides.
//! Pre-fix defects (LATENT by census — zero trailing-UR corpus words):
//!   (a) '' _UR_ rows of UTCQMMA/UTCIMMA/UTCHMMA_UR_UP_II carried tok2 at
//!       (24,8) = DUPLICATE of tok1: decode of a non-2CTA _UR_ word missed
//!       the row (prio-3 stole it to the UTCHMMA family with the sector
//!       discriminator [72,73] masked) and ENCODE clobbered tok1 with tok2's
//!       value (double write into [24:32)).
//!   (b) any textual idesc value/offset silently baked at encode.
//! Fix: data (patch185.py: tok2 -> (32,8) on the 3 rows, sm103a+sm100a) +
//! encoder gate check_idesc_derived (refuse mismatch, always-on).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn t100a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm100a.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}
fn enc_err(t: &IsaTable, text: &str) -> String {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).unwrap_err().to_string()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

// Gold words (77_blackwell_fmha_fp8.1 0x3090 / mla_2sm 0x1920), with the
// [48:56) trailing-UR window patched per arbitration probes.
const W_QMMA_II: u128 = (0x0003_e200_0f80_0308u128 << 64) | 0x00ff_0a3a_3c00_75ea;
const W_QMMA_UR: u128 = (0x0003_e200_0f80_0308u128 << 64) | 0x0006_0a3a_3c00_75ea;
const W_QMMA_2CTA_UR: u128 = (0x0003_e400_0fa0_030au128 << 64) | 0x0006_1006_1800_75ea;

#[test]
fn t185_1_decode_family_and_trailing_ur() {
    // non-2CTA _UR_ word: right family (NOT UTCHMMA prio-3 hijack), UR6 kept.
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    assert_eq!(dec(&t, &idx, W_QMMA_UR),
        "UTCQMMA gdesc[UR60], gdesc[UR58], tmem[UR8], tmem[UR10], idesc[UR11], UR6, !UPT");
    assert_eq!(dec(&t, &idx, W_QMMA_2CTA_UR),
        "UTCQMMA.2CTA gdesc[UR24], gdesc[UR6], tmem[UR10], tmem[UR16], idesc[UR17], UR6, !UPT");
}

#[test]
fn t185_2_encode_refuses_baked_idesc() {
    let t = t103a();
    let e = enc_err(&t, "UTCQMMA gdesc[UR60], gdesc[UR58], tmem[UR8], tmem[UR10], idesc[UR9], UPT ;");
    assert!(e.contains("BUG-185"), "mismatched idesc must refuse with attribution: {e}");
    // idesc offset on a field-less row: same silent-drop — refuse.
    let e2 = enc_err(&t, "UTCQMMA gdesc[UR60], gdesc[UR58], tmem[UR8], tmem[UR10], idesc[UR11+0x4], UPT ;");
    assert!(e2.contains("BUG-185"), "offset idesc must refuse: {e2}");
}

#[test]
fn t185_3_encode_derived_value_unchanged() {
    // The only decoder-produced idesc shape (derived value) must keep encoding.
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let w = enc(&t, "UTCQMMA gdesc[UR60], gdesc[UR58], tmem[UR8], tmem[UR10], idesc[UR11], !UPT ;");
    assert_eq!(w, W_QMMA_II & !SCHED, "derived-idesc payload must equal the gold anchor");
    // round trip decode(encode(text)) == text for both shapes
    let t2 = "UTCQMMA gdesc[UR60], gdesc[UR58], tmem[UR8], tmem[UR10], idesc[UR11], UR6, UPT";
    assert_eq!(dec(&t, &idx, enc(&t, t2)), t2);
}

#[test]
fn t185_4_ur_form_tok2_no_clobber() {
    // Pre-fix the duplicated tok2 field wrote tok2's UR into tok1's [24:32).
    let t = t103a();
    let w = enc(&t, "UTCQMMA gdesc[UR60], gdesc[UR58], tmem[UR8], tmem[UR10], idesc[UR11], UR6, UPT ;");
    assert_eq!((w >> 24) & 0xff, 60, "tok1 gdesc UR must stay 60");
    assert_eq!((w >> 32) & 0xff, 58, "tok2 gdesc UR lands at [32:40)");
    assert_eq!((w >> 48) & 0xff, 6, "trailing UR lands at [48:56)");
}

#[test]
fn t185_5_sm100a_parity() {
    // Vendored sm100a table shares the same rows: decode + refuse parity.
    let t = t100a();
    let idx = DecodeIndex::build(&t);
    assert_eq!(dec(&t, &idx, W_QMMA_UR),
        "UTCQMMA gdesc[UR60], gdesc[UR58], tmem[UR8], tmem[UR10], idesc[UR11], UR6, !UPT");
    let e = enc_err(&t, "UTCIMMA gdesc[UR32], gdesc[UR30], tmem[UR25], tmem[UR18], idesc[UR7], UPT ;");
    assert!(e.contains("BUG-185"), "{e}");
    // derived value passes and lands tok1/tok2 correctly (IMMA row)
    let w = enc(&t, "UTCIMMA gdesc[UR32], gdesc[UR30], tmem[UR25], tmem[UR18], idesc[UR19], UR7, UPT ;");
    assert_eq!((w >> 24) & 0xff, 32);
    assert_eq!((w >> 32) & 0xff, 30);
    assert_eq!((w >> 48) & 0xff, 7);
}

#[test]
fn t185_6_unrelated_desc_rows_untouched() {
    // Row WITH an owned consuming position: the II rows keep baking byte48=0xff
    // (and_base-authored) when no trailing UR is written — unchanged behavior.
    let t = t103a();
    let w = enc(&t, "UTCQMMA gdesc[UR60], gdesc[UR58], tmem[UR8], tmem[UR10], idesc[UR11], UPT ;");
    assert_eq!((w >> 48) & 0xff, 0xff, "II form keeps the baked 0xff sink byte");
    // Non-UTC instructions never see the gate.
    let w2 = enc(&t, "IADD3 R25, PT, PT, R25, 0x7b, RZ ;");
    assert_ne!(w2, 0);
}
