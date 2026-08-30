//! BUG-255 (F2-iter131, loop5/blind front2, 2026-08-29): FP64 special-literal
//! (±INF/±QNAN/±SNAN) glyph print laws in src/printer.rs.
//!
//! (A) Tail-pad hygiene: format_double's token-level trailing space (the
//!     mid-slot law — DSETP "+INF , PT", 582-uniq corpus match, arb255
//!     nvdisasm 13.3.73) leaked to the END of the printed line whenever the
//!     f64 immediate was the last operand (DFMA R2, R16, R2, +INF␣ — 219 uniq
//!     census words x4 legs, the sole DFMA dec-parity DIFF class). Every
//!     downstream text consumer compares on whitespace-collapsed, stripped
//!     glyphs (law census pipeline: collapse + strip), so the tail pad is
//!     dead weight. Fix: in to_sass, when the last token carries an f64hi
//!     field the formatted operand is trim_end()'d. f16/f32 literals keep
//!     their (mid-slot) trailing space untouched (BUG-177 L4 / BUG-245
//!     laws; corpus last-slot occurrences are zero, so the trim condition
//!     is scoped to f64hi exactly).
//! (B) f64 NaN glyph law (arb255, raw -b SM103a == SM121a, corpus DFMA/DSETP
//!     witnesses with patched f64hi; 12/12 probes): the NaN arm was neg-flag
//!     only and always "QNAN"; vendor composes sign = neg field XOR sign bit
//!     (INF-arm rule) and picks SNAN when the f64 quiet bit (51) is clear.
//!     Render parity only; NaN encode stays parked (bimodal, t177_5/178).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec_g(t: &IsaTable, w: u128) -> String {
    let idx = DecodeIndex::build(t);
    let s = idx.decode(w, 0, t).map(|d| to_sass(&d)).expect("decode");
    // core glyph WITHOUT trimming the tail (the pad is what we assert on)
    s.split("/* @sched")
        .next()
        .unwrap()
        .split(" !rsd[")
        .next()
        .unwrap()
        .to_string()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text};"), 0).unwrap_or_else(|e| panic!("parse {text}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}

// Corpus witnesses (law251 census, 2,406-cubin battery, nvdisasm 13.3.73).
const W_DFMA_INF: u128 = 0x0e5400000000027ff000001002742b; // DFMA R2, R16, R2, +INF
const W_DSETP_INF: u128 = 0x0fdc0003f0c2007ff000001e00742a; // DSETP.GTU.AND P0, PT, |R30|, +INF , PT

fn with_hi(w: u128, hi: u32) -> u128 {
    (w & !(0xFFFF_FFFFu128 << 32)) | ((hi as u128) << 32)
}
const H_ONE: u32 = 0x3FF0_0000; //  +1.0
const H_PINF: u32 = 0x7FF0_0000; // +INF
const H_NINF: u32 = 0xFFF0_0000; // -INF
const H_PQNAN: u32 = 0x7FF8_0000; // +QNAN
const H_NQNAN: u32 = 0xFFF8_0000; // -QNAN
const H_PSNAN: u32 = 0x7FF0_0001; // +SNAN
const H_NSNAN: u32 = 0xFFF0_0001; // -SNAN

#[test]
fn t255_1_f64_last_glyph_no_pad() {
    // arb255 LAST-operand laws (nvdisasm glyph census form): no trailing pad.
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (hi, want) in [
            (H_PINF, "DFMA R2, R16, R2, +INF"),
            (H_NINF, "DFMA R2, R16, R2, -INF"),
            (H_PQNAN, "DFMA R2, R16, R2, +QNAN"),
            (H_NQNAN, "DFMA R2, R16, R2, -QNAN"),
            (H_PSNAN, "DFMA R2, R16, R2, +SNAN"),
            (H_NSNAN, "DFMA R2, R16, R2, -SNAN"),
            (H_ONE, "DFMA R2, R16, R2, 1"),
        ] {
            assert_eq!(
                dec_g(&t, with_hi(W_DFMA_INF, hi)),
                want,
                "{arch} hi={hi:#x}"
            );
        }
    }
}

#[test]
fn t255_2_encode_spelling_variants() {
    // Parser trims whitespace: vendor spellings ("+INF ;", "+INF  ;", "+INF;")
    // all encode to the census witness word.
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for text in [
            "DFMA R2, R16, R2, +INF",
            "DFMA R2, R16, R2, +INF ", // trailing tail-pad spelling
        ] {
            let insn = parse_sass(&format!("{text};"), 0).expect("parse");
            let w = encode_instruction(&insn, &t).expect("encode");
            assert_eq!(w & M96, W_DFMA_INF & M96, "{arch} {text:?}");
        }
    }
}

#[test]
fn t255_3_roundtrip_inf_witnesses() {
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for w in [W_DFMA_INF, W_DSETP_INF] {
            let g = dec_g(&t, w);
            let back = enc(&t, &g);
            assert_eq!(back & M96, w & M96, "{arch} roundtrip {g:?}");
        }
    }
}

#[test]
fn t255_4_mid_slot_pad_law_stands() {
    // DSETP f64 mid-slot: token-level trailing space BEFORE the comma is the
    // vendor law (582-uniq corpus match; arb255 mid probes) — must survive.
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (hi, want) in [
            (H_PINF, "DSETP.GTU.AND P0, PT, |R30|, +INF , PT"),
            (H_NINF, "DSETP.GTU.AND P0, PT, |R30|, -INF , PT"),
            (H_PQNAN, "DSETP.GTU.AND P0, PT, |R30|, +QNAN , PT"),
            (H_NQNAN, "DSETP.GTU.AND P0, PT, |R30|, -QNAN , PT"),
            (H_ONE, "DSETP.GTU.AND P0, PT, |R30|, 1, PT"),
        ] {
            assert_eq!(
                dec_g(&t, with_hi(W_DSETP_INF, hi)),
                want,
                "{arch} mid hi={hi:#x}"
            );
        }
    }
}

#[test]
fn t255_5_contra_sentinels() {
    // (a) BUG-245/177 mid-slot f32/f16 pads are f32-domain and untouched by
    //     the f64hi-scoped trim: FSEL QNAN mid-parity stands (t177 anchor).
    let t = tab("sm103a");
    let w: u128 = u128::from_str_radix("000fe200048000007fc00000ff077808", 16).unwrap();
    assert_eq!(dec_g(&t, w).trim(), "FSEL R7, RZ, +QNAN , !P1");
    // (b) plain f64 literals never had a pad: "1" still prints bare.
    assert_eq!(dec_g(&t, with_hi(W_DFMA_INF, H_ONE)), "DFMA R2, R16, R2, 1");
    // (c) a rendered DECODED line never ends in whitespace for the whole
    //     801-uniq INF census class (decode must not panic, glyph core is
    //     pad-free; asserted on all four arches on the DFMA witness legs).
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        let g = dec_g(&t, W_DFMA_INF);
        assert!(!g.ends_with(char::is_whitespace), "{arch} tail pad: {g:?}");
    }
}
