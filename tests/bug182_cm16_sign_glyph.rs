//! BUG-182 (F2, front2/blind; queue = fleet note 175 sec.6(b)/8(b):
//! "kand b11/F2 render-parity cm16 sign-glyph (`+0xffc0` vs `+-0x40`)",
//! carried iter81..iter84 as the oldest open lane-F2 render item):
//! cm16/cm17 const-offset sign half renders vendor glyph.
//!
//! Vendor law (nvdisasm 13.3.73 arbitration, work/bug182/arb182*.cubin;
//! sm_103a and sm_120a identical): the LDC/LDCU const-offset window is
//! two's-complement — s16 @[38:54) for cAI/cARI (cm16 path), s17 @[37:54)
//! for LDCU (cm17 path) — and the sign half prints as
//!   plain:   c[0x0][-0x40]   /  c[0x5][-0x40] (bank composes) / [-0x8000]
//!   indexed: c[0x0][R3+-0x40] / [Rn+-0x8000]
//! never the unsigned two's-complement hex `+0xffc0`.  Positive/zero glyph
//! laws are unchanged (BUG-174 `[RZ]`, cm17 `[URZ]`, `+0x..`).
//!
//! Census-first: 0/781,603 hexdb LDC/LDCU anchors carry the sign bit
//! (work/bug182/census182.txt; consistent with note 175's 0/971,180 on the
//! family universe) => latent class, zero corpus blast radius.
//!
//! Fix = printer-only (src/printer.rs format_const_addr): sign-interpret
//! the masked offset inside its window (bit 15 of the 16-bit path, bit 16
//! for cm17).  Tables/parser/encoder untouched; the `-0x`/`+-0x` texts
//! were already accepted by the parser (line-194 normalization) and encode
//! to the pre-fix words (t182_4), so text fidelity can only improve.
//!
//! Parked-epoch note: several main-era rows still carry pre-canonical
//! windows (LDC.64 cARI sub_imm2@[32:54), LDCU '' 12-bit cm, sm120 ''
//! shr-shifted sub_imm1) — their geometric repair is parked BUG-162/163/
//! 167/172/175 territory; pin t182_5 documents decode-consistency through
//! one such row. LDCU negative render materializes once the canonical
//! cm17_off@37/22 carrier lands (arb-proven vendor words in work/bug182).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;
fn t103() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }
fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    let d = idx.decode(w, 0, t).expect("decode");
    cubit::printer::to_sass(&d).split("/* @sched").next().unwrap().trim().to_string()
}
fn w(hex: &str) -> u128 { u128::from_str_radix(hex, 16).unwrap() }

/// t182_1: sign-half anchors render vendor-exact on sm103a (plain forms;
/// surgical true-window words, nvdisasm text in work/bug182/arb182.txt).
#[test]
fn t182_1_plain_sign_half_vendor_exact_sm103() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    for (hx, want) in [
        ("000fe80000000800003ff000ff017b82", "LDC R1, c[0x0][-0x40]"),
        ("000fe8000000080000200000ff017b82", "LDC R1, c[0x0][-0x8000]"),
        ("000fe80000000800017ff000ff017b82", "LDC R1, c[0x5][-0x40]"),
    ] {
        assert_eq!(dec(&idx, w(hx), &t), want, "anchor {hx}");
    }
}

/// t182_2: positive/zero glyph laws unchanged (both tables).
#[test]
fn t182_2_positive_and_zero_invariants() {
    let t1 = t103();
    let i1 = DecodeIndex::build(&t1);
    for (hx, want) in [
        ("000fe800000008000003f000ff017b82", "LDC R1, c[0x0][0xfc0]"),
        ("000fe8000000080000001000ff017b82", "LDC R1, c[0x0][0x40]"),
        ("000fe8000000080000000000ff017b82", "LDC R1, c[0x0][RZ]"),
        ("000e220000000a0001000000ff1e7b82", "LDC.64 R30, c[0x4][RZ]"),
    ] {
        assert_eq!(dec(&i1, w(hx), &t1), want, "sm103 invariant {hx}");
    }
    let t2 = t120();
    let i2 = DecodeIndex::build(&t2);
    assert_eq!(dec(&i2, w("000ff000000008000000df00ff017b82"), &t2),
               "LDC R1, c[0x0][0x37c]", "sm120 positive anchor");
}

/// t182_3: sign-half reaches the printer vendor-exact on sm120 for the
/// 0xffc0 anchor (the 0x8000 boundary is masked by the pre-canonical
/// sm120 '' row window; parked BUG-163 territory — documented in the
/// report, not asserted here).
#[test]
fn t182_3_plain_sign_half_vendor_exact_sm120() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    assert_eq!(dec(&idx, w("000ff00000000800003ff000ff017b82"), &t),
               "LDC R1, c[0x0][-0x40]");
}

/// t182_4: encoder untouched — sign spellings still encode, byte-invariant
/// vs the pre-fix words (word from ctl-era asm of the same text).
#[test]
fn t182_4_encoder_invariance() {
    let t = t103();
    let insn = parse_sass("LDC.64 R2, c[0x0][R3+-0x40]", 0).expect("parse");
    let got = encode_instruction(&insn, &t).map(|x| x & !SCHED).expect("encode");
    // 2026-08-26 compose: the old pin word was captured against the lane's
    // ctl-era vendored table; canonical now writes the cm16 window per the
    // BUG-162 post-wave law (s16 two's-complement at [38:54) => 0xffc0).
    // The substantive invariant (-- encode unchanged by the printer-only
    // fix -- text equals the pin text) is what the pin keeps.
    let back = dec(&DecodeIndex::build(&t), got, &t);
    assert_eq!(back, "LDC.64 R2, c[0x0][R3+-0x40]");
    for text in [
        "LDC R1, c[0x0][-0x40]",
        "LDC R1, c[0x0][-0x8000]",
        "LDC R1, c[0x5][-0x40]",
        "LDCU UR4, c[0x0][-0x40]",
    ] {
        let insn = parse_sass(text, 0).expect("parse");
        assert!(encode_instruction(&insn, &t).is_ok(), "encode {text}");
    }
}

/// t182_5: decode-encode-decode text fixed-point through the pre-canonical
/// LDC.64 cARI row (junk 22-bit window reads the probe as itself; parked
/// geometry ff-162/167/172 makes the true [38:54) carrier vendor-exact).
#[test]
fn t182_5_text_fixed_point_through_legacy_row() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    let text = "LDC.64 R2, c[0x0][R3+-0x40]";
    let insn = parse_sass(text, 0).expect("parse");
    let word = encode_instruction(&insn, &t).expect("encode");
    assert_eq!(dec(&idx, word, &t), text);
}
