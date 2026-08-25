//! BUG-159 (front-main, iter74): MUFU.RSQ II-form rows carry the immediate
//! as a constant baked into and_base (no field). The printer's field-less
//! fallback emitted "0x0", so every corpus line `MUFU.RSQ Rn, -QNAN`
//! (1,235 vendor anchors; sole constant 0xFFC00000 over the full corpus,
//! archs sm_100/sm_103) round-tripped as `MUFU.RSQ Rn, 0x0` — losing
//! nvdisasm parity and breaking encode ("0x0" fail-closes via the BUG-071
//! default-payload guard).
//!
//! Fix (printer-only, scoped arm in format_imm_or_reg): for field-less
//! MUFU II operands print the baked constant from raw bits [32:64) as the
//! f32 literal with the sign folded in ("-QNAN"). Decode matching is
//! unchanged (row still locks the window); encode of arbitrary immediates
//! stays fail-closed by design.
//!
//! Evidence: /root/blindlab/work/i74/mufu_rsq_anchors.tsv (hexdb,
//! nvdisasm-13.3, 13,671 MUFU.RSQ* anchors; imm-form always -QNAN ==
//! 0xFFC00000; guards never co-occur).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

// (nvdisasm text, low64, hi64[0:32)) — vendor anchors (hexdb, sm_100+sm_103).
const RSQ_QNAN: &[(&str, u64, u32)] = &[
    ("MUFU.RSQ R0, -QNAN",  0xffc0000000007908, 0x00001400),
    ("MUFU.RSQ R2, -QNAN",  0xffc0000000027908, 0x00001400),
    ("MUFU.RSQ R5, -QNAN",  0xffc0000000057908, 0x00001400),
    ("MUFU.RSQ R16, -QNAN", 0xffc0000000107908, 0x00001400),
    ("MUFU.RSQ R18, -QNAN", 0xffc0000000127908, 0x00001400),
    ("MUFU.RSQ R20, -QNAN", 0xffc0000000147908, 0x00001400),
];

#[test]
fn bug159_decode_parity_qnan() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (text, lo, hi32) in RSQ_QNAN {
        let w = (*lo as u128) | ((*hi32 as u128) << 64);
        let got = dec(&t, &idx, w);
        assert_eq!(got, *text, "decode spelling == nvdisasm ({text})");
        // terminal operand: no trailing whitespace after the literal
        assert!(!got.ends_with(' '), "no trailing space: {got:?}");
        assert!(!got.contains("QNAN "), "no in-line space pad: {got:?}");
    }
}

#[test]
fn bug159_encode_byte_exact_vendor() {
    let t = t103a();
    for (text, lo, hi32) in RSQ_QNAN {
        let got = enc(&t, text);
        let want = (*lo as u128) | ((*hi32 as u128) << 64);
        assert_eq!(got, want, "encode byte-exact (low96): {text}");
    }
}

#[test]
fn bug159_fixed_point_decode_encode() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (text, lo, hi32) in RSQ_QNAN {
        let w = (*lo as u128) | ((*hi32 as u128) << 64);
        let got = dec(&t, &idx, w);
        let re = enc(&t, &got);
        assert_eq!(re, w, "word -> text -> word fixed point: {text}");
        assert_eq!(dec(&t, &idx, re), got, "text -> word -> text fixed point: {text}");
    }
}

#[test]
fn bug159_fail_closed_arbitrary_imm() {
    let t = t103a();
    // The window stays constant-locked: any immediate other than the baked
    // -QNAN remains a hard encode error (BUG-071 default-payload guard).
    for bad in ["MUFU.RSQ R0, 0x0", "MUFU.RSQ R0, 1", "MUFU.RSQ R0, 0.5",
                "MUFU.RSQ R0, 0x3f800000", "MUFU.RSQ R0, -INF"] {
        let insn = parse_sass(bad, 0).expect("parse");
        assert!(encode_instruction(&insn, &t).is_err(), "fail-closed: {bad}");
    }
}

#[test]
fn bug159_sibling_forms_unchanged() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // R,R and flag forms pinned at their vendor spellings (hexdb anchors).
    let cases: &[(&str, u64, u32)] = &[
        ("MUFU.RSQ R6, R3",     0x0000000300067308, 0x00001400),
        ("MUFU.RSQ R5, -R4",    0x8000000400057308, 0x00001400),
        ("MUFU.RSQ R10, |R22|", 0x40000016000a7308, 0x00001400),
        ("MUFU.RSQ64H R7, R5",  0x0000000500077308, 0x00001c00),
        ("MUFU.RSQ64H R11, UR5", 0x00000005000b7d08, 0x08001c00),
    ];
    for (text, lo, hi32) in cases {
        let w = (*lo as u128) | ((*hi32 as u128) << 64);
        let got = dec(&t, &idx, w);
        assert_eq!(got, *text, "sibling form parity: {text}");
        assert_eq!(enc(&t, &got), w, "sibling form roundtrip: {text}");
    }
}

#[test]
fn bug159_guarded_ii_word_not_fabricated() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // Force guard nibble [12:16)=1 on an otherwise valid -QNAN word: the
    // row locks those bits, so the word must either decode through another
    // (guard-carrying) row or yield no MUFU.RSQ-II text — never fabricate
    // "MUFU.RSQ .. -QNAN" with the guard silently dropped.
    let w = 0xffc0000000008908u128 | (0x00001400u128 << 64);
    if let Ok(d) = idx.decode(w, 0, &t) {
        let s = cubit::printer::to_sass(&d);
        assert!(s.starts_with('@'), "guard preserved in text: {s}");
    }
}
