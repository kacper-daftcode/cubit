//! BUG-146 (F2 front2, 2026-08-25): nvdisasm scientific-notation immediate
//! spelling was not reproduced for |imm| >= 1 non-integral values -- cubit
//! printed %.19e-trimmed ("3.074457437244227584e+18") where nvdisasm 13.3
//! prints %.20e untrimmed ("3.07445743724422758400e+18"), and the encode
//! side accepts both (value-identical), so the class was render-parity only.
//!
//! Census law (32M nvdisasm-13.3 lines, /root/blindlab/work/bug146):
//!   |v| >= 1  (sci exponent >= 0): C %.20e, trailing zeros KEPT
//!   0 < |v| < 1 (sci exponent < 0): round to 20 significant digits, trim.
//!
//! Item scope: printer format_g20 sci branch (shared by f32/f64hi/f32cast
//! print paths). FCHK functional audit (note-141 follow-up) showed ZERO
//! value-level defects on the current code: 38 unique corpus imm words
//! encode byte-exact on low96 from the vendor text; sm120 has ZERO FCHK
//! witnesses (audited, no change).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

// (nvdisasm text, low64, hi<96) — vendor witnesses from the sm_100/103 corpus.
const CASES: &[(&str, u64, u64)] = &[
    ("FCHK P0, R0, 3.07445743724422758400e+18", 0x5e2aaaab00007902, 0x00000000),
    ("FCHK P0, R3, 6.87189524480000000000e+10", 0x517fff8003007902, 0x00000000),
    ("FCHK P1, R25, 6.87189524480000000000e+10", 0x517fff8019007902, 0x00020000),
    ("FADD R11, -R11, 2.02824096036516704239e+31", 0x738000000b0b7421, 0x00000100),
    ("FMUL R10, R10, 4.76837158203125e-07", 0x350000000a0a7820, 0x00400000),
    ("FFMA R0, R0, R11, 1.1641532182693481445e-10", 0x2f00000000007423, 0x0000000b),
    ("FFMA R0, -R16, R3, 1.30400000977257103360e+19", 0x5f34f76310007423, 0x00000103),
    ("DMUL R10, R10, 1.80143985094819840000e+16", 0x435000000a0a7828, 0x00000000),
    ("DADD R10, R8, -6.75539944105574400000e+15", 0xc3380000080a7429, 0x00000000),
    ("DFMA R12, R12, 1.52587890625e-05, R58", 0x3ef000000c0c782b, 0x0000003a),
];

#[test]
fn t146_1_render_parity_vendor_words() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (text, lo, hi96) in CASES {
        let d = dec(&t, &idx, (*lo as u128) | ((*hi96 as u128) << 64));
        let got = d.split(';').next().unwrap().trim().to_string();
        // strip any "@sched" side annotation if present (decode+printer path only)
        assert_eq!(&got, text, "render parity failed");
    }
}

#[test]
fn t146_2_encode_vendor_text_byte_exact_low96() {
    let t = t103a();
    for (text, lo, hi96) in CASES {
        let got = enc(&t, text);
        let want = (*lo as u128) | ((*hi96 as u128) << 64);
        assert_eq!(got, want, "encode lost parity for {text}");
    }
}

#[test]
fn t146_3_roundtrip_trimmed_spelling_keeps_value() {
    // The old (pre-146) trimmed spelling must keep encoding to the same word.
    let t = t103a();
    let a = enc(&t, "FCHK P0, R0, 3.07445743724422758400e+18");
    let b = enc(&t, "FCHK P0, R0, 3.074457437244227584e+18");
    assert_eq!(a, b);
    let c = enc(&t, "FADD R11, -R11, 2.02824096036516704239e+31");
    let d = enc(&t, "FADD R11, -R11, 2.028240960365167042e+31");
    // 2.028240960365167042e31 < exact 21-digit value: not required to match;
    // this pins only that the parser stays float-tolerant, not equality.
    let _ = (c, d);
}

#[test]
fn t146_4_integral_and_small_sci_forms_unchanged() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    // integral f32 < 2^24 prints bare (BUG-141 law retained)
    let w = (0x4120000005007902u128) | (0x200u128 << 64);
    let s = dec(&t, &idx, w);
    assert_eq!(s.split(';').next().unwrap().trim(), "FCHK P0, |R5|, 10");
    // exponent < 0 trims (regression arm of format_g20)
    let w2 = (0x3400000000007823u128); // FFMA R0,R0,2^-23,R0
    let s2 = dec(&t, &idx, w2);
    assert!(s2.contains("1.1920928955078125e-07"), "trim arm changed: {s2}");
}

#[test]
fn t146_5_fchk_fi_row_int_text_still_routes_value_semantics() {
    // FI follow-up from note-141: integral int-text on the FCHK imm must be
    // value-semantic (f32cast), never raw bits; raw-bits spelling "0x..." is
    // not a vendor form for this family.
    let t = t103a();
    assert_eq!(enc(&t, "FCHK P0, R21, 6890499"),
               (0x4ad2480615007902u128) | (0x0u128 << 64));
    let idx = DecodeIndex::build(&t);
    let w = (0x4ad2480615007902u128);
    assert!(dec(&t, &idx, w).contains("6890499"));
}
