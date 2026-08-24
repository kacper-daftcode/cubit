//! BUG-082 (F2Q 082-kand stillwrong-class z censusu 081; fixed F2 2026-08-22):
//! the whole DSETP family in tables/sm120.json was harvest junk (28 keys).
//! Verified corpus-wide damage classes (17054 vendor anchors,
//! the internal fix archive
//!  (a) decode-FAIL: 5951 words had NO matching row (e.g. |R8|+UR form) --
//!      cubit rendered nothing; downstream RE lost the instruction;
//!  (b) 7-bit register windows: 8-bit R operands halved (R20 -> R10, R6 -> R3;
//!      UR14 -> UR7) and trailing P operand rendered as R0/UR0 phantom;
//!  (c) baked-PT rows dropped the real second predicate (..., P2, ... -> ..., PT, ...);
//!  (d) negated compare predicate lost (!P0 -> P0); |abs| on R rendered as -R;
//!  (e) baked-literal junk rows (P_P_R_L_P family) hijacked real forms and
//!      printed f32-isms for an f64 immediate (1 -> 0x0, +INF -> 0x0).
//! Fix: re-canonicalized the sm120 family to the sm103a 3-key geometry
//! (DSETP_P_P_R_FI_P / _R_P / _UR_P mod_groups), which passes
//! 17054/17054 anchors semantically (12 print-level f64 precision deltas are
//! bit-identical, see report) + 3639/3639 unique words RT-exact.
//! sm103a.json untouched (already correct).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn enc(text: &str, t: &IsaTable) -> anyhow::Result<u128> {
    let insn = parse_sass(&format!("{text} ;"), 0).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    encode_instruction(&insn, t)
}

fn dec_render(word: u128, t: &IsaTable) -> String {
    let idx = DecodeIndex::build(t);
    let d = idx.decode(word, 0, t).expect("decode");
    cubit::printer::to_sass(&d)
}

const PAYLOAD: u128 = (1u128 << 96) - 1;

// (word & [95:0], vendor text) anchors -- one per damage class + taxonomy spread
const DSETP_ANCHORS: &[(u128, &str)] = &[
    (0x3f08000000000080800722a & PAYLOAD, "DSETP.NAN.AND P0, PT, R8, R8, PT"),
    (0x4702000000000ff0400722a & PAYLOAD, "DSETP.EQ.AND P0, PT, R4, RZ, !P0"),
    (0x3f6e000000000140600722a & PAYLOAD, "DSETP.GEU.AND P3, PT, R6, R20, PT"),
    (0x3a0f000000000040200922a & PAYLOAD, "@!P1 DSETP.MAX.AND P0, P2, R2, R4, PT"),
    (0xbf042000000000608007e2a & PAYLOAD, "DSETP.GT.AND P0, PT, |R8|, UR6, PT"),
    (0x3f0d2007ff000001000742a & PAYLOAD, "DSETP.NEU.AND P0, PT, |R16|, +INF, PT"),
    (0x3f060005e3000002600742a & PAYLOAD, "DSETP.GE.AND P0, PT, R38, 4.99479768050558757021e+145, PT"),
    (0x70d400000000ff0800722a & PAYLOAD, "DSETP.NEU.OR P0, PT, R8, RZ, P0"),
];

// normalize: strip reuse/whitespace; compare float literals by bit pattern.
// Rust f64 parse accepts "+INF"; both render precisions land on same bits.
fn norm(t: &str) -> String {
    let t = t.trim().trim_end_matches(';').replace(".reuse", "");
    let mut out = String::new();
    for part in t.split(',') {
        let col = part.split_whitespace().collect::<Vec<_>>().join(" ");
        let p = col.trim();
        let mut emit = p.to_string();
        if let Some(sp) = p.rfind(' ') {
            let (head, tail) = p.split_at(sp + 1);
            if let Ok(v) = tail.parse::<f64>() {
                emit = format!("{head}0x{:016x}D", v.to_bits());
            }
        } else if let Ok(v) = p.parse::<f64>() {
            emit = format!("0x{:016x}D", v.to_bits());
        }
        out.push_str(&emit);
        out.push(',');
    }
    out.pop();
    out
}

#[test]
fn t1_decode_matches_vendor_text() {
    let t = t120();
    for (w, text) in DSETP_ANCHORS {
        let got = dec_render(*w, &t);
        assert_eq!(norm(&got), norm(text), "decode of {w:#x}");
    }
}

#[test]
fn t2_decode_encode_roundtrip_is_word_exact() {
    let t = t120();
    for (w, text) in DSETP_ANCHORS {
        let got = dec_render(*w, &t);
        let re = enc(&got, &t).unwrap_or_else(|e| panic!("encode {got:?}: {e}"));
        assert_eq!(re & PAYLOAD, w & PAYLOAD, "roundtrip {text:?}");
    }
}

#[test]
fn t3_encode_from_vendor_text_is_word_exact() {
    let t = t120();
    for (w, text) in DSETP_ANCHORS {
        let code = enc(text, &t).unwrap_or_else(|e| panic!("encode {text:?}: {e}"));
        assert_eq!(code & PAYLOAD, w & PAYLOAD, "encode {text:?}");
    }
}

#[test]
fn t4_dsetp_junk_keys_deleted() {
    let t = t120();
    for k in t.entries.keys() {
        assert!(!k.contains("DSETP") || k.starts_with("DSETP_P_P_R_"),
            "leftover junk key {k}");
    }
    for k in ["DSETP_P_P_R_L_P", "DSETP_P_P_R_II_P",
              "DSETP.NEU.OR_P_P_R_R_P_II_II_?", "DSETP.EQ.AND_P_P_R_UR_P_II_?"] {
        assert!(t.entries.get(k).is_none(), "junk key {k} still present");
    }
}

#[test]
fn t5_pred2_and_neg_and_abs_and_wide_regs_survive() {
    let t = t120();
    // second predicate must not be baked to PT
    let got = dec_render(0x3a0f000000000040200922a & PAYLOAD, &t);
    assert!(got.contains("P0, P2,"), "{got}");
    // 8-bit windows: R20 must not halve to R10
    let got = dec_render(0x3f6e000000000140600722a & PAYLOAD, &t);
    assert!(got.contains(", R6, R20,"), "{got}");
    // negated compare predicate preserved
    let got = dec_render(0x4702000000000ff0400722a & PAYLOAD, &t);
    assert!(got.contains("RZ, !P0"), "{got}");
    // |R8| must render as abs, not neg; UR6 kept
    let got = dec_render(0xbf042000000000608007e2a & PAYLOAD, &t);
    assert!(got.contains("|R8|, UR6"), "{got}");
}

#[test]
fn t6_sm120_sm103a_render_parity() {
    let a = t120();
    let b = t103();
    for (w, _text) in DSETP_ANCHORS {
        let ra = dec_render(*w, &a);
        let rb = dec_render(*w, &b);
        assert_eq!(norm(&ra), norm(&rb), "render parity {w:#x}");
    }
}
