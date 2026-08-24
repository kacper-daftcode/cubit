//! BUG-081 (F2Q 071-inventory; fixed F2 2026-08-22): harvest-artifact table
//! rows in three decoder families (tables/sm120.json) silently corrupted
//! SASS text renders (and any re-encode downstream):
//!
//!  (a) FSETP with f32-literal compare (P_P_R_L_P / P_P_L_II_P / P_P_L_R_P
//!      junk keys baked specific immediates like 1.0f/+INF into and_base and
//!      carried shifted token arities; real words hijacked by wrong-key rows
//!      rendering WRONG compare-op (NEU->GTU) or dropping the literal to 0x0.
//!      All three junk keys deleted; canonical key FSETP_P_P_R_FI_P rebuilt
//!      from 7905 vendor anchors (14 mod rows incl OR-buckets).
//!  (b) LEA P-forms: LEA_R_P_R_II_II fields were token-shifted (pred printed
//!      as PT, both immediates dropped to 0x0); rebuilt from 69 anchors.
//!      LEA.HI 6-token forms did not decode at all -> new keys
//!      LEA_R_P_R_R_R_II / LEA_R_P_R_UR_R_II (668+2 anchors).
//!      LEA_R_P_R_R_II lost the tok3 negation bit72 (-Rn -> !Pn predicate
//!      inversion!); field added from 99 negated anchors.
//!  (c) UIMAD.WIDE: UP-carrying shapes (UR UP UR imm UR / .X trailing UP)
//!      were decode-FAIL/covered by a token-shifted phantom row -> new keys
//!      UIMAD_UR_UP_UR_II_UR + UIMAD_UR_UR_II_UR_UP (274+274 anchors);
//!      UR_UR_UR_UR / UR_UR_II_UR rows rebuilt (28866 anchors) replacing
//!      modes that rendered phantom trailing URZ / spurious |abs|.
//!
//! Evidence harness: the internal research tree (gen/ collector,
//! per-shape anchor files; verdicts: family parity pre 32733 -> post 33551+
//! then full-fix 35877/35877 unique words, harvest census attribution).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
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

// (word & [95:0], vendor text) anchors per fixed family
const FSETP_ANCHORS: &[(u128, &str)] = &[
    (0x3f9d2007f8000000400780b & PAYLOAD, "FSETP.NEU.FTZ.AND P4, PT, |R4|, +INF, PT"),
    (0x3f1c2007f8000000400780b & PAYLOAD, "FSETP.GTU.FTZ.AND P0, PT, |R4|, +INF, PT"),
    (0x3f04200001000000000780b & PAYLOAD, "FSETP.GT.AND P0, PT, |R0|, 1.469367938527859385e-39, PT"),
    (0x03f1d0003f8000004400780b & PAYLOAD, "FSETP.NEU.FTZ.AND P0, PT, R68, 1, PT"),
];
const LEA_ANCHORS: &[(u128, &str)] = &[
    (0x078210ff00000040190c7811 & PAYLOAD, "LEA R12, P1, R25, 0x40, 0x2"),
    (0x078108ff0000000405047211 & PAYLOAD, "LEA.HI R4, P0, R5, R4, RZ, 0x1"),
    (0x078219ff0000002b022b7211 & PAYLOAD, "LEA R43, P1, -R2, R43, 0x3"),
    (0x0f83c0ff0000001a001d7c11 & PAYLOAD, "LEA.HI R29, P1, R0, UR26, RZ, 0x18"),
];
const UIMAD_ANCHORS: &[(u128, &str)] = &[
    (0x0f820004555555550b0478a5 & PAYLOAD, "UIMAD.WIDE.U32 UR4, UP1, UR11, 0x55555555, UR4"),
    (0x088e040a55555555160478a5 & PAYLOAD, "UIMAD.WIDE.U32.X UR4, UR22, 0x55555555, UR10, UP1"),
    (0x0f8e00ff00000004480472a5 & PAYLOAD, "UIMAD.WIDE.U32 UR4, UR72, UR4, URZ"),
    (0x0f8e020c00000008040478a5 & PAYLOAD, "UIMAD.WIDE UR4, UR4, 0x8, UR12"),
];

fn norm(t: &str) -> String {
    // normalize float-literal formatting to f32-hex for exact compare
    let t = t.trim().trim_end_matches(';').replace(".reuse", "");
    let mut out = String::new();
    for (i, part) in t.split(',').enumerate() {
        let mut p = part.trim().to_string();
        if let Some(sp) = p.rfind(' ') {
            let (head, tail) = p.split_at(sp + 1);
            if let Ok(v) = tail.parse::<f64>() {
                let b = (v as f32).to_bits();
                p = format!("{head}0x{b:08x}F");
            }
        } else if i > 0 {
            if let Ok(v) = p.parse::<f64>() {
                let b = (v as f32).to_bits();
                p = format!("0x{b:08x}F");
            }
        }
        out.push_str(&p);
        out.push(',');
    }
    out.pop();
    // vendor spacing artifact: "+INF " vs "+INF"
    out.replace(", ", ",")
}

#[test]
fn t1_decode_matches_vendor_text() {
    let t = t120();
    for (name, anchors) in [("FSETP", FSETP_ANCHORS), ("LEA", LEA_ANCHORS), ("UIMAD", UIMAD_ANCHORS)] {
        for (w, text) in anchors {
            let got = dec_render(*w, &t);
            assert_eq!(norm(&got), norm(text), "{name} decode of {w:#x}");
        }
    }
}

#[test]
fn t2_decode_encode_roundtrip_is_word_exact() {
    let t = t120();
    for anchors in [FSETP_ANCHORS, LEA_ANCHORS, UIMAD_ANCHORS] {
        for (w, text) in anchors {
            let got = dec_render(*w, &t);
            let re = enc(&got, &t).unwrap_or_else(|e| panic!("encode {got:?}: {e}"));
            assert_eq!(re & PAYLOAD, w & PAYLOAD, "roundtrip {text:?}");
        }
    }
}

#[test]
fn t3_encode_from_vendor_text_is_word_exact() {
    let t = t120();
    for anchors in [FSETP_ANCHORS, LEA_ANCHORS, UIMAD_ANCHORS] {
        for (w, text) in anchors {
            let code = enc(text, &t).unwrap_or_else(|e| panic!("encode {text:?}: {e}"));
            assert_eq!(code & PAYLOAD, w & PAYLOAD, "encode {text:?}");
        }
    }
}

// (b2) regression pin for the negation staging: LEA -R2 must not invert the predicate
#[test]
fn t4_lea_neg_goes_to_src_not_predicate() {
    let t = t120();
    let code = enc("LEA R43, P1, -R2, R43, 0x3", &t).unwrap();
    assert_eq!((code >> 72) & 1, 1, "neg bit72 on tok3");
    let got = dec_render(code & PAYLOAD, &t);
    assert_eq!(norm(&got), norm("LEA R43, P1, -R2, R43, 0x3"));
    assert!(!got.contains("!P1"), "predicate must not flip: {got}");
}

// (a2) deleted junk decode-keys must not come back
#[test]
fn t5_fsetp_junk_keys_deleted() {
    let t = t120();
    for k in ["FSETP_P_P_R_L_P", "FSETP_P_P_L_II_P", "FSETP_P_P_L_R_P"] {
        assert!(t.entries.get(k).is_none(), "junk key {k}");
    }
    // and compare-op must not be hijacked for literal compares
    let code = enc("FSETP.NEU.AND P0, PT, R68, 1, PT", &t).unwrap();
    let got = dec_render(code & PAYLOAD, &t);
    assert!(got.starts_with("FSETP.NEU.AND"), "{got}");
}

// (c2) phantom 5-UR key UIMAD_UR_UR_UR_UR_UR must not steal plain 4-token WIDE
#[test]
fn t6_uimad_wide_has_no_trailing_phantom_urz() {
    let t = t120();
    let code = enc("UIMAD.WIDE.U32 UR4, UR72, UR4, URZ", &t).unwrap();
    let got = dec_render(code & PAYLOAD, &t);
    assert_eq!(norm(&got), norm("UIMAD.WIDE.U32 UR4, UR72, UR4, URZ"));
    assert!(!got.ends_with("URZ, URZ"), "{got}");
}
