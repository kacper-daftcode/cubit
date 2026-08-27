//! BUG-202 — explicit tok2 pred field for the 12 DSETP P-domain mgs that
//! never carried it (owner: front2/blind F2-iter97; 202-kand z noty 201
//! sec.6(b)). Data-only patch202.py (12 mgs x 3 tables sm103a/sm120/sm100a
//! = 36 rows, src ZERO).
//!
//! Pre-fix state on d95fba5 (measured this session, F2-iter97):
//!   rows carried pred fields only at tok1=(81,3) and tok5=(87,3)+neg(90,1);
//!   [84:87) was neither field nor variable_mask (and_base has PT=7 baked).
//!   ENCODE of authored tok2=Pk (!=PT): fail-closed rc=1 ("operand 2 (P2)
//!   has no field able to encode it"); DECODE of tok2!=PT words: fail-closed
//!   hole (no match, rc=1). Production-corpus exposure ZERO: 44,419/44,419
//!   census201 anchors on these rows have tok2=PT.
//! Vendor law (arb202.json: nvdisasm 13.3.73 in-place bit-walk, 120 probes /
//! 24 corpus donors, both arches): tok2 = [84:87), 3-bit P selector, 7=PT.
//! Canon == arb200/arb201 (tok1=[81:84) tok2=[84:87) tok5=[87:90) neg=b90).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn tab(p: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(p)).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

const TABS: [&str; 3] = ["tables/sm103a.json", "tables/sm120.json", "tables/sm100a.json"];

fn pname(k: u64) -> String {
    if k == 7 { "PT".to_string() } else { format!("P{k}") }
}

/// t202_1: R_R family canon sweep (AND,GEU donor, sm_103 corpus anchor):
/// tok1=[81:84) tok2=[84:87) tok5=[87:90), byte-exact roundtrips, 3 tables.
/// The tok2 column is THE newly-added field (pre-fix: fail-closed both ways).
#[test]
fn t202_1_rr_canon_sweep() {
    // DSETP.GEU.AND P2, PT, R12, |R6|, PT
    let lo: u64 = 0x400000060c00722a;
    let hi: u64 = 0x0001e40003f4e000;
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for k in 0u64..8 {
            let w = (((hi & !(0x7 << 17)) | (k << 17)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w);
            assert_eq!(text, format!("DSETP.GEU.AND {}, PT, R12, |R6|, PT", pname(k)), "{p}: tok1 k={k}");
            assert_eq!(enc(&t, &text), w & !SCHED, "{p}: tok1 roundtrip k={k}");
            let w = (((hi & !(0x7 << 20)) | (k << 20)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w);
            assert_eq!(text, format!("DSETP.GEU.AND P2, {}, R12, |R6|, PT", pname(k)), "{p}: tok2 k={k}");
            assert_eq!(enc(&t, &text), w & !SCHED, "{p}: tok2 roundtrip k={k}");
            let w = (((hi & !(0x7 << 23)) | (k << 23)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w);
            assert_eq!(text, format!("DSETP.GEU.AND P2, PT, R12, |R6|, {}", pname(k)), "{p}: tok5 k={k}");
            assert_eq!(enc(&t, &text), w & !SCHED, "{p}: tok5 roundtrip k={k}");
        }
        let wneg = (((hi | (1 << 26)) & !(0x7 << 23)) as u128) << 64 | lo as u128; // b90=1, tok5=P0
        let text = dec(&t, &idx, wneg);
        assert_eq!(text, "DSETP.GEU.AND P2, PT, R12, |R6|, !P0", "{p}: neg law");
        assert_eq!(enc(&t, &text), wneg & !SCHED, "{p}: neg roundtrip");
    }
}

/// t202_2: R_FI family canon sweep (AND,GTU donor, abs + f32 +INF imm).
#[test]
fn t202_2_rfi_canon_sweep() {
    // DSETP.GTU.AND P0, PT, |R32|, +INF , PT
    let lo: u64 = 0x7ff000002000742a;
    let hi: u64 = 0x000e240003f0c200;
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for k in 0u64..8 {
            let w = (((hi & !(0x7 << 20)) | (k << 20)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w);
            assert_eq!(text, format!("DSETP.GTU.AND P0, {}, |R32|, +INF , PT", pname(k)), "{p}: tok2 k={k}");
            assert_eq!(enc(&t, &text), w & !SCHED, "{p}: tok2 roundtrip k={k}");
            let w = (((hi & !(0x7 << 23)) | (k << 23)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w);
            assert_eq!(text, format!("DSETP.GTU.AND P0, PT, |R32|, +INF , {}", pname(k)), "{p}: tok5 k={k}");
            assert_eq!(enc(&t, &text), w & !SCHED, "{p}: tok5 roundtrip k={k}");
        }
    }
}

/// t202_3: R_UR family canon sweep (AND,GT donor, uniform-register source).
#[test]
fn t202_3_rur_canon_sweep() {
    // DSETP.GT.AND P0, PT, R10, UR4, PT
    let lo: u64 = 0x000000040a007e2a;
    let hi: u64 = 0x000e24000bf04000;
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for k in 0u64..8 {
            let w = (((hi & !(0x7 << 20)) | (k << 20)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w);
            assert_eq!(text, format!("DSETP.GT.AND P0, {}, R10, UR4, PT", pname(k)), "{p}: tok2 k={k}");
            assert_eq!(enc(&t, &text), w & !SCHED, "{p}: tok2 roundtrip k={k}");
            let w = (((hi & !(0x7 << 23)) | (k << 23)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w);
            assert_eq!(text, format!("DSETP.GT.AND P0, PT, R10, UR4, {}", pname(k)), "{p}: tok5 k={k}");
            assert_eq!(enc(&t, &text), w & !SCHED, "{p}: tok5 roundtrip k={k}");
        }
        let wneg = (((hi | (1 << 26)) & !(0x7 << 23)) as u128) << 64 | lo as u128;
        let text = dec(&t, &idx, wneg);
        assert_eq!(text, "DSETP.GT.AND P0, PT, R10, UR4, !P0", "{p}: neg law");
        assert_eq!(enc(&t, &text), wneg & !SCHED, "{p}: neg roundtrip");
    }
}

/// t202_4: authored tok2 != PT on ALL 12 scope mgs — pre-fix fail-closed
/// ("operand 2 (P2) has no field able to encode it"); post-fix must land at
/// [84:87) and re-decode verbatim. Negative tok5 forms included.
#[test]
fn t202_4_authored_tok2_all_scope_mgs() {
    let cases: [&str; 12] = [
        "DSETP.GEU.AND P0, P2, R12, R6, PT",       // R_R AND,GEU
        "DSETP.NAN.AND P1, P6, R36, R36, PT",      // R_R AND,NAN
        "DSETP.NE.AND P0, P5, R10, RZ, PT",        // R_R AND,NE
        "DSETP.GTU.AND P1, P0, R4, RZ, PT",        // R_R AND,GTU
        "DSETP.GTU.AND P0, P3, R32, 0.5, PT",      // R_FI AND,GTU
        "DSETP.NEU.AND P2, P4, R10, 1, PT",        // R_FI AND,NEU
        "DSETP.GEU.AND P0, P1, R8, 1000, PT",      // R_FI AND,GEU
        "DSETP.GE.AND P5, P2, R26, 0.5, PT",       // R_FI AND,GE
        "DSETP.GT.AND P0, P2, R10, UR4, PT",       // R_UR AND,GT
        "DSETP.GE.AND P3, P6, R2, UR6, PT",        // R_UR AND,GE
        "DSETP.GEU.AND P2, P5, R16, UR12, PT",     // R_UR AND,GEU
        "DSETP.GTU.AND P0, P4, R2, UR8, PT",       // R_UR AND,GTU
    ];
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for text in cases {
            let w = enc(&t, text);
            let want_tok2 = text.split(", ").nth(1).unwrap().trim().trim_start_matches('!');
            let k: u128 = if want_tok2 == "PT" { 7 } else { want_tok2[1..].parse::<u128>().unwrap() };
            assert_eq!((w >> 84) & 7, k, "{p}: tok2 not at [84:87): {text}");
            assert_eq!(dec(&t, &idx, w), text, "{p}: authored roundtrip {text}");
        }
        // negated tok5 on a scope row (neg field (90,1) pre-existing)
        let w = enc(&t, "DSETP.GEU.AND P0, P2, R12, R6, !P0");
        assert_eq!(dec(&t, &idx, w), "DSETP.GEU.AND P0, P2, R12, R6, !P0", "{p}: tok2+neg combo");
    }
}

/// t202_5: table tripwire — every scope row on every table now carries
/// exactly the canonical pred set {(1,81,3),(2,84,3),(5,87,3)} + neg (5,90,1),
/// variable_mask covers [84:87), and the added field carries the _src marker.
#[test]
fn t202_5_canonical_field_set_tripwire() {
    const SCOPE: [(&str, &[&str]); 3] = [
        ("DSETP_P_P_R_R_P", &["AND,GEU","AND,NAN","AND,NE","AND,GTU"]),
        ("DSETP_P_P_R_FI_P", &["AND,GTU","AND,NEU","AND,GEU","AND,GE"]),
        ("DSETP_P_P_R_UR_P", &["AND,GT","AND,GE","AND,GEU","AND,GTU"]),
    ];
    for p in TABS {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let ins = &raw["instructions"];
        for (key, mgs) in SCOPE {
            for mg in mgs {
                let g = &ins[key]["mod_groups"][mg];
                let mut preds = Vec::new();
                let mut negs = Vec::new();
                let mut marked = false;
                for f in g["fields"].as_array().unwrap() {
                    let t3 = (f["token_idx"].as_u64().unwrap(),
                              f["shift"].as_u64().unwrap(),
                              f["bits"].as_u64().unwrap());
                    match f["extraction"].as_str().unwrap_or("") {
                        "pred" => {
                            preds.push(t3);
                            if t3 == (2, 84, 3) && f["_src"].as_str() == Some("bug202-2026-08-27") {
                                marked = true;
                            }
                        }
                        "neg" => negs.push(t3),
                        _ => {}
                    }
                }
                preds.sort();
                assert_eq!(preds, vec![(1, 81, 3), (2, 84, 3), (5, 87, 3)], "{p}: {key}::{mg} pred set");
                assert_eq!(negs, vec![(5, 90, 1)], "{p}: {key}::{mg} neg set");
                assert!(marked, "{p}: {key}::{mg} missing bug202 marker");
                let vm = u128::from_str_radix(g["variable_mask"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
                assert_ne!(vm & (7 << 84), 0, "{p}: {key}::{mg} vm missing [84:87)");
            }
        }
    }
}

/// t202_6: corpus-anchor retention — all 12 sm_103 donor words (tok2=PT)
/// keep their exact glyph post-fix and re-encode byte-exact.
#[test]
fn t202_6_corpus_anchor_retention() {
    let anchors: [(u64, u64, &str); 12] = [
        (0x5e3000001a00742a, 0x000e5e0003f06000, "DSETP.GE.AND P0, PT, R26, 4.99479768050558757021e+145, PT"),
        (0x408f40000800742a, 0x008e300003f0e000, "DSETP.GEU.AND P0, PT, R8, 1000, PT"),
        (0x7ff000002000742a, 0x000e240003f0c200, "DSETP.GTU.AND P0, PT, |R32|, +INF , PT"),
        (0x7ff000000a00742a, 0x000e240003f0d200, "DSETP.NEU.AND P0, PT, |R10|, +INF , PT"),
        (0x400000060c00722a, 0x0001e40003f4e000, "DSETP.GEU.AND P2, PT, R12, |R6|, PT"),
        (0x000000ff0400722a, 0x000fe20003f2c000, "DSETP.GTU.AND P1, PT, R4, RZ, PT"),
        (0x000000242400722a, 0x000ea40003f08000, "DSETP.NAN.AND P0, PT, R36, R36, PT"),
        (0x000000ff0a00722a, 0x000e240003f05000, "DSETP.NE.AND P0, PT, R10, RZ, PT"),
        (0x0000000602007e2a, 0x000064000bf66000, "DSETP.GE.AND P3, PT, R2, UR6, PT"),
        (0x0000000c10007e2a, 0x001e24000bf4e000, "DSETP.GEU.AND P2, PT, R16, UR12, PT"),
        (0x000000040a007e2a, 0x000e24000bf04000, "DSETP.GT.AND P0, PT, R10, UR4, PT"),
        (0x0000000802007e2a, 0x002e24000bf0c000, "DSETP.GTU.AND P0, PT, R2, UR8, PT"),
    ];
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for (lo, hi, want) in anchors {
            let w = (hi as u128) << 64 | lo as u128;
            assert_eq!(dec(&t, &idx, w), want, "{p}: retention {want}");
        }
        // re-encode byte-exact for the int-imm / plain forms (f64 %.20e
        // printed form and +INF parse to the same bits, proven in t202_4);
        // the f64 anchor is decode-pinned only to stay parser-independent.
        for (lo, hi, want) in anchors.iter().filter(|(_,_,g)| !g.contains("e+145")) {
            let w = (*hi as u128) << 64 | *lo as u128;
            assert_eq!(enc(&t, want), w & !SCHED, "{p}: retention roundtrip {want}");
        }
    }
}

/// t202_7: PT-elision byte-exactness — authored forms with tok2=PT produce
/// the exact corpus word (and_base-carried window), i.e. the vendor-elided
/// spelling encodes to the identical bits the corpus ships.
#[test]
fn t202_7_pt_elision_byte_exact() {
    let cases: [(&str, u64, u64); 4] = [
        ("DSETP.GEU.AND P2, PT, R12, |R6|, PT", 0x400000060c00722a, 0x0001e40003f4e000),
        ("DSETP.GTU.AND P1, PT, R4, RZ, PT", 0x000000ff0400722a, 0x000fe20003f2c000),
        ("DSETP.GT.AND P0, PT, R10, UR4, PT", 0x000000040a007e2a, 0x000e24000bf04000),
        ("DSETP.NEU.AND P0, PT, |R10|, +INF , PT", 0x7ff000000a00742a, 0x000e240003f0d200),
    ];
    for p in TABS {
        let t = tab(p);
        for (text, lo, hi) in cases {
            assert_eq!(enc(&t, text), ((hi as u128) << 64 | lo as u128) & !SCHED, "{p}: PT-form {text}");
        }
    }
}
