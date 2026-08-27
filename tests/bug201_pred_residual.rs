//! BUG-201 — residual non-canon pred windows in DSETP P-domain rows
//! (owner: loop5/blind iter95; 201-kand z noty 200 sec.6). Data-only
//! patch201.py (30 mgs x 3 tables sm103a/sm120/sm100a, src ZERO).
//!
//! Defects pre-fix (all OOD-LIVE, production-corpus exposure ZERO by
//! coincidence — hexdb-derived census: 7,638 defective-row anchors decode
//! IDENT to nvdisasm under ctl d95fba5):
//!   junk pred windows (12,4)==guard slot (@P probe), (15,4)==guard-neg,
//!   (25,1)/(37,4)==REGISTER interior (bit-walk moves Ra/Rb glyphs),
//!   (59,4)/(60,4)==immediate interior, (9,3)/(4,4)/(5,4)==opcode-critical
//!   (nvdisasm rejects the cubin), (16,4)==inert, (87,4)==canon+neg too-wide
//!   (P14/P15 junk), plus duplicate pred fields per token.
//!   ENCODE: authored `DSETP.<mod> Pd, Pk, ..` with tok2/tok5 non-PT either
//!   got scraped into the above windows (wrong code / foreign glyph) or
//!   fail-closed on rows with no surviving field.
//! Vendor law (arb201/arb201.json: nvdisasm 13.3.73 in-place bit-walk, 164
//! probes / 31 corpus donors): DSETP tok1=[81:84) tok2=[84:87) tok5=[87:90)
//! neg tok5=b90 — identical law on every defective mg (== arb200 canon).

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

/// t201_1: R_R (12,4)-guard-coincidence class (AND,GE donor) full law sweep:
/// tok1=[81:84) tok2=[84:87) tok5=[87:90), neg=b90; byte-exact roundtrips.
#[test]
fn t201_1_rr_guard_class_law() {
    // DSETP.GE.AND P0, PT, R4, RZ, PT (census donor, sm_103 cusolver)
    let lo: u64 = 0x000000ff0400722a;
    let hi: u64 = 0x000fde0003f06000;
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for k in 0u64..8 {
            let w81 = (((hi & !(0x7 << 17)) | (k << 17)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w81);
            assert_eq!(text, format!("DSETP.GE.AND {}, PT, R4, RZ, PT", pname(k)), "{p}: tok1 k={k}");
            assert_eq!(enc(&t, &text), w81 & !SCHED, "{p}: tok1 roundtrip k={k}");
            let w84 = (((hi & !(0x7 << 20)) | (k << 20)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w84);
            assert_eq!(text, format!("DSETP.GE.AND P0, {}, R4, RZ, PT", pname(k)), "{p}: tok2 k={k}");
            assert_eq!(enc(&t, &text), w84 & !SCHED, "{p}: tok2 roundtrip k={k}");
            let w87 = (((hi & !(0x7 << 23)) | (k << 23)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w87);
            assert_eq!(text, format!("DSETP.GE.AND P0, PT, R4, RZ, {}", pname(k)), "{p}: tok5 k={k}");
            assert_eq!(enc(&t, &text), w87 & !SCHED, "{p}: tok5 roundtrip k={k}");
        }
        let wneg = (((hi | (1 << 26)) & !(0x7 << 23)) as u128) << 64 | lo as u128; // b90=1, tok5=P0
        let text = dec(&t, &idx, wneg);
        assert_eq!(text, "DSETP.GE.AND P0, PT, R4, RZ, !P0", "{p}: neg law");
        assert_eq!(enc(&t, &text), wneg & !SCHED, "{p}: neg roundtrip");
    }
}

/// t201_2: UR (9,3)-dup opcode-adjacent class (AND,LT donor) law sweep: tok2
/// and tok5 were duplicated on opcode-critical (9,3) (nvdisasm REJECTS words
/// with junk there); canon windows only post-fix.
#[test]
fn t201_2_ur_93dup_class_law() {
    // DSETP.LT.AND P0, PT, R44, UR8, PT (census donor)
    let lo: u64 = 0x000000082c007e2a;
    let hi: u64 = 0x000e24000bf01000;
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for k in 0u64..8 {
            let w84 = (((hi & !(0x7 << 20)) | (k << 20)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w84);
            assert_eq!(text, format!("DSETP.LT.AND P0, {}, R44, UR8, PT", pname(k)), "{p}: tok2 k={k}");
            assert_eq!(enc(&t, &text), w84 & !SCHED, "{p}: tok2 roundtrip k={k}");
            let w87 = (((hi & !(0x7 << 23)) | (k << 23)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w87);
            assert_eq!(text, format!("DSETP.LT.AND P0, PT, R44, UR8, {}", pname(k)), "{p}: tok5 k={k}");
            assert_eq!(enc(&t, &text), w87 & !SCHED, "{p}: tok5 roundtrip k={k}");
        }
        let wneg = (((hi | (1 << 26)) & !(0x7 << 23)) as u128) << 64 | lo as u128;
        let text = dec(&t, &idx, wneg);
        assert_eq!(text, "DSETP.LT.AND P0, PT, R44, UR8, !P0", "{p}: neg law");
        assert_eq!(enc(&t, &text), wneg & !SCHED, "{p}: neg roundtrip");
    }
}

/// t201_3: R_R GT,OR dup class ((5,4) tok1 dup + (12,4) tok2 + too-wide
/// (87,4) tok5) — new neg field added; sweep + neg roundtrip.
#[test]
fn t201_3_rr_gtor_dup_class_law() {
    // DSETP.GT.OR P1, PT, |R38|, R44, P1 (census donor)
    let lo: u64 = 0x0000002c2600722a;
    let hi: u64 = 0x000e220000f24600;
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for k in 0u64..8 {
            let w84 = (((hi & !(0x7 << 20)) | (k << 20)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w84);
            assert_eq!(text, format!("DSETP.GT.OR P1, {}, |R38|, R44, P1", pname(k)), "{p}: tok2 k={k}");
            assert_eq!(enc(&t, &text), w84 & !SCHED, "{p}: tok2 roundtrip k={k}");
            let w87 = (((hi & !(0x7 << 23)) | (k << 23)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w87);
            assert_eq!(text, format!("DSETP.GT.OR P1, PT, |R38|, R44, {}", pname(k)), "{p}: tok5 k={k}");
            assert_eq!(enc(&t, &text), w87 & !SCHED, "{p}: tok5 roundtrip k={k}");
        }
        let wneg = ((hi | (1 << 26)) as u128) << 64 | lo as u128; // b90=1, tok5 stays P1
        let text = dec(&t, &idx, wneg);
        assert_eq!(text, "DSETP.GT.OR P1, PT, |R38|, R44, !P1", "{p}: neg law (field added)");
        assert_eq!(enc(&t, &text), wneg & !SCHED, "{p}: neg roundtrip");
    }
}

/// t201_4: neg field newly present on rows that lacked it (17 mgs): authored
/// negated last-pred roundtrips across the three families.
#[test]
fn t201_4_neg_added_roundtrips() {
    let cases: [&str; 6] = [
        "DSETP.NAN.OR P0, PT, R8, R8, !P0",          // R_R NAN,OR
        "DSETP.GT.OR P1, PT, |R38|, R44, !P1",       // R_R GT,OR
        "DSETP.GTU.OR P2, PT, R6, R8, !P2",          // R_R GTU,OR
        "DSETP.NE.AND P5, PT, |R20|, +INF , !P5",    // FI AND,NE
        "DSETP.MAX.AND P0, P1, |R8|, |UR6|, !P1",    // UR AND,MAX
        "DSETP.LT.AND P0, PT, R44, UR8, !P0",        // UR AND,LT
    ];
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for text in cases {
            let w = enc(&t, text);
            assert!(w >> 90 & 1 == 1, "{p}: neg bit set: {text}");
            assert_eq!(dec(&t, &idx, w), text, "{p}: neg authored roundtrip");
        }
    }
}

/// t201_5: silent-wrong-code encode regression — authored tok2 != PT must
/// land at [84:87) and decode back verbatim on every family (pre-fix these
/// were scraped into guard/opcode/reg/imm coincidence windows).
#[test]
fn t201_5_authored_tok2_encode() {
    let cases: [(&str, &str); 6] = [
        ("DSETP.GE.AND P0, P2, R4, RZ, P1", "DSETP.GE.AND P0, P2, R4, RZ, P1"),
        ("DSETP.LT.AND P1, P3, R44, UR8, P2", "DSETP.LT.AND P1, P3, R44, UR8, P2"),
        ("DSETP.MAX.AND P0, P2, |R8|, |UR6|, P3", "DSETP.MAX.AND P0, P2, |R8|, |UR6|, P3"),
        ("DSETP.NE.AND P2, P3, |R12|, 1, P5", "DSETP.NE.AND P2, P3, |R12|, 1, P5"),
        ("DSETP.EQ.OR P1, P2, RZ, UR4, !P0", "DSETP.EQ.OR P1, P2, RZ, UR4, !P0"),
        ("DSETP.GT.XOR P0, P3, R2, RZ, P4", "DSETP.GT.XOR P0, P3, R2, RZ, P4"),
    ];
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for (text, want) in cases {
            let w = enc(&t, text);
            assert_eq!(dec(&t, &idx, w), want, "{p}: authored {text}");
            assert_eq!(enc(&t, want), w & !SCHED, "{p}: idempotent {text}");
        }
    }
}

/// t201_6: tripwire — no pred/neg field outside the canonical window set
/// {(81,3),(84,3),(87,3),(90,1)} on all 30 scope rows; max one pred field
/// per token; neg single at (90,1).
#[test]
fn t201_6_no_residual_windows() {
    const CANON: [(u8, u8); 4] = [(81, 3), (84, 3), (87, 3), (90, 1)];
    const SCOPE: [(&str, &[&str]); 3] = [
        ("DSETP_P_P_R_R_P", &["AND,GE","AND,LEU","EQ,OR","GEU,XOR","GT,OR","GT,XOR","GTU,OR","LE,OR","LEU,OR","LTU,OR","NAN,OR"]),
        ("DSETP_P_P_R_FI_P", &["AND,EQ","AND,GT","AND,LE","AND,LT","AND,NE","LE,OR","LEU,OR","NEU,OR"]),
        ("DSETP_P_P_R_UR_P", &["AND,EQ","AND,LE","AND,LT","AND,MAX","AND,MIN","AND,NE","AND,NEU","EQ,OR","LEU,OR","LTU,OR","NEU,OR"]),
    ];
    for p in TABS {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let ins = &raw["instructions"];
        for (key, mgs) in SCOPE {
            for mg in mgs {
                let g = &ins[key]["mod_groups"][mg];
                let mut pred_toks = std::collections::BTreeSet::new();
                let mut neg_n = 0;
                for f in g["fields"].as_array().unwrap() {
                    let s = f["shift"].as_u64().unwrap() as u8;
                    let b = f["bits"].as_u64().unwrap() as u8;
                    let e = f["extraction"].as_str().unwrap_or("");
                    if e == "pred" {
                        assert!(CANON.contains(&(s, b)), "{p}: {key}::{mg} pred@({s},{b}) residual");
                        assert!(pred_toks.insert(f["token_idx"].as_u64().unwrap()), "{p}: {key}::{mg} dup tok");
                    }
                    if e == "neg" {
                        neg_n += 1;
                        assert!(CANON.contains(&(s, b)), "{p}: {key}::{mg} neg@({s},{b}) residual");
                    }
                }
                assert_eq!(pred_toks.len(), 3, "{p}: {key}::{mg} needs 3 pred slots");
                assert_eq!(neg_n, 1, "{p}: {key}::{mg} needs exactly 1 neg field");
            }
        }
    }
}

/// t201_7: corpus-anchor retention — defective-row donor words keep their
/// vendor glyph byte-exact post-fix (incl. !P forms and the (25,1)
/// reg-overlap case: LTU.OR's coincidence bit sat inside Ra).
#[test]
fn t201_7_corpus_anchor_retention() {
    let anchors: [(u64, u64, &str); 10] = [
        (0x000000ff0400722a, 0x000fde0003f06000, "DSETP.GE.AND P0, PT, R4, RZ, PT"),
        (0x0000002c2600722a, 0x000e220000f24600, "DSETP.GT.OR P1, PT, |R38|, R44, P1"),
        (0x000000ff0200722a, 0x000ea80002704800, "DSETP.GT.XOR P0, PT, R2, RZ, P4"),
        (0x4000000e1a00722a, 0x020e640000f29400, "DSETP.LTU.OR P1, PT, R26, |R14|, P1"),
        (0x000000080800722a, 0x001e240000708400, "DSETP.NAN.OR P0, PT, R8, R8, P0"),
        (0x0000001c1e00722a, 0x001e240004f23600, "DSETP.LE.OR P1, PT, |R30|, R28, !P1"),
        (0x4000000608007e2a, 0x000e22000b90f200, "DSETP.MAX.AND P0, P1, |R8|, |UR6|, PT"),
        (0x00000006ff007e2a, 0x001e24000bf05000, "DSETP.NE.AND P0, PT, RZ, UR6, PT"),
        (0x7ff000001400742a, 0x000e240003fa5200, "DSETP.NE.AND P5, PT, |R20|, +INF , PT"),
        (0x00000004ff007e2a, 0x000e620008722400, "DSETP.EQ.OR P1, PT, RZ, UR4, P0"),
    ];
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for (lo, hi, want) in anchors {
            let w = (hi as u128) << 64 | lo as u128;
            assert_eq!(dec(&t, &idx, w), want, "{p}: retention {want}");
            assert_eq!(enc(&t, want), w & !SCHED, "{p}: retention roundtrip {want}");
        }
    }
}
