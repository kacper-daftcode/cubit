//! BUG-200 — P-domain pred-window law for harvest-coincidence rows in
//! DSETP_P_P_R_R_P / DSETP_P_P_R_FI_P / DSETP_P_P_R_UR_P / IMAD_R_P_R_UR_R /
//! IMAD_R_R_UR_R_P / HSETP2_P_P_R_FI_FI_P (owner: front2/blind F2-iter96;
//! 200-kand z noty 198 sec.6). Data-only patch200.py (11/9/11 rows across
//! sm103a/sm120/sm100a).
//!
//! Defects pre-fix, all LIVE on main:
//!   DECODE: vendor-legal words with non-coincidence pred values either
//!     HOLE'd (no match) or were SILENTLY flipped to a wrong mod-group
//!     (`DSETP.LT.AND .. P3` printed as `DSETP.LT.OR`), or junk glyphs
//!     (HSETP2 neg90 donor printed "P15"). Production-corpus exposure is
//!     zero only by coincidence (hexdb 32.2M: 2,728 anchors all decode
//!     IDENT to nvdisasm — junk windows read constant-and_base values).
//!   ENCODE (silent wrong-code): authored `DSETP.EQ.OR P0, P3, .. !P0` or
//!     `HSETP2.NEU.AND P1, P2, .., P3` or `IMAD.WIDE.U32 .., P3, ..` emitted
//!     words with the pred scraped into coincidence windows — (6,4) ==
//!     OPCODE discriminator (word decodes as a DIFFERENT instruction),
//!     (12,4) == guard window, (43,4) == inside the immediate.
//! Vendor law (arb200.json: nvdisasm 13.3.73 in-place bit-walk on corpus
//! donors cusparse 727/847 + cusolver 978/1021/1026/1529/1547/1565 sm_103):
//!   DSETP/HSETP2: tok1=[81:84), tok2=[84:87), tok-last=[87:90), neg=b90;
//!   IMAD carry-out tok2=[81:84) (arb); IMAD trailing-P tok5=[87:90)
//!   (sibling rows IMAD_R_R_R_R_P / IMAD_R_R_II_R_P, zero corpus anchors).
//! (19,4) proven inert; (12,4) == guard (@P3 probe); (43,4) == imm-interior
//! (immediate moved under bit-walk); (6,4) opcode-critical (nvdisasm
//! rejects the cubin). Fix-emitted words cross-checked: nvdisasm decodes
//! them back to the authored glyph 7/7 (work/bug200/crosscheck200.py).

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

/// t200_1: DSETP R_R family (AND,LT / GE,OR / AND,NUM donors) — full
/// pred-window law: tok1=[81:84), tok2=[84:87), tok5=[87:90), neg tok5=b90;
/// decode identity + re-encode byte-exact. Pre-fix: junk (19,4) dup-window,
/// and_base-locked tok2=7 => .OR flip / HOLE.
#[test]
fn t200_1_dsetp_rr_pred_law() {
    // DSETP.LT.AND P0, PT, R8, R6, P0  (cusparse 727 sm_103)
    let lo: u64 = 0x000000060800722a;
    let hi: u64 = 0x0082e20000701000;
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for k in 0u64..8 {
            let w81 = (((hi & !(0x7 << 17)) | (k << 17)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w81);
            assert_eq!(text, format!("DSETP.LT.AND {}, PT, R8, R6, P0", pname(k)), "{p}: tok1 law k={k}");
            assert_eq!(enc(&t, &text), w81 & !SCHED, "{p}: tok1 roundtrip k={k}");
            let w84 = (((hi & !(0x7 << 20)) | (k << 20)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w84);
            assert_eq!(text, format!("DSETP.LT.AND P0, {}, R8, R6, P0", pname(k)), "{p}: tok2 law k={k}");
            assert_eq!(enc(&t, &text), w84 & !SCHED, "{p}: tok2 roundtrip k={k}");
            let w87 = (((hi & !(0x7 << 23)) | (k << 23)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w87);
            assert_eq!(text, format!("DSETP.LT.AND P0, PT, R8, R6, {}", pname(k)), "{p}: tok5 law k={k}");
            assert_eq!(enc(&t, &text), w87 & !SCHED, "{p}: tok5 roundtrip k={k}");
        }
        let wneg = (((hi | (1 << 26)) & !(0x7 << 23)) as u128) << 64 | lo as u128; // b90=1, tok5=P0
        let text = dec(&t, &idx, wneg);
        assert_eq!(text, "DSETP.LT.AND P0, PT, R8, R6, !P0", "{p}: tok5 neg law");
        assert_eq!(enc(&t, &text), wneg & !SCHED, "{p}: neg roundtrip");
    }
}

/// t200_2: DSETP FI anchor retention + tok5/tok2 law (AND,MAX / EQ,OR).
#[test]
fn t200_2_dsetp_fi_pred_law() {
    // DSETP.MAX.AND P0, P1, R14, 1, PT (cusolver 1547)
    let lo: u64 = 0x3ff000000e00742a;
    let hi: u64 = 0x000e24000390f000;
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for k in 0u64..8 {
            let w87 = (((hi & !(0x7 << 23)) | (k << 23)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w87);
            assert_eq!(text, format!("DSETP.MAX.AND P0, P1, R14, 1, {}", pname(k)), "{p}: tok5 law k={k}");
            assert_eq!(enc(&t, &text), w87 & !SCHED, "{p}: tok5 roundtrip k={k}");
        }
        // authored authored-form previously silent-wrong (ctl emitted a word
        // with tok2=P3 scraped into the guard window):
        let text = "DSETP.EQ.OR P0, P3, R16, 1, !P0";
        let w = enc(&t, text);
        assert_eq!(w, 0x0000000004302400_3ff000001000742au128 & !SCHED, "{p}: EQ.OR authored byte-pin");
        assert_eq!(dec(&t, &idx, w), text, "{p}: EQ.OR authored decode");
        // corpus anchor retention (EQ,OR donor, tok5=neg P0):
        let lo2: u64 = 0x3ff000001000742a;
        let hi2: u64 = 0x002e640004702400;
        let w2 = (hi2 as u128) << 64 | lo2 as u128;
        assert_eq!(dec(&t, &idx, w2), "DSETP.EQ.OR P0, PT, R16, 1, !P0", "{p}: EQ.OR retention");
        assert_eq!(enc(&t, "DSETP.EQ.OR P0, PT, R16, 1, !P0"), w2 & !SCHED, "{p}: EQ.OR retention roundtrip");
    }
}

/// t200_3: DSETP UR family (GT,OR) tok2/tok5 law + retention.
#[test]
fn t200_3_dsetp_ur_pred_law() {
    // DSETP.GT.OR P0, PT, R30, UR12, !P0 (cusolver 1021)
    let lo: u64 = 0x0000000c1e007e2a;
    let hi: u64 = 0x004ea4000c704400;
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for k in 0u64..8 {
            let w84 = (((hi & !(0x7 << 20)) | (k << 20)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w84);
            assert_eq!(text, format!("DSETP.GT.OR P0, {}, R30, UR12, !P0", pname(k)), "{p}: tok2 law k={k}");
            assert_eq!(enc(&t, &text), w84 & !SCHED, "{p}: tok2 roundtrip k={k}");
        }
        let w0 = (hi as u128) << 64 | lo as u128;
        assert_eq!(dec(&t, &idx, w0), "DSETP.GT.OR P0, PT, R30, UR12, !P0", "{p}: retention");
    }
}

/// t200_4: HSETP2 (sm103a/sm100a only) — tok1=[81:84), tok2=[84:87),
/// tok6=[87:90), neg tok6=b90; pre-fix tok1=(6,4) + tok2/tok6 junk-dup
/// at (87,4)/(43,4) printed P15-style garbage on neg walks.
#[test]
fn t200_4_hsetp2_pred_law() {
    // HSETP2.NEU.AND P0, PT, R6.H0_H0, 1, 1, PT (cusparse 847)
    let lo: u64 = 0x3c003c0006007434;
    let hi: u64 = 0x004fda0003f0d800;
    for p in ["tables/sm103a.json", "tables/sm100a.json"] {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for k in 0u64..8 {
            let w81 = (((hi & !(0x7 << 17)) | (k << 17)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w81);
            assert_eq!(text, format!("HSETP2.NEU.AND {}, PT, R6.H0_H0, 1, 1, PT", pname(k)), "{p}: tok1 law k={k}");
            let w84 = (((hi & !(0x7 << 20)) | (k << 20)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w84);
            assert_eq!(text, format!("HSETP2.NEU.AND P0, {}, R6.H0_H0, 1, 1, PT", pname(k)), "{p}: tok2 law k={k}");
            let w87 = (((hi & !(0x7 << 23)) | (k << 23)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w87);
            assert_eq!(text, format!("HSETP2.NEU.AND P0, PT, R6.H0_H0, 1, 1, {}", pname(k)), "{p}: tok6 law k={k}");
            assert_eq!(enc(&t, &text), w87 & !SCHED, "{p}: tok6 roundtrip k={k}");
        }
        let wneg = (((hi | (1 << 26)) & !(0x7 << 23)) as u128) << 64 | lo as u128; // !PT (tok6=PT, neg)
        let wneg = wneg | ((0x7u128) << 87);
        let text = dec(&t, &idx, wneg);
        assert_eq!(text, "HSETP2.NEU.AND P0, PT, R6.H0_H0, 1, 1, !PT", "{p}: tok6 neg law");
        assert_eq!(enc(&t, &text), wneg & !SCHED, "{p}: neg roundtrip");
        // BF16_V2 variant retention + authored crosscheck byte-pin:
        let lor: u64 = 0x3f803f8006007434;
        let hir: u64 = 0x004fda0003f0d802;
        let wr = (hir as u128) << 64 | lor as u128;
        assert_eq!(dec(&t, &idx, wr), "HSETP2.BF16_V2.NEU.AND P0, PT, R6.H0_H0, 1, 1, PT", "{p}: BF16 retention");
    }
}

/// t200_5: IMAD carry-out pred law. tok2=[81:84) (arb) on R_P forms;
/// IMAD_R_R_UR_R_P trailing-P tok5=[87:90) (sibling law, zero corpus
/// anchors). Pre-fix: ENCODE scraped the pred into the opcode nibble
/// (6,4) — silent wrong-code (word decodes as another instruction).
#[test]
fn t200_5_imad_carryout_pred_law() {
    // IMAD.WIDE.U32 R10, P0, R3, UR7, R10 (cutlass 74 smoke)
    let lo: u64 = 0x00000007030a7c25;
    let hi: u64 = 0x000fe2000f80000a;
    // IMAD.HI.U32 R8, P0, R6, UR11, R8 (cusolver 1026)
    let lo2: u64 = 0x0000000b06087c27;
    let hi2: u64 = 0x000fc8000f800008;
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for k in 0u64..8 {
            let w81 = (((hi & !(0x7 << 17)) | (k << 17)) as u128) << 64 | lo as u128;
            let text = dec(&t, &idx, w81);
            // PT-elision for the IMAD carry-out token is vendor law
            // (arb200b: (81:84)=7 -> nvdisasm prints the 4-operand form);
            // it decodes there via the no-P sibling row; both spellings
            // re-encode to the identical word.
            let want_wide = if k == 7 {
                "IMAD.WIDE.U32 R10, R3, UR7, R10".to_string()
            } else {
                format!("IMAD.WIDE.U32 R10, {}, R3, UR7, R10", pname(k))
            };
            assert_eq!(text, want_wide, "{p}: WIDE tok2 law k={k}");
            assert_eq!(enc(&t, &text), w81 & !SCHED, "{p}: WIDE tok2 roundtrip k={k}");
            assert_eq!(
                enc(&t, &format!("IMAD.WIDE.U32 R10, {}, R3, UR7, R10", pname(k))),
                w81 & !SCHED,
                "{p}: WIDE explicit-PT spelling encodes identically k={k}"
            );
            let w81b = (((hi2 & !(0x7 << 17)) | (k << 17)) as u128) << 64 | lo2 as u128;
            let text = dec(&t, &idx, w81b);
            let want_hi = if k == 7 {
                "IMAD.HI.U32 R8, R6, UR11, R8".to_string()
            } else {
                format!("IMAD.HI.U32 R8, {}, R6, UR11, R8", pname(k))
            };
            assert_eq!(text, want_hi, "{p}: HI tok2 law k={k}");
            if p.ends_with("sm120.json") {
                // BUG-002 red-line: IMAD.HI encode is refuse-by-errata on
                // sm120 (silicon re-executes it as IMAD.WIDE low-half) —
                // decode-side parity only, encode must stay refused.
                let insn = parse_sass(&text, 0).unwrap();
                assert!(encode_instruction(&insn, &t).is_err(), "{p}: sm120 IMAD.HI encode must refuse k={k}");
            } else {
                assert_eq!(enc(&t, &text), w81b & !SCHED, "{p}: HI tok2 roundtrip k={k}");
            }
        }
        // trailing-P sibling form (U32,WIDE,X): authored asm + decode law.
        let text = "IMAD.WIDE.U32.X R10, R3, UR7, R10, P3";
        let w = enc(&t, text);
        assert_eq!(dec(&t, &idx, w), text, "{p}: R_R_UR_R_P authored law");
        // sweep the trailing pred window on that authored word:
        for k in 0u64..8 {
            let wk = (w & !(0x7u128 << 87)) | (k as u128) << 87;
            let want = format!("IMAD.WIDE.U32.X R10, R3, UR7, R10, {}", pname(k));
            assert_eq!(dec(&t, &idx, wk), want, "{p}: trailing-P law k={k}");
            assert_eq!(enc(&t, &want), wk & !SCHED, "{p}: trailing-P roundtrip k={k}");
        }
    }
}

/// t200_6: tripwire — no pred/neg field may sit on a coincidence window in
/// the kand rows anymore ((6,4)/(19,4)/(12,4)/(43,4)/(87,4)); canonical
/// windows only ((81,3)/(84,3)/(87,3) + neg@90).
#[test]
fn t200_6_no_coincidence_windows_in_kand_rows() {
    const JUNK: [(u8, u8); 5] = [(6, 4), (19, 4), (12, 4), (43, 4), (87, 4)];
    const KAND: [(&str, &[&str]); 6] = [
        ("DSETP_P_P_R_R_P", &["AND,LT", "GE,OR", "AND,NUM"]),
        ("DSETP_P_P_R_FI_P", &["AND,MAX", "EQ,OR"]),
        ("DSETP_P_P_R_UR_P", &["GT,OR"]),
        ("IMAD_R_P_R_UR_R", &["U32,WIDE", "HI,U32"]),
        ("IMAD_R_R_UR_R_P", &["U32,WIDE,X"]),
        ("HSETP2_P_P_R_FI_FI_P", &["AND,NEU", "AND,BF16_V2,NEU"]),
    ];
    for p in TABS {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let ins = &raw["instructions"];
        for (key, mgs) in KAND {
            for mg in mgs {
                let Some(g) = ins.get(key).and_then(|k| k["mod_groups"].get(*mg)) else {
                    continue; // HSETP2 absent on sm120
                };
                for f in g["fields"].as_array().unwrap() {
                    let s = f["shift"].as_u64().unwrap() as u8;
                    let b = f["bits"].as_u64().unwrap() as u8;
                    let e = f["extraction"].as_str().unwrap_or("");
                    if e == "pred" || e == "neg" {
                        assert!(!JUNK.contains(&(s, b)), "{p}: {key}::{mg} still has {e}@({s},{b})");
                    }
                }
            }
        }
    }
}

/// t200_7: corpus-anchor retention — every pre-fix coincidence anchor keeps
/// its vendor glyph byte-exact (the 8 arbitration donors).
#[test]
fn t200_7_corpus_anchor_retention() {
    let anchors: [(u64, u64, &str); 8] = [
        (0x000000060800722a, 0x0082e20000701000, "DSETP.LT.AND P0, PT, R8, R6, P0"),
        (0x4000000a0800722a, 0x004e240004707200, "DSETP.NUM.AND P0, PT, |R8|, |R10|, !P0"),
        (0x000000040e00722a, 0x002e640000706400, "DSETP.GE.OR P0, PT, R14, R4, P0"),
        (0x3ff000000e00742a, 0x000e24000390f000, "DSETP.MAX.AND P0, P1, R14, 1, PT"),
        (0x3ff000001000742a, 0x002e640004702400, "DSETP.EQ.OR P0, PT, R16, 1, !P0"),
        (0x0000000c1e007e2a, 0x004ea4000c704400, "DSETP.GT.OR P0, PT, R30, UR12, !P0"),
        (0x0000000b06087c27, 0x000fc8000f800008, "IMAD.HI.U32 R8, P0, R6, UR11, R8"),
        (0x00000007030a7c25, 0x000fe2000f80000a, "IMAD.WIDE.U32 R10, P0, R3, UR7, R10"),
    ];
    for p in ["tables/sm103a.json", "tables/sm100a.json"] {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for (lo, hi, want) in anchors {
            let w = (hi as u128) << 64 | lo as u128;
            assert_eq!(dec(&t, &idx, w), want, "{p}: retention {want}");
        }
    }
}
