//! BUG-258 (F2-iter132, loop5/blind front2, 2026-08-29): era 2-bit 'neg'
//! sign-window class closure on the 4 corpus-EXPOSED rows (canon 741f3a1).
//! The 2-bit 'neg' window conflates the abs-only window (value 2) into a
//! spurious '-' ghost (printer neg arm is value!=0); BUG-253 fixed one
//! DFMA '' instance, BUG-258 measured the whole class:
//!   census258:  53 sm120 + 70 sm121a 2-bit 'neg' fields (donors 0);
//!   routex258:  law251 corpus (503,493 uniq words, 2,406-cubin battery,
//!               nvdisasm 13.3.73) routes into exactly 4 rows, 1,359 words
//!               total, window values {0,1} ONLY -> the injured {2,3} class
//!               is corpus-empty (corpus-neutral graft, trap closed);
//!   arb258:     raw -b models SM120==SM121a==SM103a (DFMA), SM120==SM121a
//!               (UFADD; donor sm103a rejects UFADD - op absent):
//!               DFMA_R_R_R_R RM/RP tok2: b72=neg, b73=abs (both '-|R|');
//!               UFADD_UR_UR_UR '' tok2:  b72=neg, b73=abs;
//!               UFADD_UR_UR_UR '' tok3:  SWAPPED b74=abs, b75=neg.
//! Graft (patch258.py replayable+idempotent): sm121a DFMA_R_R_R_R RM/RP
//! tok2 + sm120/sm121a UFADD_UR_UR_UR tok2/tok3 split to neg/abs 1-bit
//! pairs; and_base/vmask unchanged (bits already variable). Corpus-zero
//! residuum (51 sm120 + 66 sm121a fields: DFMA FI RM/RP, DMMA x26, FADD/
//! FFMA/HADD2/..., I2I/I2IP, UFFMA/UFSETP) stays fail-closed = 261-kand.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text};"), 0).unwrap_or_else(|e| panic!("parse {text}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}

// law251 corpus witnesses (routex258 hosts).
const W_RM: u128 = 0xfd4000000400a0000000e0c0a722b; // DFMA.RM R10, R12, R14, R10
const W_RP: u128 = 0xfd0000000811a0000000c0a1a722b; // DFMA.RP R26, -R10, R12, R26
const W_UF: u128 = 0x2fe200080000050000000004047254; // UFADD UR4, UR4, UR5

#[test]
fn t258_1_structure() {
    // sm121a DFMA_R_R_R_R RM + RP: tok2 -> neg 1b@72 + abs 1b@73
    let t = tab("sm121a");
    for mg in ["RM", "RP"] {
        let g = t.entries["DFMA_R_R_R_R"]
            .mod_groups
            .get(mg)
            .expect("RM/RP mg");
        let mut tok2: Vec<(u32, u32, &str)> = g
            .fields
            .iter()
            .filter(|f| f.token_idx == 2 && (f.shift == 72 || f.shift == 73))
            .map(|f| {
                (
                    f.shift,
                    f.bits,
                    match f.extraction {
                        Extraction::Neg => "neg",
                        Extraction::Abs => "abs",
                        _ => "other",
                    },
                )
            })
            .collect();
        tok2.sort();
        assert_eq!(
            tok2,
            vec![(72u32, 1u32, "neg"), (73u32, 1u32, "abs")],
            "sm121a DFMA_R_R_R_R/{mg} tok2 split drifted"
        );
    }
    // sm120 + sm121a UFADD: tok2 neg@72+abs@73; tok3 SWAPPED abs@74+neg@75
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        let g = t.entries["UFADD_UR_UR_UR"]
            .mod_groups
            .get("")
            .expect("UFADD '' mg");
        let mut hits: Vec<(i32, u32, u32, &str)> = g
            .fields
            .iter()
            .filter(|f| {
                (f.token_idx == 2 && (f.shift == 72 || f.shift == 73))
                    || (f.token_idx == 3 && (f.shift == 74 || f.shift == 75))
            })
            .map(|f| {
                (
                    f.token_idx,
                    f.shift,
                    f.bits,
                    match f.extraction {
                        Extraction::Neg => "neg",
                        Extraction::Abs => "abs",
                        _ => "other",
                    },
                )
            })
            .collect();
        hits.sort();
        assert_eq!(
            hits,
            vec![
                (2, 72, 1, "neg"),
                (2, 73, 1, "abs"),
                (3, 74, 1, "abs"),
                (3, 75, 1, "neg"),
            ],
            "{arch} UFADD window splits drifted"
        );
    }
    // and_base/vmask invariant: graft never touched masks on the 4 rows.
    let t = tab("sm121a");
    for mg in ["RM", "RP"] {
        let g = &t.entries["DFMA_R_R_R_R"].mod_groups[mg];
        let ab: u128 = g.and_base.into();
        assert_eq!((ab >> 72) & 3, 0, "DFMA {mg} and_base window bits baked!");
    }
}

#[test]
fn t258_2_decode_vendor_true() {
    // arb258 raw -b witnesses; models SM120==SM121a==SM103a (DFMA) and
    // SM120==SM121a (UFADD). Engine scope of the fix: sm120 + sm121a.
    let cases: &[(u128, &str)] = &[
        (W_RM, "DFMA.RM R10, R12, R14, R10"),
        (W_RM ^ (1u128 << 72), "DFMA.RM R10, -R12, R14, R10"),
        (W_RM ^ (1u128 << 73), "DFMA.RM R10, |R12|, R14, R10"),
        (W_RM ^ (3u128 << 72), "DFMA.RM R10, -|R12|, R14, R10"),
        (W_RP, "DFMA.RP R26, -R10, R12, R26"),
        (W_RP ^ (1u128 << 72), "DFMA.RP R26, R10, R12, R26"),
        (W_RP ^ (1u128 << 73), "DFMA.RP R26, -|R10|, R12, R26"),
        (W_RP ^ (3u128 << 72), "DFMA.RP R26, |R10|, R12, R26"),
    ];
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        for (i, (w, want)) in cases.iter().enumerate() {
            let got = dec(&t, *w & M96).unwrap_or_else(|| panic!("{arch} case{i} hole"));
            assert_eq!(got, *want, "{arch} DFMA case{i} decode != arb258");
        }
    }
    let ucases: &[(u128, &str)] = &[
        (W_UF, "UFADD UR4, UR4, UR5"),
        (W_UF ^ (1u128 << 72), "UFADD UR4, -UR4, UR5"),
        (W_UF ^ (1u128 << 73), "UFADD UR4, |UR4|, UR5"),
        (W_UF ^ (3u128 << 72), "UFADD UR4, -|UR4|, UR5"),
        (W_UF ^ (1u128 << 74), "UFADD UR4, UR4, |UR5|"),
        (W_UF ^ (1u128 << 75), "UFADD UR4, UR4, -UR5"),
        (W_UF ^ (3u128 << 74), "UFADD UR4, UR4, -|UR5|"),
    ];
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        for (i, (w, want)) in ucases.iter().enumerate() {
            let got = dec(&t, *w & M96).unwrap_or_else(|| panic!("{arch} ucase{i} hole"));
            assert_eq!(got, *want, "{arch} UFADD case{i} decode != arb258");
        }
    }
}

#[test]
fn t258_3_encode_payload_exact() {
    let t = tab("sm121a");
    let cases: &[(&str, u128)] = &[
        ("DFMA.RM R10, -R12, R14, R10", W_RM ^ (1u128 << 72)),
        ("DFMA.RM R10, |R12|, R14, R10", W_RM ^ (1u128 << 73)),
        ("DFMA.RM R10, -|R12|, R14, R10", W_RM ^ (3u128 << 72)),
        ("DFMA.RP R26, R10, R12, R26", W_RP ^ (1u128 << 72)),
        ("DFMA.RP R26, |R10|, R12, R26", W_RP ^ (3u128 << 72)),
    ];
    for (i, (text, w)) in cases.iter().enumerate() {
        let got = enc(&t, text);
        assert_eq!(got & M96, w & M96, "case{i} encode payload drift ({text})");
    }
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        let ucases: &[(&str, u128)] = &[
            ("UFADD UR4, -UR4, UR5", W_UF ^ (1u128 << 72)),
            ("UFADD UR4, |UR4|, UR5", W_UF ^ (1u128 << 73)),
            ("UFADD UR4, -|UR4|, UR5", W_UF ^ (3u128 << 72)),
            ("UFADD UR4, UR4, -UR5", W_UF ^ (1u128 << 75)),
            ("UFADD UR4, UR4, |UR5|", W_UF ^ (1u128 << 74)),
            ("UFADD UR4, UR4, -|UR5|", W_UF ^ (3u128 << 74)),
        ];
        for (i, (text, w)) in ucases.iter().enumerate() {
            let got = enc(&t, text);
            assert_eq!(got & M96, w & M96, "{arch} ucase{i} encode drift ({text})");
        }
    }
}

#[test]
fn t258_4_roundtrip() {
    let words: &[u128] = &[
        W_RM,
        W_RM ^ (1u128 << 72),
        W_RM ^ (1u128 << 73),
        W_RM ^ (3u128 << 72),
        W_RP,
        W_RP ^ (1u128 << 72),
        W_RP ^ (3u128 << 72),
        W_UF,
        W_UF ^ (1u128 << 72),
        W_UF ^ (1u128 << 73),
        W_UF ^ (3u128 << 72),
        W_UF ^ (1u128 << 74),
        W_UF ^ (1u128 << 75),
        W_UF ^ (3u128 << 74),
    ];
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        for (i, w) in words.iter().enumerate() {
            let txt = dec(&t, w & M96).unwrap_or_else(|| panic!("{arch} w{i} hole"));
            let back = enc(&t, &txt);
            assert_eq!(back & M96, w & M96, "{arch} w{i} roundtrip drift: {txt}");
        }
    }
}

#[test]
fn t258_5_flipped_by_261() {
    // FLIPPED by BUG-261 (F2-iter134, canonical dac676b): the DFMA_R_R_R_FI
    // RM/RP tok2 windows WERE the last ungrafted DFMA 2-bit neg windows;
    // 261 grafted them (A-class neg@72+abs@73, arb261 law identical to the
    // RM==RP R_R_R_R siblings). Assert the split, not the residuum.
    let t = tab("sm121a");
    for mg in ["RM", "RP"] {
        let g = t.entries["DFMA_R_R_R_FI"]
            .mod_groups
            .get(mg)
            .expect("FI RM/RP");
        let n2b = g
            .fields
            .iter()
            .filter(|f| {
                f.token_idx == 2 && f.shift == 72 && f.bits == 2 && f.extraction == Extraction::Neg
            })
            .count();
        assert_eq!(n2b, 0, "DFMA_R_R_R_FI/{mg} 2b-neg back? (261 flip)");
        assert!(g.fields.iter().any(|f| {
            f.token_idx == 2 && f.shift == 73 && f.bits == 1 && f.extraction == Extraction::Abs
        }));
    }
    // corpus witnesses keep law glyphs (regression anchors)
    let t = tab("sm121a");
    assert_eq!(
        dec(&t, W_RM & M96).as_deref(),
        Some("DFMA.RM R10, R12, R14, R10")
    );
    assert_eq!(
        dec(&t, W_RP & M96).as_deref(),
        Some("DFMA.RP R26, -R10, R12, R26")
    );
    assert_eq!(dec(&t, W_UF & M96).as_deref(), Some("UFADD UR4, UR4, UR5"));
}
