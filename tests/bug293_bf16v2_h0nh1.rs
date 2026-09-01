//! BUG-293 (F2-iter163, loop5/blind, 2026-08-31; canonical 46ff277):
//! HFMA2_R_R_R_R BF16_V2-mg b86 window closure + era-skeleton removal
//! on ALL 4 legs (TABLE graft patch293.py) + encoder redundancy-lane
//! narrowing (src/encoder.rs, BUG-293 arm).
//!
//! Pre-fix (pub pyo3-cac87b7 + canonical 57d1448; measure_pre293 +
//! arb293{,b,c}, 109+ probes nvdisasm raw -b, x4 models agree on ALL):
//!   D1 ENCODE wrong-code (neg@39 era-skeleton): authored
//!     'HFMA2.BF16_V2 R13, -R0, R15, R12' minted bit39|bit72 -- bit39 is
//!     the src2 reg-field MSB (arb H-set x4: R143/R128/RZ print PLAIN),
//!     so the word destroys src2 (R15 -> R143): vendor reads it back as
//!     'HFMA2.BF16_V2 R13, -R0, R143, R12'.
//!   D2 DECODE misprint (era twin opmod:H1_H1@86 tok2): mg|b86|hs60=v
//!     printed 'R0.H1_H1, R15.F32/H0_H0' where vendor prints
//!     'R15.INVALID5/6/7' (arb K/I); mg|b86|hs2=3 printed the doubled
//!     era glyph 'R0.H1_H1.H1_H1, R15' where vendor prints the paired
//!     spelling 'R0.H1_H1, R15.H0_NH1'.
//!   D3 ENCODE silent drop (272-era redundancy lane): authored solo
//!     'HFMA2.BF16_V2 R13, R0, R15.H0_NH1, R12' minted the mg-PLAIN
//!     word. Vendor: legal, exact mint = mg|b86 (arb C-set x10).
//!   D4 lane row-wide: authored '.H0_NH1' on tok2/tok4 of ANY
//!     HFMA2_R_R_* row was admitted row-wide by the redundancy clause
//!     then dropped ('HFMA2 R13, R0.H0_NH1, R15, R12' == plain).
//! Law (arb293{,b,c} verdicts; work/bug293/): b86 = tok3 '.H0_NH1'
//! single-bit under EVERY guard 0..15 (F x16, no era-bake anywhere),
//! composes tok2 hsel (G x16), neg63/neg84 signs (L), reuse122 (L3);
//! hsel@[61:60] tok3 1='.F32' 2/3='.H0_H0'/.H1_H1' (already armed);
//! b86+hsel@60!=0 => vendor '.INVALID5/6/7' (271 doctrine => engine
//! hole on decode / fail-closed on encode via the h0nh1 arm).
//! Graft: BF16_V2 row: -{neg@39 tok2, opmod:H1_H1@86 tok2}
//! +{h0nh1 1b@86 tok3, _src bug293-2026-08-31}; extraction swap
//! opmod:H0_NH1 -> h0nh1 on HFMA2_R_R_R_R[''] (4 legs) and
//! HFMA2_R_R_R_UR[''] (sm120/sm121a; arms the encode-side 271 INVALID
//! combo gate; decode/print byte-stable). vm unchanged.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction as X, IsaTable};

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc_res(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse {text}: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("{e}"))
}
/// lattice 0x231 BF16_V2 host: guard PT(7)@12, dst R13@16, tok2 R0@24,
/// tok3(src2) R15@32, tok4(src3) R12@64, mg b85 -> vendor
/// 'HFMA2.BF16_V2 R13, R0, R15, R12' (96-bit form, ctrl bits zeroed)
fn mghost() -> u128 {
    (0x0020000c0000000f000d7231u128 | (7 << 12)) & ((1u128 << 96) - 1)
}
/// same lattice, no mg ('' mod-group): b85 clear
fn host() -> u128 {
    mghost() & !(1u128 << 85)
}
/// encoder output = full 128-bit bundle word: instruction | ctrl template
/// (this lattice bakes 0x0fc200 at bits [111:96]).
fn full(w96: u128) -> u128 {
    (0x000fc200u128 << 96) | w96
}

#[test]
fn t293_1_structure_census_tags() {
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        let e = &t.entries["HFMA2_R_R_R_R"];
        // FLIP (BUG-320/321, F2-iter171, canonical 1e2b7ba): graft legs
        // sm120/sm121a gain F32/FMZ/F32,FMZ/BF16_V2,FMZ clone-bake lanes
        // (arb320 a/b/c x4 vendor law); donor legs keep the 293-era shape.
        let want_mgs = if arch == "sm120" || arch == "sm121a" {
            6
        } else {
            2
        };
        assert_eq!(e.mod_groups.len(), want_mgs, "{arch}: R4 mod_groups drift");
        let mg = &e.mod_groups["BF16_V2"];
        assert!(
            mg.fields.iter().any(|f| f.shift == 86
                && f.bits == 1
                && f.token_idx == 3
                && f.extraction == X::H0NH1),
            "{arch}: h0nh1 1b@86 tok3 missing on BF16_V2"
        );
        assert!(
            !mg.fields.iter().any(|f| f.shift == 39),
            "{arch}: era neg@39 survives (D1 wrong-code skeleton)"
        );
        assert!(
            !mg.fields.iter().any(|f| f.shift == 86 && f.token_idx == 2),
            "{arch}: era twin opmod:H1_H1@86 tok2 survives (D2)"
        );
        assert!(mg.variable_mask & (1u128 << 86) != 0, "{arch}: vm lost b86");
        assert!(
            mg.variable_mask & (1u128 << 39) != 0,
            "{arch}: vm lost b39 (unchanged contract)"
        );
        // '' row: the swap landed (h0nh1, no opmod:H0_NH1 remanant)
        let g0 = &e.mod_groups[""];
        assert!(
            g0.fields
                .iter()
                .any(|f| f.extraction == X::H0NH1 && f.shift == 86 && f.token_idx == 3),
            "{arch}: ''-row swap to h0nh1 missing"
        );
        assert!(
            !g0.fields
                .iter()
                .any(|f| f.extraction == X::OpModFlag("H0_NH1".into())),
            "{arch}: ''-row opmod:H0_NH1 remnant"
        );
    }
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        let g = &t.entries["HFMA2_R_R_R_UR"].mod_groups[""];
        assert!(
            g.fields
                .iter()
                .any(|f| f.extraction == X::H0NH1 && f.shift == 86 && f.token_idx == 3),
            "{arch}: RRUR swap to h0nh1 missing"
        );
        assert!(
            !g.fields
                .iter()
                .any(|f| f.extraction == X::OpModFlag("H0_NH1".into())),
            "{arch}: RRUR opmod remnant"
        );
    }
    // era twins are gone from every table (global census)
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (k, e) in &t.entries {
            for (_mgn, mg) in &e.mod_groups {
                assert!(
                    !mg.fields
                        .iter()
                        .any(|f| f.shift == 86 && f.extraction == X::OpModFlag("H1_H1".into())),
                    "{arch}:{k}: opmod:H1_H1@86 era twin resurrected"
                );
            }
        }
    }
}

fn count_tags(arch: &str, tag: &str) -> usize {
    let j: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(format!("tables/{arch}.json")).unwrap())
            .unwrap();
    let mut n = 0usize;
    for (_k, e) in j["instructions"].as_object().unwrap() {
        let Some(mgz) = e.get("mod_groups").and_then(|x| x.as_object()) else {
            continue;
        };
        for (_mg, g) in mgz {
            for f in g["fields"].as_array().unwrap() {
                if f.get("_src").and_then(|x| x.as_str()) == Some(tag) {
                    n += 1;
                }
            }
        }
    }
    n
}

#[test]
fn t293_2_decode_law_vendor_exact() {
    let h = mghost();
    let cases: &[(u128, &str)] = &[
        // D3/D2 core: b86 = tok3 '.H0_NH1' (arb C/F sets, x4)
        (1u128 << 86, "HFMA2.BF16_V2 R13, R0, R15.H0_NH1, R12"),
        (
            (1 << 86) | (1 << 63),
            "HFMA2.BF16_V2 R13, R0, -R15.H0_NH1, R12",
        ),
        (
            (1 << 86) | (1 << 84),
            "HFMA2.BF16_V2 R13, R0, R15.H0_NH1, -R12",
        ),
        (
            (1 << 86) | (1 << 63) | (1 << 84),
            "HFMA2.BF16_V2 R13, R0, -R15.H0_NH1, -R12",
        ),
        // era twin removed: paired spelling single-baked (arb D/E/G)
        (
            (1 << 86) | (3 << 74),
            "HFMA2.BF16_V2 R13, R0.H1_H1, R15.H0_NH1, R12",
        ),
        (
            (1 << 86) | (2 << 74),
            "HFMA2.BF16_V2 R13, R0.H0_H0, R15.H0_NH1, R12",
        ),
        // neg@39 skeleton gone: bit39 = src2 reg msb, prints PLAIN (arb H x4)
        (1u128 << 39, "HFMA2.BF16_V2 R13, R0, R143, R12"),
        (
            (1 << 39) | (1 << 86),
            "HFMA2.BF16_V2 R13, R0, R143.H0_NH1, R12",
        ),
        // hsel@[61:60] tok3 window sane solo (arb I)
        (1u128 << 60, "HFMA2.BF16_V2 R13, R0, R15.F32, R12"),
        (2u128 << 60, "HFMA2.BF16_V2 R13, R0, R15.H0_H0, R12"),
        (3u128 << 60, "HFMA2.BF16_V2 R13, R0, R15.H1_H1, R12"),
        // reuse x b86 neutral (arb L3). BUG-326 flip: this host is yield=0,
        // so the vendor print swallows the reuse bit (arb325 yield-gate
        // law); pre-326 the pin carried the engine's field-consistent print.
        (
            (1 << 86) | (1 << 122),
            "HFMA2.BF16_V2 R13, R0, R15.H0_NH1, R12",
        ),
    ];
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (bits, want) in cases {
            let got = dec(&t, h | bits);
            assert_eq!(
                got.as_deref(),
                Some(*want),
                "{arch} bits {bits:x}: got {got:?}"
            );
        }
        // era-bake tripwire: under EVERY guard b86 prints tok3 .H0_NH1 (arb F x16)
        for g in 0..16u128 {
            let w = (h & !(0xf << 12)) | (g << 12) | (1 << 86);
            let got = dec(&t, w).unwrap_or_else(|| panic!("{arch} g{g}: b86 holed"));
            assert!(
                got.contains("R15.H0_NH1"),
                "{arch} guard {g}: era bake drift: {got}"
            );
        }
        // 271 doctrine on the grafted window: b86+hsel@60!=0 = vendor INVALID5/6/7 = hole
        for v in [1u128, 2, 3] {
            let w = h | (1 << 86) | (v << 60);
            assert!(
                dec(&t, w).is_none(),
                "{arch}: b86+hs60={v} must hole, got {:?}",
                dec(&t, w)
            );
        }
    }
}

#[test]
fn t293_1b_tag_census() {
    // BF16_V2 add (1) + ''-row swap (1) on every leg; RRUR ''-row swap (+1)
    // on the sm120/sm121a legs that ship the row.
    assert_eq!(count_tags("sm100a", "bug293-2026-08-31"), 2);
    assert_eq!(count_tags("sm103a", "bug293-2026-08-31"), 2);
    assert_eq!(count_tags("sm120", "bug293-2026-08-31"), 3);
    assert_eq!(count_tags("sm121a", "bug293-2026-08-31"), 3);
}

#[test]
fn t293_3_mint_law_roundtrip() {
    let h = mghost();
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        let cases: &[(&str, u128)] = &[
            // D3 closed: authored solo mints b86 (arb C exact word)
            (
                "HFMA2.BF16_V2 R13, R0, R15.H0_NH1, R12",
                full(h | (1 << 86)),
            ),
            (
                "HFMA2.BF16_V2 R13, R0, -R15.H0_NH1, R12",
                full(h | (1 << 86) | (1 << 63)),
            ),
            // pair spelling (smoke272 anchor shape)
            (
                "HFMA2.BF16_V2 R13, R0.H1_H1, R15.H0_NH1, R12",
                full(h | (1 << 86) | (3 << 74)),
            ),
            // D1 closed: '-R0' mints neg@72 ONLY (bit39 clear)
            ("HFMA2.BF16_V2 R13, -R0, R15, R12", full(h | (1 << 72))),
        ];
        for (text, want) in cases {
            let got = enc_res(&t, text).unwrap_or_else(|e| panic!("{arch} enc {text}: {e}"));
            assert_eq!(got, *want, "{arch} mint {text}");
            let rt = dec(&t, got).unwrap_or_else(|| panic!("{arch} re-dec hole {text}"));
            assert_eq!(&rt, text, "{arch} roundtrip {text}");
        }
        // 271 encode gate on grafted windows: authored INVALID combos fail closed
        for bad in [
            "HFMA2.BF16_V2 R13, R0, R15.H0_NH1.H0_H0, R12",
            "HFMA2.BF16_V2 R13, R0, R15.H0_NH1.F32, R12",
            "HFMA2 R13, R0, R15.H0_NH1.H0_H0, R12",
            "HFMA2 R13, R0, R15.H0_NH1.F32, R12",
        ] {
            assert!(
                enc_res(&t, bad).is_err(),
                "{arch}: INVALID combo {bad} must fail closed"
            );
        }
        // plain mg mint unchanged (baseline anchor)
        assert_eq!(
            enc_res(&t, "HFMA2.BF16_V2 R13, R0, R15, R12").unwrap(),
            full(h),
            "{arch}: mg plain drift"
        );
    }
}

#[test]
fn t293_4_redundancy_lane_per_token() {
    // BUG-293 encoder arm: '.H0_NH1' without a mint channel on the SAME
    // operand fails closed (pre-fix: admitted row-wide, dropped silently)
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for bad in [
            "HFMA2 R13, R0.H0_NH1, R15, R12",
            "HFMA2.BF16_V2 R13, R0.H0_NH1, R15, R12",
            "HFMA2 R13, R0, R15, R12.H0_NH1",
            "HFMA2.BF16_V2 R13, R0, R15, R12.H0_NH1",
            "HFMA2 R13.H0_NH1, R0, R15, R12",
        ] {
            let e = enc_res(&t, bad).expect_err(&format!("{arch}: {bad} must fail closed"));
            assert!(
                e.contains("BUG-272")
                    || e.contains("BUG-293")
                    || e.contains("unknown operand suffix"),
                "{arch}: {bad} error without attribution: {e}"
            );
        }
        // positive control: tok3 stays minted (the lane did not over-narrow)
        assert!(
            enc_res(&t, "HFMA2 R13, R0, R15.H0_NH1, R12").is_ok(),
            "{arch}: tok3 .H0_NH1 plain-row mint broke"
        );
    }
}

#[test]
fn t293_5_anchors_and_sibling_swap() {
    let h = host();
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        // '' row: solo mint/decode byte-stable through the extraction swap
        assert_eq!(
            enc_res(&t, "HFMA2 R13, R0, R15.H0_NH1, R12").unwrap(),
            full(h | (1 << 86)),
            "{arch}: '' solo mint drift"
        );
        assert_eq!(
            dec(&t, h | (1 << 86)).as_deref(),
            Some("HFMA2 R13, R0, R15.H0_NH1, R12"),
            "{arch}: '' solo decode drift"
        );
        assert_eq!(
            enc_res(&t, "HFMA2 R13, R0, R15, R12").unwrap(),
            full(h),
            "{arch}: plain drift"
        );
    }
    // HFMA2_R_R_R_UR '' (289 graft row): swapped extraction, mint/decode stable
    let urh =
        (0x80000000000000000000e31u128 | (7 << 12) | (1 << 16) | (2 << 24) | (3 << 64) | (4 << 32))
            & ((1u128 << 96) - 1);
    for arch in ["sm120", "sm121a"] {
        let t = tab(arch);
        assert_eq!(
            enc_res(&t, "HFMA2 R1, R2, R3.H0_NH1, UR4").unwrap(),
            full(urh | (1 << 86)),
            "{arch}: RRUR mint drift"
        );
        assert_eq!(
            dec(&t, urh | (1 << 86)).as_deref(),
            Some("HFMA2 R1, R2, R3.H0_NH1, UR4"),
            "{arch}: RRUR decode drift"
        );
        // INVALID combo now also gated on encode on this row (swap pay-off)
        assert!(
            enc_res(&t, "HFMA2 R1, R2, R3.H0_NH1.H0_H0, UR4").is_err(),
            "{arch}: RRUR INVALID combo must fail closed"
        );
    }
}
