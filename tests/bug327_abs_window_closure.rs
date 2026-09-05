//! BUG-327 (F2-iter175, loop5/blind front2, 2026-09-01): HFMA2 pure-reg
//! 0x231 abs-window closure -- abs@73 tok2 / abs@62 tok3 fielded on all 6
//! mandatory mgs of HFMA2_R_R_R_R, legs sm120+sm121a (canonical bug327 cut
//! 2761da4, ride-after 8b1ad45/BUG-326). Registered 327-kand LOW at
//! F2-iter163 (293 report sec.7; arb293 J-set in hand). Measurement-first:
//! arb327 = 72 probes, nvdisasm 13.3.73 raw -b, x4 models SM100a/103a/120/
//! 121a agree on EVERY probe, zero DIVERGENT.
//!
//! LAW (x4 agree): lattice 0x231 pure-reg (guard 4b@[15:12], Rd@16, Ra@24,
//! Rb@32, Rc@64): abs@73 (tok2) / abs@62 (tok3) vendor-legal + printed on
//! '' and BF16_V2 bases and all four post-320 mod rows; compose with the
//! same-token neg ('-|R2|'), cross-token, triple-abs, hsel ('|R2|.H1_H1',
//! '|R3|.F32/.H0_H0/.H1_H1'), h0nh1 ('|R3|.H0_NH1'), inert band; guard
//! sweep x16 with b73 all print. Edges: b91 = KILL (rc=1) with signs on;
//! F32 x BF16 = '.INVALID3' print (285 doctrine); h0nh1 + hsel@60 != 0 =
//! '.INVALID5/6/7' (293 doctrine) -- both stay HOLE fail-closed.
//!
//! PRE-FIX (publish 8b1ad45; measure_pre327 + corner327): behavioral
//! parity PRE-EXISTED -- decode via generic sign rescue (decoder.rs
//! add(62/73)), encode minted exact bits via the generic emit; 48/48
//! roundtrip byte-exact; compose/clone rows x4 agree. This graft = pure
//! FIELD-CLOSURE + has_field_abs defer parity (320 mechanism): ownership
//! moves from the generic rescue lane into per-row fields (fleet era-
//! elimination doctrine). Corpus exposure ZERO (census327: 53,653 lattice
//! words, 0 with b62/b73) => decode/print byte-stable by data.
//! NOT ARMED (registered): neg@63 tok3 + neg@72 ''-row stay generic-
//! rescue = 343-kand residuum; SAT/FTZ/OOB/RELU (344); R_R_UR_R tok4 (345);
//! R_R_R_R_R (346). DONORS (sm100a/sm103a) untouched (BUG-315 owner scope).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
const B62: u128 = 1 << 62;
const B63: u128 = 1 << 63;
const B72: u128 = 1 << 72;
const B73: u128 = 1 << 73;
const B76: u128 = 1 << 76;
const B78: u128 = 1 << 78;
const B83: u128 = 1 << 83;
const B84: u128 = 1 << 84;
const B85: u128 = 1 << 85;
const B86: u128 = 1 << 86;
const B91: u128 = 1 << 91;
const BAND: u128 = 0xffffu128 << 40;
// HOST lattice: 0x231 | PT | R1@16, R2@24, R3@32, R4@64
const HOST: u128 = 0x231 | (7 << 12) | (1 << 16) | (2 << 24) | (3 << 32) | (4 << 64);
const GRAFT_MGS: [&str; 6] = ["", "BF16_V2", "F32", "FMZ", "F32,FMZ", "BF16_V2,FMZ"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t)
        .map(|d| to_sass(&d))
        .ok()
        .map(|s| s.trim_end().trim_end_matches(';').to_string())
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}

#[test]
fn t327_1_structure_graft_and_donors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let e = &t.entries["HFMA2_R_R_R_R"];
        // mandatory set intact + the 343/344 mod-window lanes grafted on top
        // (FLIP BUG-343/344, F2-iter182, canonical a013f88: 6 -> 36 rows)
        assert_eq!(e.mod_groups.len(), 36, "{leg}: mg count drift");
        for mgn in GRAFT_MGS {
            let mg = e
                .mod_groups
                .get(mgn)
                .unwrap_or_else(|| panic!("{leg}: missing mg [{mgn}]"));
            let has = |ext: Extraction, shift: u32, tok: i32| {
                mg.fields
                    .iter()
                    .filter(|f| f.extraction == ext && f.shift == shift && f.token_idx == tok)
                    .count()
            };
            // abs window fielded exactly once per token
            assert_eq!(
                has(Extraction::Abs, 73, 2),
                1,
                "{leg}[{mgn}]: abs@73 tok2 count"
            );
            assert_eq!(
                has(Extraction::Abs, 62, 3),
                1,
                "{leg}[{mgn}]: abs@62 tok3 count"
            );
            // 320's abs@83 tok4 still in place, still exactly once
            assert_eq!(has(Extraction::Abs, 83, 4), 1, "{leg}[{mgn}]: abs@83 drift");
            // no dest/tok1 sign field exists anywhere (none measured legal)
            assert_eq!(
                mg.fields
                    .iter()
                    .filter(|f| {
                        matches!(f.extraction, Extraction::Abs | Extraction::Neg)
                            && f.token_idx == 1
                    })
                    .count(),
                0,
                "{leg}[{mgn}]: tok1 sign field materialized"
            );
            // FLIP (BUG-343/344, F2-iter182, canonical a013f88): the 343
            // residuum is fielded now -- neg@63 tok3 on every mandatory mg
            // (closure of the 320/327 sign lattice; parity pre-existed via
            // the generic rescue per measure_pre343, so decode/mint are
            // byte-stable).
            assert_eq!(
                has(Extraction::Neg, 63, 3),
                1,
                "{leg}[{mgn}]: 343 neg@63 field drift"
            );
            // FLIP (BUG-343/344): neg@72 tok2 = 1 on every mandatory mg post
            // closure (pre-graft asymmetry BF16-only closed deliberately; the
            // vendor law carries neg@72 on all carriers x4 per arb343 A-set).
            assert_eq!(
                has(Extraction::Neg, 72, 2),
                1,
                "{leg}[{mgn}]: 343 neg@72 field drift"
            );
            // and_base + variable_mask carry none of the armed sign bits
            assert_eq!(
                mg.and_base & (B62 | B73),
                0,
                "{leg}[{mgn}]: ab carries sign bits"
            );
            assert_eq!(
                mg.variable_mask & (B62 | B73),
                0,
                "{leg}[{mgn}]: vm covers sign bits"
            );
        }
        // lane bakes unchanged (320 geometry)
        let ab = |m: &str| e.mod_groups[m].and_base;
        assert_eq!(ab("") & 0xfff, 0x231, "{leg}: '' kratka drift");
        assert_eq!(ab("F32") ^ ab(""), 1 << 78, "{leg}: F32 bake drift");
        assert_eq!(ab("FMZ") ^ ab(""), 1 << 76, "{leg}: FMZ bake drift");
        assert_eq!(ab("F32,FMZ") ^ ab(""), (1 << 76) | (1 << 78));
        assert_eq!(ab("BF16_V2,FMZ") ^ ab("BF16_V2"), 1 << 76);
        // inert-band relax from 320 intact
        for mgn in GRAFT_MGS {
            assert_eq!(e.mod_groups[mgn].variable_mask & BAND, BAND);
        }
    }
    // donors mg set: {'' , BF16_V2} pre-381.
    // FLIP (BUG-381, F2-iter203, canonical 3cb31e4): the sparse 0x231
    // lattice completion grafts the full 36-lane set on the donor legs
    // (pure-replica of the dense lattice; every row still carries the
    // BUG-371 abs@83 field by donor-clone descent -- asserted below; the
    // abs@62/73 tok2/tok3 poverty on donors stands = 392-kand).
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        let e = &t.entries["HFMA2_R_R_R_R"];
        assert_eq!(e.mod_groups.len(), 36, "{leg}: donor mg set drift");
        for (mgn, mg) in &e.mod_groups {
            // FLIP (BUG-371, F2-iter196, canonical 6b7a120): tok4 abs@83 is
            // field-carried on the thin legs now -- the 320/327-deferred
            // donor residuum closed after arb371/arb371b proved b83 = tok4
            // abs x4 models on the thin lattice (and measured the generic
            // b74 mint here as the silent 'R2.INVALID1' cross-read). abs@62
            // / abs@73 tok-levels stay absent (no donor law there).
            let cnt83 = mg
                .fields
                .iter()
                .filter(|f| f.extraction == Extraction::Abs && f.shift == 83)
                .count();
            assert_eq!(cnt83, 1, "{leg}[{mgn}]: abs@83 tok4 missing (BUG-371)");
            assert!(
                !mg.fields
                    .iter()
                    .any(|f| f.extraction == Extraction::Abs && matches!(f.shift, 62 | 73)),
                "{leg}[{mgn}]: donor grafted beyond 371 scope!"
            );
        }
    }
}

#[test]
fn t327_2_decode_law_vendor_equal() {
    // (extra-bits on HOST, expected vendor text); vendor law arb327 (x4 agree)
    let cases: &[(u128, &str)] = &[
        // solo / pairs / cross / triples / six-set on ''
        (B73, "HFMA2 R1, |R2|, R3, R4"),
        (B62, "HFMA2 R1, R2, |R3|, R4"),
        (B63, "HFMA2 R1, R2, -R3, R4"),
        (B72, "HFMA2 R1, -R2, R3, R4"),
        (B62 | B63, "HFMA2 R1, R2, -|R3|, R4"),
        (B72 | B73, "HFMA2 R1, -|R2|, R3, R4"),
        (B62 | B72, "HFMA2 R1, -R2, |R3|, R4"),
        (B62 | B72 | B73, "HFMA2 R1, -|R2|, |R3|, R4"),
        (B62 | B63 | B72 | B73, "HFMA2 R1, -|R2|, -|R3|, R4"),
        (B62 | B63 | B72 | B73 | B83, "HFMA2 R1, -|R2|, -|R3|, |R4|"),
        (
            B62 | B63 | B72 | B73 | B83 | B84,
            "HFMA2 R1, -|R2|, -|R3|, -|R4|",
        ),
        // BF16 base
        (B85 | B62, "HFMA2.BF16_V2 R1, R2, |R3|, R4"),
        (B85 | B63, "HFMA2.BF16_V2 R1, R2, -R3, R4"),
        (B85 | B73, "HFMA2.BF16_V2 R1, |R2|, R3, R4"),
        (B85 | B62 | B63, "HFMA2.BF16_V2 R1, R2, -|R3|, R4"),
        (B85 | B72 | B73, "HFMA2.BF16_V2 R1, -|R2|, R3, R4"),
        (
            B85 | B62 | B63 | B72 | B73,
            "HFMA2.BF16_V2 R1, -|R2|, -|R3|, R4",
        ),
        (
            B85 | B62 | B63 | B72 | B73 | B83 | B84,
            "HFMA2.BF16_V2 R1, -|R2|, -|R3|, -|R4|",
        ),
        // mod rows x abs lanes
        (B78 | B62, "HFMA2.F32 R1, R2, |R3|, R4"),
        (B78 | B73, "HFMA2.F32 R1, |R2|, R3, R4"),
        (B78 | B62 | B63, "HFMA2.F32 R1, R2, -|R3|, R4"),
        (B78 | B72 | B73, "HFMA2.F32 R1, -|R2|, R3, R4"),
        (B76 | B62, "HFMA2.FMZ R1, R2, |R3|, R4"),
        (B76 | B73, "HFMA2.FMZ R1, |R2|, R3, R4"),
        (B76 | B62 | B63, "HFMA2.FMZ R1, R2, -|R3|, R4"),
        (B76 | B72 | B73, "HFMA2.FMZ R1, -|R2|, R3, R4"),
        (B76 | B78 | B62, "HFMA2.F32.FMZ R1, R2, |R3|, R4"),
        (B76 | B78 | B73, "HFMA2.F32.FMZ R1, |R2|, R3, R4"),
        (B76 | B78 | B62 | B63, "HFMA2.F32.FMZ R1, R2, -|R3|, R4"),
        (B76 | B78 | B72 | B73, "HFMA2.F32.FMZ R1, -|R2|, R3, R4"),
        (B85 | B76 | B62, "HFMA2.BF16_V2.FMZ R1, R2, |R3|, R4"),
        (B85 | B76 | B73, "HFMA2.BF16_V2.FMZ R1, |R2|, R3, R4"),
        (B85 | B76 | B62 | B63, "HFMA2.BF16_V2.FMZ R1, R2, -|R3|, R4"),
        (B85 | B76 | B72 | B73, "HFMA2.BF16_V2.FMZ R1, -|R2|, R3, R4"),
        // composes: hsel tok2 (legal values 2/3)
        ((2 << 74) | B73, "HFMA2 R1, |R2|.H0_H0, R3, R4"),
        ((3 << 74) | B73, "HFMA2 R1, |R2|.H1_H1, R3, R4"),
        ((2 << 74) | B72 | B73, "HFMA2 R1, -|R2|.H0_H0, R3, R4"),
        // composes: hsel tok3
        ((1 << 60) | B62, "HFMA2 R1, R2, |R3|.F32, R4"),
        ((2 << 60) | B62, "HFMA2 R1, R2, |R3|.H0_H0, R4"),
        ((3 << 60) | B62, "HFMA2 R1, R2, |R3|.H1_H1, R4"),
        ((1 << 60) | B62 | B63, "HFMA2 R1, R2, -|R3|.F32, R4"),
        // BF16 h0nh1 composes
        (B85 | B86 | B62, "HFMA2.BF16_V2 R1, R2, |R3|.H0_NH1, R4"),
        (
            B85 | B86 | B62 | B63,
            "HFMA2.BF16_V2 R1, R2, -|R3|.H0_NH1, R4",
        ),
        (B85 | B86 | B73, "HFMA2.BF16_V2 R1, |R2|, R3.H0_NH1, R4"),
        // inert-band compose
        ((0x34 << 40) | B73, "HFMA2 R1, |R2|, R3, R4"),
        // triple abs
        (B62 | B73 | B83, "HFMA2 R1, |R2|, |R3|, |R4|"),
    ];
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (extra, want) in cases {
            let got =
                dec(&t, HOST | extra).unwrap_or_else(|| panic!("{leg}: HOLE on extra={extra:#x}"));
            assert_eq!(&got, want, "{leg}: decode law drift on extra={extra:#x}");
        }
        // guard sweep (arb327 A-set x16 x4-agree): abs print composes under
        // every guard; vendor guard map = v<7 '@Pv' / 7 PT-plain /
        // 8..14 '@!P(v-8)' / 15 '@!PT'
        for (g, want) in [
            (0u128, "@P0 HFMA2 R1, |R2|, R3, R4"),
            (1 << 12, "@P1 HFMA2 R1, |R2|, R3, R4"),
            (6 << 12, "@P6 HFMA2 R1, |R2|, R3, R4"),
            (7 << 12, "HFMA2 R1, |R2|, R3, R4"),
            (8 << 12, "@!P0 HFMA2 R1, |R2|, R3, R4"),
            (0xe << 12, "@!P6 HFMA2 R1, |R2|, R3, R4"),
            (0xf << 12, "@!PT HFMA2 R1, |R2|, R3, R4"),
        ] {
            let w = (HOST & !(0xfu128 << 12)) | g | B73;
            assert_eq!(&dec(&t, w).unwrap(), want, "{leg}: guard {g:#x} drift");
        }
    }
}

#[test]
fn t327_3_encode_word_exact_and_roundtrip() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // word-exact mints through the armed fields (ghost-free by structure)
        let w = enc(&t, "HFMA2 R1, |R2|, R3, R4").unwrap();
        assert_eq!(w & M96, (HOST | B73) & M96, "{leg}: tok2 abs mint drift");
        let w = enc(&t, "HFMA2 R1, R2, |R3|, R4").unwrap();
        assert_eq!(w & M96, (HOST | B62) & M96, "{leg}: tok3 abs mint drift");
        let w = enc(&t, "HFMA2 R1, -|R2|, -|R3|, R4").unwrap();
        assert_eq!(
            w & M96,
            (HOST | B62 | B63 | B72 | B73) & M96,
            "{leg}: sign-set mint drift"
        );
        let w = enc(&t, "HFMA2.BF16_V2 R1, |R2|, R3.H0_NH1, R4").unwrap();
        assert_eq!(
            w & M96,
            (HOST | B85 | B86 | B73) & M96,
            "{leg}: BF16 h0nh1 compose mint drift"
        );
        let w = enc(&t, "HFMA2.F32.FMZ R1, -|R2|, R3, R4").unwrap();
        assert_eq!(
            w & M96,
            (HOST | B76 | B78 | B72 | B73) & M96,
            "{leg}: clone-row mint drift"
        );
        // text-roundtrip byte-stable on the armed lanes (field + rescue mix
        // on '' ['-|R2|' = field abs + rescue neg] and full-field BF16)
        for txt in [
            "HFMA2 R1, |R2|, R3, R4",
            "HFMA2 R1, -|R2|, R3, R4",
            "HFMA2 R1, R2, |R3|, R4",
            "HFMA2 R1, R2, -|R3|, R4",
            "HFMA2 R1, |R2|.H1_H1, R3, R4",
            "HFMA2 R1, R2, -|R3|.F32, R4",
            "HFMA2 R1, |R2|, |R3|, |R4|",
            "HFMA2.BF16_V2 R1, -|R2|, -|R3|.H0_NH1, R4",
            "HFMA2.F32 R1, |R2|, |R3|, R4",
            "HFMA2.BF16_V2.FMZ R1, -|R2|, -|R3|, R4",
        ] {
            let w = enc(&t, txt).unwrap_or_else(|e| panic!("{leg}: encode hole: {txt}: {e}"));
            assert_eq!(
                &dec(&t, w).unwrap_or_else(|| panic!("{leg}: decode hole post-encode: {txt}")),
                txt,
                "{leg}: text roundtrip drift: {txt}"
            );
        }
    }
}

#[test]
fn t327_4_fail_closed_doctrine_edges() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // INVALID3 lane (vendor prints HFMA2.INVALID3): engine stays HOLE + encode loud-fails
        assert!(
            dec(&t, HOST | B85 | B78 | B73).is_none(),
            "{leg}: INVALID3+abs lane decoded!"
        );
        assert!(
            enc(&t, "HFMA2.BF16_V2.F32 R1, |R2|, R3, R4").is_err(),
            "{leg}: INVALID3+abs lane encoded!"
        );
        // INVALID5/6/7 window (h0nh1 + hsel@60 != 0): HOLE, also with the
        // armed abs lane on (293 doctrine)
        for hs in [1u128, 2, 3] {
            assert!(
                dec(&t, HOST | B85 | B86 | (hs << 60) | B62).is_none(),
                "{leg}: INVALID combo hsel60={hs} + abs decoded!"
            );
        }
        // b91 unit-KILL stays HOLE with sign bits on
        assert!(
            dec(&t, HOST | B91 | B73).is_none(),
            "{leg}: b91 KILL+abs decoded!"
        );
        assert!(
            dec(&t, HOST | B91 | B62).is_none(),
            "{leg}: b91 KILL+abs62 decoded!"
        );
        assert!(
            dec(&t, HOST | B91 | B85 | B73).is_none(),
            "{leg}: b91 KILL+BF16+abs decoded!"
        );
        // FLIP (BUG-343/344, F2-iter182, canonical a013f88): the SAT compose
        // with abs@73 is now armed through the closure (arb343 x4); the
        // registry doctrine it was guarding is retired by its own ticket:
        assert_eq!(
            enc(&t, "HFMA2.SAT R1, |R2|, R3, R4").unwrap() & M96,
            (HOST | (1 << 77) | B73) & M96,
            "{leg}: 343/344 SAT+abs mint drift"
        );
        assert_eq!(
            dec(&t, HOST | (1 << 77) | B73).as_deref(),
            Some("HFMA2.SAT R1, |R2|, R3, R4"),
            "{leg}: 343/344 SAT+abs decode drift"
        );
    }
}

#[test]
fn t327_5_anchors_293_320_324_intact() {
    // era-armed behaviors the graft must not disturb (same rows/HFMA2 family)
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let anchors: &[(u128, &str)] = &[
            (0, "HFMA2 R1, R2, R3, R4"),
            (3 << 74, "HFMA2 R1, R2.H1_H1, R3, R4"),
            (B84, "HFMA2 R1, R2, R3, -R4"),
            (B83, "HFMA2 R1, R2, R3, |R4|"),        // 320 lane
            (B83 | B84, "HFMA2 R1, R2, R3, -|R4|"), // 320 compose
            (B86, "HFMA2 R1, R2, R3.H0_NH1, R4"),
            (B72 | (3 << 74), "HFMA2 R1, -R2.H1_H1, R3, R4"),
            (B85, "HFMA2.BF16_V2 R1, R2, R3, R4"),
            (1 << 78, "HFMA2.F32 R1, R2, R3, R4"),
            ((1 << 76) | (1 << 78), "HFMA2.F32.FMZ R1, R2, R3, R4"),
        ];
        for (extra, want) in anchors {
            let got = dec(&t, HOST | extra)
                .unwrap_or_else(|| panic!("{leg}: anchor HOLE extra={extra:#x}"));
            assert_eq!(&got, want, "{leg}: anchor drift extra={extra:#x}");
        }
        // mixed field/rescue composes stay byte-stable ('' row: rescue neg@72
        // + field abs@73; tok3: rescue neg@63 + field abs@62)
        assert_eq!(
            &dec(&t, HOST | B72 | B73).unwrap(),
            "HFMA2 R1, -|R2|, R3, R4"
        );
        assert_eq!(
            &dec(&t, HOST | B63 | B62).unwrap(),
            "HFMA2 R1, R2, -|R3|, R4"
        );
        // BUG-384 flip (canonical 9713fd6): the harvest-junk dense era keys
        // HFMA2.BF16_V2_R_R_R_R + HFMA2_R_R_R_R_R are DELETED (junk-baked
        // hsel claims, wrong-window 5-reg fields; arb384 found 2 live WRONG
        // cells on the 5-reg row; claim space subsumed by the main rows).
        // Their shapes decode via HFMA2_R_R_R_R mg ''/BF16_V2 with the same
        // vendor-true text (420/420 battery hits vendor-exact pre==post).
        // The 371-grafted abs@83 on the era rows retired with them; all
        // sign coverage now lives on the main rows (which carry both
        // neg@84/rescue and abs@83).
        assert!(
            !t.entries.contains_key("HFMA2.BF16_V2_R_R_R_R"),
            "{leg}: junk era key BF16_V2_R_R_R_R resurrected"
        );
        assert!(
            !t.entries.contains_key("HFMA2_R_R_R_R_R"),
            "{leg}: junk era key R_R_R_R_R resurrected"
        );
        // era-base words (H0_H0-baked family) stay vendor-true decode-side:
        const ERA_BF: u128 = 0x00000000002408002000000000000231;
        const ERA_5R: u128 = 0x0000000000040802200000011c024231;
        assert_eq!(
            &dec(&t, ERA_BF).unwrap(),
            "@P0 HFMA2.BF16_V2 R0, R0.H0_H0, R0.H0_H0, R0.H0_H0"
        );
        assert_eq!(
            &dec(&t, ERA_5R).unwrap(),
            "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0"
        );
        // the live WRONG cell pre-fix (5-reg row winning the inert flip40
        // word) renders vendor-true post-delete:
        assert_eq!(
            &dec(&t, ERA_5R ^ (1 << 40)).unwrap(),
            "@P4 HFMA2 R2, R28.H0_H0, R1.H0_H0, R2.H0_H0"
        );
    }
}
