//! BUG-354 (F2-iter184, loop5/blind front2, 2026-09-02): sparse-leg
//! HFMA2 FI/II lattice (0x431 family) MOD-LANE closure -- mg family
//! {F32,FMZ,F32,FMZ,BF16_V2,BF16_V2,FMZ} x {plain,RELU} + 6 RELU _P
//! dotted keys on HFMA2_R_R_R_FI_FI, legs sm100a+sm103a (canonical graft
//! patch354.py, ride-after 5501a3b/BUG-353-fmt). Registered 354-kand LOW
//! at 329.md sec.6 (F2-iter176); hints iter182-184.
//!
//! MEASUREMENT (pre-fix publish cubit_py-13c09bf.so 9dce9a44.., canonical
//! 9717447; work/bug354/measure_pre354.json):
//!  (a) sparse DECODE of 30/30 mod-lane/RELU window words = LOUD HOLE
//!      (FI+II lattice); NO silent-mangle class on this window.
//!  (b) sparse ENCODE of 15/15 authored mod/RELU texts = loud REFUSE.
//!  (c) dense legs pre == vendor-exact 26/30 + 15/15 (era rows; the 4
//!      dense "holes" are doctrine INVALID3-285 / b91 / SATxRELU rc=1).
//! Graft corpus exposure: census354 battery ab240 2,406 cubins x4 legs
//! (window bits b76..b80 / b85 / [90:87] on lattice words).
//!
//! LAW: arb354 108 probes, nvdisasm 13.3.73 raw -b, x4 models
//! SM100a/103a/120/121a AGREE on EVERY probe;
//! work/bug354/arb354_verdicts.json. pv-law: pv=0..6 prints ', Pv';
//! pv=7+inv0 ELIDES; pv=7+inv1 prints ', !PT'; pv+inv ', !Pv'.
//! KILLS (stay HOLE fail-closed, all legs): SATxRELU any-combo (rc=1),
//! F32xBF16 (.INVALID3, 285 doctrine), b91 (rc=1), INVALID5/6 (hsel x
//! h0nh1), stray [90:87] w/o b79 (289 doctrine; vendor-INERT words).
//! SAT(b77)/FTZ(b80)/OOB(b76+b80) lanes measured legal x4 but BEYOND the
//! registered 354 scope -> registered 367-kand, stay HOLE on sparse.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
const B76: u128 = 1 << 76;
const B77: u128 = 1 << 77;
const B78: u128 = 1 << 78;
const B79: u128 = 1 << 79;
const B80: u128 = 1 << 80;
const B84: u128 = 1 << 84;
const B85: u128 = 1 << 85;
const B86: u128 = 1 << 86;
const B91: u128 = 1 << 91;
const H1: u128 = 0x3c00u128 << 48;
const BF1: u128 = 0x3f80u128 << 48;
const FI: u128 = 0x7431 | (2 << 16) | (3 << 24) | (4 << 64);
const II0: u128 = 0x0431 | (2 << 16) | (3 << 24) | (4 << 64);
const SPARSE: [&str; 2] = ["sm100a", "sm103a"];
const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    DecodeIndex::build(t)
        .decode(w & M96, 0, t)
        .map(|d| to_sass(&d))
        .ok()
        .map(|s| s.trim_end().trim_end_matches(';').to_string())
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}

#[test]
fn t354_1_structure_mirror_of_dense_delta_laws() {
    let base = &tab("sm100a").entries["HFMA2_R_R_R_FI_FI"].clone();
    for leg in SPARSE {
        let t = tab(leg);
        let e = &t.entries["HFMA2_R_R_R_FI_FI"];
        let want_mgs = [
            "",
            "F32",
            "FMZ",
            "F32,FMZ",
            "BF16_V2",
            "BF16_V2,FMZ",
            "RELU",
            "F32,RELU",
            "FMZ,RELU",
            "F32,FMZ,RELU",
            "BF16_V2,RELU",
            "BF16_V2,FMZ,RELU",
        ];
        // FLIP (BUG-367, F2-iter193, canonical 0933cf6): the sparse
        // lattice is complete now (SAT/FTZ/OOB closure +24 mgs; the
        // 354-scope delta laws below still hold verbatim on their own
        // names; the SAT/FTZ/OOB names are pinned by tests/bug367_*).
        assert_eq!(e.mod_groups.len(), 36, "{leg}: mg count drift");
        let pl = &e.mod_groups[""];
        for name in want_mgs {
            assert!(
                e.mod_groups.contains_key(name),
                "{leg}: mg {name:?} missing"
            );
            let mg = &e.mod_groups[name];
            if name.is_empty() {
                continue;
            }
            // exact ab delta law vs plain
            let want_bits: u128 = {
                let mut b = 0u128;
                if name.contains("F32") {
                    b |= B78;
                }
                if name.contains("FMZ") {
                    b |= B76;
                }
                if name.contains("BF16_V2") {
                    b |= B85;
                }
                if name.contains("RELU") {
                    b |= B79 | (0x7 << 87);
                }
                b
            };
            assert_eq!(
                mg.and_base ^ pl.and_base,
                want_bits,
                "{leg}:{name}: ab delta drift"
            );
            assert_eq!(
                mg.variable_mask, pl.variable_mask,
                "{leg}:{name}: vm delta drift"
            );
            // BF16 lanes: tok4/tok5 immediate read as bf16 (288-era swap)
            let bfcnt = mg
                .fields
                .iter()
                .filter(|f| f.extraction == Extraction::BF16)
                .count();
            let f16cnt = mg
                .fields
                .iter()
                .filter(|f| f.extraction == Extraction::F16)
                .count();
            if name.contains("BF16_V2") {
                assert_eq!((bfcnt, f16cnt), (2, 0), "{leg}:{name}: bf16 swap drift");
            } else {
                assert_eq!((bfcnt, f16cnt), (0, 2), "{leg}:{name}: f16 drift");
            }
            // RELU mg: pv7 bake, NO pred/inv fields (base-key lane)
            if name.contains("RELU") {
                assert!(
                    mg.fields.iter().all(|f| f.extraction != Extraction::Pred),
                    "{leg}:{name}: base RELU mg carries pred field"
                );
            }
            // 353/329 sign fields survive on every lane
            for (ext, sh, tok) in [
                (Extraction::Neg, 84, 3),
                (Extraction::Abs, 83, 3),
                (Extraction::H0NH1, 86, 3),
                (Extraction::Abs, 73, 2),
                (Extraction::HalfSel, 74, 2),
            ] {
                assert!(
                    mg.fields
                        .iter()
                        .any(|f| f.extraction == ext && f.shift == sh && f.token_idx == tok),
                    "{leg}:{name}: sign field {ext:?}@{sh} tok{tok} lost"
                );
            }
        }
        // dotted _P keys: geometry = non-RELU lane + b79, vm |0xf<<87, tok6 pred
        for mods in [
            "RELU",
            "F32.RELU",
            "FMZ.RELU",
            "F32.FMZ.RELU",
            "BF16_V2.RELU",
            "BF16_V2.FMZ.RELU",
        ] {
            let dk = format!("HFMA2.{mods}_R_R_R_FI_FI_P");
            let e2 = t
                .entries
                .get(&dk as &str)
                .unwrap_or_else(|| panic!("{leg}: dotted key {dk} missing"));
            let g = &e2.mod_groups[""];
            let lane_name = mods.replace('.', ",").replace(",RELU", "");
            let lane = if lane_name == "RELU" {
                &e.mod_groups[""]
            } else {
                &e.mod_groups[lane_name.as_str()]
            };
            assert_eq!(
                g.and_base,
                lane.and_base | B79,
                "{leg}:{dk}: ab drift (lane bits + b79, no pv7)"
            );
            assert_eq!(
                g.and_base & (0x7 << 87),
                0,
                "{leg}:{dk}: pv7 leaked into ab"
            );
            assert_eq!(
                g.variable_mask & (0xf << 87),
                0xf << 87,
                "{leg}:{dk}: pv window not in vm"
            );
            assert!(
                g.fields.iter().any(|f| f.extraction == Extraction::Pred
                    && f.shift == 87
                    && f.bits == 3
                    && f.token_idx == 6),
                "{leg}:{dk}: pred@87 tok6 missing"
            );
            assert!(
                g.fields
                    .iter()
                    .any(|f| f.extraction == Extraction::Inv && f.shift == 90 && f.token_idx == 6),
                "{leg}:{dk}: inv@90 tok6 missing"
            );
        }
    }
    let _ = base;
}

#[test]
fn t354_2_decode_law_x4() {
    // arb354 M/X/R/G/I in-scope battery, vendor texts verbatim.
    let fi_cases: [(u128, &str); 16] = [
        (B76 | H1, "HFMA2.FMZ R2, R3, R4, 1, 0"),
        (B78 | H1, "HFMA2.F32 R2, R3, R4, 1, 0"),
        (B76 | B78 | H1, "HFMA2.F32.FMZ R2, R3, R4, 1, 0"),
        (B85 | BF1, "HFMA2.BF16_V2 R2, R3, R4, 1, 0"),
        (B85 | B76 | BF1, "HFMA2.BF16_V2.FMZ R2, R3, R4, 1, 0"),
        (
            B85 | (0x3f81u128 << 48),
            "HFMA2.BF16_V2 R2, R3, R4, 1.0078125, 0",
        ),
        (B79, "HFMA2.RELU R2, R3, R4, 0, 0, P0"),
        (B79 | (1 << 87), "HFMA2.RELU R2, R3, R4, 0, 0, P1"),
        (B79 | (6 << 87), "HFMA2.RELU R2, R3, R4, 0, 0, P6"),
        (B79 | (7 << 87), "HFMA2.RELU R2, R3, R4, 0, 0"),
        (
            B79 | (7 << 87) | (1 << 90),
            "HFMA2.RELU R2, R3, R4, 0, 0, !PT",
        ),
        (B79 | B78 | H1, "HFMA2.F32.RELU R2, R3, R4, 1, 0, P0"),
        (
            B79 | B76 | (1 << 87) | H1,
            "HFMA2.FMZ.RELU R2, R3, R4, 1, 0, P1",
        ),
        (
            B79 | B85 | BF1 | (1 << 87),
            "HFMA2.BF16_V2.RELU R2, R3, R4, 1, 0, P1",
        ),
        (B78 | B84 | H1, "HFMA2.F32 R2, R3, -R4, 1, 0"),
        (B85 | B84 | BF1, "HFMA2.BF16_V2 R2, R3, -R4, 1, 0"),
    ];
    for leg in LEGS {
        let t = tab(leg);
        for (extra, want) in fi_cases {
            let got = dec(&t, FI | extra).unwrap_or_else(|| panic!("{leg}: HOLE on FI|{extra:#x}"));
            assert_eq!(got, want, "{leg}: FI decode drift {extra:#x}");
        }
        // II0 lattice siblings carry the '@P0 ' guard prefix
        for (extra, want) in [
            (B78 | H1, "@P0 HFMA2.F32 R2, R3, R4, 1, 0"),
            (B85 | BF1, "@P0 HFMA2.BF16_V2 R2, R3, R4, 1, 0"),
            (B79 | (1 << 87), "@P0 HFMA2.RELU R2, R3, R4, 0, 0, P1"),
            (
                B79 | B85 | BF1,
                "@P0 HFMA2.BF16_V2.RELU R2, R3, R4, 1, 0, P0",
            ),
        ] {
            let got =
                dec(&t, II0 | extra).unwrap_or_else(|| panic!("{leg}: HOLE on II0|{extra:#x}"));
            assert_eq!(got, want, "{leg}: II0 decode drift {extra:#x}");
        }
        // guard v15 = @!PT on the mod lane; g3 = @P3 RELU
        let got = dec(
            &t,
            (0x0431 | (0xf << 12) | (2 << 16) | (3 << 24) | (4 << 64)) | B78 | H1,
        )
        .unwrap();
        assert_eq!(
            got, "@!PT HFMA2.F32 R2, R3, R4, 1, 0",
            "{leg}: g15 F32 drift"
        );
        let got = dec(
            &t,
            (0x0431 | (3 << 12) | (2 << 16) | (3 << 24) | (4 << 64)) | B79 | (1 << 87),
        )
        .unwrap();
        assert_eq!(
            got, "@P3 HFMA2.RELU R2, R3, R4, 0, 0, P1",
            "{leg}: g3 RELU drift"
        );
    }
}

#[test]
fn t354_3_encode_word_exact_and_roundtrip_x4() {
    // golden words = pre-fix DENSE publish mints (sm120 era rows,
    // measure_pre354); post-graft every leg must mint the same word
    // (law x4-uniform).
    let cases: [(u128, &str); 15] = [
        (
            0xfc200000040040000000003027431,
            "HFMA2.F32 R2, R3, R4, 0, 0",
        ),
        (
            0xfc200000010040000000003027431,
            "HFMA2.FMZ R2, R3, R4, 0, 0",
        ),
        (
            0xfc200000050040000000003027431,
            "HFMA2.F32.FMZ R2, R3, R4, 0, 0",
        ),
        (
            0xfc200002000043f80000003027431,
            "HFMA2.BF16_V2 R2, R3, R4, 1, 0",
        ),
        (
            0xfc200002010043f80000003027431,
            "HFMA2.BF16_V2.FMZ R2, R3, R4, 1, 0",
        ),
        (
            0xfc200038080040000000003027431,
            "HFMA2.RELU R2, R3, R4, 0, 0",
        ),
        (
            0xfc200038080043c00000003027431,
            "HFMA2.RELU R2, R3, R4, 1, 0",
        ),
        (
            0xfc2000380c0043c00000003027431,
            "HFMA2.F32.RELU R2, R3, R4, 1, 0",
        ),
        (
            0xfc200038090040000000003027431,
            "HFMA2.FMZ.RELU R2, R3, R4, 0, 0",
        ),
        (
            0xfc20003a080043f80000003027431,
            "HFMA2.BF16_V2.RELU R2, R3, R4, 1, 0",
        ),
        (
            0xfc200000080040000000003027431,
            "HFMA2.RELU R2, R3, R4, 0, 0, P0",
        ),
        (
            0xfc200008080040000000003027431,
            "HFMA2.RELU R2, R3, R4, 0, 0, P1",
        ),
        (
            0xfc200040080040000000003027431,
            "HFMA2.RELU R2, R3, R4, 0, 0, !P0",
        ),
        (
            0xfc2000100c0043c00000003027431,
            "HFMA2.F32.RELU R2, R3, R4, 1, 0, P2",
        ),
        (
            0xfc20001b080043f80000003021431,
            "@P1 HFMA2.BF16_V2.RELU R2, R3, -R4, 1, 0, P3",
        ),
    ];
    for leg in LEGS {
        let t = tab(leg);
        for (want, text) in cases {
            let w = enc(&t, text).unwrap_or_else(|e| panic!("{leg}: REFUSE {text}: {e}"));
            assert_eq!(w & M96, want & M96, "{leg}: mint word drift {text}");
            let rt = dec(&t, w).unwrap_or_else(|| panic!("{leg}: HOLE reread {text}"));
            assert_eq!(rt, text, "{leg}: roundtrip drift {text}");
        }
    }
}

#[test]
fn t354_4_fail_closed_doctrine_x4() {
    for leg in LEGS {
        let t = tab(leg);
        for (extra, name) in [
            (B78 | B85 | H1, "INVALID3 (F32 x BF16, 285 doctrine)"),
            (B78 | B76 | B85 | H1, "INVALID3.FMZ"),
            (B91 | H1, "b91 kill"),
            (B91 | B79 | H1, "b91 x RELU"),
            (B77 | B79 | H1, "SAT x RELU kill"),
            (B77 | B78 | B79 | H1, "SAT x F32 x RELU kill"),
            ((1 << 81) | B86, "INVALID5 (hsel v1 x h0nh1)"),
            ((2 << 81) | B86, "INVALID6"),
        ] {
            assert!(
                dec(&t, FI | extra).is_none(),
                "{leg}: {name} decoded (doctrine breach)"
            );
        }
    }
    // stray [90:87] w/o b79 (289 doctrine): SPARSE stays HOLE (pre AND
    // post 354 -- the graft claims nothing there); DENSE prints the
    // vendor-inert plain form (pre-existing armed lane, verified both
    // pre/post on old_tabs + 5c12995; vendor prints the same text).
    for leg in SPARSE {
        let t = tab(leg);
        for extra in [1 << 87, 2 << 87, 7 << 87] {
            assert!(
                dec(&t, FI | extra).is_none(),
                "{leg}: stray [90:87] {extra:#x} decoded on sparse (289 breach)"
            );
        }
    }
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for extra in [1 << 87, 2 << 87, 7 << 87] {
            assert_eq!(
                dec(&t, FI | extra).as_deref(),
                Some("HFMA2 R2, R3, R4, 0, 0"),
                "{leg}: stray [90:87] {extra:#x} dense vendor-inert drift"
            );
        }
    }
    // FLIP (BUG-367, F2-iter193, canonical 0933cf6): the previously
    // registered contrast pin inverts -- 367 grafted the SAT/FTZ/OOB lane
    // family on the sparse legs (lattice completion vs dense; battery
    // tests/bug367_hfma2_sparse_satftz.rs). The sparse legs now decode
    // and mint these lanes == vendor law (x4).
    for leg in SPARSE {
        let t = tab(leg);
        for (extra, name, want) in [
            (B77 | H1, "SAT lane", "HFMA2.SAT R2, R3, R4, 1, 0"),
            (B80 | H1, "FTZ lane", "HFMA2.FTZ R2, R3, R4, 1, 0"),
            (B76 | B80 | H1, "OOB lane", "HFMA2.OOB R2, R3, R4, 1, 0"),
        ] {
            assert_eq!(
                dec(&t, FI | extra).as_deref(),
                Some(want),
                "{leg}: {name} post-367 decode drift"
            );
        }
        assert!(
            enc(&t, "HFMA2.SAT R2, R3, R4, 0, 0").is_ok(),
            "{leg}: sparse SAT mint refused post-367"
        );
    }
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        assert_eq!(
            dec(&t, FI | B77 | H1).as_deref(),
            Some("HFMA2.SAT R2, R3, R4, 1, 0"),
            "{leg}: dense SAT armed drift"
        );
    }
}

#[test]
fn t354_5_relu_pv_law_x4() {
    for leg in LEGS {
        let t = tab(leg);
        // armed pred values print explicitly, roundtrippable
        for pv in 0..=6u128 {
            let text = format!("HFMA2.RELU R2, R3, R4, 0, 0, P{pv}");
            let w = enc(&t, &text).unwrap_or_else(|e| panic!("{leg}: REFUSE {text}: {e}"));
            assert_eq!(w & B79, B79, "{leg}: {text} mint lost b79");
            assert_eq!((w >> 87) & 0x7, pv, "{leg}: {text} pv field drift");
            assert_eq!((w >> 90) & 0x1, 0, "{leg}: {text} inv drift");
            assert_eq!(dec(&t, w).unwrap(), text, "{leg}: {text} roundtrip");
        }
        // pv7+inv0 elides (both directions)
        let w = enc(&t, "HFMA2.RELU R2, R3, R4, 0, 0").unwrap();
        assert_eq!(
            (w >> 87) & 0xf,
            0x7,
            "{leg}: elided RELU mint without pv7 bake"
        );
        assert_eq!(
            dec(&t, w).unwrap(),
            "HFMA2.RELU R2, R3, R4, 0, 0",
            "{leg}: pv7 word prints un-elided"
        );
        // pv7+inv1 = '!PT'; pv+inv = '!Pv'
        let got = dec(&t, (FI | B79 | (7 << 87) | (1 << 90))).unwrap();
        assert_eq!(
            got, "HFMA2.RELU R2, R3, R4, 0, 0, !PT",
            "{leg}: !PT law drift"
        );
        let w = enc(&t, "HFMA2.RELU R2, R3, R4, 0, 0, !P2").unwrap();
        assert_eq!((w >> 87) & 0xf, 0xa, "{leg}: !P2 mint without inv bake");
        assert_eq!(
            dec(&t, w).unwrap(),
            "HFMA2.RELU R2, R3, R4, 0, 0, !P2",
            "{leg}: !P2 rt"
        );
        // inv carriers on other mod families compose (RLU _P dotted keys)
        let w = enc(&t, "HFMA2.BF16_V2.FMZ.RELU R2, R3, R4, 1, 0, P4").unwrap();
        assert_eq!(
            w & (B85 | B76 | B79),
            B85 | B76 | B79,
            "{leg}: BF16,FMZ.RELU bits"
        );
        assert_eq!(
            dec(&t, w).unwrap(),
            "HFMA2.BF16_V2.FMZ.RELU R2, R3, R4, 1, 0, P4",
            "{leg}: BF16,FMZ.RELU P4 rt"
        );
    }
}
