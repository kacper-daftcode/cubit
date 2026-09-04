//! BUG-367 (F2-iter193, loop5/blind front2, 2026-09-04): sparse-leg
//! HFMA2 FI/II lattice (0x431 family) SAT/FTZ/OOB lane closure =
//! completion of the 354 mod-lattice vs the DENSE row set -- 24 new mgs
//! (12 DIRECT + 6 BF16 + 6 RELU pv7-bake) + 6 RELU _P dotted keys on
//! HFMA2_R_R_R_FI_FI, legs sm100a+sm103a (canonical graft patch367.py,
//! fbcef1c -> 0933cf6; ENGINE src ZERO changes). Registered 367-kand
//! LOW at 354.md sec.6 (F2-iter184); hints iter185-192.
//!
//! MEASUREMENT (pre-fix publish cubit_py-8ae7c97.so 0aac6654..,
//! canonical fbcef1c; work/bug367/measure_pre367.json):
//!  (a) sparse DECODE of 91/91 in-scope window words = LOUD HOLE; ZERO
//!      WRONG cells (no silent-mangle class on this window).
//!  (b) sparse ENCODE of 27/27 authored texts = loud REFUSE.
//!  (c) dense legs pre == vendor-exact 91/91 + 26/27 (the 1 FAIL =
//!      'HFMA2.SAT.RELU' vendor kill rc=1 -- correct loud refuse).
//! Graft corpus exposure ZERO: census354 (battery ab240 2,406 cubins x4
//! legs) measured the exact graft window bits {76..80,85} + pv [90:87]
//! on 97,338 lattice words/leg -- empty.
//!
//! LAW: arb354 108 probes (18 in-scope of 367) + arb367 79-probe
//! extension (X2 8 / PV 12 / G 31 / S 12 / I 8 / K 6 / B 2), nvdisasm
//! 13.3.73 raw -b, x4 models SM100a/103a/120/121a AGREE on EVERY legal
//! probe, DIVERGENT=0 (work/bug367/arb367_verdicts.json). Print order
//! F32|BF16_V2 < FMZ < FTZ|OOB < SAT < RELU; OOB = fused rendering of
//! b76+b80 (no 'FMZ,FTZ' name exists; the bit pair IS OOB). pv-law on
//! FTZ/OOB RELU carriers == 354 law. KILLS stay HOLE fail-closed all
//! legs: SATxRELU any-combo incl xFTZ/xOOB (rc=1 x4), b91 x scope
//! (rc=1), F32xBF16 INVALID3-285, stray [90:87] w/o b79 (289 doctrine;
//! dense keeps its pre-existing vendor-inert armed lane).
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
const B90: u128 = 1 << 90;
const B91: u128 = 1 << 91;
const H1: u128 = 0x3c00u128 << 48;
const BF1: u128 = 0x3f80u128 << 48;
const FI: u128 = 0x7431 | (2 << 16) | (3 << 24) | (4 << 64);
const II0: u128 = 0x0431 | (2 << 16) | (3 << 24) | (4 << 64);
const NP: [&str; 12] = [
    "SAT",
    "FTZ",
    "OOB",
    "F32,SAT",
    "FMZ,SAT",
    "F32,FMZ,SAT",
    "F32,FTZ",
    "F32,OOB",
    "F32,FTZ,SAT",
    "F32,OOB,SAT",
    "FTZ,SAT",
    "OOB,SAT",
];
const NB: [&str; 6] = [
    "BF16_V2,SAT",
    "BF16_V2,FTZ",
    "BF16_V2,OOB",
    "BF16_V2,FMZ,SAT",
    "BF16_V2,FTZ,SAT",
    "BF16_V2,OOB,SAT",
];
const REL: [&str; 6] = [
    "FTZ,RELU",
    "OOB,RELU",
    "F32,FTZ,RELU",
    "F32,OOB,RELU",
    "BF16_V2,FTZ,RELU",
    "BF16_V2,OOB,RELU",
];
const DOT: [&str; 6] = [
    "FTZ.RELU",
    "OOB.RELU",
    "F32.FTZ.RELU",
    "F32.OOB.RELU",
    "BF16_V2.FTZ.RELU",
    "BF16_V2.OOB.RELU",
];
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
fn want_bits(name: &str) -> u128 {
    // name-parse law: OOB is the fused b76|b80 rendering; no name ever
    // carries FMZ or FTZ next to OOB on this lattice.
    let mut b = 0u128;
    let mut seen_oob = false;
    for part in name.split(',') {
        match part {
            "F32" => b |= B78,
            "FMZ" => b |= B76,
            "BF16_V2" => b |= B85,
            "SAT" => b |= B77,
            "FTZ" => b |= B80,
            "OOB" => {
                b |= B76 | B80;
                seen_oob = true;
            }
            "RELU" => b |= B79 | (0x7 << 87),
            other => panic!("want_bits: unknown part {other}"),
        }
    }
    if seen_oob {
        assert!(
            !name.split(',').any(|p| p == "FMZ" || p == "FTZ"),
            "fused OOB name carries FMZ/FTZ parts: {name}"
        );
    }
    b
}

#[test]
fn t367_1_structure_lattice_completion() {
    let dense = tab("sm120");
    let dnames: std::collections::BTreeSet<&String> = dense.entries["HFMA2_R_R_R_FI_FI"]
        .mod_groups
        .keys()
        .collect();
    for leg in SPARSE {
        let t = tab(leg);
        let e = &t.entries["HFMA2_R_R_R_FI_FI"];
        let snames: std::collections::BTreeSet<&String> = e.mod_groups.keys().collect();
        assert_eq!(
            snames, dnames,
            "{leg}: sparse mg name set != dense (lattice completion law)"
        );
        assert_eq!(e.mod_groups.len(), 36, "{leg}: mg count drift");
        let pl = &e.mod_groups[""];
        for name in NP.iter().chain(NB.iter()).chain(REL.iter()).copied() {
            let mg = &e.mod_groups[name];
            assert_eq!(
                mg.and_base ^ pl.and_base,
                want_bits(name),
                "{leg}:{name}: ab delta drift"
            );
            assert_eq!(
                mg.variable_mask, pl.variable_mask,
                "{leg}:{name}: vm delta drift"
            );
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
            if name.contains("RELU") {
                assert!(
                    mg.fields.iter().all(|f| f.extraction != Extraction::Pred),
                    "{leg}:{name}: base RELU mg carries pred field"
                );
            }
            // 353/329 sign basis survives on every new lane
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
        // dotted _P keys: all six new names, geometry = lane + b79
        // (no pv7), vm |0xf<<87, tok6 pred/inv
        for mods in DOT {
            let dk = format!("HFMA2.{mods}_R_R_R_FI_FI_P");
            let e2 = t
                .entries
                .get(&dk as &str)
                .unwrap_or_else(|| panic!("{leg}: dotted key {dk} missing"));
            let g = &e2.mod_groups[""];
            let lane_name = mods.replace('.', ",").replace(",RELU", "");
            let lane = &e.mod_groups[lane_name.as_str()];
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
}

#[test]
fn t367_2_decode_law_x4() {
    // arb354 367-scope + arb367 battery, vendor texts verbatim.
    let fi_cases: &[(u128, &str)] = &[
        (B77 | H1, "HFMA2.SAT R2, R3, R4, 1, 0"),
        (B80 | H1, "HFMA2.FTZ R2, R3, R4, 1, 0"),
        (B76 | B80 | H1, "HFMA2.OOB R2, R3, R4, 1, 0"),
        (B78 | B77 | H1, "HFMA2.F32.SAT R2, R3, R4, 1, 0"),
        (B76 | B77 | H1, "HFMA2.FMZ.SAT R2, R3, R4, 1, 0"),
        (B78 | B76 | B77 | H1, "HFMA2.F32.FMZ.SAT R2, R3, R4, 1, 0"),
        (B78 | B80 | H1, "HFMA2.F32.FTZ R2, R3, R4, 1, 0"),
        (B78 | B76 | B80 | H1, "HFMA2.F32.OOB R2, R3, R4, 1, 0"),
        (B80 | B77 | H1, "HFMA2.FTZ.SAT R2, R3, R4, 1, 0"),
        (B76 | B80 | B77 | H1, "HFMA2.OOB.SAT R2, R3, R4, 1, 0"),
        (B78 | B80 | B77 | H1, "HFMA2.F32.FTZ.SAT R2, R3, R4, 1, 0"),
        (
            B78 | B76 | B80 | B77 | H1,
            "HFMA2.F32.OOB.SAT R2, R3, R4, 1, 0",
        ),
        (B85 | B77 | BF1, "HFMA2.BF16_V2.SAT R2, R3, R4, 1, 0"),
        (B85 | B80 | BF1, "HFMA2.BF16_V2.FTZ R2, R3, R4, 1, 0"),
        (B85 | B76 | B80 | BF1, "HFMA2.BF16_V2.OOB R2, R3, R4, 1, 0"),
        (
            B85 | B76 | B77 | BF1,
            "HFMA2.BF16_V2.FMZ.SAT R2, R3, R4, 1, 0",
        ),
        (
            B85 | B80 | B77 | BF1,
            "HFMA2.BF16_V2.FTZ.SAT R2, R3, R4, 1, 0",
        ),
        (
            B85 | B76 | B80 | B77 | BF1,
            "HFMA2.BF16_V2.OOB.SAT R2, R3, R4, 1, 0",
        ),
        (
            B85 | B77 | (0x3f81u128 << 48),
            "HFMA2.BF16_V2.SAT R2, R3, R4, 1.0078125, 0",
        ),
        (B77 | B84 | H1, "HFMA2.SAT R2, R3, -R4, 1, 0"),
        (
            B77 | (1 << 73) | (1 << 83) | H1,
            "HFMA2.SAT R2, |R3|, |R4|, 1, 0",
        ),
        (
            B80 | B76 | (1 << 73) | (1 << 83) | H1,
            "HFMA2.OOB R2, |R3|, |R4|, 1, 0",
        ),
        (B80 | B79 | (1 << 87), "HFMA2.FTZ.RELU R2, R3, R4, 0, 0, P1"),
        (
            B76 | B80 | B79 | (1 << 87),
            "HFMA2.OOB.RELU R2, R3, R4, 0, 0, P1",
        ),
        (B80 | B79 | (7 << 87), "HFMA2.FTZ.RELU R2, R3, R4, 0, 0"),
        (
            B80 | B79 | (7 << 87) | B90,
            "HFMA2.FTZ.RELU R2, R3, R4, 0, 0, !PT",
        ),
        (
            B78 | B80 | B79 | (1 << 87) | H1,
            "HFMA2.F32.FTZ.RELU R2, R3, R4, 1, 0, P1",
        ),
        (
            B78 | B76 | B80 | B79 | (1 << 87) | H1,
            "HFMA2.F32.OOB.RELU R2, R3, R4, 1, 0, P1",
        ),
        (
            B85 | B80 | B79 | (1 << 87) | BF1,
            "HFMA2.BF16_V2.FTZ.RELU R2, R3, R4, 1, 0, P1",
        ),
        (
            B85 | B76 | B80 | B79 | (2 << 87) | B90 | BF1,
            "HFMA2.BF16_V2.OOB.RELU R2, R3, R4, 1, 0, !P2",
        ),
    ];
    for leg in LEGS {
        let t = tab(leg);
        for (extra, want) in fi_cases {
            let got = dec(&t, FI | extra).unwrap_or_else(|| panic!("{leg}: HOLE on FI|{extra:#x}"));
            assert_eq!(got, *want, "{leg}: FI decode drift {extra:#x}");
        }
        // II0 lattice siblings carry the guard prefix
        for (extra, want) in [
            (B77 | H1, "@P0 HFMA2.SAT R2, R3, R4, 1, 0"),
            (B80 | H1, "@P0 HFMA2.FTZ R2, R3, R4, 1, 0"),
            (B76 | B80 | H1, "@P0 HFMA2.OOB R2, R3, R4, 1, 0"),
            (B78 | B77 | H1, "@P0 HFMA2.F32.SAT R2, R3, R4, 1, 0"),
            (B85 | B77 | BF1, "@P0 HFMA2.BF16_V2.SAT R2, R3, R4, 1, 0"),
            (
                B80 | B79 | (1 << 87),
                "@P0 HFMA2.FTZ.RELU R2, R3, R4, 0, 0, P1",
            ),
            (
                B76 | B80 | B79 | (1 << 87),
                "@P0 HFMA2.OOB.RELU R2, R3, R4, 0, 0, P1",
            ),
            (
                B78 | B80 | B79 | (1 << 87) | H1,
                "@P0 HFMA2.F32.FTZ.RELU R2, R3, R4, 1, 0, P1",
            ),
        ] {
            let got =
                dec(&t, II0 | extra).unwrap_or_else(|| panic!("{leg}: HOLE on II0|{extra:#x}"));
            assert_eq!(got, want, "{leg}: II0 decode drift {extra:#x}");
        }
        // guard g15 = @!PT on the new lanes
        let g15 = 0x0431u128 | (0xf << 12) | (2 << 16) | (3 << 24) | (4 << 64);
        let got = dec(&t, g15 | B77 | H1).unwrap();
        assert_eq!(
            got, "@!PT HFMA2.SAT R2, R3, R4, 1, 0",
            "{leg}: g15 SAT drift"
        );
        let got = dec(&t, g15 | B80 | B79 | (1 << 87)).unwrap();
        assert_eq!(
            got, "@!PT HFMA2.FTZ.RELU R2, R3, R4, 0, 0, P1",
            "{leg}: g15 FTZ.RELU drift"
        );
        let got = dec(
            &t,
            (0x0431u128 | (3 << 12) | (2 << 16) | (3 << 24) | (4 << 64)) | B76 | B80 | H1,
        )
        .unwrap();
        assert_eq!(got, "@P3 HFMA2.OOB R2, R3, R4, 1, 0", "{leg}: g3 OOB drift");
    }
}

#[test]
fn t367_3_encode_word_exact_and_roundtrip_x4() {
    // golden words = pre-fix DENSE publish mints (sm120 era rows,
    // measure_pre367 harvest; nvdisasm re-decode cross-checked there);
    // post-graft every leg must mint the same word (law x4-uniform).
    let cases: &[(u128, &str)] = &[
        (0x000020043c00000003027431, "HFMA2.SAT R2, R3, R4, 1, 0"),
        (0x000100043c00000003027431, "HFMA2.FTZ R2, R3, R4, 1, 0"),
        (0x000110043c00000003027431, "HFMA2.OOB R2, R3, R4, 1, 0"),
        (0x000060043c00000003027431, "HFMA2.F32.SAT R2, R3, R4, 1, 0"),
        (0x000030043c00000003027431, "HFMA2.FMZ.SAT R2, R3, R4, 1, 0"),
        (
            0x000070043c00000003027431,
            "HFMA2.F32.FMZ.SAT R2, R3, R4, 1, 0",
        ),
        (0x000140043c00000003027431, "HFMA2.F32.FTZ R2, R3, R4, 1, 0"),
        (0x000150043c00000003027431, "HFMA2.F32.OOB R2, R3, R4, 1, 0"),
        (0x000120043c00000003027431, "HFMA2.FTZ.SAT R2, R3, R4, 1, 0"),
        (0x000130043c00000003027431, "HFMA2.OOB.SAT R2, R3, R4, 1, 0"),
        (
            0x000160043c00000003027431,
            "HFMA2.F32.FTZ.SAT R2, R3, R4, 1, 0",
        ),
        (
            0x000170043c00000003027431,
            "HFMA2.F32.OOB.SAT R2, R3, R4, 1, 0",
        ),
        (
            0x002020043f80000003027431,
            "HFMA2.BF16_V2.SAT R2, R3, R4, 1, 0",
        ),
        (
            0x002100043f80000003027431,
            "HFMA2.BF16_V2.FTZ R2, R3, R4, 1, 0",
        ),
        (
            0x002110043f80000003027431,
            "HFMA2.BF16_V2.OOB R2, R3, R4, 1, 0",
        ),
        (
            0x002030043f80000003027431,
            "HFMA2.BF16_V2.FMZ.SAT R2, R3, R4, 1, 0",
        ),
        (
            0x002120043f80000003027431,
            "HFMA2.BF16_V2.FTZ.SAT R2, R3, R4, 1, 0",
        ),
        (
            0x002130043f80000003027431,
            "HFMA2.BF16_V2.OOB.SAT R2, R3, R4, 1, 0",
        ),
        (
            0x008180040000000003027431,
            "HFMA2.FTZ.RELU R2, R3, R4, 0, 0, P1",
        ),
        (
            0x008190040000000003027431,
            "HFMA2.OOB.RELU R2, R3, R4, 0, 0, P1",
        ),
        (
            0x0081c0043c00000003027431,
            "HFMA2.F32.FTZ.RELU R2, R3, R4, 1, 0, P1",
        ),
        (
            0x0081d0043c00000003027431,
            "HFMA2.F32.OOB.RELU R2, R3, R4, 1, 0, P1",
        ),
        (
            0x00a180043f80000003027431,
            "HFMA2.BF16_V2.FTZ.RELU R2, R3, R4, 1, 0, P1",
        ),
        (
            0x00a190043f80000003027431,
            "HFMA2.BF16_V2.OOB.RELU R2, R3, R4, 1, 0, P1",
        ),
        (
            0x031180040000000003027431,
            "HFMA2.FTZ.RELU R2, R3, -R4, 0, 0, P6",
        ),
        (0x000022043c00000003027431, "HFMA2.SAT R2, |R3|, R4, 1, 0"),
    ];
    for leg in LEGS {
        let t = tab(leg);
        for (want, text) in cases {
            let w = enc(&t, text).unwrap_or_else(|e| panic!("{leg}: REFUSE {text}: {e}"));
            assert_eq!(w & M96, *want & M96, "{leg}: mint word drift {text}");
            let rt = dec(&t, w).unwrap_or_else(|| panic!("{leg}: HOLE reread {text}"));
            assert_eq!(rt, *text, "{leg}: roundtrip drift {text}");
        }
    }
}

#[test]
fn t367_4_fail_closed_doctrine_x4() {
    for leg in LEGS {
        let t = tab(leg);
        for (extra, name) in [
            (B77 | B79 | H1, "SAT x RELU kill"),
            (B77 | B79 | B80 | H1, "SAT x RELU x FTZ kill"),
            (B77 | B79 | B76 | B80 | H1, "SAT x RELU x OOB kill"),
            (B77 | B78 | B79 | H1, "SAT x F32 x RELU kill"),
            (B91 | B77 | H1, "b91 x SAT kill"),
            (B91 | B80 | B79, "b91 x FTZ.RELU kill"),
            (B78 | B85 | H1, "INVALID3 (F32 x BF16, 285 doctrine)"),
            (B91 | H1, "b91 kill"),
        ] {
            assert!(
                dec(&t, FI | extra).is_none(),
                "{leg}: {name} decoded (doctrine breach)"
            );
        }
        // vendor rc=1 combos refuse loudly on the encode side too
        for text in [
            "HFMA2.SAT.RELU R2, R3, R4, 0, 0, P1",
            "HFMA2.SAT.RELU R2, R3, R4, 0, 0",
            "HFMA2.F32.FTZ.SAT.RELU R2, R3, R4, 1, 0",
        ] {
            assert!(enc(&t, text).is_err(), "{leg}: kill mint accepted: {text}");
        }
    }
    // stray [90:87] w/o b79 on a SAT carrier (289 doctrine): SPARSE stays
    // HOLE; DENSE keeps its pre-existing vendor-inert armed lane (vendor
    // prints the same plain form, arb367 K-group x4 rc=0).
    for leg in SPARSE {
        let t = tab(leg);
        for extra in [B90, 2 << 87] {
            assert!(
                dec(&t, FI | B77 | extra).is_none(),
                "{leg}: stray {extra:#x} x SAT decoded on sparse (289 breach)"
            );
        }
    }
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for extra in [B90, 2 << 87] {
            assert_eq!(
                dec(&t, FI | B77 | H1 | extra).as_deref(),
                Some("HFMA2.SAT R2, R3, R4, 1, 0"),
                "{leg}: dense stray x SAT vendor-inert drift"
            );
        }
    }
}

#[test]
fn t367_5_pv_law_new_carriers_x4() {
    for leg in LEGS {
        let t = tab(leg);
        for mods in ["FTZ", "OOB"] {
            // armed pred values print explicitly, roundtrippable
            for pv in 0..=6u128 {
                let text = format!("HFMA2.{mods}.RELU R2, R3, R4, 0, 0, P{pv}");
                let w = enc(&t, &text).unwrap_or_else(|e| panic!("{leg}: REFUSE {text}: {e}"));
                let fbits: u128 = if mods == "FTZ" { B80 } else { B76 | B80 };
                assert_eq!(w & B79, B79, "{leg}: {text} mint lost b79");
                assert_eq!(w & fbits, fbits, "{leg}: {text} mint lost lane bits");
                assert_eq!((w >> 87) & 0x7, pv, "{leg}: {text} pv field drift");
                assert_eq!((w >> 90) & 0x1, 0, "{leg}: {text} inv drift");
                assert_eq!(dec(&t, w).unwrap(), text, "{leg}: {text} roundtrip");
            }
            // pv7+inv0 elides (both directions)
            let text = format!("HFMA2.{mods}.RELU R2, R3, R4, 0, 0");
            let w = enc(&t, &text).unwrap();
            assert_eq!((w >> 87) & 0x7, 0x7, "{leg}: elided mint without pv7 bake");
            assert_eq!((w >> 90) & 0x1, 0, "{leg}: elided mint with inv set");
            assert_eq!(
                dec(&t, w).unwrap(),
                text,
                "{leg}: pv7 word prints un-elided"
            );
            // pv7+inv1 = '!PT'; pv+inv = '!Pv'
            let fbits: u128 = if mods == "FTZ" { B80 } else { B76 | B80 };
            let got = dec(&t, FI | fbits | B79 | (7 << 87) | B90).unwrap();
            assert_eq!(got, format!("{text}, !PT"), "{leg}: !PT law drift");
            let text2 = format!("HFMA2.{mods}.RELU R2, R3, R4, 0, 0, !P4");
            let w = enc(&t, &text2).unwrap();
            assert_eq!((w >> 87) & 0x7, 0x4, "{leg}: !P4 mint pv drift");
            assert_eq!((w >> 90) & 0x1, 0x1, "{leg}: !P4 mint without inv");
            assert_eq!(dec(&t, w).unwrap(), text2, "{leg}: !P4 rt");
        }
        // composes on F32/BF16 carriers + sign lanes
        let w = enc(&t, "HFMA2.BF16_V2.FTZ.RELU R2, R3, R4, 1, 0, P4").unwrap();
        assert_eq!(
            w & (B85 | B80 | B79),
            B85 | B80 | B79,
            "{leg}: BF16,FTZ.RELU bits"
        );
        assert_eq!(
            dec(&t, w).unwrap(),
            "HFMA2.BF16_V2.FTZ.RELU R2, R3, R4, 1, 0, P4",
            "{leg}: BF16,FTZ.RELU P4 rt"
        );
        let w = enc(&t, "HFMA2.F32.OOB.RELU R2, R3, -R4, 1, 0, !P6").unwrap();
        assert_eq!(
            w & (B78 | B76 | B80 | B79 | B84),
            B78 | B76 | B80 | B79 | B84,
            "{leg}: F32,OOB.RELU tok3neg bits"
        );
        assert_eq!(
            dec(&t, w).unwrap(),
            "HFMA2.F32.OOB.RELU R2, R3, -R4, 1, 0, !P6",
            "{leg}: F32,OOB.RELU -R4 !P6 rt"
        );
    }
}
