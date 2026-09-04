//! BUG-329 (F2-iter176, loop5/blind front2, 2026-09-01): sparse-leg FI_FI
//! tok2 sign-window closure -- +abs@73 tok2 + hsel[75:74] tok2 on
//! HFMA2_R_R_R_FI_FI mg '', legs sm100a+sm103a (canonical 65a6aab,
//! ride-after 4a46e95/BUG-330). Registered 329-kand LOW at F2-iter165
//! (312 report sec.6).
//!
//! MEASUREMENT REFINEMENT (publish f77bb8e, canonical 2761da4;
//! work/bug329/measure_pre329.json):
//!  (a) pre-fix sparse decode of FI-lattice tok2-hsel words printed PLAIN
//!      -- SILENT MODIFIER DROP (vendor: '.H0_H0'/'.H1_H1'/'.INVALID1');
//!      graft = REAL wrong-text fix.
//!  (b) pre-fix sparse encode of authored 'R3.H0_H0' = loud REFUSE
//!      (312-D4); graft arms (mint now vendor-equal / dense-equal).
//!  (c) tok2 abs@73 was already decode/encode-exact via the generic sign
//!      rescue; graft = FIELD-CLOSURE (320/327-era mechanism).
//!  (d) sparse II_FI KEY deliberately NOT cloned (NEGATYW by data):
//!      guard!=7 FI-lattice words already decode+encode vendor-equal via
//!      the FI_FI row (guard engine-generic; match excludes [15:12]) --
//!      a second row on the same match surface buys zero corpus and adds
//!      election risk. Sparse tok3-sign lanes (neg@84/abs@83/hsel@81/
//!      h0nh1@86) stay LOUD holes (fail-closed) = 353-kand.
//!
//! LAW: arb329 71 probes nvdisasm 13.3.73 raw -b, x4 models agree on
//! EVERY probe + arb312 L2..L5; work/bug329/arb329_verdicts.json.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
const B72: u128 = 1 << 72;
const B73: u128 = 1 << 73;
const B78: u128 = 1 << 78;
const B79: u128 = 1 << 79;
const B83: u128 = 1 << 83;
const B84: u128 = 1 << 84;
const B85: u128 = 1 << 85;
const B86: u128 = 1 << 86;
const H1: u128 = 0x3c00u128 << 48; // f16 1.0 @ tok4 window
const BF1: u128 = 0x3f80u128 << 48; // bf16 1.0 @ tok4 window
// FI lattice (0x7431, guard pinned PT): R2@16, R3@24, R4@64
const FI: u128 = 0x7431 | (2 << 16) | (3 << 24) | (4 << 64);
// II lattice (0x0431, guard @15:12): same registers, guard 0 = @P0
const II0: u128 = 0x0431 | (2 << 16) | (3 << 24) | (4 << 64);

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
fn t329_1_structure_graft_and_siblings() {
    // sparse legs: exactly the two grafted fields, nothing else new
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        let e = &t.entries["HFMA2_R_R_R_FI_FI"];
        // FLIP 2026-09-02 (BUG-354, attribution): mod-lane closure landed
        // (11 mgs + 6 dotted _P keys, canonical 5c12995; battery
        // tests/bug354_*). mg '' docelowo same 12 fields jak dotychczas.
        // FLIP (BUG-367, F2-iter193, canonical 0933cf6): SAT/FTZ/OOB lane
        // closure 12 -> 36 (lattice completion vs dense; tests/bug367_*).
        assert_eq!(e.mod_groups.len(), 36, "{leg}: mg set drift (post-367=36)");
        let mg = &e.mod_groups[""];
        let has = |ext: Extraction, shift: u32, tok: i32| {
            mg.fields
                .iter()
                .filter(|f| f.extraction == ext && f.shift == shift && f.token_idx == tok)
                .count()
        };
        assert_eq!(has(Extraction::Abs, 73, 2), 1, "{leg}: abs@73 tok2 count");
        assert_eq!(
            has(Extraction::HalfSel, 74, 2),
            1,
            "{leg}: hsel@74 tok2 count"
        );
        assert_eq!(has(Extraction::Neg, 72, 2), 1, "{leg}: neg@72 tok2 lost");
        // BUG-353 flip (canonical 9717447, attributed): tok3 sign window
        // grafted onto mg '' (mirror of dense 279/271 geometry): 8->12 fields.
        assert_eq!(
            mg.fields.len(),
            12,
            "{leg}: field count drift (post-353: 12)"
        );
        // 353 A-LAW: tok3 sign lanes armed exactly once each
        for (ext, sh) in [
            (Extraction::Neg, 84),
            (Extraction::Abs, 83),
            (Extraction::HalfSel, 81),
            (Extraction::H0NH1, 86),
        ] {
            assert_eq!(has(ext, sh, 3), 1, "{leg}: tok3 lane @{sh} missing (353)");
        }
        assert_eq!(
            mg.and_base & (0b111u128 << 73),
            0,
            "{leg}: ab carries graft bits"
        );
        assert_eq!(
            mg.variable_mask & (0b111u128 << 73),
            0b111u128 << 73,
            "{leg}: vm mirror missing"
        );
        // 329-NEGATYW pin: no II_FI key on sparse legs
        assert!(
            !t.entries.contains_key("HFMA2_R_R_R_II_FI"),
            "{leg}: II_FI key materialized (329-NEGATYW)"
        );
    }
    // dense legs: byte-stable siblings (own the lanes since BUG-288)
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        let mg = &t.entries["HFMA2_R_R_R_FI_FI"].mod_groups[""];
        assert_eq!(mg.fields.len(), 12, "{leg}: dense FI_FI '' field drift");
    }
}

#[test]
fn t329_2_decode_law_vendor_equal_x4() {
    // (lattice, extra-bits, expected vendor text) -- arb329 F/S/T groups
    let cases: &[(u128, u128, &str)] = &[
        (FI, B73, "HFMA2 R2, |R3|, R4, 0, 0"),
        (FI, 2 << 74, "HFMA2 R2, R3.H0_H0, R4, 0, 0"),
        (FI, 3 << 74, "HFMA2 R2, R3.H1_H1, R4, 0, 0"),
        (FI, 1 << 74, "HFMA2 R2, R3.INVALID1, R4, 0, 0"),
        (FI, B72 | B73, "HFMA2 R2, -|R3|, R4, 0, 0"),
        (FI, (2 << 74) | B73, "HFMA2 R2, |R3|.H0_H0, R4, 0, 0"),
        (FI, (3 << 74) | B72, "HFMA2 R2, -R3.H1_H1, R4, 0, 0"),
        (FI, H1, "HFMA2 R2, R3, R4, 1, 0"),
        (FI, H1 | B73, "HFMA2 R2, |R3|, R4, 1, 0"),
        (FI, H1 | (2 << 74), "HFMA2 R2, R3.H0_H0, R4, 1, 0"),
        (
            FI,
            H1 | (2 << 74) | (0x3c00u128 << 32),
            "HFMA2 R2, R3.H0_H0, R4, 1, 1",
        ),
        // II lattice g0 (guard!=7): same lanes, predicated print
        (II0, B73, "@P0 HFMA2 R2, |R3|, R4, 0, 0"),
        (II0, 2 << 74, "@P0 HFMA2 R2, R3.H0_H0, R4, 0, 0"),
        (II0, 3 << 74, "@P0 HFMA2 R2, R3.H1_H1, R4, 0, 0"),
        (II0, 1 << 74, "@P0 HFMA2 R2, R3.INVALID1, R4, 0, 0"),
        (II0, H1, "@P0 HFMA2 R2, R3, R4, 1, 0"),
        (II0, H1 | (2 << 74), "@P0 HFMA2 R2, R3.H0_H0, R4, 1, 0"),
    ];
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        for (base, extra, want) in cases {
            let got = dec(&t, base | extra)
                .unwrap_or_else(|| panic!("{leg}: HOLE on base={base:#x} extra={extra:#x}"));
            assert_eq!(
                &got, want,
                "{leg}: decode law drift base={base:#x} extra={extra:#x}"
            );
        }
    }
    // BF16_V2 FI cross: FLIP 2026-09-02 (BUG-354, attribution) -- was
    // dense-only (sparse FI_FI carried mg '' only); 354 grafted the mod
    // family on the sparse legs (law arb354 x4), so the cross is x4 now.
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        for (extra, want) in [
            (B85 | BF1, "HFMA2.BF16_V2 R2, R3, R4, 1, 0"),
            (
                B85 | BF1 | (2 << 74),
                "HFMA2.BF16_V2 R2, R3.H0_H0, R4, 1, 0",
            ),
        ] {
            assert_eq!(
                &dec(&t, FI | extra).unwrap(),
                want,
                "{leg}: BF16 drift {extra:#x}"
            );
        }
    }
    // FLIP 2026-09-02 (BUG-354, attribution): sparse mod lanes ARMED
    // (were LOUD holes pre-354); full battery = tests/bug354 t354_2.
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert_eq!(
            dec(&t, FI | B85 | BF1).as_deref(),
            Some("HFMA2.BF16_V2 R2, R3, R4, 1, 0"),
            "{leg}: sparse BF16 lane post-354 drift"
        );
    }
}

#[test]
fn t329_3_guard_sweep_compose_x4() {
    // guard map (arb327/arb329 x4): v<7 '@Pv' / 7 PT-plain / 8..14 '@!P(v-8)' / 15 '@!PT'
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        for (g, want) in [
            (0u128 << 12, "@P0 HFMA2 R2, R3.H0_H0, R4, 0, 0"),
            (3u128 << 12, "@P3 HFMA2 R2, R3.H0_H0, R4, 0, 0"),
            (7u128 << 12, "HFMA2 R2, R3.H0_H0, R4, 0, 0"),
            (9u128 << 12, "@!P1 HFMA2 R2, R3.H0_H0, R4, 0, 0"),
            (0xfu128 << 12, "@!PT HFMA2 R2, R3.H0_H0, R4, 0, 0"),
        ] {
            let w = (FI & !(0xfu128 << 12)) | g | (2 << 74);
            assert_eq!(
                &dec(&t, w).unwrap(),
                want,
                "{leg}: guard {g:#x} compose drift"
            );
        }
    }
}

#[test]
fn t329_4_encode_word_exact_and_roundtrip_x4() {
    // dense mint pre == post == sparse mint post (cross-leg parity)
    let cases: &[(u128, &str)] = &[
        (0xfc200000000040000000003027431, "HFMA2 R2, R3, R4, 0, 0"),
        (0xfc200000002040000000003027431, "HFMA2 R2, |R3|, R4, 0, 0"),
        (
            0xfc200000008040000000003027431,
            "HFMA2 R2, R3.H0_H0, R4, 0, 0",
        ),
        (
            0xfc20000000c040000000003027431,
            "HFMA2 R2, R3.H1_H1, R4, 0, 0",
        ),
        (0xfc200000003040000000003027431, "HFMA2 R2, -|R3|, R4, 0, 0"),
        (0xfc200000000043c00000003027431, "HFMA2 R2, R3, R4, 1, 0"),
        (
            0xfc200000000043e00c00003020431,
            "@P0 HFMA2 R2, R3, R4, 1.5, -2",
        ),
    ];
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        for (want_w, text) in cases {
            let w = enc(&t, text).unwrap_or_else(|e| panic!("{leg}: REFUSE on {text:?}: {e}"));
            assert_eq!(w & M96, want_w & M96, "{leg}: mint drift on {text:?}");
            let back = dec(&t, w).unwrap_or_else(|| panic!("{leg}: mint HOLE on {text:?}"));
            assert_eq!(&back, text, "{leg}: roundtrip drift on {text:?}");
        }
    }
}

#[test]
fn t329_5_fail_closed_residuum_and_edges() {
    // BUG-353 flip (canonical 9717447, attributed): the tok3-sign + h0nh1
    // residuum lanes are ARMED with vendor-exact text (353 pin file carries
    // the full x4 law battery; here: re-anchor the former HOLE list).
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        for (base, extra, want) in [
            (FI, B84, "HFMA2 R2, R3, -R4, 0, 0"),
            (FI, B83, "HFMA2 R2, R3, |R4|, 0, 0"),
            (FI, 1u128 << 81, "HFMA2 R2, R3, R4.F32, 0, 0"),
            (FI, 2u128 << 81, "HFMA2 R2, R3, R4.H0_H0, 0, 0"),
            (FI, B86, "HFMA2 R2, R3, R4.H0_NH1, 0, 0"),
            (II0, B84, "@P0 HFMA2 R2, R3, -R4, 0, 0"),
            (II0, 2u128 << 81, "@P0 HFMA2 R2, R3, R4.H0_H0, 0, 0"),
        ] {
            assert_eq!(
                &dec(&t, base | extra).unwrap(),
                want,
                "{leg}: 353-armed lane drift {extra:#x}"
            );
        }
        // FLIP 2026-09-02 (BUG-354, attribution): the F32/RELU residua
        // are CURED (354 mod-lane closure, arb354 x4; canonical 5c12995);
        // the stray [90:87] zarodek w/o b79 stays LOUD hole (289 doctrine).
        for (base, extra, name, want) in [
            (FI, B78, "F32 mod lane", "HFMA2.F32 R2, R3, R4, 0, 0"),
            (FI, B79, "RELU era lane", "HFMA2.RELU R2, R3, R4, 0, 0, P0"),
        ] {
            assert_eq!(
                dec(&t, base | extra).as_deref(),
                Some(want),
                "{leg}: {name} post-354 armed drift {extra:#x}"
            );
        }
        assert!(
            dec(&t, II0 | H1 | (1u128 << 87)).is_none(),
            "{leg}: 330 zarodek b87 decoded on sparse (289 doctrine breach)"
        );
        // BUG-353 flip (attributed): tok3-hsel authored encode is ARMED
        let w_hh = enc(&t, "HFMA2 R2, R3, R4.H0_H0, 0, 0").expect("353: tok3 hsel mint must mint");
        assert_eq!(
            dec(&t, w_hh).as_deref(),
            Some("HFMA2 R2, R3, R4.H0_H0, 0, 0"),
            "{leg}: tok3 hsel roundtrip drift (353-armed)"
        );
        // 355-kand CURED ON THIS ROW BY BUG-353 (attributed flip; the
        // registry item stays sev-review for the general class): pre-graft
        // sparse encode of tok3 neg/abs MINTED fold words vendor read as
        // 'R4, -0.0' / 'R4, 2'; the grafted neg@84/abs@83 fields now mint
        // the sign bits and roundtrip vendor-exact (dense-word pins live
        // in bug353 pin t353_4).
        let wneg = enc(&t, "HFMA2 R2, R3, -R4, 0, 0").expect("353: refuses?");
        let wabs = enc(&t, "HFMA2 R2, R3, |R4|, 0, 0").expect("353: refuses?");
        assert_eq!(
            dec(&t, wneg).as_deref(),
            Some("HFMA2 R2, R3, -R4, 0, 0"),
            "{leg}: 355-cured neg lane regression"
        );
        assert_eq!(
            dec(&t, wabs).as_deref(),
            Some("HFMA2 R2, R3, |R4|, 0, 0"),
            "{leg}: 355-cured abs lane regression"
        );
    }
    // INVALID3 doctrine (285): F32 x BF16 stays HOLE on ALL legs
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        assert!(
            dec(&t, II0 | B78 | B85 | H1).is_none(),
            "{leg}: INVALID3 lane decoded (285 doctrine breach)"
        );
    }
}
