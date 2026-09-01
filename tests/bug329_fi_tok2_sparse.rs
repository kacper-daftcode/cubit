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
        assert_eq!(e.mod_groups.len(), 1, "{leg}: mg set drift");
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
        assert_eq!(mg.fields.len(), 8, "{leg}: field count drift (6->2 graft)");
        // 353 residuum: tok3 sign lanes stay unfielded
        for (ext, sh) in [
            (Extraction::Neg, 84),
            (Extraction::Abs, 83),
            (Extraction::HalfSel, 81),
            (Extraction::H0NH1, 86),
        ] {
            assert_eq!(has(ext, sh, 3), 0, "{leg}: tok3 lane armed @{sh}");
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
    // BF16_V2 FI cross: dense-only (sparse FI_FI carries mg '' only;
    // mod-lane family coverage = 354-kand, arb329 F-group x4-legal)
    for leg in ["sm120", "sm121a"] {
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
    // sparse mod lanes stay LOUD holes (354-kand)
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert!(
            dec(&t, FI | B85 | BF1).is_none(),
            "{leg}: sparse BF16 lane decoded"
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
    // 353-kand residuum: tok3-sign + h0nh1 lanes stay LOUD holes on sparse
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        for (base, extra, name) in [
            (FI, B84, "tok3 neg"),
            (FI, B83, "tok3 abs"),
            (FI, 1u128 << 81, "tok3 hsel v1"),
            (FI, 2u128 << 81, "tok3 hsel v2"),
            (FI, B86, "tok3 h0nh1"),
            (II0, B84, "II tok3 neg"),
            (II0, 2u128 << 81, "II tok3 hsel"),
            (FI, B78, "F32 mod lane (no sparse mg)"),
            (FI, B79, "RELU era lane (dense-only key)"),
            (II0, H1 | (1u128 << 87), "330 zarodek b87 (dense-armed)"),
        ] {
            assert!(
                dec(&t, base | extra).is_none(),
                "{leg}: {name} decoded on sparse (fail-closed breach {extra:#x})"
            );
        }
        // tok3-hsel authored encode stays loud REFUSE (fail-closed)
        assert!(
            enc(&t, "HFMA2 R2, R3, R4.H0_H0, 0, 0").is_err(),
            "{leg}: tok3 hsel mint accepted"
        );
        // 355-kand REGISTRATION WATCH (pre==post, NOT fixed by 329):
        // sparse encode of tok3 neg/abs MINTS words that do NOT roundtrip
        // to the authored text -- silent intent mangle on the generic emit
        // lane (publish f77bb8e words 0xfc200000000048000000003027431 /
        // 0xfc200000000044000000003027431; vendor reads '-R4' mint as
        // 'R4, -0.0' and '|R4|' mint as 'R4, 2'; nvdisasm 13.3.73 raw -b).
        // Semantic pin, byte-agnostic: the mangle must not become a silent
        // correct roundtrip without attribution. When a real fix lands,
        // this pin flips to assert the correct text.
        let wneg = enc(&t, "HFMA2 R2, R3, -R4, 0, 0").expect("355: refuses now?");
        let wabs = enc(&t, "HFMA2 R2, R3, |R4|, 0, 0").expect("355: refuses now?");
        assert_ne!(
            dec(&t, wneg).as_deref(),
            Some("HFMA2 R2, R3, -R4, 0, 0"),
            "{leg}: 355 neg lane silently fixed -- attribute!"
        );
        assert_ne!(
            dec(&t, wabs).as_deref(),
            Some("HFMA2 R2, R3, |R4|, 0, 0"),
            "{leg}: 355 abs lane silently fixed -- attribute!"
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
