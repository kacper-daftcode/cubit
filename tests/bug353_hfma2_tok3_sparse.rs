//! BUG-353 (F2-iter183, loop5/blind front2, 2026-09-02): sparse-leg
//! HFMA2 FI/II lattice tok3 sign-window closure -- +neg@84/abs@83/
//! hsel@[82:81]/h0nh1@86 tok3 fields on HFMA2_R_R_R_FI_FI mg '', legs
//! sm100a+sm103a (canonical 9717447, ride-after 2631fca/BUG-343-344-tidy).
//! Registered 353-kand LOW at 329.md sec.6 (F2-iter176).
//!
//! MEASUREMENT (pre-fix publish fd826df, canonical a013f88;
//! work/bug353/measure_pre353.json):
//!  (a) sparse DECODE of FI/II tok3-sign words = LOUD HOLE 16/16 (vendor
//!      prints '-R4'/'|R4|'/'R4.F32'/'R4.H0_H0'/'R4.H1_H1'/'R4.H0_NH1').
//!  (b) sparse ENCODE of authored tok3 hsel/h0nh1 = loud REFUSE (5/5).
//!  (c) sparse ENCODE of authored tok3 neg/abs = SILENT MANGLE: sign folded
//!      into tok4 f16 ('-R4' mints word vendor reads 'R4, -0.0'; '|R4|' ->
//!      '2'; '-|R4|' -> '-2'; '-R4, 1' -> '-1') == 355-class trigger; graft
//!      cures it on this row by data (field mints == dense == vendor).
//!  (d) dense legs pre == exact (279/271-era fields) = graft mirror source.
//! Graft is corpus-INVISIBLE (census353 battery 2,406 x4 legs: 97,338
//! lattice words/leg, tok3-sign window [86:81] bits set = ZERO words).
//!
//! LAW: arb329 S-group (18 tok3-side probes) + F/E/G controls, nvdisasm
//! 13.3.73 raw -b, x4 models SM100a/103a/120/121a AGREE on EVERY probe;
//! work/bug329/arb329_verdicts.json. INVALID5 window (h0nh1 x hsel v1) =
//! '.INVALID5' at NV -> stays doctrine-HOLE fail-closed on ALL legs.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
const B78: u128 = 1 << 78;
const B79: u128 = 1 << 79;
const B83: u128 = 1 << 83;
const B84: u128 = 1 << 84;
const B85: u128 = 1 << 85;
const B86: u128 = 1 << 86;
const B91: u128 = 1 << 91;
const H1: u128 = 0x3c00u128 << 48; // f16 1.0 @ tok4 window
const BF1: u128 = 0x3f80u128 << 48; // bf16 1.0 @ tok4 window
// FI lattice (0x7431, guard pinned PT): R2@16, R3@24, R4@64
const FI: u128 = 0x7431 | (2 << 16) | (3 << 24) | (4 << 64);
// II lattice (0x0431, guard @15:12): same registers, guard 0 = @P0
const II0: u128 = 0x0431 | (2 << 16) | (3 << 24) | (4 << 64);
// tok3 sign-window bits grafted into the vm
const WIN: u128 = B84 | B83 | (3 << 81) | B86;

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
fn t353_1_structure_graft_mirrors_dense() {
    // sparse legs: mg '' field set/cape == dense sm120 geometry post-graft
    let t120 = tab("sm120");
    let d = &t120.entries["HFMA2_R_R_R_FI_FI"].mod_groups[""];
    assert_eq!(d.fields.len(), 12, "sm120: dense donor geometry drift");
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        let e = &t.entries["HFMA2_R_R_R_FI_FI"];
        // FLIP 2026-09-02 (BUG-354, attribution): mod-lane family grafted
        // (11 mgs + 6 dotted _P keys; tests/bug354_hfma2_sparse_modlane.rs).
        // FLIP (BUG-367, F2-iter193, canonical 0933cf6): SAT/FTZ/OOB lane
        // closure 12 -> 36 (lattice completion vs dense; tests/bug367_*).
        assert_eq!(e.mod_groups.len(), 36, "{leg}: mg set drift (post-367=36)");
        let mg = &e.mod_groups[""];
        assert_eq!(mg.fields.len(), 12, "{leg}: field count drift (8->12)");
        let has = |ext: Extraction, shift: u32, tok: i32| {
            mg.fields
                .iter()
                .filter(|f| f.extraction == ext && f.shift == shift && f.token_idx == tok)
                .count()
        };
        // the four grafted tok3 lanes, exactly once each
        assert_eq!(has(Extraction::Neg, 84, 3), 1, "{leg}: neg@84 tok3");
        assert_eq!(has(Extraction::Abs, 83, 3), 1, "{leg}: abs@83 tok3");
        assert_eq!(has(Extraction::HalfSel, 81, 3), 1, "{leg}: hsel@81 tok3");
        assert_eq!(has(Extraction::H0NH1, 86, 3), 1, "{leg}: h0nh1@86 tok3");
        // ab must NOT carry the window; vm must carry it (dense mirror)
        assert_eq!(mg.and_base & WIN, 0, "{leg}: ab carries graft window");
        assert_eq!(mg.variable_mask & WIN, WIN, "{leg}: vm mirror missing");
        assert_eq!(mg.and_base, d.and_base, "{leg}: ab drift vs dense donor");
        assert_eq!(
            mg.variable_mask, d.variable_mask,
            "{leg}: vm delta vs dense donor"
        );
        // 353 scope pin: the mod-lane family stays ungrafted (354-kand)
        assert!(
            !t.entries.contains_key("HFMA2.BF16_V2_R_R_R_FI_FI"),
            "{leg}: BF16_V2 FI_FI key materialized (354-scope breach)"
        );
    }
}

#[test]
fn t353_2_decode_law_vendor_equal_x4() {
    // arb329 S-group tok3 lanes + tok2/imm/guard composes, vendor text x4
    let cases: &[(u128, u128, &str)] = &[
        (FI, B84, "HFMA2 R2, R3, -R4, 0, 0"),
        (FI, B83, "HFMA2 R2, R3, |R4|, 0, 0"),
        (FI, B84 | B83, "HFMA2 R2, R3, -|R4|, 0, 0"),
        (FI, 1 << 81, "HFMA2 R2, R3, R4.F32, 0, 0"),
        (FI, 2 << 81, "HFMA2 R2, R3, R4.H0_H0, 0, 0"),
        (FI, 3 << 81, "HFMA2 R2, R3, R4.H1_H1, 0, 0"),
        (FI, B86, "HFMA2 R2, R3, R4.H0_NH1, 0, 0"),
        (
            FI,
            (2 << 74) | (2 << 81),
            "HFMA2 R2, R3.H0_H0, R4.H0_H0, 0, 0",
        ),
        (FI, B84 | H1, "HFMA2 R2, R3, -R4, 1, 0"),
        (FI, (3 << 81) | H1, "HFMA2 R2, R3, R4.H1_H1, 1, 0"),
        // II lattice g0 (guard!=7): same FI_FI claim row
        (II0, B84, "@P0 HFMA2 R2, R3, -R4, 0, 0"),
        (II0, B83, "@P0 HFMA2 R2, R3, |R4|, 0, 0"),
        (II0, 2 << 81, "@P0 HFMA2 R2, R3, R4.H0_H0, 0, 0"),
        (II0, B86, "@P0 HFMA2 R2, R3, R4.H0_NH1, 0, 0"),
        (II0, B84 | H1, "@P0 HFMA2 R2, R3, -R4, 1, 0"),
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
}

#[test]
fn t353_3_guard_sweep_compose_x4() {
    // guard map (arb329 G x4): v<7 '@Pv' / 7 PT-plain / 8..14 '@!P(v-8)' /
    // 15 '@!PT', composed with tok3 neg and tok3 hsel
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        for (g, pre) in [
            (0u128 << 12, "@P0 "),
            (3u128 << 12, "@P3 "),
            (7u128 << 12, ""),
            (9u128 << 12, "@!P1 "),
            (0xfu128 << 12, "@!PT "),
        ] {
            let wneg = (FI & !(0xfu128 << 12)) | g | B84;
            assert_eq!(
                &dec(&t, wneg).unwrap(),
                &format!("{pre}HFMA2 R2, R3, -R4, 0, 0"),
                "{leg}: guard {g:#x} x tok3-neg drift"
            );
            let whsel = (FI & !(0xfu128 << 12)) | g | (3 << 81);
            assert_eq!(
                &dec(&t, whsel).unwrap(),
                &format!("{pre}HFMA2 R2, R3, R4.H1_H1, 0, 0"),
                "{leg}: guard {g:#x} x tok3-hsel drift"
            );
        }
    }
}

#[test]
fn t353_4_encode_word_exact_and_roundtrip_x4() {
    // golden words = pre-fix DENSE mints (279/271 geometry, vendor readback
    // verified in measure_pre353); sparse mints must now be byte-equal =>
    // the 355-class sign->f16 fold mangle on this row is cured by data.
    let cases: &[(u128, &str)] = &[
        (
            0xfc200001000040000000003027431u128,
            "HFMA2 R2, R3, -R4, 0, 0",
        ),
        (
            0xfc200000800040000000003027431u128,
            "HFMA2 R2, R3, |R4|, 0, 0",
        ),
        (
            0xfc200001800040000000003027431u128,
            "HFMA2 R2, R3, -|R4|, 0, 0",
        ),
        (
            0xfc200000400040000000003027431u128,
            "HFMA2 R2, R3, R4.H0_H0, 0, 0",
        ),
        (
            0xfc200000600040000000003027431u128,
            "HFMA2 R2, R3, R4.H1_H1, 0, 0",
        ),
        (
            0xfc200000200040000000003027431u128,
            "HFMA2 R2, R3, R4.F32, 0, 0",
        ),
        (
            0xfc200004000040000000003027431u128,
            "HFMA2 R2, R3, R4.H0_NH1, 0, 0",
        ),
        (
            0xfc200000408040000000003027431u128,
            "HFMA2 R2, R3.H0_H0, R4.H0_H0, 0, 0",
        ),
        (
            0xfc200001000043c00000003027431u128,
            "HFMA2 R2, R3, -R4, 1, 0",
        ),
        (
            0xfc200001000040000000003020431u128,
            "@P0 HFMA2 R2, R3, -R4, 0, 0",
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
    // mangle-cure assertion (semantic): pre-graft sparse folded the sign
    // into tok4 f16 -- the minted words must NOT be the fold words
    let t = tab("sm103a");
    assert_ne!(
        enc(&t, "HFMA2 R2, R3, -R4, 0, 0").unwrap() & M96,
        0xfc200000000048000000003027431u128 & M96,
        "355 fold word still minted (neg)"
    );
    assert_ne!(
        enc(&t, "HFMA2 R2, R3, |R4|, 0, 0").unwrap() & M96,
        0xfc200000000044000000003027431u128 & M96,
        "355 fold word still minted (abs)"
    );
}

#[test]
fn t353_5_fail_closed_residuum_and_doctrine() {
    // INVALID5 window (h0nh1 x hsel) + b91 kill stay HOLE on ALL legs x4
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        for (extra, name) in [
            ((1u128 << 81) | B86, "INVALID5 (hsel v1 x h0nh1)"),
            ((2u128 << 81) | B86, "INVALID6 (hsel v2 x h0nh1)"),
            (B91 | B84, "b91 kill x tok3-neg"),
        ] {
            assert!(
                dec(&t, FI | extra).is_none(),
                "{leg}: {name} decoded (doctrine breach)"
            );
        }
        // INVALID3 doctrine (285): F32 x BF16 stays HOLE on ALL legs
        assert!(
            dec(&t, II0 | B78 | B85 | H1).is_none(),
            "{leg}: INVALID3 lane decoded (285 doctrine breach)"
        );
    }
    // FLIP 2026-09-02 (BUG-354, attribution): the 354 residuum is CURED
    // -- sparse mod lanes decode/mint vendor-exact now (law arb354 x4,
    // goldens tests/bug354 t354_2/3 with word-exact pins). Kill classes
    // above stay doctrine-HOLE on ALL legs. 367-scope SAT/FTZ/OOB stays
    // HOLE on sparse (pinned in t354_4).
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        for (base, extra, name, want) in [
            (
                FI,
                B85 | BF1,
                "BF16 mod lane",
                "HFMA2.BF16_V2 R2, R3, R4, 1, 0",
            ),
            (FI, B78, "F32 mod lane", "HFMA2.F32 R2, R3, R4, 0, 0"),
            (FI, B79, "RELU era lane", "HFMA2.RELU R2, R3, R4, 0, 0, P0"),
            (
                FI,
                B85 | B84 | BF1,
                "BF16 x tok3-neg",
                "HFMA2.BF16_V2 R2, R3, -R4, 1, 0",
            ),
        ] {
            assert_eq!(
                dec(&t, base | extra).as_deref(),
                Some(want),
                "{leg}: {name} post-354 armed drift {extra:#x}"
            );
        }
        assert!(
            enc(&t, "HFMA2.BF16_V2 R2, R3, R4, 1, 0").is_ok(),
            "{leg}: sparse BF16 lane mint refused post-354"
        );
    }
}
