//! BUG-378 (F2Q-378, F2-iter201): plain SubImm windows are SIGNED offsets
//! (printer sign-extends from the top window bit; vendor print law arb378,
//! nvdisasm 13.3.73 raw -b x4 models, on every corpus-exposed window class:
//! 12b@32 desc, 20b@44, 24b@40, 23b@40, 32b@32 ...). Pre-fix the fit_soft
//! unsigned clause `v & !mask == 0` accepted a positive authored offset in
//! the sign window [2^(n-1), 2^n) and minted the raw sign-window word, which
//! decodes back as the NEGATED value -- silent sign flip vs the authored
//! intent (measured on publish cubit-7280e5e6, canonical 47e4ce4:
//! work/bug378/measure_pre378.json: FLIP-SIGN on 74 signw + 75 rawmax
//! boundary mint cells across 79 carrier windows x4 legs).
//!
//! Fix: the SubImm arm fails closed unless the value round-trips through
//! sign_extend(bits). The check reads the DECLARED window, so it can only
//! refuse texts that were never round-trip-stable (mint(t) decoded back to
//! a different offset); every byte-exact text keeps minting (chain/sweep/py
//! gates IDENT). Exclusions: ConstMem sub_imm0 carries the BANK (not an
//! offset); an authored !rsd overlay owns the residue (BUG-140(e) doctrine).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t(leg: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{leg}.json"))).unwrap()
}
fn enc(tab: &IsaTable, sass: &str) -> Result<u128, String> {
    let insn = parse_sass(sass, 0).map_err(|e| e.to_string())?;
    encode_instruction(&insn, tab).map_err(|e| e.to_string())
}
fn back(tab: &IsaTable, w: u128) -> String {
    let idx = DecodeIndex::build(tab);
    let d = idx.decode(w, 0, tab).expect("decode");
    cubit::printer::to_sass(&d)
}
// 24b@40 tok2 (LDG.E [R.64+imm]) boundary matrix: flip class refused,
// in-range + vendor negative glyphs mint EXACT.
#[test]
fn t378_1_sign_window_loud_24b() {
    let tab = t("sm103a");
    for bad in [
        "LDG.E R0, [R2.64+0x800000] ;",  // +2^23: pre-fix minted raw 0x800000
        "LDG.E R0, [R2.64+0xffffff] ;",  // +2^24-1: pre-fix decoded '+-0x1'
        "LDG.E R0, [R2.64+0x1000000] ;", // 2^24 (bits outside the window)
        "LDG.E R0, [R2.64-0x800001] ;",  // one past the signed minimum
    ] {
        let err = enc(&tab, bad).expect_err("must fail closed");
        assert!(
            err.contains("BUG-378"),
            "attribution missing for {bad}: {err}"
        );
    }
    // in-range positive stays EXACT
    assert_eq!(
        enc(&tab, "LDG.E R0, [R2.64+0x7fffff] ;")
            .map(|w| back(&tab, w))
            .as_deref(),
        Ok("LDG.E R0, [R2+0x7fffff]")
    );
    // the sign-window raw IS encodable via the vendor negative spelling
    let w1 = enc(&tab, "LDG.E R0, [R2.64+-0x800000] ;").unwrap();
    let w2 = enc(&tab, "LDG.E R0, [R2.64-0x800000] ;").unwrap();
    assert_eq!(w1, w2, "+- and - spellings mint the same word");
    assert_eq!(back(&tab, w1), "LDG.E R0, [R2+-0x800000]");
}

// 12b@32 desc window (LDGSTS_ARI_dARI_P, sm100a): the post-360 flagship
// geometry -- authored '+0x800' in the desc offset fails closed x leg.
#[test]
fn t378_2_desc_12b_window() {
    for leg in ["sm100a", "sm103a", "sm120"] {
        let tab = t(leg);
        let bad = format!("LDGSTS.E.LTC128B.64 [R115+0x180], desc[UR4][R4.64+0x800], P3 ;");
        let err = enc(&tab, &bad).expect_err("sign-window desc offset must fail closed");
        assert!(err.contains("BUG-378"), "{leg}: {err}");
        let w = enc(
            &tab,
            "LDGSTS.E.LTC128B.64 [R115+0x180], desc[UR4][R4.64+-0x800], P3 ;",
        )
        .unwrap();
        assert_eq!(
            back(&tab, w),
            "LDGSTS.E.LTC128B.64 [R115+0x180], desc[UR4][R4.64+-0x800], P3",
            "{leg}: vendor-glyph negative mints EXACT"
        );
    }
}

// The 23b@40 ATOMG desc window + 20b@44 LDGSTS dst window: same law, x4
// legs; texts are the corpus-anchored shapes (work/bug378/harvest378.json).
#[test]
fn t378_3_desc23_and_dst20_windows() {
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let tab = t(leg);
        // 23b@40 tok3 (ATOMG desc): +0x400000 sign window -> refuse
        let err = enc(
            &tab,
            "ATOMG.E.ADD.STRONG.GPU PT, RZ, desc[UR8][R8.64+0x400000], R3 ;",
        )
        .expect_err("ATOMG desc sign window must fail closed");
        assert!(err.contains("BUG-378"), "{leg}: {err}");
        let w = enc(
            &tab,
            "ATOMG.E.ADD.STRONG.GPU PT, RZ, desc[UR8][R8.64+-0x400000], R3 ;",
        )
        .unwrap();
        assert_eq!(
            back(&tab, w),
            "ATOMG.E.ADD.STRONG.GPU PT, RZ, desc[UR8][R8.64+-0x400000], R3",
            "{leg}"
        );
        // 20b@44 tok1 (LDGSTS dst): +0x80000 -> refuse, +0x7ffff EXACT.
        // era legs anchor on the ARI_ARI shape; sm121a on ARI_dARI.
        let (bad, good, want) = if leg == "sm121a" {
            (
                "LDGSTS.E.BYPASS.128 [R123+0x80000], desc[UR12][R14.64] ;",
                "LDGSTS.E.BYPASS.128 [R123+0x7ffff], desc[UR12][R14.64] ;",
                "LDGSTS.E.BYPASS.128 [R123+0x7ffff], desc[UR12][R14.64]",
            )
        } else {
            (
                "LDGSTS.E.BYPASS.LTC128B.128 [R205+0x80000], [R212.64] ;",
                "LDGSTS.E.BYPASS.LTC128B.128 [R205+0x7ffff], [R212.64] ;",
                "LDGSTS.E.BYPASS.LTC128B.128 [R205+0x7ffff], [R212.64]",
            )
        };
        let err = enc(&tab, bad).expect_err("LDGSTS dst sign window must fail closed");
        assert!(err.contains("BUG-378"), "{leg}: {err}");
        let w = enc(&tab, good).unwrap();
        assert_eq!(back(&tab, w), want, "{leg}");
    }
}

// Escape hatches: explicit !rsd overlay owns the residue (BUG-140(e)), and
// the ConstMem sub_imm0 field carries the BANK -- neither may see the bail.
#[test]
fn t378_4_rsd_overlay_and_bank_exclusion() {
    let tab = t("sm103a");
    let w = enc(&tab, "LDG.E R0, [R2.64+0x800000] !rsd[63:1] ;")
        .expect("authored !rsd overlay owns the residue window");
    assert_eq!(back(&tab, w), "LDG.E R0, [R2+-0x800000]");
    let t100 = t("sm100a");
    // LDC_R_cARI '' : sub_imm0 2b@54 on the ConstMem token = BANK. c[0x2]/c[0x3]
    // sit in/atop the 2-bit window's sign region and must keep minting.
    assert!(enc(&t100, "LDC R1, c[0x2][R2.64+0x10] ;").is_ok(), "bank 2");
    assert!(enc(&t100, "LDC R1, c[0x3][R2.64+0x10] ;").is_ok(), "bank 3");
    // ... while the OFFSET on the same token stays guarded.
}

// Round-trip discipline guard: the bail never fires on a text that the
// decode(print) side produces -- walk canonical corpus shapes at in-range
// boundary offsets and assert mint->print == print->mint.
#[test]
fn t378_5_roundtrip_boundary_stability() {
    let tab = t("sm103a");
    for txt in [
        "LDG.E R0, [R2.64+0x0]",
        "LDG.E R0, [R2.64+0x7fffff]",
        "LDG.E R0, [R2.64+-0x800000]",
        "LDG.E R0, [R2.64+-0x1]",
        "STS.64 [R50+0x800], R18",
        "ATOMS.CAST.SPIN.64 P0, [R3+0x8], R12, R14",
        "STG.E.128.STRONG.SYS desc[UR10][R32.64+0x7fffff], R8",
    ] {
        let w = enc(&tab, &format!("{txt} ;")).unwrap_or_else(|e| panic!("{txt}: {e}"));
        let b1 = back(&tab, w);
        let w2 = enc(&tab, &format!("{b1} ;")).unwrap_or_else(|e| panic!("remint {b1}: {e}"));
        assert_eq!(w, w2, "{txt}: decode-print must re-mint byte-exact");
    }
}
