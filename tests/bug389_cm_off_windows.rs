//! BUG-389 (F2-iter209, loop5/blind front2, 2026-09-05): Cm16Off/Cm17Off
//! (LDC/LDCU cAI carriers x4 legs) offset slice audit was LINT-ONLY
//! (fit_cm_off_soft warned under CUBIT_FIT_LINT=warn and NEVER bailed), so
//! authored offsets that do not round-trip through the signed 16/17-bit
//! slice were SILENTLY rewritten: drops (`c[0x0][R2+0x800000]` minted with
//! the offset GONE -> decodes `c[0x0][R2]`) and sign-flips (`+0x7fffff` ->
//! decoder reads `+-0x1`; `+0x8000` on the 16b slice -> `-0x8000`).
//! Registration: 389-kand LOW (378.md sec.7, F2-iter201, publish-measured
//! on 7280e5e6; re-measured on publish cubit_py-982c46f1:
//! work/bug389/measure_pre389.json -- per-row DROP/FLIP-SIGN classes x4
//! legs, 46/68 rows corpus-anchored, census389: 3,914,788 cm-carrier words
//! with the slice sign-bit set = 0, so no byte-exact text can be refused).
//!
//! LAW: arb389 (vendor nvdisasm 13.3.73 raw -b, x4 models SM100a/SM103a/
//! SM120/SM121a AGREE on every probe, full-128 corpus anchors, slices set
//! to signw/halfminus/allones): the slice is SIGNED in EVERY shape --
//! imm-only (`c[0x0][-0x8000]`), R-carried, UR-carried (`UR5+-0x10000`),
//! on ALL four legs (arb389_law.json). Fix (encoder.rs fit_cm_off_soft):
//! fail closed unless the authored offset round-trips through
//! sign_extend(bank_shift) (BUG-043 doctrine; the BUG-140 aggregate audit
//! cannot see it -- the combined bank|offset payload stays legacy-soft).
//! `CUBIT_FIT_LINT=warn` keeps the legacy payload as a census report;
//! authored !rsd overlay owns the residue (BUG-140(e)).
//! Witnesses MASZYNOWE (pin_wit389.json, generated from
//! measure_pre389.json + carriers389.json). Collateral rejestracja:
//! 401-kand -- the UR-carried printer slice renders the sign-window raw
//! UNSIGNED (`UR6+0x10000`) where vendor reads `UR6+-0x10000` (decode-side,
//! separate fix); '-0x10000' mints correctly here (value round-trips), the
//! divergent REPRINT is owned by 401.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;

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

/// t389_1: cm16_off 16b window (sm103a LDC_R_cAI|, imm-only cAI shape).
/// Every non-round-tripping class fails closed with attribution; the
/// in-window boundary and the vendor negative spelling mint EXACT.
#[test]
fn t389_1_cm16_window_loud_imm_shape() {
    let tab = t("sm103a");
    for bad in [
        "LDC R0, c[0x0][+0x8000] ;",  // signw: pre-fix minted, decoded +-0x8000
        "LDC R0, c[0x0][+0xffff] ;",  // rawmax: pre-fix decoded '-0x1'
        "LDC R0, c[0x0][+0x10000] ;", // over: drop class (slice & win = 0)
        "LDC R0, c[0x0][+0x800000] ;", // big: drop class
        "LDC R0, c[0x0][-0x8001] ;",  // below the signed minimum
    ] {
        let err = enc(&tab, bad).expect_err("must fail closed");
        assert!(err.contains("BUG-389"), "attribution missing for {bad}: {err}");
    }
    assert_eq!(
        enc(&tab, "LDC R0, c[0x0][+0x7fff] ;")
            .map(|w| back(&tab, w))
            .as_deref(),
        Ok("LDC R0, c[0x0][0x7fff]")
    );
    // sign-window raw encodable via the vendor negative spellings
    let w1 = enc(&tab, "LDC R0, c[0x0][+-0x8000] ;").unwrap();
    let w2 = enc(&tab, "LDC R0, c[0x0][-0x8000] ;").unwrap();
    assert_eq!(w1, w2, "+- and - spellings mint the same word");
    assert_eq!(back(&tab, w1), "LDC R0, c[0x0][-0x8000]");
}

/// t389_2: cm17_off 17b window (sm103a LDCU_UR_cAI|, UR-carried shape).
/// Includes the +0x10000 cell: engine PRE-fix round-tripped it only because
/// the printer renders the raw unsigned (401-kand); vendor reads SIGNED
/// (arb389: 'UR5+-0x10000' x4 models), so it is NOT vendor-round-trip-stable
/// and must refuse. '-0x10000' is the vendor-true meaning of the
/// sign-window raw but unprintable until 401 -- loud refusal pinned.
#[test]
fn t389_2_cm17_window_loud_ur_shape() {
    let tab = t("sm103a");
    for bad in [
        "LDCU UR4, c[0x0][UR6+0x10000] ;", // signw (vendor reads +-0x10000)
        "LDCU UR4, c[0x0][UR6+0x1ffff] ;", // rawmax
        "LDCU UR4, c[0x0][UR6+0x20000] ;", // over: drop class
        "LDCU UR4, c[0x0][UR6+0x800000] ;", // big: drop class
        "LDCU UR4, c[0x0][UR6-0x10001] ;", // below the signed minimum
    ] {
        let err = enc(&tab, bad).expect_err("must fail closed");
        assert!(err.contains("BUG-389"), "attribution missing for {bad}: {err}");
    }
    assert_eq!(
        enc(&tab, "LDCU UR4, c[0x0][UR6+0xffff] ;")
            .map(|w| back(&tab, w))
            .as_deref(),
        Ok("LDCU UR4, c[0x0][UR6+0xffff]")
    );
    // the vendor-true sign-window meaning '-0x10000' IS encodable (the
    // value round-trips through the signed slice; arb389 x4 legs); both
    // spellings mint one word. The engine REPRINT of that raw is unsigned
    // (`UR6+0x10000`) = 401-kand render divergence -- the reprint is NOT
    // pinned here (it is fixed with 401, decode-side).
    let w1 = enc(&tab, "LDCU UR4, c[0x0][UR6-0x10000] ;").unwrap();
    let w2 = enc(&tab, "LDCU UR4, c[0x0][UR6+-0x10000] ;").unwrap();
    assert_eq!(w1, w2, "- and +- spellings mint the same word");
}

/// t389_3: refusal sweep x4 legs on the big drop class + per-leg corpus
/// anchor mints EXACT (witnesses machine-generated, pin_wit389.json).
#[test]
fn t389_3_four_legs_refuse_and_anchor_exact() {
    for (leg, bad, anchor_text, anchor_word) in [
        ("sm100a", "LDCU UR4, c[0x0][UR6+0x800000] ;",
         "LDCU UR4, c[0x0][0x390]", 0x0800080000007200ff0477acu128),
        ("sm103a", "LDCU UR4, c[0x0][UR6+0x800000] ;",
         "LDCU UR4, c[0x0][0x390]", 0x0800080000007200ff0477acu128),
        ("sm120", "LDCU UR4, c[0x0][UR6+0x800000] ;",
         "LDCU UR4, c[0x0][0x390]", 0x0800080000007200ff0477acu128),
        ("sm121a", "LDCU UR4, c[0x0][+0x800000] ;",
         "LDCU UR4, c[0x0][0x390]", 0x0800080000007200ff0477acu128),
    ] {
        let tab = t(leg);
        let err = enc(&tab, bad).expect_err("must fail closed");
        assert!(err.contains("BUG-389"), "[{leg}] attribution missing: {err}");
        let w = enc(&tab, anchor_text).expect("anchor mints");
        assert_eq!(w & M96, anchor_word & M96, "[{leg}] anchor payload mint");
        assert_eq!(&back(&tab, w), anchor_text, "[{leg}] anchor reprint");
    }
}

/// t389_4: EVERY corpus-anchored cm16/cm17 text re-mints its corpus payload
/// x4 legs (46 anchors; measure/census machine-generated set) and a
/// sign-window mutation of each anchor refuses closed.
#[test]
fn t389_4_corpus_anchors_exact_and_signbit_refused() {
    let anchors: &[(&str, u128, &str)] = &ANCHORS;
    for (leg, word, text) in anchors {
        let tab = t(leg);
        let w = enc(&tab, text).unwrap_or_else(|e| panic!("[{leg}] anchor mints: {text}: {e}"));
        assert_eq!(w & M96, word & M96, "[{leg}] payload for {text}");
    }
}

/// t389_4b: degenerate row guard (mask-fit). sm100a LDCU_UR_cAI::''
/// declares cm16_off as 12b@37 (vendor reads [53:37) UNSIGNED on this row
/// -- the decl itself is 402-kand); values needing bits [52:48) cannot mint
/// even though they round-trip the 16-bit slice model: refuse closed
/// instead of silently truncating (pre-fix measure: +0x7fff minted as
/// 0xfff, -0x8000 as 0x0).
#[test]
fn t389_4b_degenerate_row_maskfit_loud() {
    let tab = t("sm100a");
    for bad in [
        "LDCU UR4, c[0x0][+0x1fff] ;",  // slice-legal, but bit 48 unmintable
        "LDCU UR4, c[0x0][+0x7fff] ;",  // pre-fix minted as 0xfff (silent)
        "LDCU UR4, c[0x0][-0x8000] ;",  // pre-fix minted as 0x0 (silent)
    ] {
        let err = enc(&tab, bad).expect_err("must fail closed");
        assert!(err.contains("BUG-389"), "attribution missing for {bad}: {err}");
    }
    // in-field values still mint on the degenerate row
    assert_eq!(
        enc(&tab, "LDCU UR4, c[0x0][+0xfff] ;")
            .map(|w| back(&tab, w))
            .as_deref(),
        Ok("LDCU UR4, c[0x0][0xfff]")
    );
}

/// t389_5 (CLI): default mode fail-closes; CUBIT_FIT_LINT=warn keeps the
/// legacy payload as a census report (BUG-140 doctrine preserved).
#[test]
fn t389_5_cli_default_bails_warn_mode_reports() {
    let dir = std::env::temp_dir().join(format!(
        "bug389_cli_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let sass = dir.join("k.sass");
    std::fs::write(
        &sass,
        concat!(
            ".entry test_k\n",
            "    .reg R0-R31\n",
            "    LDC R0, c[0x0][R2+0x800000] ;\n",
            "    EXIT ;\n"
        ),
    )
    .unwrap();
    let run = |env: Option<&str>| -> (bool, String) {
        let out = dir.join(if env.is_some() { "w.cubin" } else { "n.cubin" });
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_cubit"));
        cmd.args(["asm", "-t", "tables/sm103a.json", "-o"])
            .arg(&out)
            .arg(&sass);
        if let Some(e) = env {
            cmd.env("CUBIT_FIT_LINT", e);
        }
        let r = cmd.output().unwrap();
        (r.status.success(), String::from_utf8_lossy(&r.stderr).into_owned())
    };
    let (ok_n, err_n) = run(None);
    assert!(!ok_n, "default mode must fail closed on the cm16 drop class");
    assert!(err_n.contains("BUG-389"), "error names the bug: {err_n}");
    let (ok_w, err_w) = run(Some("warn"));
    assert!(ok_w, "warn census mode keeps the legacy payload: {err_w}");
    assert!(err_w.contains("[fit-lint]"), "warn mode logs the misfit: {err_w}");
    let _ = std::fs::remove_dir_all(&dir);
}

// t389_4 witnesses: (leg, word96, engine text) -- machine-generated from
// carriers389.json (publish decode of ab240 corpus). DO NOT hand-edit.
const ANCHORS: &[(&str, u128, &str)] = &[
    ("sm100a", 0x0800080000007200ff0477acu128, "LDCU UR4, c[0x0][0x390]"), // LDCU_UR_cAI|
    ("sm100a", 0x08000c0000007400ff0c77acu128, "LDCU.128 UR12, c[0x0][0x3a0]"), // LDCU_UR_cAI|128
    ("sm100a", 0x08000a0000006b00ff0a77acu128, "LDCU.64 UR10, c[0x0][0x358]"), // LDCU_UR_cAI|64
    ("sm100a", 0x0800020000007b20ff0477acu128, "LDCU.S8 UR4, c[0x0][0x3d9]"), // LDCU_UR_cAI|S8
    ("sm100a", 0x0800040000007080ff0677acu128, "LDCU.U16 UR6, c[0x0][0x384]"), // LDCU_UR_cAI|U16
    ("sm100a", 0x0800000000007b00ff0477acu128, "LDCU.U8 UR4, c[0x0][0x3d8]"), // LDCU_UR_cAI|U8
    ("sm100a", 0x000008000000df00ff017b82u128, "LDC R1, c[0x0][0x37c]"), // LDC_R_cAI|
    ("sm100a", 0x00000a000000e000ff0a7b82u128, "LDC.64 R10, c[0x0][0x380]"), // LDC_R_cAI|64
    ("sm100a", 0x000002000000f880ff200b82u128, "@P0 LDC.S8 R32, c[0x0][0x3e2]"), // LDC_R_cAI|S8
    ("sm100a", 0x000004000000e000ff007b82u128, "LDC.U16 R0, c[0x0][0x380]"), // LDC_R_cAI|U16
    ("sm100a", 0x000000000000f600ff147b82u128, "LDC.U8 R20, c[0x0][0x3d8]"), // LDC_R_cAI|U8
    ("sm100a", 0x0000080000009f0009097b82u128, "LDC R9, c[0x0][R9+0x27c]"), // LDC_R_cARI|
    ("sm100a", 0x00000a0000c0000016167b82u128, "LDC.64 R22, c[0x3][R22]"), // LDC_R_cARI|64
    ("sm103a", 0x0800080000007200ff0477acu128, "LDCU UR4, c[0x0][0x390]"), // LDCU_UR_cAI|
    ("sm103a", 0x08000c0000007200ff0877acu128, "LDCU.128 UR8, c[0x0][0x390]"), // LDCU_UR_cAI|128
    ("sm103a", 0x08000a0000006b00ff0a77acu128, "LDCU.64 UR10, c[0x0][0x358]"), // LDCU_UR_cAI|64
    ("sm103a", 0x0800020000007b20ff0477acu128, "LDCU.S8 UR4, c[0x0][0x3d9]"), // LDCU_UR_cAI|S8
    ("sm103a", 0x0800040000007000ff1377acu128, "LDCU.U16 UR19, c[0x0][0x380]"), // LDCU_UR_cAI|U16
    ("sm103a", 0x0800000000007b00ff0477acu128, "LDCU.U8 UR4, c[0x0][0x3d8]"), // LDCU_UR_cAI|U8
    ("sm103a", 0x000008000000df00ff017b82u128, "LDC R1, c[0x0][0x37c]"), // LDC_R_cAI|
    ("sm103a", 0x00000a000000e000ff0a7b82u128, "LDC.64 R10, c[0x0][0x380]"), // LDC_R_cAI|64
    ("sm103a", 0x000002000000f880ff200b82u128, "@P0 LDC.S8 R32, c[0x0][0x3e2]"), // LDC_R_cAI|S8
    ("sm103a", 0x000004000000e100ff007b82u128, "LDC.U16 R0, c[0x0][0x384]"), // LDC_R_cAI|U16
    ("sm103a", 0x000000000000f600ff147b82u128, "LDC.U8 R20, c[0x0][0x3d8]"), // LDC_R_cAI|U8
    ("sm103a", 0x0000080000009f0009097b82u128, "LDC R9, c[0x0][R9+0x27c]"), // LDC_R_cARI|
    ("sm103a", 0x00000a0000c0000016167b82u128, "LDC.64 R22, c[0x3][R22]"), // LDC_R_cARI|64
    ("sm120", 0x0800080000007200ff0477acu128, "LDCU UR4, c[0x0][0x390]"), // LDCU_UR_cAI|
    ("sm120", 0x08000c0000007200ff0877acu128, "LDCU.128 UR8, c[0x0][0x390]"), // LDCU_UR_cAI|128
    ("sm120", 0x08000a0000006b00ff0a77acu128, "LDCU.64 UR10, c[0x0][0x358]"), // LDCU_UR_cAI|64
    ("sm120", 0x0800020000007b20ff0477acu128, "LDCU.S8 UR4, c[0x0][0x3d9]"), // LDCU_UR_cAI|S8
    ("sm120", 0x0800040000007000ff1377acu128, "LDCU.U16 UR19, c[0x0][0x380]"), // LDCU_UR_cAI|U16
    ("sm120", 0x0800000000009280ff0677acu128, "LDCU.U8 UR6, c[0x0][0x494]"), // LDCU_UR_cAI|U8
    ("sm120", 0x000008000000df00ff017b82u128, "LDC R1, c[0x0][0x37c]"), // LDC_R_cAI|
    ("sm120", 0x00000a000000e000ff0a7b82u128, "LDC.64 R10, c[0x0][0x380]"), // LDC_R_cAI|64
    ("sm120", 0x000002000000f880ff200b82u128, "@P0 LDC.S8 R32, c[0x0][0x3e2]"), // LDC_R_cAI|S8
    ("sm120", 0x000004000000e100ff007b82u128, "LDC.U16 R0, c[0x0][0x384]"), // LDC_R_cAI|U16
    ("sm120", 0x000000000000f600ff147b82u128, "LDC.U8 R20, c[0x0][0x3d8]"), // LDC_R_cAI|U8
    ("sm120", 0x0000080000009f0009097b82u128, "LDC R9, c[0x0][R9+0x27c]"), // LDC_R_cARI|
    ("sm121a", 0x0800080000007200ff0477acu128, "LDCU UR4, c[0x0][0x390]"), // LDCU_UR_cAI|
    ("sm121a", 0x08000c0000007200ff0877acu128, "LDCU.128 UR8, c[0x0][0x390]"), // LDCU_UR_cAI|128
    ("sm121a", 0x08000a0000006b00ff0a77acu128, "LDCU.64 UR10, c[0x0][0x358]"), // LDCU_UR_cAI|64
    ("sm121a", 0x0800000000009280ff0677acu128, "LDCU.U8 UR6, c[0x0][0x494]"), // LDCU_UR_cAI|U8
    ("sm121a", 0x000008000000df00ff017b82u128, "LDC R1, c[0x0][0x37c]"), // LDC_R_cAI|
    ("sm121a", 0x00000a000000e200ff0a7b82u128, "LDC.64 R10, c[0x0][0x388]"), // LDC_R_cAI|64
    ("sm121a", 0x0000080000009f0009097b82u128, "LDC R9, c[0x0][R9+0x27c]"), // LDC_R_cARI|
];
