//! BUG-328 (F2-iter166, loop5/blind front2, 2026-08-31): sm121a
//! HMUL2_R_R_UR / HFMA2_R_R_UR_R UR-targeted reuse@123 field strip
//! (canonical 500bff5, graft patch328.py, 4 fields).
//!
//! LAW (arb328/arb328b: nvdisasm 13.3.73 raw -b, x4 models agree on
//! EVERY probe): reuse bits 122/123/124 on these forms are VENDOR-LEGAL
//! when the bundle control word carries the reuse-collectable gate (any
//! of ctrl bits b105..b108); the 328-kand registration (arb307,
//! CTRL=0x000fc000) read rc=1 artifacts = FALSE POSITIVE and R-window
//! reuse fields (b122 tok2 / b124 tok4) STAY with corpus anchor backing
//! (t243-era, thousands of witnesses). b123 on the UR slot (window @32)
//! is vendor display-INERT x4 (accepted, never printed). Pre-fix the
//! sm121a clone-style rows carried (123 -> tok3), so authored
//! '.reuse' on the UR operand MINTED a bit that decodes back plain
//! (silent EXACT-doctrine breach; dense legs refuse via BUG-252).
//! Post-fix: sm121a refuses like the dense legs; decode of b123-set
//! words stays vendor-plain on all legs.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    // full word (ctrl bits >= 96 included): reuse fields/sideband read them
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).unwrap();
    encode_instruction(&insn, t).map_err(|e| format!("{e}"))
}

/// No reuse field may target the UR token (token_idx 3, window @32) on
/// these keys on any leg; R-window reuse (b122/b124) stays put.
#[test]
fn t328_1_structure_ur_reuse_stripped_r_window_kept() {
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for key in ["HMUL2_R_R_UR", "HFMA2_R_R_UR_R"] {
            let e = t.entries.get(key).unwrap_or_else(|| panic!("{arch} {key}"));
            for (mg_name, mg) in &e.mod_groups {
                assert!(
                    !mg.fields
                        .iter()
                        .any(|f| f.extraction == Extraction::Reuse && f.token_idx == 3),
                    "{arch} {key}|{mg_name} UR reuse field stripped"
                );
                for f in mg
                    .fields
                    .iter()
                    .filter(|f| f.extraction == Extraction::Reuse)
                {
                    assert!(
                        f.shift != 123,
                        "{arch} {key}|{mg_name} reuse@123 only ever pairs window @32"
                    );
                }
            }
        }
    }
}

/// b123-set (=UR reuse) words decode vendor-PLAIN on every leg
/// (display-inert per arb328b x4; no 'UR..reuse' fabrication).
#[test]
fn t328_2_decode_b123_vendor_plain() {
    // t243 anchor family (b122|b124 legal) with EXTRA b123 (UR reuse):
    // vendor prints UR plain on every leg (arb328b x4).
    const W_UR: u128 = 0x140fe4000816080b200000080c097c31 | (1u128 << 123);
    const H_UR: u128 = (0x140fe4u128 << 96) | 0x080000006000000402017c32 | (1u128 << 123);
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        let hf = dec(&t, W_UR).expect("b123 hfma2 word decodes");
        assert!(
            !hf.contains("UR8.reuse"),
            "{arch} no UR reuse fabrication: {hf}"
        );
        assert!(hf.contains("UR8.H0_H0"), "{arch} UR operand intact: {hf}");
        assert_eq!(
            dec(&t, H_UR).expect("b123 hmul word decodes"),
            "HMUL2 R1, R2, |UR4.H0_H0|",
            "{arch}"
        );
    }
}

/// Authored '.reuse' on the UR operand now fails loudly on ALL legs
/// (sm121a parity with the BUG-252 refuse; pre-fix it minted b123=1).
#[test]
fn t328_3_encode_ur_reuse_fail_closed() {
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for text in [
            "HFMA2 R5, R2.H0_H0, UR4.reuse, R5.H0_H0",
            "HMUL2 R1, R2, |UR4.H0_H0|.reuse",
        ] {
            assert!(enc(&t, text).is_err(), "{arch} must refuse: {text}");
        }
    }
}

/// R-window reuse mint STAYS (guards against re-doing the refuted broad
/// graft): authored '.reuse' on R tokens of these forms mints b122/b124.
#[test]
fn t328_4_r_window_reuse_mint_preserved() {
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        let w = enc(&t, "HFMA2 R9, R12.reuse.H0_H0, UR8.H0_H0, -R11.reuse.H1_H1")
            .unwrap_or_else(|e| panic!("{arch}: {e}"));
        assert_eq!((w >> 122) & 1, 1, "{arch} b122 minted");
        assert_eq!((w >> 124) & 1, 1, "{arch} b124 minted");
        assert_eq!((w >> 123) & 1, 0, "{arch} b123 stays clear");
    }
}
