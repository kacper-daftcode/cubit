//! mk67 (2026-08-13): domkniecie rodziny mini2 4B (dekod merclab/mk67):
//!  * 410c260a HADD2: NIE dla HADD2.F32 (widening) ani dla form z literalem
//!    imm ("HADD2 R11, RZ, -1.875, -1.875" — 5 lane'i korpusowych);
//!    regula plain-no-F32-no-imm EXACT 2527/2527 kerneli korpusu.
//!  * 4105000a BREAK: NIE dla BREAK.RELIABLE (atrybucja TLV c18 gemmk1 203:
//!    rekordy siadaja na plain BREAK B0, RELIABLE B1 nigdy);
//!    regula no-RELIABLE EXACT 2723/2723 kerneli korpusu.
use cubit::parser::parse_sass;
use cubit::sass_file::{merc_mini2_scan, merc_txt_has_imm_literal};

fn scan_named(name: &str, lines: &[&str]) -> Vec<(u32, u32)> {
    let ins: Vec<_> = lines
        .iter()
        .enumerate()
        .map(|(i, t)| parse_sass(t, (i * 16) as u32).unwrap())
        .collect();
    merc_mini2_scan(name, &ins)
}
fn scan(lines: &[&str]) -> Vec<(u32, u32)> {
    scan_named("k_plain", lines)
}

#[test]
fn hadd2_plain_and_bf16_get_mini() {
    let r = scan(&[
        "HADD2 R0, R2.H0_H0, R3.H0_H0 ;",
        "HADD2.BF16_V2 R4, R6.H0_H0, RZ.H0_H0 ;",
        "@P2 HADD2 R8, R9.H1_H1, R10.H0_H0 ;",
    ]);
    assert_eq!(
        r,
        vec![(0, 0x0a260c41), (1, 0x0a260c41), (2, 0x0a260c41)],
        "plain/BF16/predykatowane HADD2 dostaja mini"
    );
}

#[test]
fn hadd2_f32_and_imm_form_no_mini() {
    // korpus: 2321 kerneli z samymi .F32 (kandydatura (d)); 5 lane'i imm
    // (cublasLt.so.197 epilogue x3 + cusparse.766 x2) — orig NIGDY nie emituje.
    let r = scan(&[
        "HADD2.F32 R25, -RZ, R28.H0_H0 ;",
        "HADD2 R11, RZ, -1.875, -1.875 ;",
        "@P2 HADD2 R11, RZ, -1, -1 ;",
        "HADD2 R2, R3.H0_H0, 0x3c00 ;",
    ]);
    assert!(r.is_empty(), "F32/imm-form bez mini, dostalismy: {:?}", r);
}

#[test]
fn break_plain_only() {
    let r = scan(&[
        "@P1 BREAK.RELIABLE B1 ;",
        "@P0 BREAK B0 ;",
        "BREAK B0 ;",
        "@P0 PREEXIT B0 ;",
    ]);
    assert_eq!(
        r,
        vec![(1, 0x0a000541), (2, 0x0a000541), (3, 0x0a026241)],
        "RELIABLE bez mini; PREEXIT bez zmian, dostalismy: {:?}", 
        r
    );
}

#[test]
fn imm_literal_helper() {
    assert!(!merc_txt_has_imm_literal("HADD2 R0, R2.H0_H0, R3.H0_H0 ;"));
    assert!(merc_txt_has_imm_literal("HADD2 R11, RZ, -1.875, -1.875 ;"));
    assert!(merc_txt_has_imm_literal("HADD2 R2, R3.H0_H0, 0x3c00 ;"));
    assert!(merc_txt_has_imm_literal("@P2 HADD2 R11, RZ, -1, -1 ;"));
    assert!(!merc_txt_has_imm_literal("HADD2.F32 R25, -RZ, R28.H0_H0 ;"));
    // dest-slot nie moze byc mylony z imm:
    assert!(!merc_txt_has_imm_literal("BREAK B0 ;"));
}

#[test]
fn ffma_mini_only_in_xmma_fp32_dialect() {
    let l = &["FFMA R2, R23, R20, R2 ;", "FFMA2 R4, R5.H0_H0, R6.H0_H0, R4 ;"];
    // dialekt fp32: oba rekordy; cp32 i plain: tylko FFMA2
    assert_eq!(
        scan_named("sm80_xmma_syrk_nt_l_tilesize128x64x8_stage4_ffma_fp32_kernel", l),
        vec![(0, 0x0a101741), (1, 0x26140d42)]
    );
    assert_eq!(
        scan_named("sm80_xmma_syrk_nt_l_tilesize128x64x8_stage3_ffma_cp32_kernel", l),
        vec![(1, 0x26140d42)]
    );
    assert_eq!(scan_named("_Z15axpy_kernel_refI6__halffEv19cublasAxpyParam", l), vec![(1, 0x26140d42)]);
}
