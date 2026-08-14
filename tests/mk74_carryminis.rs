//! mk74: nowe minis-carry IADD3.X 421d0a06/421d0814 + ULOP3-fc-imm 42280c06.
//! Reguly z korpusu sm_100 (merclab/mk74 c3 bitmap-attr, c8/c9 fit):
//! EXACT licznikowo 5893/5893 kerneli l2 (0a06 305/305, 0814 7233/7233,
//! 80c06 527/527 — bramka lut==0xfc; 0xc0/0x3c/0x0c bez rekordu).
use cubit::sass_file::{kernel_def_to_meta, merc_iadd3x_carry, merc_ulop3_fcimm, parse_sass_file_str};

fn minis(sass: &str) -> Vec<(u32, u32)> {
    let file = parse_sass_file_str(sass).unwrap();
    let n = file.kernels[0].instructions.len();
    let meta = kernel_def_to_meta(&file.kernels[0], &vec![0u8; 16 * (n + 1)]);
    meta.merc_mini2
}

#[test]
fn iadd3x_imm_is_0a06() {
    // transpose_readWrite cublas.14 (imm w tok4)
    assert_eq!(
        merc_iadd3x_carry("IADD3.X R28, PT, PT, R21, -0x1, RZ, P2, P3 ;"),
        Some(0x060a1d42)
    );
    // imm w tok3 tez (trmm_right cublasLt.477) + guard OK
    assert_eq!(
        merc_iadd3x_carry("@P1 IADD3.X R20, PT, PT, RZ, -0x1, RZ, P0, P1 ;"),
        Some(0x060a1d42)
    );
    // imm-form zakonczona (PT,PT) bez rekordu (fit korpusowy: tylko (Pn,Pn))
    assert_eq!(
        merc_iadd3x_carry("IADD3.X R26, PT, PT, R59, 0x4, RZ, PT, PT ;"),
        None
    );
    assert_eq!(
        merc_iadd3x_carry("IADD3.X R26, PT, PT, R59, R24, RZ, P2, !PT ;"),
        None
    );
}

#[test]
fn iadd3x_reg_is_0814() {
    // sbhbmv cublas.273 klassycznie; guarded wariant gemvx cublasLt.468
    assert_eq!(
        merc_iadd3x_carry("IADD3.X R21, PT, PT, RZ, R9, RZ, P1, P2 ;"),
        Some(0x14081d42)
    );
    assert_eq!(
        merc_iadd3x_carry("@!P1 IADD3.X R88, PT, PT, R65, R88.reuse, RZ, P4, P5 ;"),
        Some(0x14081d42)
    );
    // hseqr chase_bulge: ogon (PT,PT) bez UR -> rekord (14/14 resid)
    assert_eq!(
        merc_iadd3x_carry("IADD3.X R0, PT, PT, R0, R15, RZ, PT, PT ;"),
        Some(0x14081d42)
    );
    // negacje: tok5 != RZ; UR w operandach; 7 tokenow; IADD3 bez .X
    assert_eq!(merc_iadd3x_carry("IADD3.X R33, PT, PT, R2, R13, R2, P3, P4 ;"), None);
    assert_eq!(merc_iadd3x_carry("IADD3.X R15, PT, PT, R12, UR4, RZ, PT, PT ;"), None);
    assert_eq!(merc_iadd3x_carry("IADD3.X R24, PT, PT, RZ, ~R6, RZ, P0, !PT ;"), None);
    assert_eq!(merc_iadd3x_carry("IADD3 R10, P2, PT, R0, 0x1, RZ ;"), None);
}

#[test]
fn ulop3_fcimm_is_80c06() {
    assert_eq!(
        merc_ulop3_fcimm("ULOP3.LUT UR13, UR12, 0xffffffe0, URZ, 0xfc, !UPT ;"),
        Some(0x060c2842)
    );
    // lut 0xc0/0x3c bez rekordu; guard fail-closed; LOP3 (R-form) bez rekordu
    assert_eq!(merc_ulop3_fcimm("ULOP3.LUT UR10, UR9, 0xf, URZ, 0xc0, !UPT ;"), None);
    assert_eq!(merc_ulop3_fcimm("@P2 ULOP3.LUT UR13, UR12, 0x10, URZ, 0xfc, !UPT ;"), None);
    assert_eq!(merc_ulop3_fcimm("LOP3.LUT R54, R27, 0xffff, RZ, 0xc0, !PT ;"), None);
}

#[test]
fn minis_pipeline() {
    let x = minis(
        ".entry t\n    .reg R0-R79\n    IADD3.X R18, PT, PT, RZ, R13, RZ, P1, P2 ;\n    ULOP3.LUT UR4, UR4, 0x200, URZ, 0xfc, !UPT ;\n    IADD3.X R3, PT, PT, R3, -0x1, R9, P1, P2 ;\n",
    );
    assert!(x.contains(&(0, 0x14081d42)), "jest: {x:?}");
    assert!(x.contains(&(1, 0x060c2842)), "jest: {x:?}");
    assert!(!x.iter().any(|&(_, m)| m == 0x060a1d42), "tok5!=RZ nie moze byc 0a06: {x:?}");
    assert_eq!(x.len(), 2);
}
