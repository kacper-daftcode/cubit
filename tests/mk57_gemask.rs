//! mk57: closing the residuals of the 010b040a anchor family (value analysis 1:1):
//! - SR_GEMASK = 11 (0x0b) in merc_s2r_sr_enum — corpus 1:1
//!   (merclab/mk57 c4: all 607 records with b12=11 on l2 stand by
//!   lanes whose dest is S2R SR_GEMASK; the 92 residual M02/E02
//!   cub/thrust kernels vanish; c6: the emulator with GEMASK=11 gives 18932/18932 EXACT
//!   multiset+byte together with c[0x0][0x2f8]),
//! - the b13=04 geo-anchor record for LDC @ c[0x0][0x2f8] -> b12=0x44
//!   (c5: 12 records / 9 cusparse kernels glu_qdcsrsv2/csrqr/binary_search:
//!   lane<->record bijection 1:1, 0 FP, 0 records 0x44 without a 0x2f8 lane).
//! Po mk57 emulator 010b040a (boot + per-S2R-lane + per-LDC-lane z mapa
//! {2f8:44,360:1,364:2,368:3,370:4,374:5,378:6}): 18932/18932 EXACT.
use cubit::mercury::{merc_ldc_geo, merc_s2r_sr_enum};

#[test]
fn mk57_sr_gemask() {
    assert_eq!(merc_s2r_sr_enum("SR_GEMASK"), 11);
    // neighbors untouched (regression guard: the fallback stays 1)
    assert_eq!(merc_s2r_sr_enum("SR_GTMASK"), 10);
    assert_eq!(merc_s2r_sr_enum("SR_CLOCK"), 1); // nieznane -> TID.X fallback
}

#[test]
fn mk57_ldc_2f8_gold() {
    // cusparse binary_search_lb_offset_kernel: LDC @0x2f8 dest 30
    // -> rekord b10/b11 = (30<<6)|1 = 0x781, b12=0x44, b13=04.
    assert_eq!(merc_ldc_geo("LDC R30, c[0x0][0x2f8] ;"), Some((30, 0x44)));
    // csrqr_upper_direct_qd: desty 11 i 19
    assert_eq!(merc_ldc_geo("LDC R11, c[0x0][0x2f8] ;"), Some((11, 0x44)));
    assert_eq!(merc_ldc_geo("@!P0 LDC R19, c[0x0][0x2f8] ;"), Some((19, 0x44)));
}

#[test]
fn mk57_ldc_2f8_sasiedzi_falz() {
    for t in [
        "LDC R2, c[0x0][0x2f4] ;",   // the 0x2f8 neighbor — still fail-closed
        "LDC R2, c[0x0][0x2fc] ;",
        "LDC.64 R4, c[0x0][0x2f8] ;", // .64 — not a shaved LDC
        "LDC RZ, c[0x0][0x2f8] ;",
        "LDC R2, c[0x2][0x2f8] ;",   // inny bank
    ] {
        assert_eq!(merc_ldc_geo(t), None, "{t}");
    }
}
