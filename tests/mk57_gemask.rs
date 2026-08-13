//! mk57: domkniecie residuow rodziny anchor 010b040a (value-analysis 1:1):
//! - SR_GEMASK = 11 (0x0b) w merc_s2r_sr_enum — korpus 1:1
//!   (merclab/mk57 c4: wszystkie 607 rekordow b12=11 na l2 stoja przy
//!   lane'ach z destem of S2R SR_GEMASK; 92 kernele residualne M02/E02
//!   cub/thrust znikaja; c6: emulator z GEMASK=11 daje 18932/18932 EXACT
//!   multiset+byte razem z c[0x0][0x2f8]),
//! - rekord geo-anchor b13=04 dla LDC @ c[0x0][0x2f8] -> b12=0x44
//!   (c5: 12 rekordow / 9 kerneli cusparse glu_qdcsrsv2/csrqr/binary_search:
//!   bijekcja lane<->rekord 1:1, 0 FP, 0 rekordow 0x44 bez lane'a 0x2f8).
//! Po mk57 emulator 010b040a (boot + per-S2R-lane + per-LDC-lane z mapa
//! {2f8:44,360:1,364:2,368:3,370:4,374:5,378:6}): 18932/18932 EXACT.
use cubit::mercury::{merc_ldc_geo, merc_s2r_sr_enum};

#[test]
fn mk57_sr_gemask() {
    assert_eq!(merc_s2r_sr_enum("SR_GEMASK"), 11);
    // sasiedzi nietkniete (regres-strażnik: fallback zostaje 1)
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
        "LDC R2, c[0x0][0x2f4] ;",   // sasiedzi 0x2f8 — nadal fail-closed
        "LDC R2, c[0x0][0x2fc] ;",
        "LDC.64 R4, c[0x0][0x2f8] ;", // .64 — nie golony LDC
        "LDC RZ, c[0x0][0x2f8] ;",
        "LDC R2, c[0x2][0x2f8] ;",   // inny bank
    ] {
        assert_eq!(merc_ldc_geo(t), None, "{t}");
    }
}
