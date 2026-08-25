//! mk56: LDC geo anchors `01 0b 04 0a` with b13=0x04 — CLOSED for the driver
//! window c[0x0][0x360..0x378]. Corpus rules (merclab/mk56 c1..c13,
//! 1580 l2 files, records /tmp/mk40/recs.jsonl):
//! - a record PER LANE `LDC Rn, c[0x0][0x360..0x378]` (not per-first-def:
//!   a dup-def dest carries a record per instruction; c6/rot/splitKreduce),
//! - b12 = the window map {360:1, 364:2, 368:3, 370:4, 374:5, 378:6} (the same
//!   geometry numbering as the SR enum in mk13; b13=04 tells the LDC class apart),
//! - payload b10/b11 = (dest<<6)|1 like an S2R anchor; b4 = the mk41 guard
//!   (corpus: 399x @!P1, 310x @!P0 on b13=04); b6=04 fixed,
//! - TLV order = the instruction lane (c12: 18831/18831), the boot anchor always
//!   position 0 (18932/18932),
//! - fail-closed: LDC.64 / LDC.U8 / LDCU/ULDC / dest RZ / offsets outside the
//!   fix-map window (e.g. 0x380+ takes b12 from ptxas value analysis — mk57),
//! - mk56 additionally: SR_LEMASK=9, SR_GTMASK=10 in merc_s2r_sr_enum
//!   (c10: corpus 1:1 245 GTMASK / 2 LEMASK; the dominant E02 mk55 residual).
//! The c7 emulator: 17951/18932 kernels multiset+byte EXACT for
//! boot + per-S2R-lane + per-LDC-lane (reszta = klasy value-analysis,
//! parked mk57: MOV/IMAD/LEA/LOP3/LDG + LDC poza oknem fix-map).
use cubit::mercury::{merc_ldc_geo, merc_s2r_sr_enum};

#[test]
fn mk56_ldcgeo_window_gold() {
    // (text, dest, b12) — pairs from the sm_100 corpus (map c4/c7).
    let v: &[(&str, u32, u8)] = &[
        ("LDC R0, c[0x0][0x360] ;", 0, 1),
        ("LDC R5, c[0x0][0x364] ;", 5, 2),
        ("LDC R4, c[0x0][0x368] ;", 4, 3),
        ("LDC R3, c[0x0][0x370] ;", 3, 4),
        ("LDC R2, c[0x0][0x374] ;", 2, 5),
        ("LDC R1, c[0x0][0x378] ;", 1, 6),
        ("@!P1 LDC R5, c[0x0][0x364] ;", 5, 2),
        ("@P0 LDC R9, c[0x0][0x370] ;", 9, 4),
    ];
    for (t, d, g) in v {
        assert_eq!(merc_ldc_geo(t), Some((*d, *g)), "{t}");
    }
}

#[test]
fn mk56_ldcgeo_fail_closed() {
    for t in [
        "LDC.64 R4, c[0x0][0x380] ;",   // .64 poza fix-mapa (value-analysis)
        "LDC.64 R4, c[0x0][0x370] ;",   // .64 even in the window — not a shaved LDC
        "LDC.U8 R2, c[0x0][0x3bc] ;",
        "LDCU UR5, c[0x0][0x360] ;",    // uniform — to 010b060a (mk46)
        "ULDC UR4, c[0x0][0x360] ;",
        "LDC RZ, c[0x0][0x360] ;",      // RZ carries no anchor
        "LDC R2, c[0x0][0x380] ;",      // okno poza fix-mapa
        "LDC R2, c[0x0][0x3f0] ;",
        "LDC R2, c[0x2][0x360] ;",      // inny bank
        "LDG.E R2, [R4] ;",
        "S2R R2, SR_TID.X ;",
    ] {
        assert_eq!(merc_ldc_geo(t), None, "{t}");
    }
}

#[test]
fn mk56_sr_enum_maski() {
    assert_eq!(merc_s2r_sr_enum("SR_GTMASK"), 10);
    assert_eq!(merc_s2r_sr_enum("SR_LEMASK"), 9);
    // istniejace klucze nietkniete
    assert_eq!(merc_s2r_sr_enum("SR_LTMASK"), 8);
    assert_eq!(merc_s2r_sr_enum("SR_CgaCtaId"), 0x2c);
}

#[test]
fn mk56_ldcgeo_record_shape() {
    // The record shape byte-wise (like Ev::AnchorGeo in elf_builder):
    // 01 0b 04 0a | b4=guard | 00 | b6=04 | 00 00 00 | (dest<<6)|1 LE | b12 | 04 | 00 00
    // Gold from the corpus: splitKreduce LDC R5, c[0x0][0x364] ->
    let gold = [
        0x01u8, 0x0b, 0x04, 0x0a, 0xf8, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x41, 0x01, 0x02, 0x04, 0x00, 0x00,
    ];
    let (d, b12) = merc_ldc_geo("LDC R5, c[0x0][0x364] ;").unwrap();
    let mut cf = [
        0x01u8, 0x0b, 0x04, 0x0a, 0xf8, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00, 0x00,
    ];
    let v: u32 = (d << 6) | 1;
    cf[10] = (v & 0xff) as u8;
    cf[11] = (v >> 8) as u8;
    cf[12] = b12;
    cf[13] = 0x04;
    assert_eq!(&cf, &gold);
}
