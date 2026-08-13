//! mk56: geo-anchory LDC `01 0b 04 0a` z b13=0x04 — DOMKNIETE dla okna
//! drivera c[0x0][0x360..0x378]. Reguly korpusowe (merclab/mk56 c1..c13,
//! 1580 plikow l2, rekordy /tmp/mk40/recs.jsonl):
//! - rekord PER LANE `LDC Rn, c[0x0][0x360..0x378]` (nie per-first-def:
//!   dup-def desta nosi rekord per instrukcja; c6/rot/splitKreduce),
//! - b12 = mapa okna {360:1, 364:2, 368:3, 370:4, 374:5, 378:6} (ta sama
//!   numeracja geometrii co enum SR mk13; b13=04 odroznia klase-LDC),
//! - payload b10/b11 = (dest<<6)|1 jak anchor S2R; b4 = guard mk41
//!   (korpus: 399x @!P1, 310x @!P0 na b13=04); b6=04 stale,
//! - porzadek TLV = lane instrukcji (c12: 18831/18831), boot-anchor zawsze
//!   pozycja 0 (18932/18932),
//! - fail-closed: LDC.64 / LDC.U8 / LDCU/ULDC / dest RZ / offset spoza
//!   okna fix-mapy (np. 0x380+ ma b12 z value-analysis ptxas — mk57),
//! - dodatkowo mk56: SR_LEMASK=9, SR_GTMASK=10 w merc_s2r_sr_enum
//!   (c10: korpus 1:1 245 GTMASK / 2 LEMASK; dominowny residuum E02 mk55).
//! Emulator c7: 17951/18932 kerneli multiset+byte EXACT dla
//! boot + per-S2R-lane + per-LDC-lane (reszta = klasy value-analysis,
//! parked mk57: MOV/IMAD/LEA/LOP3/LDG + LDC poza oknem fix-map).
use cubit::mercury::{merc_ldc_geo, merc_s2r_sr_enum};

#[test]
fn mk56_ldcgeo_window_gold() {
    // (tekst, dest, b12) — pary z korpusu sm_100 (mapa c4/c7).
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
        "LDC.64 R4, c[0x0][0x370] ;",   // .64 nawet w oknie — nie golony LDC
        "LDC.U8 R2, c[0x0][0x3bc] ;",
        "LDCU UR5, c[0x0][0x360] ;",    // uniform — to 010b060a (mk46)
        "ULDC UR4, c[0x0][0x360] ;",
        "LDC RZ, c[0x0][0x360] ;",      // RZ nie nosi anchora
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
    // Ksztalt rekordu bajtowo (jak Ev::AnchorGeo w elf_builder):
    // 01 0b 04 0a | b4=guard | 00 | b6=04 | 00 00 00 | (dest<<6)|1 LE | b12 | 04 | 00 00
    // Gold z korpusu: splitKreduce LDC R5, c[0x0][0x364] ->
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
