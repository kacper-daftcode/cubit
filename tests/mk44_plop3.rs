//! mk44: generalizacja rekordow 0110060a (PLOP3 dual-output, nibswap-LUT pair).
//! Zrodla: korpus EQ 5902/5902 kerneli (K4 w mk44/c011m), sondy nvcc
//! sm_100a/sm_103a (mk44/lutsweep, probe101) — era-inwariantne.
use cubit::mercury::{merc_plop3_record, MERC_TMA_A, MERC_TMA_B, MERC_TMA_C};

#[test]
fn legacy_trio_identical() {
    assert_eq!(merc_plop3_record("PLOP3.LUT P0, PT, PT, PT, PT, 0x80, 0x8 ;", 0xf8), Some(MERC_TMA_A));
    assert_eq!(merc_plop3_record("@P1 PLOP3.LUT P0, PT, P1, PT, PT, 0x8, 0x80 ;", 0x08), Some(MERC_TMA_B));
    assert_eq!(merc_plop3_record("PLOP3.LUT P1, PT, PT, PT, PT, 0x8, 0x80 ;", 0xf8), Some(MERC_TMA_C));
}

#[test]
fn general_fields() {
    // k7-sonda: Pd=P0 Pa=P1 Pb=P0 luts (f8,8f) -> b6=0x20 b7=0
    assert_eq!(
        merc_plop3_record("PLOP3.LUT P0, PT, P1, P0, PT, 0xf8, 0x8f ;", 0xf8),
        Some([0x01,0x10,0x06,0x0a, 0xf8,0,0x20,0, 0,0,0x01,0x00, 0,0x08, 0,0x00])
    );
    // guard @!P2 + Pd=P2 Pa=P0 Pb=P1 luts (28,82)
    assert_eq!(
        merc_plop3_record("@!P2 PLOP3.LUT P2, PT, P0, P1, PT, 0x28, 0x82 ;", 0x11),
        Some([0x01,0x10,0x06,0x0a, 0x11,0,0x40,0, 0,0,0x01,0x10, 0,0x00, 0,0x08])
    );
    // negacja na Pa
    assert_eq!(
        merc_plop3_record("PLOP3.LUT P3, PT, !P4, PT, PT, 0x8, 0x80 ;", 0xf8),
        Some([0x01,0x10,0x06,0x0a, 0xf8,0,0x00,1, 0,0,0x01,0x18, 0,0x21, 0,0xf8])
    );
}

#[test]
fn gates() {
    // non-nibswap (0xe0,0) -> no record (527 clean kernels, trsv)
    assert_eq!(merc_plop3_record("PLOP3.LUT P0, PT, P0, P1, P2, 0xe0, 0x0 ;", 0xf8), None);
    // non-nibswap luts (0x50,0)
    assert_eq!(merc_plop3_record("PLOP3.LUT P0, PT, P0, P1, P2, 0x50, 0x0 ;", 0xf8), None);
    // UP w Pc
    assert_eq!(merc_plop3_record("PLOP3.LUT P0, PT, PT, PT, UP0, 0x80, 0x8 ;", 0xf8), None);
    // nieznana para nibswap (canonical-unseen)
    assert_eq!(merc_plop3_record("PLOP3.LUT P0, PT, P1, P2, PT, 0x96, 0x69 ;", 0xf8), None);
    // not PLOP3
    assert_eq!(merc_plop3_record("LOP3.LUT R1, R2, R3, R4, 0x8, 0x80 ;", 0xf8), None);
    // Pd == PT
    assert_eq!(merc_plop3_record("PLOP3.LUT PT, PT, P1, P2, PT, 0x8, 0x80 ;", 0xf8), None);
}
