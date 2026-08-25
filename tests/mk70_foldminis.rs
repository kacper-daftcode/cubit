//! mk70 (2026-08-13): the 28-family minis — the early-exit prolog idiom
//! cublas-COMMONS (OR-fold of predicates through (U)LOP3.LUT + @P EXIT / BRA[.U]).
//! Atrybucja merclab/mk70 c1..c19 (l2 korpus 18932 kern):
//!   42281414 EXACT 16/16, 42282414 EXACT 21/21,
//!   41271004 pure EXACT 18729 (resid xmma-selfimm, park mk71),
//!   41281004 over=0 (resid xmma, park mk71).
//! Dowody okienkowe: rotm_kernel_val dd (cublas.153) tight-window (36,44):
//! TLV19=41281004 -> L41 ULOP3.fc !UPT, TLV20=42282414 -> L42 ULOP3.fc UP0.

use cubit::sass_file::merc_fold28;

#[test]
fn mk70_c0_pure() {
    // 41 27 10 04: ULOP3.LUT 6tok lut=0xc0 !UPT no imm
    assert_eq!(
        merc_fold28("ULOP3.LUT UR11, UR16, UR11, URZ, 0xc0, !UPT ;"),
        Some(0x04102741)
    );
    // imm w tok2 wyklucza (maski alignment w axpy / trsm)
    assert_eq!(merc_fold28("ULOP3.LUT UR8, UR6, 0x3, URZ, 0xc0, !UPT ;"), None);
    assert_eq!(
        merc_fold28("ULOP3.LUT UR4, UR4, 0xffffffe0, URZ, 0xc0, !UPT ;"),
        None
    );
}

#[test]
fn mk70_fc_start() {
    // 41 28 10 04: 6tok UR-dst (magma) albo 7tok UP-dst (rotm-dd L41)
    assert_eq!(
        merc_fold28("ULOP3.LUT UR4, UR4, UR5, URZ, 0xfc, !UPT ;"),
        Some(0x04102841)
    );
    assert_eq!(
        merc_fold28("ULOP3.LUT UP0, URZ, UR6, UR8, URZ, 0xfc, !UPT ;"),
        Some(0x04102841)
    );
    // imm-mask wyklucza (trsm_ln/trsm_lt over-fix mk70/c17)
    assert_eq!(
        merc_fold28("ULOP3.LUT UR4, UR4, 0xffffffe0, URZ, 0xfc, !UPT ;"),
        None
    );
    // mk70b: cubit-neg-forma nvdis-7tok (rot_kernel bf16 prolog, c14/nvdis)
    assert_eq!(
        merc_fold28("ULOP3.LUT URZ, UR16, UR18, URZ, 0xfc, !UP0 ;"),
        Some(0x04102841)
    );
    // c0 with neg-UP is not 41281004
    assert_eq!(merc_fold28("ULOP3.LUT URZ, UR16, UR18, URZ, 0xc0, !UP0 ;"), None);
}

#[test]
fn mk70_fc_cont() {
    // 42 28 24 14: ULOP3.LUT 7tok UP-dst, cin=UP<n> (rotm-dd L42)
    assert_eq!(
        merc_fold28("ULOP3.LUT UP0, URZ, UR7, UR9, URZ, 0xfc, UP0 ;"),
        Some(0x14242842)
    );
    // 42 28 14 14: LOP3.LUT 7tok P-dst, cin=P<n> (swap L18)
    assert_eq!(
        merc_fold28("LOP3.LUT P1, RZ, R3, R5, RZ, 0xfc, P1 ;"),
        Some(0x14142842)
    );
    // start forms (cin=!PT/!UPT / P-only) are not continuations
    assert_eq!(
        merc_fold28("LOP3.LUT P1, RZ, R8, UR4, RZ, 0xfc, !PT ;"),
        None
    );
    // an @Px guard ahead of the line does not interfere
    assert_eq!(
        merc_fold28("@P2 ULOP3.LUT UP0, URZ, UR7, UR9, URZ, 0xfc, UP0 ;"),
        Some(0x14242842)
    );
}

#[test]
fn mk70_no_side_classes() {
    // klasy pokrewne NIE sa 28-minis: NOT-MOV 0x33 (mk47/58), 0xb8-sign (mk68B)
    assert_eq!(merc_fold28("ULOP3.LUT UR10, URZ, UR4, URZ, 0x33, !UPT ;"), None);
    assert_eq!(
        merc_fold28("ULOP3.LUT UP0, URZ, UR7, 0x80000000, URZ, 0xb8, !UPT ;"),
        None
    );
    // plain IMAD etc.
    assert_eq!(merc_fold28("IADD3 R1, P0, PT, R2, RZ, RZ ;"), None);
}
