//! mk54: rekordy rodziny 02 10 (klasa SETP):
//!   02 10 02 14 = PLOP3.LUT z uniform Pc (Pd, PT, Pa, PT, UPn, l1, l2)
//!   02 10 04 14 = UPLOP3.LUT (wszystkie predy uniform; Pt/Pa/Pb == UPT)
//!   02 10 16 0e = DSETP z imm f64, Pt==PT i Pc==PT (marker 13@b14)
//!   02 10 0a 0e = DSETP z imm f64, Pt!=PT lub Pc!=PT (marker 13@b17)
//! Gold vectors = literal bytes from the sm_100 corpus (merclab/mk54 c20:
//! 4347/4347 kernels multiset+sequence EXACT, bidirectional).
use cubit::mercury::{merc_dsetpimm_record, merc_plop3u_record, merc_uplop3_record};

fn hx(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn mk54_plop3u_gold() {
    // (lane text, gold hex) — all unguarded (b4=f8).
    let v: &[(&str, &str)] = &[
        ("PLOP3.LUT P3, PT, PT, PT, UP0, 0x80, 0x8 ;", "02100214f80000000000011801f800f80000f800000000000000000000000000"),
        ("PLOP3.LUT P0, PT, PT, PT, UP1, 0x80, 0x8 ;", "02100214f80000000000010001f800f80000f800080000000000000000000000"),
        ("PLOP3.LUT P0, PT, P0, PT, UP0, 0xea, 0xae ;", "02100214f80000010000010001f800000000f800000000000000000000000000"),
        ("PLOP3.LUT P6, PT, P5, PT, UP0, 0xd5, 0x5d ;", "02100214f80000210000013001f800280000f800000000000000000000000000"),
        ("PLOP3.LUT P0, PT, P0, PT, UP0, 0x5d, 0xd5 ;", "02100214f80000290000010001f800000000f800000000000000000000000000"),
        ("PLOP3.LUT P0, PT, PT, PT, UP0, 0x40, 0x4 ;", "02100214f80000200000010001f800f80000f800000000000000000000000000"),
    ];
    for (t, g) in v {
        assert_eq!(merc_plop3u_record(t, 0xf8).map(|r| r.to_vec()), Some(hx(g)), "{t}");
    }
}

#[test]
fn mk54_plop3u_fail_closed() {
    for t in [
        "PLOP3.LUT P0, PT, PT, PT, PT, 0x80, 0x8 ;",   // all-P -> mk44, not mk54
        "PLOP3.LUT P0, PT, PT, PT, UP7, 0x80, 0x8 ;",  // UP7 poza zakresem
        "PLOP3.LUT P6, PT, P5, PT, UP0, 0xf8, 0x8f ;", // para LUT poza tabela
        "PLOP3.LUT P6, PT, P5, PT, UP0, 0xd5, 0x44 ;", // non-nibswap
    ] {
        assert_eq!(merc_plop3u_record(t, 0xf8), None, "{t}");
    }
    // lane z guardem (tekstowo '@P0') + kod guarda -> tez fail-closed
    // a guarded variant (guard_code != f8) fails closed regardless of the text
    assert_eq!(
        merc_plop3u_record("PLOP3.LUT P0, PT, PT, PT, UP0, 0x80, 0x8 ;", 0x01),
        None
    );
    assert_eq!(
        merc_plop3u_record("@P0 PLOP3.LUT P0, PT, PT, PT, UP0, 0x80, 0x8 ;", 0x00),
        None
    );
}

#[test]
fn mk54_uplop3_gold() {
    let v: &[(u8, &str, &str)] = &[
        (0xf8, "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8 ;", "02100414fa0000000000010001f800f80000f800f80000000000000000000000"),
        (0xf8, "UPLOP3.LUT UP2, UPT, UPT, UPT, UPT, 0x40, 0x4 ;", "02100414fa0000200000011001f800f80000f800f80000000000000000000000"),
        (0xf8, "UPLOP3.LUT UP6, UPT, UPT, UPT, UPT, 0x40, 0x4 ;", "02100414fa0000200000013001f800f80000f800f80000000000000000000000"),
        (0xf8, "UPLOP3.LUT UP2, UPT, UPT, UPT, UP1, 0x80, 0x8 ;", "02100414fa0000000000011001f800f80000f800080000000000000000000000"),
        (0x0b, "@!UP1 UPLOP3.LUT UP0, UPT, UPT, UPT, UP2, 0x80, 0x8 ;", "021004140b0000000000010001f800f80000f800100000000000000000000000"),
    ];
    for (gc, t, g) in v {
        assert_eq!(merc_uplop3_record(t, *gc).map(|r| r.to_vec()), Some(hx(g)), "{t}");
    }
    // P-space (non-uniform) guard -> fail-closed
    assert_eq!(
        merc_uplop3_record("UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8 ;", 0x01),
        None
    );
    assert_eq!(
        merc_uplop3_record("UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x20, 0x2 ;", 0xf8),
        None
    );
}

#[test]
fn mk54_dsetpimm_16_gold() {
    let v: &[(u8, &str, &str)] = &[
        (0xf8, "DSETP.GTU.AND P0, PT, |R2|, +INF , PT ;", "0210160ef800880900000100820013000000000000000000000000000000f07f"),
        (0xf8, "DSETP.GTU.AND P1, PT, |R30|, +INF , PT ;", "0210160ef800880900000108820713000000000000000000000000000000f07f"),
        (0xf8, "DSETP.GT.AND P1, PT, R28, 1, PT ;", "0210160ef800880000000108020713000000000000000000000000000000f03f"),
        (0xf8, "DSETP.GE.AND P0, PT, R8, 4.98960077383679952914e+291, PT ;", "0210160ef800c80000000100020213000000000000000000000000000000807c"),
        (0xf8, "DSETP.NEU.AND P0, PT, R6, 1, PT ;", "0210160ef800a80100000100820113000000000000000000000000000000f03f"),
        (0xf8, "DSETP.EQ.AND P1, PT, R20, 1, PT ;", "0210160ef800480000000108020513000000000000000000000000000000f03f"),
        (0xf8, "DSETP.GEU.AND P0, PT, R28.reuse, 1, PT ;", "0210160ef800c80100000100020713000000000000000000000000000000f03f"),
    ];
    for (gc, t, g) in v {
        assert_eq!(merc_dsetpimm_record(t, *gc).map(|r| r.to_vec()), Some(hx(g)), "{t}");
    }
}

#[test]
fn mk54_dsetpimm_0a_gold() {
    let v: &[(u8, &str, &str)] = &[
        (0x01, "@!P0 DSETP.EQ.AND P1, PT, R20, 1, !P2 ;", "02100a0e010048800000010801f802050013000010000000000000000000f03f"),
        (0x09, "@!P1 DSETP.EQ.AND P0, PT, R20, 1, !P2 ;", "02100a0e090048800000010001f802050013000010000000000000000000f03f"),
        (0xf8, "DSETP.NEU.OR P1, PT, R12, 1, P1 ;", "02100a0ef800a8050000010801f802030013000008000000000000000000f03f"),
        (0xf8, "DSETP.EQ.AND P0, PT, R4, 1, !P0 ;", "02100a0ef80048800000010001f802010013000000000000000000000000f03f"),
        (0xf8, "DSETP.LE.OR P0, PT, R16, 2.004168360008972778e-292, P2 ;", "02100a0ef80068040000010001f8020400130000100000000000000000006003"),
        (0xf8, "DSETP.LT.AND P0, PT, R8, 1, !P0 ;", "02100a0ef80028800000010001f802020013000000000000000000000000f03f"),
        (0xf8, "DSETP.MAX.AND P0, P1, R2, 1, PT ;", "02100a0ef800e801000001000108820000130000f8000000000000000000f03f"),
    ];
    for (gc, t, g) in v {
        assert_eq!(merc_dsetpimm_record(t, *gc).map(|r| r.to_vec()), Some(hx(g)), "{t}");
    }
}

#[test]
fn mk54_dsetpimm_fail_closed() {
    for t in [
        "DSETP.NEU.AND P0, PT, R6, RZ, PT ;",     // 4th operand RZ (not a literal)
        "DSETP.NEU.AND P0, PT, R6, UR4, PT ;",    // UR
        "DSETP.NEU.AND P0, PT, R6, R8, PT ;",     // reg-reg
        "DSETP.MIN.AND P0, PT, R6, 1, PT ;",      // MIN poza drabinka
        "DSETP.NEU.AND P0, PT, -R6, 1, PT ;",     // neg A
        "DSETP.NEU.AND UP0, PT, R6, 1, PT ;",     // Pd uniform
        "DSETP.GTU.AND P0, PT, R6, 1, UP2 ;",     // Pc uniform
        "DSETP.NEU.AND P0, PT, R6, QNAN, PT ;",   // NAN imm
        "DSETP.GT.OR P0, PT, R6, 1, PT ;",        // .OR w 16-formie
        "DSETP.LT.AND P0, PT, R6, 1, PT ;",       // LT w 16-formie
    ] {
        assert_eq!(merc_dsetpimm_record(t, 0xf8), None, "{t}");
    }
}
