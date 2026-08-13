//! mk55: rekordy wait 01 23 40 0a (16B) per DEPBAR.SB0 — multi-wait DOMKNIETE.
//! Reguly korpusowe (merclab/mk55 c1..c9, 2619/2619 rekordow, 1250/1250 kerneli
//! multiset+porzadek EXACT, obustronnie):
//! - rekord tylko dla klasy SB0 (`DEPBAR.LE SB0, 0xN`); SB5 nie nosi rekordu
//!   (dlatego mk53-per-DEPBAR "przepieklo" o +208 new-only),
//! - b11 = imm DEPBAR; bajty stale: b4=f8 (brak guarda korpusowo; guard ->
//!   fail-closed), b6=08, reszta 0,
//! - host = ostatnia slotted instrukcja przed DEPBARem (zero-weight skip),
//! - legacy mk14.3 (brak desc-form LDGSTS): single-wait tez z true-imm.
//! Wektory gold = doslowne bajty z korpusu sm_100 (atlas mk54hA keep-set).
use cubit::mercury::{build_ldgsts2_wait, merc_ldgsts2_scan, merc_ldgsts2_waits, merc_ldgsts_scan};

fn hx(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn lanes(v: &[(u32, &str)]) -> Vec<(u32, String)> {
    v.iter().map(|(l, t)| (*l, t.to_string())).collect()
}

#[test]
fn mk55_wait_bytes_gold() {
    // imm 0..3: bajty wprost z korpusu (cuds_symv / cutlass_80).
    assert_eq!(
        build_ldgsts2_wait(0).as_slice(),
        hx("0123400af80008000000000000000000").as_slice()
    );
    assert_eq!(
        build_ldgsts2_wait(1).as_slice(),
        hx("0123400af80008000000000100000000").as_slice()
    );
    assert_eq!(
        build_ldgsts2_wait(2).as_slice(),
        hx("0123400af80008000000000200000000").as_slice()
    );
    assert_eq!(
        build_ldgsts2_wait(3).as_slice(),
        hx("0123400af80008000000000300000000").as_slice()
    );
}

#[test]
fn mk55_sb0_only_i_imm_pooparta() {
    // wejscie z klastrem SB5 jak getrf (libcusolver 985/993): rekordy tylko
    // dla SB0, imm brane z operandu DEPBAR-a, hosty = poprzednie slotted.
    let l = lanes(&[
        (10, "IADD3 R1, R2, R3, RZ ;"),
        (11, "LDGDEPBAR ;"),
        (12, "DEPBAR.LE SB0, 0x3 ;"),
        (13, "DEPBAR.LE SB5, 0x7 ;"), // SB5: bez rekordu
        (14, "LDS.128 R36, [R1+UR4+0x100] ;"),
        (15, "LDCU.64 UR20, c[0x0][0x440] ;"),
        (16, "LDGDEPBAR ;"),
        (17, "LDC.64 R12, c[0x0][0x398] ;"), // zero-weight? nie — LDC
        (18, "DEPBAR.LE SB0, 0x0 ;"), // host = L17 (LDC.64), LDGDEPBAR skip
        (19, "BRA 0x30 ;"),
        (20, "DEPBAR.LE SB0, 0x1 ;"), // host = L19 (BRA)
    ]);
    let w = merc_ldgsts2_waits(&l);
    assert_eq!(w, vec![(10, 3u8), (17, 0u8), (19, 1u8)]);
}

#[test]
fn mk55_guard_fail_closed() {
    let l = lanes(&[
        (5, "ISETP.GT.AND P0, PT, R1, RZ, PT ;"),
        (6, "@P0 DEPBAR.LE SB0, 0x1 ;"), // guardowany: korpusowo nieobs., FC
        (7, "@!P0 DEPBAR.LE SB5, 0x0 ;"),
        (8, "DEPBAR.LE SB0, 0x2 ;"), // host = L5? nie — guardowany tez jest
                                   // lane'm; poprz slotted = L6? L6 jest
                                   // slotted (DEPBAR jest zero-weight!) ->
                                   // host = L5 (ostatnia slotted przed 8:
                                   // L6/L7 to DEPBAR-y => skip)
    ]);
    let w = merc_ldgsts2_waits(&l);
    assert_eq!(w, vec![(5, 2u8)]);
}

#[test]
fn mk55_multiwait_blob_kernel_przeplot() {
    // scena jak K1/xmma: runy killpadow + bloby + DEPBAR-y; waity miedzy.
    let l = lanes(&[
        (100, "@!PT LDS RZ, [RZ] ;"),
        (101, "@!PT LDS RZ, [RZ] ;"),
        (102, "LDGSTS.E.BYPASS.128 [R26], desc[UR20][R54.64] ;"),
        (103, "LDGDEPBAR ;"),
        (104, "IMAD.WIDE R4, R5, R6, c[0x0][0x168] ;"),
        (105, "DEPBAR.LE SB0, 0x0 ;"), // host = 104
        (106, "LDS.128 R36, [R36.128+UR4] ;"),
        (107, "DEPBAR.LE SB0, 0x1 ;"), // host = 106
        (108, "LDGSTS.E.BYPASS.128 [R26+0x2000], desc[UR20][R52.64] ;"),
        (109, "LDGDEPBAR ;"),
        (110, "LDSM.16.M88.4 R110, [R65] ;"),
        (111, "DEPBAR.LE SB0, 0x2 ;"), // host = 110
        (112, "DEPBAR.LE SB5, 0xc ;"), // bez rekordu
    ]);
    let blobs = merc_ldgsts2_scan(&l, "K1ish");
    assert_eq!(blobs.len(), 2);
    let w = merc_ldgsts2_waits(&l);
    assert_eq!(w, vec![(104, 0u8), (106, 1u8), (110, 2u8)]);
    // bajty sekwencyjnie: gold korpusowy wzorzec imm
    let bytes: Vec<u8> = w
        .iter()
        .flat_map(|&(_, imm)| build_ldgsts2_wait(imm))
        .collect();
    let gold = hx(
        "0123400af80008000000000000000000\
         0123400af80008000000000100000000\
         0123400af80008000000000200000000",
    );
    assert_eq!(bytes, gold);
}

#[test]
fn mk55_legacy_wait_true_imm() {
    // no-desc-form (mk14.3): pojedynczy DEPBAR SB0 po LDGSTS -> (host, imm).
    // (syherk-era: legacy kiedys const imm=0 — mk55 naprawia b11).
    let l = lanes(&[
        (10, "LDGSTS.E [R7], desc[UR16][R2.64] ;"), // desc-form! -> blob-path,
                                                    // legacy skaner i tak tu
                                                    // zwroci wait lt. (host,
                                                    // imm); emisja legacy jest
                                                    // gated l2-empty poza tym
                                                    // skanerem
        (11, "LDS.128 R36, [R36+UR4] ;"),
        (12, "LDGDEPBAR ;"),
        (13, "DEPBAR.LE SB5, 0x1 ;"), // SB5 nie wybieramy
        (14, "DEPBAR.LE SB0, 0x2 ;"),
        (15, "EXIT ;"),
    ]);
    let (_pin, wait) = merc_ldgsts_scan(&l);
    assert_eq!(wait, Some((11, 2u8))); // host = poprz slotted przed L14, imm=2
}
