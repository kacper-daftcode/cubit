//! mk53: silnik rekordow 02 23 30 34 / 34 34 (LDGSTS desc-form pinned blobs).
//! Wektory gold = doslowne bajty z korpusu sm_100 (syherk_559 = K1,
//! cuds_symv annotated = SY) + gold m15_base (single-blob, mk14.3-compat).
use cubit::mercury::{build_ldgsts2_blob, merc_ldgsts2_scan, Ldgsts2Blob};

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
fn mk53_m15_base_single_gold() {
    let l = lanes(&[
        (15, "@!PT LDS RZ, [RZ] ;"),
        (16, "@!PT LDS RZ, [RZ] ;"),
        (17, "@!PT LDS RZ, [RZ] ;"),
        (18, "LDGSTS.E [R7], desc[UR6][R4.64] ;"),
        (22, "LDS R9, [R6+UR4] ;"),
    ]);
    let blobs = merc_ldgsts2_scan(&l, "m15_base");
    assert_eq!(blobs.len(), 1);
    assert!(blobs[0].pin);
    assert_eq!(blobs[0].pin_host, Some(15));
    let blob = build_ldgsts2_blob(&blobs[0], true);
    let gold = hx("02233034f800241000010000c0010a010002010900820100f800000000000000");
    assert_eq!(blob.as_slice(), gold.as_slice());
}

#[test]
fn mk53_k1_multi_grupy_i_piny() {
    let l = lanes(&[
        (181, "@!PT LDS RZ, [RZ] ;"),
        (182, "@!PT LDS RZ, [RZ] ;"),
        (183, "@!PT LDS RZ, [RZ] ;"),
        (184, "@!P1 LDGSTS.E.BYPASS.128 [R26], desc[UR20][R54.64] ;"),
        (185, "@!P1 LDGSTS.E.BYPASS.128 [R26+0x2000], desc[UR20][R52.64] ;"),
        (186, "LDGDEPBAR ;"),
        (192, "@!PT LDS RZ, [RZ] ;"),
        (193, "@!PT LDS RZ, [RZ] ;"),
        (194, "@!PT LDS RZ, [RZ] ;"),
        (195, "LDGSTS.E.BYPASS.128 [R26+0x1000], desc[UR20][R14.64+0x40] ;"),
        (196, "LDGSTS.E.BYPASS.128 [R26+0x3000], desc[UR20][R16.64+0x40] ;"),
        (197, "LDGDEPBAR ;"),
        (538, "@!PT LDS RZ, [RZ] ;"),
        (539, "@!PT LDS RZ, [RZ] ;"),
        (540, "@!PT LDS RZ, [RZ] ;"),
        (541, "@!P1 LDGSTS.E.BYPASS.128 [R75], desc[UR20][R16.64] ;"),
        (544, "@!P1 LDGSTS.E.BYPASS.128 [R75+0x2000], desc[UR20][R52.64] ;"),
        (547, "LDGDEPBAR ;"),
    ]);
    let blobs = merc_ldgsts2_scan(&l, "_Z20syherk_kernel_ldgstsXX");
    assert_eq!(blobs.len(), 6);
    assert_eq!(
        blobs.iter().map(|b| b.pin).collect::<Vec<_>>(),
        vec![true, false, true, false, true, false]
    );
    assert_eq!(blobs.iter().map(|b| b.pin_host).collect::<Vec<_>>(),
               vec![Some(181), None, Some(192), None, Some(538), None]);
    // b22: driver per-kernel NIEZNANY (park mk54, sweep na harnessie) —
    // porownujemy wszystko poza b22.
    for (idx, gold_hex) in [
        (0usize, "02233034090020101001000080060a0100820d0900020500f800000000000000"),
        (2usize, "02233034f80020101001000080060a010082030900020500f800400000100000"),
        (3usize, "02233034f80020101001000080060a010002040900020500f800400000300000"),
    ] {
        let got = build_ldgsts2_blob(&blobs[idx], false);
        let gold = hx(gold_hex);
        for j in 0..32 {
            if j == 22 {
                continue;
            }
            assert_eq!(got[j], gold[j], "blob {idx} bajt {j}");
        }
    }
}

#[test]
fn mk53_guard_i_fail_closed() {
    let l = lanes(&[
        (10, "@UP1 LDGSTS.E.BYPASS.128 [R26], desc[UR20][R54.64] ;"),
        (11, "LDGSTS.E.BYPASS.128 [UR4], desc[UR20][R54.64] ;"),
        (12, "LDGSTS.E.BYPASS.128 [R26], [R54.64] ;"),
        (13, "LDGSTS.E.BYPASS.128 [R26], desc[UR20][R54.64], P2 ;"),
    ]);
    let blobs = merc_ldgsts2_scan(&l, "x");
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].npred, Some(2));
    let b = build_ldgsts2_blob(&blobs[0], true);
    assert_eq!(b[24], 2 << 3);
}

#[test]
fn mk53_tag3434_cutlass80() {
    let l = lanes(&[(7, "LDGSTS.E.BYPASS.LTC128B.128 [R140], desc[UR6][R28.64], P0 ;")]);
    let b1 = merc_ldgsts2_scan(&l, "cutlass_80_tensorop_x");
    let b2 = merc_ldgsts2_scan(&l, "zwykly_kernel");
    assert_eq!(b1.len(), 1);
    assert!(b1[0].tag3434);
    assert!(!b2[0].tag3434);
    let blob = build_ldgsts2_blob(&b1[0], true);
    assert_eq!(&blob[..4], &[0x02, 0x23, 0x34, 0x34]);
    assert_eq!(blob[6], 0x20);
    assert_eq!(blob[8], 0x12);
    let _t: Ldgsts2Blob = b2[0].clone();
}
