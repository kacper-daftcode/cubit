//! mk55: 01 23 40 0a wait records (16B) per DEPBAR.SB0 — multi-wait CLOSED.
//! Corpus rules (merclab/mk55 c1..c9, 2619/2619 records, 1250/1250 kernels
//! multiset+order EXACT, bidirectional):
//! - record only for the SB0 class (`DEPBAR.LE SB0, 0xN`); SB5 carries no record
//!   (which is why the mk53 per-DEPBAR probe "overbaked" by +208 new-only),
//! - b11 = the DEPBAR imm; fixed bytes: b4=f8 (corpus-wise no guard; a guard ->
//!   fail-closed), b6=08, the rest 0,
//! - host = the last slotted instruction before the DEPBAR (zero-weight skip),
//! - legacy mk14.3 (no LDGSTS desc forms): single-wait with the true imm too.
//! Gold vectors = literal bytes from the sm_100 corpus (the mk54hA atlas keep-set).
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
    // imm 0..3: bytes straight from the corpus (cuds_symv / cutlass_80).
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
    // input with an SB5 cluster like getrf (libcusolver 985/993): records only
    // for SB0, the imm taken from the DEPBAR operand, hosts = previous slotted.
    let l = lanes(&[
        (10, "IADD3 R1, R2, R3, RZ ;"),
        (11, "LDGDEPBAR ;"),
        (12, "DEPBAR.LE SB0, 0x3 ;"),
        (13, "DEPBAR.LE SB5, 0x7 ;"), // SB5: no record
        (14, "LDS.128 R36, [R1+UR4+0x100] ;"),
        (15, "LDCU.64 UR20, c[0x0][0x440] ;"),
        (16, "LDGDEPBAR ;"),
        (17, "LDC.64 R12, c[0x0][0x398] ;"), // zero-weight? no — LDC
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
        (8, "DEPBAR.LE SB0, 0x2 ;"), // host = L5? no — the guarded one is also
                                   // a lane; the previous slotted = L6? L6 is
                                   // slotted (the DEPBAR is zero-weight!) ->
                                   // host = L5 (ostatnia slotted przed 8:
                                   // L6/L7 to DEPBAR-y => skip)
    ]);
    let w = merc_ldgsts2_waits(&l);
    assert_eq!(w, vec![(5, 2u8)]);
}

#[test]
fn mk55_multiwait_blob_kernel_przeplot() {
    // a scene like K1/xmma: killpad runs + blobs + DEPBARs; waits between them.
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
        (112, "DEPBAR.LE SB5, 0xc ;"), // no record
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
    // no-desc-form (mk14.3): a single DEPBAR SB0 after LDGSTS -> (host, imm).
    // (syherk era: legacy used to be const imm=0 — mk55 fixes b11).
    let l = lanes(&[
        (10, "LDGSTS.E [R7], desc[UR16][R2.64] ;"), // desc-form! -> the blob path, but
                                                    // the legacy scanner still
                                                    // returns wait lt. (host,
                                                    // imm) here; legacy emission is
                                                    // gated l2-empty outside this
                                                    // scanner path.
        (11, "LDS.128 R36, [R36+UR4] ;"),
        (12, "LDGDEPBAR ;"),
        (13, "DEPBAR.LE SB5, 0x1 ;"), // SB5 not picked
        (14, "DEPBAR.LE SB0, 0x2 ;"),
        (15, "EXIT ;"),
    ]);
    let (_pin, wait) = merc_ldgsts_scan(&l);
    assert_eq!(wait, Some((11, 2u8))); // host = poprz slotted przed L14, imm=2
}
