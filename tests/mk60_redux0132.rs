//! mk60: rekordy 0132100a (16B) per lane REDUX/CREDUX — DOMKNIECIE
//! nadprodukcji (front mk59hA: new-only 289) i pelny dekod klas:
//!   CREDUX.MAX.S32 -> b6=55, CREDUX.MIN.S32 -> b6=51, CREDUX.MIN -> b6=50,
//!   REDUX.SUM.S32  -> b6=4d (ale dst==UR79 BEZ rekordu: 88/88 korpus);
//!   REDUX.OR (3376 lane'ow), goly REDUX, guardy: NIGDY rekordu.
//! Pola: (b10,b11)=LE16((URd<<6)|1), (b12,b13)=LE16(src<<6), RZ-src ->
//! 0xffc0; (b14,b15)=0; b4=f8 zawsze (guard -> fail-closed).
//! Korpus l2 676 / 18932 kerneli (merclab/mk60 c1/c2): align lane->rekord
//! EXACT (parowanie podzbioru noszacego, porzadek zachowany).
use cubit::mercury::merc_redux2_record;

fn hex(b: Option<[u8; 16]>) -> String {
    b.map(|x| x.iter().map(|b2| format!("{:02x}", b2)).collect())
        .unwrap_or_else(|| "NONE".into())
}

#[test]
fn classes_and_fields() {
    // cublasLt.191 splitKreduce: CREDUX.MAX.S32 UR5, R2 (korpus).
    assert_eq!(
        hex(merc_redux2_record("CREDUX.MAX.S32 UR5, R2 ;")),
        "0132100af80055000000410180000000"
    );
    // CREDUX.MIN (bez .S32): b6=50.
    assert_eq!(
        hex(merc_redux2_record("CREDUX.MIN UR5, R2 ;")),
        "0132100af80050000000410180000000"
    );
    // CREDUX.MIN.S32 + src R30 (bsrsv2 cusparse.286): f2=0x780.
    assert_eq!(
        hex(merc_redux2_record("CREDUX.MIN.S32 UR5, R30 ;")),
        "0132100af80051000000410180070000"
    );
    // RZ src -> sentinel f2=0xffc0 (splitKreduce CREDUX.MAX.S32 UR8, RZ).
    assert_eq!(
        hex(merc_redux2_record("CREDUX.MAX.S32 UR8, RZ ;")),
        "0132100af800550000000102c0ff0000"
    );
    // REDUX.SUM.S32: b6=4d; p_redux (mk35 gold): UR6, R0.
    assert_eq!(
        hex(merc_redux2_record("REDUX.SUM.S32 UR6, R0 ;")),
        "0132100af8004d000000810100000000"
    );
    // forma wydruku cubit (legacy reversed) akceptowana identycznie.
    assert_eq!(
        hex(merc_redux2_record("REDUX.S32.SUM UR6, R0 ;")),
        hex(merc_redux2_record("REDUX.SUM.S32 UR6, R0 ;"))
    );
}

#[test]
fn rejects() {
    // REDUX.OR — glowny zrodlo nadprodukcji (symv, korpus 3376 lane'ow).
    assert!(merc_redux2_record("REDUX.OR UR4, R6 ;").is_none());
    // goly REDUX (stary warp-vote).
    assert!(merc_redux2_record("REDUX UR5, R0 ;").is_none());
    // dst UR79 przy REDUX.SUM.S32 (coomm; korpusowo bez rekordu).
    assert!(merc_redux2_record("REDUX.SUM.S32 UR79, R12 ;").is_none());
    // guard -> fail-closed.
    assert!(merc_redux2_record("@P1 CREDUX.MIN.S32 UR5, R30 ;").is_none());
    // dst R-klasa / URZ / src UR — brak korpusowy.
    assert!(merc_redux2_record("CREDUX.MIN.S32 R5, R30 ;").is_none());
    assert!(merc_redux2_record("CREDUX.MIN.S32 URZ, R30 ;").is_none());
    assert!(merc_redux2_record("REDUX.SUM.S32 UR6, UR3 ;").is_none());
    // 3 operandosc / nieznane klasy.
    assert!(merc_redux2_record("CREDUX.MIN.S32 UR5, R30, R31 ;").is_none());
    assert!(merc_redux2_record("CREDUX.AND.S32 UR5, R30 ;").is_none());
    assert!(merc_redux2_record("REDUX.MAX.U32 UR5, R30 ;").is_none());
}
