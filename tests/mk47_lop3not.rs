//! mk47: rekordy 012b{00|04}0a (16B): host = lane
//! `LOP3.LUT Rd, RZ, Rs, RZ, 0x33, !PT` (kanoniczny NOT-MOV; LUT 0x33 = !B).
//! Rd always R<n>; class (tag byte 2): 0x00 when Rs = R<n>, 0x04 when Rs =
//! UR<n>. Domkniecie korpusowe (676 plikow sm_100): multiset
//! (guard,Rd,Rs,cls) EXACT 7305/7305 kerneli z rekordami + 0 kerneli
//! with a lane pattern but no record (17684 records: 16478 R + 1206 UR).
//! The host lane gets no bitmap bit (the "record replaces the t4 node" doctrine).
use cubit::mercury::merc_lop3_not_record;

trait Hex {
    fn hexify(&self) -> String;
}
impl Hex for [u8; 16] {
    fn hexify(&self) -> String {
        self.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[test]
fn pattern_accept() {
    // korpus tpttr (cublas.651): LOP3.LUT R6, RZ, R5, RZ, 0x33, !PT
    assert_eq!(
        merc_lop3_not_record("LOP3.LUT R6, RZ, R5, RZ, 0x33, !PT ;", 0xf8)
            .unwrap()
            .hexify(),
        "012b000af8000400000001f881014001"
    );
    // guarded @!P2 (kod 0x11); korpus sddmm (cusparse.230)
    assert_eq!(
        merc_lop3_not_record("LOP3.LUT R4, RZ, R7, RZ, 0x33, !PT ;", 0x11)
            .unwrap()
            .hexify(),
        "012b000a11000400000001f80101c001"
    );
    // .reuse na operandach (korpus tbmv cublas.195)
    assert_eq!(
        merc_lop3_not_record("LOP3.LUT R4, RZ, R2.reuse, RZ, 0x33, !PT ;", 0xf8)
            .unwrap()
            .hexify(),
        "012b000af8000400000001f801018000"
    );
    // korpus sphpmv (cublas.285): guard @P1 -> 0x08, rd=2, rs=2
    assert_eq!(
        merc_lop3_not_record("@P1 LOP3.LUT R2, RZ, R2, RZ, 0x33, !PT ;", 0x08)
            .unwrap()
            .hexify(),
        "012b000a08000400000001f881008000"
    );
}

#[test]
fn ur_source_class() {
    // korpus sellmv (cusparse.126): Rs = UR4 -> klasa 0x04, guard 0x11
    assert_eq!(
        merc_lop3_not_record("@!P2 LOP3.LUT R3, RZ, UR4, RZ, 0x33, !PT ;", 0x11)
            .unwrap()
            .hexify(),
        "012b040a11000400000001f8c1000001"
    );
}

#[test]
fn pattern_reject() {
    // inne LUT / formy
    assert!(merc_lop3_not_record("LOP3.LUT R6, R4, 0x600, RZ, 0xc0, !PT ;", 0xf8).is_none());
    assert!(merc_lop3_not_record("LOP3.LUT R8, R8, UR4, RZ, 0xfc, !PT ;", 0xf8).is_none());
    // RZ not in the a/c slots
    assert!(merc_lop3_not_record("LOP3.LUT R6, R5, RZ, RZ, 0x33, !PT ;", 0xf8).is_none());
    assert!(merc_lop3_not_record("LOP3.LUT R6, RZ, R5, R7, 0x33, !PT ;", 0xf8).is_none());
    // non-R dest (predicate form)
    assert!(merc_lop3_not_record("LOP3.LUT P0, RZ, R5, RZ, 0x33, !PT ;", 0xf8).is_none());
    // dest/source RZ rejected like any non-numeric reg
    assert!(merc_lop3_not_record("LOP3.LUT RZ, RZ, R5, RZ, 0x33, !PT ;", 0xf8).is_none());
    assert!(merc_lop3_not_record("LOP3.LUT R6, RZ, RZ, RZ, 0x33, !PT ;", 0xf8).is_none());
    // PLOP3 / ULOP3 spoza rodziny
    assert!(merc_lop3_not_record("PLOP3.LUT P0, PT, PT, PT, PT, 0x80, 0x8 ;", 0xf8).is_none());
    assert!(merc_lop3_not_record("ULOP3.LUT UR4, URZ, UR5, URZ, 0x33, !UPT ;", 0xf8).is_none());
}
