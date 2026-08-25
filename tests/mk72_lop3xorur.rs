//! mk72: the NEW 01290804 record (mixed R/R/UR xor): siblings 01291004 (mk71,
//! 3xUR) and 01290004 (mk13, 3xR) with b2=0x08.
//!
//! Corpus class (l2, EXACT 271/271 count-wise per kernel and payload-wise,
//! merclab/mk72 c11/c12): `LOP3.LUT Rd, Ra, URb, RZ, 0x3c, !PT` — dst and srcA
//! are R registers, the srcB operand UR<n>, unguarded (b4=0xf8 fixed; guarded
//! forms unobserved -> fail-closed). 16B: `01 29 08 04 f8 00 04 00 01 f8 |
//! dst<<6|1 u16 | a<<6 u16 | b<<6 u16`. Lane without a bitmap bit (the
//! mk13/mk47/mk58/mk71: rekord zastepuje wezel t4).
use cubit::mercury::merc_lop3_xor_ur_record;

trait Hex {
    fn hexify(&self) -> String;
}
impl Hex for [u8; 16] {
    fn hexify(&self) -> String {
        self.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[test]
fn lop3xorur_accept() {
    // libcublasLt.so.502 gemvx-double2 L98 (mk72 c7): orig payload (4,4,22):
    assert_eq!(
        merc_lop3_xor_ur_record("LOP3.LUT R4, R4, UR22, RZ, 0x3c, !PT ;", 0xf8)
            .unwrap()
            .hexify(),
        "01290804f800040001f8010100018005"
    );
    // dominanta korpusowa (50 wystapien): R8, R3, UR7 (cusparse.590 etc.):
    assert_eq!(
        merc_lop3_xor_ur_record("LOP3.LUT R8, R3, UR7, RZ, 0x3c, !PT ;", 0xf8)
            .unwrap()
            .hexify(),
        "01290804f800040001f80102c000c001"
    );
}

#[test]
fn lop3xorur_reject() {
    // siostry rodziny: (R,R,R) -> 01290004 mk13; (UR,UR,UR) -> 01291004 mk71
    assert!(merc_lop3_xor_ur_record("LOP3.LUT R4, R4, R5, RZ, 0x3c, !PT ;", 0xf8).is_none());
    assert!(merc_lop3_xor_ur_record("ULOP3.LUT UR4, UR4, UR22, URZ, 0x3c, !UPT ;", 0xf8).is_none());
    // imm w srcB -> kanal imm mk13; ULOP3 nigdy
    assert!(merc_lop3_xor_ur_record("LOP3.LUT R4, R4, 0x5, RZ, 0x3c, !PT ;", 0xf8).is_none());
    // inny lut / c != RZ / pin != !PT / 5 tokenow / guard -> fail-closed
    assert!(merc_lop3_xor_ur_record("LOP3.LUT R4, R4, UR22, RZ, 0xc0, !PT ;", 0xf8).is_none());
    assert!(merc_lop3_xor_ur_record("LOP3.LUT R4, R4, UR22, R6, 0x3c, !PT ;", 0xf8).is_none());
    assert!(merc_lop3_xor_ur_record("LOP3.LUT R4, R4, UR22, RZ, 0x3c, PT ;", 0xf8).is_none());
    assert!(merc_lop3_xor_ur_record("LOP3.LUT R4, R4, UR22, RZ, 0x3c ;", 0xf8).is_none());
    assert!(merc_lop3_xor_ur_record("LOP3.LUT R4, R4, UR22, RZ, 0x3c, !PT ;", 0x11).is_none());
    // UR in srcA or dst are outside the class (unobserved)
    assert!(merc_lop3_xor_ur_record("LOP3.LUT R4, UR4, UR22, RZ, 0x3c, !PT ;", 0xf8).is_none());
    // URZ in srcB: 'URZ' is not UR<num> — corpus-unobserved
    assert!(merc_lop3_xor_ur_record("LOP3.LUT R4, R4, URZ, RZ, 0x3c, !PT ;", 0xf8).is_none());
}
