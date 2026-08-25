//! mk71: closing the 28-fold family + the NEW 01291004 record (xor-U).
//!
//! (a) 41271004 = ULOP3.LUT 6tok !UPT noimm, lut in {0xc0, 0x30, 0x0c}
//!     (AND fam: a&b / a&~b / !a&b). l2 corpus EXACT 1395/1395 (mk70:
//!     1175; widened by the xmma-Lt residual, merclab/mk71 c4/c8, over=0).
//! (b) 41281004 = the 2-op OR family: 0xfc (a|b; mk70) + 0xf3 (a|!b; xmma
//!     185/185 EXACT; all 6tok URdst noimm; bitmap hosts 185/185 bit=0).
//! (c) 01291004 = `ULOP3.LUT URd, URa, URb, URZ, 0x3c, !UPT` (uniform xor):
//!     16B `01 29 10 04 fa 00 04 00 01 f8 | dst<<6|1 u16 | a<<6 u16 | b<<6
//!     u16` — 491/491 payload-EXACT (c7), header/b4 fixed, the lane without a
//!     bitmap bit (per the mk13/mk47/mk58 doctrine).
use cubit::mercury::merc_ulop3_xor_record;
use cubit::sass_file::merc_fold28;

trait Hex {
    fn hexify(&self) -> String;
}
impl Hex for [u8; 16] {
    fn hexify(&self) -> String {
        self.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[test]
fn uxor_accept() {
    // libcublasLt.so.1170 kernel_blas3 L36 (TLV13, mk71 c2):
    // ULOP3.LUT UR11, UR8, UR4, URZ, 0x3c, !UPT
    assert_eq!(
        merc_ulop3_xor_record("ULOP3.LUT UR11, UR8, UR4, URZ, 0x3c, !UPT ;", 0xf8)
            .unwrap()
            .hexify(),
        "01291004fa00040001f8c10200020001"
    );
}

#[test]
fn uxor_reject() {
    // imm in a/b (the imm form gets no record — 348 l2 lanes)
    assert!(merc_ulop3_xor_record("ULOP3.LUT UR11, UR8, 0x1, URZ, 0x3c, !UPT ;", 0xf8).is_none());
    // inny LUT / c!=URZ / pin != !UPT / LOP3 (R-space ma 01290004 z mk13)
    assert!(merc_ulop3_xor_record("ULOP3.LUT UR11, UR8, UR4, URZ, 0xc0, !UPT ;", 0xf8).is_none());
    assert!(merc_ulop3_xor_record("ULOP3.LUT UR11, UR8, UR4, UR6, 0x3c, !UPT ;", 0xf8).is_none());
    assert!(merc_ulop3_xor_record("ULOP3.LUT UR11, UR8, UR4, URZ, 0x3c, UPT ;", 0xf8).is_none());
    assert!(merc_ulop3_xor_record("LOP3.LUT R11, R8, R4, RZ, 0x3c ;", 0xf8).is_none());
    assert!(merc_ulop3_xor_record("ULOP3.LUT UP0, URZ, UR8, UR4, URZ, 0x3c, !UPT ;", 0xf8).is_none());
}

#[test]
fn fold28_and_fam() {
    // mk70 pozostaje: c0
    assert_eq!(merc_fold28("ULOP3.LUT UR7, UR10, UR6, URZ, 0xc0, !UPT"), Some(0x04102741));
    // mk71: 0x30 (xmma lt.1170 L44) i 0x0c (cusparse.342 spike L54/L56)
    assert_eq!(merc_fold28("ULOP3.LUT UR10, UR6, UR10, URZ, 0x30, !UPT"), Some(0x04102741));
    assert_eq!(merc_fold28("ULOP3.LUT UR5, UR6, UR5, URZ, 0x0c, !UPT"), Some(0x04102741));
    // imm gate unchanged (selfimm UR8,UR8,0x1 -> none)
    assert_eq!(merc_fold28("ULOP3.LUT UR8, UR8, 0x1, URZ, 0xc0, !UPT"), None);
    assert_eq!(merc_fold28("ULOP3.LUT UR8, UR6, 0x1, URZ, 0x30, !UPT"), None);
}

#[test]
fn fold28_or_fam() {
    // f3 (xmma lt.1170 L17), 6tok URdst:
    assert_eq!(merc_fold28("ULOP3.LUT UR7, UR6, UR4, URZ, 0xf3, !UPT"), Some(0x04102841));
    // mk70 pozostaje: fc 6tok URdst / 7tok UPdst / neg-forma; b8 poza klasa
    assert_eq!(merc_fold28("ULOP3.LUT UR7, UR10, UR6, URZ, 0xfc, !UPT"), Some(0x04102841));
    assert_eq!(merc_fold28("ULOP3.LUT UP0, URZ, UR16, UR18, URZ, 0xfc, !UPT"), Some(0x04102841));
    assert_eq!(merc_fold28("ULOP3.LUT UR6, UR6, UR10, UR7, 0xb8, !UPT"), None);
    assert_eq!(merc_fold28("ULOP3.LUT UR11, UR8, UR4, URZ, 0x3c, !UPT"), None);
}
