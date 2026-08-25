//! mk58: 012b080a records (16B): host = a lane
//! `ULOP3.LUT URd, URZ, URs, URZ, 0x33, !UPT` (uniform NOT-MOV; LUT 0x33 = !B),
//! optionally with an @!UPn guard. Corpus closure (676 sm_100 files,
//! 18932 kernels): multiset (guard,URd,URs) EXACT over 975/975 kernels with records
//! (1630 records) + reverse gate 0 kernels with a lane pattern but no record
//! (merclab/mk58 c3/c4). Guard: none -> 0xfa (the |2 bit relative to 0xf8 from mk47);
//! only negated @!UPn ((n<<3)|3) — a positive @UPn without a single
//! corpus occurrence -> fail-closed. Lane without a bitmap bit (675/134,
//! doktryna 'rekord zastepuje wezel t4').
use cubit::mercury::merc_ulop3_not_record;

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
    // korpus cutlass_80_simt_sgemm_grouped (cublas.1070), lane 8173/8215
    assert_eq!(
        merc_ulop3_not_record("@!UP1 ULOP3.LUT UR5, URZ, UR6, URZ, 0x33, !UPT ;", 0x0b)
            .unwrap()
            .hexify(),
        "012b080a0b000400000001f841018001"
    );
    assert_eq!(
        merc_ulop3_not_record("@!UP0 ULOP3.LUT UR5, URZ, UR7, URZ, 0x33, !UPT ;", 0x03)
            .unwrap()
            .hexify(),
        "012b080a03000400000001f84101c001"
    );
    // unguarded (the most common corpus-wise, 1319/1630): b4=0xfa; UR5<=UR4
    assert_eq!(
        merc_ulop3_not_record("ULOP3.LUT UR5, URZ, UR4, URZ, 0x33, !UPT ;", 0xf8)
            .unwrap()
            .hexify(),
        "012b080afa000400000001f841010001"
    );
    // @!UP2 (0x13), korpus: UR5<=UR7
    assert_eq!(
        merc_ulop3_not_record("@!UP2 ULOP3.LUT UR5, URZ, UR7, URZ, 0x33, !UPT ;", 0x13)
            .unwrap()
            .hexify(),
        "012b080a13000400000001f84101c001"
    );
}

#[test]
fn pattern_reject() {
    // positive @UPn / P-space guard: corpus-absent -> fail-closed
    assert!(merc_ulop3_not_record("@UP1 ULOP3.LUT UR5, URZ, UR6, URZ, 0x33, !UPT ;", 0x0a).is_none());
    assert!(merc_ulop3_not_record("@!P1 ULOP3.LUT UR5, URZ, UR6, URZ, 0x33, !UPT ;", 0x09).is_none());
    // other LUT / non-UR operand / non-UR dest
    assert!(merc_ulop3_not_record("ULOP3.LUT UR5, URZ, UR6, URZ, 0xc0, !UPT ;", 0xf8).is_none());
    assert!(merc_ulop3_not_record("ULOP3.LUT UR5, URZ, R6, URZ, 0x33, !UPT ;", 0xf8).is_none());
    assert!(merc_ulop3_not_record("ULOP3.LUT R5, URZ, UR6, URZ, 0x33, !UPT ;", 0xf8).is_none());
    // RZ instead of URZ in the a/c slot
    assert!(merc_ulop3_not_record("ULOP3.LUT UR5, RZ, UR6, URZ, 0x33, !UPT ;", 0xf8).is_none());
    assert!(merc_ulop3_not_record("ULOP3.LUT UR5, URZ, UR6, RZ, 0x33, !UPT ;", 0xf8).is_none());
    // URZ dest/source rejected like a non-numeric reg
    assert!(merc_ulop3_not_record("ULOP3.LUT URZ, URZ, UR6, URZ, 0x33, !UPT ;", 0xf8).is_none());
    assert!(merc_ulop3_not_record("ULOP3.LUT UR5, URZ, URZ, URZ, 0x33, !UPT ;", 0xf8).is_none());
    // LOP3 outside the family (mk47 handles), a !PT predicate without U
    assert!(merc_ulop3_not_record("ULOP3.LUT UR5, URZ, UR6, URZ, 0x33, !PT ;", 0xf8).is_none());
    assert!(merc_lop3_not_less("LOP3.LUT R6, RZ, R5, RZ, 0x33, !PT ;"));
}

fn merc_lop3_not_less(t: &str) -> bool {
    // The ULOP3 scanner must reject plain LOP3 (the base split lives in the caller).
    merc_ulop3_not_record(t, 0xf8).is_none()
}
