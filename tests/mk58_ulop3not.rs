//! mk58: rekordy 012b080a (16B): host = lane
//! `ULOP3.LUT URd, URZ, URs, URZ, 0x33, !UPT` (uniformny NOT-MOV; LUT 0x33 = !B),
//! opcjonalnie z guardem @!UPn. Domkniecie korpusowe (676 plikow sm_100,
//! 18932 kerneli): multiset (guard,URd,URs) EXACT 975/975 kerneli z rekordami
//! (1630 rekordy) + bramka odwrotna 0 kerneli z lane-wzorcem bez rekordu
//! (merclab/mk58 c3/c4). Guard: brak -> 0xfa (bit |2 wzgledem 0xf8 z mk47);
//! tylko zanegowane @!UPn ((n<<3)|3) — pozytywny @UPn bez jedynego
//! wystapienia korpusowego -> fail-closed. Lane bez bitu bitmapy (675/134,
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
    // bez guardu (najczestszy korpusowo, 1319/1630): b4=0xfa; UR5<=UR4
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
    // pozytywny @UPn / P-space guard: brak korpusowy -> fail-closed
    assert!(merc_ulop3_not_record("@UP1 ULOP3.LUT UR5, URZ, UR6, URZ, 0x33, !UPT ;", 0x0a).is_none());
    assert!(merc_ulop3_not_record("@!P1 ULOP3.LUT UR5, URZ, UR6, URZ, 0x33, !UPT ;", 0x09).is_none());
    // inne LUT / operand nie-UR / dest nie-UR
    assert!(merc_ulop3_not_record("ULOP3.LUT UR5, URZ, UR6, URZ, 0xc0, !UPT ;", 0xf8).is_none());
    assert!(merc_ulop3_not_record("ULOP3.LUT UR5, URZ, R6, URZ, 0x33, !UPT ;", 0xf8).is_none());
    assert!(merc_ulop3_not_record("ULOP3.LUT R5, URZ, UR6, URZ, 0x33, !UPT ;", 0xf8).is_none());
    // RZ zamiast URZ w slocie a/c
    assert!(merc_ulop3_not_record("ULOP3.LUT UR5, RZ, UR6, URZ, 0x33, !UPT ;", 0xf8).is_none());
    assert!(merc_ulop3_not_record("ULOP3.LUT UR5, URZ, UR6, RZ, 0x33, !UPT ;", 0xf8).is_none());
    // URZ dest/zrodlo odrzucane jak reg-nie-numeryczny
    assert!(merc_ulop3_not_record("ULOP3.LUT URZ, URZ, UR6, URZ, 0x33, !UPT ;", 0xf8).is_none());
    assert!(merc_ulop3_not_record("ULOP3.LUT UR5, URZ, URZ, URZ, 0x33, !UPT ;", 0xf8).is_none());
    // LOP3 spoza rodziny (obsluguje mk47), predykat !PT bez U
    assert!(merc_ulop3_not_record("ULOP3.LUT UR5, URZ, UR6, URZ, 0x33, !PT ;", 0xf8).is_none());
    assert!(merc_lop3_not_less("LOP3.LUT R6, RZ, R5, RZ, 0x33, !PT ;"));
}

fn merc_lop3_not_less(t: &str) -> bool {
    // ULOP3-skener musi odrzucac zwykle LOP3 (bazowy rozdzial w callerze).
    merc_ulop3_not_record(t, 0xf8).is_none()
}
