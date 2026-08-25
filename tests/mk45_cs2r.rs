//! mk45: rekordy 010b0c0a (CS2R Rd, SRZ) — siatka payloadu domknieta
//! korpusowo (EXACT 184252/184361 par; bramka SR==SRZ).
use cubit::mercury::merc_cs2r_srz_record;

fn expected(dst: u32, guard: u8) -> [u8; 16] {
    let mut r = [0u8; 16];
    r[0] = 0x01; r[1] = 0x0b; r[2] = 0x0c; r[3] = 0x0a;
    r[4] = guard; r[6] = 0x05;
    r[10] = 0x03 | (((dst as u8) & 3) << 6);
    r[11] = (dst >> 2) as u8;
    r[12] = 0xff; r[13] = 0x0f;
    r
}

#[test]
fn debug_path() {
    eprintln!("plain: {:?}", merc_cs2r_srz_record("CS2R R22, SRZ ;", 0xf8));
    eprintln!("dot32: {:?}", merc_cs2r_srz_record("CS2R.32 R5, SRZ ;", 0xf8));
}

#[test]
fn grid_payload() {
    // korpus trsm_batch: R22 -> (0x83, 0x05), R16 -> (0x03, 0x04)
    assert_eq!(merc_cs2r_srz_record("CS2R R22, SRZ ;", 0xf8), Some(expected(22, 0xf8)));
    assert_eq!(merc_cs2r_srz_record("CS2R R16, SRZ ;", 0xf8), Some(expected(16, 0xf8)));
    assert_eq!(merc_cs2r_srz_record("CS2R R2, SRZ ;", 0xf8), Some(expected(2, 0xf8)));
    // guard with the full code
    assert_eq!(merc_cs2r_srz_record("@!P4 CS2R R6, SRZ ;", 0x21), Some(expected(6, 0x21)));
    // wariant .32
    assert_eq!(merc_cs2r_srz_record("CS2R.32 R5, SRZ ;", 0xf8), Some(expected(5, 0xf8)));
}

#[test]
fn rz_special() {
    assert_eq!(
        merc_cs2r_srz_record("CS2R RZ, SRZ ;", 0xf8),
        Some([0x01, 0x0b, 0x0c, 0x0a, 0xf8, 0, 0x05, 0, 0, 0, 0xc1, 0xff, 0xff, 0x0f, 0, 0])
    );
}

#[test]
fn gates() {
    // other SR -> no record (8 CgaSize-only kernels; GTLO parked)
    assert_eq!(merc_cs2r_srz_record("CS2R.32 R3, SR_CgaSize ;", 0xf8), None);
    assert_eq!(merc_cs2r_srz_record("CS2R R5, SR_GLOBALTIMERLO ;", 0xf8), None);
    assert_eq!(merc_cs2r_srz_record("S2R R0, SR_TID.X ;", 0xf8), None);
    assert_eq!(merc_cs2r_srz_record("CS2R UR4, SRZ ;", 0xf8), None);
}
