//! Tests for the Mercury (capmerc) parser — SM100+/SM103a wire format.
use cubit::mercury::{tail_for_instr_count, CapMerc};

fn hx(parts: &[&str]) -> Vec<u8> {
    let s: String = parts.concat();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn parse_k_empty() {
    // k_empty (3 non-NOP: LDC; EXIT; BRA): ordinal 12, B=3, bitmap bit1=EXIT,
    // one 16B record, tail 0x0750.
    let blob = hx(&[
        "0c000000010000c003000000",
        "02000000",
        "010b040af80004000000410000040000",
        "5007",
    ]);
    let cm = CapMerc::parse(&blob, true).unwrap();
    assert_eq!(cm.ordinal, 12);
    assert_eq!(cm.magic, 0xC0000001);
    assert_eq!(cm.n_nonnop, 3);
    assert_eq!(cm.bitmap, vec![0x02, 0x00, 0x00, 0x00]);
    assert_eq!(cm.set_bits(), vec![1]);
    assert_eq!(cm.records.len(), 1);
    assert_eq!(cm.records[0].tag, [0x01, 0x0b, 0x04, 0x0a]);
    assert_eq!(cm.records[0].payload.len(), 12);
    assert_eq!(cm.tail, 0x0750);
    assert!(cm.tail_consistent());
    assert_eq!(cm.trailing_slop, 0);
}

#[test]
fn parse_k_sync_two_records_bar() {
    // k_sync (LDC, BAR.SYNC, EXIT, BRA): B=4, bitmap bit2 (EXIT),
    // records: prolog + BAR record `01 47 5a 16`; tail 0x06d0 (B even).
    let blob = hx(&[
        "0c000000010000c004000000",
        "04000000",
        "010b040af80004000000410000040000",
        "01475a16f80004000000000001000000",
        "d006",
    ]);
    let cm = CapMerc::parse(&blob, true).unwrap();
    assert_eq!(cm.n_nonnop, 4);
    assert_eq!(cm.set_bits(), vec![2]);
    assert_eq!(cm.records.len(), 2);
    assert_eq!(cm.records[1].tag, [0x01, 0x47, 0x5a, 0x16]);
    assert_eq!(cm.tail, 0x06d0);
    assert!(cm.tail_consistent());
}

#[test]
fn tail_table_empirical() {
    let cases = [
        (3u32, 0x0750u16),
        (4, 0x06d0),
        (8, 0x04d0),
        (9, 0x0850),
        (10, 0x07d0),
        (12, 0x06d0),
        (13, 0x0650),
        (14, 0x05d0),
        (128, 0x04d0),
        (168, 0x04d0),
        (26, 0x07d0),
        (44, 0x06d0),
        (31, 0x0550),
        (95, 0x0550),
        (127, 0x0550),
        (175, 0x0550),
    ];
    for (b, t) in cases {
        assert_eq!(tail_for_instr_count(b), t, "B={b}");
    }
}

#[test]
fn strict_rejects_unknown_tag_class() {
    // klasa 0xd1 01 01 .. (poza znana mapa d10102xx) = nieznana
    let blob = hx(&[
        "0c000000010000c003000000",
        "02000000",
        "d101011b00000117",
        "5007",
    ]);
    assert!(CapMerc::parse(&blob, true).is_err());
    let cm = CapMerc::parse(&blob, false).unwrap();
    // lenient: resync chwyta pozniejsze klasy; pierwszy rekord = nasz 0xd1
    assert!(!cm.records.is_empty());
    assert_eq!(cm.records[0].tag[0], 0xd1);
}

#[test]
fn scalar_mini_records_41_4b() {
    // dwa rekordy 4B (41 00 00 0a) + rekord 16B, tail
    let blob = hx(&[
        "0c000000010000c003000000",
        "02000000",
        "4100000a",
        "4100000a",
        "010b040af80004000000410000040000",
        "5007",
    ]);
    let cm = CapMerc::parse(&blob, true).unwrap();
    assert_eq!(cm.records.len(), 3);
    assert_eq!(cm.records[2].tag, [0x01, 0x0b, 0x04, 0x0a]);
}

#[test]
fn bad_magic_rejected() {
    let blob = hx(&[
        "0c0000000000000003000000",
        "02000000",
        "010b040af80004000000410000040000",
        "5007",
    ]);
    match CapMerc::parse(&blob, true) {
        Err(cubit::mercury::MercError::BadMagic(0)) => {}
        _ => panic!("expected BadMagic"),
    }
}


#[test]
fn parse_v3_cpasync_atoms_and_51x34() {
    // Real nvcc-13.3 sm_103a section (b_cpasync from the micro-lab):
    // exercises 34B `51 02 02 23` records + `01 23 40 0a` + BAR records.
    let blob = hx(&[
        "0d000000010000c018000000c0ff5200010b040af80004000000410000040000",
        "010b040af80004000000c10201020000010b060afa000400000041012c020000",
        "02220806fa005200000003024000020000000000000000000000000008000000",
        "010b0e0afa000500000083013904000002220e06f80052000000830040000200",
        "00000000000000000000000000000000510202233034f800201010010000c001",
        "0a010002010900820100f8000000000000000123400af8000800000000000000",
        "000001475a16f8000400000000000100000002380e32f8004011000000008200",
        "0a00008201400200000000000000000000005007",
    ]);
    let cm = CapMerc::parse(&blob, true).unwrap();
    assert_eq!(cm.n_nonnop, 24);
    assert_eq!(cm.trailing_slop, 0);
    assert_eq!(cm.records.len(), 10);
    // 34-byte pinned record `51 02 02 23` at 0x90.
    let pinned = cm
        .records
        .iter()
        .find(|r| r.tag == [0x51, 0x02, 0x02, 0x23])
        .expect("pinned record");
    assert_eq!(pinned.len, 34);
    assert_eq!(pinned.payload.len(), 30);
    assert!(pinned.payload.ends_with(&[0xf8, 0x00, 0, 0, 0, 0, 0, 0]));
    assert!(cm.records.iter().all(|r| !r.is_atom()));
}

#[test]
fn parse_v3_d0_atoms_before_record_and_trailing() {
    // Mirror of libcusolver larf_minus_tau (sm_103): 4x `d0 00` atoms between
    // the param group and the STG record; tail directly after the record.
    let blob = hx(&[
        "01000000010000c00e000000",
        "18140000",
        "010b040af80004000000410000040000",
        "d000d000d000d000",
        "02380e32f80060110000000002010a0000020106020000000000000000000000",
        "d005",
    ]);
    let cm = CapMerc::parse(&blob, true).unwrap();
    assert_eq!(cm.n_nonnop, 14);
    assert_eq!(cm.trailing_slop, 0);
    assert_eq!(cm.records.iter().filter(|r| r.is_atom()).count(), 4);
    assert!(cm.tail_consistent());
}

#[test]
fn parse_v3_trailing_d0_atom_before_tail() {
    // cusolver divide_on_device shape: one `d0 00` atom directly before tail
    // (only 2 bytes left -> dedicated edge path).
    let blob = hx(&[
        "01000000010000c002000000",
        "02000000",
        "010b040af80004000000410000040000",
        "d000",
        "d007",
    ]);
    let cm = CapMerc::parse(&blob, true).unwrap();
    assert_eq!(cm.trailing_slop, 0);
    assert_eq!(cm.records.len(), 2);
    let last = cm.records.last().unwrap();
    assert!(last.is_atom());
    assert_eq!(last.tag, [0xd0, 0x00, 0, 0]);
    assert!(cm.tail_consistent());
}


// ===== mk11 (2026-08-05): buildery rekordow 025a MMA + 020f/020c f64-imm =====
// Wartosci-oczekiwane = doslowne bajty z lab/korpusu (mma_model.py: 15,104
// rekordow corpus-cover byte-exact; f64imm_harvest: 221/221).

use cubit::mercury::{build_f64imm_rec, build_mma_rec, merc_mma_class};

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn mma_rec_kmma_pair() {
    // k_mma: HMMA.16816.F32 R16,R4.reuse,R12,RZ / R12,R4,R14,RZ
    let hmma = merc_mma_class("HMMA.16816.F32").unwrap();
    let r1 = build_mma_rec(hmma, 16, 4, 12, 255, 0);
    assert_eq!(
        hexs(&r1),
        "025a0026f80081800200000007040601000203c0ff00f8000000000000000000"
    );
    let r2 = build_mma_rec(hmma, 12, 4, 14, 255, 0);
    assert_eq!(
        hexs(&r2),
        "025a0026f80081800200000007030601008203c0ff00f8000000000000000000"
    );
}

#[test]
fn mma_rec_pmma_and_dmma() {
    // p_mma16816: HMMA.16816.F32 R8,R4,R4,R8
    let hmma = merc_mma_class("HMMA.16816.F32").unwrap();
    assert_eq!(
        hexs(&build_mma_rec(hmma, 8, 4, 4, 8, 0)),
        "025a0026f80081800200000007020601000201060200f8000000000000000000"
    );
    // p_dmma: DMMA.8x8x4 R4,R4,R6,RZ
    let dmma = merc_mma_class("DMMA.8x8x4").unwrap();
    assert_eq!(
        hexs(&build_mma_rec(dmma, 4, 4, 6, 255, 0)),
        "025a0426f80000000800000007010201008201c0ff00f8000000000000000000"
    );
}

#[test]
fn mma_rec_corpus_spot_bmma() {
    // b_mma_f16: HMMA.16816.F32 R16,R8.reuse,R12.reuse,RZ
    let hmma = merc_mma_class("HMMA.16816.F32").unwrap();
    assert_eq!(
        hexs(&build_mma_rec(hmma, 16, 8, 12, 255, 0)),
        "025a0026f80081800200000007040602000203c0ff00f8000000000000000000"
    );
    // b_mma_f64 #2: DMMA.8x8x4 R8,R2,R4,R8
    let dmma = merc_mma_class("DMMA.8x8x4").unwrap();
    assert_eq!(
        hexs(&build_mma_rec(dmma, 8, 2, 4, 8, 0)),
        "025a0426f80000000800000007028200000201060200f8000000000000000000"
    );
}

#[test]
fn mma_mini_sat() {
    assert_eq!(merc_mma_class("IMMA.16832.S8.S8.SAT"), Some(7));
    assert!(cubit::mercury::merc_mma_is_mini(7));
    assert_eq!(cubit::mercury::MERC_MMA_MINI_SAT, [0x42, 0x5a, 0x08, 0x26]);
    assert!(merc_mma_class("UTCHMMA.2CTA").is_none());
}

#[test]
fn f64imm_rec_pdmma() {
    // DMUL R4, R4, 0.5 -> top32(0.5) = 0x3fe00000; DADD R6, R4, 1.0 -> 0x3ff00000
    let r1 = build_f64imm_rec(0, 4, 4, 0x3fe00000, 0xf8, 0);
    assert_eq!(
        hexs(&r1),
        "020f120ef800080000000301020113000000000000000000000000000000e03f"
    );
    let r2 = build_f64imm_rec(1, 6, 4, 0x3ff00000, 0xf8, 0);
    assert_eq!(
        hexs(&r2),
        "020c1e0ef800080000008301020113000000000000000000000000000000f03f"
    );
}


#[test]
fn s2r_dest_reg_f4_payload() {
    // mk17a: payload f4 rekordu anchor = (numer R dest S2R). Empiria:
    // mk20 oraculum gdb 90/90 + bajty gold (c_ld_dyn2: R7->c1 01, R9->41 02).
    use cubit::mercury::merc_s2r_dest_reg as f;
    assert_eq!(f("S2R R7, SR_TID.X"), Some(7));
    assert_eq!(f("S2R R9, SR_CTAID.X"), Some(9));
    assert_eq!(f("S2R R0, SR_TID.X"), Some(0));
    assert_eq!(f("@P0 S2R R5, SR_LANEID"), Some(5));
    assert_eq!(f("S2R RZ, SR_TID.X"), Some(0x3f));
    assert_eq!(f("MOV R1, R2"), None);
}
