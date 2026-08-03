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
