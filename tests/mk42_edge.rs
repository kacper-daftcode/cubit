//! mk42 (2026-08-12): 02 22 32 32 edge records for generic LD with desc[URm].
//! Byte pins from the sm_100 corpus (mk42/edge5..edge13; EXACT selection,
//! tail=off bracket, [19:21)=(maxDescUR<<6)|2).

use cubit::eiattr::{KernelMeta, KernelParam};
use cubit::elf_builder::generate_mercury_full;
use cubit::mercury::CapMerc;

fn dummy_code(n: usize) -> Vec<u8> {
    vec![0u8; n * 16]
}

fn ops(n: usize) -> Vec<String> {
    let mut v = vec!["NOP".to_string(); n];
    v[n - 1] = "EXIT".to_string();
    v
}

fn meta_with_load() -> KernelMeta {
    KernelMeta {
        name: "t".into(),
        regcount: 16,
        exit_offsets: vec![0u32],
        cbank_param_size: 8,
        params: vec![KernelParam { index: 0, ordinal: 0, offset: 0, size: 8 }],
        merc_param_loads: vec![(1, 0, 0, 8, 0xf8)],
        merc_param_load_dreg: vec![4],
        ..Default::default()
    }
}

fn edge_recs(cm: &CapMerc) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for r in &cm.records {
        if r.tag == [0x02, 0x22, 0x32, 0x32] {
            let mut v = r.tag.to_vec();
            v.extend_from_slice(&r.payload);
            out.push(v);
        }
    }
    out
}

#[test]
fn mk42_edge_ld64_layout() {
    // LD.E.64 R12, desc[UR6][R26.64+0x8] in lane 5; unguarded; maxDescUR=6.
    let mut m = meta_with_load();
    m.merc_edge_ld = vec![(5, 0xf8, 0x15, 0x08, 0x00, 12, 26, 3, 8)];
    m.merc_edge_maxur = 6;
    let o = ops(8);
    let out = generate_mercury_full(&dummy_code(8), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    let recs = edge_recs(&cm);
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    assert_eq!(&r[..4], &[0x02, 0x22, 0x32, 0x32]);
    assert_eq!(r[4], 0xf8);
    assert_eq!(&r[5..12], &[0x00, 0x15, 0x08, 0x00, 0x00, 0x00, 0x00]);
    // [12:14) = (12<<6)|3 = 0x303
    assert_eq!(&r[12..14], &[0x03, 0x03]);
    // [14:16) = (26<<6)|2 = 0x682
    assert_eq!(&r[14..16], &[0x82, 0x06]);
    // [16:18) = 00 0a
    assert_eq!(&r[16..18], &[0x00, 0x0a]);
    // [19:21) = (6<<6)|2 = 0x182
    assert_eq!(&r[19..21], &[0x82, 0x01]);
    assert_eq!(r[22], 0xf8);
    assert_eq!(&r[28..32], &8u32.to_le_bytes());
}

#[test]
fn mk42_edge_pred_i_kolejnosc() {
    // Dwa LD.E.128 STRONG.SYS (lane 9 i 3) + LD.E z @!P2 (lane 7);
    // maxDescUR=14 -> porzadek strumienia wg lane'ow rosnaco.
    let mut m = meta_with_load();
    m.merc_edge_ld = vec![
        (9, 0xf8, 0x16, 0x10, 0x01, 16, 22, 7, 0x10),
        (3, 0xf8, 0x16, 0x10, 0x01, 12, 22, 7, 0),
        (7, (2 << 3) | 1, 0x14, 0x08, 0x00, 12, 22, 1, 0),
    ];
    m.merc_edge_maxur = 14;
    let o = ops(12);
    let out = generate_mercury_full(&dummy_code(12), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    let recs = edge_recs(&cm);
    assert_eq!(recs.len(), 3);
    // lane 3 pierwszy: X=12,Y=22,C=7,b7b8=10 01
    assert_eq!(recs[0][6], 0x16);
    assert_eq!(&recs[0][7..9], &[0x10, 0x01]);
    assert_eq!(&recs[0][12..16], &[0x07, 0x03, 0x82, 0x05]);
    assert_eq!(&recs[0][28..32], &0u32.to_le_bytes());
    // lane 7: pred @!P2 -> (2<<3)|1 = 0x11, b6=0x14 (32-bit), C=1
    assert_eq!(recs[1][4], 0x11);
    assert_eq!(recs[1][6], 0x14);
    // lane 9: off 0x10
    assert_eq!(&recs[2][28..32], &0x10u32.to_le_bytes());
    // maxDescUR=14 -> (14<<6)|2 = 0x382
    assert_eq!(&recs[0][19..21], &[0x82, 0x03]);
}

#[test]
fn mk42_edge_brak_bez_rekordow() {
    // Without merc_edge_ld -> zero records of that tag (the corpus gated rule = no LD desc).
    let m = meta_with_load();
    let o = ops(6);
    let out = generate_mercury_full(&dummy_code(6), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    assert!(edge_recs(&cm).is_empty());
}
