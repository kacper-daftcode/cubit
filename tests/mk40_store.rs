//! mk40 (2026-08-12): store-matrix 0238 + mini-slownik korpusowy.
//! Piny bajtowe: korpus sm_100 (mk40/stgfields fits; mk40lab probes).

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
        merc_param_loads: vec![(1, 0, 0, 8, 0xf8)], // mk41: 5. pole = pelny kod (0xf8 = brak guarda)
        merc_param_load_dreg: vec![4],
        ..Default::default()
    }
}

fn recs(cm: &CapMerc) -> Vec<[u8; 4]> {
    cm.records.iter().map(|r| r.tag).collect()
}

fn find_store(cm: &CapMerc) -> Vec<u8> {
    for r in &cm.records {
        if r.tag[1] == 0x38 && (r.tag[2] == 0x2a || r.tag[2] == 0x20) {
            let mut v = r.tag.to_vec();
            v.extend_from_slice(&r.payload);
            return v;
        }
    }
    panic!("no store2 record");
}

#[test]
fn mk40_ste64_layout() {
    // ST.E.64 desc[UR12][R2.64], R4 w lane 3:
    // 02382a32 f8 00 15 01(mk41: ->0x1a dla desc-formy) 00000000 | [12:14]=8200 (R2|2) 0a00
    // [17:19]=0203 (UR12|2) [19:21]=0201 (R4|flag2) [28:32]=0.
    let mut m = meta_with_load();
    m.merc_store2 = vec![(3, 1, 3, 2, 12, 4, 0, 0xf8)];
    let o = ops(8);
    let out = generate_mercury_full(&dummy_code(8), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    let r = find_store(&cm);
    assert_eq!(
        &r[..24],
        &[
            0x02, 0x38, 0x2a, 0x32, 0xf8, 0x00, 0x15, 0x01, 0x00, 0x00, 0x00, 0x00, 0x82, 0x00,
            0x0a, 0x00, 0x00, 0x02, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00,
        ]
    );
}

#[test]
fn mk40_stl128_layout() {
    // STL.128 [R1+0x10], RZ -> 02382006 f8 00 61 01 | 00 00 [10:12]=0040
    // 0a00 [14:16]=c0ff ... [28:32]=1000
    let mut m = meta_with_load();
    m.merc_store2 = vec![(3, 2, 4, 1, 0xffff, 0x3ff, 0x10, 0xf8)];
    let o = ops(8);
    let out = generate_mercury_full(&dummy_code(8), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    let r = find_store(&cm);
    assert_eq!(
        &r[..16],
        &[
            0x02, 0x38, 0x20, 0x06, 0xf8, 0x00, 0x61, 0x01, 0x00, 0x00, 0x40, 0x00, 0x0a, 0x00,
            0xc0, 0xff,
        ]
    );
    assert_eq!(&r[28..32], &[0x10, 0x00, 0x00, 0x00]);
}

#[test]
fn mk40_mini_ffma2_emitted_bit0() {
    // FFMA2 w lane 2 -> mini 420d1426, lane NIE dostaje bitu bitmapy.
    let mut m = meta_with_load();
    m.merc_mini2 = vec![(2, 0x26140d42)];
    let mut o = ops(8);
    o[2] = "FFMA2".to_string();
    let out = generate_mercury_full(&dummy_code(8), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    assert!(recs(&cm).contains(&[0x42, 0x0d, 0x14, 0x26]));
    // bitmapa: automat pelny record-cover; indeks 2*slot — tu prosto: bit kasowany
}

#[test]
fn mk40_break_preexit_minis() {
    let mut m = meta_with_load();
    m.merc_mini2 = vec![(2, 0x0a0005_41), (4, 0x0a026241)];
    let o = ops(8);
    let out = generate_mercury_full(&dummy_code(8), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    let t = recs(&cm);
    assert!(t.contains(&[0x41, 0x05, 0x00, 0x0a]));
    assert!(t.contains(&[0x41, 0x62, 0x02, 0x0a]));
}

#[test]
fn mk40_stg_u16_width() {
    // STG.E.U16 -> b6=0x20 (korpus; dawniej 0x40 z defaultu)
    let mut m = meta_with_load();
    m.merc_stg_pos = vec![3];
    m.merc_stg_ser = vec![0];
    m.merc_stg_dreg = vec![6];
    m.merc_stg_dur = vec![4];
    m.merc_stg_guard = vec![0];
    m.merc_stg_areg = vec![2];
    m.merc_stg_wsel = vec![1];
    let o = ops(8);
    let out = generate_mercury_full(&dummy_code(8), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    let stg = cm
        .records
        .iter()
        .find(|r| r.tag == [0x02, 0x38, 0x0e, 0x32])
        .expect("no 02380e32");
    let mut v = stg.tag.to_vec();
    v.extend_from_slice(&stg.payload);
    assert_eq!(v[6], 0x20);
}
