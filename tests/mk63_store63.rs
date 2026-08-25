//! mk63 (2026-08-13): closing the 0238** records —
//! the (b7,b8) store semantics (EF/STRONG.SYS/GPU/SM), the width flag without
//! OR for dreg=RZ, terminal-STRONG skip before EXIT + MEMBAR.ALL, STL with a
//! pure-uniform address recordless. Evidence: merclab/mk63 c13..c25.

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

fn meta_base() -> KernelMeta {
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

fn stg_recs(cm: &CapMerc) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for r in &cm.records {
        if r.tag[1] == 0x38 && r.tag[2] == 0x0e {
            let mut v = r.tag.to_vec();
            v.extend_from_slice(&r.payload);
            out.push(v);
        }
    }
    out
}

#[test]
fn mk63_stg_sem_b7b8() {
    // 3 STG: plain(sem0) / STRONG.SYS(sem2) / STRONG.GPU(sem3) ->
    // (b7,b8) = (0x11,0) / (0x21,2) / (0xa1,1).
    let mut m = meta_base();
    m.merc_stg_pos = vec![3, 4, 5];
    m.merc_stg_areg = vec![2, 2, 2];
    m.merc_stg_dreg = vec![4, 4, 4];
    m.merc_stg_dur = vec![4, 4, 4];
    m.merc_stg_guard = vec![0xf8, 0xf8, 0xf8];
    m.merc_stg_wsel = vec![2, 2, 2];
    m.merc_stg_sem = vec![0, 2, 3];
    let o = ops(8);
    let out = generate_mercury_full(&dummy_code(8), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    let rs = stg_recs(&cm);
    assert_eq!(rs.len(), 3);
    assert_eq!((rs[0][7], rs[0][8]), (0x11, 0x00));
    assert_eq!((rs[1][7], rs[1][8]), (0x21, 0x02));
    assert_eq!((rs[2][7], rs[2][8]), (0xa1, 0x01));
}

#[test]
fn mk63_stg_rz_widthflag() {
    // STG.E.128 z danymi RZ: (b19,b20)=0xffc0 BEZ flagi szerokosci (|6 bylo
    // bledem mk35, korpus c13: 5899/5899 flag=0).
    let mut m = meta_base();
    m.merc_stg_pos = vec![3];
    m.merc_stg_areg = vec![2];
    m.merc_stg_dreg = vec![255];
    m.merc_stg_dur = vec![4];
    m.merc_stg_guard = vec![0xf8];
    m.merc_stg_wsel = vec![4];
    m.merc_stg_sem = vec![0];
    let o = ops(8);
    let out = generate_mercury_full(&dummy_code(8), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    let rs = stg_recs(&cm);
    assert_eq!(rs.len(), 1);
    assert_eq!((rs[0][6], rs[0][19], rs[0][20]), (0x60, 0xc0, 0xff));
}

#[test]
fn mk63_stg_sem_skip() {
    // bit7 (terminal STRONG) and bit6 (ENL2 park) => no record.
    let mut m = meta_base();
    m.merc_stg_pos = vec![3, 4, 5];
    m.merc_stg_areg = vec![2, 2, 2];
    m.merc_stg_dreg = vec![4, 4, 4];
    m.merc_stg_dur = vec![4, 4, 4];
    m.merc_stg_guard = vec![0xf8, 0xf8, 0xf8];
    m.merc_stg_wsel = vec![2, 2, 2];
    m.merc_stg_sem = vec![0x80, 0xc0, 3];
    let o = ops(8);
    let out = generate_mercury_full(&dummy_code(8), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    let rs = stg_recs(&cm);
    assert_eq!(rs.len(), 1);
    assert_eq!((rs[0][7], rs[0][8]), (0xa1, 0x01));
}

#[test]
fn mk63_ste_sem_b7() {
    // ST.E STRONG.SYS -> b7=0x22; STRONG.GPU -> 0x1a; plain 0x01.
    let mut m = meta_base();
    m.merc_store2 = vec![
        (3, 1, 2, 2, 12, 4, 0, 0xf8, 0),
        (4, 1, 2, 2, 12, 4, 0, 0xf8, 2),
        (5, 1, 2, 2, 12, 4, 0, 0xf8, 3),
    ];
    let o = ops(8);
    let out = generate_mercury_full(&dummy_code(8), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    let mut b7s = Vec::new();
    for r in &cm.records {
        if r.tag[1] == 0x38 && r.tag[2] == 0x2a {
            b7s.push(r.payload[3]); // b7 = tag[4B] + payload[3]
        }
    }
    assert_eq!(b7s, vec![0x01, 0x22, 0x1a]);
}
