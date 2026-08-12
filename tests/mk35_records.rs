//! mk35 (2026-08-11): regresje z zamkniecia wide-sweep (198 -> 214/214):
//! siatka rol desc = (dst-load-reg<<6)|C (C = drabinka szerokosci),
//! zachowanie REDUX/CREDUX, ISETP-UR mini, guardy BAR per-lane,
//! brak fabrykacji rekordow gdy kernel nie laduje parametrow,
//! rekord REDG-desc-form (024d2432), STG.128 b6=0x60+flaga dreg.

use cubit::eiattr::{KernelMeta, KernelParam};
use cubit::elf_builder::generate_mercury_full;
use cubit::mercury::{build_atom_rec, CapMerc, MERC_ATOM_CLS_REDG_D};

fn dummy_code(n: usize) -> Vec<u8> {
    vec![0u8; n * 16]
}

// meta z jednym parametrem wskaznikowym 8B i podanymi loadami.
fn meta_with_loads(loads: Vec<(u32, u32, u8, u8, u8)>, dregs: Vec<u8>) -> KernelMeta {
    KernelMeta {
        name: "t".into(),
        regcount: 16,
        num_barriers: 0,
        exit_offsets: vec![(0u32)],
        cbank_param_size: 8,
        params: vec![KernelParam { index: 0, ordinal: 0, offset: 0, size: 8 }],
        merc_param_loads: loads,
        merc_param_load_dreg: dregs,
        ..Default::default()
    }
}

fn ops(n: usize) -> Vec<String> {
    let mut v = vec!["NOP".to_string(); n];
    v[n - 1] = "EXIT".to_string(); // bitmapa musi miec >=1 bit (nvcc tak ma)
    v
}

// [10],[11] pierwszego rekordu desc 0222 w strumieniu
fn desc_role(cm: &CapMerc) -> (u8, u8) {
    for r in &cm.records {
        if r.tag[1] == 0x22 && (r.tag[2] == 0x0e || r.tag[2] == 0x08) {
            return (r.payload[6], r.payload[7]); // payload = bez tagu(4B): b10=+[6]
        }
    }
    panic!("no desc record");
}

#[test]
fn mk35_role_grid_reg8() {
    // REG-path 8B load z dst R4 -> (b10,b11) = (4<<6)|3 = (03,01)
    let m = meta_with_loads(vec![(1, 0, 0, 8, 0xf8)], vec![4]);
    let o = ops(8);
    let out = generate_mercury_full(&dummy_code(8), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    assert_eq!(desc_role(&cm), (0x03, 0x01));
}

#[test]
fn mk35_role_grid_unif16() {
    // UNIF 16B load z dst UR8 -> (07,02)
    let m = meta_with_loads(vec![(1, 0, 1, 16, 0xf8)], vec![8]);
    let o = ops(8);
    let out = generate_mercury_full(&dummy_code(8), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    assert_eq!(desc_role(&cm), (0x07, 0x02));
}

#[test]
fn mk35_redux_bare_vs_typed() {
    // goly REDUX: bit w bitmapie, brak rekordu 0132.
    let mut o = ops(4);
    o[1] = "LDC".into();
    o[2] = "REDUX".into();
    let m = meta_with_loads(vec![(1, 0, 0, 8, 0xf8)], vec![2]);
    let out = generate_mercury_full(&dummy_code(4), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    assert!(cm.set_bits().contains(&2), "goly REDUX trzyma bit");
    assert!(
        !cm.records.iter().any(|r| r.tag[..4] == [0x01, 0x32, 0x10, 0x0a]),
        "goly REDUX bez rekordu 0132"
    );
}

#[test]
fn mk35_credux_record_payload() {
    let mut o = ops(4);
    o[1] = "LDC".into();
    o[2] = "CREDUX.MIN.S32".into();
    let mut m = meta_with_loads(vec![(1, 0, 0, 8, 0xf8)], vec![2]);
    m.merc_redux = vec![(2, 1, 5)];
    let out = generate_mercury_full(&dummy_code(4), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    assert!(!cm.set_bits().contains(&2), "CREDUX bez bitu");
    let r = cm
        .records
        .iter()
        .find(|r| r.tag[..4] == [0x01, 0x32, 0x10, 0x0a])
        .expect("rekord 0132 obecny");
    // at_min: 0132 100a f8 00 51 00 00 00 41 01 00 01 ...
    assert_eq!(r.payload[2], 0x51); // b6 = 51 dla CREDUX
    assert_eq!(r.payload[6], 0x41); // dst UR5 grid (5<<6)|1
    assert_eq!(r.payload[7], 0x01);
    assert_eq!(r.payload[9], 0x01); // b13 = 01 dla CREDUX
}

#[test]
fn mk35_bar_guard_ladder() {
    let mut o = ops(8);
    o[1] = "LDC".into();
    o[3] = "BAR.SYNC".into(); // @P
    o[4] = "BAR.SYNC".into(); // bez guarda
    let mut m = meta_with_loads(vec![(1, 0, 0, 8, 0xf8)], vec![2]);
    m.num_barriers = 2;
    m.merc_bar_pos = vec![3, 4];
    m.merc_bar_guard = vec![0x00u8, 0xf8]; // mk41: pelne kody
    let out = generate_mercury_full(&dummy_code(8), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    let bars: Vec<&cubit::mercury::Record> = cm
        .records
        .iter()
        .filter(|r| r.tag[..4] == [0x01, 0x47, 0x5a, 0x16])
        .collect();
    assert_eq!(bars.len(), 2);
    assert_eq!(bars[0].payload[0], 0x00, "@P BAR -> b4=00 (bar_if2 lane7)");
    assert_eq!(bars[1].payload[0], 0xf8, "plain BAR -> b4=f8 (bar_if2 lane8)");
}

#[test]
fn mk35_isetp_ur_mini_no_bit() {
    let mut o = ops(6);
    o[1] = "LDC".into();
    o[2] = "ISETP.NE.U32.AND".into();
    let mut m = meta_with_loads(vec![(1, 0, 0, 8, 0xf8)], vec![2]);
    m.merc_isetp_ur = vec![2];
    let out = generate_mercury_full(&dummy_code(6), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    assert!(
        cm.records.iter().any(|r| r.tag[..4] == [0x42, 0x10, 0x32, 0x14]),
        "mini 42103214 obecne"
    );
    assert!(!cm.set_bits().contains(&2), "lane ISETP-UR bez bitu");
}

#[test]
fn mk35_no_loads_no_records_sm103() {
    // div3/v_scalar/v_gconst: parametry zadeklarowane, ale nic ich nie
    // laduje -> nvcc nie emituje nic poza prologiem (era-103).
    let o = vec!["LDC".to_string(), "EXIT".to_string(), "BRA".to_string()];
    let m = KernelMeta {
        name: "t".into(),
        regcount: 8,
        exit_offsets: vec![16],
        cbank_param_size: 24,
        params: vec![
            KernelParam { index: 0, ordinal: 0, offset: 0, size: 4 },
            KernelParam { index: 1, ordinal: 1, offset: 4, size: 4 },
        ],
        ..Default::default()
    };
    let out = generate_mercury_full(&dummy_code(3), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    assert!(
        cm.records.iter().all(|r| r.tag[..4] == [0x01, 0x0b, 0x04, 0x0a]),
        "bez rekordow desc/cbank gdy brak loadow paramow"
    );
}

#[test]
fn mk35_redg_desc_record_bytes() {
    // at_and: @P0 REDG.E.AND.STRONG.GPU.AND? — kanonicznie nvdisasm:
    // "REDG.E.AND.STRONG.GPU desc[UR6][R2.64], R5" (guard @P0 -> b4=00)
    // bajty nvcc (mk35/at_and g5b-sekcja):
    let gold: [u8; 32] = [
        0x02, 0x4d, 0x24, 0x32, 0x00, 0x00, 0x50, 0xa0, 0x01, 0x00, 0x00, 0x00, 0x82, 0x00, 0x0a,
        0x00, 0x00, 0x82, 0x01, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    // build_atom_rec(cls, guard_b4, subop6, dst, addr, v1, v2) — v2: dur|0x80*S32
    let r = build_atom_rec(MERC_ATOM_CLS_REDG_D, 0x00, 0x50, 255, 2, 5, 6);
    assert_eq!(r, gold);
}
