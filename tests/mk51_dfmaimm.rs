//! mk51 (2026-08-13): rekordy 020d1c0e (DFMA Rd, ±Ra, ±Rb, imm — imm LAST),
//! 020d1a0e (DFMA Rd, Ra, imm, Rb — imm MIDDLE) + domkniecie 020f120e
//! (DMUL imm) / 020c1e0e (DADD imm) o pred/b7/RZ-zrodla.
//! Emulator korpusowy merclab/mk51 c10: 18932/18932 kerneli byte-exact
//! (72,255 + 4,256 + 12,206 rekordow; obustronnie — lane-kandydaci poza
//! klasa nie dostaja rekordow). Wektory ponizej = bajty z korpusu sm_100
//! (c14_vecprint.py) z Lane'text->record parowaniem po polach.

use cubit::eiattr::{KernelMeta, KernelParam};
use cubit::elf_builder::generate_mercury_full;
use cubit::ir::{ControlCode, Guard, Instruction};
use cubit::mercury::CapMerc;
use cubit::sass_file::{merc_dfmaimm_scan, merc_f64imm_scan};

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

fn recs_tag(cm: &CapMerc, t1: u8, t2: u8) -> Vec<Vec<u8>> {
    cm.records
        .iter()
        .filter(|r| r.tag == [0x02, t1, t2, 0x0e])
        .map(|r| {
            let mut v = r.tag.to_vec();
            v.extend_from_slice(&r.payload);
            v
        })
        .collect()
}

fn hx(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn mk_ins(lane: u32, opf: &str, text: &str, guard: Option<Guard>) -> Instruction {
    Instruction {
        addr: lane * 16,
        opcode: opf.split('.').next().unwrap_or(opf).to_string(),
        opcode_full: opf.to_string(),
        key: String::new(),
        guard,
        operands: Vec::new(),
        modifiers: Vec::new(),
        ctrl: ControlCode::default(),
        hand_sched: false,
        rsd: None,
        raw_text: text.to_string(),
    }
}

#[test]
fn mk51_skan_klas_i_failclosed() {
    let ins = vec![
        mk_ins(1, "DFMA", "DFMA R30, -R26, R32, 1 ;", None),                 // last
        mk_ins(2, "DFMA", "DFMA R4, R18, -5920, R4 ;", None),               // mid
        mk_ins(3, "DFMA", "DFMA R6, R6, R6, R6 ;", None),                   // bez imm
        mk_ins(4, "DFMA", "DFMA R10, -R16, R8, UR4 ;", None),               // UR zamiast imm
        mk_ins(5, "DFMA", "DFMA R10, UR6, -R30, 1 ;", None),                // UR zrodlo — odrzut
        mk_ins(6, "DFMA", "DFMA R6, -R2, R4 ;", None),                      // 3 operandowa
        mk_ins(7, "DMUL", "DMUL R10, R12, 4.49423283715578976932e+307 ;", None),
        mk_ins(8, "DADD", "DADD R22, -RZ, |R12| ;", None),                  // DADD reg-reg
        mk_ins(9, "EXIT", "EXIT ;", None),
    ];
    let d = merc_dfmaimm_scan(&ins);
    assert_eq!(d.len(), 2);
    assert_eq!(d[0].0, 1);
    assert_eq!(d[0].1, 0); // last
    assert_eq!((d[0].3, d[0].4, d[0].5, d[0].6), (2, 30, 26, 32));
    assert_eq!(d[1].0, 2);
    assert_eq!(d[1].1, 1); // mid
    assert_eq!((d[1].3, d[1].4, d[1].5, d[1].6), (0, 4, 18, 4));
    assert_eq!(d[1].7, (-5920f64).to_bits());
    let m = merc_f64imm_scan(&ins);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].0, 7);
    assert_eq!(m[0].1, 0);
    assert_eq!((m[0].2, m[0].3), (10, 12));
    assert_eq!(m[0].4, 0x7fd00000);
}

#[test]
fn mk51_skan_flagi_pred_reuse_rz() {
    let ins = vec![
        // -|A| combo: b7 = 2(negA) + 4(absA) = 6  (nrm2_kernel sm_100.81)
        mk_ins(3, "DFMA", "DFMA R18, -|R12|, R8, 1 ;", None),
        // oba neg: b7 = 2+8 = 10 (gen_quasi_scrambled)
        mk_ins(5, "DFMA", "DFMA R10, -R10, -R30, 1 ;", None),
        // pred @P2 + INF (gen_sequenced)
        mk_ins(
            7,
            "DFMA",
            "@P2 DFMA R24, R26, R24, +INF ;",
            Some(Guard { pred: 2, negated: false, uniform: false }),
        ),
        // zrodlo RZ: siatka 0xffc0 bez flagi |2 (getri_2x2)
        mk_ins(9, "DFMA", "DFMA R14, -RZ, R14, 1 ;", None),
        // .reuse na zrodle (generate_seed_pseudo)
        mk_ins(11, "DMUL", "DMUL R16, R4.reuse, 12345 ;", None),
        mk_ins(12, "EXIT", "EXIT ;", None),
    ];
    let d = merc_dfmaimm_scan(&ins);
    assert_eq!(d.len(), 4);
    assert_eq!(d[0].3, 6);
    assert_eq!(d[1].3, 10);
    assert_eq!((d[2].2, d[2].3), (0x10, 0)); // pred (2<<3), bez neg
    assert_eq!(d[2].7, f64::INFINITY.to_bits());
    assert_eq!(d[3].5, 0x3ff); // RZ zrodlo
    let m = merc_f64imm_scan(&ins);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].0, 11);
    assert_eq!(m[0].4, (12345f64.to_bits() >> 32) as u32);
}

#[test]
fn mk51_bajty_z_korpusu() {
    // Wektory gold z korpusu sm_100 (c14): odtworzenie bajt po bajcie.
    let mut m = meta_with_load();
    m.merc_dfmaimm = vec![
        // matinv (1011): DFMA R30, -R26, R32, 1
        (12, 0, 0xf8, 2, 30, 26, 32, 1.0f64.to_bits()),
        // nrm2 (81): DFMA R18, -|R12|, R8, 1
        (20, 0, 0xf8, 6, 18, 12, 8, 1.0f64.to_bits()),
        // gen_quasi (15): DFMA R10, -R10, -R30, 1
        (24, 0, 0xf8, 10, 10, 10, 30, 1.0f64.to_bits()),
        // gen_sequenced (15): @P2 DFMA R24, R26, R24, +INF
        (30, 0, 0x10, 0, 24, 26, 24, f64::INFINITY.to_bits()),
        // FillRandNormal (1924): DFMA R4, R18, -5920, R4  (imm-MIDDLE)
        (36, 1, 0xf8, 0, 4, 18, 4, (-5920f64).to_bits()),
        // getri_2x2 (7): DFMA R14, -RZ, R14, 1
        (40, 0, 0xf8, 2, 14, 0x3ff, 14, 1.0f64.to_bits()),
    ];
    m.merc_f64imm = vec![
        // matinv double2 (1016): @!P0 DMUL R38, R16, 8.98846567431157953865e+307
        (50, 0, 38, 16, 0x7fe00000, 0x01, 0),
        // generate_seed_pseudo (15): DMUL R16, R4.reuse, 12345 (ogon >16b)
        (54, 0, 16, 4, 0x40c81c80, 0xf8, 0),
        // splitKreduce (191): DADD R22, -R20, 1
        (58, 1, 22, 20, 0x3ff00000, 0xf8, 2),
        // splitKreduce (191): DADD R22, -R22, 2
        (62, 1, 22, 22, 0x40000000, 0xf8, 2),
    ];
    // Uwaga: EXIT nie w ostatnim bicie słowa bitmapy (corner n_counted
    // = bitmax+2 przekracza dlugosc emitowanej bitmapy gdy lane%32==31|
    // 63 — separatny od mk51; mk50 test unikal go przypadkiem).
    let o = ops(66);
    let out = generate_mercury_full(&dummy_code(66), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    let r1c = recs_tag(&cm, 0x0d, 0x1c);
    assert_eq!(r1c.len(), 5); // 5 rekordow imm-last (porzadek lane-rosnaco)
    assert_eq!(
        r1c[0],
        hx("020d1c0ef800080200008307820602080013000000000000000000000000f03f")
    );
    assert_eq!(
        r1c[1],
        hx("020d1c0ef800080600008304020302020013000000000000000000000000f03f")
    );
    assert_eq!(
        r1c[2],
        hx("020d1c0ef800080a00008302820282070013000000000000000000000000f03f")
    );
    assert_eq!(
        r1c[3],
        hx("020d1c0e1000080000000306820602060013000000000000000000000000f07f")
    );
    assert_eq!(
        r1c[4],
        hx("020d1c0ef800080200008303c0ff82030013000000000000000000000000f03f")
    );
    let r1a = recs_tag(&cm, 0x0d, 0x1a);
    assert_eq!(r1a.len(), 1);
    assert_eq!(
        r1a[0],
        hx("020d1a0ef800080000000301820413000002010000000000000000000020b7c0")
    );
    let r0f = recs_tag(&cm, 0x0f, 0x12);
    assert_eq!(r0f.len(), 2);
    assert_eq!(
        r0f[0],
        hx("020f120e0100080000008309020413000000000000000000000000000000e07f")
    );
    assert_eq!(
        r0f[1],
        hx("020f120ef80008000000030402011300000000000000000000000000801cc840")
    );
    let r0c = recs_tag(&cm, 0x0c, 0x1e);
    assert_eq!(r0c.len(), 2);
    assert_eq!(
        r0c[0],
        hx("020c1e0ef800080200008305020513000000000000000000000000000000f03f")
    );
    assert_eq!(
        r0c[1],
        hx("020c1e0ef8000802000083058205130000000000000000000000000000000040")
    );
}

#[test]
fn mk51_brak_bez_rekordow() {
    let m = meta_with_load();
    let o = ops(6);
    let out = generate_mercury_full(&dummy_code(6), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    assert!(recs_tag(&cm, 0x0d, 0x1c).is_empty());
    assert!(recs_tag(&cm, 0x0d, 0x1a).is_empty());
    assert!(recs_tag(&cm, 0x0f, 0x12).is_empty());
    assert!(recs_tag(&cm, 0x0c, 0x1e).is_empty());
}
