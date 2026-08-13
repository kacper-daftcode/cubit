//! mk50 (2026-08-13): rekordy edge 02 22 1e 32 dla LDG z desc[URm][Ry.64(+off)]
//! w kernelach *annotated_ptr* (siostra mk42 02223232 dla LD-desc).
//! Piny z korpusu sm_100 (merclab/mk50 c1..c10: 2986 rekordow, 72/72 kerneli
//! EXACT + porzadek lane-rosnaco; zero falszywych bramkowan poza
//! libcublas.so.72). Bramka: nazwa z "annotated_ptr" + desc-UR wylacznie
//! pod lane'y bazowe LDG (wspoldzielenie ze STG/LDGSTS/REDG wylacza UR).

use cubit::eiattr::{KernelMeta, KernelParam};
use cubit::elf_builder::generate_mercury_full;
use cubit::ir::{ControlCode, Guard, Instruction};
use cubit::mercury::CapMerc;
use cubit::sass_file::merc_edge_ldg_scan;

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

fn recs1e(cm: &CapMerc) -> Vec<Vec<u8>> {
    cm.records
        .iter()
        .filter(|r| r.tag == [0x02, 0x22, 0x1e, 0x32])
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
fn mk50_bajty_z_korpusu() {
    // Wektory z libcublas.so.72 sm_100 (cuds_symv_*; c10_vecs.py).
    let mut m = meta_with_load();
    m.merc_edge_ldg = vec![
        // LDG.E.64 R14, desc[UR10][R24.64]
        (44, 0xf8, 0x50, 14, 24, 3, 10, 0),
        // LDG.E.128 R12, desc[UR10][R14.64]  (X!=Y)
        (90, 0xf8, 0x60, 12, 14, 7, 10, 0),
        // LDG.E R18, desc[UR4][R16.64]
        (43, 0xf8, 0x40, 18, 16, 1, 4, 0),
        // @!P0 LDG.E.64 R40, desc[UR10][R34.64+0x100]
        (460, 0x01, 0x50, 40, 34, 3, 10, 0x100),
    ];
    let o = ops(461);
    let out = generate_mercury_full(&dummy_code(461), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    let recs = recs1e(&cm);
    assert_eq!(recs.len(), 4);
    // porzadek lane-rosnaco: 43, 44, 90, 460
    assert_eq!(
        recs[0],
        hx("02221e32f80040814000000081040204000a00020100f8000000000000000000")
    );
    assert_eq!(
        recs[1],
        hx("02221e32f80050814000000083030206000a00820200f8000000000000000000")
    );
    assert_eq!(
        recs[2],
        hx("02221e32f80060814000000007038203000a00820200f8000000000000000000")
    );
    assert_eq!(
        recs[3],
        hx("02221e320100508140000000030a8208000a00820200f8000000000000010000")
    );
}

#[test]
fn mk50_bramka_nazwa_i_wspoldzielenie_ur() {
    let ins = vec![
        mk_ins(0, "VIADD", "VIADD R2, R0, UR5 ;", None),
        mk_ins(3, "LDG.E.128", "LDG.E.128 R12, desc[UR10][R12.64] ;", None),
        mk_ins(5, "LDG.E.64", "LDG.E.64 R18, desc[UR6][R16.64] ;", None),
        mk_ins(7, "STG.E", "STG.E desc[UR6][R20.64], R22 ;", None), // UR6 dzielony!
        // .U16 — korpusowo bez rekordow
        mk_ins(9, "LDG.E.U16", "LDG.E.U16 R40, desc[UR10][R40.64] ;", None),
        mk_ins(11, "EXIT", "EXIT ;", None),
    ];
    // jadro annotated_ptr: UR10 (ldg-only) -> rekordy; UR6 dzielony ze STG -> brak
    let out = merc_edge_ldg_scan("kern_annotated_ptr_x", &ins);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, 3); // lane 3 (adres 0x30/16)
    assert_eq!((out[0].2, out[0].3, out[0].4, out[0].5, out[0].6), (0x60, 12, 12, 7, 10));
    // zwykla nazwa -> pusto
    let out2 = merc_edge_ldg_scan("czysty_kernel", &ins);
    assert!(out2.is_empty());
}

#[test]
fn mk50_skan_pred_i_off() {
    let ins = vec![
        mk_ins(
            12,
            "LDG.E.64",
            "LDG.E.64 R40, desc[UR10][R34.64+0x100] ;",
            Some(Guard { pred: 0, negated: true, uniform: false }),
        ),
        mk_ins(20, "LDG.E", "LDG.E R18, desc[UR4][R16.64] ;", None),
        mk_ins(30, "EXIT", "EXIT ;", None),
    ];
    let out = merc_edge_ldg_scan("x_annotated_ptr", &ins);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0], (12, 0x01, 0x50, 40, 34, 3, 10, 0x100));
    assert_eq!(out[1], (20, 0xf8, 0x40, 18, 16, 1, 4, 0));
}

#[test]
fn mk50_brak_bez_rekordow() {
    let m = meta_with_load();
    let o = ops(6);
    let out = generate_mercury_full(&dummy_code(6), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    assert!(recs1e(&cm).is_empty());
}
