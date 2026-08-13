//! mk52 (2026-08-13): minis UISETP/ULEA — 42103406 (imm) / 42103614 (reg) /
//! 42104014 (para-EX) / 42254214 (ULEA carry-out). Reguly z korpusu sm_100
//! (merclab/mk52 c1..c26; bitmapa: firing-lane traci bit — poza testem,
//! walidowane harness):
//!  * para non-EX head (dst UPn) + EX tail (..., UPn): class-mini na head-lane
//!    (3406 gdy imm w head LUB tail; 3614 o.w.) + 4014 gdy tail bez imm,
//!  * non-EX lancuch (ostatni operand !?UP#): mini wg wlasnego imm,
//!  * ULEA "URd, UPcout, .." -> 42254214; ULEA.HI(.X) bez rekordu.

use cubit::eiattr::{KernelMeta, KernelParam};
use cubit::elf_builder::generate_mercury_full;
use cubit::ir::{ControlCode, Guard, Instruction};
use cubit::mercury::CapMerc;
use cubit::sass_file::merc_usetp_scan;

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

fn minis42(cm: &CapMerc) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for r in &cm.records {
        if r.tag.len() == 4 && r.tag[0] == 0x42 {
            let mut v = r.tag.to_vec();
            v.extend_from_slice(&r.payload);
            out.push(v);
        }
    }
    out
}

#[test]
fn mk52_skan_par_i_lancuchow() {
    let ins = vec![
        mk_ins(1, "LDCU.64", "LDCU.64 UR6, c[0x0][0x390] ;", None),
        // geqrf: para reg-reg -> 3614 + 4014 (head lane 3)
        mk_ins(3, "UISETP", "UISETP.GT.U32.AND UP0, UPT, UR4, UR5, UPT ;", None),
        mk_ins(4, "UISETP.GT.AND.EX", "UISETP.GT.AND.EX UP0, UPT, UR6, URZ, UPT, UP0 ;", None),
        // thrust: head z imm -> 3406 + 4014 (head lane 6)
        mk_ins(6, "UISETP", "UISETP.GE.U32.AND UP1, UPT, UR6, 0x200, UPT ;", None),
        mk_ins(7, "UISETP.GE.AND.EX", "UISETP.GE.AND.EX UP1, UPT, UR7, URZ, UPT, UP1 ;", None),
        // gemv2: imm w head i w tail -> 3406 (head lane 9; 4014 zgaszone) PLUS
        // mk68: mini 42103e06 na lane EX-tail (10) — merclab/mk68 c3/c4/c6.
        mk_ins(9, "UISETP", "UISETP.GT.U32.AND UP2, UPT, UR8, 0x7f, UPT ;", None),
        mk_ins(10, "UISETP.GT.AND.EX", "UISETP.GT.AND.EX UP2, UPT, UR9, -0x1, UPT, UP2 ;", None),
        // sam EX bez znanego heada -> nic (fail-closed)
        mk_ins(12, "UISETP.LT.AND.EX", "UISETP.LT.AND.EX UP3, UPT, UR4, URZ, UPT, UP5 ;", None),
        // trsm: lancuch z imm -> jedno 3406 na lane lancucha (14)
        mk_ins(13, "UISETP", "UISETP.NE.AND UP4, UPT, UR4, URZ, UPT ;", None),
        mk_ins(14, "UISETP", "UISETP.LT.OR UP4, UPT, UR5, 0x1, UP4 ;", None),
        // iamax: lancuch bez imm -> 3614 na lane 16
        mk_ins(15, "UISETP", "UISETP.NE.U32.AND UP6, UPT, UR6, URZ, UPT ;", None),
        mk_ins(16, "UISETP", "UISETP.EQ.OR UP6, UPT, UR5, URZ, !UP6 ;", None),
        mk_ins(18, "EXIT", "EXIT ;", None),
    ];
    let (m, u) = merc_usetp_scan(&ins);
    assert_eq!(
        m,
        vec![(3, 0), (3, 2), (6, 1), (6, 2), (9, 1), (10, 3), (14, 1), (16, 0)]
    );
    assert!(u.is_empty());
}

#[test]
fn mk52_skan_ulea() {
    let ins = vec![
        // gebd2: carry-out -> mini
        mk_ins(2, "ULEA", "ULEA UR4, UP0, UR6, UR4, 0x2 ;", None),
        // carry-in HI.X -> bez rekordu
        mk_ins(3, "ULEA.HI.X", "ULEA.HI.X UR5, UR6, UR5, UR7, 0x2, UP0 ;", None),
        // zwykly ULEA bez UP -> bez rekordu
        mk_ins(4, "ULEA", "ULEA UR4, UR6, UR4, 0x18 ;", None),
        mk_ins(5, "EXIT", "EXIT ;", None),
    ];
    let (m, u) = merc_usetp_scan(&ins);
    assert_eq!(u, vec![2]);
    assert!(m.is_empty());
}

#[test]
fn mk52_skan_guard_i_dst_neg() {
    // guardka na head nie blokuje; dst UPT/PT nie sledzone
    let g = Some(Guard { pred: 2, negated: true, uniform: false });
    let ins = vec![
        mk_ins(1, "UISETP", "@!P2 UISETP.GE.U32.AND UP0, UPT, UR4, 0x9, UPT ;", g),
        mk_ins(2, "UISETP.GE.AND.EX", "UISETP.GE.AND.EX UP0, UPT, UR5, URZ, UPT, UP0 ;", None),
        mk_ins(3, "UISETP", "UISETP.NE.AND UPT, UPT, UR4, URZ, UPT ;", None),
        mk_ins(4, "EXIT", "EXIT ;", None),
    ];
    let (m, _) = merc_usetp_scan(&ins);
    assert_eq!(m, vec![(1, 1), (1, 2)]);
}

#[test]
fn mk52_emisja_bajtow_i_kolejnosc() {
    let mut m = meta_with_load();
    m.merc_usetp_minis = vec![(3, 0), (3, 2), (6, 1), (9, 1), (9, 0)];
    m.merc_ulea_upco = vec![5];
    let o = ops(12);
    let out = generate_mercury_full(&dummy_code(12), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    let got: Vec<String> = minis42(&cm)
        .iter()
        .map(|v| v[..4].iter().map(|b| format!("{:02x}", b)).collect::<String>())
        .collect();
    assert_eq!(
        got,
        vec![
            "42103614", // lane 3 para reg
            "42104014", // + follower
            "42254214", // lane 5 ULEA
            "42103406", // lane 6 imm
            "42103406", // lane 9
            "42103614", // lane 9 pozniej
        ]
    );
}

#[test]
fn mk52_brak_bez_rekordow() {
    let m = meta_with_load();
    let o = ops(6);
    let out = generate_mercury_full(&dummy_code(6), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    assert!(minis42(&cm).is_empty());
}
