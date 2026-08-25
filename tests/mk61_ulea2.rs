//! mk61 (2026-08-13): the 42254214 mini — class-2 CLOSED (mk52 park) +
//! a strict class-1. sm_100 corpus rules (merclab/mk61 c1..c22):
//!  * class-1: [UR|URZ, UPn, UR|URZ, UR|URZ, imm] exactly-5 tokens
//!    (UR negations allowed; gbmv 'UR24, UP0, UR8, 0xffffffe0, 0x5' does NOT carry
//!    — imm in the srcB slot);
//!  * class-2: [UR|URZ, UR|URZ, UR|URZ, imm<=15] 4 tokens, no .HI/.X
//!    (imma '@!UP0 ULEA UR11, UR11, UR14, 0x3' DOES carry — a guard does not exclude;
//!    imm>15 (0x18/0x1e) does NOT carry — the 2-kernel cusparse-cub 838 park).
//! EXACT: 14117/14119 kerneli count + 9556/9556 okien porzadku; porownanie
//! ze 138 rozwiazanymi kernelami atrybucji (c8): 138/138 zgodnych lane-setow.

use cubit::eiattr::{KernelMeta, KernelParam};
use cubit::elf_builder::generate_mercury_full;
use cubit::ir::{ControlCode, Guard, Instruction};
use cubit::mercury::CapMerc;
use cubit::sass_file::{merc_ulea_rec, merc_usetp_scan};

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
fn mk61_skan_klasa1_scisla() {
    // nrm2: negacja srcA + URZ jako srcB -> NOSI
    let ins = vec![
        mk_ins(2, "ULEA", "ULEA UR8, UP0, -UR20, URZ, 0x7 ;", None),
        // gbmv: imm w slocie srcB -> NIE
        mk_ins(3, "ULEA", "ULEA UR24, UP0, UR8, 0xffffffe0, 0x5 ;", None),
        // gemmSN: dst URZ -> NOSI
        mk_ins(4, "ULEA", "ULEA URZ, UP1, UR6, UR32, 0x2 ;", None),
        // gebd2: 6 tokenow (carry-in) -> NIE
        mk_ins(5, "ULEA", "ULEA UR7, UP0, UR11, UR10, URZ, 0x1 ;", None),
        mk_ins(6, "EXIT", "EXIT ;", None),
    ];
    let (_m, u) = merc_usetp_scan(&ins);
    assert_eq!(u, vec![2, 4]);
}

#[test]
fn mk61_skan_klasa2() {
    let g = Some(Guard { pred: 0, negated: true, uniform: true });
    let ins = vec![
        // trsm upper: plain all-UR imm 5 -> carries; HI recordless
        mk_ins(1, "ULEA.HI", "ULEA.HI UR4, UR4, UR14, URZ, 0x5 ;", None),
        mk_ins(2, "ULEA", "ULEA UR5, UR7, UR6, 0x5 ;", None),
        // trsm Li1: negacja srcB -> NOSI
        mk_ins(3, "ULEA", "ULEA UR4, UR12, -UR5, 0x6 ;", None),
        // imma epilogue: guard @!UP0 -> NOSI
        mk_ins(4, "ULEA", "@!UP0 ULEA UR11, UR11, UR14, 0x3 ;", g),
        // imm-srcB (trsm lower) -> NIE
        mk_ins(5, "ULEA", "ULEA UR10, UR12, 0x20, 0x5 ;", None),
        // imm>15 (cusparse-cub 838 park) -> NIE
        mk_ins(6, "ULEA", "ULEA UR4, UR5, UR4, 0x18 ;", None),
        mk_ins(7, "ULEA", "ULEA UR19, UR4, UR9, 0x1e ;", None),
        mk_ins(8, "EXIT", "EXIT ;", None),
    ];
    let (_m, u) = merc_usetp_scan(&ins);
    assert_eq!(u, vec![2, 3, 4]);
}

#[test]
fn mk61_rec_helper_granice() {
    // bezposrednio na tokenach: granica imm 15/16
    assert!(merc_ulea_rec(&["UR5", "UR7", "UR6", "0xf"], "ULEA"));
    assert!(!merc_ulea_rec(&["UR5", "UR7", "UR6", "0x10"], "ULEA"));
    assert!(!merc_ulea_rec(&["UR5", "UR7", "UR6", "5"], "ULEA.HI"));
    assert!(!merc_ulea_rec(&["UR5", "UR7", "UR6", "5"], "ULEA.HI.SX32"));
    // dziesietne imm tez (nvcc drukuje '5')
    assert!(merc_ulea_rec(&["URZ", "UR7", "UR6", "5"], "ULEA"));
}

#[test]
fn mk61_emisja_kolejnosc_up_ur() {
    let mut m = meta_with_load();
    // class-1 on lane 6, class-2 on lanes 3 and 9: order by lane
    m.merc_ulea_upco = vec![6, 3, 9];
    let o = ops(12);
    let out = generate_mercury_full(&dummy_code(12), 0x0c, Some(&o), &m, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    let got: Vec<String> = minis42(&cm)
        .iter()
        .map(|v| v[..4].iter().map(|b| format!("{:02x}", b)).collect::<String>())
        .collect();
    assert_eq!(got, vec!["42254214", "42254214", "42254214"]);
}
