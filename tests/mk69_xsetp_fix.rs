//! mk69 (2026-08-13): refining mk41 XSETP (merclab/mk69 c2..c14 —
//! l2 corpus + keep-400; per-site proof: rot_kernel libcublas.141, sphpr2
//! libcublas.339/345/836/841, mtr_gerc libcusolver.1186, sparse22
//! libcusparse.102, ds_symv libcusolver.1573):
//!  * a head Pn is CONSUMED by the first matching .EX tail (pop) —
//!    a repeated EX with the same carry-pred on a distant lane emits nothing
//!    (rot_kernel: (12,13)+(12,119) -> one mini);
//!  * head eligibility: a non-EX ISETP writing Pn with last token != PT
//!    (bool-join) is NOT a head and CLEARS the older one (a rewrite);
//!  * the mini class comes from the HEAD only (a UR in the tail does not upgrade: sphpr2
//!    ISETP.GE.AND.EX P0, PT, RZ, UR13, PT, P0 -> 42102e14, not 3214).

use cubit::ir::{ControlCode, Guard, Instruction};
use cubit::sass_file::merc_xsetp_scan;

fn mk_ins(lane: u32, opf: &str, text: &str) -> Instruction {
    Instruction {
        addr: lane * 16,
        opcode: opf.split('.').next().unwrap_or(opf).to_string(),
        opcode_full: opf.to_string().into(),
        key: String::new(),
        guard: None::<Guard>,
        operands: Vec::new(),
        modifiers: Vec::new(),
        ctrl: ControlCode::default(),
        hand_sched: false,
        rsd: None,
        raw_text: text.to_string(),
    }
}

#[test]
fn mk69_stale_rematch_bez_dublera() {
    // rot_kernel-ref float2f (cublas.141): head 12 (P0) +EX 13 +EX 119.
    let ins = vec![
        mk_ins(12, "ISETP", "ISETP.NE.U32.AND P0, PT, R2, RZ, PT ;"),
        mk_ins(13, "ISETP.NE.AND.EX", "ISETP.NE.AND.EX P2, PT, R3, RZ, PT, P0 ;"),
        mk_ins(119, "ISETP.NE.AND.EX", "ISETP.NE.AND.EX P0, PT, R3, RZ, PT, P0 ;"),
    ];
    let out = merc_xsetp_scan(&ins);
    assert_eq!(out, vec![(12, 0)], "jedno mini na head 12, stale 119 ciche");
}

#[test]
fn mk69_klasa_z_heada_tail_ur_nie_podnosi() {
    // sphpr2_64addr (cublas.339): head reg-reg, tail z UR13 -> 42102e14.
    let ins = vec![
        mk_ins(78, "ISETP", "ISETP.GE.U32.AND P0, PT, R20, R14, PT ;"),
        mk_ins(80, "ISETP.GE.AND.EX", "ISETP.GE.AND.EX P0, PT, RZ, UR13, PT, P0 ;"),
    ];
    let out = merc_xsetp_scan(&ins);
    assert_eq!(out, vec![(78, 0)]);
    // a head with UR -> class 2 as before
    let ins2 = vec![
        mk_ins(18, "ISETP", "ISETP.GE.U32.AND P1, PT, R2, UR4, PT ;"),
        mk_ins(19, "ISETP.GE.AND.EX", "ISETP.GE.AND.EX P1, PT, R3, UR5, PT, P1 ;"),
    ];
    assert_eq!(merc_xsetp_scan(&ins2), vec![(18, 2)]);
    // head z imm -> klasa 1
    let ins3 = vec![
        mk_ins(8, "ISETP", "ISETP.GE.U32.AND P0, PT, R2, 0x1, PT ;"),
        mk_ins(9, "ISETP.GE.AND.EX", "ISETP.GE.AND.EX P0, PT, R3, RZ, PT, P0 ;"),
    ];
    assert_eq!(merc_xsetp_scan(&ins3), vec![(8, 1)]);
}

#[test]
fn mk69_booljoin_kasuje_heada() {
    // mtr_gerc (cusolver.1186): ISETP.EQ.U32.AND P3, PT, RZ, UR44, !P2 zapisuje
    // P3 with non-PT carry-in -> NOT a head; EX tail 237 without a mini.
    let ins = vec![
        mk_ins(226, "ISETP", "ISETP.NE.U32.AND P2, PT, R44, -0x1, PT ;"),
        mk_ins(228, "ISETP.NE.U32.AND.EX", "ISETP.NE.U32.AND.EX P2, PT, R45, -0x1, PT, P2 ;"),
        mk_ins(230, "ISETP", "ISETP.EQ.U32.AND P3, PT, RZ, UR44, !P2 ;"),
        mk_ins(237, "ISETP.LT.AND.EX", "ISETP.LT.AND.EX P3, PT, R46, UR33, !P2, P3 ;"),
    ];
    let out = merc_xsetp_scan(&ins);
    assert_eq!(out, vec![(226, 1)], "bool-join not a head; 226->class1");
}

#[test]
fn mk69_pop_nie_lamie_kolejnej_pary() {
    // sparse22 (cusparse.102): after tail 254 (P3) a NEW head P2/etc. arrives;
    // each head->one record; no dangling ones.
    let ins = vec![
        mk_ins(189, "ISETP", "ISETP.GE.U32.AND P3, PT, R22, UR4, PT ;"),
        mk_ins(254, "ISETP.GE.AND.EX", "ISETP.GE.AND.EX P6, PT, RZ, UR5, PT, P3 ;"),
        mk_ins(300, "ISETP.GE.AND.EX", "ISETP.GE.AND.EX P3, PT, RZ, UR5, PT, P3 ;"),
        mk_ins(298, "ISETP", "ISETP.GE.U32.AND P6, PT, R20, UR4, PT ;"),
        mk_ins(302, "ISETP.GE.AND.EX", "ISETP.GE.AND.EX P6, PT, RZ, UR5, PT, P6 ;"),
    ];
    let out = merc_xsetp_scan(&ins);
    assert_eq!(out, vec![(189, 2), (298, 2)]);
}
