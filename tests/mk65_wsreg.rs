//! mk65 (2026-08-13): the 4147-family mini bundle — reg-form WARPSYNC:
//! the 4147780a mini (the lane is an EIATTR-0x28 site from .merc_cgsites) vs
//! 4147700a (off sites). Corpus EXACT both ways (merclab/mk65 c5/c7/c9:
//! 18932/18932 kernels, 324 kern with 78, 310+14 with 70). Forms: plain
//! `WARPSYNC R<n>` and `WARPSYNC.EXCLUSIVE R<n>` (16/16 EXCLUSIVE off sites);
//! .ALL/.COLLECTIVE have their own families (mk64b/mk59). Side fix:
//! BAR.ARV no longer gets the full 01475a16 record (overproduction +64/kern
//! w cublasLt.536) — mini 41471216 obsluguje slownik mini2 (mk40).

use cubit::sass_file::{kernel_def_to_meta, merc_mc_scan, parse_sass_file_str};
use cubit::ir::{ControlCode, Guard, Instruction};
use cubit::sass_file;
use std::collections::BTreeSet;

fn mk_ins(lane: u32, opf: &str, text: &str) -> Instruction {
    Instruction {
        addr: lane * 16,
        opcode: opf.split('.').next().unwrap_or(opf).to_string(),
        opcode_full: opf.to_string(),
        key: String::new(),
        guard: None,
        operands: Vec::new(),
        modifiers: Vec::new(),
        ctrl: ControlCode::default(),
        hand_sched: false,
        rsd: None,
        raw_text: text.to_string(),
    }
}

#[test]
fn mk65_wsreg_variants() {
    let ins = vec![
        mk_ins(2, "WARPSYNC", "WARPSYNC R20 ;"),
        mk_ins(3, "WARPSYNC.EXCLUSIVE", "WARPSYNC.EXCLUSIVE R16 ;"),
        mk_ins(4, "WARPSYNC.ALL", "WARPSYNC.ALL ;"),            // not reg-form
        mk_ins(5, "WARPSYNC.COLLECTIVE", "WARPSYNC.COLLECTIVE R20, `(.L_1) ;"),
        mk_ins(6, "WARPSYNC", "WARPSYNC R44 ;"),
    ];
    // sites: lane 2 (plain) i lane 3 (EXCLUSIVE-test site-owy hipotetyczny)
    let sites: BTreeSet<u32> = [2u32, 3u32].into_iter().collect();
    let mc = merc_mc_scan(&ins, &sites);
    assert_eq!(mc.ws_reg, vec![(2, 0x78u8), (3, 0x78), (5, 0x70), (6, 0x70)]
        .into_iter()
        .filter(|(l, _)| *l != 5) // lane 5 = COLLECTIVE: NOT reg-form
        .collect::<Vec<_>>());
    // ws_minis only for .ALL
    assert_eq!(mc.ws, vec![(4u32, 0x6eu8)]);
}

#[test]
fn mk65_exec_pos_skip_arv() {
    let sass = ".entry t\n    .reg R0-R3\n    .param u64 p0\n    [B------:R-:W-:Y:S01] LDC R1, c[0x0][0x37c] ;\n    [B------:R-:W-:Y:S01] BAR.ARV 0x1, -0xf00 ;\n    [B------:R-:W-:Y:S01] BAR.SYNC 0x0 ;\n    [B------:R-:W-:Y:S01] BAR.SYNC.DEFER_BLOCKING 0x2, 0x20 ;\n    [B------:R-:W-:Y:S01] EXIT ;\n.endentry\n";
    let mut f = parse_sass_file_str(sass).expect("parse");
    let def = &mut f.kernels[0];
    sass_file::auto_detect_resources(def);
    let code = vec![0u8; def.instructions.len() * 16];
    let meta = kernel_def_to_meta(def, &code);
    // BAR.ARV on lane 1 excluded from bar_pos; 2 real BAR.SYNC remain.
    assert_eq!(meta.merc_bar_pos, vec![2, 3]);
}

#[test]
fn mk65_wsreg_meta_paths() {
    // the same pattern as above through full sass: site 0x28 -> 0x78
    let sass = ".entry t\n    .reg R0-R9\n    .param u64 p0\n    .merc_cgsites 0x20:0xffffffff\n    [B------:R-:W-:Y:S01] LDC R1, c[0x0][0x37c] ;\n    [B------:R-:W-:Y:S01] S2R R5, SR_TID.X ;\n    [B------:R-:W-:Y:S01] WARPSYNC R20 ;\n    [B------:R-:W-:Y:S01] WARPSYNC.EXCLUSIVE R3 ;\n    [B------:R-:W-:Y:S01] EXIT ;\n.endentry\n";
    let mut f = parse_sass_file_str(sass).expect("parse");
    let def = &mut f.kernels[0];
    sass_file::auto_detect_resources(def);
    let code = vec![0u8; def.instructions.len() * 16];
    let meta = kernel_def_to_meta(def, &code);
    assert_eq!(meta.merc_wsreg_minis, vec![(2u32, 0x78u8), (3u32, 0x70u8)]);
    assert!(meta.merc_ws_minis.is_empty());
}
