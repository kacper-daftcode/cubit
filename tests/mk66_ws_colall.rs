//! mk66 (2026-08-13): WARPSYNC.ALL.COLLECTIVE (nvdis: WARPSYNC.COLLECTIVE.ALL)
//! NIE dostaje mini 41476e0a/4147760a — orig zeruie te lane'y korpusowo
//! (cusparse.318 find_colors*: 57 lane'ow, 0 rekordow; A/B przed poprawka
//! 41476e0a orig 180 vs new 237, po: 180==180). Regula mk64b (76 iff site
//! 0x28 else 6e) dotyczy WYLACZNIE czystego WARPSYNC.ALL; nasza pisownia
//! .ALL.COLLECTIVE nie moze byc lapana przez filtr `.contains(".ALL")` —
//! wykluczenie `.COLLECTIVE` w merc_mc_scan / mc_scan_lines / fallbacku.

use cubit::sass_file::{kernel_def_to_meta, merc_mc_scan, parse_sass_file_str};
use cubit::ir::{ControlCode, Instruction};
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
fn mk66_colall_no_mini() {
    // 7 lane'ow WARPSYNC.ALL.COLLECTIVE (jak find_colors w cusparse.318):
    // zadne nie dostaje ws-mini, niezaleznie od sites.
    let ins = vec![
        mk_ins(2, "WARPSYNC.ALL.COLLECTIVE", "WARPSYNC.ALL.COLLECTIVE 0x5 ;"),
        mk_ins(3, "WARPSYNC.ALL.COLLECTIVE", "WARPSYNC.ALL.COLLECTIVE 0x5 ;"),
        mk_ins(4, "WARPSYNC.ALL", "WARPSYNC.ALL 0xffffffff ;"),
    ];
    let sites: BTreeSet<u32> = [2u32, 4u32].into_iter().collect();
    let mc = merc_mc_scan(&ins, &sites);
    assert_eq!(mc.ws, vec![(4u32, 0x76u8)]);
    // COLLECTIVE.ALL nie jest tez reg-form ani d1wc47 (mk59 fail-closed .ALL):
    assert!(mc.ws_reg.is_empty());
    assert!(mc.d1wc47.is_empty());
}

#[test]
fn mk66_colall_meta_path() {
    let sass = ".entry t\n    .reg R0-R9\n    .param u64 p0\n    .merc_cgsites 0x30:0x05000007\n    [B------:R-:W-:Y:S01] LDC R1, c[0x0][0x37c] ;\n    [B------:R-:W-:Y:S05] WARPSYNC.ALL.COLLECTIVE 0x5 ;\n    [B------:R-:W-:Y:S01] WARPSYNC.ALL 0xffffffff ;\n    [B------:R-:W-:Y:S01] EXIT ;\n.endentry\n";
    let mut f = parse_sass_file_str(sass).expect("parse");
    let def = &mut f.kernels[0];
    sass_file::auto_detect_resources(def);
    let code = vec![0u8; def.instructions.len() * 16];
    let meta = kernel_def_to_meta(def, &code);
    // tylko bare WARPSYNC.ALL (lane 2, site 0x30/16=3? nie: site 0x30 to
    // lane 3, lane 2 nie jest site'em) -> 6e; COLLECTIVE.ALL (lane 1) NIC.
    assert_eq!(meta.merc_ws_minis, vec![(2u32, 0x6eu8)]);
    assert!(meta.merc_wsreg_minis.is_empty());
}

#[test]
fn mk66_scan_lines_mirror() {
    // lustro mercury::mc_scan_lines: ta sama regula na surowym tekscie.
    use cubit::mercury::{mc_scan_lines, McScanText};
    let it = |lane: u32, full: &str, text: &str| McScanText {
        lane,
        base: full.split('.').next().unwrap_or(full).to_string(),
        full: full.to_string(),
        text: text.to_string(),
        guarded: false,
        guard_code: 0xf8,
    };
    // COLLECTIVE.ALL wyciete z ws_lanes; bare .ALL lane5 bez BAR po nim
    // -> regula tekstowa has_bar=false -> 0x76.
    let items = vec![
        it(0, "WARPSYNC.ALL.COLLECTIVE", "WARPSYNC.ALL.COLLECTIVE 0x5 ;"),
        it(5, "WARPSYNC.ALL", "WARPSYNC.ALL 0xffffffff ;"),
        it(6, "BAR.SYNC", "BAR.SYNC 0x0 ;"),
        it(9, "WARPSYNC.ALL", "WARPSYNC.ALL 0xffffffff ;"),
    ];
    let out = mc_scan_lines(&items);
    assert_eq!(out.ws, vec![(5u32, 0x6eu8), (9, 0x76u8)]);
}
