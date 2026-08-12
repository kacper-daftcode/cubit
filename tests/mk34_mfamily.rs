//! mk34 (2026-08-11): node-model bitmapy capmerc dla rodziny m-family
//! (SYNCS.EXCH/ARRIVE/PHASECHK / bulk-async) — reguly zweryfikowane
//! ground-truth na wezlach emitowanych przez nvcc (g5b dump listy M+0x288,
//! analysis/re/shim/g5b.py) dla b_mbarrier i b_bulk_cp.
//!
//! Kluczowe poprawki vs lane-space-era mk30b:
//!  - para USHF licznika mbarrier ("USHF ..,0xb" + "USHF ..,0x1" po
//!    d1-UIADD3) nie ma wezlow wcale — lane'e wypadaja z przestrzeni bitmapy
//!    (slot-skip), a nie tylko traca bit;
//!  - FENCE.ASYNC tez nodeless (b_bulk_cp lane18);
//!  - EXCH/ARRIVE(wszy.) / PLOP3-tx / UBLKCP hostuja rekordy — bez bitu;
//!  - kazdy BRA w m-family ma wezel t4 flaga=1 (dowod: bloby n13/n19/n32/n33
//!    b_mbarrier z offsetami skokow), wyjatek: samo-petla;
//!  - MOV R?,0x400 i ULEA prologu maja bity (wezly flag=1) — reguly kasujace
//!    mk30b (mov400/ulea_x/bra_np/s2ur_extra) bylo lane-space artefaktami.
//!
//! Oczekiwane listy bitow to literalne TYPE4BITS z dumpow g5b (ktore ==
//! bitmap-set nvcc na oryginalnych cubinach, mk33 README).

use cubit::eiattr::KernelMeta;
use cubit::elf_builder::generate_mercury_full;
use cubit::mercury::CapMerc;

fn dummy_code(n_instr: usize) -> Vec<u8> {
    vec![0u8; n_instr * 16]
}

fn mb_meta() -> KernelMeta {
    KernelMeta {
        name: "_Z10b_mbarrierPi".into(),
        merc_mc_exch: vec![(13, true, 6, 4)],
        merc_mc_arrive: vec![(19, 0xf8)],
        merc_mc_phase: vec![20, 33],
        merc_mc_d1: vec![(8, true)],
        merc_mc_nodeless: vec![9, 10],
        merc_mc_voteu_all: vec![5, 12],
        merc_s2ur_cga: vec![(6, true, 6), (23, false, 5)],
        merc_ws_minis: vec![(22, 0x6e)],
        merc_mc_lea18: vec![18],
        // celowo ustawione: mk34 ma IGNOROWAC te pole (MOV-400 ma wezel z
        // bitem; poprzednia regula kasowania byla lane-space bledem)
        merc_mc_mov400: vec![17],
        merc_guarded_bra: vec![15, 21, 34],
        merc_bra_selfloop: vec![36],
        ..Default::default()
    }
}

fn mb_ops() -> Vec<String> {
    [
        "LDC", "S2R", "UMOV", "LDCU.64", "ISETP.NE.U32.AND", "VOTEU.ALL", "S2UR", "UMOV",
        "UIADD3", "USHF.L.U32", "USHF.L.U32", "ULEA", "VOTEU.ALL", "SYNCS.EXCH.64",
        "BAR.SYNC.DEFER_BLOCKING", "BRA", "S2R", "MOV", "LEA", "SYNCS.A1T0.ARRIVE.TRANS64",
        "SYNCS.PHASECHK.TRANS64.TRYWAIT", "BRA", "WARPSYNC.ALL", "S2UR", "BAR.SYNC.DEFER_BLOCKING",
        "UMOV", "LDC.64", "ULEA", "IMAD.WIDE.U32", "LDS", "STG.E", "EXIT", "YIELD",
        "SYNCS.PHASECHK.TRANS64.TRYWAIT", "BRA", "BRA", "BRA",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain(std::iter::repeat("NOP".to_string()).take(11))
    .collect()
}

#[test]
fn mk34_mbarrier_bitmap_node_model() {
    let ops = mb_ops();
    let out = generate_mercury_full(&dummy_code(ops.len()), 0x0c, Some(&ops), &mb_meta(), false);
    let cm = CapMerc::parse(&out, true).unwrap();
    assert_eq!(cm.n_nonnop, 35, "B in-mianownik == liczba wezlow nvcc");
    assert_eq!(
        cm.set_bits(),
        vec![2, 4, 7, 9, 13, 15, 19, 23, 25, 26, 27, 29, 30, 32, 33],
        "bitmap slots == g5b TYPE4BITS (b_mbarrier)"
    );
}

fn bc_ops() -> Vec<String> {
    [
        "LDC", "S2R", "BSSY.RECONVERGENT", "ISETP.NE.U32.AND", "BRA", "S2UR", "LDCU",
        "PLOP3.LUT", "UMOV", "UMOV", "UIADD3", "UIADD3", "USHF.L.U32", "USHF.L.U32",
        "LDCU.64", "UISETP.LT.AND", "ULEA", "ULEA", "FENCE.ASYNC.S.VIEW", "SYNCS.EXCH.64",
        "USEL", "USHF.L.U32", "USHF.R.U32.HI", "UPRMT", "ELECT", "__raw__", "PLOP3.LUT",
        "PLOP3.LUT", "BRA.ANY.U", "NOP", "BSYNC.RECONVERGENT", "S2UR", "BAR.SYNC.DEFER_BLOCKING",
        "IMAD.SHL.U32", "UMOV", "LOP3.LUT", "LDC.64", "ULEA", "LDS", "IMAD.WIDE.U32",
        "LDCU.64", "STG.E", "EXIT", "BRA",
    ]
    .iter()
    .map(|s| s.to_string())
    .chain(std::iter::repeat("NOP".to_string()).take(10))
    .collect()
}

#[test]
fn mk34_bulk_cp_bitmap_node_model() {
    let ops = bc_ops();
    let meta = KernelMeta {
        name: "_Z9b_bulk_cpPiPKii".into(),
        merc_mc_exch: vec![(19, false, 7, 4)],
        merc_mc_d1: vec![(11, false)],
        merc_mc_nodeless: vec![12, 13, 18],
        merc_s2ur_cga: vec![(5, false, 5), (31, false, 5)],
        merc_plop3_tx: vec![(7, 0), (26, 1), (27, 2)],
        merc_ublkcp: vec![25],
        merc_bsync_close: vec![30],
        merc_bra_selfloop: vec![43],
        merc_guarded_bra: vec![4, 28],
        ..Default::default()
    };
    let out = generate_mercury_full(&dummy_code(ops.len()), 0x0c, Some(&ops), &meta, false);
    let cm = CapMerc::parse(&out, true).unwrap();
    assert_eq!(cm.n_nonnop, 40, "B == 40 (g5b NNODES z tailem)");
    assert_eq!(
        cm.set_bits(),
        vec![2, 3, 4, 8, 9, 10, 13, 14, 15, 17, 18, 19, 20, 25, 29, 30, 31, 33, 34, 35, 38],
        "bitmap slots == g5b TYPE4BITS (b_bulk_cp)"
    );
}

/// Skan tekstowy: para USHF licznika mbarrier + FENCE.ASYNC -> nodeless,
/// ale tylko w m-family (SYNCS.*).
#[test]
fn mk34_scan_nodeless_ushf_pair_and_fence_gating() {
    use cubit::mercury::{mc_scan_lines, McScanText};
    let mk = |lane: u32, full: &str, text: &str, guarded: bool| McScanText {
        lane,
        base: full.split('.').next().unwrap_or(full).to_string(),
        full: full.to_string(),
        text: text.to_string(),
        guarded,
        guard_code: if guarded { 0 } else { 0xf8 },
    };
    // m-family: SYNCS.EXCH obecne
    let items = vec![
        mk(0, "S2R", "S2R R7, SR_TID.X ;", false),
        mk(1, "SYNCS", "SYNCS.EXCH.64 URZ, [UR7], UR4 ;", true),
        mk(2, "UIADD3", "UIADD3 UR4, UPT, UPT, -UR4, 0x100000, URZ ;", false),
        mk(3, "USHF", "USHF.L.U32 UR5, UR4, 0xb, URZ ;", false),
        mk(4, "USHF", "USHF.L.U32 UR4, UR4, 0x1, URZ ;", false),
        mk(5, "FENCE", "FENCE.ASYNC.S.VIEW ;", false),
        mk(6, "EXIT", "EXIT ;", false),
    ];
    let out = mc_scan_lines(&items);
    assert_eq!(out.nodeless, vec![3, 4, 5]);
    assert_eq!(out.ushf_fin, vec![4], "pole zostaje (stary kontrakt)");
    // bez m-family: nodeless puste
    let items2 = vec![
        mk(0, "USHF", "USHF.L.U32 UR5, UR4, 0xb, URZ ;", false),
        mk(1, "USHF", "USHF.L.U32 UR4, UR4, 0x1, URZ ;", false),
        mk(2, "FENCE", "FENCE.ASYNC.S.VIEW ;", false),
        mk(3, "EXIT", "EXIT ;", false),
    ];
    let out2 = mc_scan_lines(&items2);
    assert!(out2.nodeless.is_empty());
}
