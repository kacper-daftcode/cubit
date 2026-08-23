//! BUG-108 (sm120 registry TS2-WIDEX-AUTOSTALL i235): the auto-ctrl path
//! treated IMAD.WIDE.* / UIMAD.WIDE.* forms tagged ctrl_class "imad_wide"
//! (sm120 table: IMAD_R_P_R_II_R[_P], UIMAD.WIDE.U32_UR_UR_*_UR) as
//! scoreboard producers: the producer got write_bar + stall 1 and the
//! consumer merely waited the barrier. Hardware does NOT scoreboard
//! fixed-latency ALU writeback — nvcc uses stall=6, wbar=7 — so a consumer
//! of the WIDE result pair issuing +2 slots after the producer read
//! torn/stale values (silicon-harnessed i235; S0c floor lo=3 / hi=5).
//!
//! Fix (scheduling_pass.rs, no table/encoder/decoder changes):
//!   1. insn_needs_write_bar: IMAD/UIMAD excluded from the scoreboard path
//!      unconditionally (fixed-latency ALU; nvcc discipline stall=6/wbar=7).
//!   2. dest_regs/src_regs: uniform-domain UIMAD.WIDE UR-pair spans
//!      (dest URd+URd+1, 64-bit addend UR pair), mirroring the vector WIDE
//!      arm and the BUG-101 span doctrine.
//!
//! Pins (final control state after schedule()+reallocate_barriers — the
//! exact `cubit asm` flow):
//!   1) imm-src2 .X producer carries NO write barrier and stall>=5
//!      (S0c hi-half floor; producer-side rule lands 6);
//!   2) its lo-pair consumer uses pure stall sync (wait_mask==0, issue gap
//!      producer->consumer >= 5);
//!   3) reg-src2 .X form (already correct on main) pinned: no-bar, stall 6;
//!   4) plain IMAD.WIDE.U32 unchanged on both tables (no-FP regression);
//!   5) UIMAD.WIDE UR pair spans: a hand-frozen S01 producer (dist 1) is
//!      seen by consumers of BOTH URd and URd+1 (hi half pre-fix invisible),
//!      and the 64-bit addend registers as a UR pair.

use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, schedule};
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

const HDR: &str = ".entry t\n    .param u64 io\n    S2R R16, SR_TID.X ;\n    MOV R192, RZ ;\n    MOV R211, RZ ;\n    IMAD.WIDE.U32 R232, R16, 0x2, RZ ;\n    MOV R233, R232 ;\n";

/// (wb, wait_mask, stall) per instruction; hand_sched prefix lines pass through.
fn ctrls(body: &str, tab: &IsaTable) -> Vec<(u8, u8, u8)> {
    let src = format!("{HDR}{body}    EXIT ;\n");
    let f = parse_sass_file_str_strict(&src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    schedule(&mut insns, Some(tab));
    reallocate_barriers(&mut insns, Some(tab));
    insns.iter()
        .map(|x| (x.ctrl.write_bar, x.ctrl.wait_mask, x.ctrl.stall))
        .collect()
}

fn idx_of(body: &str, frag: &str) -> usize {
    let src = format!("{HDR}{body}    EXIT ;\n");
    let f = parse_sass_file_str_strict(&src).unwrap();
    f.kernels[0]
        .instructions
        .iter()
        .position(|x| x.opcode_full.contains(frag))
        .unwrap_or_else(|| panic!("no op containing {frag:?}"))
}

const WIDEX_IMM: &str = "    IMAD.WIDE.U32.X R212, P0, R233, 0x3d1, R232, P6 ;\n";
const CONSUMER_LO: &str = "    IADD3.X R33, P4, P5, R192, R211, R212, P4, P5 ;\n";

#[test]
fn t108_1_widex_imm_producer_no_barrier() {
    for tab in [t120(), t103()] {
        let c = ctrls(&format!("{WIDEX_IMM}{CONSUMER_LO}"), &tab);
        let q = idx_of(&format!("{WIDEX_IMM}{CONSUMER_LO}"), "IMAD.WIDE.U32.X");
        assert!(c[q].0 >= 7, "WIDE.X producer must NOT carry a scoreboard wb, got wb={}", c[q].0);
        assert!(c[q].2 >= 5, "WIDE.X producer stall must cover the pair (S0c lo=3/hi=5), got {}", c[q].2);
    }
}

#[test]
fn t108_2_lo_pair_consumer_stall_synced() {
    for tab in [t120(), t103()] {
        let c = ctrls(&format!("{WIDEX_IMM}{CONSUMER_LO}"), &tab);
        let q = idx_of(&format!("{WIDEX_IMM}{CONSUMER_LO}"), "IMAD.WIDE.U32.X");
        let k = idx_of(&format!("{WIDEX_IMM}{CONSUMER_LO}"), "IADD3.X");
        assert_eq!(c[k].1, 0, "consumer of an ALU WIDE result must not wait a barrier, got wait={:#x}", c[k].1);
        // issue gap producer -> consumer is the producer's own stall (post-fix >= 6)
        assert!(c[q].2 >= 6, "gap {} < nvcc stall=6", c[q].2);
    }
}

#[test]
fn t108_3_reg_src2_form_pinned() {
    let body = "    IMAD.WIDE.U32.X R214, P0, R233, R234, R232, P6 ;\n    IADD3.X R33, P4, P5, R192, R211, R214, P4, P5 ;\n";
    for tab in [t120(), t103()] {
        let c = ctrls(body, &tab);
        let q = idx_of(body, "IMAD.WIDE.U32.X");
        assert!(c[q].0 >= 7 && c[q].2 >= 5, "reg-src2 .X: wb={} stall={}", c[q].0, c[q].2);
    }
}

#[test]
fn t108_4_plain_wide_unchanged() {
    let body = "    IMAD.WIDE.U32 R210, R232, 0x3d1, RZ ;\n    IADD3.X R33, P4, P5, R192, R211, R210, P4, P5 ;\n";
    for tab in [t120(), t103()] {
        let c = ctrls(body, &tab);
        let src = format!("{HDR}{body}    EXIT ;\n");
        let q = parse_sass_file_str_strict(&src).unwrap().kernels[0]
            .instructions.iter().position(|x| x.opcode_full == "IMAD.WIDE.U32").unwrap();
        assert!(c[q].0 >= 7, "plain WIDE must stay stall-synced, wb={}", c[q].0);
        assert_eq!(c[q].2, 6, "plain WIDE producer stall must stay nvcc-like 6, got {}", c[q].2);
    }
}

/// Pipeline-level regression pin (the exact span contents are pinned
/// white-box in src/scheduling_pass.rs bug108_tests: the default pipeline's
/// producer-side stall floor swamps the observable effect of a missing UR
/// dep, so the span itself must be verified at the dest_regs/src_regs level).
#[test]
fn t108_5_uimad_wide_ur_pair_spans() {
    // Hand-frozen S01 producer: the gap is exactly 1 slot, so only proper
    // span tracking can raise the consumer; pre-fix UR11 (hi half) was
    // invisible and the consumer passed at stall 1.
    for consume in ["UR10", "UR11"] {
        let body = format!(
            "    [B------:R-:W-:-:S01] UIMAD.WIDE.U32 UR10, UR20, 0x5, UR22 ;\n    UIADD3 UR8, {consume}, UR24, RZ ;\n"
        );
        let c = ctrls(&body, &t120());
        let k = idx_of(&body, "UIADD3");
        assert!(
            c[k].2 >= 4,
            "consumer of UIMAD.WIDE {consume} at dist 1 must stall >= ALU floor 4 (hi-half span), got {}",
            c[k].2
        );
    }
    // 64-bit addend: producer of UR23 (addend hi) must be seen by the WIDE op.
    let body = "    [B------:R-:W-:-:S01] UIADD3 UR23, UR24, 0x1, RZ ;\n    UIMAD.WIDE.U32 UR10, UR20, 0x5, UR22 ;\n";
    let c = ctrls(body, &t120());
    let k = idx_of(body, "UIMAD.WIDE.U32");
    assert!(c[k].2 >= 4, "WIDE op reading addend-pair hi (UR23) must stall >= 4 at dist 1, got {}", c[k].2);
}
