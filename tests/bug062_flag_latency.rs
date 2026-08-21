//! BUG-062 (sm120 register 046 family + i134/i135): silicon latency floor
//! for flag (predicate) producers. A consumer of a fresh Pn (guard @Pn or
//! predicate operand) issued less than 13 issue-clocks after an ISETP/PLOP3
//! producer reads the STALE flag (i134: global sweep S12 FAIL / S13 SAFE,
//! per-slot map 15/15 SAFE @ S13; i135: S13 re-confirmed as the target-safe
//! point at production occupancy). The audit reports it as WARN (floors are
//! occupancy-contextual, so never a hard gate). These tests pin:
//!   0) the class is ENV-GATED (frozen=false always): on the certified R0b
//!      publish text (5640 ins, silicon-EXACT) an unconditional print would
//!      raise 193 findings at gaps 1..12cy -- the i134 low-occ floor does NOT
//!      generalise across kernels, so this class lives behind CUBIT_HAZ only.
//!   A) frozen flag producer under the floor + near consumer  -> FLAG-LATENCY
//!   B) floor boundary (S13)                                  -> quiet
//!   C) all-white autosched                                   -> no FP (S14 floor cover)
//!   D) predicate written by an unmeasured class (IADD3 carry) -> silent
//!   E) consumer via predicate operand (not only guard)       -> FLAG-LATENCY

use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, report_hazards, schedule};
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

const HDR: &str = ".entry t\n    .param u64 io\n    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n";

fn hazards(body: &str) -> Vec<cubit::scheduling_pass::HazardReport> {
    let src = format!("{HDR}{body}    EXIT ;\n");
    let f = parse_sass_file_str_strict(&src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    schedule(&mut insns, Some(&t120()));
    reallocate_barriers(&mut insns, Some(&t120()));
    report_hazards(&insns)
}

fn flag_findings(hs: &[cubit::scheduling_pass::HazardReport]) -> Vec<String> {
    hs.iter().filter(|h| h.msg.contains("FLAG-LATENCY")).map(|h| h.msg.clone()).collect()
}

// A) frozen ISETP with a hand-lowered stall (S04, the i130/i134 failure
// shape) feeding a guard consumer right after: must be flagged, frozen=true.
#[test]
fn t_a_frozen_flag_under_floor_guarded_consumer() {
    let hs = hazards(
        "    [B------:R-:W-:-:S04] ISETP.GT.AND P0, PT, R10, 0x5, PT ;\n    @P0 IADD3 R11, PT, PT, R12, 0x1, RZ ;\n",
    );
    let f = flag_findings(&hs);
    assert!(!f.is_empty(), "under-floor flag gap must be flagged: {:?}", hs.iter().map(|h| h.msg.clone()).collect::<Vec<_>>());
    let h = hs.iter().find(|h| h.msg.contains("FLAG-LATENCY")).unwrap();
    assert!(!h.frozen, "env-gated class: never unconditional (publish-pipeline FP gate)");
    assert!(h.msg.contains("gap 4cy < 13cy"), "gap math (producer stall spans to consumer), got: {}", h.msg);
    assert!(h.msg.contains("ISETP"), "producer named, got: {}", h.msg);
}

// B) same shape at the silicon floor (S13): quiet.
#[test]
fn t_b_floor_boundary_quiet() {
    let hs = hazards(
        "    [B------:R-:W-:-:S13] ISETP.GT.AND P0, PT, R10, 0x5, PT ;\n    @P0 IADD3 R11, PT, PT, R12, 0x1, RZ ;\n",
    );
    assert!(flag_findings(&hs).is_empty(), "gap == 13cy floor must not fire: {:?}", flag_findings(&hs));
}

// C) all-white: the auto scheduler's flag stall (S14) covers the floor; no FP.
#[test]
fn t_c_all_white_no_fp() {
    let hs = hazards(
        "    ISETP.GT.AND P0, PT, R10, 0x5, PT ;\n    @P0 IADD3 R11, PT, PT, R12, 0x1, RZ ;\n    @P0 IADD3 R13, PT, PT, R14, 0x1, RZ ;\n",
    );
    assert!(flag_findings(&hs).is_empty(), "autosched-covered flags must be silent: {:?}", flag_findings(&hs));
}

// D) P0 produced by an unmeasured class (IADD3 carry-out): no floor data ->
// producer is unknown -> silent (doctrine: no invented floors).
#[test]
fn t_d_unmeasured_producer_silent() {
    let hs = hazards(
        "    [B------:R-:W-:-:S02] IADD3 R5, P0, PT, R1, R1, RZ ;\n    @P0 IADD3 R6, PT, PT, R7, 0x1, RZ ;\n",
    );
    assert!(flag_findings(&hs).is_empty(), "carry-out producer has no calibrated floor: {:?}", flag_findings(&hs));
}

// E) consumer reads the flag as a predicate OPERAND (not a guard): covered.
#[test]
fn t_e_predicate_operand_consumer() {
    let hs = hazards(
        "    [B------:R-:W-:-:S02] PLOP3.LUT P1, PT, P2, P3, PT, 0x80 ;\n    SEL R20, R21, R22, P1 ;\n",
    );
    let f = flag_findings(&hs);
    assert!(f.iter().any(|m| m.contains("reads P1 <-") && m.contains("PLOP3")), "operand-form consumer must be flagged: {:?}", f);
}
