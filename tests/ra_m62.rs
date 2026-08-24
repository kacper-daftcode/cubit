//! M6.2: pin-mode predicate renames (P/UP) -- the windowed splice contract
//! for the predicate domains. Mirrors the M4.2 contract shape (windows,
//! boundary-deadness, per-instruction injectivity, splice re-parse proof)
//! minus any span rule (predicates carry no geometry, design sec.3).

use cubit::ra::{run_file, PinKernelPlan, PinPlan, RaMode};
use std::collections::BTreeMap;

fn pin(kname: &str, windows: &[(u32, u32)], p: &[(u8, u8)], up: &[(u8, u8)]) -> RaMode {
    let mut kp = PinKernelPlan::default();
    kp.windows = windows.to_vec();
    kp.p = p.iter().copied().collect();
    kp.up = up.iter().copied().collect();
    let mut kernels = BTreeMap::new();
    kernels.insert(kname.to_string(), kp);
    RaMode::Pin(PinPlan { kernels })
}

// ------------------------------------------------------------- legal moves

#[test]
fn t62_1_pred_swap_roundtrip_in_window() {
    // P0 defined and guard-used inside [0,2), dead at both edges: the pin
    // rewrites exactly the two in-window numerals; inverse restores bytes.
    let src = ".entry k\n    ISETP.GT.AND P0, PT, R4, R5, PT ;\n    @P0 IADD3 R0, R1, R2, RZ ;\n    MOV R7, 0x4 ;\n    EXIT ;\n";
    let run = run_file(src, pin("k", &[(0, 2)], &[(0, 3)], &[])).unwrap();
    let out = &run.out_text;
    assert!(out.contains("ISETP.GT.AND P3,"), "{out}");
    assert!(out.contains("@P3 IADD3"), "{out}");
    assert!(out.contains("    MOV R7, 0x4 ;"), "outside window verbatim:\n{out}");
    assert_eq!(run.report.kernels[0].changed, 2);
    let back = run_file(out, pin("k", &[(0, 2)], &[(3, 0)], &[])).unwrap();
    assert_eq!(&back.out_text, src, "inverse pin must restore the text");
}

#[test]
fn t62_2_guard_negation_follows_the_pin() {
    let src = ".entry k\n    ISETP.GT.AND P0, PT, R4, R5, PT ;\n    @!P0 MOV R0, RZ ;\n    EXIT ;\n";
    let run = run_file(src, pin("k", &[(0, 2)], &[(0, 1)], &[])).unwrap();
    assert!(run.out_text.contains("@!P1 MOV"), "neg bit preserved:\n{}", run.out_text);
    assert!(!run.out_text.contains("@P1 MOV"), "neg bit not dropped:\n{}", run.out_text);
}

#[test]
fn t62_6_up_pin_and_mixed_guard_line_needle_discipline() {
    // ins1 carries BOTH a @UP2 guard token and a P2 def: the UP needle
    // must rewrite the guard without mangling it, and nothing may ever
    // match a P-needle inside the UP token.
    let src = ".entry k\n    UISETP.?GT.?S32.?OR UP2, UPT, UR63, UR15, UPT ;\n    @UP2 ISETP.GT.AND P2, PT, R4, R5, PT ;\n    EXIT ;\n";
    let run = run_file(src, pin("k", &[(0, 2)], &[(2, 5)], &[(2, 3)])).unwrap();
    let out = &run.out_text;
    assert!(out.contains("UISETP.?GT.?S32.?OR UP3,"), "{out}");
    assert!(out.contains("@UP3 ISETP.GT.AND P5,"), "{out}");
    assert_eq!(run.report.kernels[0].changed, 3,
               "UP def + guard + P def -- exactly the planned numerals");
    let back = run_file(out, pin("k", &[(0, 2)], &[(5, 2)], &[(3, 2)])).unwrap();
    assert_eq!(&back.out_text, src, "inverse restores byte-exact");
}

#[test]
fn t62_7_pt_sink_never_moves_in_a_window() {
    // PT as second ISETP def + a @PT guard inside the window: the sink is
    // not a plan key and must pass through untouched.
    let src = ".entry k\n    ISETP.GT.AND P0, PT, R4, R5, PT ;\n    @PT MOV R0, RZ ;\n    EXIT ;\n";
    let run = run_file(src, pin("k", &[(0, 2)], &[(0, 1)], &[])).unwrap();
    assert!(run.out_text.contains("PT, R4, R5, PT"), "{}", run.out_text);
    assert!(run.out_text.contains("@PT MOV"), "{}", run.out_text);
}

// ------------------------------------------------------------ fail-closed

#[test]
fn t62_3_boundary_live_in_rejected() {
    // P0 is live across the [1,2) window start: rename would desync the
    // occurrences outside the window.
    let src = ".entry k\n    ISETP.GT.AND P0, PT, R4, R5, PT ;\n    @P0 IADD3 R0, R1, R2, RZ ;\n    @P0 IADD3 R3, R1, R2, RZ ;\n    EXIT ;\n";
    let err = run_file(src, pin("k", &[(1, 2)], &[(0, 3)], &[])).unwrap_err();
    assert!(format!("{err:#}").contains("crosses window"), "{err:#}");
}

#[test]
fn t62_4_per_instruction_collision_rejected() {
    let src = ".entry k\n    ISETP.GT.AND P0, PT, R4, R5, PT ;\n    ISETP.LT.AND P2, PT, R4, R6, PT ;\n    @P0 MOV R0, RZ ;\n    EXIT ;\n";
    let err = run_file(src, pin("k", &[(0, 3)], &[(0, 2)], &[])).unwrap_err();
    assert!(format!("{err:#}").contains("collision"), "{err:#}");
}

#[test]
fn t62_5_sink_and_typo_trap_rejected() {
    let src = ".entry k\n    ISETP.GT.AND P0, PT, R4, R5, PT ;\n    @P0 IADD3 R0, R1, R2, RZ ;\n    EXIT ;\n";
    let err = run_file(src, pin("k", &[(0, 2)], &[(0, 7)], &[])).unwrap_err();
    assert!(format!("{err:#}").contains("PT/UPT"), "sink value: {err:#}");
    let err = run_file(src, pin("k", &[(0, 2)], &[(7, 1)], &[])).unwrap_err();
    assert!(format!("{err:#}").contains("PT/UPT"), "sink source: {err:#}");
    let err = run_file(src, pin("k", &[(0, 2)], &[(6, 1)], &[])).unwrap_err();
    assert!(format!("{err:#}").contains("never occurs"), "typo trap: {err:#}");
    let err = run_file(src, pin("k", &[(0, 2)], &[(0, 0)], &[])).unwrap_err();
    assert!(format!("{err:#}").contains("no-op"), "no-op: {err:#}");
}
