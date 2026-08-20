//! M4.2: RA pass pin-override (windowed splice) unit tests.
//! The engine contract is validate_pin + splice re-parse proof (G11d-class
//! fail-closed); corpus byte-attribution is the BARRACUDA gate G11c
//! (results/fe/M4).

use cubit::ra::{parse_mode, parse_mode_kind, run_file, PinPlan, RaMode};

fn pin(json: &str) -> RaMode {
    RaMode::Pin(serde_json::from_str::<PinPlan>(json).expect("plan JSON"))
}

fn run_pin(text: &str, json: &str) -> anyhow::Result<cubit::ra::RaRun> {
    run_file(text, pin(json))
}

/// Positive kernel: R3/R11 swap fully inside window [3,6).
const K_SWAP: &str = "\
.entry k
    .reg R0-R47
    S2R R0, SR_TID.X ;
    IMAD R1, R0, 0x4, RZ ;
    IMAD R2, R0, 0x8, RZ ;
L_9:  [B------:R-:W-:Y:S01] IMAD R3, R1, R2, RZ ;
    IMAD R11, R1, R2, RZ ;
    IMAD R4, R3, R11, RZ ;
    EXIT ;
";

#[test]
fn t_pin_swap_two_way() {
    let j = r#"{"kernels":{"k":{"windows":[[3,6]],"r":{"3":11,"11":3}}}}"#;
    let run = run_pin(K_SWAP, j).expect("swap must validate + apply");
    assert_eq!(run.report.mode, "pin");
    let k = &run.report.kernels[0];
    // defs insn3/insn4 + two uses at insn5 = 4 numerals
    assert_eq!(k.changed, 4);
    let want = "\
.entry k
    .reg R0-R47
    S2R R0, SR_TID.X ;
    IMAD R1, R0, 0x4, RZ ;
    IMAD R2, R0, 0x8, RZ ;
L_9:  [B------:R-:W-:Y:S01] IMAD R11, R1, R2, RZ ;
    IMAD R3, R1, R2, RZ ;
    IMAD R4, R11, R3, RZ ;
    EXIT ;
";
    assert_eq!(run.out_text, want, "splice emission must be exact");
}

#[test]
fn t_pin_one_way_to_dead_reg_and_label_prefix_kept() {
    let j = r#"{"kernels":{"k":{"windows":[[3,6]],"r":{"3":9}}}}"#;
    let run = run_pin(K_SWAP, j).expect("one-way pin");
    assert_eq!(run.report.kernels[0].changed, 2); // def@3 + use@5
    assert!(run.out_text.contains("L_9:  [B------:R-:W-:Y:S01] IMAD R9, R1, R2, RZ ;"));
    assert!(run.out_text.contains("    IMAD R4, R9, R11, RZ ;"));
    // lines outside the window stay byte-verbatim
    let before: Vec<&str> = K_SWAP.lines().take(3).collect();
    let after: Vec<&str> = run.out_text.lines().take(3).collect();
    assert_eq!(before, after);
}

#[test]
fn t_pin_boundary_live_out_rejected() {
    // STG at insn 6 (outside window [3,6)) reads R3 -> R3 is live-out at
    // the window exit edge.
    let text = "\
.entry k
    .reg R0-R47
    S2R R0, SR_TID.X ;
    IMAD R1, R0, 0x4, RZ ;
    IMAD R2, R0, 0x8, RZ ;
    IMAD R3, R1, R2, RZ ;
    IMAD R11, R1, R2, RZ ;
    IMAD R4, R3, R11, RZ ;
    STG.E desc[UR4][R8.64], R3 ;
    EXIT ;
";
    let j = r#"{"kernels":{"k":{"windows":[[3,6]],"r":{"3":9}}}}"#;
    let e = run_pin(text, j).unwrap_err();
    assert!(format!("{e:#}").contains("live-out"), "unexpected: {e:#}");
}

#[test]
fn t_pin_boundary_live_in_rejected() {
    // R10 defined at insn 2 and used inside window [3,5) -> live-in.
    let text = "\
.entry k
    .reg R0-R47
    S2R R0, SR_TID.X ;
    IMAD R1, R0, 0x4, RZ ;
    IMAD R10, R0, 0x8, RZ ;
    IMAD R3, R1, R10, RZ ;
    IMAD R4, R3, R3, RZ ;
    EXIT ;
";
    let j = r#"{"kernels":{"k":{"windows":[[3,5]],"r":{"3":10,"10":3}}}}"#;
    let e = run_pin(text, j).unwrap_err();
    assert!(format!("{e:#}").contains("live-in"), "unexpected: {e:#}");
}

#[test]
fn t_pin_collision_rejected() {
    // R4 is defined at insn 4 inside the window; pinning R3->R4 collides.
    let j = r#"{"kernels":{"k":{"windows":[[3,6]],"r":{"3":4}}}}"#;
    let e = run_pin(K_SWAP, j).unwrap_err();
    assert!(format!("{e:#}").contains("collision"), "unexpected: {e:#}");
}

#[test]
fn t_pin_span_tearing_rejected() {
    let text = "\
.entry k
    .reg R0-R255
    S2R R0, SR_TID.X ;
    MOV R30, 0x1 ;
    MOV R31, 0x2 ;
    IMAD.WIDE.U32 R20, R30, R31, RZ ;
    IMAD R5, R20, R21, RZ ;
    EXIT ;
";
    // moving the WIDE base tears the pair {R20,R21}
    let j = r#"{"kernels":{"k":{"windows":[[3,5]],"r":{"20":40}}}}"#;
    let e = run_pin(text, j).unwrap_err();
    assert!(format!("{e:#}").contains("span"), "unexpected: {e:#}");
    // moving the non-base member tears it too
    let j2 = r#"{"kernels":{"k":{"windows":[[3,5]],"r":{"21":41}}}}"#;
    let e2 = run_pin(text, j2).unwrap_err();
    assert!(format!("{e2:#}").contains("span"), "unexpected: {e2:#}");
}

#[test]
fn t_pin_ur_positive_and_desc_ns_rejected() {
    let text = "\
.entry k
    .reg R0-R47
    S2R R0, SR_TID.X ;
    LDCU UR6, c[0x0][0x358] ;
    UMOV UR7, 0x1 ;
    UIADD3 UR8, UR6, 0x1, UR7 ;
    MOV R5, UR8 ;
    EXIT ;
";
    let j = r#"{"kernels":{"k":{"windows":[[3,5]],"ur":{"8":20}}}}"#;
    let run = run_pin(text, j).expect("UR pin");
    assert_eq!(run.report.kernels[0].changed, 2);
    assert!(run.out_text.contains("UIADD3 UR20, UR6, 0x1, UR7 ;"));
    assert!(run.out_text.contains("MOV R5, UR20 ;"));
    // desc[URx>=64] is a separate namespace: pinning it is out of scope
    let j2 = r#"{"kernels":{"k":{"windows":[[3,5]],"ur":{"212":60}}}}"#;
    let e = run_pin(text, j2).unwrap_err();
    assert!(format!("{e:#}").contains("desc-namespace"), "unexpected: {e:#}");
    let j3 = r#"{"kernels":{"k":{"windows":[[3,5]],"ur":{"6":212}}}}"#;
    let e3 = run_pin(text, j3).unwrap_err();
    assert!(format!("{e3:#}").contains("desc-namespace"), "unexpected: {e3:#}");
}

#[test]
fn t_pin_plan_rejections() {
    // no-op pin
    let e = run_pin(K_SWAP, r#"{"kernels":{"k":{"windows":[[3,6]],"r":{"3":3}}}}"#).unwrap_err();
    assert!(format!("{e:#}").contains("no-op"));
    // RZ not allocatable
    let e = run_pin(K_SWAP, r#"{"kernels":{"k":{"windows":[[3,6]],"r":{"3":255}}}}"#).unwrap_err();
    assert!(format!("{e:#}").contains("RZ"));
    // source never occurs
    let e = run_pin(K_SWAP, r#"{"kernels":{"k":{"windows":[[3,6]],"r":{"47":9}}}}"#).unwrap_err();
    assert!(format!("{e:#}").contains("never occurs"));
    // unknown kernel name
    let e = run_pin(K_SWAP, r#"{"kernels":{"zzz":{"windows":[[3,6]],"r":{"3":9}}}}"#).unwrap_err();
    assert!(format!("{e:#}").contains("unknown kernel"));
    // no windows
    let e = run_pin(K_SWAP, r#"{"kernels":{"k":{"r":{"3":9}}}}"#).unwrap_err();
    assert!(format!("{e:#}").contains("no windows"));
    // overlapping windows
    let e = run_pin(K_SWAP, r#"{"kernels":{"k":{"windows":[[3,5],[4,6]],"r":{"3":9}}}}"#).unwrap_err();
    assert!(format!("{e:#}").contains("overlapping"));
    // window out of range
    let e = run_pin(K_SWAP, r#"{"kernels":{"k":{"windows":[[3,99]],"r":{"3":9}}}}"#).unwrap_err();
    assert!(format!("{e:#}").contains("past kernel end"));
    // mode spellings
    assert!(parse_mode("pin").is_err(), "bare parse_mode('pin') must fail (plan-less)");
    assert_eq!(parse_mode_kind("pin").unwrap(), "pin");
    assert!(parse_mode_kind("pins").is_err());
}

#[test]
fn t_pin_emitter_exact_text_forms() {
    // guards, abs-bars, negation, desc + R-base, rsd annotations must all
    // survive the splice byte-exact outside the planned numerals.
    let text = "\
.entry k
    .reg R0-R255
    S2R R0, SR_TID.X ;
    IMAD R1, R0, 0x4, RZ ;
    IMAD R2, R0, 0x8, RZ ;
    @P0 IMAD R3, R1, R2, RZ ;
    IMAD.SHL.U32 R12, |R3|, 0x20, RZ ;
    IADD3 R13, -R3, R0, RZ ;
    STG.E desc[UR4][R8.64], R13 ;
    EXIT ;
";
    let j = r#"{"kernels":{"k":{"windows":[[3,6]],"r":{"3":9}}}}"#;
    let run = run_pin(text, j).expect("emitter forms");
    assert!(run.out_text.contains("@P0 IMAD R9, R1, R2, RZ ;"));
    assert!(run.out_text.contains("IMAD.SHL.U32 R12, |R9|, 0x20, RZ ;"));
    assert!(run.out_text.contains("IADD3 R13, -R9, R0, RZ ;"));
    // line 6 (outside window) verbatim, incl. R13 untouched:
    assert!(run.out_text.contains("STG.E desc[UR4][R8.64], R13 ;"));
    let want = "\
.entry k
    .reg R0-R255
    S2R R0, SR_TID.X ;
    IMAD R1, R0, 0x4, RZ ;
    IMAD R2, R0, 0x8, RZ ;
    @P0 IMAD R9, R1, R2, RZ ;
    IMAD.SHL.U32 R12, |R9|, 0x20, RZ ;
    IADD3 R13, -R9, R0, RZ ;
    STG.E desc[UR4][R8.64], R13 ;
    EXIT ;
";
    assert_eq!(run.out_text, want);
}

#[test]
fn t_pin_multi_kernel_isolation() {
    let text = "\
.entry k1
    S2R R0, SR_TID.X ;
    IMAD R1, R0, 0x4, RZ ;
    IMAD R2, R0, 0x8, RZ ;
    IMAD R3, R1, R2, RZ ;
    IMAD R4, R3, R3, RZ ;
    EXIT ;
.entry k2
    S2R R0, SR_TID.X ;
    IMAD R1, R0, 0x4, RZ ;
    IMAD R2, R0, 0x8, RZ ;
    IMAD R3, R1, R2, RZ ;
    IMAD R4, R3, R3, RZ ;
    EXIT ;
";
    let j = r#"{"kernels":{"k1":{"windows":[[3,5]],"r":{"3":9}}}}"#;
    let run = run_pin(text, j).expect("k1-only splice");
    let k2_part = run.out_text.split(".entry k2").nth(1).unwrap();
    assert!(k2_part.contains("IMAD R3, R1, R2, RZ ;"), "k2 must stay verbatim");
    let k1_part = run.out_text.split(".entry k2").next().unwrap();
    assert!(k1_part.contains("IMAD R9, R1, R2, RZ ;"));
}
