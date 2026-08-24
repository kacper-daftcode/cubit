//! M6.1: RA pass predicate-domain tests (pred-liveness-RA, first slice).
//! Identity + remap mechanics for P/UP: plan covers Pred/UPred operands AND
//! the guard, PT/UPT (7) is a constant-true sink that never maps, unknown
//! predicate families fail closed, and the windowed (pin) recorder refuses
//! out-of-scope predicate moves (M6.2 territory). Corpus byte-exactness is
//! the BARRACUDA gate G18a (results/fe/M6).

use cubit::ir::Operand;
use cubit::parser::parse_sass;
use cubit::pred_liveness::{pred_xfer, PredXfer, XferMode};
use cubit::ra::{
    apply_plan, apply_plan_windowed, plan_for_mode, run_file, validate_coverage, RaMode,
};
use cubit::reg_liveness::{reg_xfer, RegXfer};
use std::collections::BTreeSet;

fn ksrc(body: &str) -> String {
    format!(".entry k\n{body}    EXIT ;\n")
}

fn engines(insns: &[cubit::Instruction]) -> (Vec<RegXfer>, Vec<PredXfer>) {
    (
        insns.iter().map(reg_xfer).collect(),
        insns.iter().map(|i| pred_xfer(i, XferMode::Strict)).collect(),
    )
}

// ------------------------------------------------- remap: operands + guard

#[test]
fn t61_1_remap_pred_operands_and_guard_neg_preserved() {
    // P0 -> P3: the carry-out def, the guard read and the ISETP source all
    // move; PT sink and the NEG bit never move.
    let mut insns: Vec<_> = [
        "    IADD3 R4, P0, PT, R4, R5, RZ ;",
        "    @P0 ISETP.GT.AND P0, PT, R4, R5, P4 ;",
    ]
    .iter()
    .map(|s| parse_sass(s, 0).unwrap())
    .collect();
    let (xf, pxf) = engines(&insns);
    let mut plan = plan_for_mode(&RaMode::Identity, "k", &xf, &pxf).unwrap();
    plan.p.insert(0, 3);
    let changed = apply_plan(&mut insns, &plan).unwrap();
    assert_eq!(changed, 3, "carry-out def + guard use + ISETP def move; ISETP source P4 stays");
    // def arm of IADD3
    assert!(matches!(insns[0].operands[1], Operand::Pred { num: 3, .. }));
    // guard moved, carries neg=false
    let g = insns[1].guard.as_ref().unwrap();
    assert_eq!((g.pred, g.negated, g.uniform), (3, false, false));
    // ISETP def moved
    assert!(matches!(insns[1].operands[0], Operand::Pred { num: 3, .. }));
}

#[test]
fn t61_2_guard_negation_and_pt_sink_untouched() {
    let mut insns: Vec<_> = [
        "    @!P5 ISETP.GT.AND P0, PT, R4, R5, P4 ;",
    ]
    .iter()
    .map(|s| parse_sass(s, 0).unwrap())
    .collect();
    let (xf, pxf) = engines(&insns);
    let mut plan = plan_for_mode(&RaMode::Identity, "k", &xf, &pxf).unwrap();
    plan.p.insert(5, 1);
    plan.p.insert(0, 6);
    let changed = apply_plan(&mut insns, &plan).unwrap();
    assert_eq!(changed, 2, "guard @!P5->@!P1 and ISETP def P0->P6; PT sinks stay");
    let g = insns[0].guard.as_ref().unwrap();
    assert_eq!((g.pred, g.negated), (1, true), "neg bit must survive the remap");
    assert!(matches!(insns[0].operands[0], Operand::Pred { num: 6, .. }));
    // PT at operand 1 stays the sink (never a plan key)
    assert!(matches!(insns[0].operands[1], Operand::Pred { num: 7, .. }));
}

#[test]
fn t61_3_uniform_predicates_and_upt_sink() {
    let mut insns: Vec<_> = [
        "    UISETP.?GT.?S32.?OR UP0, UPT, UR63, UR15, UPT ;",
        "    @UP2 UIADD3 UR1, UPT, UR3, UR4, URZ ;",
    ]
    .iter()
    .map(|s| parse_sass(s, 0).unwrap())
    .collect();
    let (xf, pxf) = engines(&insns);
    let mut plan = plan_for_mode(&RaMode::Identity, "k", &xf, &pxf).unwrap();
    plan.up.insert(0, 3);
    plan.up.insert(2, 4);
    let changed = apply_plan(&mut insns, &plan).unwrap();
    assert_eq!(changed, 2, "UISETP def UP0->UP3 and guard UP2->UP4; UPT sinks stay");
    assert!(matches!(insns[0].operands[0], Operand::UPred { num: 3, .. }));
    assert!(matches!(insns[0].operands[4], Operand::UPred { num: 7, .. }));
    let g = insns[1].guard.as_ref().unwrap();
    assert_eq!((g.pred, g.uniform), (4, true));
}

// ------------------------------------------------------- fail-closed rules

#[test]
fn t61_4_plan_gap_fail_closed() {
    let mut insns: Vec<_> = ["    ISETP.GT.AND P0, PT, R4, R5, P4 ;"]
        .iter()
        .map(|s| parse_sass(s, 0).unwrap())
        .collect();
    let (xf, pxf) = engines(&insns);
    let mut plan = plan_for_mode(&RaMode::Identity, "k", &xf, &pxf).unwrap();
    plan.p.remove(&4);
    let err = apply_plan(&mut insns, &plan).unwrap_err();
    assert!(
        format!("{err:#}").contains("plan misses P4"),
        "gap must fail closed: {err:#}"
    );
}

#[test]
fn t61_5_pt_as_plan_key_or_value_is_rejected() {
    let insns: Vec<_> = ["    ISETP.GT.AND P0, PT, R4, R5, P4 ;"]
        .iter()
        .map(|s| parse_sass(s, 0).unwrap())
        .collect();
    let (xf, pxf) = engines(&insns);
    let mut plan = plan_for_mode(&RaMode::Identity, "k", &xf, &pxf).unwrap();
    validate_coverage(&plan, &xf, &pxf).unwrap();
    plan.p.insert(4, 7);
    let err = validate_coverage(&plan, &xf, &pxf).unwrap_err();
    assert!(format!("{err:#}").contains("PT/UPT"), "value-7: {err:#}");
    let mut plan = plan_for_mode(&RaMode::Identity, "k", &xf, &pxf).unwrap();
    plan.p.insert(7, 4);
    let err = validate_coverage(&plan, &xf, &pxf).unwrap_err();
    assert!(format!("{err:#}").contains("PT/UPT"), "key-7: {err:#}");
}

#[test]
fn t61_6_unknown_predicate_family_fails_closed() {
    // SEL carries a selector predicate but is outside the pred_liveness
    // families -- the RA pass must refuse the run, not pass it through.
    let src = ksrc("    SEL R0, R1, R2, P3 ;\n");
    let err = run_file(&src, RaMode::Identity).unwrap_err();
    assert!(
        format!("{err:#}").contains("unknown predicate-role"),
        "SEL-with-pred must fail closed: {err:#}"
    );
}

#[test]
fn t61_7_windowed_recorder_records_predicate_moves() {
    // M6.1 shipped this pin as "windowed pred move = fail loud" because no
    // splice record existed for the predicate domains. M6.2 superseded it:
    // the recorder now CARRIES P/UP changes (ChangeDom::P) for the splice
    // emitter, and the refusal doctrine migrated to validate_pin
    // (boundary / injectivity / sink rules -- pinned in tests/ra_m62.rs).
    // This test pins the raw recorder semantics reachable by hand-built
    // plans below the validator layer.
    let mut insns: Vec<_> = ["    ISETP.GT.AND P0, PT, R4, R5, P4 ;"]
        .iter()
        .map(|s| parse_sass(s, 0).unwrap())
        .collect();
    let (xf, pxf) = engines(&insns);
    let mut plan = plan_for_mode(&RaMode::Identity, "k", &xf, &pxf).unwrap();
    plan.p.insert(0, 3);
    let window: BTreeSet<usize> = [0].into_iter().collect();
    let (changed, edits) = apply_plan_windowed(&mut insns, &plan, &window).unwrap();
    assert_eq!(changed, 1);
    assert_eq!(edits.len(), 1);
    assert_eq!(
        (edits[0].dom, edits[0].from, edits[0].to),
        (cubit::ra::ChangeDom::P, 0, 3),
        "predicate move recorded for the splice emitter: {:?}",
        edits
    );
}

// ------------------------------------------------------ identity end-to-end

#[test]
fn t61_8_identity_report_carries_pred_census() {
    let src = ksrc(
        "    IADD3 R4, P0, PT, R4, R5, RZ ;\n    @!P5 ISETP.GT.AND P0, PT, R4, R5, P4 ;\n    UISETP.?GT.?S32.?OR UP0, UPT, UR63, UR15, UPT ;\n    @UP2 UIADD3 UR1, UPT, UR3, UR4, URZ ;\n",
    );
    let run = run_file(&src, RaMode::Identity).unwrap();
    assert_eq!(run.out_text, src, "identity emission stays byte-verbatim");
    let k = &run.report.kernels[0];
    assert_eq!(k.changed, 0);
    assert!(k.unknown_ops.is_empty());
    assert_eq!(k.p_used, vec![0, 4, 5], "P defs/uses incl. guard");
    assert_eq!(k.up_used, vec![0, 2], "UP defs/uses incl. uniform guard");
}
