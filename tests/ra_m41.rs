//! M4.1: RA pass unit tests (identity mode). Corpus byte-exactness is the
//! BARRACUDA gate G11a (results/fe/M4); here: plan semantics, rewriter
//! correctness, and the fail-closed span/coverage/unknown doctrine (G11d).

use cubit::ir::Operand;
use cubit::parser::parse_sass;
use cubit::pred_liveness::{pred_xfer, PredXfer, XferMode};
use cubit::ra::{apply_plan, parse_mode, plan_for_mode, run_file, RaMode, RegPlan};
use cubit::reg_liveness::reg_xfer;

fn ksrc(body: &str) -> String {
    format!(".entry k\n{body}    EXIT ;\n")
}

fn pxfers_of(insns: &[cubit::Instruction]) -> Vec<PredXfer> {
    insns.iter().map(|i| pred_xfer(i, XferMode::Strict)).collect()
}

fn run(text: &str) -> cubit::ra::RaRunReport {
    run_file(text, RaMode::Identity).unwrap().report
}

// ---------------------------------------------------------------- mode parse

#[test]
fn t_mode_parse() {
    assert!(matches!(parse_mode("identity").unwrap(), RaMode::Identity));
    for bad in ["pins", "linear", "", "Identity"] {
        assert!(parse_mode(bad).is_err(), "mode {bad:?} must fail closed");
    }
}

// ------------------------------------------------------- identity plan/apply

#[test]
fn t_identity_covers_span_expanded_sets() {
    // WIDE def pair + quad load: plan keys must carry the SPAN members too
    // (R91, R4..R7), not just the printed bases.
    let src = ksrc(
        "    S2R R0, SR_TID.X ;\n    IMAD.WIDE.U32 R90, R60, R61, RZ ;\n    LDG.E.LTC128B.128 R4, desc[UR38][R210.64] ;\n",
    );
    let rep = run(&src);
    assert_eq!(rep.kernels.len(), 1);
    let k = &rep.kernels[0];
    assert!(k.unknown_ops.is_empty());
    assert_eq!(k.changed, 0);
    for r in [0, 60, 61, 90, 91, 4, 5, 6, 7, 210] {
        assert!(k.r_used.contains(&r), "R{r} missing from plan coverage");
    }
    assert!(k.ur_used == vec![38]);
    assert_eq!(k.r_max, Some(210));
}

#[test]
fn t_identity_rewriter_reports_zero_changes() {
    // apply_plan on the identity plan must prove a true no-op: every
    // operand occurrence is visited and none is altered.
    let mut insns: Vec<_> = [
        "S2R R0, SR_TID.X ;",
        "IMAD.WIDE.U32 R90, R60, R61, R90 ;",
        "STG.E.64 desc[UR4][R2.64], R90 ;",
    ]
    .iter()
    .map(|s| parse_sass(s, 0).unwrap())
    .collect();
    let xfers: Vec<_> = insns.iter().map(reg_xfer).collect();
    let plan = plan_for_mode(&RaMode::Identity, "k", &xfers, &pxfers_of(&insns)).unwrap();
    let changed = apply_plan(&mut insns, &plan).unwrap();
    assert_eq!(changed, 0);
}

#[test]
fn t_apply_remaps_all_operand_shapes() {
    // Non-identity mechanics (the M4.2 machinery): plan moves R4->R8 and
    // UR38->UR40; every operand SHAPE carrying those numerals must follow
    // (plain regs, desc UR idx, desc/addr bases).
    let mut insns: Vec<_> = [
        "IADD3 R4, P0, PT, R4, R5, RZ ;",
        "LDG.E.128 R12, desc[UR38][R4.64] ;",
        "LDS R4, [R4.X4] ;",
    ]
    .iter()
    .map(|s| parse_sass(s, 0).unwrap())
    .collect();
    let xfers: Vec<_> = insns.iter().map(reg_xfer).collect();
    let mut plan = plan_for_mode(&RaMode::Identity, "k", &xfers, &pxfers_of(&insns)).unwrap();
    // keep every other mapping identity, retarget the two registers
    plan.r.insert(4, 8);
    plan.r.insert(8, 8); // collision-free bookkeeping is the M4.2 allocator's job
    plan.ur.insert(38, 40);
    plan.ur.insert(40, 40);
    let changed = apply_plan(&mut insns, &plan).unwrap();
    assert!(
        changed >= 4,
        "expected >=4 changed numerals (IADD3 def+use, desc UR, desc base, LDS pair), got {changed}"
    );
    let get_reg = |o: &Operand| -> Option<u8> {
        if let Operand::Reg { num, .. } = o {
            Some(*num)
        } else {
            None
        }
    };
    assert_eq!(get_reg(&insns[0].operands[0]), Some(8));
    assert_eq!(get_reg(&insns[0].operands[3]), Some(8));
    match &insns[1].operands[1] {
        Operand::Desc {
            ur_idx, base_reg, ..
        } => {
            assert_eq!(*ur_idx, 40);
            assert_eq!(*base_reg, Some(8));
        }
        other => panic!("expected desc operand, got {other:?}"),
    }
}

#[test]
fn t_apply_missing_mapping_fails_closed() {
    let mut insns = vec![parse_sass("IADD3 R4, P0, PT, R5, R6, RZ ;", 0).unwrap()];
    let plan = RegPlan::default(); // empty plan: everything unmapped
    assert!(apply_plan(&mut insns, &plan).is_err());
}

// -------------------------------------------------- span notes (advisory)

#[test]
fn t_span_odd_wide_pair_noted_not_rejected() {
    // M4.1 corpus finding (certified R0b): odd UR WIDE dest bases HAPPEN
    // on silicon (UR13). Alignment is an advisory tripwire, not an error.
    let src = ksrc("    IMAD.WIDE.U32 R91, R60, R61, RZ ;\n");
    let rep = run(&src);
    let k = &rep.kernels[0];
    assert!(k.span_notes_total >= 1, "odd WIDE base must surface a note");
    assert!(k.span_notes.iter().any(|n| n.contains("R91")), "{:?}", k.span_notes);
}

#[test]
fn t_span_unusual_quad_base_noted() {
    let src = ksrc("    LDG.E.LTC128B.128 R5, desc[UR38][R210.64] ;\n");
    let rep = run(&src);
    assert!(
        rep.kernels[0].span_notes.iter().any(|n| n.contains("R5 ")),
        "{:?}",
        rep.kernels[0].span_notes
    );
}

#[test]
fn t_span_domain_crossing_noted() {
    // R254 width 2 -> top 256 > 255 (RZ end of the R domain): noted;
    // silicon-alone adjudicates legality (encoder accepts it).
    let src = ksrc("    IMAD.WIDE.U32 R254, R60, R61, RZ ;\n");
    let rep = run(&src);
    assert!(
        rep.kernels[0]
            .span_notes
            .iter()
            .any(|n| n.contains("crosses domain end")),
        "{:?}",
        rep.kernels[0].span_notes
    );
}

#[test]
fn t_desc_high_ur_index_silent() {
    // desc[UR220]: descriptor namespace (not architectural UR) -- no note.
    let src = ksrc("    LDG.E.LTC128B.128 R0, desc[UR220][R218.64+0x10] ;\n");
    let rep = run(&src);
    assert_eq!(
        rep.kernels[0].span_notes_total, 0,
        "desc-namespace indices must not trip span notes: {:?}",
        rep.kernels[0].span_notes
    );
}

#[test]
fn t_aligned_spans_no_notes() {
    let src = ksrc(
        "    IMAD.WIDE.U32 R90, R60, R61, RZ ;\n    LDG.E.LTC128B.128 R4, desc[UR38][R210.64] ;\n    LDCU.64 UR6, c[0x0][0x100] ;\n    LDG.E.256 R200, R204, desc[UR38][R210.64] ;\n",
    );
    let rep = run(&src);
    assert_eq!(rep.kernels[0].span_notes_total, 0, "{:?}", rep.kernels[0].span_notes);
    assert_eq!(rep.kernels[0].unknown_ops.len(), 0);
}

// ------------------------------------------------------------ fail-closed other

#[test]
fn t_unknown_reg_op_fails_closed() {
    // Synthetic unknown family carrying registers (M3 G9d doctrine).
    let src = ksrc("    HOPZXP9 R1, R2, R3 ;\n");
    let e = run_file(&src, RaMode::Identity).unwrap_err();
    assert!(
        format!("{e:#}").contains("unknown register-role"),
        "error must surface unknown-family doctrine: {e:#}"
    );
}

#[test]
fn t_rz_and_urz_sinks_untracked() {
    // RZ destinations / URZ literals are architectural sinks: no plan key,
    // no remap error.
    let src = ksrc("    IADD3 RZ, P0, PT, R1, R2, RZ ;\n    UIMAD UR4, UR2, 0x1, URZ, URZ ;\n");
    let rep = run(&src);
    let k = &rep.kernels[0];
    assert!(!k.r_used.contains(&255));
    assert!(k.ur_used.contains(&4) && k.ur_used.contains(&2));
}
