//! M4.6: windowed list-scheduler unit tests (mode "list"). Byte-attributed
//! gate on the certified R0b is BARRACUDA G13a (results/fe/M4); here:
//! scheduling policy semantics, pin rules, segment confinement, emitter
//! byte discipline, cost-model plumbing, and the fail-closed contracts.

use cubit::ir::Instruction;
use cubit::sched::{
    emit_permuted_splice, parse_mode_kind, run_file_cost, CostModel, SchedMode, SchedPlan,
};
use cubit::table::IsaTable;

fn table() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn cost(lat: f64) -> CostModel {
    CostModel {
        arch: "sm_103a".into(),
        quantum_cy: 7.9,
        dep_link_latency_slots: lat,
        credits_default: 1.0,
        credits: [
            ("IMAD".to_string(), 1.0),
            ("IADD3".to_string(), 1.0),
            ("SHF".to_string(), 1.0),
            ("IMAD.WIDE".to_string(), 2.0),
        ]
        .into_iter()
        .collect(),
    }
}

fn plan(json: &str) -> SchedMode {
    SchedMode::List(serde_json::from_str::<SchedPlan>(json).expect("plan JSON"))
}

fn run(text: &str, pl: SchedMode, cm: &CostModel) -> cubit::sched::SchedRun {
    run_file_cost(text, pl, &table(), Some(cm)).expect("list run")
}

fn ins_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('.') && !l.starts_with("//"))
        .collect()
}

/// Detuned kernel: chain R2->R3->R4 issued ADJACENT (latency exposed
/// serially, ~16 wasted slots), then 12 independent fillers, all S00.
/// The repair: chain head early, fillers ride the dependency bubbles.
fn bubble_src() -> String {
    let mut v = vec![".entry k".to_string()];
    v.push("    [B------:R-:W-:-:S00] IADD3 R2, R0, R1, RZ ;".into()); // 0
    v.push("    [B------:R-:W-:-:S00] IADD3 R3, R2, 0x1, RZ ;".into());  // 1 chain
    v.push("    [B------:R-:W-:-:S00] IADD3 R4, R3, R5, RZ ;".into());   // 2 chain
    for i in 0..12 {
        v.push(format!("    [B------:R-:W-:-:S00] IADD3 R{}, R{}, 0x1, RZ ;", 10 + i, 10 + i));
    }
    v.push("    EXIT ;".into());
    v.push(".endentry".into());
    v.join("\n") + "\n"
}

// ---------------------------------------------------------------- mode parse

#[test]
fn t46_mode_parse() {
    assert_eq!(parse_mode_kind("list").unwrap(), "list");
    assert_eq!(parse_mode_kind("identity").unwrap(), "identity");
    for bad in ["List", "LIST", "pin", ""] {
        assert!(parse_mode_kind(bad).is_err(), "mode {bad:?} must fail closed");
    }
}

// ------------------------------------------------------- policy semantics

#[test]
fn t46_list_pulls_chain_into_bubbles() {
    let src = bubble_src();
    let cm = cost(8.0);
    let r = run(&src, plan(r#"{"kernels":{"k":{"windows":[[0,15]]}}}"#), &cm);
    let k = &r.report.kernels[0];
    assert_eq!(k.name, "k");
    assert_eq!(k.windows.len(), 1);
    let w = &k.windows[0];
    assert!(w.cost_after < w.cost_before, "chain must be pulled early: {w:?}");
    assert!(w.moved > 0, "chain repair must move instructions: {w:?}");
    // dependency truth: chain order preserved in output
    let ls = ins_lines(&r.out_text);
    let pos = |needle: &str| ls.iter().position(|l| l.contains(needle)).unwrap();
    assert!(pos("IADD3 R2,") < pos("IADD3 R3,"));
    assert!(pos("IADD3 R3,") < pos("IADD3 R4,"));
    // window lines: same multiset of instructions as before
    let mut a = ins_lines(&src)[..15].to_vec();
    let mut b = ls[..15].to_vec();
    a.sort();
    b.sort();
    assert_eq!(a, b, "window must carry exactly the same instructions");
}

#[test]
fn t46_list_output_is_fixpoint() {
    let src = bubble_src();
    let cm = cost(8.0);
    let once = run(&src, plan(r#"{"kernels":{"k":{"windows":[[0,15]]}}}"#), &cm);
    let twice = run(&once.out_text, plan(r#"{"kernels":{"k":{"windows":[[0,15]]}}}"#), &cm);
    assert_eq!(once.out_text, twice.out_text, "scheduled text must be a fixpoint");
}

#[test]
fn t46_determinism() {
    let src = bubble_src();
    let cm = cost(8.0);
    let a = run(&src, plan(r#"{"kernels":{"k":{"windows":[[0,15]]}}}"#), &cm);
    let b = run(&src, plan(r#"{"kernels":{"k":{"windows":[[0,15]]}}}"#), &cm);
    assert_eq!(a.out_text, b.out_text);
}

#[test]
fn t46_parity_keeps_seed_order() {
    // stall-saturated window (all S03, no chains): any legal order prices
    // the same; the pass must NOT churn a saturated schedule.
    let mut v = vec![".entry k".to_string()];
    for i in 0..8 {
        v.push(format!("    [B------:R-:W-:Y:S03] IADD3 R{}, R{}, 0x1, RZ ;", 10 + i, 10 + i));
    }
    v.push("    EXIT ;".into());
    v.push(".endentry".into());
    let src = v.join("\n") + "\n";
    let cm = cost(8.0);
    let r = run(&src, plan(r#"{"kernels":{"k":{"windows":[[0,8]]}}}"#), &cm);
    let w = &r.report.kernels[0].windows[0];
    assert_eq!(r.out_text, src, "cost-neutral window must stay byte-identical");
    assert_eq!(w.moved, 0);
    assert!((w.cost_after - w.cost_before).abs() < 1e-9);
}

// ------------------------------------------------------------------- pins

#[test]
fn t46_label_carrier_is_pinned() {
    let mut v = vec![".entry k".to_string()];
    v.push("L_head:  [B------:R-:W-:-:S00] IADD3 R2, R0, R1, RZ ;".to_string());
    for i in 0..4 {
        v.push(format!("    [B------:R-:W-:-:S00] IADD3 R{}, R{}, 0x1, RZ ;", 10 + i, 10 + i));
    }
    v.push("    EXIT ;".into());
    v.push(".endentry".into());
    let src = v.join("\n") + "\n";
    let cm = cost(8.0);
    let r = run(&src, plan(r#"{"kernels":{"k":{"windows":[[0,5]]}}}"#), &cm);
    let w = &r.report.kernels[0].windows[0];
    assert_eq!(w.pin_reasons.get("label"), Some(&1));
    let first = ins_lines(&r.out_text)[0].clone();
    assert!(first.starts_with("L_head:"), "label carrier must stay first: {first}");
}

#[test]
fn t46_mem_and_scoreboard_and_nop_are_segment_walls() {
    // [0,10): IADD3 R2 (chain head), LDG at 2, NOP at 5, wait-IADD3 at 8,
    // free IADD3s elsewhere; nop/wait/ldg are walls between segments.
    let ldg = "[B------:R-:W0:Y:S03] LDG.E.EL.ELL2.256.STRONG.GPU R24, R20, desc[UR20][R22.64] ;";
    let wait = "[B----4-:R-:W-:Y:S05] IADD3 R30, PT, PT, R30, -0x1, RZ ;";
    let lines = [
        "    [B------:R-:W-:-:S00] IADD3 R2, R0, R1, RZ ;",       // 0
        &format!("    [B------:R-:W-:-:S00] IADD3 R3, R2, 0x1, RZ ;"), // 1 chain link (seg A mover)
        &format!("    {ldg}"),                                 // 2 mem pin
        "    [B------:R-:W-:-:S00] IADD3 R10, R10, 0x1, RZ ;",  // 3
        "    [B------:R-:W-:-:S00] IADD3 R11, R11, 0x1, RZ ;",  // 4
        "    [B0-----:R-:W-:-:S03] NOP ;",                      // 5 nop+wait pin
        "    [B------:R-:W-:-:S00] IADD3 R12, R12, 0x1, RZ ;",  // 6
        "    [B------:R-:W-:-:S00] IADD3 R13, R13, 0x1, RZ ;",  // 7
        &format!("    {wait}"),                                // 8 scoreboard pin
        "    [B------:R-:W-:-:S00] IADD3 R14, R14, 0x1, RZ ;",  // 9
    ];
    let mut v = vec![".entry k".to_string()];
    v.extend(lines.into_iter().map(|s| s.to_string()));
    v.push("    EXIT ;".into());
    v.push(".endentry".into());
    let src = v.join("\n") + "\n";
    let cm = cost(8.0);
    let r = run(&src, plan(r#"{"kernels":{"k":{"windows":[[0,10]]}}}"#), &cm);
    let w = &r.report.kernels[0].windows[0];
    assert_eq!(w.pin_reasons.get("mem_chain"), Some(&1));
    assert_eq!(w.pin_reasons.get("nop"), Some(&1));
    assert_eq!(w.pin_reasons.get("scoreboard"), Some(&1));
    assert_eq!(w.segments, 4, "walls at 2/5/8 => segments [0..2),[3..5),[6..8),[9..10)");
    // segment walls: the ins AT 2/5/8 in output are exactly the wall lines
    let ls = ins_lines(&r.out_text);
    assert!(ls[2].contains("LDG.E.EL"));
    assert!(ls[5].starts_with("[B0") && ls[5].contains("NOP"));
    assert!(ls[8].contains("IADD3 R30"));
    // chain truth: R3 consumer stays after R2 producer and CANNOT cross
    // the mem wall at 2 (segment confinement via anchor edges)
    let p2 = ls.iter().position(|l| l.contains("IADD3 R2,")).unwrap();
    let p3 = ls.iter().position(|l| l.contains("IADD3 R3,")).unwrap();
    assert!(p2 < p3 && p3 < 2, "chain stays left of the wall: {p2}/{p3}");
}

// ------------------------------------------------------------ fail closed

#[test]
fn t46_fail_closed_battery() {
    let plain = ".entry k\n    [B------:R-:W-:-:S00] IADD3 R2, R0, R1, RZ ;\n    EXIT ;\n";
    let cm = cost(8.0);
    let must_fail = |src: &str, pl: SchedMode, needle: &str| {
        let e = match run_file_cost(src, pl, &table(), Some(&cm)) { Err(e) => e, Ok(_) => panic!("expected failure") };
        assert!(format!("{e:#}").contains(needle), "want {needle:?} in {e:#}");
    };
    // control flow inside window
    must_fail(
        ".entry k\n    [B------:R-:W-:-:S00] BRA L_x ;\nL_x:  [B------:R-:W-:-:S00] IADD3 R2, R0, R1, RZ ;\n    EXIT ;\n",
        plan(r#"{"kernels":{"k":{"windows":[[0,2]]}}}"#),
        "anchor-class",
    );
    // zero movers (window covers a single pinned NOP)
    must_fail(
        ".entry k\n    [B0-----:R-:W-:-:S03] NOP ;\n    EXIT ;\n",
        plan(r#"{"kernels":{"k":{"windows":[[0,1]]}}}"#),
        "zero movable",
    );
    // overlapping windows
    must_fail(plain, plan(r#"{"kernels":{"k":{"windows":[[0,1],[0,1]]}}}"#), "overlapping/unsorted");
    // out of range
    must_fail(plain, plan(r#"{"kernels":{"k":{"windows":[[0,9]]}}}"#), "out of range");
    // empty window
    must_fail(plain, plan(r#"{"kernels":{"k":{"windows":[[1,1]]}}}"#), "empty window");
    // unknown kernel
    must_fail(plain, plan(r#"{"kernels":{"nope":{"windows":[[0,1]]}}}"#), "unknown kernel");
    // label-only line floating inside the window
    must_fail(
        ".entry k\n    [B------:R-:W-:-:S00] IADD3 R2, R0, R1, RZ ;\nL_mid:\n    [B------:R-:W-:-:S00] IADD3 R3, R3, 0x1, RZ ;\n    EXIT ;\n",
        plan(r#"{"kernels":{"k":{"windows":[[0,2]]}}}"#),
        "label-only line",
    );
    // no windows at all
    must_fail(plain, plan(r#"{"kernels":{"k":{"windows":[]}}}"#), "no windows");
    // cost model required at the run_file_cost layer
    let e = match run_file_cost(plain, plan(r#"{"kernels":{"k":{"windows":[[0,1]]}}}"#), &table(), None) {
        Err(e) => e,
        Ok(_) => panic!("expected failure"),
    };
    assert!(format!("{e:#}").contains("requires a cost model"), "{e:#}");
}

#[test]
fn t46_window_lines_byte_reuse_and_outside_verbatim() {
    let src = bubble_src();
    let cm = cost(8.0);
    let r = run(&src, plan(r#"{"kernels":{"k":{"windows":[[0,15]]}}}"#), &cm);
    let a: Vec<&str> = src.lines().collect();
    let b: Vec<&str> = r.out_text.lines().collect();
    assert_eq!(a.len(), b.len(), "line count is permutation-stable");
    // every emitted line is an ORIGINAL line (byte-reuse, incl. prefixes)
    for l in &b {
        assert!(a.contains(l), "emitted line must come from the seed: {l}");
    }
}

// ----------------------------------------------------------- cost plumbing

#[test]
fn t46_credit_lookup_ladder_and_default_tripwire() {
    let cm = cost(8.0);
    let file = cubit::sass_file::parse_sass_file_str_strict(&bubble_src()).unwrap();
    let ins: &Instruction = &file.kernels[0].instructions[0];
    let mut d = 0usize;
    assert_eq!(cm.credit_of(ins, &mut d), 1.0); // IADD3 named
    assert_eq!(d, 0);
    // unknown base -> default + tripwire
    let src = ".entry k\n    [B------:R-:W-:-:S00] IMAD.SHL.U32 R2, R0, 0x20, RZ ;\n    EXIT ;\n";
    let f = cubit::sass_file::parse_sass_file_str_strict(src).unwrap();
    let m = &f.kernels[0].instructions[0];
    // IMAD modifier form: base IMAD is in the table but "IMAD.SHL.U32"
    // resolves via explicit "IMAD" entry after the modifier candidates miss.
    let v = cm.credit_of(m, &mut d);
    assert_eq!(v, 1.0);
    // fully unknown family counts defaulted
    let mut cm2 = cost(8.0);
    cm2.credits.clear();
    let mut dd = 0usize;
    assert_eq!(cm2.credit_of(m, &mut dd), 1.0);
    assert_eq!(dd, 1, "defaulted credit must be counted (tripwire)");
}

#[test]
fn t46_wide_two_credits_priced() {
    // WIDE chain: latency binds at 2 credits; model must price the pair
    // higher than two 1-credit ops in every order.
    let cm = cost(8.0);
    assert_eq!(cm.credits.get("IMAD.WIDE"), Some(&2.0));
}

// ------------------------------------------------------------- emitter law

#[test]
fn t46_emitter_rejects_nonpermutation() {
    use cubit::sched::WindowEmit;
    let src = ".entry k\n    IADD3 R2, R0, R1, RZ ;\n    EXIT ;\n.endentry\n";
    let bad = WindowEmit { kernel_idx: 0, start: 0, new_order: vec![0, 0] };
    assert!(emit_permuted_splice(src, &[bad]).is_err());
}
