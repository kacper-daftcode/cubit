//! M6.3: full-from-zero allocation of the predicate domains (P/UP) --
//! geometry-free permutations over the 7-slot pool, PT/UPT sink fail-closed,
//! def-tuple anti-tearing via the per-instruction injectivity audit, and the
//! apply-plan p/up intake (typo trap + sink rule + tear rejection).

use cubit::ra::{run_file, ApplyPlan, RaMode};
use cubit::ra_full::alloc_pred_permutation;
use std::collections::{BTreeMap, BTreeSet};

fn ksrc(body: &str) -> String {
    format!(".entry k\n    .reg R0-R255\n{body}    EXIT ;\n.endentry\n")
}

fn run_full(text: &str) -> cubit::ra::RaRun {
    run_file(text, RaMode::Full).unwrap()
}

/// Apply-mode intake contract is the G15a one: plans carry the total r/ur
/// maps (p/up optional, identity-filled when absent). Seed plans from the
/// kernel's own full-mode export, then mutate the predicate map per case.
fn apply_mutated(text: &str, mutate: &dyn Fn(&mut serde_json::Value)) -> String {
    let run = run_file(text, RaMode::Full).unwrap();
    let k = &run.report.kernels[0];
    let mut plan = serde_json::json!({ "kernels": { "k": k.plan.as_ref().unwrap() } });
    mutate(&mut plan["kernels"]["k"]);
    serde_json::to_string(&plan).unwrap()
}

fn apply_err(text: &str, mutate: &dyn Fn(&mut serde_json::Value)) -> String {
    let plan_text = apply_mutated(text, mutate);
    let ap: ApplyPlan = serde_json::from_str(&plan_text).unwrap();
    let e = run_file(text, RaMode::ApplyFile(ap)).expect_err("plan must fail closed");
    format!("{e:#}")
}

fn apply_ok(text: &str, mutate: &dyn Fn(&mut serde_json::Value)) -> String {
    let plan_text = apply_mutated(text, mutate);
    let ap: ApplyPlan = serde_json::from_str(&plan_text).unwrap();
    run_file(text, RaMode::ApplyFile(ap)).unwrap().out_text
}

// ------------------------------------------------------- allocator arms

#[test]
fn t63_1_full_clique_rederives_identity() {
    // Seven P symbols co-live at one point: the dataflow conflict graph is
    // K7, so the lowest-free greedy in ascending order must re-derive the
    // seed identity -- the G19a mechanism, unit-pinned (no "identity by
    // default": the map is COMPUTED and audited).
    let mut defs = String::new();
    let mut uses = String::new();
    for i in 0..7 {
        defs.push_str(&format!("    ISETP.GT.AND P{i}, PT, R4, R5, PT ;\n"));
    }
    for i in 0..7 {
        uses.push_str(&format!("    @P{i} MOV R{i}, RZ ;\n"));
    }
    let run = run_full(&ksrc(&(defs + &uses)));
    let k = &run.report.kernels[0];
    let plan = k.plan.as_ref().unwrap();
    let pmap: BTreeMap<u8, u8> =
        plan.p.iter().map(|(k, v)| (k.parse().unwrap(), *v)).collect();
    assert_eq!(pmap, (0..7u8).map(|i| (i, i)).collect::<BTreeMap<_, _>>(), "clique -> identity");
    let f = k.full.as_ref().unwrap();
    assert_eq!(f.p.symbols, 7);
    assert_eq!(f.p.permuted, 0, "certified-shape clique must not permute");
    assert_eq!(f.p.conflict_edges, 21, "K7 has 21 edges");
}

#[test]
fn t63_2_lone_high_numeral_permuted_to_zero() {
    // From-zero poof: a lone P5 is re-homed to P0 (lowest free). The
    // allocator is NOT identity-by-construction; identity on the certified
    // corpus is a DATA outcome (clique), pinned by t63_1 vs this arm.
    let src = ksrc("    ISETP.GT.AND P5, PT, R4, R5, PT ;\n    @P5 MOV R0, RZ ;\n");
    let run = run_full(&src);
    assert!(run.out_text.contains("ISETP.GT.AND P0,"), "{}", run.out_text);
    assert!(run.out_text.contains("@P0 MOV"), "{}", run.out_text);
    let k = &run.report.kernels[0];
    let f = k.full.as_ref().unwrap();
    assert_eq!(f.p.symbols, 1);
    assert_eq!(f.p.permuted, 1);
}

#[test]
fn t63_3_up_domain_permuted_and_guard_follows() {
    // UP: lone UP3 re-homed to UP0; the @UP guard numeral moves with it.
    let src = ksrc("    UISETP.?GT.?S32.?OR UP3, UPT, UR63, UR15, UPT ;\n    @UP3 UIADD3 UR1, UPT, UR3, UR4, URZ ;\n");
    let run = run_full(&src);
    assert!(run.out_text.contains("UISETP.?GT.?S32.?OR UP0,"), "{}", run.out_text);
    assert!(run.out_text.contains("@UP0 UIADD3"), "{}", run.out_text);
    let f = run.report.kernels[0].full.as_ref().unwrap();
    assert_eq!(f.up.symbols, 1);
    assert_eq!(f.up.permuted, 1);
}

#[test]
fn t63_4_def_tuple_forces_distinct_homes() {
    // ISETP two-destination form with two real defs: {P0,P4} sit in one
    // instruction's co-occurrence set, so the audit/machine-checked plan
    // must keep them apart (identity here; a second co-live pair shifts).
    let src = ksrc("    ISETP.GT.AND P0, P4, R4, R5, PT ;\n    @P0 MOV R1, RZ ;\n    @P4 MOV R2, RZ ;\n");
    let run = run_full(&src);
    let plan = run.report.kernels[0].plan.as_ref().unwrap();
    let pmap: BTreeMap<u8, u8> =
        plan.p.iter().map(|(k, v)| (k.parse().unwrap(), *v)).collect();
    assert_ne!(pmap[&0], pmap[&4], "def-tuple members must keep distinct homes");
    let f = run.report.kernels[0].full.as_ref().unwrap();
    assert_eq!(f.p.conflict_edges, 1, "tuple edge 0-4");
}

// ------------------------------------------------------- apply plan intake

#[test]
fn t63_5_apply_def_tuple_tear_rejected() {
    // Manual plan tearing an ISETP def-tuple onto one home: the predicate
    // injectivity audit must reject before any numeral moves.
    let src = ksrc("    ISETP.GT.AND P0, P4, R4, R5, PT ;\n    @P0 MOV R1, RZ ;\n    @P4 MOV R2, RZ ;\n");
    let msg = apply_err(&src, &|kp| {
        kp["p"] = serde_json::json!({ "0": 2, "4": 2 });
    });
    assert!(msg.contains("predicate renaming collision"), "msg: {msg}");
}

#[test]
fn t63_6_apply_sink_and_typo_rejected() {
    let src = ksrc("    ISETP.GT.AND P3, PT, R4, R5, PT ;\n    @P3 MOV R0, RZ ;\n");
    // PT as a KEY
    let m1 = apply_err(&src, &|kp| {
        kp["p"] = serde_json::json!({ "3": 0, "7": 0 });
    });
    assert!(m1.contains("sink"), "{m1}");
    // PT as a VALUE
    let m2 = apply_err(&src, &|kp| {
        kp["p"] = serde_json::json!({ "3": 7 });
    });
    assert!(m2.contains("sink"), "{m2}");
    // typo trap: P6 never occurs
    let m3 = apply_err(&src, &|kp| {
        kp["p"] = serde_json::json!({ "3": 3, "6": 1 });
    });
    assert!(m3.contains("typo trap"), "{m3}");
    // prefixed spelling accepted: "P3" -> 5 (legal: 5 free, no conflicts)
    let out = apply_ok(&src, &|kp| {
        kp["p"] = serde_json::json!({ "P3": 5 });
    });
    assert!(out.contains("ISETP.GT.AND P5,"), "{out}");
    assert!(out.contains("@P5 MOV"), "{out}");
}

#[test]
fn t63_7_engine_sink_breach_fail_closed() {
    // Engine-level defense pin: the allocator refuses a symbol at/above the
    // sink index (not reachable from well-formed text -- the STRICT
    // transfers drop PT/UPT at source -- kept pinned for plan sources).
    let symbols: BTreeSet<u8> = [7].into_iter().collect();
    let conf: BTreeMap<u8, BTreeSet<u8>> = [(7u8, BTreeSet::new())].into_iter().collect();
    let e = alloc_pred_permutation("P", &symbols, &conf, &BTreeSet::new())
        .expect_err("sink symbol must fail closed");
    assert!(format!("{e:#}").contains("sink"), "{}", format!("{e:#}"));
    // ... and a genuine coloring still goes through the engine: two
    // conflicting symbols get distinct lowest-free homes.
    let symbols: BTreeSet<u8> = [3, 5].into_iter().collect();
    let conf: BTreeMap<u8, BTreeSet<u8>> = [
        (3u8, [5u8].into_iter().collect()),
        (5u8, [3u8].into_iter().collect()),
    ]
    .into_iter()
    .collect();
    let (m, st) = alloc_pred_permutation("P", &symbols, &conf, &BTreeSet::new()).unwrap();
    assert_eq!(m[&3], 0);
    assert_eq!(m[&5], 1, "3 blocks home 0 for 5");
    assert_eq!(st.permuted, 2);
}

#[test]
fn t63_8_full_on_pred_free_kernel_unchanged() {
    // Pred-free kernels carry empty p/up plans (allocator trivial); the
    // R/UR behavior is untouched.
    let src = ksrc("    MOV R7, 0x1 ;\n    IADD3 R9, R7, 0x2, RZ ;\n");
    let run = run_full(&src);
    let f = run.report.kernels[0].full.as_ref().unwrap();
    assert_eq!(f.p.symbols, 0);
    assert_eq!(f.up.symbols, 0);
    assert!(run.report.kernels[0].plan.as_ref().unwrap().p.is_empty());
}
