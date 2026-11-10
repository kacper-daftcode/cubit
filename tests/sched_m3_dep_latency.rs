//! M3 (BARRACUDA cost model v2, B300 2026-11-07): per-class dependency
//! latency in the M4.6 list scheduler. A v1 cost file (no `dep_latency_cy`)
//! keeps the legacy single-link behaviour byte for byte; a v2 file prices
//! every RAW edge by (producer class, consumer kind) from the producer's
//! START, ordering edges (WAR/WAW) carry no latency, unknown classes take
//! `dep_latency_default_cy` and are counted in `dep_class_defaulted`.

use cubit::sched::{run_file_cost, CostModel, SchedMode, SchedPlan};
use cubit::table::IsaTable;

fn table() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

const V1: &str = r#"{"arch":"sm_103a","quantum_cy":7.9,"dep_link_latency_slots":8,"credits_default":1,
  "credits":{"IADD3":1,"IMAD":1,"FFMA":0.5}}"#;

const V2: &str = r#"{"arch":"sm_103a","schema":2,"quantum_cy":2.0,"dep_link_latency_slots":2,"credits_default":1,
  "credits":{"IADD3":1,"IMAD":1,"FFMA":0.5},
  "issue_floor_cy":{"value":2.0,"provisional":true},
  "dep_latency_default_cy":{"value":4.0,"note":"INT/FP32 ALU floor"},
  "dep_latency_cy":[
    {"producer_class":"IADD3","consumer_kind":"data","L_cy":4.0,"scoreboard_only":false},
    {"producer_class":"IMAD","consumer_kind":"data","L_cy":5.0,"scoreboard_only":false},
    {"producer_class":"FFMA","consumer_kind":"data","L_cy":4.0,"scoreboard_only":false},
    {"producer_class":"ISETP","consumer_kind":"guard","L_cy":13.0,"scoreboard_only":false},
    {"producer_class":"MUFU","consumer_kind":"data","L_cy":null,"scoreboard_only":true}
  ]}"#;

fn src() -> String {
    let mut v = vec![".entry k".to_string()];
    v.push("    [B------:R-:W-:-:S00] IADD3 R2, R0, R1, RZ ;".into());
    v.push("    [B------:R-:W-:-:S00] IADD3 R3, R2, 0x1, RZ ;".into());
    v.push("    [B------:R-:W-:-:S00] IADD3 R4, R3, R5, RZ ;".into());
    for i in 0..12 {
        v.push(format!("    [B------:R-:W-:-:S00] IADD3 R{}, R{}, 0x1, RZ ;", 10 + i, 10 + i));
    }
    v.push("    EXIT ;".into());
    v.push(".endentry".into());
    v.join("\n") + "\n"
}

fn plan() -> SchedMode {
    SchedMode::List(serde_json::from_str::<SchedPlan>(r#"{"kernels":{"k":{"windows":[[0,15]]}}}"#).unwrap())
}

#[test]
fn t_m3_v1_file_is_legacy_model() {
    let cm = CostModel::from_str_json(V1).unwrap();
    assert!(!cm.has_per_class_latency());
    assert_eq!(cm.default_latency_cy(), 8.0);
    let run = run_file_cost(&src(), plan(), &table(), Some(&cm)).expect("list run");
    let k = &run.report.kernels[0];
    assert_eq!(k.dep_latency_model, "legacy");
    assert_eq!(k.dep_class_defaulted, 0);
}

#[test]
fn t_m3_v2_file_prices_per_class() {
    let cm = CostModel::from_str_json(V2).unwrap();
    assert!(cm.has_per_class_latency());
    assert_eq!(cm.default_latency_cy(), 4.0);
    let rows = cm.dep_latency_cy.as_ref().unwrap();
    assert_eq!(rows.len(), 5);
    assert!(rows[4].scoreboard_only && rows[4].l_cy.is_none());
    let run = run_file_cost(&src(), plan(), &table(), Some(&cm)).expect("list run");
    let k = &run.report.kernels[0];
    assert_eq!(k.dep_latency_model, "per_class");
    // every RAW edge of the chain is IADD3 -> data: no default needed
    assert_eq!(k.dep_class_defaulted, 0);
    let w = &k.windows[0];
    // chain of three S00 IADD3 at the head: start + 4 per link under v2
    // (legacy: end + 8); the list policy never regresses the model cost
    assert!(w.cost_after <= w.cost_before + 1e-9);
    assert!(w.cost_before > 0.0);
    // v2 prices the adjacent chain cheaper than the legacy link (4 vs 9 per hop)
    let cm1 = CostModel::from_str_json(V1).unwrap();
    let run1 = run_file_cost(&src(), plan(), &table(), Some(&cm1)).expect("list run");
    assert!(run.report.kernels[0].windows[0].cost_before < run1.report.kernels[0].windows[0].cost_before);
}

#[test]
fn t_m3_v2_unknown_class_counts_default() {
    // IMAD producer -> IADD3 consumer has a row; drop it and the edge falls to the default + tripwire
    let v2 = V2.replace(r#"{"producer_class":"IMAD","consumer_kind":"data","L_cy":5.0,"scoreboard_only":false},"#, "");
    let cm = CostModel::from_str_json(&v2).unwrap();
    let text = ".entry k\n    [B------:R-:W-:-:S00] IMAD R2, R0, R1, RZ ;\n    [B------:R-:W-:-:S00] IADD3 R3, R2, 0x1, RZ ;\n    [B------:R-:W-:-:S00] IADD3 R10, R10, 0x1, RZ ;\n    [B------:R-:W-:-:S00] IADD3 R11, R11, 0x1, RZ ;\n    EXIT ;\n.endentry\n";
    let pl = SchedMode::List(serde_json::from_str::<SchedPlan>(r#"{"kernels":{"k":{"windows":[[0,4]]}}}"#).unwrap());
    let run = run_file_cost(text, pl, &table(), Some(&cm)).expect("list run");
    let k = &run.report.kernels[0];
    assert_eq!(k.dep_latency_model, "per_class");
    assert_eq!(k.dep_class_defaulted, 1);
}

/// nvdisasm's display aliases of IMAD are members of the measured IMAD class -- B300 (sm_103a) silicon, 2026-11-09, the
/// stall-floor harness of 2026-11-07 (588 cubit-assembled kernels, consumer `IADD3 R8, PT, PT, R6, R5, RZ`, 655 360
/// thread-runs per kernel): floors d0 / d1 / d2 = 5 / 3 / 0 for every form below, as for the `IMAD` and `IMAD.WIDE.U32`
/// controls of the same run; `MOV`, `IADD3` and `LOP3.LUT` measure 4 / 0 / 0. ptxas agrees (no alias -> ALU-consumer pair
/// with a producer stall below 5 in 240 sm_103a cubins of one image and in the 328 cubins of the B300 publish corpus).
/// The table and the limits are in the review of cubit pull request 3; a separate alias class (priced with the 4-cycle
/// default) was proposed there without a measurement and is contradicted by this one. `IMAD.SHR` is not listed: no
/// witness in compiler output, no table row.
#[test]
fn t_m3_imad_display_aliases_take_the_measured_imad_class() {
    let measured = [
        "IMAD.MOV.U32 R6, RZ, RZ, R4",
        "IMAD.MOV R6, RZ, RZ, -R4",
        "IMAD.IADD R6, R4, 0x1, R5",
        "IMAD.SHL.U32 R6, R4, 0x8, RZ",
        "IMAD.HI.U32 R6, R4, R5, RZ",
        "IMAD.U32 R6, R4, 0x38, RZ",
        "IMAD.U32 R6, RZ, RZ, UR8",
        "IMAD R6, R4, R5, RZ",
    ];
    // not measured (a constant has no stale value the harness could tell apart): stays in the class, the conservative side
    let unmeasured = ["IMAD.MOV.U32 R6, RZ, RZ, 0x1"];
    for text in measured.iter().chain(unmeasured.iter()) {
        let ins = cubit::parse_sass(text, 0).unwrap();
        assert_eq!(ins.opcode, "IMAD", "{text}");
        assert_eq!(CostModel::producer_class(&ins), "IMAD", "{text}");
    }
    let wide = cubit::parse_sass("IMAD.WIDE.U32 R6, R4, R5, RZ", 0).unwrap();
    assert_eq!(CostModel::producer_class(&wide), "IMAD.WIDE");
    // the ALU controls of the same run are their own classes
    for (text, class) in [("MOV R6, R4", "MOV"), ("IADD3 R6, PT, PT, R4, R5, RZ", "IADD3"), ("LOP3.LUT R6, R4, R5, RZ, 0x3c, !PT", "LOP3")] {
        let ins = cubit::parse_sass(text, 0).unwrap();
        assert_eq!(CostModel::producer_class(&ins), class, "{text}");
    }
    // end to end: an alias -> IADD3 edge is priced by the table's IMAD row (5 cycles), not by the default (4) -- with the
    // IMAD row removed the same edge is the one defaulted edge of the kernel
    let text = ".entry k\n    [B------:R-:W-:-:S00] IMAD.MOV.U32 R2, RZ, RZ, R0 ;\n    [B------:R-:W-:-:S00] IADD3 R3, R2, 0x1, RZ ;\n    [B------:R-:W-:-:S00] IADD3 R10, R10, 0x1, RZ ;\n    [B------:R-:W-:-:S00] IADD3 R11, R11, 0x1, RZ ;\n    EXIT ;\n.endentry\n";
    let pl = || SchedMode::List(serde_json::from_str::<SchedPlan>(r#"{"kernels":{"k":{"windows":[[0,4]]}}}"#).unwrap());
    let cm = CostModel::from_str_json(V2).unwrap();
    let run = run_file_cost(text, pl(), &table(), Some(&cm)).expect("list run");
    assert_eq!(run.report.kernels[0].dep_class_defaulted, 0, "the alias edge is priced by the IMAD row");
    let no_imad = V2.replace(r#"{"producer_class":"IMAD","consumer_kind":"data","L_cy":5.0,"scoreboard_only":false},"#, "");
    let cm = CostModel::from_str_json(&no_imad).unwrap();
    let run = run_file_cost(text, pl(), &table(), Some(&cm)).expect("list run");
    assert_eq!(run.report.kernels[0].dep_class_defaulted, 1, "without the IMAD row the alias edge is the defaulted one");
}
