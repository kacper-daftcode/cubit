//! M5 (BARRACUDA eDSL author surface): pin/mover introspection
//! (`window_pins` / pyo3 `sched_pins`). Contract: same strict parse, same
//! window-shape validation, same pin classification as the list/replay
//! planner -- the introspection is the author's map of what MAY be
//! permuted inside a window (movable set, segment runs) and what holds its
//! position (pins with reasons). Cross-checked against the list planner's
//! own per-window report.

use cubit::sched::{run_file_cost, window_pins, CostModel, SchedMode, SchedPlan};
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
            ("LDG.E.EL.ELL2.256.STRONG.GPU".to_string(), 1.0),
        ]
        .into_iter()
        .collect(),
    }
}

fn plan(json: &str) -> SchedPlan {
    serde_json::from_str::<SchedPlan>(json).expect("plan JSON")
}

/// 12-ins window with every pin class: label carrier at 0, mem at 3,
/// NOP at 6, scoreboard at 9; free IADD3s elsewhere; EXIT outside.
fn pin_soup_src() -> String {
    let ldg = "[B------:R-:W0:Y:S03] LDG.E.EL.ELL2.256.STRONG.GPU R24, R20, desc[UR20][R22.64] ;";
    let wait = "[B----4-:R-:W-:Y:S05] IADD3 R30, PT, PT, R30, -0x1, RZ ;";
    let lines = [
        "L_head:  [B------:R-:W-:-:S00] IADD3 R2, R0, R1, RZ ;".to_string(), // 0 label
        "    [B------:R-:W-:-:S00] IADD3 R3, R2, 0x1, RZ ;".to_string(),    // 1 chain
        "    [B------:R-:W-:-:S00] IADD3 R10, R10, 0x1, RZ ;".to_string(),  // 2
        format!("    {ldg}"),                                               // 3 mem
        "    [B------:R-:W-:-:S00] IADD3 R11, R11, 0x1, RZ ;".to_string(),  // 4
        "    [B------:R-:W-:-:S00] IADD3 R12, R12, 0x1, RZ ;".to_string(),  // 5
        "    [B0-----:R-:W-:-:S03] NOP ;".to_string(),                      // 6 nop
        "    [B------:R-:W-:-:S00] IADD3 R13, R13, 0x1, RZ ;".to_string(),  // 7
        "    [B------:R-:W-:-:S00] IADD3 R14, R14, 0x1, RZ ;".to_string(),  // 8
        format!("    {wait}"),                                              // 9 scoreboard
        "    [B------:R-:W-:-:S00] IADD3 R15, R15, 0x1, RZ ;".to_string(),  // 10
        "    [B------:R-:W-:-:S00] IADD3 R16, R16, 0x1, RZ ;".to_string(),  // 11
    ];
    let mut v = vec![".entry k".to_string()];
    v.extend(lines);
    v.push("    EXIT ;".into());
    v.push(".endentry".into());
    v.join("\n") + "\n"
}

#[test]
fn t5_pins_classification_and_segments() {
    let src = pin_soup_src();
    let reps = window_pins(&src, &plan(r#"{"kernels":{"k":{"windows":[[0,12]]}}}"#), &table())
        .expect("window_pins");
    assert_eq!(reps.len(), 1);
    let w = &reps[0];
    assert_eq!(w.kernel, "k");
    assert_eq!((w.start, w.end), (0, 12));
    assert_eq!(w.movable, vec![1, 2, 4, 5, 7, 8, 10, 11]);
    assert_eq!(w.pins.len(), 4);
    assert_eq!(w.pins[&0], "label");
    assert_eq!(w.pins[&3], "mem_chain");
    assert_eq!(w.pins[&6], "nop");
    assert_eq!(w.pins[&9], "scoreboard");
    // segments = maximal mover runs between pins
    assert_eq!(w.segments, vec![vec![1, 2], vec![4, 5], vec![7, 8], vec![10, 11]]);
    // disjoint union covers the window
    let cover: Vec<u32> = w
        .movable
        .iter()
        .chain(w.pins.keys())
        .copied()
        .collect::<BTreeSetCover>()
        .0;
    assert_eq!(cover, (0..12).collect::<Vec<u32>>());
}

/// Helper: collect a sorted union (keeps the cover assertion readable).
struct BTreeSetCover(Vec<u32>);
impl FromIterator<u32> for BTreeSetCover {
    fn from_iter<I: IntoIterator<Item = u32>>(it: I) -> Self {
        let mut v: Vec<u32> = it.into_iter().collect();
        v.sort_unstable();
        BTreeSetCover(v)
    }
}

#[test]
fn t5_pins_crosscheck_vs_planner_report() {
    let src = pin_soup_src();
    let w = &window_pins(&src, &plan(r#"{"kernels":{"k":{"windows":[[0,12]]}}}"#), &table())
        .expect("pins")[0];
    let run = run_file_cost(
        &src,
        SchedMode::List(plan(r#"{"kernels":{"k":{"windows":[[0,12]]}}}"#)),
        &table(),
        Some(&cost(8.0)),
    )
    .expect("list run");
    let pw = &run.report.kernels[0].windows[0];
    assert_eq!(pw.movers, w.movable.len());
    assert_eq!(pw.pinned, w.pins.len());
    assert_eq!(pw.segments, w.segments.len());
    for (reason, cnt) in &pw.pin_reasons {
        let got = w.pins.values().filter(|r| r.as_str() == reason).count();
        assert_eq!(*cnt, got, "pin reason {reason} count mismatch");
    }
}

#[test]
fn t5_introspected_identity_order_replays_verbatim() {
    let src = pin_soup_src();
    let order: Vec<u32> = (0..12).collect();
    let pl = plan(&format!(
        r#"{{"kernels":{{"k":{{"windows":[[0,12]],"orders":[{:?}]}}}}}}"#,
        order
    ));
    let run = run_file_cost(&src, SchedMode::List(pl), &table(), Some(&cost(8.0)))
        .expect("replay identity");
    assert_eq!(run.out_text, src, "identity order must stay byte-verbatim");
    let w = &run.report.kernels[0].windows[0];
    assert!(w.replay);
    assert_eq!(w.moved, 0);
}

#[test]
fn t5_authored_move_within_segment_ring() {
    // authored mutation: swap the two independent fillers of segment [7,8]
    // (R13 <-> R14 positions); pins and other segments untouched.
    let src = pin_soup_src();
    let mut order: Vec<u32> = (0..12).collect();
    order.swap(7, 8);
    let pl = plan(&format!(
        r#"{{"kernels":{{"k":{{"windows":[[0,12]],"orders":[{:?}]}}}}}}"#,
        order
    ));
    let run = run_file_cost(&src, SchedMode::List(pl), &table(), Some(&cost(8.0)))
        .expect("authored swap must be legal (independent fillers)");
    let ls: Vec<&str> = run.out_text.lines().collect();
    let p13 = ls.iter().position(|l| l.contains("IADD3 R13,")).unwrap();
    let p14 = ls.iter().position(|l| l.contains("IADD3 R14,")).unwrap();
    assert!(p14 < p13, "authored swap emitted: {p14} before {p13}");
    let w = &run.report.kernels[0].windows[0];
    assert!(w.replay);
    assert_eq!(w.moved, 2);
}

#[test]
fn t5_fail_closed_battery() {
    let src = pin_soup_src();
    // shape: overlapping windows
    assert!(window_pins(&src, &plan(r#"{"kernels":{"k":{"windows":[[0,6],[5,12]]}}}"#), &table()).is_err());
    // shape: out of range
    assert!(window_pins(&src, &plan(r#"{"kernels":{"k":{"windows":[[0,13]]}}}"#), &table()).is_err());
    // shape: unknown kernel
    assert!(window_pins(&src, &plan(r#"{"kernels":{"zzz":{"windows":[[0,2]]}}}"#), &table()).is_err());
    // anchor crossing (BRA inside window)
    let br = ".entry k\n    [B------:R-:W-:-:S00] BRA L_x ;\nL_x:  [B------:R-:W-:-:S00] IADD3 R2, R0, R1, RZ ;\n    EXIT ;\n";
    let e = window_pins(br, &plan(r#"{"kernels":{"k":{"windows":[[0,2]]}}}"#), &table())
        .err()
        .expect("anchor-class must fail closed");
    assert!(format!("{e:#}").contains("anchor-class"), "{e:#}");
    // authored order moving a pin -> replay refuses before emission
    let mut order: Vec<u32> = (0..12).collect();
    order.swap(3, 4); // 3 = mem_chain pin
    let pl = plan(&format!(
        r#"{{"kernels":{{"k":{{"windows":[[0,12]],"orders":[{:?}]}}}}}}"#,
        order
    ));
    let e = run_file_cost(&src, SchedMode::List(pl), &table(), Some(&cost(8.0)))
        .err()
        .expect("pin move must fail closed");
    assert!(format!("{e:#}").contains("moves pinned"), "{e:#}");
    // authored order not a permutation
    let order = vec![0u32, 1, 2, 3, 4];
    let pl = plan(&format!(
        r#"{{"kernels":{{"k":{{"windows":[[0,12]],"orders":[{:?}]}}}}}}"#,
        order
    ));
    let e = run_file_cost(&src, SchedMode::List(pl), &table(), Some(&cost(8.0)))
        .err()
        .expect("non-permutation must fail closed");
    assert!(format!("{e:#}").contains("not a"), "{e:#}");
}

#[test]
fn t5_multi_window_union() {
    // two disjoint windows in one kernel; introspection per window
    let src = pin_soup_src();
    let reps = window_pins(
        &src,
        &plan(r#"{"kernels":{"k":{"windows":[[0,3],[10,12]]}}}"#),
        &table(),
    )
    .expect("two windows");
    assert_eq!(reps.len(), 2);
    assert_eq!(reps[0].movable, vec![1, 2]);
    assert_eq!(reps[0].pins.len(), 1);
    assert_eq!(reps[1].movable, vec![10, 11]);
}
