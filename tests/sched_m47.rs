//! M4.7: replay mode -- authored (explicit) window orders. The eDSL
//! seed-mutation contract: the author assigns an order by hand, the pass
//! PROVES legality (pin fixed points + verify_permutation) and emits
//! exactly it, priced by the same ready-time model. The optimizer is
//! bypassed, never "repairing" an authored order; illegal orders are
//! refused before any emission.

use cubit::sched::{parse_mode_kind, run_file_cost, CostModel, SchedMode, SchedPlan};
use cubit::table::IsaTable;

fn table() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn cost() -> CostModel {
    CostModel {
        arch: "sm_103a".into(),
        quantum_cy: 7.9,
        dep_link_latency_slots: 8.0,
        credits_default: 1.0,
        credits: [("IADD3".to_string(), 1.0)].into_iter().collect(),
    }
}

fn plan(json: &str) -> SchedMode {
    SchedMode::List(serde_json::from_str::<SchedPlan>(json).expect("plan JSON"))
}

/// 3-chain (R2->R3->R4) + 12 fillers, all S00; matches the G13b fixture.
fn bubble_src() -> String {
    let mut v = vec![".entry k".to_string()];
    v.push("    [B------:R-:W-:-:S00] IADD3 R2, R0, R1, RZ ;".into()); // 0
    v.push("    [B------:R-:W-:-:S00] IADD3 R3, R2, 0x1, RZ ;".into()); // 1 chain
    v.push("    [B------:R-:W-:-:S00] IADD3 R4, R3, R5, RZ ;".into()); // 2 chain
    for i in 0..12 {
        v.push(format!(
            "    [B------:R-:W-:-:S00] IADD3 R{0}, R{0}, 0x1, RZ ;",
            10 + i
        ));
    }
    v.push("    EXIT ;".into());
    v.push(".endentry".into());
    v.join("\n") + "\n"
}

#[test]
fn replay_identity_byte_verbatim() {
    let order: Vec<u32> = (0..15).collect();
    let pl = plan(&format!(
        r#"{{"kernels":{{"k":{{"windows":[[0,15]],"orders":[{:?}]}}}}}}"#,
        order
    ));
    let run = run_file_cost(&bubble_src(), pl, &table(), Some(&cost())).expect("replay run");
    assert_eq!(run.out_text, bubble_src(), "identity replay must be byte-verbatim");
    let w = &run.report.kernels[0].windows[0];
    assert!(w.replay && w.moved == 0 && w.cost_after == w.cost_before);
}

#[test]
fn replay_emits_authored_order_not_optimizer() {
    // chain LAST (a known suboptimal detune): replay must emit exactly it
    // (author sovereignty -- no regression refusal, no parity flattening).
    let mut order: Vec<u32> = (3..15).collect();
    order.extend([0, 1, 2]);
    let pl = plan(&format!(
        r#"{{"kernels":{{"k":{{"windows":[[0,15]],"orders":[{:?}]}}}}}}"#,
        order
    ));
    let run = run_file_cost(&bubble_src(), pl, &table(), Some(&cost())).expect("replay run");
    let lines: Vec<&str> = run.out_text.lines().collect();
    // .entry header shifts instruction p to line 1+p
    assert!(lines[13].contains("IADD3 R2, R0, R1"), "{:?}", lines[13]);
    assert!(lines[14].contains("IADD3 R3, R2, 0x1"), "{:?}", lines[14]);
    assert!(lines[15].contains("IADD3 R4, R3, R5"), "chain tail last: {:?}", lines[15]);
    let w = &run.report.kernels[0].windows[0];
    assert!(w.replay && w.moved == 15);
    assert!(w.cost_after > 0.0);
}

#[test]
fn replay_refuses_illegal_raw_inversion() {
    let mut order: Vec<u32> = (0..15).collect();
    order.swap(1, 2); // R3 consumer before producer -- RAW inversion
    let pl = plan(&format!(
        r#"{{"kernels":{{"k":{{"windows":[[0,15]],"orders":[{:?}]}}}}}}"#,
        order
    ));
    let err = match run_file_cost(&bubble_src(), pl, &table(), Some(&cost())) {
        Ok(_) => panic!("RAW inversion must fail"),
        Err(e) => e,
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("illegal permutation"), "{msg}");
    assert!(msg.contains("raw_r"), "{msg}");
}

#[test]
fn replay_refuses_non_permutation_and_pin_moves() {
    let zeros = vec![0u32; 15];
    let pl = plan(&format!(
        r#"{{"kernels":{{"k":{{"windows":[[0,15]],"orders":[{:?}]}}}}}}"#,
        zeros
    ));
    let err = match run_file_cost(&bubble_src(), pl, &table(), Some(&cost())) {
        Ok(_) => panic!("non-permutation must fail"),
        Err(e) => e,
    };
    assert!(format!("{err:#}").contains("not a"));

    // pinned instruction (write barrier) moved -> refuse
    let mut src = bubble_src();
    src = src.replace(
        "[B------:R-:W-:-:S00] IADD3 R13, R13, 0x1, RZ ;",
        "[B------:R-:W0:-:S00] IADD3 R13, R13, 0x1, RZ ;",
    );
    let mut order: Vec<u32> = (0..15).collect();
    order.swap(6, 7); // 6 is the pinned IADD3 R13 (chain 0..2, then fillers)
    let pl = plan(&format!(
        r#"{{"kernels":{{"k":{{"windows":[[0,15]],"orders":[{:?}]}}}}}}"#,
        order
    ));
    let err = match run_file_cost(&src, pl, &table(), Some(&cost())) { Ok(_) => panic!("must fail"), Err(e) => e };
    assert!(format!("{err:#}").contains("pinned"), "{err:#}");
}

#[test]
fn replay_orders_length_mismatch_refused() {
    let pl = plan(r#"{"kernels":{"k":{"windows":[[0,15]],"orders":[]}}}"#);
    let err = match run_file_cost(&bubble_src(), pl, &table(), Some(&cost())) {
        Ok(_) => panic!("length mismatch must fail"),
        Err(e) => e,
    };
    assert!(format!("{err:#}").contains("orders has"));
}
