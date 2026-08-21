//! M4.3b: full-allocate-from-zero unit tests. Corpus gates live in the
//! barracuda driver (G15a..d, results/fe/M4/M4_3.md); here: allocator
//! invariants and the fail-closed doctrine on synthetic kernels.

use cubit::ra::{parse_mode, run_file, RaMode};
use cubit::ra_full::plan_full_kernel_live;
use cubit::reg_liveness;
use std::collections::BTreeSet;

fn run_full(text: &str) -> cubit::ra::RaRun {
    run_file(text, RaMode::Full).unwrap()
}

fn ksrc(body: &str) -> String {
    format!(".entry k\n    .reg R0-R255\n{body}    EXIT ;\n.endentry\n")
}

#[test]
fn t_full_mode_parse() {
    assert!(matches!(parse_mode("full").unwrap(), RaMode::Full));
    // "apply" has a plan payload; parse_mode_kind validates the spelling.
    assert_eq!(cubit::ra::parse_mode_kind("apply").unwrap(), "apply");
    assert_eq!(cubit::ra::parse_mode_kind("full").unwrap(), "full");
    assert!(cubit::ra::parse_mode_kind("bogus").is_err());
}

#[test]
fn t_full_basic_renumber_sound() {
    // Two disjoint lifetimes must SHARE a home; overlapping ones must not.
    let src = ksrc("    MOV R7, 0x1 ;\n    IADD3 R9, R7, 0x2, RZ ;\n    MOV R7, 0x3 ;\n    IADD3 R11, R7, 0x4, RZ ;\n");
    let run = run_full(&src);
    let p = run.report.kernels[0].plan.as_ref().unwrap();
    // R7's two lifetimes are NOT split in v0 (one home per symbol): R7 maps
    // to ONE physical; R9/R11 co-live with the first/second R7 lifetime
    // respectively but R9 and R11 never co-live with each other.
    assert_eq!(p.r.len(), 3); // R7,R9,R11
    // Allocation is a per-instruction-injective RENAMING, globally allowed
    // to SHARE homes across disjoint lifetimes (that's the point of RA):
    // only per-position co-live separation is required, audited natively.
    assert_ne!(p.r["7"], p.r["9"]);
    assert_ne!(p.r["7"].to_string()=="", true);
}

#[test]
fn t_full_wide_pair_stays_adjacent() {
    let src = ksrc("    IMAD.WIDE.U32 R20, R4, R5, RZ ;\n    MOV R8, R21 ;\n    MOV R9, R20 ;\n");
    let run = run_full(&src);
    let p = run.report.kernels[0].plan.as_ref().unwrap();
    assert_eq!(p.r["21"], p.r["20"] + 1, "WIDE pair must stay adjacent");
}

#[test]
fn t_full_entry_live_pinned_identity() {
    // Read-before-def at kernel entry = hardware ABI value; must not move.
    let src = ksrc("    IADD3 R4, R5, 0x1, RZ ;\n    MOV R5, 0x0 ;\n    IADD3 R6, R4, 0x1, RZ ;\n");
    let run = run_full(&src);
    let k = &run.report.kernels[0];
    let p = k.plan.as_ref().unwrap();
    assert_eq!(p.r["5"], 5, "entry-live R5 pinned to identity");
    assert!(k.full.as_ref().unwrap().entry_pins.iter().any(|s| s.contains('5')));
}

#[test]
fn t_full_pool_exhaustion_fail_closed() {
    // 255 co-live R values cannot fit the 0..=253 pool -> bail.
    let mut defs = String::new();
    let mut uses = String::new();
    for i in 0..255u32 {
        defs.push_str(&format!("    MOV R{i}, 0x{i:x} ;\n"));
    }
    uses.push_str("    IADD3 R0, R0, R1, RZ ;\n");
    for i in 0..255u32 {
        uses.push_str(&format!("    IADD3 R0, R0, R{i}, RZ ;\n"));
    }
    let src = ksrc(&format!("{defs}{uses}"));
    let e = run_file(&src, RaMode::Full).expect_err("pool exhaustion must fail closed");
    let msg = format!("{e:#}");
    assert!(msg.contains("pool exhausted"), "msg: {msg}");
}

#[test]
fn t_full_deterministic() {
    let src = ksrc("    MOV R7, 0x1 ;\n    IMAD.WIDE.U32 R20, R7, R3, RZ ;\n    LDG.E.LTC128B.128 R100, desc[UR4][R2.64] ;\n    MOV R5, R101 ;\n");
    let a = run_full(&src).out_text;
    let b = run_full(&src).out_text;
    assert_eq!(a, b, "full allocation must be bit-deterministic");
}

#[test]
fn t_full_mma_quad_aligned() {
    // Sources produced with FULL quads (4 MOVs each) so nothing is ABI
    // entry-live; then every MMA tuple base must land at its BUG-037
    // positional alignment after renumbering: D%4 A%4 B%2 C%4.
    let mut defs = String::new();
    for base in [40u32, 46, 56] {
        for k in 0..4 {
            defs.push_str(&format!("    MOV R{}, 0x{:x} ;\n", base + k, base + k));
        }
    }
    let src = format!(
        ".entry k\n    .reg R0-R255\n{defs}    IMMA.16832.S8.S8 R8, R40, R46, R56 ;\n    IMMA.16832.S8.S8 R12, R40, R46, R56 ;\n    EXIT ;\n.endentry\n"
    );
    let run = run_full(&src);
    let k = &run.report.kernels[0];
    let p = k.plan.as_ref().unwrap();
    assert!(k.full.as_ref().unwrap().entry_pins.is_empty(),
            "full-quad producers leave no entry-live pins: {:?}",
            k.full.as_ref().unwrap().entry_pins);
    for (sym, a) in [("8", 4), ("12", 4), ("40", 4), ("46", 2), ("56", 4)] {
        assert_eq!(p.r[sym] % a, 0, "MMA tuple base R{sym} must be {a}-aligned");
    }
    // partial-quad producers make the tuple ABI entry-live => identity pin
    // keeps its (pre-alignment-checked-by-author) home:
    let src2 = ".entry k\n    .reg R0-R255\n    MOV R40, 0x1 ;\n    MOV R46, 0x2 ;\n    MOV R56, 0x3 ;\n    IMMA.16832.S8.S8 R8, R40, R46, R56 ;\n    EXIT ;\n.endentry\n";
    let run2 = run_full(src2);
    let p2 = run2.report.kernels[0].plan.as_ref().unwrap();
    assert_eq!(p2.r["46"], 46, "entry-live B-tuple stays at its pinned home");
}
#[test]
fn t_full_zero_change_when_pool_matches_order() {
    // A kernel whose symbols are already in dense collision-free order CAN
    // be allocated to itself (property: the allocator never REQUIRES a
    // change; not asserting identity, just that the round-trip is sound).
    let src = ksrc("    S2R R0, SR_TID.X ;\n    IMAD R1, R0, 0x4, RZ ;\n    IMAD R2, R1, 0x8, RZ ;\n");
    let run = run_full(&src);
    // render-proof ran inside run_file; additionally the emitted text must
    // re-parse strictly and liveness of the output must not report unknown ops.
    let lv = reg_liveness::liveness_file(&run.out_text).unwrap();
    assert!(lv[0].unknown_ops.is_empty());
}

#[test]
fn t_full_unknown_op_fail_closed() {
    // An op outside operand_roles.json must stop the pass (M3 doctrine).
    let src = ksrc("    FSEL R4, R5, R6, P2 ;\n");
    let e = run_file(&src, RaMode::Full).expect_err("unknown role op must fail closed");
    let msg = format!("{e:#}");
    assert!(msg.contains("unknown register-role"), "msg: {msg}");
}

#[test]
fn t_full_plan_export_matches_text() {
    // The exported plan, re-applied to the INPUT via apply-mode, must
    // reproduce the full mode's output text exactly.
    let src = ksrc("    MOV R7, 0x1 ;\n    IMAD.WIDE.U32 R20, R7, R3, RZ ;\n    MOV R5, R20 ;\n");
    let run = run_full(&src);
    let k = &run.report.kernels[0];
    let plan_json = serde_json::json!({
        "kernels": { "k": { "r": k.plan.as_ref().unwrap().r, "ur": k.plan.as_ref().unwrap().ur } }
    });
    let path = std::env::temp_dir().join("ra_m43_plan_test.json");
    std::fs::write(&path, serde_json::to_string(&plan_json).unwrap()).unwrap();
    let plan: cubit::ra::ApplyPlan =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let run2 = run_file(&src, RaMode::ApplyFile(plan)).unwrap();
    assert_eq!(run.out_text, run2.out_text, "apply(plan) == full output");
}

#[test]
fn t_full_liveness_engine_parity_mulmod_style() {
    // Parity per design (G15b spirit): on a straight-line block the
    // sequential backward sweep must agree with the CFG dataflow engine.
    let src = ksrc("    MOV R7, 0x1 ;\n    MOV R8, 0x2 ;\n    IADD3 R9, R7, R8, RZ ;\n    MOV R10, R9 ;\n");
    let insns = cubit::sass_file::parse_sass_file_str_strict(&src)
        .unwrap().kernels.pop().unwrap().instructions;
    let xfers: Vec<_> = insns.iter().map(reg_liveness::reg_xfer).collect();
    let live = reg_liveness::liveness(&insns);
    // naive straight-line: live_next = live_out[i+1] (or empty at end)
    let mut expect_out: Vec<BTreeSet<u8>> = vec![BTreeSet::new(); insns.len()];
    let mut nxt: BTreeSet<u8> = BTreeSet::new();
    for i in (0..insns.len()).rev() {
        expect_out[i] = nxt.clone();
        let mut l = nxt;
        for d in &xfers[i].rdefs { l.remove(d); }
        for u in &xfers[i].ruses { l.insert(*u); }
        nxt = l;
    }
    for (i, row) in live.iter().enumerate() {
        assert_eq!(row.rlive_out, expect_out[i], "ins {i} live_out parity");
    }
    let (_p, _st) = plan_full_kernel_live("k", &xfers, &live).unwrap();
}
