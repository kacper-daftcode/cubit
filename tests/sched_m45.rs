//! M4.5: reordering-scheduler pass unit tests (identity mode). Corpus
//! byte-exactness is the BARRACUDA gate G11b (results/fe/M4); here: mode
//! doctrine, dependency-graph semantics, checker correctness, and the
//! fail-closed role/class rules.

use cubit::ir::Operand;
use cubit::parser::parse_sass;
use cubit::sched::{
    build_graph, fallback_class, parse_mode_kind, run_file, verify_permutation, EdgeClass,
    SchedMode,
};
use cubit::table::IsaTable;

fn ksrc(body: &str) -> String {
    format!(".entry k\n{body}    EXIT ;\n")
}

fn table() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn run(text: &str) -> (String, cubit::sched::SchedRunReport) {
    let r = run_file(text, SchedMode::Identity, &table()).unwrap();
    (r.out_text, r.report)
}

// ---------------------------------------------------------------- mode parse

#[test]
fn t_mode_parse() {
    assert_eq!(parse_mode_kind("identity").unwrap(), "identity");
    // M4.6: "list" is a real mode now (windowed list scheduler, plan+cost
    // carried separately); the remaining spellings stay fail-closed.
    assert_eq!(parse_mode_kind("list").unwrap(), "list");
    for bad in ["sched", "", "Identity", "pin"] {
        assert!(parse_mode_kind(bad).is_err(), "mode {bad:?} must fail closed");
    }
}

// ------------------------------------------------------- graph construction

#[test]
fn t_raw_waw_war_edges_r_domain() {
    // R2: def @0, use @1 (RAW); R1: use @0, def @1 (WAR); R3: def @0, def @2 (WAW).
    let src = ksrc(
        "    IADD3 R2, R0, R1, RZ ;\n    IADD3 R1, R2, R0, RZ ;\n    IADD3 R3, R1, R2, RZ ;\n",
    );
    let file = cubit::sass_file::parse_sass_file_str_strict(&src).unwrap();
    let g = build_graph(&file.kernels[0].instructions, &table()).unwrap();
    let has = |a: u32, b: u32, c: EdgeClass| g.edges.iter().any(|&(x, y, k)| x == a && y == b && k == c);
    assert!(has(0, 1, EdgeClass::RawR), "RAW R2 0->1");
    assert!(has(0, 1, EdgeClass::WarR), "WAR R1 0->1");
    assert!(!has(1, 0, EdgeClass::RawR), "no backward edges");
    // IADD3 R3.. def of R1 at idx1 then use at idx2 -> raw; def R2 at idx0 use idx2 -> raw
    assert!(has(1, 2, EdgeClass::RawR));
    assert!(has(0, 2, EdgeClass::RawR));
}

#[test]
fn t_self_dependency_is_inherent_not_an_edge() {
    // IMAD reading and writing the same register must NOT create an a->a edge
    // (regression: initial builder emitted (i,i) WAR self-edges the checker
    // then flagged as inverted).
    let src = ksrc("    IMAD R5, R5, R6, R5 ;\n    IMAD R7, R5, R6, RZ ;\n");
    let file = cubit::sass_file::parse_sass_file_str_strict(&src).unwrap();
    let g = build_graph(&file.kernels[0].instructions, &table()).unwrap();
    assert!(
        !g.edges.iter().any(|&(a, b, _)| a == b),
        "self-edge found: {:?}",
        g.edges.iter().filter(|&&(a, b, _)| a == b).collect::<Vec<_>>()
    );
    // identity permutation must verify
    let perm: Vec<u32> = (0..g.n as u32).collect();
    verify_permutation(&g, &perm).unwrap();
}

#[test]
fn t_pred_and_up_edges() {
    // ISETP defines P0, guarded IMAD uses P0 -> raw_p 0->1. Uniform pair
    // exercises the UP domain (Strict superset).
    let src = ksrc(
        "    ISETP.GT.AND P0, PT, R4, R5, PT ;\n    @P0 IMAD R6, R5, R4, RZ ;\n    ULOP3.LUT UR4, URZ, 0x1, URZ, 0xc0 ;\n    UIMAD UR5, UR4, UR4, URZ, URZ ;\n",
    );
    let file = cubit::sass_file::parse_sass_file_str_strict(&src).unwrap();
    let g = build_graph(&file.kernels[0].instructions, &table()).unwrap();
    let has = |a: u32, b: u32, c: EdgeClass| g.edges.iter().any(|&(x, y, k)| x == a && y == b && k == c);
    assert!(has(0, 1, EdgeClass::RawP), "RAW P0 0->1");
    assert!(has(2, 3, EdgeClass::RawUr), "RAW UR4 2->3");
}

#[test]
fn t_mem_chain_and_anchors() {
    // LDG then STG must carry a mem_chain edge; BRA is an anchor: every
    // instruction on one side gets an anchor edge towards it.
    let src = ksrc(
        "    LDG.E R4, [R2.64] ;\n    STG.E [R2.64], R4 ;\n    BRA `L1 ;\n    IMAD R6, R5, R5, RZ ;\nL1: EXIT ;\n",
    );
    let file = cubit::sass_file::parse_sass_file_str_strict(&src).unwrap();
    let g = build_graph(&file.kernels[0].instructions, &table()).unwrap();
    let has = |a: u32, b: u32, c: EdgeClass| g.edges.iter().any(|&(x, y, k)| x == a && y == b && k == c);
    assert!(has(0, 1, EdgeClass::MemChain), "LDG->STG ordered");
    assert!(g.anchors.contains(&2), "BRA anchored");
    assert!(g.anchors.contains(&4), "EXIT anchored");
    assert!(has(1, 2, EdgeClass::Anchor), "mem op before BRA ordered to it");
    assert!(has(3, 4, EdgeClass::Anchor), "pre-EXIT insn ordered to EXIT");
    assert!(has(2, 3, EdgeClass::Anchor), "BRA -> post-BRA insn ordered");
}

#[test]
fn t_hand_sched_is_anchor() {
    let src = ksrc("    [B------:R-:W-:-:S01] IMAD R5, R4, R4, RZ ;\n    IMAD R6, R5, R5, RZ ;\n");
    let file = cubit::sass_file::parse_sass_file_str_strict(&src).unwrap();
    let g = build_graph(&file.kernels[0].instructions, &table()).unwrap();
    assert_eq!(g.n_hand_sched, 1);
    assert!(g.anchors.contains(&0), "hand_sched insn anchored");
}

// ------------------------------------------------------------- legality check

#[test]
fn t_verify_permutation_catches_inversion() {
    let src = ksrc("    IMAD R5, R4, R4, RZ ;\n    IMAD R6, R5, R5, RZ ;\n    IMAD R7, R6, R6, RZ ;\n");
    let file = cubit::sass_file::parse_sass_file_str_strict(&src).unwrap();
    let g = build_graph(&file.kernels[0].instructions, &table()).unwrap();
    // swap the first two instructions: inverts the raw_r edge 0->1.
    let e = verify_permutation(&g, &[1, 0, 2, 3]).unwrap_err();
    assert!(
        format!("{e:#}").contains("raw_r"),
        "checker must attribute the inverted edge class: {e:#}"
    );
    // length / duplicate / range traps
    assert!(verify_permutation(&g, &[0, 1, 2]).is_err());
    assert!(verify_permutation(&g, &[0, 0, 1, 2]).is_err());
    assert!(verify_permutation(&g, &[0, 1, 2, 9]).is_err());
    // a legal reordering of independent instructions passes
    let src2 = ksrc("    IMAD R5, R4, R4, RZ ;\n    IMAD R7, R8, R8, RZ ;\n");
    let file2 = cubit::sass_file::parse_sass_file_str_strict(&src2).unwrap();
    let g2 = build_graph(&file2.kernels[0].instructions, &table()).unwrap();
    verify_permutation(&g2, &[1, 0, 2]).unwrap();
}

// ---------------------------------------------------------------- run_file

#[test]
fn t_identity_byte_verbatim_and_report() {
    let src = ksrc(
        "    S2R R0, SR_TID.X ;\n    LDG.E R4, [R2.64] ;\n    IMAD R6, R4, R4, RZ ;\n    STG.E [R2.64], R6 ;\n",
    );
    let (out, rep) = run(&src);
    assert_eq!(out, src, "identity emission must be byte-verbatim");
    assert_eq!(rep.mode, "identity");
    assert_eq!(rep.kernels.len(), 1);
    let k = &rep.kernels[0];
    assert_eq!(k.n_ins, 5);
    assert_eq!(k.moved, 0);
    assert!(k.unknown_ops.is_empty());
    assert!(k.unknown_classes.is_empty());
    assert!(k.edges_total > 0);
    assert!(k.edges_by_class.get("raw_r").copied().unwrap_or(0) >= 2);
    assert!(k.edges_by_class.get("mem_chain").copied().unwrap_or(0) >= 1);
    assert!(k.live_peak_r >= 1);
}

#[test]
fn t_fallback_classification_counted() {
    // UIMAD rows carry no ctrl_class in the repo table: the explicit base-op
    // fallback must classify and the report must count it (table-gap census).
    let src = ksrc("    UIMAD UR4, UR5, 0x1, URZ, URZ ;\n    UIMAD UR6, UR4, UR4, URZ, URZ ;\n");
    let (_, rep) = run(&src);
    let k = &rep.kernels[0];
    assert!(k.unknown_classes.is_empty());
    assert!(k.class_fallback >= 2, "fallback hits must be counted");
}

// ------------------------------------------------------------ fail-closed

#[test]
fn t_unknown_role_op_fails_closed() {
    let src = ksrc("    HOPZXP9 R1, R2, R3 ;\n");
        let e = match run_file(&src, SchedMode::Identity, &table()) {
        Err(e) => e,
        Ok(_) => panic!("unknown-role op must fail closed"),
    };
    assert!(
        format!("{e:#}").contains("unknown operand roles"),
        "error must surface unknown-role doctrine: {e:#}"
    );
}

#[test]
fn t_unknown_class_fails_closed() {
    // Zero-operand synthetic op: register roles are vacuously known (no reg
    // operands), so the CLASS gate is the one that must fire -- the base is
    // absent from the table AND from the grounded fallback lists.
    let src = ksrc("    HOPZXC1 ;\n");
    let r = run_file(&src, SchedMode::Identity, &table());
    match r {
        Err(e) => assert!(
            format!("{e:#}").contains("no ctrl_class"),
            "error must surface the class doctrine: {e:#}"
        ),
        Ok(_) => panic!("unclassifiable instruction must fail closed"),
    }
}

#[test]
fn t_fallback_class_unit() {
    let mk = |body: &str| parse_sass(body, 0).unwrap();
    assert!(fallback_class(&mk("UIMAD UR4, UR5, 0x1, URZ, URZ ;")).is_some());
    assert!(fallback_class(&mk("LDCU.64 UR4, c[0x0][0x358] ;")).is_some());
    assert!(fallback_class(&mk("HOPZXP9 R1, R2, R3 ;")).is_none());
    let _ = mk; // silence
}
