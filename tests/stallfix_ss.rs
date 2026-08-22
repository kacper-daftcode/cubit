//! POSTFIX-103 v0 (STALLSUF-1 / BARRACUDA b1): stall-sufficiency legalizer.
//!
//! The floors are silicon-measured facts (tables/stallfix_sm103a.json);
//! these tests pin the pass semantics: R1 global floor, R2 dmix floor at
//! slot distance 0, R3 guard floors at distance 0/2, the guard-D1 hard
//! failure (flaky at every S<=8), chain kills by predicate redefinition,
//! raise-only doctrine (never lower, never touch B/R/W/Y), and the
//! fail-closed region/plan contract. Byte-identity against the
//! silicon-validated reference output lives in the barracuda ss3 gates
//! (G-SS3a/b) since it needs the O3 corpus artifact.

use cubit::stallfix::{run_file, StallFixPlan, StallRules};

fn rules() -> StallRules {
    StallRules::load(std::path::Path::new("tables/stallfix_sm103a.json")).unwrap()
}

fn plan(json: &str) -> StallFixPlan {
    serde_json::from_str::<StallFixPlan>(json).expect("plan JSON")
}

fn pl(windows: &str) -> StallFixPlan {
    plan(&format!(
        r#"{{"arch":"sm_103a","kernels":{{"k":{{"windows":{windows}}}}}}}"#,
        windows = windows
    ))
}

fn kern(insns: &[&str]) -> String {
    let mut v = vec![".entry k".to_string()];
    for l in insns {
        v.push(format!("    {l} ;"));
    }
    v.push(".endentry".into());
    v.join("\n") + "\n"
}

#[test]
fn r1_global_floor_raises_path_chain() {
    let src = kern(&[
        "[B------:R-:W-:-:S00] IADD3 R2, R0, R1, RZ",
        "[B------:R-:W-:-:S01] IADD3 R3, R2, 0x1, RZ",
        "[B------:R-:W-:-:S03] IADD3 R4, R3, R5, RZ",
        "[B------:R-:W-:-:S00] IADD3 R9, R7, R8, RZ",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,4]]"), &rules()).unwrap();
    assert_eq!(run.report.total_raises, 4);
    let k = &run.report.kernels[0];
    for r in &k.raises {
        assert_eq!((r.old_stall, r.new_stall), ([0, 1, 3, 0][r.ins_idx as usize], 4));
        assert_eq!(r.rules, vec!["R1".to_string()]);
    }
    // EXIT is outside the window: untouched.
    let out_last = run.out_text.lines().nth(5).unwrap();
    assert!(out_last.contains("EXIT"), "{out_last}");
    // every raised line differs from the source line only in ":Sxx]"
    for (a, b) in src.lines().zip(run.out_text.lines()) {
        let diffs: Vec<(u8, u8)> = a.bytes().zip(b.bytes()).filter(|(x, y)| x != y).collect();
        assert!(diffs.len() <= 2, "{a} vs {b}");
    }
}

#[test]
fn r2_dmix_d0_floor5() {
    // IMAD.WIDE.U32 cout P4 consumed as cin by an adjacent IADD3.X
    // (the .X form on the producer side would carry cin P4 at the last
    // operand instead; census class dmix = WIDE.X(P4)->IADD3.X(cin P4)).
    let src = kern(&[
        "[B------:R-:W-:-:S00] IMAD.WIDE.U32 R166, P4, R134, R140, R166",
        "[B------:R-:W-:-:S00] IADD3.X R166, P4, PT, R166, R189, RZ, P4, !PT",
        "[B------:R-:W-:-:S00] IADD3 R9, R7, R8, RZ",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,3]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    let prod = k.raises.iter().find(|r| r.ins_idx == 0).unwrap();
    assert_eq!(prod.new_stall, 5);
    assert!(prod.rules.iter().any(|r| r == "R2-dmix-d0"), "{:?}", prod.rules);
    // the consumer itself carries only the R1 floor
    let cons = k.raises.iter().find(|r| r.ins_idx == 1).unwrap();
    assert_eq!(cons.new_stall, 4);
}

#[test]
fn iadd3x_to_iadd3x_cin_stays_floor4() {
    // cin chain inside the integer pipe: census b1dual/b2single -> S04
    // suffices at d0; only the IMAD* -> IADD3.X mix needs S05.
    let src = kern(&[
        "[B------:R-:W-:-:S00] IADD3.X R2, P1, PT, R0, R1, RZ, P1, !PT",
        "[B------:R-:W-:-:S00] IADD3.X R3, P2, PT, R2, R5, RZ, P1, !PT",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,2]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    assert!(k.raises.iter().all(|r| r.new_stall == 4));
}

#[test]
fn r3_guard_d0_floor7() {
    let src = kern(&[
        "[B------:R-:W-:-:S00] ISETP.GT.U32.AND P2, PT, R0, R1, PT",
        "[B------:R-:W-:-:S01] @P2 IADD3 R5, R3, R4, RZ",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,2]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    let prod = k.raises.iter().find(|r| r.ins_idx == 0).unwrap();
    assert_eq!(prod.new_stall, 7);
    assert!(prod.rules.iter().any(|r| r == "R3-guard-d0"));
}

#[test]
fn r3_guard_d1_is_hard_error() {
    let src = kern(&[
        "[B------:R-:W-:-:S09] ISETP.GT.U32.AND P2, PT, R0, R1, PT",
        "[B------:R-:W-:-:S00] IADD3 R9, R7, R8, RZ", // the one-instruction gap
        "[B------:R-:W-:-:S00] @!P2 IADD3 R5, R3, R4, RZ",
        "EXIT",
    ]);
    let err = run_file(&src, &pl("[[0,3]]"), &rules()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("guard-D1"), "{msg}");
    assert!(msg.contains("no stall legalizes"), "{msg}");
}

#[test]
fn r3_guard_d2_floor5() {
    let src = kern(&[
        "[B------:R-:W-:-:S00] ISETP.GT.U32.AND P2, PT, R0, R1, PT",
        "[B------:R-:W-:-:S00] IADD3 R9, R7, R8, RZ",
        "[B------:R-:W-:-:S00] LOP3.LUT R10, R7, R8, RZ, 0x80, !PT",
        "[B------:R-:W-:-:S00] @P2 IADD3 R5, R3, R4, RZ",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,4]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    let prod = k.raises.iter().find(|r| r.ins_idx == 0).unwrap();
    assert_eq!(prod.new_stall, 5);
    assert!(prod.rules.iter().any(|r| r == "R3-guard-d2"));
}

#[test]
fn guard_chain_killed_by_redefinition() {
    // ins0's P2 is redefined at ins1 before the guard consumer at ins2:
    // ins0 owes nothing beyond R1; ins1 carries the d0 guard floor.
    let src = kern(&[
        "[B------:R-:W-:-:S00] ISETP.GT.U32.AND P2, PT, R0, R1, PT",
        "[B------:R-:W-:-:S00] ISETP.LT.U32.AND P2, PT, R7, R8, PT",
        "[B------:R-:W-:-:S00] @P2 IADD3 R5, R3, R4, RZ",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,3]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    let r0 = k.raises.iter().find(|r| r.ins_idx == 0).unwrap();
    assert_eq!(r0.new_stall, 4);
    let r1 = k.raises.iter().find(|r| r.ins_idx == 1).unwrap();
    assert_eq!(r1.new_stall, 7);
}

#[test]
fn raise_only_never_lowers() {
    let src = kern(&[
        "[B------:R-:W-:-:S09] IADD3 R2, R0, R1, RZ",
        "[B------:R-:W-:-:S11] ISETP.GT.U32.AND P2, PT, R0, R1, PT",
        "[B------:R-:W-:-:S00] @P2 IADD3 R5, R3, R4, RZ",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,3]]"), &rules()).unwrap();
    assert_eq!(run.report.total_raises, 1); // only the S00 guard consumer -> 4
    assert!(run.out_text.contains(":S09] IADD3 R2"));
    assert!(run.out_text.contains(":S11] ISETP"));
}

#[test]
fn input_above_cap_reported_untouched() {
    let src = kern(&[
        "[B------:R-:W-:-:S12] IADD3 R2, R0, R1, RZ",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,1]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    assert_eq!(k.input_above_cap, vec![0]);
    assert_eq!(run.report.total_raises, 0);
    assert!(run.out_text.contains(":S12]"));
}

#[test]
fn fail_closed_region_and_plan_contract() {
    let needs_prefix = kern(&[
        "[B------:R-:W-:-:S00] IADD3 R2, R0, R1, RZ",
        "IADD3 R3, R2, 0x1, RZ", // naked inside the window
        "EXIT",
    ]);
    let err = run_file(&needs_prefix, &pl("[[0,2]]"), &rules()).unwrap_err();
    assert!(format!("{err:#}").contains("no ctrl prefix"));

    let src = kern(&["[B------:R-:W-:-:S00] IADD3 R2, R0, R1, RZ", "EXIT"]);
    // unknown kernel
    let err = run_file(&src, &plan(r#"{"arch":"sm_103a","kernels":{"nope":{"windows":[[0,1]]}}}"#), &rules()).unwrap_err();
    assert!(format!("{err:#}").contains("unknown kernel"));
    // window past the end
    let err = run_file(&src, &pl("[[0,9]]"), &rules()).unwrap_err();
    assert!(format!("{err:#}").contains("past end"));
    // overlapping windows
    let err = run_file(&src, &pl("[[0,1],[0,1]]"), &rules()).unwrap_err();
    assert!(format!("{err:#}").contains("overlapping"));
    // empty window
    let err = run_file(&src, &pl("[[1,1]]"), &rules()).unwrap_err();
    assert!(format!("{err:#}").contains("empty"));
    // arch mismatch against the measured rules
    let err = run_file(&src, &plan(r#"{"arch":"sm_120","kernels":{"k":{"windows":[[0,1]]}}}"#), &rules()).unwrap_err();
    assert!(format!("{err:#}").contains("scope-locked"));
}

#[test]
fn no_edits_byte_verbatim() {
    let src = kern(&[
        "[B------:R-:W-:-:S07] IADD3 R2, R0, R1, RZ",
        "[B------:R-:W-:-:S04] IADD3 R3, R2, 0x1, RZ",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,2]]"), &rules()).unwrap();
    assert_eq!(run.report.total_raises, 0);
    assert_eq!(run.out_text, src);
}

#[test]
fn rules_sanity_rejects_bad_data() {
    let err = StallRules::from_str_json(
        r#"{"arch":"sm_103a","cap_stall":16,"floor_global":4,
            "floor_dmix_d0":5,"floor_guard_d0":7,"floor_guard_d2":5}"#,
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("4-bit"));
}
