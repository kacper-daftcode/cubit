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

// -------------------------------------------------------------------
// v1 (F-ss4 census-hi, 2026-08-22): class-resolved guard-D1.
// -------------------------------------------------------------------

#[test]
fn r6_guard_d1_isetp_floor5_applies() {
    // producer ISETP S01 -> one-instruction gap -> @P2 ISETP consumer:
    // isetp-class D1 is measured LEGAL for producer stalls 5..=11
    // (census-hi B300, 3 runs x 2 tiers); the pass floors the producer.
    let src = kern(&[
        "[B------:R-:W-:-:S01] ISETP.GT.U32.AND P2, PT, R0, R1, PT",
        "[B------:R-:W-:-:S00] IADD3 R9, R7, R8, RZ",
        "[B------:R-:W-:-:S00] @P2 ISETP.EQ.AND P3, PT, R2, R3, PT",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,3]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    let prod = k.raises.iter().find(|r| r.ins_idx == 0).unwrap();
    assert_eq!(prod.new_stall, 5);
    assert!(prod.rules.iter().any(|r| r == "R6-guard-d1-isetp"), "{:?}", prod.rules);
    assert_eq!(k.d1_sites.len(), 1);
    assert_eq!(k.d1_sites[0].class, "isetp");
    assert_eq!(k.d1_sites[0].action, "floor-raise:S01->S05");
    assert!(k.high_stall_risk.is_empty());
}

#[test]
fn r6_guard_d1_isetp_inband_noop() {
    // producer already at S07: inside the measured legal band -> no raise,
    // site enumerated as noop.
    let src = kern(&[
        "[B------:R-:W-:-:S07] ISETP.GT.U32.AND P2, PT, R0, R1, PT",
        "[B------:R-:W-:-:S04] IADD3 R9, R7, R8, RZ",
        "[B------:R-:W-:-:S04] @!P2 ISETP.NE.AND P3, PT, R2, R3, PT",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,3]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    assert_eq!(k.n_raises, 0);
    assert_eq!(k.d1_sites.len(), 1);
    assert_eq!(k.d1_sites[0].action, "noop");
}

#[test]
fn r6_guard_d1_isetp_bad_band_12_is_error() {
    // producer at S13 with an isetp-class D1 consumer: measured bad band
    // (S12/S13 flaky/mismatch); raise-only cannot lower -> violation.
    let src = kern(&[
        "[B------:R-:W-:-:S13] ISETP.GT.U32.AND P2, PT, R0, R1, PT",
        "[B------:R-:W-:-:S04] IADD3 R9, R7, R8, RZ",
        "[B------:R-:W-:-:S04] @P2 ISETP.EQ.AND P3, PT, R2, R3, PT",
        "EXIT",
    ]);
    let err = run_file(&src, &pl("[[0,3]]"), &rules()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("guard-D1"), "{msg}");
    assert!(msg.contains("isetp-class"), "{msg}");
    assert!(msg.contains("eliminate"), "{msg}");
}

#[test]
fn r6_guard_d1_atomic_is_error() {
    // guarded-atomic forms are silicon-gated on sm_103a (census-hi):
    // any guard-D1 on a RED/ATOM op is a violation regardless of stall.
    let src = kern(&[
        "[B------:R-:W-:-:S07] ISETP.GT.U32.AND P2, PT, R0, R1, PT",
        "[B------:R-:W-:-:S04] IADD3 R9, R7, R8, RZ",
        "[B------:R-:W-:-:S04] @P2 REDG.E.ADD.EL.STRONG.GPU PT, desc[UR0][RZ.64], R5",
        "EXIT",
    ]);
    let err = run_file(&src, &pl("[[0,3]]"), &rules()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("guard-D1"), "{msg}");
    assert!(msg.contains("silicon-gated"), "{msg}");
}

#[test]
fn v1_high_stall_risk_is_report_only() {
    // producer S13 with a d2 guard: floor satisfied (13 > 5), but the
    // legacy S>=12 zone is a measured risk pocket -> report-only row,
    // no raise, no error.
    let src = kern(&[
        "[B------:R-:W-:-:S13] ISETP.GT.U32.AND P2, PT, R0, R1, PT",
        "[B------:R-:W-:-:S04] IADD3 R9, R7, R8, RZ",
        "[B------:R-:W-:-:S04] IADD3 R8, R7, R6, RZ",
        "[B------:R-:W-:-:S04] @P2 IADD3 R5, R3, R4, RZ",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,4]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    assert_eq!(k.n_raises, 0);
    assert_eq!(k.d1_sites.len(), 0);
    assert_eq!(k.high_stall_risk.len(), 1);
    assert_eq!(k.high_stall_risk[0].prod_stall, 13);
    assert_eq!(k.high_stall_risk[0].dist, 3);
    assert_eq!(k.high_stall_risk[0].class, "data");
}

#[test]
fn v1_violations_collect_all_sites() {
    // two bad D1 sites in one run: the error must enumerate BOTH (map
    // for the D1-elimination pass, no bail-at-first).
    let src = kern(&[
        "[B------:R-:W-:-:S09] ISETP.GT.U32.AND P2, PT, R0, R1, PT",
        "[B------:R-:W-:-:S04] IADD3 R9, R7, R8, RZ",
        "[B------:R-:W-:-:S04] @P2 IADD3 R5, R3, R4, RZ",
        "[B------:R-:W-:-:S09] ISETP.LT.U32.AND P4, PT, R6, R7, PT",
        "[B------:R-:W-:-:S04] IADD3 R10, R7, R8, RZ",
        "[B------:R-:W-:-:S04] @P4 LOP3.LUT R11, R3, R4, R5, 0x96, !PT",
        "EXIT",
    ]);
    let err = run_file(&src, &pl("[[0,6]]"), &rules()).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("2 guard-D1 site(s)"), "{msg}");
    assert!(msg.matches("\"prod_idx\":3").count() == 1, "{msg}");
    assert!(msg.matches("\"prod_idx\":0").count() == 1, "{msg}");
}

#[test]
fn v1_rules_version_flows_to_report() {
    let r = rules();
    assert_eq!(r.rules_version, "v2");
    assert_eq!(r.guard_d1_isetp_floor, 5);
    assert_eq!(r.legacy_stall_risk_from, 12);
    assert_eq!(r.floor_xread_d0, 6);
    assert_eq!(r.floor_r2ur_d0, 8);
    assert_eq!(r.floor_uguard_d0, 10);
    assert_eq!(r.floor_uguard_d1, 8);
    let src = kern(&["[B------:R-:W-:-:S04] IADD3 R2, R0, R1, RZ", "EXIT"]);
    let run = run_file(&src, &pl("[[0,1]]"), &r).unwrap();
    assert_eq!(run.report.rules_version, "v2");
}

#[test]
fn v1_defaults_keep_old_rules_files_loadable() {
    // pre-v1 rules JSON (no new fields) must still parse and behave
    // exactly like v0 semantics (serde defaults).
    let v0 = r#"{"arch":"sm_103a","cap_stall":11,"floor_global":4,
        "floor_dmix_d0":5,"floor_guard_d0":7,"floor_guard_d2":5,
        "guard_d1_forbid":true}"#;
    let r = StallRules::from_str_json(v0).unwrap();
    assert_eq!(r.guard_d1_isetp_floor, 5);
    assert_eq!(r.legacy_stall_risk_from, 12);
    assert_eq!(r.rules_version, "");
    // v2 defaults keep pre-v2 files loadable with measured values.
    assert_eq!(r.floor_xread_d0, 6);
    assert_eq!(r.floor_r2ur_d0, 8);
    assert_eq!(r.floor_uguard_d0, 10);
    assert_eq!(r.floor_uguard_d1, 8);
}

// ---------------------------------------------------------------------------
// v2 (F-ss6): F-SS2 uniform-domain census rules R7..R10. Payload forms are
// the exact silicon-measured probe shapes (work/stallsuf/gen_ss.py v3).
// ---------------------------------------------------------------------------

#[test]
fn r7_urpath_d0_attribution_at_floor4() {
    // UIADD3 UR chain: in-domain uniform ALU behaves exactly like vector
    // ALU (floor 4 == R1); R7 only adds attribution.
    let src = kern(&[
        "[B------:R-:W-:-:S00] UIADD3 UR16, UPT,UPT, UR16, UR40, UR63",
        "[B------:R-:W-:-:S00] UIADD3 UR17, UPT,UPT, UR16, UR41, UR63",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,2]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    let prod = k.raises.iter().find(|r| r.ins_idx == 0).unwrap();
    assert_eq!(prod.new_stall, 4);
    assert!(prod.rules.iter().any(|r| r == "R7-urpath"), "{:?}", prod.rules);
    let cons = k.raises.iter().find(|r| r.ins_idx == 1).unwrap();
    assert_eq!(cons.new_stall, 4);
    assert!(!cons.rules.iter().any(|r| r.starts_with("R7")));
}

#[test]
fn r7_ucarry_dual_carry_d0() {
    // UIADD3.X dual-carry chain (UP0/UP1): measured floor S04 (ucarry class).
    let src = kern(&[
        "[B------:R-:W-:-:S00] UIADD3.X UR16, UP0,UP1, UR16, UR40, UR63, UP0,UP1",
        "[B------:R-:W-:-:S00] UIADD3.X UR17, UP0,UP1, UR17, UR41, UR63, UP0,UP1",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,2]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    let prod = &k.raises[0];
    assert_eq!((prod.new_stall, prod.rules.contains(&"R7-urpath".to_string())), (4, true));
}

#[test]
fn r8_xread_d0_floor6() {
    // Uniform UR write consumed by a VECTOR op through a UR operand at d0
    // (measured uxread class): floor 6 (cross-domain +2).
    let src = kern(&[
        "[B------:R-:W-:-:S00] UIMAD.U32 UR18, UR40, 0x1, UR41",
        "[B------:R-:W-:-:S00] IADD3 R16, PT,PT, R16, UR18, RZ",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,2]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    let prod = k.raises.iter().find(|r| r.ins_idx == 0).unwrap();
    assert_eq!(prod.new_stall, 6);
    assert!(prod.rules.iter().any(|r| r == "R8-xread"), "{:?}", prod.rules);
}

#[test]
fn r8_vector_consumer_outside_window_invisible() {
    // Same pair but the consumer sits outside the window: the v2 rules are
    // window-scoped exactly like R1..R6.
    let src = kern(&[
        "[B------:R-:W-:-:S00] UIMAD.U32 UR18, UR40, 0x1, UR41",
        "[B------:R-:W-:-:S00] IADD3 R16, PT,PT, R16, UR18, RZ",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,1]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    let prod = k.raises.iter().find(|r| r.ins_idx == 0).unwrap();
    assert_eq!(prod.new_stall, 4);
    assert!(!prod.rules.iter().any(|r| r == "R8-xread"));
}

#[test]
fn r9_r2ur_boundary_both_directions_floor8() {
    // Measured usr2ur decomposition: hop A (vector R write -> R2UR read)
    // and hop B (R2UR UR write -> consumer) both floor 8 at d0.
    let src = kern(&[
        "[B------:R-:W-:-:S00] IADD3 R16, PT,PT, R17, R18, RZ",
        "[B------:R-:W-:-:S00] R2UR UR24, R16",
        "[B------:R-:W-:-:S00] UIADD3 UR20, UPT,UPT, UR20, UR24, UR63",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,3]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    let a = k.raises.iter().find(|r| r.ins_idx == 0).unwrap();
    assert_eq!(a.new_stall, 8);
    assert!(a.rules.iter().any(|r| r == "R9-r2ur"), "{:?}", a.rules);
    let b = k.raises.iter().find(|r| r.ins_idx == 1).unwrap();
    assert_eq!(b.new_stall, 8);
    assert!(b.rules.iter().any(|r| r == "R9-r2ur"), "{:?}", b.rules);
    // the uniform consumer itself carries only the R1 floor
    let c = k.raises.iter().find(|r| r.ins_idx == 2).unwrap();
    assert_eq!(c.new_stall, 4);
}

#[test]
fn r10_uguard_d0_floor10_d1_floor8_d2_clean() {
    // usetp_g class: UISETP.UP write -> @UP guarded uniform consumer.
    // d0 (adjacent)
    let src = kern(&[
        "[B------:R-:W-:-:S01] UISETP.GE.AND UP2, UPT, UR16, UR40, UPT",
        "[B------:R-:W-:-:S00] @UP2 UIADD3 UR20, UPT,UPT, UR20, UR42, UR63",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,2]]"), &rules()).unwrap();
    let prod = &run.report.kernels[0].raises[0];
    assert_eq!(prod.new_stall, 10);
    assert!(prod.rules.iter().any(|r| r == "R10-uguard-d0"));

    // d1 (one in between): FLOOR 8, and crucially NOT the P-domain D1
    // pathology -- legal, repairable, no violation, no site record.
    let src1 = kern(&[
        "[B------:R-:W-:-:S01] UISETP.GE.AND UP2, UPT, UR16, UR40, UPT",
        "[B------:R-:W-:-:S02] UIADD3 UR17, UPT,UPT, UR17, UR41, UR63",
        "[B------:R-:W-:-:S00] @UP2 UIADD3 UR20, UPT,UPT, UR20, UR42, UR63",
        "EXIT",
    ]);
    let run1 = run_file(&src1, &pl("[[0,3]]"), &rules()).unwrap();
    let k1 = &run1.report.kernels[0];
    let prod1 = k1.raises.iter().find(|r| r.ins_idx == 0).unwrap();
    assert_eq!(prod1.new_stall, 8);
    assert!(prod1.rules.iter().any(|r| r == "R10-uguard-d1"));
    assert!(k1.d1_sites.is_empty(), "{:?}", k1.d1_sites);

    // d2 (two in between): clean at any stall -- only the R1 floor.
    let src2 = kern(&[
        "[B------:R-:W-:-:S01] UISETP.GE.AND UP2, UPT, UR16, UR40, UPT",
        "[B------:R-:W-:-:S02] UIADD3 UR17, UPT,UPT, UR17, UR41, UR63",
        "[B------:R-:W-:-:S00] UIADD3 UR19, UPT,UPT, UR19, UR41, UR63",
        "[B------:R-:W-:-:S00] @UP2 UIADD3 UR20, UPT,UPT, UR20, UR42, UR63",
        "EXIT",
    ]);
    let run2 = run_file(&src2, &pl("[[0,4]]"), &rules()).unwrap();
    let prod2 = run2.report.kernels[0].raises.iter().find(|r| r.ins_idx == 0).unwrap();
    assert_eq!(prod2.new_stall, 4);
    assert!(!prod2.rules.iter().any(|r| r.starts_with("R10")));
}

#[test]
fn r10_up_chain_kill_by_redefinition() {
    // A UISETP redefining UP2 ends the earlier producer's chain; only the
    // nearest producer pairs with the guard.
    let src = kern(&[
        "[B------:R-:W-:-:S01] UISETP.GE.AND UP2, UPT, UR16, UR40, UPT",
        "[B------:R-:W-:-:S04] UISETP.LT.AND UP2, UPT, UR17, UR41, UPT",
        "[B------:R-:W-:-:S00] @!UP2 UIADD3 UR20, UPT,UPT, UR20, UR42, UR63",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,3]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    let first = k.raises.iter().find(|r| r.ins_idx == 0).unwrap();
    assert_eq!(first.new_stall, 4); // R1 only -- chain killed at idx 1
    let second = k.raises.iter().find(|r| r.ins_idx == 1).unwrap();
    assert_eq!(second.new_stall, 10);
    assert!(second.rules.iter().any(|r| r == "R10-uguard-d0"));
}

#[test]
fn r10_raise_only_above_cap_untouched() {
    // Producer already in the S>=12 zone: raise-only never lowers, the
    // R10 floor (10) stays below it, and the input is reported.
    let src = kern(&[
        "[B------:R-:W-:-:S12] UISETP.GE.AND UP2, UPT, UR16, UR40, UPT",
        "[B------:R-:W-:-:S00] @UP2 UIADD3 UR20, UPT,UPT, UR20, UR42, UR63",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,2]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    assert_eq!(k.n_raises, 1); // only the consumer's R1 raise
    assert_eq!(k.input_above_cap, vec![0]);
    let out_first = run.out_text.lines().nth(1).unwrap();
    assert!(out_first.contains("S12"), "{out_first}");
}

#[test]
fn v2_rules_sanity_rejects_floor_above_cap() {
    let raw = serde_json::json!({
        "arch": "sm_103a", "cap_stall": 11, "floor_global": 4,
        "floor_dmix_d0": 5, "floor_guard_d0": 7, "floor_guard_d2": 5,
        "floor_r2ur_d0": 12
    });
    let err = StallRules::from_str_json(&raw.to_string()).unwrap_err();
    assert!(err.to_string().contains("floor_r2ur_d0"), "{err}");
}

#[test]
fn v2_rules_version_flows_to_report() {
    let src = kern(&["[B------:R-:W-:-:S00] IADD3 R2, R0, R1, RZ", "EXIT"]);
    let run = run_file(&src, &pl("[[0,1]]"), &rules()).unwrap();
    assert_eq!(run.report.rules_version, "v2");
}

#[test]
fn v2_p_domain_behavior_unchanged_on_uniform_free_input() {
    // Mixed kernel: P-domain rules fire exactly as v1, uniform rules do not
    // interfere (no tracked state crosses domains).
    let src = kern(&[
        "[B------:R-:W-:-:S00] ISETP.GT.U32.AND P2, PT, R0, R1, PT",
        "[B------:R-:W-:-:S00] @P2 IADD3 R5, R3, R4, RZ",
        "[B------:R-:W-:-:S00] UIADD3 UR16, UPT,UPT, UR16, UR40, UR63",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,3]]"), &rules()).unwrap();
    let k = &run.report.kernels[0];
    let prod = k.raises.iter().find(|r| r.ins_idx == 0).unwrap();
    assert_eq!(prod.new_stall, 7); // R3-guard-d0, unchanged
    assert!(prod.rules.iter().any(|r| r == "R3-guard-d0"));
    let uni = k.raises.iter().find(|r| r.ins_idx == 2).unwrap();
    assert_eq!(uni.new_stall, 4);
}
