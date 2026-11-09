//! POSTFIX-103 v3-data (B300 stall floors 2026-11-07, BARRACUDA
//! tables/stallfix_sm103a_v3_20261107.json): the producer classes the
//! v0..v3 allowlist never carried -- IMAD / FMA-pipe / F2FP data results,
//! UMOV, MUFU without a scoreboard, and the split R2UR hops. Every new key
//! defaults to "no rule", so the sm_103a v2 section keeps its behaviour.

use cubit::stallfix::{run_file, StallFixPlan, StallRules};

const V3: &str = r#"{
 "arch": "sm_103a", "rules_version": "v3-data-20261107", "cap_stall": 11,
 "floor_global": 4, "floor_dmix_d0": 5,
 "guard_d0_forbid": true, "floor_guard_d0": 11, "measured_guard_d0": 13,
 "guard_d1_forbid": false, "floor_guard_d1": 11, "guard_d1_isetp_floor": 11, "floor_guard_d2": 9,
 "legacy_stall_risk_from": 12,
 "floor_xread_d0": 6, "floor_xread_d1": 4, "floor_xread_d2": 2,
 "floor_r2ur_d0": 8, "floor_r2ur_in_d0": 4, "floor_r2ur_out_d1": 6, "floor_r2ur_out_d2": 4,
 "floor_uguard_d0": 10, "floor_uguard_d1": 8, "floor_uguard_d2": 6,
 "floor_urpath_d1": 3, "floor_pcarry_d0": 4, "floor_pcarry_d1": 0,
 "floor_imad_d0": 5, "floor_imad_d1": 3, "floor_fma_d0": 4, "floor_fma_d1": 3,
 "floor_f2fp_d0": 4, "floor_umov_d0": 0, "mufu_scoreboard_only": true
}"#;

fn v3() -> StallRules {
    StallRules::from_str_json(V3).unwrap()
}

fn v2() -> StallRules {
    StallRules::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn pl(windows: &str) -> StallFixPlan {
    serde_json::from_str::<StallFixPlan>(&format!(
        r#"{{"arch":"sm_103a","kernels":{{"k":{{"windows":{windows}}}}}}}"#
    ))
    .unwrap()
}

fn kern(insns: &[&str]) -> String {
    let mut v = vec![".entry k".to_string()];
    for l in insns {
        v.push(format!("    {l} ;"));
    }
    v.push(".endentry".into());
    v.join("\n") + "\n"
}

fn raise_of(run: &cubit::stallfix::StallFixRun, idx: u32) -> Option<(u8, u8, Vec<String>)> {
    run.report.kernels[0]
        .raises
        .iter()
        .find(|r| r.ins_idx == idx)
        .map(|r| (r.old_stall, r.new_stall, r.rules.clone()))
}

#[test]
fn v3data_keys_load_and_default_to_no_rule() {
    let r = v3();
    assert_eq!((r.floor_imad_d0, r.floor_imad_d1, r.floor_fma_d0, r.floor_fma_d1, r.floor_f2fp_d0), (5, 3, 4, 3, 4));
    assert_eq!((r.floor_r2ur_in_d0, r.floor_r2ur_out_d1, r.floor_r2ur_out_d2), (4, 6, 4));
    assert!(r.mufu_scoreboard_only && r.guard_d0_forbid);
    assert_eq!(r.measured_guard_d0, 13);
    let old = v2();
    assert_eq!((old.floor_imad_d0, old.floor_fma_d1, old.floor_f2fp_d0, old.floor_r2ur_in_d0), (0, 0, 0, 0));
    assert!(!old.mufu_scoreboard_only);
}

#[test]
fn v3data_sanity_rejects_new_floor_above_cap() {
    let bad = V3.replace(r#""floor_imad_d0": 5"#, r#""floor_imad_d0": 12"#);
    assert!(StallRules::from_str_json(&bad).is_err());
}

#[test]
fn r12_imad_data_result_d0_and_d1() {
    let src = kern(&[
        "[B------:R-:W-:-:S04] IMAD R6, R4, R5, RZ",        // 0: IMAD -> IADD3 at d0 needs 5
        "[B------:R-:W-:-:S04] IADD3 R8, PT, PT, R6, R5, RZ",
        "[B------:R-:W-:-:S04] IMAD R9, R4, R5, RZ",        // 2: IMAD -> consumer at d1 needs 3 (R1 already 4)
        "[B------:R-:W-:-:S04] IADD3 R15, PT, PT, R15, 0x1, RZ",
        "[B------:R-:W-:-:S04] IADD3 R10, PT, PT, R9, R5, RZ",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,5]]"), &v3()).unwrap();
    let (old, new, rules) = raise_of(&run, 0).expect("IMAD at d0 raised");
    assert_eq!((old, new), (4, 5));
    assert!(rules.iter().any(|r| r == "R12-imad-d0"), "{rules:?}");
    assert!(raise_of(&run, 2).is_none(), "d1 floor 3 is below the R1 floor already present");
    // the same text under the v2 rules: no IMAD raise at all
    let run2 = run_file(&src, &pl("[[0,5]]"), &v2()).unwrap();
    assert!(raise_of(&run2, 0).is_none());
}

#[test]
fn r13_fma_pipe_d1_needs_s03_only_below_global_floor_not_visible() {
    // R1 raises every in-window stall to 4 already, so the d1 floor 3 only
    // shows through its rule attribution when the producer sits below it.
    let src = kern(&[
        "[B------:R-:W-:-:S02] FFMA R6, R4, R5, R4",
        "[B------:R-:W-:-:S04] IADD3 R15, PT, PT, R15, 0x1, RZ",
        "[B------:R-:W-:-:S04] FFMA R8, R6, R5, RZ",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,3]]"), &v3()).unwrap();
    let (old, new, rules) = raise_of(&run, 0).expect("FFMA raised");
    assert_eq!((old, new), (2, 4));
    assert!(rules.iter().any(|r| r == "R13-fma-d1"), "{rules:?}");
    assert!(rules.iter().any(|r| r == "R1"), "{rules:?}");
}

#[test]
fn r14_f2fp_d0() {
    let src = kern(&[
        "[B------:R-:W-:-:S04] F2FP.BF16.F32.PACK_AB R6, R4, R5",
        "[B------:R-:W-:-:S04] IADD3 R8, PT, PT, R6, R5, RZ",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,2]]"), &v3()).unwrap();
    // measured floor 4 == R1: legal as written, attribution only
    assert!(raise_of(&run, 0).is_none());
    let bumped = V3.replace(r#""floor_f2fp_d0": 4"#, r#""floor_f2fp_d0": 6"#);
    let run = run_file(&src, &pl("[[0,2]]"), &StallRules::from_str_json(&bumped).unwrap()).unwrap();
    let (old, new, rules) = raise_of(&run, 0).expect("F2FP raised under a higher data floor");
    assert_eq!((old, new), (4, 6));
    assert!(rules.iter().any(|r| r == "R14-f2fp-d0"), "{rules:?}");
}

#[test]
fn imad_display_aliases_do_not_use_the_arithmetic_floor() {
    let elevated = V3.replace(r#""floor_imad_d0": 5"#, r#""floor_imad_d0": 9"#);
    let rules = StallRules::from_str_json(&elevated).unwrap();
    for (index, alias) in [
        "IMAD.MOV.U32 R6, RZ, RZ, 0x1",
        "IMAD.IADD R6, R4, R5, RZ",
        "IMAD.SHL.U32 R6, R4, 0x1, RZ",
        "IMAD.SHR R6, R4, 0x1, RZ",
    ].into_iter().enumerate() {
        let src = kern(&[
            &format!("[B------:R-:W-:-:S04] {alias}"),
            "[B------:R-:W-:-:S04] IADD3 R8, PT, PT, R6, R5, RZ",
            "EXIT",
        ]);
        let run = run_file(&src, &pl("[[0,2]]"), &rules).unwrap();
        assert!(raise_of(&run, 0).is_none(), "alias {index} inherited IMAD floor");
    }
}

#[test]
fn r16_mufu_without_scoreboard_is_a_violation() {
    let src = kern(&[
        "[B------:R-:W-:-:S15] MUFU.RCP R6, R4",
        "[B------:R-:W-:-:S04] FFMA R8, R6, R5, RZ",
        "EXIT",
    ]);
    let err = run_file(&src, &pl("[[0,2]]"), &v3()).unwrap_err().to_string();
    assert!(err.contains("MUFU"), "{err}");
    // with a write barrier on the MUFU the pass is silent (the consumer's wait is the scoreboard's job)
    let ok = kern(&[
        "[B------:R-:W0:-:S01] MUFU.RCP R6, R4",
        "[B0-----:R-:W-:-:S04] FFMA R8, R6, R5, RZ",
        "EXIT",
    ]);
    assert!(run_file(&ok, &pl("[[0,2]]"), &v3()).is_ok());
    // the v2 rules do not know the class: no error
    assert!(run_file(&src, &pl("[[0,2]]"), &v2()).is_ok());
}

#[test]
fn r9_split_r2ur_hops() {
    let src = kern(&[
        "[B------:R-:W-:-:S04] IADD3 R6, PT, PT, R4, R5, RZ",   // 0: vector -> R2UR at d0: in-hop 4 (v2: 8)
        "[B------:R-:W-:-:S04] R2UR UR9, R6",                   // 1: R2UR -> UIADD3 at d1: out-hop 6
        "[B------:R-:W-:-:S04] IADD3 R15, PT, PT, R15, 0x1, RZ",
        "[B------:R-:W-:-:S04] UIADD3 UR10, UPT, UPT, UR9, 0x5, URZ",
        "EXIT",
    ]);
    let run = run_file(&src, &pl("[[0,4]]"), &v3()).unwrap();
    assert!(raise_of(&run, 0).is_none(), "in-hop floor 4 == R1 under v3-data");
    let (old, new, rules) = raise_of(&run, 1).expect("R2UR out-hop at d1 raised");
    assert_eq!((old, new), (4, 6));
    assert!(rules.iter().any(|r| r == "R9-r2ur-out-d1"), "{rules:?}");
    let run2 = run_file(&src, &pl("[[0,4]]"), &v2()).unwrap();
    let (old, new, rules) = raise_of(&run2, 0).expect("v2 raises the in-hop to 8");
    assert_eq!((old, new), (4, 8));
    assert!(rules.iter().any(|r| r == "R9-r2ur"), "{rules:?}");
}
