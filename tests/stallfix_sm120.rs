//! SM120 `stallfix` rules (v3), measured 2026-11-03 on 4x NVIDIA RTX PRO 6000 Server Edition
//! (cubit session T harness `tools/stallfloor/`, 370 cubit-assembled kernels, 32 CTAs x 1 024
//! threads x 20 repetitions; docs/SM120_STALLFIX_PLAN.md §4 lists the 23 floors and their reading).
//! The section lives in `tables/sm120.json`; this file pins what the pass does with it:
//!
//! * the measured floors land as raises on the producer of each path's d0 pair (rpath 4, dmix 5,
//!   pcarry 5 (R11, new: a predicate read as data), xread 6, uguard 10) and the d1/d2 keys that
//!   sm_103a never had (pcarry d1 4, urpath d1 3, xread d1 4 / d2 2, uguard d2 6, guard d2 9);
//! * a predicate producer directly followed by its `@P` guard consumer needs S13 on SM120 (v4, measured
//!   2026-11-05 in the S12..S15 band: S12 still wrong, S13..S15 clean; the v3 sweep ended at S11 and
//!   called the site a violation);
//!   guard at d1 is a raise to 11 for every consumer class (`floor_guard_d1`, the single clean
//!   value measured), not the sm_103a class split;
//! * R2UR boundaries raise to the cap (11): the measurement's CPU model was wrong for that path,
//!   so the pass takes the most conservative legal stall instead of a guess;
//! * the arch lock refuses an sm_103a plan against SM120 rules; the sm_103a v2 section is
//!   unaffected by the new keys (their defaults mean "no rule").
use cubit::stallfix::{run_file, StallFixPlan, StallRules};

fn rules() -> StallRules {
    StallRules::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn pl(windows: &str) -> StallFixPlan {
    serde_json::from_str::<StallFixPlan>(&format!(
        r#"{{"arch":"sm_120","kernels":{{"k":{{"windows":{windows}}}}}}}"#
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

/// stall the pass gives instruction `idx` of a two/three-instruction window at S00 everywhere
fn raised_to(insns: &[&str], idx: u32) -> (u8, Vec<String>) {
    let src = kern(insns);
    let n = insns.len() as u32 - 1; // EXIT closes every kernel here
    let run = run_file(&src, &pl(&format!("[[0,{n}]]")), &rules()).unwrap();
    let k = &run.report.kernels[0];
    match k.raises.iter().find(|r| r.ins_idx == idx) {
        Some(r) => (r.new_stall, r.rules.clone()),
        None => (0, vec![]),
    }
}

#[test]
fn section_is_the_measured_sm120_set() {
    let r = rules();
    assert_eq!(r.arch, "sm_120");
    assert_eq!(r.rules_version, "v4"); // 2026-11-05: guard d0 measured in the S12..S15 band
    assert_eq!(r.cap_stall, 15);
    assert_eq!((r.floor_global, r.floor_dmix_d0), (4, 5));
    assert_eq!((r.floor_pcarry_d0, r.floor_pcarry_d1), (5, 4));
    assert!(!r.guard_d0_forbid && !r.guard_d1_forbid);
    assert_eq!((r.floor_guard_d0, r.floor_guard_d1, r.floor_guard_d2), (13, 11, 9), "guard d0 13 measured 2026-11-05 (harness v4, S12..S15 band: S12 wrong, S13..S15 clean)");
    assert_eq!((r.floor_xread_d0, r.floor_xread_d1, r.floor_xread_d2), (6, 4, 2));
    assert_eq!(r.floor_urpath_d1, 3);
    assert_eq!((r.floor_uguard_d0, r.floor_uguard_d1, r.floor_uguard_d2), (10, 8, 6));
    assert_eq!(r.floor_r2ur_d0, r.floor_global, "r2ur measured 2026-11-04 (4x RTX PRO 6000 Server Edition, v3 warp-uniform kernels): floor 4 = floor_global");
    assert!(r.provenance["measured"].as_str().unwrap().contains("RTX PRO 6000"));
    assert_eq!(r.provenance["stall_floors_json_sha256"].as_str().map(str::len), Some(64));
}

#[test]
fn sm103a_section_keeps_its_v2_behaviour() {
    let r = StallRules::load(std::path::Path::new("tables/sm103a.json")).unwrap();
    assert_eq!(r.rules_version, "v2");
    assert_eq!((r.floor_pcarry_d0, r.floor_pcarry_d1, r.floor_guard_d1), (0, 0, 0));
    assert!(!r.guard_d0_forbid && r.guard_d1_forbid);
    assert_eq!((r.floor_urpath_d1, r.floor_xread_d1, r.floor_xread_d2, r.floor_uguard_d2), (0, 0, 0, 0));
}

#[test]
fn arch_lock_refuses_an_sm103a_plan() {
    let src = kern(&["[B------:R-:W-:-:S00] IADD3 R2, R0, R1, RZ", "EXIT"]);
    let plan = serde_json::from_str::<StallFixPlan>(
        r#"{"arch":"sm_103a","kernels":{"k":{"windows":[[0,1]]}}}"#).unwrap();
    let err = run_file(&src, &plan, &rules()).unwrap_err().to_string();
    assert!(err.contains("sm_103a") && err.contains("sm_120"), "{err}");
}

#[test]
fn rpath_d0_floor4_r1() {
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S00] IADD3 R6, PT, PT, R4, R5, RZ",
        "[B------:R-:W-:-:S00] IADD3 R8, PT, PT, R6, R5, RZ",
        "EXIT"], 0);
    assert_eq!(s, 4);
    assert_eq!(why, vec!["R1".to_string()]);
}

#[test]
fn dmix_d0_floor5() {
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S00] IMAD.WIDE.U32 R6, P0, R4, R5, RZ",
        "[B------:R-:W-:-:S00] IADD3.X R8, PT, PT, R6, R5, RZ, P0, !PT",
        "EXIT"], 0);
    assert_eq!(s, 5);
    assert!(why.iter().any(|r| r == "R2-dmix-d0"), "{why:?}");
}

#[test]
fn pcarry_d0_floor5_and_d1_floor4_r11() {
    // the measured pair: ISETP writes P0, SEL reads it as a data operand
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S00] ISETP.LT.U32.AND P0, PT, R4, R5, PT",
        "[B------:R-:W-:-:S00] SEL R8, R4, R5, P0",
        "EXIT"], 0);
    assert_eq!(s, 5);
    assert!(why.iter().any(|r| r == "R11-pcarry-d0"), "{why:?}");
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S00] ISETP.LT.U32.AND P0, PT, R4, R5, PT",
        "[B------:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ",
        "[B------:R-:W-:-:S00] SEL R8, R4, R5, P0",
        "EXIT"], 0);
    assert_eq!(s, 4);
    assert!(why.iter().any(|r| r == "R11-pcarry-d1"), "{why:?}");
    // a carry-in read is not a pcarry read (xchain measured 4 = R1 at d0, free at d1)
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S00] IADD3.X R6, P0, PT, R4, R5, RZ, PT, !PT",
        "[B------:R-:W-:-:S00] IADD3.X R8, PT, PT, R6, R5, RZ, P0, !PT",
        "EXIT"], 0);
    assert_eq!(s, 4);
    assert!(!why.iter().any(|r| r.starts_with("R11")), "{why:?}");
}

/// 2026-11-05 (harness v4, T-5): guard at d0 is a raise to 13, not a violation. The v3 sweep ended at
/// S11 (all wrong); S12 is still wrong, S13 / S14 / S15 are clean — on the data consumer and on a
/// guarded branch alike. cubit's own `schedule()` emits S14 before `@P BRA` (one above the floor).
#[test]
fn guard_d0_is_raised_to_13_on_sm120() {
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S09] ISETP.LT.U32.AND P0, PT, R4, R5, PT",
        "[B------:R-:W-:-:S04] @P0 IADD3 R8, PT, PT, R4, R5, RZ",
        "EXIT"], 0);
    assert_eq!(s, 13);
    assert!(why.iter().any(|r| r == "R3-guard-d0"), "{why:?}");
    // S14 (what schedule() writes before a guarded branch) is above the floor: nothing to raise
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S14] ISETP.LT.U32.AND P0, PT, R4, R5, PT",
        "[B------:R-:W-:-:S05] @P0 IADD3 R8, PT, PT, R4, R5, RZ",
        "EXIT"], 0);
    assert_eq!((s, why.len()), (0, 0), "no raise record expected for a producer already at S14");
}

#[test]
fn guard_d1_floor11_every_class_and_d2_floor9() {
    // data-class consumer at d1: the sm_103a pathology does not apply; raise to 11
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S00] ISETP.LT.U32.AND P0, PT, R4, R5, PT",
        "[B------:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ",
        "[B------:R-:W-:-:S00] @P0 IADD3 R8, PT, PT, R4, R5, RZ",
        "EXIT"], 0);
    assert_eq!(s, 11);
    assert!(why.iter().any(|r| r == "R3-guard-d1"), "{why:?}");
    // isetp-class consumer at d1: the same 11 (no class split was measured on SM120)
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S00] ISETP.LT.U32.AND P0, PT, R4, R5, PT",
        "[B------:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ",
        "[B------:R-:W-:-:S00] @P0 ISETP.GT.U32.AND P1, PT, R4, R5, PT",
        "EXIT"], 0);
    assert_eq!(s, 11);
    assert!(why.iter().any(|r| r == "R3-guard-d1"), "{why:?}");
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S00] ISETP.LT.U32.AND P0, PT, R4, R5, PT",
        "[B------:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ",
        "[B------:R-:W-:-:S01] IADD3 R16, PT, PT, R16, 0x1, RZ",
        "[B------:R-:W-:-:S00] @P0 IADD3 R8, PT, PT, R4, R5, RZ",
        "EXIT"], 0);
    assert_eq!(s, 9);
    assert!(why.iter().any(|r| r == "R3-guard-d2"), "{why:?}");
}

#[test]
fn uniform_domain_floors() {
    // xread d0 6 / d1 4 / d2 2
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S00] UIADD3 UR8, UPT, UPT, UR8, 0x3, URZ",
        "[B------:R-:W-:-:S00] IADD3 R8, PT, PT, R4, UR8, RZ",
        "EXIT"], 0);
    assert_eq!((s, why.iter().any(|r| r == "R8-xread")), (6, true), "{why:?}");
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S00] UIADD3 UR8, UPT, UPT, UR8, 0x3, URZ",
        "[B------:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ",
        "[B------:R-:W-:-:S00] IADD3 R8, PT, PT, R4, UR8, RZ",
        "EXIT"], 0);
    assert_eq!((s, why.iter().any(|r| r == "R8-xread-d1")), (4, true), "{why:?}");
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S00] UIADD3 UR8, UPT, UPT, UR8, 0x3, URZ",
        "[B------:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ",
        "[B------:R-:W-:-:S01] IADD3 R16, PT, PT, R16, 0x1, RZ",
        "[B------:R-:W-:-:S00] IADD3 R8, PT, PT, R4, UR8, RZ",
        "EXIT"], 0);
    // the window's R1 floor (4) is larger than the measured d2 floor (2): R1 wins, R8-xread-d2 attributes
    assert_eq!((s, why.iter().any(|r| r == "R8-xread-d2")), (4, true), "{why:?}");
    // urpath d0 4 (R1/R7) / d1 3 (R1 wins at 4, attribution recorded)
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S00] UIADD3 UR8, UPT, UPT, UR8, 0x3, URZ",
        "[B------:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ",
        "[B------:R-:W-:-:S00] UIADD3 UR9, UPT, UPT, UR8, 0x5, URZ",
        "EXIT"], 0);
    assert_eq!((s, why.iter().any(|r| r == "R7-urpath-d1")), (4, true), "{why:?}");
    // uguard d0 10 / d1 8 / d2 6
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S00] UISETP.LT.U32.AND UP0, UPT, UR8, 0x80000000, UPT",
        "[B------:R-:W-:-:S00] @UP0 UIADD3 UR9, UPT, UPT, UR9, 0x5, URZ",
        "EXIT"], 0);
    assert_eq!((s, why.iter().any(|r| r == "R10-uguard-d0")), (10, true), "{why:?}");
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S00] UISETP.LT.U32.AND UP0, UPT, UR8, 0x80000000, UPT",
        "[B------:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ",
        "[B------:R-:W-:-:S00] @UP0 UIADD3 UR9, UPT, UPT, UR9, 0x5, URZ",
        "EXIT"], 0);
    assert_eq!((s, why.iter().any(|r| r == "R10-uguard-d1")), (8, true), "{why:?}");
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S00] UISETP.LT.U32.AND UP0, UPT, UR8, 0x80000000, UPT",
        "[B------:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ",
        "[B------:R-:W-:-:S01] IADD3 R16, PT, PT, R16, 0x1, RZ",
        "[B------:R-:W-:-:S00] @UP0 UIADD3 UR9, UPT, UPT, UR9, 0x5, URZ",
        "EXIT"], 0);
    assert_eq!((s, why.iter().any(|r| r == "R10-uguard-d2")), (6, true), "{why:?}");
}

#[test]
fn r2ur_boundary_floor_measured() {
    // r2ur measured 2026-11-04 (v3 warp-uniform kernels, model_r2ur PASS): floor 4 at d0,
    // == floor_global (was raised to the cap while unmeasured).
    let (s, why) = raised_to(&[
        "[B------:R-:W-:-:S00] IADD3 R6, PT, PT, R4, R5, RZ",
        "[B------:R-:W-:-:S00] R2UR UR9, R6",
        "EXIT"], 0);
    assert_eq!((s, why.iter().any(|r| r == "R9-r2ur")), (4, true), "{why:?}");
}

#[test]
fn raised_text_differs_only_in_stall_digits() {
    let src = kern(&[
        "[B------:R-:W-:-:S00] ISETP.LT.U32.AND P0, PT, R4, R5, PT",
        "[B------:R-:W-:-:S00] SEL R8, R4, R5, P0",
        "EXIT"]);
    let run = run_file(&src, &pl("[[0,2]]"), &rules()).unwrap();
    for (a, b) in src.lines().zip(run.out_text.lines()) {
        let diffs: Vec<(u8, u8)> = a.bytes().zip(b.bytes()).filter(|(x, y)| x != y).collect();
        assert!(diffs.len() <= 2, "{a} vs {b}");
    }
}
