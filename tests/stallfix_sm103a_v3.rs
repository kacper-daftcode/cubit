//! sm_103a `stallfix` rules v3 -- the `stallfix` section of `tables/sm103a.json` since 2026-11 -- measured on B300
//! with the SM120 stall-floor harness of `tools/stallfloor/` ported to sm_103a (one cubit-assembled kernel per path,
//! distance and producer stall S00..S15, no yield flag, 32 CTAs x 1 024 threads x 20 launches = 655 360 thread-runs per
//! kernel, the reference of a path is its own kernel with the tested edge behind a scoreboard; four nights, 42 paths;
//! docs/POSTFIX103_STALLFIX.md "v3" has the table). The section before it was v2, the census of 2026-08-22.
//!
//! This file pins
//!
//! * that every numeric value of the section IS the measurement: the floors are recomputed here from the per-stall
//!   counts of the four raw result files (`tests/fixtures/stallfix_sm103a/stall_floors_*.json`, byte-identical to the
//!   files whose SHA-256 the section names) and each key is compared with the paths it stands for;
//! * what the pass does with the section, pair by pair as the harness measured them: a predicate producer directly in
//!   front of its `@P` guard is a violation (the floor 13 is above the cap 11) unless it already stands at S13..S15
//!   without the yield flag; one instruction between: 11 for a data consumer and an ISETP consumer, the atomic
//!   consumer and the ISETP consumer behind S12+ stay violations (v2's classes, not measured again); two between: 9;
//!   FSETP and ELECT are predicate producers next to ISETP; the R2UR hops 4 and 8 / 6 / 4; the uniform paths at d1 and
//!   d2; the IMAD class 5 / 3, the float class 4 / 3, F2FP 4, UMOV free, MUFU scoreboard only;
//! * the consumer class: a vector ALU result read by an IMAD needs 5 at d0 and 4 at d1 (R17), an IMAD result read by
//!   an IMAD needs 4 (R12 by consumer class), for the measured forms only.
//!
//! The v0..v2 semantics of the engine keep their own files on the frozen v2 rule set (`stallfix_ss.rs`,
//! `stallfix_v3data.rs`, the fixture `tests/fixtures/stallfix_sm103a/rules_v2.json`).
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use cubit::stallfix::{run_file, StallFixPlan, StallFixRun, StallRules};
use serde_json::Value;
use sha2::{Digest, Sha256};

const FIXTURES: &str = "tests/fixtures/stallfix_sm103a";
/// night letter of the section's provenance -> raw result file
const NIGHTS: [(&str, &str); 4] = [
    ("a", "stall_floors_20261107.json"),
    ("b", "stall_floors_imad_forms_20261109.json"),
    ("c", "stall_floors_imad_forms_20261110.json"),
    ("d", "stall_floors_imad_forms_20261111.json"),
];
/// thread-runs per kernel: 32 CTAs x 1 024 threads x 20 launches
const RUNS: u64 = 32 * 1024 * 20;

fn rules() -> StallRules {
    StallRules::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn rules_v2() -> StallRules {
    StallRules::load(std::path::Path::new("tests/fixtures/stallfix_sm103a/rules_v2.json")).unwrap()
}

/// the section as JSON (the keys by name, the provenance)
static SECTION: LazyLock<Value> = LazyLock::new(|| {
    let table: Value = serde_json::from_str(&cubit::table::read_table_text("tables/sm103a.json").unwrap()).unwrap();
    table["stallfix"].clone()
});

/// One night: `"<path>_d<distance>"` -> wrong thread-runs per producer stall S00..S15.
type Cells = BTreeMap<(String, usize), [u64; 16]>;

fn night(file: &str) -> (Vec<u8>, Cells, Value) {
    let bytes = std::fs::read(format!("{FIXTURES}/{file}")).unwrap();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["arch"], "sm_103a");
    assert_eq!((v["threads"].as_u64(), v["ctas"].as_u64(), v["reps"].as_u64()), (Some(1024), Some(32), Some(20)));
    let mut cells = Cells::new();
    for (key, by) in v["mismatches"].as_object().unwrap() {
        let (path, d) = key.rsplit_once("_d").unwrap();
        let mut row = [u64::MAX; 16];
        for (s, n) in by.as_object().unwrap() {
            row[s.parse::<usize>().unwrap()] = n.as_u64().unwrap();
        }
        assert!(row.iter().all(|&n| n <= RUNS), "{key}: every stall S00..S15 has a count");
        cells.insert((path.to_string(), d.parse().unwrap()), row);
    }
    (bytes, cells, v)
}

/// The harness's floor: the smallest stall with no wrong thread-run such that every larger stall is clean as well;
/// `None` = S15 itself is not clean (variable latency: only a scoreboard schedules it).
fn floor(row: &[u64; 16]) -> Option<u8> {
    if row[15] != 0 {
        return None;
    }
    (0..16u8).find(|&s| row[s as usize..].iter().all(|&n| n == 0))
}

/// path -> (d0, d1, d2) over the four nights; a path measured on several nights has the same floors on each.
static MEASURED: LazyLock<BTreeMap<String, [Option<u8>; 3]>> = LazyLock::new(|| {
    let mut out: BTreeMap<String, [Option<u8>; 3]> = BTreeMap::new();
    let mut seen: BTreeSet<(String, usize)> = BTreeSet::new();
    for (_, file) in NIGHTS {
        let (_, cells, v) = night(file);
        for ((path, d), row) in &cells {
            let f = floor(row);
            // the file's own `floors` entry is this definition
            let recorded = &v["floors"][format!("{path}_d{d}")];
            match f {
                Some(s) => assert_eq!(recorded.as_u64(), Some(s as u64), "{file} {path} d{d}"),
                None => assert_eq!(recorded, "NEEDS_SCOREBOARD", "{file} {path} d{d}"),
            }
            let slot = &mut out.entry(path.clone()).or_default()[*d];
            if !seen.insert((path.clone(), *d)) {
                assert_eq!(*slot, f, "{path} d{d}: the nights disagree ({file})");
            }
            *slot = f;
        }
    }
    out
});

fn pl(windows: &str) -> StallFixPlan {
    serde_json::from_str::<StallFixPlan>(&format!(r#"{{"arch":"sm_103a","kernels":{{"k":{{"windows":{windows}}}}}}}"#)).unwrap()
}

fn kern(insns: &[&str]) -> String {
    let mut v = vec![".entry k".to_string()];
    for l in insns {
        v.push(format!("    {l} ;"));
    }
    v.push(".endentry".into());
    v.join("\n") + "\n"
}

/// run the pass over a kernel whose last line (`EXIT`) closes it; the window is everything in front of it
fn run_with(insns: &[&str], r: &StallRules) -> anyhow::Result<StallFixRun> {
    let n = insns.len() - 1;
    run_file(&kern(insns), &pl(&format!("[[0,{n}]]")), r)
}

fn run(insns: &[&str]) -> StallFixRun {
    run_with(insns, &rules()).unwrap_or_else(|e| panic!("{insns:?}: {e:#}"))
}

/// (new stall, rules) of the raise of instruction `idx`; (0, []) when it is not raised
fn raised(r: &StallFixRun, idx: u32) -> (u8, Vec<String>) {
    match r.report.kernels[0].raises.iter().find(|x| x.ins_idx == idx) {
        Some(x) => (x.new_stall, x.rules.clone()),
        None => (0, vec![]),
    }
}

fn has(rules: &[String], name: &str) -> bool {
    rules.iter().any(|r| r == name)
}

const FILL: &str = "[B------:R-:W-:-:S01] IADD3 R15, PT, PT, R15, 0x1, RZ";
const GUARDED: &str = "[B------:R-:W-:-:S01] @P0 IADD3 R8, PT, PT, R4, R5, RZ";
/// the three predicate producers of the guard paths (`guard`, `fsetp_guard`, `elect_guard`)
const PRED_PRODUCERS: [&str; 3] = ["ISETP.LT.U32.AND P0, PT, R4, R5, PT", "FSETP.GT.AND P0, PT, R4, R5, PT", "ELECT P0, URZ, PT"];

// ---------------------------------------------------------------------------------------------------------------------
// the section is the measurement
// ---------------------------------------------------------------------------------------------------------------------

#[test]
fn section_is_the_measured_sm103a_set() {
    let r = rules();
    assert_eq!((r.arch.as_str(), r.rules_version.as_str()), ("sm_103a", "v3"));
    assert_eq!((r.floor_global, r.floor_dmix_d0), (4, 5));
    assert_eq!((r.floor_pcarry_d0, r.floor_pcarry_d1), (4, 0));
    // guard: 13 / 11 / 9. 13 is above the cap, so d0 is forbidden and the floor is carried as measured_guard_d0
    assert!(r.guard_d0_forbid);
    assert_eq!((r.measured_guard_d0, r.guard_d1_data_floor, r.floor_guard_d2), (13, 11, 9));
    assert_eq!(r.pred_producers_op0, ["FSETP", "ELECT"]);
    assert_eq!((r.floor_urpath_d1, r.floor_xread_d0, r.floor_xread_d1, r.floor_xread_d2), (3, 6, 4, 2));
    assert_eq!((r.floor_r2ur_in_d0, r.floor_r2ur_d0, r.floor_r2ur_out_d1, r.floor_r2ur_out_d2), (4, 8, 6, 4));
    assert_eq!((r.floor_uguard_d0, r.floor_uguard_d1, r.floor_uguard_d2), (10, 8, 6));
    assert_eq!((r.floor_imad_d0, r.floor_imad_d1, r.floor_imad_imad_d0), (5, 3, 4));
    assert_eq!((r.floor_alu_imad_d0, r.floor_alu_imad_d1), (5, 4));
    assert_eq!((r.floor_fma_d0, r.floor_fma_d1, r.floor_f2fp_d0, r.floor_umov_d0), (4, 3, 4, 0));
    assert!(r.mufu_scoreboard_only);
    // not from the 2026-11 measurement: the cap (the pass writes no S12..S15), v2's risk threshold and v2's
    // resolution of guard d1 by consumer class; the ISETP consumer takes the measured data-consumer floor (v2: 5, and
    // 11 is inside the band 5..=11 v2 called legal); floor_guard_d0 is not applied while d0 is forbidden
    assert_eq!((r.cap_stall, r.legacy_stall_risk_from, r.floor_guard_d0), (11, 12, 11));
    assert!(r.guard_d1_forbid);
    assert_eq!((r.guard_d1_isetp_floor, r.floor_guard_d1), (r.guard_d1_data_floor, 0));
    // what the section itself lists as not measured (yield with S12..S15, the other guard-d1 consumer classes, ...)
    assert_eq!(r.provenance["not_measured"].as_array().map(Vec::len), Some(8));
}

/// Every numeric rule of the section equals the floor of every path it stands for, recomputed from the raw counts.
#[test]
fn every_floor_is_recomputed_from_the_result_files() {
    let m = &*MEASURED;
    assert_eq!(m.len(), 42, "24 paths of 2026-11-07, 8 more IMAD forms of -09, 10 consumer-class / constant paths of -10");
    const ALU: [&str; 5] = ["rpath", "xchain", "lop3", "mov", "mov_imm"];
    const GUARD: [&str; 3] = ["guard", "fsetp_guard", "elect_guard"];
    const IMAD: [&str; 11] = [
        "imad", "imadwide_hi", "imad_mov", "imad_movs", "imad_iadd", "imad_shl", "imad_hi", "imad_u32", "imad_u32_ur",
        "imad_mov_imm", "imad_mov_clob",
    ];
    const FMA: [&str; 4] = ["ffma", "fmul", "fmul2", "hfma2"];
    const ALU_IMAD: [&str; 4] = ["alu_imad_a", "alu_imad_c", "lop3_imad_a", "mov_imad_a"];
    const IMAD_IMAD: [&str; 3] = ["imad_imad_a", "imad_imad_c", "imadmov_imad_a"];
    let keys: [(&str, &[&str], usize); 29] = [
        ("floor_global", &ALU, 0),
        ("floor_dmix_d0", &["dmix"], 0),
        ("floor_pcarry_d0", &["pcarry", "fsetp_sel"], 0),
        ("floor_pcarry_d1", &["pcarry", "fsetp_sel"], 1),
        ("measured_guard_d0", &GUARD, 0),
        ("guard_d1_data_floor", &GUARD, 1),
        ("floor_guard_d2", &GUARD, 2),
        ("floor_urpath_d1", &["urpath"], 1),
        ("floor_xread_d0", &["xread"], 0),
        ("floor_xread_d1", &["xread"], 1),
        ("floor_xread_d2", &["xread"], 2),
        ("floor_r2ur_in_d0", &["r2ur"], 0),
        ("floor_r2ur_d0", &["r2ur_out"], 0),
        ("floor_r2ur_out_d1", &["r2ur_out"], 1),
        ("floor_r2ur_out_d2", &["r2ur_out"], 2),
        ("floor_uguard_d0", &["uguard"], 0),
        ("floor_uguard_d1", &["uguard"], 1),
        ("floor_uguard_d2", &["uguard"], 2),
        ("floor_umov_d0", &["umov"], 0),
        ("floor_imad_d0", &IMAD, 0),
        ("floor_imad_d1", &IMAD, 1),
        ("floor_imad_imad_d0", &IMAD_IMAD, 0),
        ("floor_alu_imad_d0", &ALU_IMAD, 0),
        ("floor_alu_imad_d1", &ALU_IMAD, 1),
        ("floor_fma_d0", &FMA, 0),
        ("floor_fma_d1", &FMA, 1),
        ("floor_f2fp_d0", &["f2fp_pack", "f2fp_unpack"], 0),
        // the floors the section does not carry as a key of their own, stated in its comment
        ("floor_imad_d1", &IMAD_IMAD, 1), // an IMAD result read by an IMAD at d1: 3, like every consumer
        ("floor_global", &["urpath", "r2ur", "pcarry", "fsetp_sel", "ffma", "fmul", "fmul2", "hfma2", "f2fp_pack", "f2fp_unpack"], 0),
    ];
    for (key, paths, d) in keys {
        let want = SECTION[key].as_u64().unwrap_or_else(|| panic!("{key}: not a number in the section"));
        for path in paths {
            let got = m.get(*path).unwrap_or_else(|| panic!("{path}: not measured"))[d];
            assert_eq!(got.map(u64::from), Some(want), "{key} = {want}, but {path} d{d} measured {got:?}");
        }
    }
    // every key of the section that holds a number is either checked above or named as not measured
    let checked: BTreeSet<&str> = keys.iter().map(|k| k.0).collect();
    let unmeasured = ["cap_stall", "legacy_stall_risk_from", "floor_guard_d0", "guard_d1_isetp_floor"];
    for (key, value) in SECTION.as_object().unwrap() {
        if value.is_number() {
            assert!(checked.contains(key.as_str()) || unmeasured.contains(&key.as_str()), "{key}: a number with no measured path");
        }
    }
    // everything beyond the first slot is free where the section has no key for it
    for path in ALU.iter().chain(["pcarry", "fsetp_sel", "dmix", "r2ur", "f2fp_pack", "f2fp_unpack"].iter()) {
        assert_eq!(m[*path][1..], [Some(0), Some(0)], "{path}: d1 / d2");
    }
    for path in IMAD.iter().chain(FMA.iter()).chain(ALU_IMAD.iter()).chain(IMAD_IMAD.iter()).chain(["urpath"].iter()) {
        assert_eq!(m[*path][2], Some(0), "{path}: d2");
    }
    assert_eq!(m["umov"], [Some(0); 3]);
    // MUFU: no stall up to S15 is clean at any distance
    assert_eq!(m["mufu"], [None; 3]);
    assert_eq!(SECTION["mufu_scoreboard_only"], true);
    // guard d0 forbidden because the measured floor is above the cap
    assert!(SECTION["measured_guard_d0"].as_u64() > SECTION["cap_stall"].as_u64());
}

/// The provenance of the section: the hashes of the four result files, the measured table as text, and the facts its
/// comment states about the raw counts.
#[test]
fn provenance_matches_the_result_files() {
    let prov = &SECTION["provenance"];
    let hashes = prov["result_files_sha256"].as_object().unwrap();
    assert_eq!(hashes.len(), 4);
    let mut nights_of: BTreeMap<String, String> = BTreeMap::new();
    let mut all: Vec<(String, Cells)> = Vec::new();
    for (letter, file) in NIGHTS {
        let (bytes, cells, _) = night(file);
        let digest: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
        let (_, recorded) = hashes.iter().find(|(k, _)| k.starts_with(&format!("{letter} "))).unwrap();
        assert_eq!(recorded.as_str(), Some(digest.as_str()), "night {letter}: {file}");
        for (path, _) in cells.keys() {
            let n = nights_of.entry(path.clone()).or_default();
            if !n.contains(letter) {
                n.push_str(letter);
            }
        }
        all.push((letter.to_string(), cells));
    }
    // provenance.floors: "<d0> / <d1> / <d2> : <producer> -> <consumer> [<nights>]" for each of the 42 paths
    let table = prov["floors"].as_object().unwrap();
    assert_eq!(table.keys().map(String::as_str).collect::<BTreeSet<_>>(), MEASURED.keys().map(String::as_str).collect());
    for (path, text) in table {
        let text = text.as_str().unwrap();
        let want = MEASURED[path].iter().map(|f| f.map_or("SB".to_string(), |s| s.to_string())).collect::<Vec<_>>().join(" / ");
        assert!(text.starts_with(&format!("{want} : ")), "{path}: {text}");
        assert!(text.contains(" -> ") && text.ends_with(&format!(" [{}]", nights_of[path])), "{path}: {text}");
    }
    // kernels per night: paths x 3 distances x 16 stalls + one reference per path
    let kernels: Vec<usize> = all.iter().map(|(_, c)| c.len() * 16 + c.len() / 3).collect();
    assert_eq!(kernels, [1176, 588, 1078, 1078]);
    // S00 is clean in every cell of every path (the interlock); the S12..S15 columns are clean everywhere but under
    // guard d0 (S12 on the three producers) and MUFU
    let mut dirty_high = BTreeSet::new();
    for (_, cells) in &all {
        for ((path, d), row) in cells {
            assert_eq!(row[0], 0, "{path} d{d}: S00");
            for s in 12..16 {
                if row[s] != 0 {
                    dirty_high.insert((path.as_str(), *d, s));
                }
            }
        }
    }
    let guard_s12: BTreeSet<_> = [("guard", 0, 12), ("fsetp_guard", 0, 12), ("elect_guard", 0, 12)].into();
    assert_eq!(dirty_high.iter().filter(|x| x.0 != "mufu").copied().collect::<BTreeSet<_>>(), guard_s12);
    assert_eq!(dirty_high.iter().filter(|x| x.0 == "mufu").count(), 12, "MUFU: S12..S15 at d0, d1, d2");
    let a = &all[0].1;
    // the guard paths: not clean at S01 .. floor - 1, clean from the floor to S15, on each of the three producers
    for path in ["guard", "fsetp_guard", "elect_guard"] {
        for (d, fl) in [(0, 13), (1, 11), (2, 9)] {
            let row = &a[&(path.to_string(), d)];
            assert!(row[1..fl].iter().all(|&n| n > 0) && row[fl..].iter().all(|&n| n == 0), "{path} d{d}: {row:?}");
        }
    }
    assert_eq!((a[&("guard".to_string(), 0)][12], a[&("mufu".to_string(), 0)][15]), (653_696, 410_176));
    // ALU -> IMAD at d0: at S04 every thread-run is wrong, on both nights
    for (_, cells) in &all[2..] {
        for path in ["alu_imad_a", "alu_imad_c", "lop3_imad_a", "mov_imad_a"] {
            assert_eq!(cells[&(path.to_string(), 0)][4], RUNS, "{path} d0 S04");
        }
    }
    // replication of the consumer-class night: the same floors, 26 of 1 056 cells differ, each a partial count
    let (c, d) = (&all[2].1, &all[3].1);
    assert_eq!(c.len(), 66);
    let differing: Vec<_> = c.iter().flat_map(|(k, row)| (0..16).filter(move |&s| row[s] != d[k][s]).map(move |s| (k, s))).collect();
    assert_eq!((differing.len(), c.len() * 16), (26, 1056));
    for (k, s) in differing {
        assert!(c[k][s] > 0 && d[k][s] > 0 && floor(&c[k]) == floor(&d[k]) && floor(&c[k]).is_some_and(|f| s < f as usize), "{k:?} S{s:02}");
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// guard: 13 / 11 / 9
// ---------------------------------------------------------------------------------------------------------------------

/// Guard at d0. The measured floor 13 is above the cap 11: the pass cannot raise to it, so the site is a violation --
/// for a producer at any stall below 13 (S01..S12 are not clean on silicon) and for one that carries the yield flag
/// (no measured kernel does; ptxas never writes yield with S12..S15). A producer already at S13 / S14 / S15 without
/// yield is the measured control, and what ptxas writes in front of a guard: it passes, untouched.
#[test]
fn guard_d0_is_a_violation_below_the_measured_13() {
    for producer in PRED_PRODUCERS {
        for stall in ["S01", "S04", "S07", "S11", "S12"] {
            let err = run_with(&[&format!("[B------:R-:W-:-:{stall}] {producer}"), GUARDED, "EXIT"], &rules())
                .expect_err(&format!("{producer} at {stall}: a violation"));
            let msg = format!("{err:#}");
            assert!(msg.contains("guard at d0") && msg.contains("on sm_103a"), "{msg}");
            assert!(msg.contains("cap_stall (11)") && msg.contains("measured floor is S13") && msg.contains("d2 floor is S09"), "{msg}");
            assert!(!msg.contains("sm_120"), "{msg}");
        }
        for stall in ["S13", "S14", "S15"] {
            let r = run(&[&format!("[B------:R-:W-:-:{stall}] {producer}"), GUARDED, "EXIT"]);
            let k = &r.report.kernels[0];
            assert_eq!(raised(&r, 0), (0, vec![]), "{producer} at {stall}: the measured control is left as written");
            assert_eq!(k.input_above_cap, vec![0], "{producer} at {stall}: reported as above the cap");
            assert!(r.out_text.contains(&format!(":{stall}] {producer}")));
            // v2's report-only row for a guard relation behind S12+ is still written (legacy_stall_risk_from 12)
            assert_eq!(k.high_stall_risk.len(), 1);
            // the yield flag on the same stall is not the measured control
            let err = run_with(&[&format!("[B------:R-:W-:Y:{stall}] {producer}"), GUARDED, "EXIT"], &rules())
                .expect_err(&format!("{producer} at {stall} with yield: a violation"));
            assert!(format!("{err:#}").contains("without the yield flag"), "{err:#}");
        }
    }
    // the guard reads another predicate: no site
    let r = run(&["[B------:R-:W-:-:S04] ISETP.LT.U32.AND P0, PT, R4, R5, PT", "[B------:R-:W-:-:S04] @P1 IADD3 R8, PT, PT, R4, R5, RZ", "EXIT"]);
    assert_eq!(r.report.total_raises, 0);
}

/// Without `measured_guard_d0` the forbidden d0 site is a violation at every stall, as it was before the key carried
/// a meaning; without `guard_d0_forbid` nothing here is a violation.
#[test]
fn guard_d0_keys_one_by_one() {
    let text = serde_json::to_string(&*SECTION).unwrap();
    let at_s13 = ["[B------:R-:W-:-:S13] ISETP.LT.U32.AND P0, PT, R4, R5, PT", GUARDED, "EXIT"];
    let no_measured = StallRules::from_str_json(&text.replace(r#""measured_guard_d0":13"#, r#""measured_guard_d0":0"#)).unwrap();
    assert_eq!(no_measured.measured_guard_d0, 0);
    let err = run_with(&at_s13, &no_measured).expect_err("no measured floor: every d0 site is a violation");
    assert!(!format!("{err:#}").contains("measured floor"), "{err:#}");
    let no_forbid = StallRules::from_str_json(&text.replace(r#""guard_d0_forbid":true"#, r#""guard_d0_forbid":false"#)).unwrap();
    let r = run_with(&["[B------:R-:W-:-:S04] ISETP.LT.U32.AND P0, PT, R4, R5, PT", GUARDED, "EXIT"], &no_forbid).unwrap();
    assert_eq!(raised(&r, 0).0, 11, "floor_guard_d0, the cap");
    // a measured floor outside the stall field is refused with the rule set
    assert!(StallRules::from_str_json(&text.replace(r#""measured_guard_d0":13"#, r#""measured_guard_d0":16"#)).is_err());
}

/// Guard with one instruction between, resolved by the consumer's class as in v2. Data consumer: the measured floor
/// 11 (S01..S10 not clean, S11..S15 clean on the three producers) instead of v2's ban. ISETP consumer: the same 11
/// (v2: 5; not measured again), and still a violation behind a producer at S12+ (v2's bad band). Atomic consumer:
/// still a violation at any stall (v2; not measured again).
#[test]
fn guard_d1_by_consumer_class() {
    for producer in PRED_PRODUCERS {
        let r = run(&[&format!("[B------:R-:W-:-:S00] {producer}"), FILL, GUARDED, "EXIT"]);
        let (stall, why) = raised(&r, 0);
        assert_eq!(stall, 11, "{producer}");
        assert!(has(&why, "R3-guard-d1-data"), "{producer}: {why:?}");
        let site = &r.report.kernels[0].d1_sites[0];
        assert_eq!((site.class.as_str(), site.action.as_str()), ("data", "floor-raise:S00->S11"));
        // at the floor and above it: nothing to do (S11..S15 are clean)
        for stall in ["S11", "S13"] {
            let r = run(&[&format!("[B------:R-:W-:-:{stall}] {producer}"), FILL, GUARDED, "EXIT"]);
            assert_eq!(raised(&r, 0), (0, vec![]), "{producer} at {stall}");
            assert_eq!(r.report.kernels[0].d1_sites[0].action, "noop");
        }
        // ISETP consumer
        let isetp = "[B------:R-:W-:-:S01] @P0 ISETP.GT.U32.AND P1, PT, R4, R5, PT";
        let r = run(&[&format!("[B------:R-:W-:-:S05] {producer}"), FILL, isetp, "EXIT"]);
        let (stall, why) = raised(&r, 0);
        assert_eq!(stall, 11, "{producer}: v2 left S05 as written");
        assert!(has(&why, "R6-guard-d1-isetp"), "{producer}: {why:?}");
        let err = run_with(&[&format!("[B------:R-:W-:-:S12] {producer}"), FILL, isetp, "EXIT"], &rules()).expect_err("ISETP consumer behind S12");
        assert!(format!("{err:#}").contains("isetp-class"), "{err:#}");
        // atomic consumer
        let atomic = "[B------:R-:W-:-:S04] @P0 REDG.E.ADD.EL.STRONG.GPU PT, desc[UR0][RZ.64], R5";
        let err = run_with(&[&format!("[B------:R-:W-:-:S11] {producer}"), FILL, atomic, "EXIT"], &rules()).expect_err("atomic consumer");
        assert!(format!("{err:#}").contains("silicon-gated"), "{err:#}");
    }
    // the key alone: without guard_d1_data_floor the data consumer is v2's violation again
    let text = serde_json::to_string(&*SECTION).unwrap();
    let banned = StallRules::from_str_json(&text.replace(r#""guard_d1_data_floor":11"#, r#""guard_d1_data_floor":0"#)).unwrap();
    let err = run_with(&["[B------:R-:W-:-:S11] ISETP.LT.U32.AND P0, PT, R4, R5, PT", FILL, GUARDED, "EXIT"], &banned).expect_err("no data floor");
    assert!(format!("{err:#}").contains("data-class"), "{err:#}");
    assert!(StallRules::from_str_json(&text.replace(r#""guard_d1_data_floor":11"#, r#""guard_d1_data_floor":12"#)).is_err(), "above the cap");
}

#[test]
fn guard_d2_floor_9() {
    for producer in PRED_PRODUCERS {
        let r = run(&[&format!("[B------:R-:W-:-:S05] {producer}"), FILL, FILL, GUARDED, "EXIT"]);
        let (stall, why) = raised(&r, 0);
        assert_eq!(stall, 9, "{producer}: v2 left S05 as written");
        assert!(has(&why, "R3-guard-d2"), "{producer}: {why:?}");
        // three instructions between: no rule beyond the global floor
        let r = run(&[&format!("[B------:R-:W-:-:S04] {producer}"), FILL, FILL, FILL, GUARDED, "EXIT"]);
        assert_eq!(raised(&r, 0), (0, vec![]), "{producer}");
    }
}

/// `pred_producers_op0`: FSETP and ELECT are predicate producers of the pass on sm_103a -- measured in front of the
/// guard with ISETP's floors, FSETP also in front of SEL. A rule set without the key tracks ISETP and the carry-outs
/// alone, as before: the v2 rule set and the sm_120 section do not see these producers.
#[test]
fn fsetp_and_elect_are_predicate_producers_by_data() {
    assert!(rules_v2().pred_producers_op0.is_empty());
    for producer in &PRED_PRODUCERS[1..] {
        // v2 rule set: R1 alone, no guard rule, no violation
        let insns = [&format!("[B------:R-:W-:-:S01] {producer}"), GUARDED, "EXIT"];
        let r = run_with(&insns, &rules_v2()).unwrap();
        assert_eq!(raised(&r, 0), (4, vec!["R1".to_string()]), "{producer}: not a producer of the v2 rule set");
        // the vendored section: the measured guard-d0 violation
        assert!(run_with(&insns, &rules()).is_err(), "{producer}");
    }
    let sm120 = StallRules::load(std::path::Path::new("tables/sm120.json")).unwrap();
    assert!(sm120.pred_producers_op0.is_empty());
    // a redefinition by one of them ends the chain of the earlier producer (its guard reads the NEW value)
    let r = run(&[
        "[B------:R-:W-:-:S04] ISETP.LT.U32.AND P0, PT, R4, R5, PT",
        "[B------:R-:W-:-:S13] FSETP.GT.AND P0, PT, R4, R5, PT",
        GUARDED,
        "EXIT",
    ]);
    assert_eq!(raised(&r, 0), (0, vec![]), "the ISETP's P0 is rewritten in front of the guard: no d1 site for it");
    assert!(r.report.kernels[0].d1_sites.is_empty());
    // FSETP read as data by SEL: the measured 4 / 0 / 0 (R11 names the pair, the floor is the global one)
    let r = run(&["[B------:R-:W-:-:S00] FSETP.GT.AND P0, PT, R4, R5, PT", "[B------:R-:W-:-:S01] SEL R8, R4, R5, P0", "EXIT"]);
    let (stall, why) = raised(&r, 0);
    assert_eq!(stall, 4);
    assert!(has(&why, "R11-pcarry-d0"), "{why:?}");
    let r = run(&["[B------:R-:W-:-:S00] ISETP.LT.U32.AND P0, PT, R4, R5, PT", "[B------:R-:W-:-:S01] SEL R8, R4, R5, P0", "EXIT"]);
    assert!(has(&raised(&r, 0).1, "R11-pcarry-d0"));
}

// ---------------------------------------------------------------------------------------------------------------------
// the consumer class (2026-11-10 / -11)
// ---------------------------------------------------------------------------------------------------------------------

/// R17: a vector ALU result (IADD3, LOP3.LUT, MOV measured) read by an IMAD -- as its multiplicand or as its addend --
/// needs 5 at d0 (S04: every one of the 655 360 thread-runs wrong) and 4 at d1. The v2 rule set and every rule set
/// without the keys let S04 in front of the IMAD through.
#[test]
fn r17_alu_result_into_an_imad() {
    let imad_a = "[B------:R-:W-:-:S01] IMAD R8, R6, R5, RZ";
    let imad_c = "[B------:R-:W-:-:S01] IMAD R8, R4, R5, R6";
    for producer in ["IADD3 R6, PT, PT, R4, R5, RZ", "LOP3.LUT R6, R4, R5, RZ, 0x3c, !PT", "MOV R6, R4"] {
        let p4 = format!("[B------:R-:W-:-:S04] {producer}");
        let p2 = format!("[B------:R-:W-:-:S02] {producer}");
        for cons in [imad_a, imad_c] {
            let r = run(&[&p4, cons, "EXIT"]);
            let (stall, why) = raised(&r, 0);
            assert_eq!(stall, 5, "{producer} -> {cons}");
            assert!(has(&why, "R17-alu-imad-d0"), "{why:?}");
            let old = run_with(&[&p4, cons, "EXIT"], &rules_v2()).unwrap();
            assert_eq!(raised(&old, 0), (0, vec![]), "{producer}: the v2 rule set leaves S04 in front of the IMAD");
            // d1: 4 = the global floor; the rule is named on a producer written below it
            let r = run(&[&p2, FILL, cons, "EXIT"]);
            let (stall, why) = raised(&r, 0);
            assert_eq!(stall, 4, "{producer} -> filler -> {cons}");
            assert!(has(&why, "R17-alu-imad-d1") && !has(&why, "R17-alu-imad-d0"), "{why:?}");
            // d2: free
            let r = run(&[&p2, FILL, FILL, cons, "EXIT"]);
            assert_eq!(raised(&r, 0), (4, vec!["R1".to_string()]), "{producer}: two between");
        }
        // an ALU consumer, an IMAD that reads other registers, a rewrite of the register in between: not the pair
        // -- at d0 (nothing to raise at S04) and at d1 (the global floor alone, R17 is not named)
        for other in ["[B------:R-:W-:-:S01] IADD3 R8, PT, PT, R6, R5, RZ", "[B------:R-:W-:-:S01] IMAD R8, R7, R5, RZ"] {
            assert_eq!(raised(&run(&[&p4, other, "EXIT"]), 0), (0, vec![]), "{producer} -> {other}");
            assert_eq!(raised(&run(&[&p2, FILL, other, "EXIT"]), 0), (4, vec!["R1".to_string()]), "{producer} -> filler -> {other}");
        }
        let r = run(&[&p2, "[B------:R-:W-:-:S04] IADD3 R6, PT, PT, R4, 0x1, RZ", imad_a, "EXIT"]);
        assert_eq!(raised(&r, 0), (4, vec!["R1".to_string()]), "{producer}: R6 rewritten in front of the IMAD");
    }
    // the other IMAD forms as consumers are not measured: R17 raises in front of them all the same (raise-only: the
    // conservative side)
    for cons in ["IMAD.WIDE.U32 R8, R6, R5, RZ", "IMAD.MOV.U32 R8, RZ, RZ, R6", "IMAD.HI.U32 R8, R6, R5, RZ", "IMAD.U32 R8, R6, 0x38, RZ"] {
        let r = run(&["[B------:R-:W-:-:S04] IADD3 R6, PT, PT, R4, R5, RZ", &format!("[B------:R-:W-:-:S01] {cons}"), "EXIT"]);
        assert_eq!(raised(&r, 0).0, 5, "IADD3 -> {cons}");
    }
    // a producer with a data class of its own is not an R17 producer
    let r = run(&["[B------:R-:W-:-:S01] F2FP.BF16.F32.PACK_AB R6, R4, R5", imad_a, "EXIT"]);
    let (stall, why) = raised(&r, 0);
    assert_eq!(stall, 4);
    assert!(has(&why, "R14-f2fp-d0") && !why.iter().any(|x| x.starts_with("R17")), "{why:?}");
    // the keys one by one: each is its own rule, and each obeys the cap like every other floor
    let text = serde_json::to_string(&*SECTION).unwrap();
    let iadd3_s02 = "[B------:R-:W-:-:S02] IADD3 R6, PT, PT, R4, R5, RZ";
    let no_d0 = StallRules::from_str_json(&text.replace(r#""floor_alu_imad_d0":5"#, r#""floor_alu_imad_d0":0"#)).unwrap();
    assert_eq!(raised(&run_with(&[iadd3_s02, imad_a, "EXIT"], &no_d0).unwrap(), 0), (4, vec!["R1".to_string()]));
    assert!(has(&raised(&run_with(&[iadd3_s02, FILL, imad_a, "EXIT"], &no_d0).unwrap(), 0).1, "R17-alu-imad-d1"));
    let no_d1 = StallRules::from_str_json(&text.replace(r#""floor_alu_imad_d1":4"#, r#""floor_alu_imad_d1":0"#)).unwrap();
    assert_eq!(raised(&run_with(&[iadd3_s02, FILL, imad_a, "EXIT"], &no_d1).unwrap(), 0), (4, vec!["R1".to_string()]));
    assert_eq!(raised(&run_with(&[iadd3_s02, imad_a, "EXIT"], &no_d1).unwrap(), 0).0, 5);
    for (key, value) in [("floor_alu_imad_d0", 5), ("floor_alu_imad_d1", 4), ("floor_imad_imad_d0", 4)] {
        let above = text.replace(&format!(r#""{key}":{value}"#), &format!(r#""{key}":12"#));
        assert_ne!(above, text);
        assert!(StallRules::from_str_json(&above).is_err(), "{key} above cap_stall");
    }
}

/// R12 by consumer class: the result of `IMAD R, R, R, R` or of the register move `IMAD.MOV.U32 R, RZ, RZ, R` read by
/// `IMAD R, R, R, R` needs 4 at d0 -- one less than in front of an ALU consumer. The key names the measured forms
/// only: every other IMAD form on either side keeps the class floor 5.
#[test]
fn r12_imad_result_into_an_imad() {
    let imad_a = "[B------:R-:W-:-:S01] IMAD R8, R6, R5, RZ";
    let imad_c = "[B------:R-:W-:-:S01] IMAD R8, R4, R5, R6";
    let iadd3 = "[B------:R-:W-:-:S01] IADD3 R8, PT, PT, R6, R5, RZ";
    for producer in ["IMAD R6, R4, R5, RZ", "IMAD.MOV.U32 R6, RZ, RZ, R4"] {
        let p4 = format!("[B------:R-:W-:-:S04] {producer}");
        let p3 = format!("[B------:R-:W-:-:S03] {producer}");
        for cons in [imad_a, imad_c] {
            assert_eq!(raised(&run(&[&p4, cons, "EXIT"]), 0), (0, vec![]), "{producer} -> {cons}: S04 is the pair's floor");
            let (stall, why) = raised(&run(&[&p3, cons, "EXIT"]), 0);
            assert_eq!(stall, 4, "{producer} -> {cons}");
            assert!(has(&why, "R12-imad-imad-d0") && !has(&why, "R12-imad-d0"), "{why:?}");
            // d1: 3 like every consumer of an IMAD -- below the global floor, named on a producer written below it
            let (stall, why) = raised(&run(&[&format!("[B------:R-:W-:-:S02] {producer}"), FILL, cons, "EXIT"]), 0);
            assert_eq!(stall, 4);
            assert_eq!(why, ["R1", "R12-imad-d1"], "{producer} -> filler -> {cons}: R12 at d1, R17 names no IMAD producer");
        }
        // an ALU consumer: the class floor
        let (stall, why) = raised(&run(&[&p4, iadd3, "EXIT"]), 0);
        assert_eq!(stall, 5, "{producer} -> IADD3");
        assert!(has(&why, "R12-imad-d0"), "{why:?}");
    }
    // not the measured pair: the class floor 5 stays
    for (producer, cons) in [
        ("IMAD.WIDE.U32 R6, R4, R5, RZ", "IMAD R8, R7, R5, RZ"),      // a wide producer (its high half)
        ("IMAD.IADD R6, R4, 0x1, R5", "IMAD R8, R6, R5, RZ"),         // display aliases other than the register move
        ("IMAD.MOV R6, RZ, RZ, -R4", "IMAD R8, R6, R5, RZ"),
        ("IMAD.SHL.U32 R6, R4, 0x8, RZ", "IMAD R8, R6, R5, RZ"),
        ("IMAD.HI.U32 R6, R4, R5, RZ", "IMAD R8, R6, R5, RZ"),
        ("IMAD.U32 R6, R4, 0x38, RZ", "IMAD R8, R6, R5, RZ"),
        ("IMAD.MOV.U32 R6, RZ, RZ, 0x80", "IMAD R8, R6, R5, RZ"),     // the constant load
        ("IMAD.U32 R6, RZ, RZ, UR8", "IMAD R8, R6, R5, RZ"),          // the move from a uniform register
        ("IMAD R6, R4, 0x400, R5", "IMAD R8, R6, R5, RZ"),            // an immediate in the producer
        ("IMAD R6, R4, R5, RZ", "IMAD R8, R6, 0x400, R5"),            // ... in the consumer
        ("IMAD R6, R4, R5, RZ", "IMAD.WIDE.U32 R8, R6, R5, RZ"),      // other forms as the consumer
        ("IMAD R6, R4, R5, RZ", "IMAD.U32 R8, R6, 0x38, RZ"),
        ("IMAD R6, R4, R5, RZ", "IMAD.MOV.U32 R8, RZ, RZ, R6"),
    ] {
        let r = run(&[&format!("[B------:R-:W-:-:S04] {producer}"), &format!("[B------:R-:W-:-:S01] {cons}"), "EXIT"]);
        let (stall, why) = raised(&r, 0);
        assert_eq!(stall, 5, "{producer} -> {cons}");
        assert!(has(&why, "R12-imad-d0") && !has(&why, "R12-imad-imad-d0"), "{producer} -> {cons}: {why:?}");
    }
    // one cycle more across the ALU / IMAD boundary in either direction, the IMAD path itself at 4
    let r = run(&[
        "[B------:R-:W-:-:S04] IADD3 R6, PT, PT, R4, R5, RZ",  // 0: ALU  -> IMAD  5
        "[B------:R-:W-:-:S04] IMAD R8, R6, R5, RZ",           // 1: IMAD -> IMAD  4
        "[B------:R-:W-:-:S04] IMAD R9, R8, R5, RZ",           // 2: IMAD -> ALU   5
        "[B------:R-:W-:-:S04] IADD3 R10, PT, PT, R9, R5, RZ", // 3
        "EXIT",
    ]);
    assert_eq!([raised(&r, 0).0, raised(&r, 1).0, raised(&r, 2).0, raised(&r, 3).0], [5, 0, 5, 0]);
    // the key alone
    let text = serde_json::to_string(&*SECTION).unwrap();
    let class_floor = StallRules::from_str_json(&text.replace(r#""floor_imad_imad_d0":4"#, r#""floor_imad_imad_d0":0"#)).unwrap();
    let r = run_with(&["[B------:R-:W-:-:S04] IMAD R6, R4, R5, RZ", imad_a, "EXIT"], &class_floor).unwrap();
    assert_eq!(raised(&r, 0).0, 5, "without the key: floor_imad_d0 for every consumer");
}

// ---------------------------------------------------------------------------------------------------------------------
// the producer classes (2026-11-07 / -09)
// ---------------------------------------------------------------------------------------------------------------------

/// The IMAD class in front of an ALU consumer: 5 / 3 / 0 for each of the eleven measured forms, the constant load
/// included (measured 2026-11-10 with the register overwritten at the end of every iteration); the ALU controls of the
/// same runs 4 / 0 / 0.
#[test]
fn imad_class_5_3_and_the_alu_controls() {
    let iadd3 = "[B------:R-:W-:-:S01] IADD3 R8, PT, PT, R6, R5, RZ";
    for producer in [
        "IMAD R6, R4, R5, RZ",
        "IMAD.MOV.U32 R6, RZ, RZ, R4",
        "IMAD.MOV R6, RZ, RZ, -R4",
        "IMAD.IADD R6, R4, 0x1, R5",
        "IMAD.SHL.U32 R6, R4, 0x8, RZ",
        "IMAD.HI.U32 R6, R4, R5, RZ",
        "IMAD.U32 R6, R4, 0x38, RZ",
        "IMAD.U32 R6, RZ, RZ, UR8",
        "IMAD.MOV.U32 R6, RZ, RZ, 0x80",
    ] {
        let (stall, why) = raised(&run(&[&format!("[B------:R-:W-:-:S04] {producer}"), iadd3, "EXIT"]), 0);
        assert_eq!(stall, 5, "{producer}");
        assert!(has(&why, "R12-imad-d0"), "{producer}: {why:?}");
        let (stall, why) = raised(&run(&[&format!("[B------:R-:W-:-:S02] {producer}"), FILL, iadd3, "EXIT"]), 0);
        assert_eq!(stall, 4, "{producer}: d1 floor 3 is below the global floor");
        assert!(has(&why, "R12-imad-d1"), "{producer}: {why:?}");
    }
    // the high half of the wide product
    let (stall, why) = raised(&run(&["[B------:R-:W-:-:S04] IMAD.WIDE.U32 R6, R4, R5, RZ", "[B------:R-:W-:-:S01] IADD3 R8, PT, PT, R7, R5, RZ", "EXIT"]), 0);
    assert_eq!(stall, 5);
    assert!(has(&why, "R12-imad-d0"), "{why:?}");
    // ALU controls: S04 in front of the adjacent ALU consumer stays as written
    for producer in ["IADD3 R6, PT, PT, R4, R5, RZ", "LOP3.LUT R6, R4, R5, RZ, 0x3c, !PT", "MOV R6, R4", "MOV R6, 0x80"] {
        assert_eq!(raised(&run(&[&format!("[B------:R-:W-:-:S04] {producer}"), iadd3, "EXIT"]), 0), (0, vec![]), "{producer}");
    }
    // the carry chain: IMAD.WIDE cout -> IADD3.X cin 5
    let (stall, why) = raised(&run(&["[B------:R-:W-:-:S04] IMAD.WIDE.U32 R6, P0, R4, R5, RZ", "[B------:R-:W-:-:S01] IADD3.X R8, PT, PT, R6, R5, RZ, P0, !PT", "EXIT"]), 0);
    assert_eq!(stall, 5);
    assert!(has(&why, "R2-dmix-d0"), "{why:?}");
}

/// FFMA / FMUL / FMUL2 / HFMA2 4 / 3 / 0, F2FP pack and unpack 4 / 0 / 0, UMOV 0 / 0 / 0: every one at or below the
/// global floor, so the pass names the rule on a producer written below it and raises nothing that stands at S04.
#[test]
fn float_f2fp_and_umov_classes() {
    for (producer, cons) in [
        ("FFMA R6, R4, R5, R4", "FFMA R8, R6, R5, RZ"),
        ("FMUL R6, R4, R5", "FADD R8, R6, R5"),
        ("HFMA2 R6, R4, R5, R4", "HADD2 R8, R6, R5"),
    ] {
        let cons = format!("[B------:R-:W-:-:S01] {cons}");
        assert_eq!(raised(&run(&[&format!("[B------:R-:W-:-:S04] {producer}"), &cons, "EXIT"]), 0), (0, vec![]), "{producer}");
        let (stall, why) = raised(&run(&[&format!("[B------:R-:W-:-:S02] {producer}"), &cons, "EXIT"]), 0);
        assert_eq!(stall, 4, "{producer}");
        assert!(has(&why, "R13-fma-d0"), "{producer}: {why:?}");
        let (stall, why) = raised(&run(&[&format!("[B------:R-:W-:-:S02] {producer}"), FILL, &cons, "EXIT"]), 0);
        assert_eq!(stall, 4, "{producer}: d1 floor 3");
        assert!(has(&why, "R13-fma-d1"), "{producer}: {why:?}");
    }
    // FMUL2 measures the same 4 / 3 / 0, but the operand-role table has no row for it (nor for FADD2 / FFMA2): the pass
    // tracks nothing behind it and names no rule. The stall it ends with is the window's global floor, which is the
    // measured floor; a role row for the packed-FP32 words is a table change of its own.
    for between in [0, 1] {
        let mut insns = vec!["[B------:R-:W-:-:S02] FMUL2 R6, R4.F32x2.HI_LO, R4.F32"];
        insns.extend(std::iter::repeat_n(FILL, between));
        insns.extend(["[B------:R-:W-:-:S01] FADD R8, R7, R6", "EXIT"]);
        assert_eq!(raised(&run(&insns), 0), (4, vec!["R1".to_string()]), "FMUL2, {between} between");
    }
    for producer in ["F2FP.BF16.F32.PACK_AB R6, R4, R5", "F2FP.BF16.E2M1.UNPACK_B R6, R4, R5.B0"] {
        let cons = "[B------:R-:W-:-:S01] IADD3 R8, PT, PT, R6, R5, RZ";
        let (stall, why) = raised(&run(&[&format!("[B------:R-:W-:-:S02] {producer}"), cons, "EXIT"]), 0);
        assert_eq!(stall, 4, "{producer}");
        assert!(has(&why, "R14-f2fp-d0"), "{producer}: {why:?}");
    }
    // UMOV: clean at every stall -- no rule of its own (floor_umov_d0 0). In a window it still gets the global floor,
    // and as a uniform ALU-role word in front of a uniform reader it is named by R7, whose floor is the global one.
    let r = run(&["[B------:R-:W-:-:S01] UMOV UR10, UR9", "[B------:R-:W-:-:S01] UIADD3 UR11, UPT, UPT, UR10, 0x1, URZ", "EXIT"]);
    let (stall, why) = raised(&r, 0);
    assert_eq!(stall, 4);
    assert!(!why.iter().any(|x| x.starts_with("R15")), "{why:?}");
    assert_eq!(why, ["R1", "R7-urpath"], "the rules behind the UMOV's raise");
}

/// MUFU: no stall up to S15 is clean at any distance (S15 at d0: 410 176 of 655 360 wrong). Without a write barrier on
/// the MUFU the consumer is a violation; with one the pass is silent.
#[test]
fn mufu_is_scoreboard_only() {
    for between in [0, 1, 2] {
        let mut insns = vec!["[B------:R-:W-:-:S15] MUFU.RCP R6, R4"];
        insns.extend(std::iter::repeat_n(FILL, between));
        insns.extend(["[B------:R-:W-:-:S04] FFMA R8, R6, R5, RZ", "EXIT"]);
        let err = run_with(&insns, &rules()).expect_err("MUFU without a scoreboard");
        assert!(format!("{err:#}").contains("MUFU"), "{err:#}");
    }
    let r = run(&["[B------:R-:W0:-:S01] MUFU.RCP R6, R4", "[B0-----:R-:W-:-:S04] FFMA R8, R6, R5, RZ", "EXIT"]);
    assert_eq!(raised(&r, 0), (4, vec!["R1".to_string()]));
}

/// R2UR: the vector -> R2UR hop is 4 / 0 / 0 (v2: 8), the R2UR -> uniform consumer hop 8 / 6 / 4 (v2: 8 at d0 only).
#[test]
fn r2ur_hops() {
    let r = run(&["[B------:R-:W-:-:S04] IADD3 R6, PT, PT, R4, R5, RZ", "[B------:R-:W-:-:S15] R2UR UR9, R6", "EXIT"]);
    assert_eq!(raised(&r, 0), (0, vec![]), "the in-hop: 4 = the global floor");
    let r = run(&["[B------:R-:W-:-:S02] IADD3 R6, PT, PT, R4, R5, RZ", "[B------:R-:W-:-:S15] R2UR UR9, R6", "EXIT"]);
    let (stall, why) = raised(&r, 0);
    assert_eq!(stall, 4);
    assert!(has(&why, "R9-r2ur-in-d0") && !has(&why, "R9-r2ur"), "{why:?}");
    let old = run_with(&["[B------:R-:W-:-:S04] IADD3 R6, PT, PT, R4, R5, RZ", "[B------:R-:W-:-:S15] R2UR UR9, R6", "EXIT"], &rules_v2()).unwrap();
    assert_eq!(raised(&old, 0).0, 8, "the v2 rule set: 8 in both directions");
    let consumer = "[B------:R-:W-:-:S01] UIADD3 UR10, UPT, UPT, UR9, 0x5, URZ";
    for (between, floor, rule) in [(0, 8, "R9-r2ur"), (1, 6, "R9-r2ur-out-d1"), (2, 4, "R9-r2ur-out-d2")] {
        let mut insns = vec!["[B------:R-:W-:-:S02] R2UR UR9, R12"];
        insns.extend(std::iter::repeat_n(FILL, between));
        insns.extend([consumer, "EXIT"]);
        let (stall, why) = raised(&run(&insns), 0);
        assert_eq!(stall, floor, "R2UR -> consumer, {between} between");
        assert!(has(&why, rule), "{between} between: {why:?}");
    }
}

/// The uniform paths: urpath 4 / 3 / 0, xread 6 / 4 / 2, uguard 10 / 8 / 6 -- the d0 values and uguard d1 are v2's,
/// confirmed; the d1 / d2 keys are new on sm_103a.
#[test]
fn uniform_paths() {
    let producer = "UIADD3 UR8, UPT, UPT, UR8, 0x3, URZ";
    for (between, cons, floor, rule) in [
        (0, "UIADD3 UR9, UPT, UPT, UR8, 0x5, URZ", 4, "R7-urpath"),
        (1, "UIADD3 UR9, UPT, UPT, UR8, 0x5, URZ", 4, "R7-urpath-d1"),
        (0, "IADD3 R8, PT, PT, R4, UR8, RZ", 6, "R8-xread"),
        (1, "IADD3 R8, PT, PT, R4, UR8, RZ", 4, "R8-xread-d1"),
        (2, "IADD3 R8, PT, PT, R4, UR8, RZ", 4, "R8-xread-d2"),
    ] {
        let mut insns = vec![format!("[B------:R-:W-:-:S01] {producer}")];
        insns.extend(std::iter::repeat_n(FILL.to_string(), between));
        insns.extend([format!("[B------:R-:W-:-:S01] {cons}"), "EXIT".to_string()]);
        let refs: Vec<&str> = insns.iter().map(String::as_str).collect();
        let (stall, why) = raised(&run(&refs), 0);
        assert_eq!(stall, floor, "{cons}, {between} between");
        assert!(has(&why, rule), "{cons}, {between} between: {why:?}");
    }
    let producer = "[B------:R-:W-:-:S01] UISETP.LT.U32.AND UP0, UPT, UR8, 0x80000000, UPT";
    let consumer = "[B------:R-:W-:-:S01] @UP0 UIADD3 UR9, UPT, UPT, UR9, 0x5, URZ";
    for (between, floor, rule) in [(0, 10, "R10-uguard-d0"), (1, 8, "R10-uguard-d1"), (2, 6, "R10-uguard-d2")] {
        let mut insns = vec![producer];
        insns.extend(std::iter::repeat_n(FILL, between));
        insns.extend([consumer, "EXIT"]);
        let (stall, why) = raised(&run(&insns), 0);
        assert_eq!(stall, floor, "uguard, {between} between");
        assert!(has(&why, rule), "{between} between: {why:?}");
    }
}

/// The pass writes no stall above the cap 11 on sm_103a, whatever the rule: every raise of every pair above ends at
/// or below it, and an input above it is reported, never changed.
#[test]
fn nothing_is_written_above_the_cap() {
    let r = rules();
    for (name, floor) in [
        ("floor_global", r.floor_global), ("floor_dmix_d0", r.floor_dmix_d0), ("floor_guard_d0", r.floor_guard_d0),
        ("guard_d1_data_floor", r.guard_d1_data_floor), ("guard_d1_isetp_floor", r.guard_d1_isetp_floor),
        ("floor_guard_d2", r.floor_guard_d2), ("floor_xread_d0", r.floor_xread_d0), ("floor_r2ur_d0", r.floor_r2ur_d0),
        ("floor_uguard_d0", r.floor_uguard_d0), ("floor_imad_d0", r.floor_imad_d0), ("floor_alu_imad_d0", r.floor_alu_imad_d0),
    ] {
        assert!(floor <= r.cap_stall, "{name}");
    }
    let out = run(&["[B------:R-:W-:-:S14] IADD3 R6, PT, PT, R4, R5, RZ", "[B------:R-:W-:-:S15] IMAD R8, R6, R5, RZ", "EXIT"]);
    assert_eq!((out.report.total_raises, out.report.kernels[0].input_above_cap.clone()), (0, vec![0, 1]));
    assert_eq!(out.report.rules_version, "v3");
}
