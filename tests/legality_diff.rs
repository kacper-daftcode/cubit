//! `cubit legality-diff <seed.jsonl> <candidate.jsonl>`: the rule a candidate schedule is held to
//! against its seed (`legality::compare`, 2026-11-11) -- **no finding the seed does not have, and
//! none CLOSER than the seed has it.**
//!
//! `CUBIT_VERIFY_JSON` gives the findings of the three legality checks with their instruction
//! indices, and the first form of the rule was a set difference of the keys (kind + indices). A
//! schedule search then took one cycle off pairs the vendor's schedule ALREADY has below the table
//! -- the key of such a pair does not change, only its distance -- and 12 of 14 such candidates of
//! a served kernel came out "nothing new". The line always carried the distance (`have` of a
//! dependency finding, `distance` of a store path): the rule reads it now.
//!
//! Pinned here: a stall lowered at a reported pair keeps every key and is refused as `closer`; the
//! same kernel against itself, and a candidate that only moves pairs APART, are clean; a new key is
//! `new`; two lines that are not reports of one instruction list under one model are not
//! comparable, which is not clean.

use cubit::legality::{self, Difference};
use serde_json::{json, Value};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);

const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
/// 17 instructions; three dependency findings behind `[7] R2UR P1, UR4, R3`: `[8]` at 1 of 6, `[9]` at 3 of 13,
/// `[10]` at 4 of 13 (`tests/r2ur_pred_dest.rs`)
const SEED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/r2ur_pred/broadcast.sched2_6264d55.frozen.sass");

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("legality_diff_{}_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst), tag));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

/// The seed's text with `from` replaced by `to` once (a control field of one instruction).
fn edited(from: &str, to: &str) -> String {
    let text = std::fs::read_to_string(SEED).unwrap();
    assert_eq!(text.matches(from).count(), 1, "`{from}` names one instruction of the fixture");
    text.replacen(from, to, 1)
}

/// Assemble `text` under `env` and return the file of its `CUBIT_VERIFY_JSON` lines.
fn lines(dir: &std::path::Path, name: &str, text: &str, env: &[(&str, &str)]) -> String {
    let src = dir.join(format!("{name}.frozen.sass"));
    std::fs::write(&src, text).unwrap();
    let file = dir.join(format!("{name}.jsonl"));
    let mut e: Vec<(&str, &str)> = vec![("CUBIT_VERIFY_JSON", file.to_str().unwrap())];
    e.extend_from_slice(env);
    let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", dir.join(format!("{name}.cubin")).to_str().unwrap()], &e);
    assert!(ok, "{log}");
    file.to_str().unwrap().to_string()
}

fn one(file: &str) -> Value {
    let text = std::fs::read_to_string(file).unwrap();
    assert_eq!(text.lines().count(), 1);
    serde_json::from_str(text.lines().next().unwrap()).unwrap()
}

/// the keys of the first form of the rule: kind + the two instruction indices (+ register), per list
fn keys(line: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for f in line["scoreboard"]["findings"].as_array().unwrap() {
        out.push(format!("sb {} {} {} {}", f["kind"], f["at"], f["other"], f["register"]));
    }
    for f in line["store_paths"]["findings"].as_array().unwrap() {
        out.push(format!("sp {} {} {}", f["store"], f["overwriter"], f["register"]));
    }
    for f in line["dep"]["findings"].as_array().unwrap() {
        out.push(format!("dep {} {} {}", f["kind"], f["producer"], f["consumer"]));
    }
    out.sort();
    out
}

#[test]
fn a_stall_lowered_at_a_reported_pair_keeps_every_key_and_is_refused() {
    let dir = scratch("closer");
    // the seed: the fixture with `[8] PLOP3.LUT` at stall 3; the candidate takes one cycle off it (the fixture
    // as it is, stall 2): `[9]` and `[10]` stand one cycle closer to `[7] R2UR`, whose results they read too early
    // in the seed already
    let seed = lines(&dir, "seed", &edited(":S02] PLOP3.LUT", ":S03] PLOP3.LUT"), &[]);
    let cand = lines(&dir, "cand", &std::fs::read_to_string(SEED).unwrap(), &[]);
    let (s, c) = (one(&seed), one(&cand));
    // the hole: by the keys alone the candidate has nothing the seed does not have
    assert_eq!(keys(&c), keys(&s));
    assert_eq!(c["dep"]["below_default"], s["dep"]["below_default"]);
    // the rule: two pairs are closer than the seed has them
    let d = legality::compare(&s, &c);
    assert!(d.not_comparable.is_none() && d.new.is_empty(), "{d:?}");
    let closer: Vec<(&str, &str, Option<u64>, Option<u64>)> = d.closer.iter().map(|f| (f.list, f.key.as_str(), f.candidate, f.seed)).collect();
    assert_eq!(closer, [("dep", "raw [7] -> [10]", Some(4), Some(5)), ("dep", "raw [7] -> [9]", Some(3), Some(4))]);
    assert!(!d.is_clean());
    // the command: exit code 1, the two pairs named, the same as JSON
    let out = dir.join("diff.json");
    let (ok, log) = cubit(&["legality-diff", &seed, &cand, "--json", out.to_str().unwrap()], &[]);
    assert!(!ok, "{log}");
    assert!(log.contains("broadcast: LEGALITY-DIFF 0 new, 2 closer than the seed (3 findings in the seed, 3 in the candidate)"), "{log}");
    assert!(log.contains("closer dep raw [7] -> [9]: 3 < 4 in the seed:"), "{log}");
    assert!(log.contains("closer dep raw [7] -> [10]: 4 < 5 in the seed:"), "{log}");
    let o = one(out.to_str().unwrap());
    assert_eq!((o["schema"].as_str(), o["kernel"].as_str(), o["verdict"].as_str()), (Some("cubit-legality-diff-1"), Some("broadcast"), Some("worse")));
    assert_eq!(o["new"], json!([]));
    assert_eq!(o["closer"].as_array().unwrap().len(), 2);
    assert_eq!((&o["closer"][1]["key"], &o["closer"][1]["candidate"], &o["closer"][1]["seed"]), (&json!("raw [7] -> [9]"), &json!(3), &json!(4)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_seed_against_itself_and_a_candidate_that_moves_pairs_apart_are_clean() {
    let dir = scratch("clean");
    let seed = lines(&dir, "seed", &std::fs::read_to_string(SEED).unwrap(), &[]);
    let (ok, log) = cubit(&["legality-diff", &seed, &seed], &[]);
    assert!(ok, "{log}");
    assert!(log.contains("broadcast: LEGALITY-DIFF 0 new, 0 closer than the seed (3 findings in the seed, 3 in the candidate)"), "{log}");
    // `[8] PLOP3.LUT` from stall 2 to 4: the pairs behind it are farther from `[7]` -- still findings, not worse
    let apart = lines(&dir, "apart", &edited(":S02] PLOP3.LUT", ":S04] PLOP3.LUT"), &[]);
    let d = legality::compare(&one(&seed), &one(&apart));
    assert_eq!(d, Difference::default());
    let (ok, log) = cubit(&["legality-diff", &seed, &apart], &[]);
    assert!(ok, "{log}");
    // a file the assembler appended to twice: the last line of a kernel counts
    let twice = lines(&dir, "seed", &edited(":S02] PLOP3.LUT", ":S01] PLOP3.LUT"), &[]);
    assert_eq!(twice, seed);
    assert_eq!(std::fs::read_to_string(&seed).unwrap().lines().count(), 2);
    let (ok, log) = cubit(&["legality-diff", &apart, &seed], &[]);
    assert!(!ok && log.contains("2 closer than the seed"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_finding_the_seed_does_not_have_is_new() {
    let dir = scratch("new");
    let seed = lines(&dir, "seed", &std::fs::read_to_string(SEED).unwrap(), &[]);
    // `[11] IADD3 R6, ..., UR5` from stall 5 to 1: `[12] SEL R6, R6, RZ, P2` reads R6 one cycle behind it
    let cand = lines(&dir, "cand", &edited(":S05] IADD3 R6, PT, PT, R6, UR5, RZ", ":S01] IADD3 R6, PT, PT, R6, UR5, RZ"), &[]);
    let d = legality::compare(&one(&seed), &one(&cand));
    assert!(d.new.iter().any(|f| f.list == "dep" && f.key == "raw [11] -> [12]" && f.seed.is_none() && f.candidate == Some(1)), "{d:?}");
    let (ok, log) = cubit(&["legality-diff", &seed, &cand], &[]);
    assert!(!ok && log.contains("new    dep raw [11] -> [12]:"), "{log}");
    // the other way round the finding is gone: clean
    let (ok, log) = cubit(&["legality-diff", &cand, &seed], &[]);
    assert!(ok, "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn lines_that_are_not_reports_of_one_kernel_under_one_model_are_not_comparable() {
    let dir = scratch("nc");
    let text = std::fs::read_to_string(SEED).unwrap();
    let seed = lines(&dir, "seed", &text, &[]);
    // the same listing under the other operand model: the keys of two models are not one set
    let sync = lines(&dir, "sync", &text, &[("CUBIT_SYNC_CLASSES", "1")]);
    let d = legality::compare(&one(&seed), &one(&sync));
    assert!(d.not_comparable.as_deref().is_some_and(|w| w.contains("another model (`sync_classes`)")), "{d:?}");
    assert!(!d.is_clean());
    let (ok, log) = cubit(&["legality-diff", &seed, &sync], &[]);
    assert!(!ok && log.contains("NOT COMPARABLE: another model"), "{log}");
    // another kernel name: the candidate's kernel has no line in the seed, the seed's none in the candidate
    let other = lines(&dir, "other", &text.replace(".entry broadcast", ".entry elsewhere"), &[]);
    let (ok, log) = cubit(&["legality-diff", &seed, &other], &[]);
    assert!(!ok, "{log}");
    assert!(log.contains("elsewhere: LEGALITY-DIFF NOT COMPARABLE: the seed has no line for this kernel"), "{log}");
    assert!(log.contains("broadcast: LEGALITY-DIFF NOT COMPARABLE: the candidate has no line for this kernel"), "{log}");
    // another instruction count: indices are the keys
    let (mut a, b) = (one(&seed), one(&seed));
    a["instructions"] = json!(18);
    assert!(legality::compare(&a, &b).not_comparable.is_some_and(|w| w.contains("instruction count")));
    // another table; a line of another schema
    let mut a = one(&seed);
    a["dep"]["edition"] = json!({"name": "x", "entries": 1});
    assert!(legality::compare(&a, &b).not_comparable.is_some_and(|w| w.contains("different dependency tables")));
    let mut a = one(&seed);
    a["schema"] = json!("cubit-legality-0");
    assert!(legality::compare(&a, &b).not_comparable.is_some());
    // an empty candidate file is not a clean candidate
    let empty = dir.join("empty.jsonl");
    std::fs::write(&empty, "").unwrap();
    let (ok, log) = cubit(&["legality-diff", &seed, empty.to_str().unwrap()], &[]);
    assert!(!ok && log.contains("no kernel line"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_store_path_is_compared_by_its_distance_and_a_scoreboard_finding_by_its_key() {
    let line = |paths: Value, sb: Value| {
        json!({
            "schema": "cubit-legality-1", "kernel": "k", "instructions": 100, "sync_classes": false,
            "scoreboard": {"findings": sb}, "store_paths": {"findings": paths}, "dep": {"table": "sm_120", "findings": []},
        })
    };
    let path = |distance: u64| {
        json!([{"store": 40, "overwriter": 48, "register": "R13", "operand": "address", "read_barrier": 2, "distance": distance,
                "class": "shared-address", "store_text": "STS.64 [R13], R8 ;", "overwriter_text": "CS2R R12, SRZ ;"}])
    };
    let raw = json!([{"kind": "raw", "at": 623, "other": 922, "register": "R62", "at_text": "ISETP ;", "other_text": "LDG ;"}]);
    // the same store -> overwriter pair, the overwriter closer: worse
    let d = legality::compare(&line(path(25), json!([])), &line(path(24), json!([])));
    assert_eq!(d.closer.len(), 1);
    assert_eq!((d.closer[0].list, d.closer[0].key.as_str(), d.closer[0].candidate, d.closer[0].seed), ("store_paths", "shared-address [40] -> [48] R13 (address)", Some(24), Some(25)));
    // farther, or the same: clean
    assert!(legality::compare(&line(path(25), json!([])), &line(path(26), json!([]))).is_clean());
    assert!(legality::compare(&line(path(25), json!([])), &line(path(25), json!([]))).is_clean());
    // a pair the seed does not have, of either class, is new
    let d = legality::compare(&line(json!([]), json!([])), &line(path(25), json!([])));
    assert_eq!((d.new.len(), d.closer.len()), (1, 0));
    // a scoreboard finding has no distance: its key alone
    let d = legality::compare(&line(json!([]), json!([])), &line(json!([]), raw.clone()));
    assert_eq!((d.new.len(), d.new[0].list, d.new[0].key.as_str()), (1, "scoreboard", "raw [922] -> [623] R62"));
    assert!(legality::compare(&line(json!([]), raw.clone()), &line(json!([]), raw)).is_clean());
}
