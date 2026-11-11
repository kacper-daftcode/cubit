//! `CUBIT_VERIFY_JSON=<file>`: the read-only legality checks of a scheduled kernel as one JSON line
//! per kernel (`src/legality.rs`, 2026-11-11).
//!
//! `CUBIT_VERIFY=1 CUBIT_DEP_VERIFY=1 cubit asm <listing>` prints its findings; a tool that holds
//! a candidate schedule against its seed -- "nothing the seed does not have" -- parsed that text.
//! The line carries the same counts and every finding with its instruction indices, so the
//! comparison is a set difference. Pinned here: the counts are the text's, the findings are the
//! text's lines, the variable changes no byte of the output and prints nothing, the file is
//! appended to.

use serde_json::Value;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);

const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
/// a schedule that reads both results of `R2UR P1, UR4, R3` before they land (`tests/r2ur_pred_dest.rs`)
const R2UR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/r2ur_pred/broadcast.sched2_6264d55.frozen.sass");
/// the attention kernel with three unwaited store -> overwriter pairs (`tests/store_paths_verify.rs`)
const V43B: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/store_paths/attention_v43b.frozen.sass");

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("verify_json_{}_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst), tag));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `cubit asm <listing>` in `dir` with `env`: (stdout + stderr, the cubin's bytes).
fn asm(dir: &std::path::Path, listing: &str, env: &[(&str, &str)]) -> (String, Vec<u8>) {
    let out = dir.join("k.cubin");
    let o = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", TABLE, listing, "-o", out.to_str().unwrap()])
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .expect("run cubit");
    let log = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success(), "{log}");
    (log, std::fs::read(&out).unwrap())
}

/// The JSON lines `CUBIT_VERIFY_JSON` writes for `listing` (with `more` in the environment).
fn lines(tag: &str, listing: &str, more: &[(&str, &str)]) -> Vec<Value> {
    let dir = scratch(tag);
    let file = dir.join("legality.jsonl");
    let mut env: Vec<(&str, &str)> = vec![("CUBIT_VERIFY_JSON", file.to_str().unwrap())];
    env.extend_from_slice(more);
    asm(&dir, listing, &env);
    let text = std::fs::read_to_string(&file).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    text.lines().map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}"))).collect()
}

fn n(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| panic!("not a count: {v}"))
}

#[test]
fn the_dependency_findings_are_the_lines_of_the_text_report() {
    let l = lines("r2ur", R2UR, &[]);
    assert_eq!(l.len(), 1);
    let k = &l[0];
    assert_eq!(k["schema"], "cubit-legality-1");
    assert_eq!(k["kernel"], "broadcast");
    assert_eq!(n(&k["instructions"]), 17);
    assert_eq!(k["sync_classes"], false);
    let dep = &k["dep"];
    assert_eq!(dep["table"], "sm_120");
    assert_eq!((n(&dep["below_cell"]), n(&dep["barrier_arm"]), n(&dep["below_resource"]), n(&dep["below_default"])), (0, 0, 0, 3));
    let f: Vec<(u64, u64, u64, u64, bool, &str)> = dep["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (n(&f["producer"]), n(&f["consumer"]), n(&f["have"]), n(&f["need"]), f["defaulted"].as_bool().unwrap(), f["kind"].as_str().unwrap()))
        .collect();
    assert_eq!(f, [(7, 8, 1, 6, true, "raw"), (7, 9, 3, 13, true, "raw"), (7, 10, 4, 13, true, "raw")]);
    // ... word for word what CUBIT_DEP_VERIFY prints
    let dir = scratch("r2ur_text");
    let (log, _) = asm(&dir, R2UR, &[("CUBIT_VERIFY", "1"), ("CUBIT_DEP_VERIFY", "40")]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(log.contains("DEP_VERIFY 0 below a table cell, 0 waits closer than the arming distance to their barrier's setter, 0 below a resource spacing, 3 below a default"), "{log}");
    for f in dep["findings"].as_array().unwrap() {
        let text = f["text"].as_str().unwrap();
        assert!(log.lines().any(|l| l.trim() == format!("DEP dflt {text}")), "not in the text report: {text}\n{log}");
    }
    // the scoreboard simulation and the path check have nothing on this kernel, as the text says
    assert!(log.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale"), "{log}");
    let sb = &k["scoreboard"];
    assert_eq!((n(&sb["raw"]), n(&sb["war"]), n(&sb["recycle_stale"]), n(&sb["unresolved_edges"])), (0, 0, 0, 0));
    assert!(sb["findings"].as_array().unwrap().is_empty());
    assert_eq!((n(&k["store_paths"]["pairs"]), n(&k["store_paths"]["shared_address"])), (0, 0));
    assert!(dep["blind"].as_array().unwrap().is_empty());
}

#[test]
fn the_store_pairs_and_the_scoreboard_findings_carry_their_instructions() {
    let l = lines("v43b", V43B, &[]);
    assert_eq!(l.len(), 1);
    let k = &l[0];
    let sp = &k["store_paths"];
    assert_eq!((n(&sp["pairs"]), n(&sp["shared_address"])), (3, 0));
    let f: Vec<(u64, u64, &str, &str, u64, u64, &str)> = sp["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                n(&f["store"]),
                n(&f["overwriter"]),
                f["register"].as_str().unwrap(),
                f["operand"].as_str().unwrap(),
                n(&f["read_barrier"]),
                n(&f["distance"]),
                f["class"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        f,
        [(1177, 733, "R68", "data", 3, 67, "pair"), (1348, 730, "R64", "data", 5, 58, "pair"), (1349, 733, "R68", "data", 3, 67, "pair")]
    );
    assert!(sp["findings"][0]["store_text"].as_str().unwrap().contains("STS.128"));
    assert!(sp["findings"][0]["overwriter_text"].as_str().unwrap().contains("LDSM.16.M88.4"));
    // the three classic counts are the CUBIT_VERIFY line's; every finding names its two instructions
    let dir = scratch("v43b_text");
    let (log, _) = asm(&dir, V43B, &[("CUBIT_VERIFY", "1")]);
    let _ = std::fs::remove_dir_all(&dir);
    let sb = &k["scoreboard"];
    let line = format!("CUBIT_VERIFY: {} unprotected RAW, {} broken WAR, {} recycle-stale", n(&sb["raw"]), n(&sb["war"]), n(&sb["recycle_stale"]));
    assert!(log.contains(&line), "{line}\n{log}");
    assert_eq!((n(&sb["raw"]), n(&sb["war"])), (0, 0));
    let findings = sb["findings"].as_array().unwrap();
    assert!(!findings.is_empty() && findings.len() as u64 <= n(&sb["recycle_stale"]));
    let count = n(&k["instructions"]);
    for f in findings {
        assert_eq!(f["kind"], "recycle-stale");
        assert!(n(&f["at"]) < count && n(&f["other"]) < count);
        let reg = f["register"].as_str().unwrap();
        assert!(reg.starts_with('R') || reg.starts_with('P') || reg.starts_with('U'), "{reg}");
        assert!(!f["at_text"].as_str().unwrap().is_empty() && !f["other_text"].as_str().unwrap().is_empty());
    }
}

#[test]
fn the_variable_changes_no_byte_prints_nothing_and_the_file_is_appended_to() {
    let dir = scratch("readonly");
    let file = dir.join("legality.jsonl");
    let (plain_log, plain) = asm(&dir, R2UR, &[]);
    let (log, with) = asm(&dir, R2UR, &[("CUBIT_VERIFY_JSON", file.to_str().unwrap())]);
    assert_eq!(plain, with);
    assert_eq!(plain_log, log);
    assert_eq!(std::fs::read_to_string(&file).unwrap().lines().count(), 1);
    // a second kernel into the same file: a second line, the first untouched
    let first = std::fs::read_to_string(&file).unwrap();
    asm(&dir, V43B, &[("CUBIT_VERIFY_JSON", file.to_str().unwrap())]);
    let both = std::fs::read_to_string(&file).unwrap();
    assert!(both.starts_with(&first));
    assert_eq!(both.lines().count(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_switch_of_the_synchronisation_classes_is_recorded() {
    let l = lines("sync", R2UR, &[("CUBIT_SYNC_CLASSES", "1")]);
    assert_eq!(l[0]["sync_classes"], true);
    assert_eq!(n(&l[0]["dep"]["below_default"]), 3);
}
