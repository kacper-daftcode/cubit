//! The sites of cubit's own schedule of a served kernel (the persistent MoE kernel under `CUBIT_SYNC_CLASSES`) that
//! an independent gate listed and `CUBIT_VERIFY` did not, as small frozen kernels — written by session EM-7
//! (2026-11-11) as failing-first tests for the gatekeeper, taken with the fixes they describe.
//!
//! Each fixture (`tests/fixtures/ps_s2/`) is a seven-to-ten-instruction frozen kernel with the control codes of the
//! real site; every one assembles, and on the tree before the fix every one was clean in every count (0 RAW / 0 WAR /
//! 0 recycle-stale, 0 dependency findings, 0 store paths), so nothing else speaks in them.
//!
//! WRITE AFTER WRITE of two scoreboarded producers (BUG-489): `[W5] LDC.64 R28, c[0x0][0x388]` … `[W5] @P0 LDC.64 R28,
//! c[0x0][0x3b8]` — one register pair, one write barrier, no wait between (ptxas schedules the same two words `[W3]` …
//! `[B---3--:W1]`: the second writer waits on the first one's barrier). `ps_s2_waw` failed first (no finding);
//! `ps_s2_waw_vendor` (ptxas's form) and `ps_s2_waw_exclusive` (complementary guards: the two writers never both
//! execute) are the controls.
//!
//! The assertions fix a FORM, not names: a finding is any object of any `findings` array of the `CUBIT_VERIFY_JSON`
//! line that carries both instruction indices as numbers and the register as a string. Indices are those of the
//! fixture (first instruction = 0).

use serde_json::Value;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);

const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ps_s2/");

/// The one JSON line `CUBIT_VERIFY_JSON` writes for the fixture `name`.
fn legality(name: &str) -> Value {
    let dir = std::env::temp_dir().join(format!("ps_s2_sites_{}_{}_{name}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (file, out) = (dir.join("legality.jsonl"), dir.join("k.cubin"));
    let listing = format!("{DIR}{name}.frozen.sass");
    let o = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", TABLE, &listing, "-o", out.to_str().unwrap()])
        .env_clear()
        .envs([("CUBIT_VERIFY", "1"), ("CUBIT_VERIFY_JSON", file.to_str().unwrap())])
        .output()
        .expect("run cubit");
    let log = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success(), "{log}");
    let text = std::fs::read_to_string(&file).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "{text}");
    serde_json::from_str(lines[0]).unwrap_or_else(|e| panic!("not JSON ({e}): {}", lines[0]))
}

/// Every object of every array called `findings` anywhere in the line.
fn findings(v: &Value, out: &mut Vec<Value>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if k == "findings" {
                    if let Value::Array(a) = x {
                        out.extend(a.iter().cloned());
                    }
                } else {
                    findings(x, out);
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| findings(x, out)),
        _ => {}
    }
}

/// The findings that name the instructions `a` and `b` (as numbers, in any field) and the register `reg` (as a string).
fn naming(line: &Value, a: u64, b: u64, reg: &str) -> Vec<Value> {
    let mut all = Vec::new();
    findings(line, &mut all);
    all.into_iter()
        .filter(|f| {
            let m = f.as_object().unwrap();
            let has = |n: u64| m.values().any(|x| x.as_u64() == Some(n));
            has(a) && has(b) && m.values().any(|x| x.as_str() == Some(reg))
        })
        .collect()
}

fn counters(line: &Value) -> (u64, u64, u64) {
    let s = &line["scoreboard"];
    (s["raw"].as_u64().unwrap(), s["war"].as_u64().unwrap(), s["recycle_stale"].as_u64().unwrap())
}

// ---- write after write of two scoreboarded producers ----

#[test]
fn two_scoreboarded_writes_of_one_register_with_no_wait_between_are_reported() {
    // [2] [W5] LDC.64 R28 ... [4] [W5] @P0 LDC.64 R28 -- no wait on barrier 5 between them
    let line = legality("ps_s2_waw");
    let f = naming(&line, 2, 4, "R28");
    assert!(!f.is_empty(), "no finding names the two writers [2], [4] of R28: {line}");
    assert!(f.iter().all(|x| x["kind"] == "waw"), "{f:?}");
    // beside the three classic counts, not inside them
    assert_eq!(counters(&line), (0, 0, 0));
    assert_eq!(line["scoreboard"]["waw"], 1);
}

#[test]
fn the_second_writer_waiting_on_the_first_ones_barrier_is_clean() {
    let line = legality("ps_s2_waw_vendor"); // ptxas: [2] [W3] ... [4] [B---3--:W5]
    assert!(naming(&line, 2, 4, "R28").is_empty(), "{line}");
    assert_eq!(counters(&line), (0, 0, 0));
}

#[test]
fn two_writers_under_complementary_guards_are_no_pair() {
    let line = legality("ps_s2_waw_exclusive"); // [3] @!P0 LDC.64 R28 / [4] @P0 LDC.64 R28
    assert!(naming(&line, 3, 4, "R28").is_empty(), "{line}");
    assert_eq!(counters(&line), (0, 0, 0));
}
