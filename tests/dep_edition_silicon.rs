//! The 'silicon' edition of the sm_120 dependency table (`tables/dep_latency_sm120_silicon.json`,
//! `src/dep_edition.rs`, 2026-11-11): the table with lower numbers in the entries that have silicon
//! evidence -- read only when asked for by name, and refused where the evidence falls short.
//!
//! The rule an entry is held to: `L` = measured floor + 1; the evidence is a set of probe digests
//! committed under `tools/stallfloor/silicon/`, and it must hold the Server Edition card and at
//! least TWO Workstation Edition cards (production's model: the floor of a model is the maximum
//! over its cards), each of those in two clock states -- the SM clock at 2.8 GHz or more, and the
//! card at its 400 W cap under load. Every run: the floor distance right at the four occupancies
//! (and the served grids for a tensor row), a wrong result below the floor (or the declared
//! interlock at floor 1), nothing wrong at or above it, clean controls, and 1e8 thread-launches
//! right at `L` itself. The floors of the four production cards are recorded beside an edition
//! that has an entry (witnesses), and no cell lies below any of them + 1.
//!
//! Pinned here: (1) the bundled edition stands on its evidence files, entry by entry; (2) without
//! an entry it prices every kernel like the default table, and it is read only when named
//! (`CUBIT_SCHED2_LAT=sm120-silicon`, `CUBIT_DEP_TABLE=sm120-silicon`); (3) every way of falling
//! short of the rule is refused -- a missing file, an altered file, one card model, ONE CARD of
//! the Workstation model, one clock state of a Workstation card, too few thread-launches at the
//! entry's distance, a floor without its positive control, a wrong result at or above the floor,
//! a failed control, a missing occupancy, fewer than four production cards as witnesses, a cell
//! below a production card's floor + 1; (4) the switches fail closed.

use cubit::dep_edition::{self, Edition};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);

const ROOT: &str = env!("CARGO_MANIFEST_DIR");
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
/// frozen listings with findings of every kind (`tests/store_paths_verify.rs`, `tests/r2ur_pred_dest.rs`)
const V43B: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/store_paths/attention_v43b.frozen.sass");
const R2UR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/r2ur_pred/broadcast.sched2_6264d55.frozen.sass");
/// sources the dependency-aware scheduler builds (`tests/sched2_dep_latency.rs`)
const SCHED2_SOURCES: [&str; 8] = ["arm", "branch_target", "join", "loop", "pairs", "resources", "mma_chain", "mma_adjacent"];

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("dep_edition_{}_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst), tag));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `cubit asm <listing>` with `env`: (success, stdout + stderr, the cubin's bytes when written).
fn asm(tag: &str, isa: &str, listing: &str, env: &[(&str, &str)]) -> (bool, String, Vec<u8>) {
    let dir = scratch(tag);
    let out = dir.join("k.cubin");
    let o = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", isa, listing, "-o", out.to_str().unwrap()])
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .expect("run cubit");
    let log = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    let bytes = std::fs::read(&out).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);
    (o.status.success(), log.replace(dir.to_str().unwrap(), "<dir>"), bytes)
}

fn bundled() -> Edition {
    dep_edition::parse(dep_edition::SM120_SILICON).unwrap()
}

// ───────────────────────── (1) the bundled edition and its evidence ─────────────────────────

#[test]
fn the_bundled_edition_stands_on_its_evidence_files() {
    let ed = bundled();
    assert_eq!(ed.name, "sm120-silicon");
    assert_eq!(ed.arch, "sm_120");
    // the file of the repository IS the edition the binary carries
    let on_disk = std::fs::read_to_string(format!("{ROOT}/tables/dep_latency_sm120_silicon.json")).unwrap();
    assert_eq!(on_disk, dep_edition::SM120_SILICON);
    // every entry against its files, as the rule reads (an edition without entries has nothing to show)
    let read = |path: &str| std::fs::read(format!("{ROOT}/{path}")).ok();
    let problems = dep_edition::validate_evidence(&ed, &read);
    assert!(problems.is_empty(), "the bundled edition falls short of its own rule:\n{}", problems.join("\n"));
    // and it applies to the bundled table (no entry names nothing, none raises)
    let t = dep_edition::load_bundled().unwrap();
    assert_eq!(t.edition, Some(("sm120-silicon".to_string(), ed.len())));
    // an evidence file that no entry names does not belong beside the table
    let named: Vec<&str> =
        ed.entries().flat_map(|(_, e)| e.evidence.iter().map(|r| r.file.as_str())).chain(ed.witnesses.iter().map(|w| w.file.as_str())).collect();
    if let Ok(dir) = std::fs::read_dir(format!("{ROOT}/{}", dep_edition::EVIDENCE_DIR)) {
        for f in dir.flatten() {
            let name = f.file_name().to_string_lossy().to_string();
            if name.ends_with(".json") {
                let path = format!("{}{name}", dep_edition::EVIDENCE_DIR);
                assert!(named.contains(&path.as_str()), "{path} is evidence of no entry");
            }
        }
    }
}

// ───────────────────────── (2) read only when asked; without entries = the default ─────────────────────────

#[test]
fn the_edition_is_read_only_when_named_and_without_entries_prices_like_the_default() {
    let ed = bundled();
    let label = format!("table sm_120 edition sm120-silicon ({} entries)", ed.len());
    for (tag, listing) in [("v43b", V43B), ("r2ur", R2UR)] {
        // the read-only check of a frozen listing: default, the default by name, the edition by name
        let (ok, plain, cubin) = asm(tag, TABLE, listing, &[("CUBIT_DEP_VERIFY", "400")]);
        assert!(ok, "{plain}");
        assert!(plain.contains("DEP_VERIFY") && plain.contains("table sm_120)") && !plain.contains("edition"), "{plain}");
        let (ok, named, cubin_named) = asm(tag, TABLE, listing, &[("CUBIT_DEP_VERIFY", "400"), ("CUBIT_DEP_TABLE", "sm120")]);
        assert!(ok, "{named}");
        assert_eq!(named, plain, "CUBIT_DEP_TABLE=sm120 is the default table");
        assert_eq!(cubin_named, cubin);
        for off in ["", "0"] {
            let (ok, log, _) = asm(tag, TABLE, listing, &[("CUBIT_DEP_VERIFY", "400"), ("CUBIT_DEP_TABLE", off)]);
            assert!(ok && log == plain, "CUBIT_DEP_TABLE={off:?} is off:\n{log}");
        }
        let (ok, silicon, cubin_silicon) = asm(tag, TABLE, listing, &[("CUBIT_DEP_VERIFY", "400"), ("CUBIT_DEP_TABLE", "sm120-silicon")]);
        assert!(ok, "{silicon}");
        assert!(silicon.contains(&label), "{silicon}");
        assert_eq!(cubin_silicon, cubin, "a read-only check writes the same bytes");
        if ed.is_empty() {
            assert_eq!(silicon.replace(&label, "table sm_120"), plain, "an edition without entries finds what the default table finds");
        }
        // the variable alone prints nothing and changes nothing
        let (ok, quiet, cubin_quiet) = asm(tag, TABLE, listing, &[("CUBIT_DEP_TABLE", "sm120-silicon")]);
        let (_, quiet_plain, _) = asm(tag, TABLE, listing, &[]);
        assert!(ok && quiet == quiet_plain && cubin_quiet == cubin, "{quiet}");
    }
}

#[test]
fn the_json_line_names_the_edition_only_under_it() {
    fn line(tag: &str, more: &[(&str, &str)]) -> Value {
        let dir = scratch(tag);
        let file = dir.join("legality.jsonl");
        let mut env: Vec<(&str, &str)> = vec![("CUBIT_VERIFY_JSON", file.to_str().unwrap())];
        env.extend_from_slice(more);
        let (ok, log, _) = asm(tag, TABLE, R2UR, &env);
        assert!(ok, "{log}");
        let text = std::fs::read_to_string(&file).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        serde_json::from_str(text.lines().next().unwrap()).unwrap()
    }
    let plain = line("json_plain", &[]);
    assert_eq!(plain["dep"]["table"], "sm_120");
    assert!(plain["dep"].get("edition").is_none(), "the default line has no such field");
    let silicon = line("json_silicon", &[("CUBIT_DEP_TABLE", "sm120-silicon")]);
    assert_eq!(silicon["dep"]["table"], "sm_120");
    assert_eq!(silicon["dep"]["edition"], json!({"name": "sm120-silicon", "entries": bundled().len()}));
    if bundled().is_empty() {
        let mut same = silicon.clone();
        same["dep"].as_object_mut().unwrap().remove("edition");
        assert_eq!(same, plain);
    }
}

#[test]
fn the_scheduler_reads_the_edition_by_name_and_without_entries_builds_the_same_kernel() {
    let ed = bundled();
    for name in SCHED2_SOURCES {
        let src = format!("{ROOT}/tests/fixtures/sched2_dep/{name}.sass");
        let (ok, log, base) = asm(name, TABLE, &src, &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120"), ("CUBIT_DEP_VERIFY", "40")]);
        assert!(ok, "{name}: {log}");
        let (ok, log_s, silicon) =
            asm(name, TABLE, &src, &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120-silicon"), ("CUBIT_DEP_VERIFY", "40")]);
        assert!(ok, "{name}: {log_s}");
        assert!(log_s.contains("edition sm120-silicon"), "{name}: the check names the table the scheduler ran with:\n{log_s}");
        if ed.is_empty() {
            assert_eq!(silicon, base, "{name}: an edition without entries schedules like the default table");
            assert_eq!(log_s.replace(&format!(" edition sm120-silicon ({} entries)", ed.len()), ""), log, "{name}");
        }
    }
}

// ───────────────────────── (4) the switches fail closed ─────────────────────────

#[test]
fn the_switches_fail_closed() {
    // the edition for the scheduler needs the scheduler's switch, like every table
    let src = format!("{ROOT}/tests/fixtures/sched2_dep/pairs.sass");
    let (ok, log, _) = asm("lat_alone", TABLE, &src, &[("CUBIT_SCHED2_LAT", "sm120-silicon")]);
    assert!(!ok && log.contains("CUBIT_SCHED2_LAT needs CUBIT_SCHED2=1"), "{log}");
    // a table file that is not there
    let (ok, log, _) = asm("nofile", TABLE, R2UR, &[("CUBIT_DEP_VERIFY", "1"), ("CUBIT_DEP_TABLE", "/nonexistent/table.json")]);
    assert!(!ok && log.contains("CUBIT_DEP_TABLE: cannot read"), "{log}");
    // an edition file is not a table: by path it is refused (an edition is read by its name only)
    let (ok, log, _) = asm(
        "edition_by_path",
        TABLE,
        R2UR,
        &[("CUBIT_DEP_VERIFY", "1"), ("CUBIT_DEP_TABLE", concat!(env!("CARGO_MANIFEST_DIR"), "/tables/dep_latency_sm120_silicon.json"))],
    );
    assert!(!ok, "{log}");
    // the arch lock: a table measured for another architecture is refused
    let dir = scratch("arch");
    let other = dir.join("dep_other.json");
    let text = std::fs::read_to_string(format!("{ROOT}/tables/dep_latency_sm120.json")).unwrap();
    assert!(text.contains(r#""arch": "sm_120""#));
    std::fs::write(&other, text.replacen(r#""arch": "sm_120""#, r#""arch": "sm_103a""#, 1)).unwrap();
    let (ok, log, _) = asm("arch_run", TABLE, R2UR, &[("CUBIT_DEP_VERIFY", "1"), ("CUBIT_DEP_TABLE", other.to_str().unwrap())]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!ok && log.contains("is for sm_103a but the ISA table is SM120"), "{log}");
    // a table by path prices by its own numbers (the way of an exploration table stays open)
    let dir = scratch("path");
    let own = dir.join("dep_own.json");
    std::fs::write(&own, std::fs::read_to_string(format!("{ROOT}/tables/dep_latency_sm120.json")).unwrap()).unwrap();
    let (ok, log, _) = asm("path_run", TABLE, R2UR, &[("CUBIT_DEP_VERIFY", "400"), ("CUBIT_DEP_TABLE", own.to_str().unwrap())]);
    let (_, plain, _) = asm("path_plain", TABLE, R2UR, &[("CUBIT_DEP_VERIFY", "400")]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(ok && log == plain, "{log}");
}

// ───────────────────────── (3) the evidence rule: every way of falling short is refused ─────────────────────────

const SERVER: &str = "NVIDIA RTX PRO 6000 Blackwell Server Edition";
const WORKSTATION: &str = "NVIDIA RTX PRO 6000 Blackwell Workstation Edition";

/// One series of a digest: every distance of `good` right in every thread, every one of `bad` not.
fn series(variant: &str, occ: &str, launches: u64, good: &[u64], bad: &[u64]) -> Value {
    let not_good: serde_json::Map<String, Value> = bad.iter().map(|d| (d.to_string(), json!({"stale": launches}))).collect();
    json!({
        "variant": variant, "occupancy": occ, "front": "none",
        "floor": good.iter().min(), "last_not_good": bad.iter().max(),
        "thread_launches_per_kernel": launches, "good_at": good, "not_good": not_good,
        "oracle": format!("ok (distance {}: good in every thread)", good.iter().max().unwrap_or(&0)),
    })
}

fn request(id: &str, series: Vec<Value>) -> Value {
    json!({
        "id": id, "pair": "synthetic", "request": {"kind": "raw", "producer": "IADD3", "consumer": "IADD3.r1"},
        "table_cell": null, "floor": {"binding": 2, "per_condition": {}, "oracle_failures": []},
        "errors": 0, "skipped_kernels": 0, "series": series,
    })
}

/// A digest as `tools/stallfloor/probe.py` files it: the card model, the card, the mean SM clock and the
/// median draw of the run.
fn digest(gpu: &str, card: &str, clock_mhz: f64, median_w: f64, requests: Vec<Value>) -> Value {
    json!({
        "arch": "sm_120", "harness": "synthetic (tests/dep_edition_silicon.rs): no silicon behind these numbers", "what": "synthetic",
        "conditions": {"gpu": gpu, "card": card, "driver": "0", "clocks_max_sm": "3090 MHz", "power_limit": "400.00 W", "reps": 20,
                       "clock_busy_mean_mhz": clock_mhz, "clock_busy_max_mhz": clock_mhz,
                       "power_median_w": median_w, "power_max_w": median_w + 3.0},
        "provenance": {"tool": "synthetic"}, "classes": {}, "requests": requests,
    })
}

/// The runs of a complete entry by name: `server`; `ws_<card>_fast` (2.95 GHz, 190 W); `ws_<card>_cap`
/// (2.29 GHz, the median draw 399 W of the 400 W limit).
fn run_digest(name: &str, requests: Vec<Value>) -> Value {
    let parts: Vec<&str> = name.split('_').collect();
    match parts.as_slice() {
        ["server"] => digest(SERVER, "", 2370.0, 180.0, requests),
        ["ws", card, "fast"] => digest(WORKSTATION, &format!("ws-{card}"), 2950.0, 190.0, requests),
        ["ws", card, "cap"] => digest(WORKSTATION, &format!("ws-{card}"), 2290.0, 399.0, requests),
        _ => panic!("no such run: {name}"),
    }
}

const RUNS: [&str; 5] = ["server", "ws_a_fast", "ws_a_cap", "ws_b_fast", "ws_b_cap"];

/// The floors of one production card, as the edition's `witnesses` name them.
fn witness(card: &str, floors: &[(&str, &str, &str, u64)]) -> Value {
    let floors: Vec<Value> = floors.iter().map(|(p, c, r, f)| json!({"producer": p, "consumer": c, "role": r, "floor": f})).collect();
    json!({
        "schema": "cubit-dep-witness-1", "arch": "sm_120", "what": "synthetic (tests/dep_edition_silicon.rs)",
        "conditions": {"gpu": WORKSTATION, "card": card}, "floors": floors,
    })
}

const OCC: [&str; 4] = ["w1", "w8", "w32", "g32"];

/// The two requests of a complete run for the floor 2 / the entry's distance 3: the sweep (wrong at 1,
/// right from 2, at the four occupancies) and the confirmation at 3 (4 x 30e6 thread-launches).
fn complete_run() -> Vec<Value> {
    vec![
        request("sweep", OCC.iter().map(|o| series("raw", o, 3_850_240, &[2, 3, 4, 5, 6, 30], &[1])).collect()),
        request("confirm", OCC.iter().map(|o| series("raw", o, 30_000_000, &[3], &[])).collect()),
    ]
}

struct Case {
    files: HashMap<String, Vec<u8>>,
    /// (file, request) in the order the entry names them
    refs: Vec<(String, String)>,
    /// the witness files in the order the edition names them
    witnesses: Vec<String>,
    floor: u8,
    l: u8,
    basis: &'static str,
    /// the sha256 the edition names for a file, when it is not the file's own
    forged: HashMap<String, String>,
    section: &'static str,
}

impl Case {
    fn empty(section: &'static str, floor: u8, basis: &'static str) -> Self {
        Case { files: HashMap::new(), refs: Vec::new(), witnesses: Vec::new(), floor, l: floor + 1, basis, forged: HashMap::new(), section }
    }

    /// The entry `IADD3 -> IADD3 (r1)`: floor 2, L 3, a complete run on the Server Edition card and on
    /// two Workstation Edition cards in both clock states, and the floors of four production cards
    /// (2 for this pair on each) as witnesses.
    fn complete() -> Self {
        let mut c = Case::empty("cells", 2, "wrong-below");
        for name in RUNS {
            c.put(name, &run_digest(name, complete_run()));
        }
        for i in 0..4 {
            c.put_witness(&format!("witness_prod_{i}"), &witness(&format!("prod-{i}"), &[("IADD3", "IADD3", "r1", 2), ("FMNMX", "SHFL", "r1", 2)]));
        }
        c
    }

    fn path(name: &str) -> String {
        format!("{}{name}.json", dep_edition::EVIDENCE_DIR)
    }

    /// (re)place the digest `name` and name its requests in the entry
    fn put(&mut self, name: &str, doc: &Value) {
        let path = Self::path(name);
        self.files.insert(path.clone(), serde_json::to_vec(doc).unwrap());
        for r in doc["requests"].as_array().unwrap() {
            let key = (path.clone(), r["id"].as_str().unwrap().to_string());
            if !self.refs.contains(&key) {
                self.refs.push(key);
            }
        }
    }

    fn drop_run(&mut self, name: &str) {
        let path = Self::path(name);
        self.files.remove(&path);
        self.refs.retain(|(f, _)| f != &path);
    }

    /// (re)place the witness file `name` and name it in the edition
    fn put_witness(&mut self, name: &str, doc: &Value) {
        let path = Self::path(name);
        self.files.insert(path.clone(), serde_json::to_vec(doc).unwrap());
        if !self.witnesses.contains(&path) {
            self.witnesses.push(path);
        }
    }

    fn drop_witness(&mut self, name: &str) {
        let path = Self::path(name);
        self.files.remove(&path);
        self.witnesses.retain(|f| f != &path);
    }

    fn sha(&self, file: &str) -> String {
        self.forged.get(file).cloned().unwrap_or_else(|| match self.files.get(file) {
            Some(b) => Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect(),
            None => "0".repeat(64),
        })
    }

    fn edition(&self) -> Edition {
        let evidence: Vec<Value> = self.refs.iter().map(|(f, r)| json!({"file": f, "sha256": self.sha(f), "request": r})).collect();
        let common = json!({"id": "e", "floor": self.floor, "floor_basis": self.basis, "L": self.l, "evidence": evidence});
        let mut entry = common.as_object().unwrap().clone();
        let target = match self.section {
            "cells" => json!({"producer": "IADD3", "consumer": "IADD3", "role": "r1"}),
            "resources" => json!({"resource": "mma", "first": "QMMA", "second": "QMMA"}),
            _ => json!({"hold": "mma_a_fragment"}),
        };
        entry.extend(target.as_object().unwrap().clone());
        let witnesses: Vec<Value> = self.witnesses.iter().map(|f| json!({"file": f, "sha256": self.sha(f)})).collect();
        let mut doc = json!({"schema": "cubit-dep-edition-1", "edition": "synthetic", "arch": "sm_120", "base": "dep_latency_sm120.json",
                             "witnesses": witnesses});
        doc[self.section] = json!([entry]);
        dep_edition::parse(&doc.to_string()).unwrap_or_else(|e| panic!("the synthetic edition does not parse: {e}"))
    }

    fn problems(&self) -> Vec<String> {
        let read = |path: &str| self.files.get(path).cloned();
        dep_edition::validate_evidence(&self.edition(), &read)
    }

    /// refused, for a reason that says `why` -- and for nothing else
    fn refused(&self, why: &str) {
        self.refused_with(&[why]);
    }

    /// refused: every one of `whys` is said, and nothing is said beside them
    fn refused_with(&self, whys: &[&str]) {
        let p = self.problems();
        for why in whys {
            assert!(p.iter().any(|x| x.contains(why)), "expected a refusal that says `{why}`:\n{}", p.join("\n"));
        }
        assert!(p.iter().all(|x| whys.iter().any(|why| x.contains(why))), "expected only {whys:?}:\n{}", p.join("\n"));
    }
}

#[test]
fn an_entry_with_complete_runs_on_both_card_models_is_accepted() {
    let c = Case::complete();
    assert_eq!(c.problems(), Vec::<String>::new());
    // and it applies: IADD3 -> IADD3 (r1) is 4 in today's table, 3 under this edition
    let t = dep_edition::apply(cubit::dep_stall::DepLatTable::from_json(cubit::dep_stall::SM120_TABLE).unwrap(), &c.edition()).unwrap();
    assert_eq!(t.edition, Some(("synthetic".to_string(), 1)));
    // a third Workstation card is welcome
    let mut c = Case::complete();
    for name in ["ws_c_fast", "ws_c_cap"] {
        c.put(name, &run_digest(name, complete_run()));
    }
    assert_eq!(c.problems(), Vec::<String>::new());
}

#[test]
fn an_entry_without_its_evidence_files_is_refused() {
    // the file the entry names is not in the repository
    let mut c = Case::complete();
    c.files.remove(&Case::path("ws_b_cap"));
    c.refused_with(&["ws_b_cap.json is missing", "no evidence run on the Workstation Edition card `ws-b` at its 400 W cap under load"]);
    // none of them is
    let mut c = Case::complete();
    c.files.retain(|f, _| f.contains("witness"));
    let p = c.problems();
    assert_eq!(p.iter().filter(|x| x.contains("evidence file") && x.contains("is missing")).count(), 10, "{p:?}");
    assert!(p.iter().any(|x| x.contains("no evidence run on the Server Edition card")), "{p:?}");
    assert!(p.iter().any(|x| x.contains("no evidence run on a Workstation Edition card (at least 2 cards, each in both clock states)")), "{p:?}");
    assert_eq!(p.len(), 12, "{p:?}");
    // the file is there and is not the file the entry was written against
    let mut c = Case::complete();
    c.forged.insert(Case::path("server"), "a".repeat(64));
    c.refused_with(&["server.json: sha256 is", "no evidence run on the Server Edition card"]);
    // a file changed after the entry was written: one byte is enough
    let mut c = Case::complete();
    let ed = c.edition();
    c.files.get_mut(&Case::path("ws_a_fast")).unwrap().push(b'\n');
    let read = |path: &str| c.files.get(path).cloned();
    let p = dep_edition::validate_evidence(&ed, &read);
    assert!(p.iter().any(|x| x.contains("ws_a_fast.json: sha256 is")), "{p:?}");
    // the request the entry names is not in the file
    let mut c = Case::complete();
    c.refs.push((Case::path("server"), "elsewhere".to_string()));
    c.refused("has no request `elsewhere`");
}

#[test]
fn an_entry_measured_on_one_card_model_is_refused() {
    // the Server Edition card alone: an exploration result, not an entry
    let mut c = Case::complete();
    for name in &RUNS[1..] {
        c.drop_run(name);
    }
    c.refused("no evidence run on a Workstation Edition card (at least 2 cards, each in both clock states)");
    // the Workstation Edition cards alone
    let mut c = Case::complete();
    c.drop_run("server");
    c.refused("no evidence run on the Server Edition card");
    // five files of the same card model are one card model
    let mut c = Case::complete();
    for name in &RUNS[1..] {
        c.put(name, &digest(SERVER, "", 2370.0, 180.0, complete_run()));
    }
    c.refused("no evidence run on a Workstation Edition card");
    // a card the rule does not name
    let mut c = Case::complete();
    c.put("server", &digest("NVIDIA GeForce RTX 5090", "x", 2700.0, 300.0, complete_run()));
    c.refused_with(&["is neither card model of the rule", "no evidence run on the Server Edition card"]);
}

#[test]
fn an_entry_measured_on_one_card_of_the_workstation_model_is_refused() {
    // two cards of one model were measured one cycle apart on rare events: the floor of the model is the
    // maximum over at least two cards -- one card, however complete, is not the model
    let mut c = Case::complete();
    c.drop_run("ws_b_fast");
    c.drop_run("ws_b_cap");
    c.refused("evidence from 1 Workstation Edition card (`ws-a`): the floor of the model is the maximum over at least 2 cards");
    // the same card filed twice is one card
    let mut c = Case::complete();
    c.put("ws_b_fast", &run_digest("ws_a_fast", complete_run()));
    c.put("ws_b_cap", &run_digest("ws_a_cap", complete_run()));
    c.refused("evidence from 1 Workstation Edition card (`ws-a`)");
    // a digest that does not say which card it is cannot be a second card
    let mut c = Case::complete();
    c.put("ws_b_fast", &digest(WORKSTATION, "", 2950.0, 190.0, complete_run()));
    c.refused_with(&["does not name its card", "no evidence run on the Workstation Edition card `ws-b` at an SM clock of 2.8 GHz or more"]);
    let mut c = Case::complete();
    let mut d = run_digest("ws_b_fast", complete_run());
    d["conditions"].as_object_mut().unwrap().remove("card");
    c.put("ws_b_fast", &d);
    assert!(c.problems().iter().any(|x| x.contains("does not name its card")));
    // the second card in one clock state only
    let mut c = Case::complete();
    c.drop_run("ws_b_cap");
    c.refused("no evidence run on the Workstation Edition card `ws-b` at its 400 W cap under load");
    // the second card short of the thread-launches at the entry's distance
    let mut c = Case::complete();
    c.drop_run("ws_b_cap");
    c.put("ws_b_cap", &run_digest("ws_b_cap", complete_run()[..1].to_vec()));
    c.refused("on the Workstation Edition card `ws-b` at its 400 W cap under load 15400960 thread-launches right at the entry's own distance 3");
    // a wrong result at the floor on the SECOND card only: the model's floor is higher than the entry says
    let mut c = Case::complete();
    let mut run = complete_run();
    run[0] = request("sweep", OCC.iter().map(|o| series("raw", o, 3_850_240, &[3, 4, 5, 6, 30], &[1, 2])).collect());
    c.put("ws_b_fast", &run_digest("ws_b_fast", run));
    assert!(c.problems().iter().any(|x| x.contains("ws_b_fast.json") && x.contains("a wrong result at distance 2, at or above the floor 2")));
}

#[test]
fn a_workstation_card_needs_both_clock_states() {
    // only the fast clock
    let mut c = Case::complete();
    c.drop_run("ws_a_cap");
    c.refused("no evidence run on the Workstation Edition card `ws-a` at its 400 W cap under load");
    // only the capped card
    let mut c = Case::complete();
    c.drop_run("ws_a_fast");
    c.refused("no evidence run on the Workstation Edition card `ws-a` at an SM clock of 2.8 GHz or more");
    // two runs in the same state are one state: 2.95 GHz twice
    let mut c = Case::complete();
    c.put("ws_a_cap", &run_digest("ws_a_fast", complete_run()));
    c.refused("no evidence run on the Workstation Edition card `ws-a` at its 400 W cap under load");
    // a run in neither state -- 2.36 GHz at 180 W, the probe alone on a card that is not loaded -- is no run
    let mut c = Case::complete();
    c.put("ws_a_fast", &digest(WORKSTATION, "ws-a", 2360.0, 180.0, complete_run()));
    c.refused_with(&["a Workstation Edition run in neither clock state", "no evidence run on the Workstation Edition card `ws-a` at an SM clock of 2.8 GHz or more"]);
    // the thresholds: 2 799 MHz is not the fast clock, a median of 379 W is not the cap
    let mut c = Case::complete();
    c.put("ws_a_fast", &digest(WORKSTATION, "ws-a", 2799.0, 190.0, complete_run()));
    assert!(c.problems().iter().any(|x| x.contains("neither clock state")));
    let mut c = Case::complete();
    c.put("ws_a_cap", &digest(WORKSTATION, "ws-a", 2290.0, 379.0, complete_run()));
    assert!(c.problems().iter().any(|x| x.contains("neither clock state")));
    let mut c = Case::complete();
    c.put("ws_a_fast", &digest(WORKSTATION, "ws-a", 2800.0, 190.0, complete_run()));
    c.put("ws_a_cap", &digest(WORKSTATION, "ws-a", 2290.0, 380.0, complete_run()));
    assert_eq!(c.problems(), Vec::<String>::new());
    // near the cap is not at the cap: the largest draw reached 403 W, the median stayed at 376 W
    let mut c = Case::complete();
    let mut d = digest(WORKSTATION, "ws-a", 2415.0, 376.0, complete_run());
    d["conditions"]["power_max_w"] = json!(403.0);
    c.put("ws_a_cap", &d);
    assert!(c.problems().iter().any(|x| x.contains("neither clock state") && x.contains("median draw 376 W")));
    // a digest without the median draw cannot show the cap
    let mut c = Case::complete();
    let mut d = run_digest("ws_a_cap", complete_run());
    d["conditions"].as_object_mut().unwrap().remove("power_median_w");
    c.put("ws_a_cap", &d);
    assert!(c.problems().iter().any(|x| x.contains("neither clock state")));
    // another power limit than the one production runs under
    let mut c = Case::complete();
    let mut d = run_digest("ws_a_cap", complete_run());
    d["conditions"]["power_limit"] = json!("600.00 W");
    c.put("ws_a_cap", &d);
    assert!(c.problems().iter().any(|x| x.contains("neither clock state") && x.contains("power limit 600 W")));
}

#[test]
fn every_run_needs_1e8_thread_launches_at_the_entrys_own_distance() {
    assert_eq!(dep_edition::MIN_THREAD_LAUNCHES, 100_000_000);
    // a sweep alone finds a floor (4 x 3.85e6 at the distance 3) and is thin for a number a kernel stands on:
    // every one of the five runs needs its own 1e8
    for name in RUNS {
        let mut c = Case::complete();
        c.drop_run(name);
        c.put(name, &run_digest(name, complete_run()[..1].to_vec()));
        c.refused("15400960 thread-launches right at the entry's own distance 3");
    }
    // launches at another distance do not count: the confirmation ran at 4, the entry stands at 3
    let mut c = Case::complete();
    let mut run = complete_run();
    run[1] = request("confirm", OCC.iter().map(|o| series("raw", o, 30_000_000, &[4], &[])).collect());
    c.put("server", &run_digest("server", run));
    c.refused("on the Server Edition card 15400960 thread-launches right at the entry's own distance 3");
    // one short of the rule; and the rule exactly
    let at3 = |confirm: u64| {
        let mut run = complete_run();
        run[1] = request("confirm", vec![series("raw", "w32", confirm, &[3], &[])]);
        let mut c = Case::complete();
        c.put("ws_a_cap", &run_digest("ws_a_cap", run));
        c
    };
    at3(100_000_000 - 15_400_960 - 1).refused("99999999 thread-launches right at the entry's own distance 3");
    assert_eq!(at3(100_000_000 - 15_400_960).problems(), Vec::<String>::new());
}

#[test]
fn a_floor_needs_its_positive_control_and_nothing_wrong_above_it() {
    // "no failure found" is not a floor: nothing wrong below it on one card
    let mut c = Case::complete();
    let mut run = complete_run();
    run[0] = request("sweep", OCC.iter().map(|o| series("raw", o, 3_850_240, &[1, 2, 3, 4, 5, 6, 30], &[])).collect());
    c.put("ws_a_fast", &run_digest("ws_a_fast", run));
    c.refused("no wrong result below the floor 2");
    // a wrong result AT the floor, at one occupancy of one run: the floor is not the floor
    let mut c = Case::complete();
    let mut run = complete_run();
    let mut s: Vec<Value> = OCC.iter().map(|o| series("raw", o, 3_850_240, &[2, 3, 4, 5, 6, 30], &[1])).collect();
    s[2] = series("raw", "w32", 3_850_240, &[3, 4, 5, 6, 30], &[1, 2]);
    run[0] = request("sweep", s);
    c.put("ws_a_cap", &run_digest("ws_a_cap", run));
    let p = c.problems();
    assert!(p.iter().any(|x| x.contains("a wrong result at distance 2, at or above the floor 2")), "{p:?}");
    // a wrong result above the entry's own distance (a late tail) refuses it as well
    let mut c = Case::complete();
    let mut run = complete_run();
    let mut s: Vec<Value> = OCC.iter().map(|o| series("raw", o, 3_850_240, &[2, 3, 4, 5, 6, 30], &[1])).collect();
    s[0] = series("raw", "w1", 3_850_240, &[2, 3, 4, 6, 30], &[1, 5]);
    run[0] = request("sweep", s);
    c.put("server", &run_digest("server", run));
    assert!(c.problems().iter().any(|x| x.contains("a wrong result at distance 5, at or above the floor 2")));
    // the entry's distance is the floor + 1: with the same evidence, L = floor is not an entry (parse refuses it)
    let mut c = Case::complete();
    c.l = 2;
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| c.edition()));
    assert!(r.is_err(), "L = floor must not parse");
    // a claimed floor below the measured one: the evidence shows a wrong result at it
    // (floor 1 would have to be an interlock, and an interlock has nothing wrong anywhere)
    let mut c = Case::complete();
    c.floor = 1;
    c.l = 2;
    c.basis = "interlock";
    let p = c.problems();
    assert!(p.iter().any(|x| x.contains("a wrong result at distance 1, at or above the floor 1")), "{p:?}");
}

#[test]
fn the_controls_and_the_occupancies_of_every_run_count() {
    // a failed control of the request
    let mut c = Case::complete();
    let mut run = complete_run();
    run[0]["floor"]["oracle_failures"] = json!(["w8/none: the largest distance (30) is not good (other 0.01%)"]);
    c.put("server", &run_digest("server", run));
    let p = c.problems();
    assert!(p.iter().any(|x| x.contains("has a failed control")), "{p:?}");
    // a series whose control did not run clean
    let mut c = Case::complete();
    let mut run = complete_run();
    run[1]["series"][3]["oracle"] = json!("FAILED");
    c.put("server", &run_digest("server", run));
    assert!(c.problems().iter().any(|x| x.contains("the series has no clean control")));
    // an incomplete request (a kernel that did not launch, a launch error)
    for key in ["errors", "skipped_kernels"] {
        let mut c = Case::complete();
        let mut run = complete_run();
        run[0][key] = json!(1);
        c.put("ws_a_fast", &run_digest("ws_a_fast", run));
        assert!(c.problems().iter().any(|x| x.contains("is incomplete")), "{key}");
    }
    // the floor at three of the four occupancies
    let mut c = Case::complete();
    let mut run = complete_run();
    run[0] = request("sweep", OCC[..3].iter().map(|o| series("raw", o, 3_850_240, &[2, 3, 4, 5, 6, 30], &[1])).collect());
    c.put("ws_b_cap", &run_digest("ws_b_cap", run));
    c.refused("on the Workstation Edition card `ws-b` at its 400 W cap under load the floor distance 2 is not shown right at the occupancies g32");
    // a control series (`ctl`) is not the measurement: only the series of the probe itself count
    let mut c = Case::complete();
    let run = vec![
        request("sweep", OCC.iter().map(|o| series("ctl", o, 3_850_240, &[2, 3, 4, 5, 6, 30], &[1])).collect()),
        request("confirm", OCC.iter().map(|o| series("ctl", o, 30_000_000, &[3], &[])).collect()),
    ];
    c.put("server", &run_digest("server", run));
    assert!(c.problems().iter().any(|x| x.contains("has no `raw` series")));
    // another architecture's digest
    let mut c = Case::complete();
    let mut d = run_digest("server", complete_run());
    d["arch"] = json!("sm_103a");
    c.put("server", &d);
    assert!(c.problems().iter().any(|x| x.contains("the edition is for sm_120")));
}

#[test]
fn a_tensor_row_needs_the_served_grids_and_a_hold_stands_under_the_same_rule() {
    // P1's shape: floor 1 (an interlock: nothing is wrong at any distance), L 2, the resource `mma`
    let grid_run = |occ: &[&str]| {
        let mut run = vec![
            request("sweep", occ.iter().map(|o| series("bare", o, 3_850_240, &[1, 2, 3, 4, 16, 30], &[])).collect()),
            request("confirm", occ.iter().map(|o| series("bare", o, 30_000_000, &[2], &[])).collect()),
        ];
        for r in run.iter_mut() {
            r["request"] = json!({"kind": "mma", "form": "QMMA.SF"});
        }
        run
    };
    let mma = |section: &'static str, occ: &[&str]| {
        let mut c = Case::empty(section, 1, "interlock");
        for name in RUNS {
            c.put(name, &run_digest(name, grid_run(occ)));
        }
        for i in 0..4 {
            c.put_witness(&format!("witness_prod_{i}"), &witness(&format!("prod-{i}"), &[("FMNMX", "SHFL", "r1", 2)]));
        }
        c
    };
    // the four occupancies alone are not enough for a tensor row: every one of the five runs says so
    let p = mma("resources", &OCC).problems();
    assert_eq!(p.len(), 5, "{p:?}");
    assert!(p.iter().all(|x| x.contains("is not shown right at the occupancies w12, c2w9s")), "{p:?}");
    // the 376-CTA grid `c2w9` of the earlier batches holds ONE CTA per SM: it is not the served 2 x 9 grid
    let p = mma("resources", &["w1", "w8", "w32", "g32", "w12", "c2w9"]).problems();
    assert_eq!(p.len(), 5, "{p:?}");
    assert!(p.iter().all(|x| x.contains("is not shown right at the occupancies c2w9s")), "{p:?}");
    // with the served grids it stands
    let all = ["w1", "w8", "w32", "g32", "w12", "c2w9s"];
    assert_eq!(mma("resources", &all).problems(), Vec::<String>::new());
    // the same evidence under a hold of the tensor operands: the same rule
    assert_eq!(mma("holds", &all).problems(), Vec::<String>::new());
    assert_eq!(mma("holds", &OCC).problems().len(), 5);
}

#[test]
fn the_production_cards_are_witnesses_no_cell_lies_below_their_floors() {
    // an edition with an entry records the floors of the four production cards beside it
    let mut c = Case::complete();
    c.drop_witness("witness_prod_3");
    c.refused("the floors of 3 production card(s) are recorded beside the edition as witnesses; an edition with an entry needs those of 4");
    let mut c = Case::complete();
    for i in 0..4 {
        c.drop_witness(&format!("witness_prod_{i}"));
    }
    c.refused("the floors of 0 production card(s)");
    // four files of one card are one card
    let mut c = Case::complete();
    for i in 1..4 {
        c.put_witness(&format!("witness_prod_{i}"), &witness("prod-0", &[("IADD3", "IADD3", "r1", 2)]));
    }
    c.refused("the floors of 1 production card(s)");
    // one production card measured the pair one cycle later than the probes did: the entry is below its floor + 1
    let mut c = Case::complete();
    c.put_witness("witness_prod_1", &witness("prod-1", &[("IADD3", "IADD3", "r1", 3)]));
    c.refused("cells entry `e`: L 3 is below the floor 3 + 1 that production card `prod-1` measured for IADD3 -> IADD3 (r1)");
    // the floor of another role or another pair on that card says nothing about this cell
    let mut c = Case::complete();
    c.put_witness("witness_prod_1", &witness("prod-1", &[("IADD3", "IADD3", "r2", 9), ("IADD3", "IMAD", "r1", 9)]));
    assert_eq!(c.problems(), Vec::<String>::new());
    // a witness file that is missing, altered, of another card model, or that does not name its card is no witness
    let mut c = Case::complete();
    c.files.remove(&Case::path("witness_prod_2"));
    c.refused_with(&["witness file tools/stallfloor/silicon/witness_prod_2.json is missing", "the floors of 3 production card(s)"]);
    let mut c = Case::complete();
    c.forged.insert(Case::path("witness_prod_2"), "b".repeat(64));
    c.refused_with(&["witness_prod_2.json: sha256 is", "the floors of 3 production card(s)"]);
    let mut c = Case::complete();
    let mut w = witness("prod-2", &[]);
    w["conditions"]["gpu"] = json!(SERVER);
    c.put_witness("witness_prod_2", &w);
    c.refused_with(&["is not the Workstation Edition", "the floors of 3 production card(s)"]);
    let mut c = Case::complete();
    c.put_witness("witness_prod_2", &witness("", &[]));
    c.refused_with(&["does not name its card", "the floors of 3 production card(s)"]);
    let mut c = Case::complete();
    let mut w = witness("prod-2", &[]);
    w["schema"] = json!("stall-floors");
    c.put_witness("witness_prod_2", &w);
    c.refused_with(&["is not `cubit-dep-witness-1`", "the floors of 3 production card(s)"]);
    // a floor line that is not whole is not skipped
    let mut c = Case::complete();
    let mut w = witness("prod-2", &[("IADD3", "IADD3", "r1", 2)]);
    w["floors"][0].as_object_mut().unwrap().remove("role");
    c.put_witness("witness_prod_2", &w);
    c.refused_with(&["a floor without producer / consumer / role / floor", "the floors of 3 production card(s)"]);
}
