//! The read-only legality checks of a scheduled kernel as data: `CUBIT_VERIFY_JSON=<file>`.
//!
//! `CUBIT_VERIFY=1 CUBIT_DEP_VERIFY=1 cubit asm <listing>` prints what the three checks find --
//! the scoreboard simulation (`scheduling_pass::verify_scoreboard_report`), the stores' read
//! barriers on every path (`store_paths`) and the fixed-latency dependencies against the table
//! (`dep_stall::check`). A tool that compares a candidate schedule with its seed had to parse
//! that text. With `CUBIT_VERIFY_JSON=<file>` the assembler appends ONE JSON line per kernel to
//! the file: the same counts and every finding with its instruction indices, so "what is new
//! against the seed" is a set difference. Nothing is printed for it and the bytes written are the
//! same with and without the variable; it does not need `CUBIT_VERIFY` / `CUBIT_DEP_VERIFY`.
//!
//! The counts are not a verdict. A listing of the vendor's assembler has findings of every class
//! (its schedules follow rules the checks do not model: the copy bursts, the idioms of
//! `docs/SM120_ASYNC_IDIOMS.md`); the rule a caller can hold a candidate to is "no finding the
//! seed does not have, and none closer than the seed has it" -- [`compare`], the command
//! `cubit legality-diff` -- and `store_paths.pairs` of a kernel cubit schedules itself is 0.

use crate::dep_stall::{self, DepLatTable};
use crate::ir::Instruction;
use crate::scheduling_pass as sp;
use crate::store_paths;
use crate::table::IsaTable;
use serde_json::{json, Value};

/// Version of the line's layout; a field is only ever added under the same number.
pub const SCHEMA: &str = "cubit-legality-1";

fn text(insns: &[Instruction], i: usize) -> String {
    insns[i].raw_text.trim().to_string()
}

/// The JSON object of one kernel (see the module documentation).
pub fn report(kernel: &str, insns: &[Instruction], table: Option<&IsaTable>, dep_table: &DepLatTable) -> Value {
    let (rep, sb) = sp::verify_scoreboard_findings(insns, table);
    let scoreboard: Vec<Value> = sb
        .iter()
        .map(|f| {
            json!({
                "kind": f.kind, "at": f.at, "other": f.other, "register": f.register,
                "at_text": text(insns, f.at), "other_text": text(insns, f.other),
            })
        })
        .collect();

    let paths: Vec<Value> = store_paths::unwaited_store_overwrites(insns, false)
        .iter()
        .map(|f| {
            json!({
                "store": f.store, "overwriter": f.overwriter, "register": format!("R{}", f.reg),
                "operand": if f.data { "data" } else { "address" },
                "read_barrier": f.read_bar, "distance": f.distance,
                "class": if store_paths::is_shared_store_address(insns, f) { "shared-address" } else { "pair" },
                "store_text": text(insns, f.store), "overwriter_text": text(insns, f.overwriter),
            })
        })
        .collect();

    let viol = dep_stall::check(insns, dep_table);
    let cells = viol.iter().filter(|v| !v.defaulted && v.kind == "raw").count();
    let arm = viol.iter().filter(|v| v.kind == "barrier-arm").count();
    let res = viol.iter().filter(|v| v.kind != "raw").count() - arm;
    let dflt = viol.iter().filter(|v| v.defaulted).count();
    let dep: Vec<Value> = viol
        .iter()
        .map(|v| {
            json!({
                "kind": v.kind, "defaulted": v.defaulted, "producer": v.producer, "consumer": v.consumer,
                "have": v.have, "need": v.need, "text": dep_stall::describe(insns, v),
            })
        })
        .collect();
    let blind: Vec<Value> = dep_stall::blind_spots(insns)
        .iter()
        .map(|(i, why)| json!({"at": i, "text": text(insns, *i), "why": why}))
        .collect();

    let mut line = json!({
        "schema": SCHEMA,
        "kernel": kernel,
        "instructions": insns.len(),
        "sync_classes": crate::sync_class::enabled(),
        "scoreboard": {
            "raw": rep.raw, "war": rep.war, "recycle_stale": rep.recycle,
            "wrap_raw": rep.wrap_raw, "wrap_war": rep.wrap_war, "wrap_recycle": rep.wrap_recycle,
            "unresolved_edges": rep.unresolved_edges,
            "waw": rep.waw, "waw_shuffle_into_load": rep.waw_shuffle_into_load,
            "shfl_sources": rep.shfl_sources, "shfl_sources_practice": rep.shfl_sources_practice,
            "findings": scoreboard,
        },
        "store_paths": {
            "pairs": rep.store_paths, "shared_address": rep.store_paths_shared_addr,
            "findings": paths,
        },
        "dep": {
            "table": dep_table.arch.clone(),
            "below_cell": cells, "barrier_arm": arm, "below_resource": res, "below_default": dflt,
            "findings": dep,
            "blind": blind,
        },
    });
    // an edition of the table (`dep_edition`, opt-in by name) is named; without one the line is as before
    if let Some((name, entries)) = &dep_table.edition {
        line["dep"]["edition"] = json!({"name": name, "entries": entries});
    }
    line
}

/// The `reuse` object of a kernel's line: the operand-reuse flags of its final words on every path
/// (`store_paths::reuse_flag_rewrites`) -- what was walked; `rewritten`: the law's findings (a
/// register read through a slot with the flag and written before the next reader through that
/// slot, flagged or not, on the fall-through or behind a taken branch); `apart`: the rows counted
/// apart, by kind of path (behind a word of the slot that does not execute, a wider operand);
/// `flags_apart`: the flags with no finding and such a row, by their cleanest kind;
/// `clean`: the flags with neither. `findings` lists every row (the text of the three words for
/// the law's findings only). `cubit asm` adds the object behind the encoder (the slots are read
/// off the encoded words).
pub fn reuse_json(insns: &[Instruction], findings: &[store_paths::ReuseFlagFinding], count: &store_paths::ReuseFlagCount, undecoded: usize) -> Value {
    use store_paths::ReuseFlagFinding as F;
    let list: Vec<Value> = findings
        .iter()
        .map(|f| {
            let mut row = json!({
                "flagged": f.flagged, "slot": store_paths::ReuseSlots::NAMES[f.slot].to_string(), "register": format!("R{}", f.reg),
                "writer": f.writer, "reader": f.reader, "distance": f.distance, "path": F::path_name(f.path),
            });
            if f.is_finding() {
                row["flagged_text"] = json!(text(insns, f.flagged));
                row["writer_text"] = json!(text(insns, f.writer));
                row["reader_text"] = json!(text(insns, f.reader));
            }
            row
        })
        .collect();
    let mut apart = std::collections::BTreeMap::<String, usize>::new();
    for f in findings.iter().filter(|f| !f.is_finding()) {
        *apart.entry(F::path_name(f.path)).or_default() += 1;
    }
    // per flag (word, slot): a finding, else the cleanest kind of its rows
    let mut per_flag = std::collections::BTreeMap::<(usize, usize), (bool, u32, u8)>::new();
    for f in findings {
        let rank = (!f.is_finding(), f.path.count_ones(), f.path);
        let e = per_flag.entry((f.flagged, f.slot)).or_insert(rank);
        if rank < *e {
            *e = rank;
        }
    }
    let mut flags_apart = std::collections::BTreeMap::<String, usize>::new();
    for (apart_only, _, path) in per_flag.values() {
        if *apart_only {
            *flags_apart.entry(F::path_name(*path)).or_default() += 1;
        }
    }
    json!({
        "flags": count.flags, "words": count.words, "without_yield": count.without_yield,
        "without_register": count.without_register, "uniform": count.uniform, "by_position": count.by_position,
        "to_unflagged": count.to_unflagged, "to_end": count.to_end, "to_wide": count.to_wide, "undecoded": undecoded,
        "rewritten": findings.iter().filter(|f| f.is_finding()).count(),
        "flags_rewritten": per_flag.values().filter(|r| !r.0).count(),
        "clean": count.clean,
        "apart": apart,
        "flags_apart": flags_apart,
        "findings": list,
    })
}

// ───────────────────────── a candidate against its seed ─────────────────────────

/// Version of the comparison's layout (`cubit legality-diff --json`).
pub const DIFF_SCHEMA: &str = "cubit-legality-diff-1";

/// One finding of a candidate that its seed does not have, or has farther apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffFinding {
    /// `scoreboard`, `store_paths` or `dep`
    pub list: &'static str,
    /// the finding's identity: its kind and its instruction indices (and register)
    pub key: String,
    /// the distance the seed has at this key (`None`: the seed has no such finding, or the list carries no distance)
    pub seed: Option<u64>,
    /// the candidate's distance at this key
    pub candidate: Option<u64>,
    /// the two instructions, as the candidate's line names them
    pub text: String,
}

/// What a candidate schedule has that its seed does not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Difference {
    /// the two lines are not reports of one kernel under one model and one table: why
    pub not_comparable: Option<String>,
    /// findings whose key the seed does not have
    pub new: Vec<DiffFinding>,
    /// findings the seed has too, CLOSER in the candidate: a dependency with a smaller `have`, a
    /// store whose overwriter stands at a smaller `distance`
    pub closer: Vec<DiffFinding>,
}

impl Difference {
    /// Nothing the seed does not have, and nothing closer than the seed has it.
    pub fn is_clean(&self) -> bool {
        self.not_comparable.is_none() && self.new.is_empty() && self.closer.is_empty()
    }
}

/// The keyed findings of one list of a line: key -> (smallest distance, text).
fn keyed(line: &Value, list: &'static str) -> std::collections::BTreeMap<String, (Option<u64>, String)> {
    let mut out: std::collections::BTreeMap<String, (Option<u64>, String)> = std::collections::BTreeMap::new();
    let Some(findings) = line[list]["findings"].as_array() else { return out };
    for f in findings {
        let s = |k: &str| f[k].as_str().unwrap_or("?").to_string();
        let n = |k: &str| f[k].as_u64().map_or("?".to_string(), |v| v.to_string());
        let (key, distance, text) = match list {
            "scoreboard" => (
                format!("{} [{}] -> [{}] {}", s("kind"), n("other"), n("at"), s("register")),
                None,
                format!("{} ; / {} ;", s("other_text").trim_end_matches(';').trim_end(), s("at_text").trim_end_matches(';').trim_end()),
            ),
            // a flag whose register is written inside its window is wrong at any distance: by key
            "reuse" => (
                format!("reuse-flag {} [{}] -> [{}] {} (slot {})", s("path"), n("flagged"), n("reader"), s("register"), s("slot")),
                None,
                format!("{} ; / {} ;", s("flagged_text").trim_end_matches(';').trim_end(), s("reader_text").trim_end_matches(';').trim_end()),
            ),
            "store_paths" => (
                format!("{} [{}] -> [{}] {} ({})", s("class"), n("store"), n("overwriter"), s("register"), s("operand")),
                f["distance"].as_u64(),
                format!("{} ; / {} ;", s("store_text").trim_end_matches(';').trim_end(), s("overwriter_text").trim_end_matches(';').trim_end()),
            ),
            _ => (format!("{} [{}] -> [{}]", s("kind"), n("producer"), n("consumer")), f["have"].as_u64(), s("text")),
        };
        let e = out.entry(key).or_insert((distance, text.clone()));
        // several findings under one key (a consumer that reads two registers of one producer): the closest
        if let (Some(d), Some(old)) = (distance, e.0) {
            if d < old {
                *e = (Some(d), text);
            }
        }
    }
    out
}

/// A candidate's line against its seed's (two lines of `CUBIT_VERIFY_JSON` for one kernel): the
/// rule a gate can hold a candidate to. The counts of a line are not a verdict -- a listing of the
/// vendor's assembler has findings of every class -- and "no finding the seed does not have" is
/// not enough either: a candidate that takes one cycle off a pair the seed ALREADY reports keeps
/// every key and is one cycle closer to the hazard (12 of 14 such moves on a served kernel left
/// the three key sets identical). So the rule is: **no new key, and no key closer than the seed
/// has it** -- a dependency finding's `have`, a store path's `distance`. The scoreboard findings
/// carry no distance; they are compared by key.
///
/// A key is the finding's kind and its instruction indices, so the two lines must be reports of
/// the same instruction list under the same model: another kernel, instruction count,
/// `sync_classes` or dependency table is `not_comparable`, never clean.
pub fn compare(seed: &Value, candidate: &Value) -> Difference {
    let mut d = Difference::default();
    for (what, v) in [("seed", seed), ("candidate", candidate)] {
        if v["schema"].as_str() != Some(SCHEMA) {
            d.not_comparable = Some(format!("the {what}'s line is not a `{SCHEMA}` line"));
            return d;
        }
    }
    for (field, what) in [("kernel", "kernel"), ("instructions", "instruction count"), ("sync_classes", "model (`sync_classes`)")] {
        if seed[field] != candidate[field] {
            d.not_comparable = Some(format!("another {what}: seed {}, candidate {}", seed[field], candidate[field]));
            return d;
        }
    }
    if seed["dep"]["table"] != candidate["dep"]["table"] || seed["dep"].get("edition") != candidate["dep"].get("edition") {
        d.not_comparable = Some("the two lines were made with different dependency tables".to_string());
        return d;
    }
    for list in ["scoreboard", "store_paths", "dep", "reuse"] {
        let s = keyed(seed, list);
        for (key, (cand, text)) in keyed(candidate, list) {
            match s.get(&key) {
                None => d.new.push(DiffFinding { list, key, seed: None, candidate: cand, text }),
                Some((Some(old), _)) if cand.is_some_and(|c| c < *old) => {
                    d.closer.push(DiffFinding { list, key, seed: Some(*old), candidate: cand, text })
                }
                Some(_) => {}
            }
        }
    }
    d
}

/// The comparison as one JSON object (`cubit legality-diff --json`).
pub fn difference_json(kernel: &str, d: &Difference) -> Value {
    let list = |v: &[DiffFinding]| -> Vec<Value> {
        v.iter().map(|f| json!({"list": f.list, "key": f.key, "seed": f.seed, "candidate": f.candidate, "text": f.text})).collect()
    };
    json!({
        "schema": DIFF_SCHEMA,
        "kernel": kernel,
        "verdict": if d.is_clean() { "clean" } else if d.not_comparable.is_some() { "not-comparable" } else { "worse" },
        "not_comparable": d.not_comparable,
        "new": list(&d.new),
        "closer": list(&d.closer),
    })
}
