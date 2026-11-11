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
//! seed does not have" -- and `store_paths.pairs` of a kernel cubit schedules itself is 0.

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

    json!({
        "schema": SCHEMA,
        "kernel": kernel,
        "instructions": insns.len(),
        "sync_classes": crate::sync_class::enabled(),
        "scoreboard": {
            "raw": rep.raw, "war": rep.war, "recycle_stale": rep.recycle,
            "wrap_raw": rep.wrap_raw, "wrap_war": rep.wrap_war, "wrap_recycle": rep.wrap_recycle,
            "unresolved_edges": rep.unresolved_edges,
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
    })
}
