//! What a frozen schedule leaves on the table against a dependency-latency table: per instruction
//! the stall its scheduler gave it and the stall the table's legaliser needs when the other stalls
//! are lowered to their floor first -- the static half of a headroom census of a ptxas-scheduled
//! kernel (the dynamic half is `ncu`'s `wait` stall reason per issued instruction).
//!
//!     cargo run --release --example depslack -- kernel.frozen.sass [kernel name] > kernel.slack.jsonl
//!
//! Every line: the instruction (`i`, `addr`, `op`, `opf`, `cls` = the table's class, `labels`, `tgt`,
//! `guard`), its control code (`s`, `y`, `wb`, `rb`, `wait`), `kept` (true = the instruction keeps
//! its stall in every variant: control flow, synchronisation words, barriers -- their floors are
//! not dependency latencies), and
//!
//! * `smin`: the stall after `dep_stall::apply` with the bundled sm_120 table on a copy whose
//!   other instructions start at `min(s, 1)`;
//! * `smin_x`: the same with the MMA rows below ptxas's practice (spacing 1, accumulate 1,
//!   reader 20 = the silicon floor of HMMA -> FMUL): a bound, not a schedule anyone ships;
//! * `unres` / `unres_x` on the first line: requirements the legaliser could not place.
//!
//! `Sum(s) - Sum(smin)` over a region, weighted by its executions, is what a dependency-aware
//! schedule with this table could remove there at most.
use cubit::dep_stall::{self, DepLatTable, SM120_TABLE};
use cubit::ir::Instruction;
use cubit::sass_file::parse_sass_file_str;

/// Instructions whose stall is not a dependency latency of the table: they keep it.
fn kept(ins: &Instruction) -> bool {
    let op = ins.opcode.as_str();
    matches!(
        op,
        // control flow
        "EXIT" | "BRA" | "BRX" | "JMP" | "JMX" | "RET" | "BREAK" | "CONT" | "KILL" | "CALL" | "BBREAK" | "BMOV"
            // synchronisation words, barriers, fences
            | "SYNCS"
            | "ARRIVES"
            | "FENCE"
            | "MEMBAR"
            | "ERRBAR"
            | "CGAERRBAR"
            | "CCTL"
            | "BAR"
            | "DEPBAR"
            | "LDGDEPBAR"
            | "USETMAXREG"
            | "UBLKCP"
            | "UTMALDG"
            | "UTMASTG"
            | "UTMACMDFLUSH"
            | "UTMACCTL"
            | "NANOSLEEP"
            | "YIELD"
            | "WARPSYNC"
            | "ENDCOLLECTIVE"
            | "BSSY"
            | "BSYNC"
            | "BPT"
            | "PREEXIT"
            | "ACQBULK"
            | "UCGABAR_ARV"
            | "UCGABAR_WAIT"
    )
}

fn minimal(insns: &[Instruction], t: &DepLatTable) -> (Vec<u8>, usize) {
    let mut v: Vec<Instruction> = insns.to_vec();
    for ins in v.iter_mut() {
        if kept(ins) {
            ins.hand_sched = true;
        } else {
            ins.hand_sched = false;
            ins.ctrl.stall = ins.ctrl.stall.min(1);
        }
    }
    let rep = dep_stall::apply(&mut v, t);
    (v.iter().map(|i| i.ctrl.stall).collect(), rep.unresolved.len())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let text = std::fs::read_to_string(&args[1])?;
    let only = args.get(2).cloned();
    let table = DepLatTable::from_json(SM120_TABLE)?;
    // the same table with the MMA rows below ptxas's practice
    let mut j: serde_json::Value = serde_json::from_str(SM120_TABLE)?;
    j["mma"]["to_mma_accumulate"] = serde_json::json!(1);
    j["mma"]["to_data"] = serde_json::json!(20);
    if let Some(rs) = j["resources"].as_array_mut() {
        for r in rs.iter_mut() {
            if r["name"] == "mma" {
                r["spacing"] = serde_json::json!(1);
            }
        }
    }
    let table_x = DepLatTable::from_json(&j.to_string())?;
    let sf = parse_sass_file_str(&text)?;
    for k in &sf.kernels {
        if let Some(o) = &only {
            if &k.name != o {
                continue;
            }
        }
        let (smin, unres) = minimal(&k.instructions, &table);
        let (smin_x, unres_x) = minimal(&k.instructions, &table_x);
        // the given schedule against the table (read-only): requirements below their latency
        let viol = dep_stall::check(&k.instructions, &table);
        for (i, ins) in k.instructions.iter().enumerate() {
            let labels: Vec<String> = k.labels.get(&ins.addr).cloned().unwrap_or_default();
            let guard = ins.guard.as_ref().map(|g| serde_json::json!({"pred": g.pred, "neg": g.negated, "uniform": g.uniform}));
            let tgt: Option<u32> = ins.operands.iter().find_map(|o| match o {
                cubit::ir::Operand::BranchTarget(a) => Some(*a),
                _ => None,
            });
            let mut j = serde_json::json!({
                "k": k.name, "i": i, "addr": ins.addr, "labels": labels,
                "op": ins.opcode, "opf": ins.opcode_full, "cls": dep_stall::dep_class(ins),
                "s": ins.ctrl.stall, "y": ins.ctrl.yield_flag, "wb": ins.ctrl.write_bar, "rb": ins.ctrl.read_bar,
                "wait": ins.ctrl.wait_mask, "kept": kept(ins), "guard": guard, "tgt": tgt,
                "smin": smin[i], "smin_x": smin_x[i], "text": ins.raw_text,
            });
            if i == 0 {
                j["unres"] = serde_json::json!(unres);
                j["unres_x"] = serde_json::json!(unres_x);
                j["viol"] = serde_json::json!(viol.len());
                j["viol_list"] = serde_json::json!(viol
                    .iter()
                    .take(200)
                    .map(|v| serde_json::json!([v.producer, v.consumer, v.kind, v.have, v.need, v.defaulted]))
                    .collect::<Vec<_>>());
            }
            println!("{}", j);
        }
    }
    Ok(())
}
