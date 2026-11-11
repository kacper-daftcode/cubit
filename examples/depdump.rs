//! Dump the control code and the def / use sets of every instruction of a (frozen) .sass file as
//! JSON lines -- the input of `tools/stallfloor/dep_latency_census.py`, which mines the minimum
//! issue distance ptxas schedules per (producer class, consumer class, operand role) from the
//! frozen census (`cubit disassemble --frozen`). All register / predicate extraction is cubit's own
//! (`reg_liveness::reg_xfer`, `pred_liveness::pred_xfer`).
//!
//!     cargo run --release --example depdump -- kernel.frozen.sass [kernel name] [--scheduler] > kernel.dep.jsonl
//!
//! `--scheduler` adds two keys per instruction, `"sd"` / `"su"`: the definitions and uses in the SCHEDULER's view under
//! the current switches (`sync_class::scheduler_xfer`) as `[domain, number]` pairs -- `r` general register, `p`
//! predicate, `u` uniform register, `q` uniform predicate. With `CUBIT_SYNC_CLASSES=1` in the environment that is the
//! operand model the verifier and the barrier allocator judge an nvcc-shaped kernel with: it has sets for the words the
//! certified functions do not know (`"known": false`, empty `rd` / `ru`: `QMMA.SF`, `IADD.64`, `ULEA`, `USHF`, `P2R`,
//! `R2P`, `ARRIVES.LDGSTSBAR`, `CS2UR`), the high half of a 64-bit address base and of a 64-bit operand, the fragments
//! of a tensor instruction. A dependency graph takes the union of both views: neither is complete alone
//! (docs/SM120_ASYNC_IDIOMS.md, "The two operand models"). Without the flag the output is unchanged.
use cubit::pred_liveness::{pred_xfer, XferMode};
use cubit::reg_liveness::reg_xfer;
use cubit::sass_file::parse_sass_file_str;

fn main() -> anyhow::Result<()> {
    let all: Vec<String> = std::env::args().collect();
    let scheduler = all.iter().any(|a| a == "--scheduler");
    let args: Vec<String> = all.into_iter().filter(|a| a != "--scheduler").collect();
    let text = std::fs::read_to_string(&args[1])?;
    let only = args.get(2).cloned();
    // the scheduler's key space: GPR number, 256 + predicate, uniform register number, 64 + uniform predicate
    let keys = |v: Vec<(bool, u16)>| -> Vec<serde_json::Value> {
        v.into_iter()
            .map(|(uniform, k)| match (uniform, k) {
                (false, k) if k >= 256 => serde_json::json!(["p", k - 256]),
                (false, k) => serde_json::json!(["r", k]),
                (true, k) if k >= 64 => serde_json::json!(["q", k - 64]),
                (true, k) => serde_json::json!(["u", k]),
            })
            .collect()
    };
    let sf = parse_sass_file_str(&text)?;
    for k in &sf.kernels {
        if let Some(o) = &only {
            if &k.name != o {
                continue;
            }
        }
        for (i, ins) in k.instructions.iter().enumerate() {
            let rx = reg_xfer(ins);
            let px = pred_xfer(ins, XferMode::Strict);
            // fallback (pred_liveness has no family rule for FSETP / HSETP2 / DSETP ...): the scheduler's own
            // convention -- predicate operands in the first two slots of a SETP-like op are defs, the rest uses.
            let setp_like = matches!(ins.opcode.as_str(), "ISETP" | "ISETP3" | "FSETP" | "DSETP" | "HSETP2" | "PSETP"
                | "PLOP3" | "FSET" | "FCMP");
            let mut pd: Vec<u8> = px.defs.iter().copied().collect();
            let mut pu: Vec<u8> = px.uses.iter().copied().collect();
            if setp_like && pd.is_empty() && matches!(ins.opcode.as_str(), "FSETP" | "DSETP" | "HSETP2" | "PSETP" | "ISETP3") {
                pu.clear();
                for (oi, o) in ins.operands.iter().enumerate() {
                    if let cubit::ir::Operand::Pred { num, .. } = o {
                        if *num < 7 {
                            if oi < 2 {
                                pd.push(*num);
                            } else {
                                pu.push(*num);
                            }
                        }
                    }
                }
            }
            let labels: Vec<String> = k.labels.get(&ins.addr).cloned().unwrap_or_default();
            let guard = ins.guard.as_ref().map(|g| {
                serde_json::json!({"pred": g.pred, "neg": g.negated, "uniform": g.uniform})
            });
            let tgt: Option<u32> = ins.operands.iter().find_map(|o| match o {
                cubit::ir::Operand::BranchTarget(a) => Some(*a),
                _ => None,
            });
            // per-operand register slots: [operand index, kind, base] with kind r = register operand, a = address base
            // (memory operand), u = uniform register, p / q = predicate / uniform predicate operand (PT excluded)
            let mut slots: Vec<serde_json::Value> = Vec::new();
            let mut npos: usize = 0; // position among the non-predicate operands (dest included)
            for (oi0, o) in ins.operands.iter().enumerate() {
                let is_pred = matches!(o, cubit::ir::Operand::Pred { .. } | cubit::ir::Operand::UPred { .. });
                let oi = if is_pred { oi0 + 100 } else { npos };
                if !is_pred {
                    npos += 1;
                }
                match o {
                    cubit::ir::Operand::Reg { num, .. } if *num != 255 => slots.push(serde_json::json!([oi, "r", num])),
                    cubit::ir::Operand::UReg { num, is_zero, .. } if !*is_zero => slots.push(serde_json::json!([oi, "u", num])),
                    cubit::ir::Operand::Pred { num, .. } if *num < 7 => slots.push(serde_json::json!([oi, "p", num])),
                    cubit::ir::Operand::UPred { num, .. } if *num < 7 => slots.push(serde_json::json!([oi, "q", num])),
                    cubit::ir::Operand::Addr { base_reg, ur_reg, .. } => {
                        if let Some(b) = base_reg.filter(|b| *b != 255) {
                            slots.push(serde_json::json!([oi, "a", b]));
                        }
                        if let Some(u) = ur_reg {
                            slots.push(serde_json::json!([oi, "u", u]));
                        }
                    }
                    cubit::ir::Operand::ConstMem { base_reg: Some(b), .. } | cubit::ir::Operand::Desc { base_reg: Some(b), .. }
                        if *b != 255 =>
                    {
                        slots.push(serde_json::json!([oi, "a", b]));
                    }
                    _ => {}
                }
            }
            let spans: Vec<serde_json::Value> = rx.spans.iter().filter(|sp| matches!(sp.dom, cubit::reg_liveness::RegDom::R))
                .map(|sp| serde_json::json!([sp.base, sp.width, sp.is_def])).collect();
            let mut j = serde_json::json!({
                "k": k.name, "i": i, "addr": ins.addr, "labels": labels,
                "op": ins.opcode, "opf": ins.opcode_full, "mods": ins.modifiers,
                "wait": ins.ctrl.wait_mask, "rb": ins.ctrl.read_bar, "wb": ins.ctrl.write_bar,
                "y": ins.ctrl.yield_flag, "s": ins.ctrl.stall, "hand": ins.hand_sched,
                "guard": guard, "tgt": tgt,
                "rd": rx.rdefs, "ru": rx.ruses, "ud": rx.udefs, "uu": rx.uuses, "known": rx.known,
                "pd": pd, "pu": pu, "pknown": px.known, "upd": px.udefs, "upu": px.uuses,
                "slots": slots, "spans": spans, "text": ins.raw_text,
            });
            if scheduler {
                let (sd, su) = cubit::sync_class::scheduler_xfer(ins);
                j["sd"] = serde_json::Value::Array(keys(sd));
                j["su"] = serde_json::Value::Array(keys(su));
            }
            println!("{}", j);
        }
    }
    Ok(())
}
