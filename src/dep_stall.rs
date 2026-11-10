//! Dependency-latency legalisation of a scheduled kernel on its control-flow graph
//! (`CUBIT_SCHED2_LAT`, opt-in; the sm_120 table is `tables/dep_latency_sm120.json`).
//!
//! `CUBIT_SCHED2` charges a fixed-latency producer's latency to the gap in front of its
//! consumer instead of to the producer (ptxas's discipline). Its stage-3 rules had two
//! holes on a kernel with control flow, both visible only on silicon:
//!
//! * the latency was a property of the PRODUCER opcode (plus a blanket margin). On sm_120
//!   it is a property of the PAIR — `IADD3 -> IADD3` 4 but `IADD3 -> IMAD` 5,
//!   `IMAD -> IMAD` 4 but `IMAD -> IADD3` 5, `MOV -> SEL` 5 / 6 by operand, anything
//!   `-> MMA fragment` 7, `MMA -> MMA accumulate` 29 (the pair matrix ptxas schedules by,
//!   mined from the frozen sm_120 census and checked on silicon with `tools/stallfloor/`);
//! * the deficit was computed on the instruction TEXT: the consumer at a branch target or
//!   behind a join was priced with the distance of the fall-through path, so a taken
//!   branch could reach it earlier than the producer's latency;
//!
//! This module is the replacement, run on the FINAL instruction list (after every
//! insertion and after the barrier allocator): a forward dataflow over the control-flow
//! graph gives, at every instruction, the minimum issue distance (sum of stalls) from
//! every reaching definition on ANY path; every pair below its latency is repaired by
//! raising the stall in front of the consumer on the offending edge. Stalls only grow,
//! so the repair converges; a pair that cannot be reached with 15-cycle stalls on the
//! instructions between producer and consumer is reported (the kernel then needs
//! padding) and the assembly fails closed.
//!
//! Besides register / predicate dependencies the table carries ptxas's issue-spacing
//! rules as resources (two MMAs never closer than 16, memory-pipe instructions 4,
//! `LDC` 8, the multiplier 2 / 4, `BAR` -> memory 6) — the same machinery with one
//! pseudo-register per resource.
//!
//! `check` is the read-only form (`CUBIT_DEP_VERIFY=1`, also on `[CC]`-frozen text): the
//! fixed-latency half of the scheduling-legality oracle (invariant 6 of
//! `docs/SCHED_LEGALITY_ORACLE.md`) with the pair table instead of one global floor.

use crate::ir::{Instruction, Operand};
use crate::scheduling_pass as sp;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

const KEY_PRED: u16 = 256; // == scheduling_pass::PRED_KEY
const KEY_UNI: u16 = 300; // uniform registers 300..363, uniform predicates 364..370
const KEY_RES: u16 = 400; // one pseudo-register per resource
const KEY_BAR: u16 = 500; // the six scoreboards: set by a write / read barrier, used by a wait
/// Distances are saturated here: no latency of the table is larger.
const CAP: u8 = 63;
const MAX_STALL: u8 = 15;

#[derive(Debug, Clone, Deserialize)]
struct CellJson {
    producer: String,
    consumer: String,
    role: String,
    #[serde(rename = "L")]
    l: u8,
}

#[derive(Debug, Clone, Deserialize)]
struct DefaultsJson {
    data: u8,
    mma_input: u8,
    guard: u8,
    pred_operand: u8,
    uniform: u8,
}

#[derive(Debug, Clone, Deserialize)]
struct MmaJson {
    classes: Vec<String>,
    to_mma_accumulate: u8,
    to_data: u8,
}

#[derive(Debug, Clone, Deserialize)]
struct ResourceJson {
    name: String,
    members: Vec<String>,
    #[serde(default)]
    spacing: Option<u8>,
    #[serde(default)]
    spacing_by_first: Option<HashMap<String, u8>>,
    #[serde(default)]
    then: Option<HashMap<String, u8>>,
}

#[derive(Debug, Clone, Deserialize)]
struct TableJson {
    arch: String,
    defaults: DefaultsJson,
    mma: MmaJson,
    #[serde(default)]
    resources: Vec<ResourceJson>,
    #[serde(default)]
    variable_latency: Vec<String>,
    /// Minimum issue distance from the instruction that sets a scoreboard (write or read
    /// barrier) to an instruction that waits on it.
    #[serde(default)]
    barrier_arm: Option<BarrierArmJson>,
    #[serde(default)]
    cells: Vec<CellJson>,
}

#[derive(Debug, Clone, Deserialize)]
struct BarrierArmJson {
    cycles: u8,
}

/// The dependency-latency table of one architecture.
#[derive(Debug, Clone)]
pub struct DepLatTable {
    pub arch: String,
    cells: HashMap<(String, String, String), u8>,
    any_role: HashMap<(String, String), u8>,
    defaults: DefaultsJson,
    mma: MmaJson,
    resources: Vec<ResourceJson>,
    variable: HashSet<String>,
    /// Scoreboard arming distance (0 = no rule): a wait issued one cycle behind the instruction
    /// that set the barrier can pass before the barrier is armed. ptxas never schedules it (census:
    /// 0 of 70 000 setter -> first-waiter pairs closer than 2; an adjacent waiter always finds the
    /// setter at S02 or more); on silicon the pair `MUFU [W:Y:S01]` / waiter at S01 reads the
    /// stale register (the two CUBIT_SCHED2 failures of sparse_mla_prefill_v41, 2026-11-10).
    pub barrier_arm: u8,
    /// Only the scoreboard arming rule (plain CUBIT_SCHED2 without a latency table).
    pub only_barriers: bool,
    /// Added to every register / predicate latency (`CUBIT_SCHED2_MARGIN`, default 0 with a table).
    pub margin: u8,
}

/// The bundled sm_120 table (ptxas census + silicon floors; see its `provenance`).
pub const SM120_TABLE: &str = include_str!("../tables/dep_latency_sm120.json");

impl DepLatTable {
    pub fn from_json(text: &str) -> anyhow::Result<Self> {
        let j: TableJson = serde_json::from_str(text)?;
        let mut cells = HashMap::new();
        let mut any_role: HashMap<(String, String), u8> = HashMap::new();
        for c in &j.cells {
            cells.insert((c.producer.clone(), c.consumer.clone(), c.role.clone()), c.l);
            let e = any_role.entry((c.producer.clone(), c.consumer.clone())).or_insert(0);
            *e = (*e).max(c.l);
        }
        Ok(Self {
            arch: j.arch,
            cells,
            any_role,
            defaults: j.defaults,
            mma: j.mma,
            resources: j.resources,
            variable: j.variable_latency.into_iter().collect(),
            barrier_arm: j.barrier_arm.map(|b| b.cycles).unwrap_or(0),
            only_barriers: false,
            margin: 0,
        })
    }

    /// The scoreboard arming rule alone (no register latencies, no resources): what plain
    /// `CUBIT_SCHED2` needs behind the barrier allocator.
    pub fn barriers_only(cycles: u8) -> Self {
        Self {
            arch: "any".into(),
            cells: HashMap::new(),
            any_role: HashMap::new(),
            defaults: DefaultsJson { data: 0, mma_input: 0, guard: 0, pred_operand: 0, uniform: 0 },
            mma: MmaJson { classes: Vec::new(), to_mma_accumulate: 0, to_data: 0 },
            resources: Vec::new(),
            variable: HashSet::new(),
            barrier_arm: cycles,
            only_barriers: true,
            margin: 0,
        }
    }

    /// `CUBIT_SCHED2_LAT`: unset / empty / `0` = off; `sm120` = the bundled table; anything
    /// else = the path of a table file. `CUBIT_SCHED2_MARGIN` adds to every latency.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let v = match std::env::var("CUBIT_SCHED2_LAT") {
            Ok(v) if !v.is_empty() && v != "0" => v,
            _ => return Ok(None),
        };
        let mut t = if v == "sm120" || v == "1" {
            Self::from_json(SM120_TABLE)?
        } else {
            let text = std::fs::read_to_string(&v)
                .map_err(|e| anyhow::anyhow!("CUBIT_SCHED2_LAT: cannot read {v}: {e}"))?;
            Self::from_json(&text)?
        };
        t.margin = std::env::var("CUBIT_SCHED2_MARGIN").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
        Ok(Some(t))
    }

    /// The table's `arch` (`sm_120`, `sm_103a`, ...) names the SM number of the ISA table in use.
    pub fn arch_matches(&self, target_sm: u32) -> bool {
        let digits: String = self.arch.trim_start_matches("sm_").chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse::<u32>().is_ok_and(|n| n == target_sm)
    }

    fn is_mma_class(&self, class: &str) -> bool {
        self.mma.classes.iter().any(|c| c == class)
    }

    fn is_variable(&self, insn: &Instruction) -> bool {
        self.variable.contains(insn.opcode.as_str())
    }

    /// Latency of one dependency edge; `defaulted` = no cell names the pair.
    fn latency(&self, prod: &Instruction, cons: &Instruction, key: u16) -> (u8, bool) {
        let pc = dep_class(prod);
        let cc = dep_class(cons);
        let cons_mma = self.is_mma_class(&cc);
        let roles = roles_of(cons, key);
        if self.is_mma_class(&pc) {
            // the accumulate operand of an MMA is its last register operand (position 3)
            let acc = cons_mma && roles.iter().any(|r| r == "r3");
            return (if acc { self.mma.to_mma_accumulate } else { self.mma.to_data }, false);
        }
        let mut best: u8 = 0;
        let mut defaulted = false;
        for role in &roles {
            // exact cell; the high half of a multi-register operand falls back on its low half
            // (never cheaper in the census); a role the scan could not resolve (`*`) takes the
            // largest cell of the pair. Nothing else borrows another role's number: the low half
            // of an IMAD.WIDE addend needs 5 where its high half needs 3 (silicon 2026-11-10).
            let low = role.strip_suffix('h').map(|r| (pc.clone(), cc.clone(), r.to_string()));
            let l = if let Some(l) = self.cells.get(&(pc.clone(), cc.clone(), role.clone())) {
                *l
            } else if let Some(l) = low.as_ref().and_then(|k| self.cells.get(k)) {
                *l
            } else if let Some(l) = self.any_role.get(&(pc.clone(), cc.clone())).filter(|_| role == "*") {
                *l
            } else {
                defaulted = true;
                if cons_mma {
                    self.defaults.mma_input
                } else if role == "g" || role == "gc" {
                    self.defaults.guard
                } else if role == "p" {
                    self.defaults.pred_operand
                } else if key >= KEY_UNI {
                    self.defaults.uniform
                } else {
                    self.defaults.data
                }
            };
            best = best.max(l);
        }
        (best.saturating_add(self.margin).min(CAP), defaulted)
    }

    /// Resources an instruction USES (it must keep the spacing to the last holder) and
    /// DEFINES (later members must keep a spacing to it): indices into `resources`.
    fn resource_use_def(&self, insn: &Instruction) -> (Vec<usize>, Vec<usize>) {
        let class = dep_class(insn);
        let op = insn.opcode.as_str();
        let member = |r: &ResourceJson| r.members.iter().any(|m| m == &class || m == op);
        let mut uses = Vec::new();
        let mut defs = Vec::new();
        for (i, r) in self.resources.iter().enumerate() {
            if member(r) {
                uses.push(i);
                defs.push(i);
            }
        }
        // `then`: a member of resource A is also a holder of the resources A names
        for r in self.resources.iter() {
            if !member(r) {
                continue;
            }
            if let Some(then) = &r.then {
                for (name, _) in then.iter() {
                    if let Some(j) = self.resources.iter().position(|x| &x.name == name) {
                        if !defs.contains(&j) {
                            defs.push(j);
                        }
                    }
                }
            }
        }
        (uses, defs)
    }

    /// Spacing a member `cons` of resource `ri` must keep to the holder `prod`.
    fn resource_spacing(&self, prod: &Instruction, ri: usize) -> u8 {
        let r = &self.resources[ri];
        let class = dep_class(prod);
        let op = prod.opcode.as_str();
        let mut best = 1u8;
        if r.members.iter().any(|m| m == &class || m == op) {
            best = match r.spacing_by_first.as_ref().and_then(|by| by.get(&class).or_else(|| by.get(op))) {
                Some(v) => *v,
                None => r.spacing.unwrap_or(1),
            };
        }
        // a holder through a resource's `then` (its own included: BAR -> BAR)
        for other in self.resources.iter() {
            if !other.members.iter().any(|m| m == &class || m == op) {
                continue;
            }
            if let Some(then) = &other.then {
                if let Some(v) = then.get(&r.name) {
                    best = best.max(*v);
                }
            }
        }
        best
    }
}

/// Producer / consumer class of the table (mirror of `tools/stallfloor/` and of the census
/// miner): the base opcode with the distinctions the latencies were found to depend on.
pub fn dep_class(insn: &Instruction) -> String {
    let op = insn.opcode.as_str();
    let has = |m: &str| insn.modifiers.iter().any(|x| x == m);
    match op {
        "F2FP" => {
            if insn.modifiers.iter().any(|m| m.starts_with(".PACK")) {
                "F2FP.PACK".into()
            } else if insn.modifiers.iter().any(|m| m.starts_with(".UNPACK")) {
                "F2FP.UNPACK".into()
            } else {
                op.into()
            }
        }
        "IADD3" | "UIADD3" if has(".X") => format!("{op}.X"),
        "IMAD" => {
            if has(".WIDE") {
                "IMAD.WIDE".into()
            } else if has(".HI") {
                "IMAD.HI".into()
            } else {
                // .MOV / .IADD / .SHL / .SHR are display aliases of the same word (the source text
                // `IMAD R5, R5, 0x4, RZ` disassembles as IMAD.SHL): one class, whatever the spelling
                op.into()
            }
        }
        "HADD2" if has(".F32") => "HADD2.F32".into(),
        "MOV" if has(".64") => "MOV.64".into(),
        _ => op.into(),
    }
}

/// Operand roles in which `cons` reads `key` (several when the register is named twice;
/// `*` when no operand names it — a span the role scan does not resolve). A register above the
/// named one of a multi-register operand (the high half of a 64-bit addend or address) has the
/// role of the operand with an `h`.
fn roles_of(cons: &Instruction, key: u16) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let is_ctrl = sp::is_control_flow(cons.opcode.as_str());
    if (KEY_PRED..KEY_UNI).contains(&key) || key >= KEY_UNI + 64 {
        let uniform = key >= KEY_UNI;
        let n = if uniform { key - KEY_UNI - 64 } else { key - KEY_PRED } as u8;
        if let Some(g) = &cons.guard {
            if g.pred == n && g.uniform == uniform {
                out.push(if is_ctrl { "gc".into() } else { "g".into() });
            }
        }
        let named = cons.operands.iter().any(|o| match o {
            Operand::Pred { num, .. } => !uniform && *num == n,
            Operand::UPred { num, .. } => uniform && *num == n,
            _ => false,
        });
        if named {
            // a predicate operand of a branch (`BRA.U UP0, L`) resolves like a guard
            out.push(if is_ctrl { "gc".into() } else { "p".into() });
        }
        if out.is_empty() {
            out.push("*".into());
        }
        return out;
    }
    let widths: Vec<(u8, usize)> = crate::reg_liveness::reg_xfer(cons)
        .spans
        .iter()
        .filter(|s| !s.is_def)
        .map(|s| (s.base, s.width))
        .collect();
    let width_of = |base: u8| -> u16 {
        widths.iter().filter(|(b, _)| *b == base).map(|(_, w)| *w as u16).max().unwrap_or(1).max(1)
    };
    let dests: Vec<(bool, u16)> = sp::dest_regs(cons);
    let mut npos: usize = 0;
    for o in cons.operands.iter() {
        let is_pred = matches!(o, Operand::Pred { .. } | Operand::UPred { .. });
        let pos = npos;
        if !is_pred {
            npos += 1;
        }
        match o {
            Operand::Reg { num, .. } if *num != 255 && key < KEY_PRED => {
                let b = *num as u16;
                if key >= b && key < b + width_of(*num) {
                    // the destination slot: position 0 of an instruction that writes the register
                    if pos == 0 && dests.contains(&(false, key)) {
                        continue;
                    }
                    // the upper registers of a multi-register operand are their own role (`r3h`:
                    // the high half of a 64-bit addend is read later than its low half)
                    out.push(if key > b { format!("r{pos}h") } else { format!("r{pos}") });
                }
            }
            Operand::Addr { base_reg: Some(b), .. }
            | Operand::Desc { base_reg: Some(b), .. }
            | Operand::ConstMem { base_reg: Some(b), .. }
                if key < KEY_PRED =>
            {
                let bb = *b as u16;
                if *b != 255 && key >= bb && key < bb + width_of(*b).max(2) {
                    out.push(if key > bb { format!("a{pos}h") } else { format!("a{pos}") });
                }
            }
            Operand::UReg { num, .. } if (KEY_UNI..KEY_UNI + 64).contains(&key) => {
                if *num as u16 == key - KEY_UNI || (*num as u16) + 1 == key - KEY_UNI {
                    out.push(format!("u{pos}"));
                }
            }
            Operand::Addr { ur_reg: Some(u), .. } | Operand::ConstMem { ur_reg: Some(u), .. }
                if (KEY_UNI..KEY_UNI + 64).contains(&key) =>
            {
                if *u as u16 == key - KEY_UNI {
                    out.push(format!("u{pos}"));
                }
            }
            Operand::Desc { ur_idx, .. } if (KEY_UNI..KEY_UNI + 64).contains(&key) => {
                if *ur_idx as u16 == key - KEY_UNI {
                    out.push(format!("u{pos}"));
                }
            }
            _ => {}
        }
    }
    if out.is_empty() {
        out.push("*".into());
    }
    out.sort();
    out.dedup();
    out
}

fn key_of(uniform: bool, k: u16) -> u16 {
    if uniform {
        KEY_UNI + k
    } else {
        k // GPRs 0..254, vector predicates PRED_KEY + n
    }
}

/// One reaching definition: (key, defining instruction, minimum elapsed issue cycles).
type Entry = (u16, u32, u8);

struct Flow {
    succ: Vec<Vec<usize>>,
    pred: Vec<Vec<usize>>,
    /// i -> i + 1 is an execution edge
    falls: Vec<bool>,
}

fn build_flow(insns: &[Instruction]) -> Flow {
    let n = insns.len();
    let mut addr2idx: HashMap<u32, usize> = HashMap::new();
    for (i, ins) in insns.iter().enumerate() {
        let a = if ins.addr > 0 || i == 0 { ins.addr } else { (i * 16) as u32 };
        addr2idx.entry(a).or_insert(i);
    }
    let mut succ = vec![Vec::new(); n];
    let mut falls = vec![false; n];
    for (i, ins) in insns.iter().enumerate() {
        let op = ins.opcode.as_str();
        let guarded = ins.guard.as_ref().is_some_and(|g| g.pred < 7);
        let pred_operand = ins.operands.iter().any(
            |o| matches!(o, Operand::Pred { num, .. } | Operand::UPred { num, .. } if *num < 7),
        );
        let unconditional = !guarded && !pred_operand;
        let mut fall = true;
        if matches!(op, "EXIT" | "RET") {
            fall = !unconditional;
        } else if matches!(op, "BRA" | "JMP") {
            if let Some(t) = sp::branch_target(ins) {
                if let Some(&ti) = addr2idx.get(&t) {
                    succ[i].push(ti);
                    fall = !unconditional;
                }
            }
        }
        if fall && i + 1 < n {
            succ[i].push(i + 1);
            falls[i] = true;
        }
    }
    let mut pred = vec![Vec::new(); n];
    for (i, ss) in succ.iter().enumerate() {
        for &s in ss {
            if !pred[s].contains(&i) {
                pred[s].push(i);
            }
        }
    }
    Flow { succ, pred, falls }
}

struct Sem {
    /// (key, role-independent) keys read / written by the instruction
    uses: Vec<u16>,
    defs: Vec<u16>,
    guarded: bool,
    res_uses: Vec<usize>,
    res_defs: Vec<usize>,
    /// scoreboards the instruction waits on / sets (write or read barrier)
    bar_uses: Vec<u8>,
    bar_defs: Vec<u8>,
}

fn semantics(insns: &[Instruction], t: &DepLatTable) -> Vec<Sem> {
    insns
        .iter()
        .map(|ins| {
            let mut uses: Vec<u16> = sp::src_regs(ins).into_iter().map(|(u, k)| key_of(u, k)).collect();
            uses.sort_unstable();
            uses.dedup();
            let mut defs: Vec<u16> = sp::dest_regs(ins).into_iter().map(|(u, k)| key_of(u, k)).collect();
            defs.sort_unstable();
            defs.dedup();
            // PT / RZ / URZ never carry a dependency (`@!UPT UIADD3 URZ, ...` writes nothing)
            uses.retain(|k| *k != 255 && *k != KEY_PRED + 7);
            defs.retain(|k| *k != 255 && *k != KEY_PRED + 7);
            if ins.operands.iter().any(|o| matches!(o, Operand::UReg { is_zero: true, .. })) {
                defs.retain(|k| *k != KEY_UNI + 63);
                uses.retain(|k| *k != KEY_UNI + 63);
            }
            let (mut res_uses, mut res_defs) = t.resource_use_def(ins);
            if t.only_barriers {
                uses.clear();
                defs.clear();
                res_uses.clear();
                res_defs.clear();
            }
            let mut bar_uses = Vec::new();
            let mut bar_defs = Vec::new();
            if t.barrier_arm > 0 {
                for b in 0..6u8 {
                    if (ins.ctrl.wait_mask >> b) & 1 == 1 {
                        bar_uses.push(b);
                    }
                }
                if ins.ctrl.write_bar < 6 {
                    bar_defs.push(ins.ctrl.write_bar);
                }
                if ins.ctrl.read_bar < 6 && !bar_defs.contains(&ins.ctrl.read_bar) {
                    bar_defs.push(ins.ctrl.read_bar);
                }
            }
            Sem { uses, defs, guarded: ins.guard.as_ref().is_some_and(|g| g.pred < 7), res_uses, res_defs, bar_uses, bar_defs }
        })
        .collect()
}

/// OUT state of instruction `i` from its IN state: its own definitions (a guarded write
/// does not kill the older ones), then every distance advanced by its stall.
fn transfer(i: usize, st: &[Entry], sem: &Sem, stall: u8) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::with_capacity(st.len() + sem.defs.len() + sem.res_defs.len());
    let kills = |k: u16| -> bool {
        if k >= KEY_BAR {
            // the barrier is re-set, or waited (its setter is then complete: nothing left to arm)
            let b = (k - KEY_BAR) as u8;
            sem.bar_defs.contains(&b) || sem.bar_uses.contains(&b)
        } else if k >= KEY_RES {
            sem.res_defs.contains(&((k - KEY_RES) as usize)) && !sem.guarded
        } else {
            sem.defs.contains(&k) && !sem.guarded
        }
    };
    for e in st {
        if !kills(e.0) {
            out.push(*e);
        }
    }
    for k in &sem.defs {
        out.retain(|e| !(e.0 == *k && e.1 == i as u32));
        out.push((*k, i as u32, 0));
    }
    for r in &sem.res_defs {
        let k = KEY_RES + *r as u16;
        out.retain(|e| !(e.0 == k && e.1 == i as u32));
        out.push((k, i as u32, 0));
    }
    for b in &sem.bar_defs {
        let k = KEY_BAR + *b as u16;
        out.retain(|e| !(e.0 == k && e.1 == i as u32));
        out.push((k, i as u32, 0));
    }
    for e in out.iter_mut() {
        e.2 = e.2.saturating_add(stall).min(CAP);
    }
    out.sort_unstable();
    out
}

/// Pointwise minimum-merge of `b` into `a` (both sorted by (key, def)); true when `a` changed.
fn merge(a: &mut Vec<Entry>, b: &[Entry]) -> bool {
    let mut changed = false;
    let mut out: Vec<Entry> = Vec::with_capacity(a.len().max(b.len()));
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        if j >= b.len() || (i < a.len() && (a[i].0, a[i].1) < (b[j].0, b[j].1)) {
            out.push(a[i]);
            i += 1;
        } else if i >= a.len() || (b[j].0, b[j].1) < (a[i].0, a[i].1) {
            out.push(b[j]);
            j += 1;
            changed = true;
        } else {
            let e = a[i].2.min(b[j].2);
            if e < a[i].2 {
                changed = true;
            }
            out.push((a[i].0, a[i].1, e));
            i += 1;
            j += 1;
        }
    }
    *a = out;
    changed
}

struct Analysis {
    /// IN state per instruction (None = unreachable)
    ins: Vec<Option<Vec<Entry>>>,
}

fn analyse(insns: &[Instruction], flow: &Flow, sem: &[Sem]) -> Analysis {
    let n = insns.len();
    let mut st: Vec<Option<Vec<Entry>>> = vec![None; n];
    if n == 0 {
        return Analysis { ins: st };
    }
    st[0] = Some(Vec::new());
    let mut work: std::collections::VecDeque<usize> = std::collections::VecDeque::new();
    let mut queued = vec![false; n];
    work.push_back(0);
    queued[0] = true;
    while let Some(i) = work.pop_front() {
        queued[i] = false;
        let out = transfer(i, st[i].as_ref().unwrap(), &sem[i], insns[i].ctrl.stall);
        for &s in &flow.succ[i] {
            let changed = match &mut st[s] {
                None => {
                    st[s] = Some(out.clone());
                    true
                }
                Some(cur) => merge(cur, &out),
            };
            if changed && !queued[s] {
                queued[s] = true;
                work.push_back(s);
            }
        }
    }
    Analysis { ins: st }
}

/// One dependency below its latency.
#[derive(Debug, Clone)]
pub struct Violation {
    pub producer: usize,
    pub consumer: usize,
    pub key: u16,
    pub have: u8,
    pub need: u8,
    /// "raw" | "barrier-arm" | the resource name
    pub kind: String,
    /// the latency is a default of the table (no cell names the pair), not a measured cell
    pub defaulted: bool,
}

/// What `apply` did.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub raised: usize,
    pub added_cycles: usize,
    pub rounds: usize,
    pub defaulted: Vec<String>,
    pub unresolved: Vec<Violation>,
}

struct Need {
    key: u16,
    def: usize,
    need: u8,
    kind: &'static str,
    res: Option<usize>,
    /// priced with a default: no cell of the table names the pair
    defaulted: bool,
}

/// Every requirement instruction `c` puts on the reaching definitions in `st`.
fn needs_of(
    insns: &[Instruction],
    sem: &[Sem],
    t: &DepLatTable,
    c: usize,
    st: &[Entry],
    defaulted: &mut Option<&mut HashSet<String>>,
) -> Vec<Need> {
    let mut out = Vec::new();
    let cons = &insns[c];
    for e in st {
        let (key, d) = (e.0, e.1 as usize);
        let prod = &insns[d];
        if key >= KEY_BAR {
            if sem[c].bar_uses.contains(&((key - KEY_BAR) as u8)) && d != c {
                out.push(Need { key, def: d, need: t.barrier_arm, kind: "barrier-arm", res: None, defaulted: false });
            }
            continue;
        }
        if key >= KEY_RES {
            let ri = (key - KEY_RES) as usize;
            if sem[c].res_uses.contains(&ri) {
                out.push(Need { key, def: d, need: t.resource_spacing(prod, ri), kind: "resource", res: Some(ri), defaulted: false });
            }
            continue;
        }
        // a scoreboarded producer is synchronised by its barrier, a variable-latency class
        // without one is the allocator's (and the scoreboard verifier's) business
        let mma = sp::is_warp_mma(prod.opcode.as_str());
        if !mma && (prod.ctrl.write_bar != 7 || t.is_variable(prod)) {
            continue;
        }
        if sem[c].uses.contains(&key) {
            let (l, dflt) = t.latency(prod, cons, key);
            // a defaulted pair is worth naming only where the default could bind (within 16 cycles of it)
            if dflt && e.2 < l.saturating_add(16) {
                if let Some(set) = defaulted.as_deref_mut() {
                    set.insert(format!("{} -> {}", dep_class(prod), dep_class(cons)));
                }
            }
            out.push(Need { key, def: d, need: l, kind: "raw", res: None, defaulted: dflt });
        }
        // No write-after-write rule: fixed-latency writes land in issue order. The census has an ALU
        // overwriter one cycle behind the producer it overwrites in every family (`LOP3 R12, ...` /
        // `@!P0 MOV R12, 0xffffffff` at S01; `IMAD.WIDE` then `MOV` at 1; `FFMA` then `FADD` 240 times
        // at 1), so the pipeline retires them in order whatever their forwarding latency.
    }
    out
}

fn elapsed_in(st: &[Entry], key: u16, def: usize) -> Option<u8> {
    st.binary_search_by(|e| (e.0, e.1).cmp(&(key, def as u32))).ok().map(|i| st[i].2)
}

/// Read-only: every fixed-latency dependency below its table latency on some path.
pub fn check(insns: &[Instruction], t: &DepLatTable) -> Vec<Violation> {
    let flow = build_flow(insns);
    let sem = semantics(insns, t);
    let an = analyse(insns, &flow, &sem);
    let mut out = Vec::new();
    for c in 0..insns.len() {
        let Some(st) = &an.ins[c] else { continue };
        for nd in needs_of(insns, &sem, t, c, st, &mut None) {
            let have = elapsed_in(st, nd.key, nd.def).unwrap_or(CAP);
            if have < nd.need {
                out.push(Violation {
                    producer: nd.def,
                    consumer: c,
                    key: nd.key,
                    have,
                    need: nd.need,
                    kind: match nd.res {
                        Some(ri) => t.resources[ri].name.clone(),
                        None => nd.kind.to_string(),
                    },
                    defaulted: nd.defaulted,
                });
            }
        }
    }
    out
}

/// One dependency edge of a kernel as the table prices it (`CUBIT_DEP_CELLS`): which cell,
/// what it needs, what the schedule gives on the tightest path.
#[derive(Debug, Clone)]
pub struct EdgeUse {
    pub producer: usize,
    pub consumer: usize,
    pub producer_class: String,
    pub consumer_class: String,
    /// operand roles in which the consumer reads the value; the resource name for a spacing;
    /// `arm` for a scoreboard
    pub role: String,
    pub need: u8,
    pub have: u8,
    pub kind: String,
    pub defaulted: bool,
}

/// Read-only: every requirement of the table on the kernel with its tightest distance — the
/// cells a schedule rests on (`have == need` = binding).
pub fn usage(insns: &[Instruction], t: &DepLatTable) -> Vec<EdgeUse> {
    let flow = build_flow(insns);
    let sem = semantics(insns, t);
    let an = analyse(insns, &flow, &sem);
    let mut out = Vec::new();
    for c in 0..insns.len() {
        let Some(st) = &an.ins[c] else { continue };
        for nd in needs_of(insns, &sem, t, c, st, &mut None) {
            let have = elapsed_in(st, nd.key, nd.def).unwrap_or(CAP);
            let (kind, role) = match nd.res {
                Some(ri) => ("resource".to_string(), t.resources[ri].name.clone()),
                None if nd.kind == "barrier-arm" => (nd.kind.to_string(), "arm".to_string()),
                None => (nd.kind.to_string(), roles_of(&insns[c], nd.key).join("+")),
            };
            out.push(EdgeUse {
                producer: nd.def,
                consumer: c,
                producer_class: dep_class(&insns[nd.def]),
                consumer_class: dep_class(&insns[c]),
                role,
                need: nd.need,
                have,
                kind,
                defaulted: nd.defaulted,
            });
        }
    }
    out
}

/// Where one stall field cannot carry a requirement between two text-adjacent instructions (the
/// MMA rows of the table: 16 between any two MMAs, 28 / 29 from an MMA to a reader of its result):
/// `(i + 1, pads)` = the number of pad instructions to insert in front of instruction `i + 1`.
/// With them every requirement of the table is reachable by stalls alone on straight-line text.
/// Hand-scheduled (`[CC]`) neighbours are left alone (the legaliser reports what it cannot place).
pub fn pads_needed(insns: &[Instruction], t: &DepLatTable) -> Vec<(usize, usize)> {
    let sem = semantics(insns, t);
    let mut out = Vec::new();
    for i in 0..insns.len().saturating_sub(1) {
        if insns[i].hand_sched || insns[i + 1].hand_sched || !sp::is_warp_mma(insns[i].opcode.as_str()) {
            continue;
        }
        let st = transfer(i, &[], &sem[i], 0);
        let need = needs_of(insns, &sem, t, i + 1, &st, &mut None).iter().map(|n| n.need).max().unwrap_or(0);
        if need > MAX_STALL {
            out.push((i + 1, ((need - 1) / MAX_STALL) as usize));
        }
    }
    out
}

fn room(insn: &Instruction) -> u8 {
    if insn.hand_sched {
        0
    } else {
        MAX_STALL.saturating_sub(insn.ctrl.stall)
    }
}

/// Raise the stalls in front of consumer `c` on the linear path so that the distance from
/// `def` reaches `need`: the instruction right before `c` first, then backwards down to the
/// producer itself. Returns the cycles that could not be placed.
fn raise_linear(insns: &mut [Instruction], binding: &mut [bool], def: usize, c: usize, mut deficit: u8, rep: &mut Report) -> u8 {
    let mut j = c;
    while deficit > 0 && j > def {
        j -= 1;
        let add = room(&insns[j]).min(deficit);
        if add > 0 {
            insns[j].ctrl.stall += add;
            binding[j] = true;
            rep.raised += 1;
            rep.added_cycles += add as usize;
            deficit -= add;
        }
    }
    deficit
}

/// The legaliser: raise stalls until no fixed-latency dependency of the table is violated
/// on any control-flow path. Hand-scheduled (`[CC]`) instructions are never changed.
pub fn apply(insns: &mut [Instruction], t: &DepLatTable) -> Report {
    let n = insns.len();
    let mut rep = Report::default();
    if n == 0 {
        return rep;
    }
    let flow = build_flow(insns);
    let sem = semantics(insns, t);
    let mut binding = vec![false; n];
    let mut defaulted: HashSet<String> = HashSet::new();

    // Phase 1 — the fall-through paths, tight: one forward walk with the linear reaching
    // definitions (reset where the text is not an execution path).
    {
        let mut st: Vec<Entry> = Vec::new(); // elapsed is recomputed from the stalls: only (key, def) is used
        for c in 0..n {
            let needs = needs_of(insns, &sem, t, c, &st, &mut None);
            for nd in needs {
                // distance on the text from the producer to c
                let mut have: u32 = 0;
                for k in nd.def..c {
                    have += insns[k].ctrl.stall as u32;
                    if have >= CAP as u32 {
                        break;
                    }
                }
                if (have as u8) < nd.need && have < CAP as u32 {
                    let _ = raise_linear(insns, &mut binding, nd.def, c, nd.need - have as u8, &mut rep);
                }
            }
            if flow.falls[c] {
                st = transfer(c, &st, &sem[c], 0);
            } else {
                st.clear();
            }
        }
    }

    // Phase 2 — every path: dataflow, repair the first violating consumer on each offending
    // predecessor edge, repeat. Stalls only grow.
    let max_rounds = 4 * n + 64;
    loop {
        rep.rounds += 1;
        let an = analyse(insns, &flow, &sem);
        let mut fixed_any = false;
        let mut pending: Vec<Violation> = Vec::new();
        'scan: for c in 0..n {
            let Some(st) = &an.ins[c] else { continue };
            let mut dref = Some(&mut defaulted);
            let needs = needs_of(insns, &sem, t, c, st, &mut dref);
            let mut touched = false;
            for nd in needs {
                let have = elapsed_in(st, nd.key, nd.def).unwrap_or(CAP);
                if have >= nd.need {
                    continue;
                }
                // repair on every predecessor edge that carries the definition too early
                let mut placed_all = true;
                for &p in &flow.pred[c] {
                    let Some(pst) = &an.ins[p] else { continue };
                    let out = transfer(p, pst, &sem[p], insns[p].ctrl.stall);
                    let Some(e) = elapsed_in(&out, nd.key, nd.def) else { continue };
                    if e >= nd.need {
                        continue;
                    }
                    let mut deficit = nd.need - e;
                    // walk back from p along single-predecessor fall-through links
                    let mut q = p;
                    loop {
                        let add = room(&insns[q]).min(deficit);
                        if add > 0 {
                            insns[q].ctrl.stall += add;
                            binding[q] = true;
                            rep.raised += 1;
                            rep.added_cycles += add as usize;
                            deficit -= add;
                            touched = true;
                        }
                        if deficit == 0 || q == nd.def {
                            break;
                        }
                        // continue behind q only when q has exactly one predecessor (the text before it)
                        if q > 0 && flow.pred[q].len() == 1 && flow.pred[q][0] == q - 1 {
                            q -= 1;
                        } else {
                            break;
                        }
                    }
                    if deficit > 0 {
                        placed_all = false;
                    }
                }
                if !placed_all && !touched {
                    pending.push(Violation {
                        producer: nd.def,
                        consumer: c,
                        key: nd.key,
                        have,
                        need: nd.need,
                        kind: match nd.res {
                            Some(ri) => t.resources[ri].name.clone(),
                            None => nd.kind.to_string(),
                        },
                        defaulted: nd.defaulted,
                    });
                }
            }
            if touched {
                fixed_any = true;
                break 'scan; // distances changed: analyse again
            }
        }
        if !fixed_any {
            rep.unresolved = pending;
            break;
        }
        if rep.rounds > max_rounds {
            rep.unresolved = check(insns, t);
            break;
        }
    }

    // Yield: ptxas clears it on a stall that carries a dependency (census: an ALU stall >= 3
    // that binds a dependency is yield-free in 95 % of 180 000 sites; memory instructions and
    // branches keep it; >= 12 is yield-free by the OPEX law).
    for (i, ins) in insns.iter_mut().enumerate() {
        if ins.hand_sched {
            continue;
        }
        let op = ins.opcode.as_str();
        let mem_like = sp::is_long_latency(op) || sp::is_store(op) || sp::is_warp_mma(op) || sp::is_control_flow(op) || op == "BAR";
        if ins.ctrl.stall >= 12 || (binding[i] && ins.ctrl.stall >= 3 && !mem_like) {
            ins.ctrl.yield_flag = false;
        }
    }
    let mut d: Vec<String> = defaulted.into_iter().collect();
    d.sort();
    rep.defaulted = d;
    rep
}

/// Human-readable form of a violation.
pub fn describe(insns: &[Instruction], v: &Violation) -> String {
    let key = if v.key >= KEY_BAR {
        format!("scoreboard {}", v.key - KEY_BAR)
    } else if v.key >= KEY_RES {
        format!("resource {}", v.kind)
    } else if v.key >= KEY_UNI + 64 {
        format!("UP{}", v.key - KEY_UNI - 64)
    } else if v.key >= KEY_UNI {
        format!("UR{}", v.key - KEY_UNI)
    } else if v.key >= KEY_PRED {
        format!("P{}", v.key - KEY_PRED)
    } else {
        format!("R{}", v.key)
    };
    format!(
        "[{}] {} -> [{}] {} ({} {}): distance {} < {}{}",
        v.producer,
        insns[v.producer].raw_text.trim(),
        v.consumer,
        insns[v.consumer].raw_text.trim(),
        v.kind,
        key,
        v.have,
        v.need,
        if v.defaulted { " (default: no cell for the pair)" } else { "" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> DepLatTable {
        DepLatTable::from_json(SM120_TABLE).unwrap()
    }

    #[test]
    fn bundled_table_parses_and_names_the_measured_pairs() {
        let t = table();
        assert_eq!(t.arch, "sm_120");
        assert!(t.arch_matches(120) && !t.arch_matches(103) && !t.arch_matches(121));
        let ins = |s: &str| crate::parse_sass(s, 0).unwrap();
        // the pair property (T-26's adjacent-pair census): same unit 4, cross unit 5
        let iadd = ins("IADD3 R6, PT, PT, R4, R5, RZ");
        assert_eq!(t.latency(&iadd, &ins("IADD3 R8, PT, PT, R6, R5, RZ"), 6), (4, false));
        assert_eq!(t.latency(&iadd, &ins("IMAD R8, R6, R5, RZ"), 6), (5, false));
        let imad = ins("IMAD R6, R4, R5, RZ");
        assert_eq!(t.latency(&imad, &ins("IMAD R8, R6, R5, RZ"), 6), (4, false));
        assert_eq!(t.latency(&imad, &ins("IADD3 R8, PT, PT, R6, R5, RZ"), 6), (5, false));
        // predicate: 13 into a guard, 5 into a select
        let setp = ins("ISETP.LT.U32.AND P0, PT, R4, R5, PT");
        assert_eq!(t.latency(&setp, &ins("@P0 IADD3 R8, PT, PT, R4, R5, RZ"), KEY_PRED), (13, false));
        assert_eq!(t.latency(&setp, &ins("SEL R8, R4, R5, P0"), KEY_PRED), (5, false));
        // MMA: 29 into the accumulate operand, 28 into anything else
        let mma = ins("HMMA.16816.F32.BF16 R28, R64, R72, R28");
        assert_eq!(t.latency(&mma, &ins("HMMA.16816.F32.BF16 R28, R68, R74, R28"), 28), (29, false));
        assert_eq!(t.latency(&mma, &ins("FMUL.FTZ R28, R28, R23"), 28), (28, false));
    }

    fn ins(s: &str) -> Instruction {
        let mut i = crate::parse_sass(s, 0).unwrap();
        i.hand_sched = false;
        i
    }

    fn sched(s: &str, stall: u8, yld: bool, wb: u8, wait: u8) -> Instruction {
        let mut i = ins(s);
        i.ctrl.stall = stall;
        i.ctrl.yield_flag = yld;
        i.ctrl.write_bar = wb;
        i.ctrl.wait_mask = wait;
        i
    }

    /// The CUBIT_SCHED2 failure of 2026-11-10 as data: `MUFU [W0:Y:S01]` with its waiter right
    /// behind it. The arming rule sees it, raises the setter by one cycle and nothing else.
    #[test]
    fn the_arming_rule_finds_and_repairs_a_waiter_one_cycle_behind_its_setter() {
        let t = DepLatTable::barriers_only(2);
        let mut k = vec![
            sched("FADD.FTZ R8, R7, R5", 5, false, 7, 0),
            sched("MUFU.EX2 R8, R8", 1, true, 0, 0),
            sched("FSEL R8, R8, RZ, P0", 6, false, 7, 0b1),
            sched("MUFU.LG2 R9, R8", 3, true, 1, 0),
            sched("FADD.FTZ R9, R9, R6", 1, true, 7, 0b10),
        ];
        let v = check(&k, &t);
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!((v[0].producer, v[0].consumer, v[0].have, v[0].need, v[0].kind.as_str()), (1, 2, 1, 2, "barrier-arm"));
        let rep = apply(&mut k, &t);
        assert_eq!((rep.raised, rep.added_cycles, rep.unresolved.len()), (1, 1, 0));
        assert_eq!(k.iter().map(|i| i.ctrl.stall).collect::<Vec<_>>(), vec![5, 2, 6, 3, 1]);
        assert!(k[1].ctrl.yield_flag, "the arming rule leaves the yield flag alone");
        assert!(check(&k, &t).is_empty());
        // without a table the fixed latencies are not this rule's business
        assert!(t.only_barriers && t.cells.is_empty());
    }

    /// A frozen (`[CC]`) setter is never changed: the violation is reported, not repaired.
    #[test]
    fn a_hand_scheduled_setter_is_reported_not_changed() {
        let t = DepLatTable::barriers_only(2);
        let mut k = vec![sched("MUFU.EX2 R8, R8", 1, true, 0, 0), sched("FSEL R8, R8, RZ, P0", 6, false, 7, 0b1)];
        k[0].hand_sched = true;
        let rep = apply(&mut k, &t);
        assert_eq!((rep.raised, rep.unresolved.len(), k[0].ctrl.stall), (0, 1, 1));
    }

    #[test]
    fn classes_follow_the_word_not_the_spelling() {
        for (text, class) in [
            ("IMAD R5, R5, 0x4, RZ", "IMAD"),
            ("IMAD.MOV R5, RZ, RZ, R4", "IMAD"),
            ("IMAD.SHL R5, R5, 0x4, RZ", "IMAD"),
            ("IMAD.WIDE.U32 R2, R0, 0x4, R2", "IMAD.WIDE"),
            ("F2FP.BF16.F32.PACK_AB R9, R8, R7", "F2FP.PACK"),
            ("F2FP.F16.E4M3.UNPACK_B R6, R2", "F2FP.UNPACK"),
            ("HADD2.F32 R7, -RZ, R6.H0_H0", "HADD2.F32"),
            ("FADD.FTZ R8, R7, R5", "FADD"),
        ] {
            assert_eq!(dep_class(&ins(text)), class, "{text}");
        }
    }

    /// A row one stall field cannot carry between text-adjacent instructions asks for a pad:
    /// two MMAs back to back (16), an MMA in front of a reader of its result (28 / 29).
    #[test]
    fn pads_where_one_stall_field_cannot_carry_an_mma_row() {
        let t = table();
        let k = vec![
            ins("HMMA.16816.F32.BF16 R28, R64, R72, RZ"),
            ins("HMMA.16816.F32.BF16 R32, R68, R74, RZ"),
            ins("FADD.FTZ R4, R32, R5"),
            ins("FADD.FTZ R6, R4, R5"),
            ins("HMMA.16816.F32.BF16 R28, R64, R72, R28"),
            ins("IADD3 R7, PT, PT, R4, R5, RZ"),
            ins("FADD.FTZ R8, R28, R5"),
        ];
        assert_eq!(pads_needed(&k, &t), vec![(1, 1), (2, 1)]);
        // straight-line text with the pads in: stalls alone reach every row
        let mut p = k.clone();
        p.insert(2, ins("NOP"));
        p.insert(1, ins("NOP"));
        let rep = apply(&mut p, &t);
        assert!(rep.unresolved.is_empty(), "{:?}", rep.unresolved);
        assert!(check(&p, &t).is_empty());
        // and without them the legaliser says so instead of emitting a short distance
        let mut q = k.clone();
        assert!(!apply(&mut q, &t).unresolved.is_empty());
    }
}
