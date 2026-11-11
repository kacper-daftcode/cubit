//! `CUBIT_VERIFY_FLOW=1` (opt-in, a part of `CUBIT_VERIFY`): the three kinds of the scoreboard
//! simulation — unprotected RAW, broken WAR, recycle-stale — walked on the flow graph.
//!
//! The simulation of `scheduling_pass::run_verify_keys` walks the words of a kernel in TEXT
//! order and carries the scoreboard from one word to the next, also across a word that never
//! falls through; its loop pass re-walks the text from the target of every backward branch with
//! the state at the branch. On straight-line code with a few loops that is the execution. On a
//! kernel as nvcc lays it out — out-of-line blocks behind the hot text that are entered by a
//! forward branch and return by a backward one — it is not, in both directions:
//!
//! * it reports what no execution has. A store at the end of a loop body whose read barrier the
//!   first overwriter at the loop top waits: the text behind the unconditional back branch is
//!   an out-of-line block, the pending read barrier is carried into it, and every word of every
//!   block behind it that writes one of the store's registers is a "broken WAR" — and once more
//!   for the text from the target of each of those blocks' backward returns (276 lines for one
//!   store of a served kernel's schedule, 0 of them on a path; the vendor's own schedule of that
//!   store has the same shape and one such line). A load whose reader stands in a block the
//!   load's path never enters is an "unprotected RAW" for the same reason;
//! * it misses what an execution has. A forward branch carries nothing: the state at its
//!   target is the state of the text in front of the target. A result pending at the branch
//!   and read at its target, with the wait on the fall-through only, is not seen.
//!
//! This view asks the simulation's questions of the paths instead — the walk of
//! `store_paths` (every path of the flow graph, predicates correlated along a path, a dispatch
//! followed into every block only it can reach) from every word that puts something in flight:
//!
//! * **unprotected RAW** — from every scoreboarded producer, for every register it writes:
//!   each word that reads the register on a path with no wait on the producer's write barrier
//!   and no rewrite of the register in front of it;
//! * **recycle-stale** — the same reader behind a word that sets the producer's write barrier
//!   again for a result of another completion class, the first result not yet waited
//!   (`scheduling_pass::same_completion_class`: the simulation's rule);
//! * **broken WAR** — from every memory word the simulation tracks (a global store's address
//!   and data, a tensor instruction's sources, a load's address, an atomic's data) that carries
//!   a read barrier: the FIRST word on each path that rewrites one of those registers with no
//!   wait on the read barrier — or on the word's own write barrier (its result has landed, its
//!   operands are consumed) — in front of it, and for a load that is not served late, closer
//!   than three issue cycles on that path. With `CUBIT_VERIFY_RBPROBE=1` also from the memory
//!   words that carry no read barrier. And — a register no other check of the stores names —
//!   the uniform register of a store's address (the descriptor of a global store, the uniform
//!   base of a shared one): a rewrite on a path with no wait on the store's read barrier is a
//!   finding closer than `sync_class::STORE_UNIFORM_OPERAND_HOLD` issue cycles and is counted
//!   apart from there on (the vendor's schedules do it from 7 on). The same register of a LOAD's
//!   address is counted in a rubric of its own at every distance — no rule names it.
//!
//! The per-word rules are the simulation's (`sb_step`); what differs is which words follow
//! which. Three differences of counting, on purpose: a memory word's finding is its first
//! overwriter on each path (the simulation counts every later overwriter until some wait: one
//! missing wait is hundreds of lines); a register that a second memory word reads late stays
//! the first one's too (the simulation hands it over); and an overwriter whose own result
//! lands late — a load, a scoreboarded producer, a tensor instruction — is counted apart, not
//! as a finding: the vendor's schedules have it everywhere (a self-overwriting
//! `LDS.64 Rx, [Rx+…]` behind earlier loads of its base on one read barrier, a fragment load
//! one cycle behind a tensor instruction), and it is right where it was measured.
//!
//! What the walk does not see is what `store_paths` does not see: a path ends at a return and
//! at an absolute jump, and a called routine is not entered — the walk goes on behind the
//! call. The number of walks that reach such an end with their barrier unwaited is reported
//! (`ends`), so a kernel with calls shows how much of it this view leaves open.
//!
//! A word under `@!PT` never executes (the vendor pads a run of copies with `@!PT LDS RZ, [RZ]`):
//! it puts nothing in flight, reads and writes nothing; `RZ` and `URZ` are no registers. (The
//! simulation counts an "overwrite of R255" on those pads in the views that track a word
//! without a read barrier.)
//!
//! Read-only, printed next to the three classic counts; nothing of `CUBIT_VERIFY`'s own
//! output changes with it.

use crate::ir::Instruction;
use crate::scheduling_pass as sp;
use crate::store_paths::{executes, guard_need, waits, Facts, Flow, FACT_STATE_BUDGET};
use crate::table::IsaTable;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashSet};

/// `CUBIT_VERIFY_FLOW=1`.
pub fn enabled() -> bool {
    std::env::var("CUBIT_VERIFY_FLOW").ok().as_deref() == Some("1")
}

/// One finding of the view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowFinding {
    /// `"raw"`, `"war"` or `"recycle-stale"` — the kinds of the scoreboard simulation
    pub kind: &'static str,
    /// the reader (`raw`, `recycle-stale`) / the overwriter (`war`)
    pub at: usize,
    /// the producer / the memory word
    pub other: usize,
    /// the register, as the scheduler keys it: `(uniform, key)` — a general register, `256 + n`
    /// a predicate, a uniform register, `64 + n` a uniform predicate
    pub reg: (bool, u16),
    /// the barrier nothing waited: the producer's write barrier / the memory word's read barrier
    /// (`None`: the probe's view of a memory word without one)
    pub barrier: Option<u8>,
    /// the smallest issue distance (sum of the stall counts) of a path that reaches `at`
    pub distance: u32,
}

/// The findings and what the walks left open.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowReport {
    pub findings: Vec<FlowFinding>,
    /// walks that reached a return or an absolute jump with their barrier unwaited (the path
    /// behind it is not in the text)
    pub ends: usize,
    /// walks that gave up the correlation of predicates (too many states) and report a superset
    pub uncorrelated: usize,
    /// (store, overwriter, uniform register, distance): the uniform register of a store's address
    /// rewritten on a path with no wait on the store's read barrier, from the operand hold on —
    /// counted apart, not a finding (closer than the hold it is a `war` finding)
    pub store_uniform_apart: Vec<(usize, usize, u8, u32)>,
    /// (memory word, overwriter, register, distance): a late operand rewritten, with no wait in
    /// front, by a word whose own result lands late (a load, a scoreboarded producer, a tensor
    /// instruction) — counted apart, not a finding
    pub war_by_load: Vec<(usize, usize, (bool, u16), u32)>,
    /// (load, overwriter, uniform register, distance): the uniform register of a LOAD's address
    /// rewritten by a fixed-latency word on a path with no wait on the load's read barrier —
    /// counted apart at every distance (no rule names it), never a finding
    pub load_uniform_apart: Vec<(usize, usize, u8, u32)>,
}

impl FlowReport {
    pub fn count(&self, kind: &str) -> usize {
        self.findings.iter().filter(|f| f.kind == kind).count()
    }
}

/// The register as it is printed: `R12`, `P3`, `UR4`, `UP1`.
pub fn reg_name(reg: (bool, u16)) -> String {
    match reg {
        (false, k) if k >= sp::PRED_KEY => format!("P{}", k - sp::PRED_KEY),
        (false, k) => format!("R{k}"),
        (true, k) if k >= 64 => format!("UP{}", k - 64),
        (true, k) => format!("UR{k}"),
    }
}

/// The word's result lands late: a load or another long-latency producer, anything that carries
/// a write barrier, a tensor instruction, a synchronisation word (`sync_class::hold_need`'s
/// "slow" writer). As the overwriter of a late operand it is the vendor's practice — a
/// self-overwriting `LDS.64 Rx, [Rx+…]` behind earlier loads of the same base, a fragment load
/// one cycle behind a tensor instruction — and measured right where it was measured.
fn lands_late(ins: &Instruction) -> bool {
    let op = ins.opcode.as_str();
    sp::is_long_latency(op) || ins.ctrl.write_bar != 7 || sp::is_warp_mma(op) || crate::sync_class::classify(ins).is_some()
}

/// A path ends here and the text does not say where it goes on.
fn leaves_the_text(ins: &Instruction) -> bool {
    matches!(ins.opcode.as_str(), "JMP" | "RET")
}

struct Walker<'a> {
    insns: &'a [Instruction],
    flow: Flow<'a>,
    table: Option<&'a IsaTable>,
}

/// What a walk found: (word, smallest distance, kind index), and whether a path left the text.
struct Hits {
    found: BTreeMap<(usize, u8), u32>,
    ended: bool,
}

impl Walker<'_> {
    /// From producer `p`, register `reg` pending on write barrier `wb`: the readers reached with
    /// the barrier not waited (kind 0), or behind a word that set the barrier again for a
    /// result of another completion class (kind 2). `None`: the state budget of the correlated
    /// walk is used up.
    fn readers(&self, p: usize, reg: (bool, u16), wb: u8, correlate: bool) -> Option<Hits> {
        let insns = self.insns;
        let start = guard_need(&insns[p]).map_or(Facts::default(), |(n, need)| Facts::default().with(n, need));
        let mut hits = Hits { found: BTreeMap::new(), ended: false };
        // state: (word, predicate facts, the barrier was recycled)
        let mut seen: HashSet<(usize, Facts, bool)> = HashSet::new();
        let mut heap: BinaryHeap<Reverse<(u32, usize, Facts, bool)>> = BinaryHeap::new();
        let d0 = insns[p].ctrl.stall as u32;
        for (j, f) in self.flow.succ(p, start, correlate) {
            heap.push(Reverse((d0, j, f, false)));
        }
        while let Some(Reverse((d, i, f, lost))) = heap.pop() {
            if !seen.insert((i, f, lost)) {
                continue;
            }
            if correlate && seen.len() > FACT_STATE_BUDGET {
                return None;
            }
            let ins = &insns[i];
            // the wait comes first, as in the simulation: it releases a pending result — not one
            // whose barrier was taken over
            if !lost && waits(ins) & (1 << wb) != 0 {
                continue;
            }
            let runs = executes(ins, f) && !crate::sync_class::never_executes(ins);
            // a word reads its guard whether or not the guard holds
            let reads_guard = ins.guard.as_ref().is_some_and(|g| g.pred < 7 && reg == (g.uniform, if g.uniform { 64 + g.pred as u16 } else { sp::PRED_KEY + g.pred as u16 }));
            if (runs || reads_guard) && sp::src_regs(ins).contains(&reg) {
                let e = hits.found.entry((i, if lost { 2 } else { 0 })).or_insert(d);
                *e = (*e).min(d);
            }
            // a rewrite ends the result (the simulation drops it; the pair is the write-after-write walk's)
            if runs && sp::dest_regs(ins).contains(&reg) {
                continue;
            }
            // the barrier is set again for a result that does not complete in order behind this one
            let mut lost2 = lost;
            if !lost && runs && ins.ctrl.write_bar == wb && sp::insn_needs_write_bar(ins, self.table, true) && !sp::is_warp_mma(ins.opcode.as_str()) && !sp::same_completion_class(&insns[p], ins) {
                lost2 = true;
            }
            if leaves_the_text(ins) {
                hits.ended = true;
            }
            let d2 = d + ins.ctrl.stall as u32;
            for (j, g) in self.flow.succ(i, f, correlate) {
                if !seen.contains(&(j, g, lost2)) {
                    heap.push(Reverse((d2, j, g, lost2)));
                }
            }
        }
        Some(hits)
    }

    /// From memory word `m`, late register `reg`: the first overwriter on each path that no wait
    /// on `release` (the word's read barrier and its own write barrier) stands in front of —
    /// for a word that is not served late (`late == false`) only closer than three issue cycles.
    fn overwriters(&self, m: usize, reg: (bool, u16), release: u8, late: bool, correlate: bool) -> Option<Hits> {
        const LOAD_ADDR_LATCH: u32 = 3;
        let insns = self.insns;
        let start = guard_need(&insns[m]).map_or(Facts::default(), |(n, need)| Facts::default().with(n, need));
        let mut hits = Hits { found: BTreeMap::new(), ended: false };
        let mut seen: HashSet<(usize, Facts)> = HashSet::new();
        let mut heap: BinaryHeap<Reverse<(u32, usize, Facts)>> = BinaryHeap::new();
        let d0 = insns[m].ctrl.stall as u32;
        for (j, f) in self.flow.succ(m, start, correlate) {
            heap.push(Reverse((d0, j, f)));
        }
        while let Some(Reverse((d, i, f))) = heap.pop() {
            if !seen.insert((i, f)) {
                continue;
            }
            if correlate && seen.len() > FACT_STATE_BUDGET {
                return None;
            }
            let ins = &insns[i];
            if waits(ins) & release != 0 {
                continue;
            }
            // (the smallest distance comes first: a word the three cycles cover on its shortest
            // path is covered on every path)
            if !late && d >= LOAD_ADDR_LATCH {
                continue;
            }
            if executes(ins, f) && !crate::sync_class::never_executes(ins) && sp::dest_regs(ins).contains(&reg) {
                // (kind 3: the overwriter is itself a word whose result lands late — counted apart)
                hits.found.entry((i, if lands_late(ins) { 3 } else { 1 })).or_insert(d);
                continue;
            }
            if leaves_the_text(ins) {
                hits.ended = true;
            }
            let d2 = d + ins.ctrl.stall as u32;
            for (j, g) in self.flow.succ(i, f, correlate) {
                if !seen.contains(&(j, g)) {
                    heap.push(Reverse((d2, j, g)));
                }
            }
        }
        Some(hits)
    }
}

/// The uniform registers of a memory word's address: a descriptor, a uniform base (of a store:
/// `sync_class::store_uniform_operands`).
fn uniform_address_operands(ins: &Instruction) -> Vec<(bool, u16)> {
    let mut out: Vec<(bool, u16)> = Vec::new();
    for o in &ins.operands {
        let u = match o {
            crate::ir::Operand::Desc { ur_idx, .. } => Some(*ur_idx),
            crate::ir::Operand::Addr { ur_reg: Some(u), .. } => Some(*u),
            crate::ir::Operand::ConstMem { ur_reg: Some(u), .. } => Some(*u),
            _ => None,
        };
        if let Some(u) = u {
            if u < 63 && !out.contains(&(true, u as u16)) {
                out.push((true, u as u16));
            }
        }
    }
    out
}

/// The late operands of a memory word as the scoreboard simulation registers them, and whether
/// the word is served late (no issue distance covers an overwriter).
fn late_operands(ins: &Instruction, table: Option<&IsaTable>) -> (Vec<u8>, bool) {
    let op = ins.opcode.as_str();
    if matches!(op, "STS" | "STSM" | "STL") {
        // (the stores `store_paths` walks with its own count: shared and local stores)
        (Vec::new(), true)
    } else if sp::insn_is_store(ins, table) {
        let mut v = sp::store_addr_gprs(ins);
        for r in sp::store_data_gprs(ins) {
            if !v.contains(&r) {
                v.push(r);
            }
        }
        (v, true)
    } else if sp::is_warp_mma(op) {
        (sp::mma_src_gprs(ins), true)
    } else if sp::is_long_latency(op) {
        let mut v = sp::load_addr_gprs(ins);
        for r in sp::atom_data_gprs(ins) {
            if !v.contains(&r) {
                v.push(r);
            }
        }
        (v, matches!(op, "LDS" | "LDSM" | "LDL"))
    } else {
        (Vec::new(), false)
    }
}

/// The view: every finding, sorted by (kind, word, other word, register). `rb_probe`: also
/// the memory words that carry no read barrier (the read-barrier probe's view).
pub fn walk(insns: &[Instruction], table: Option<&IsaTable>, rb_probe: bool) -> FlowReport {
    let w = Walker { insns, flow: Flow::new(insns), table };
    let mut rep = FlowReport::default();
    let nb = sp::NUM_BARRIERS as u8;
    let kind_name = |k: u8| match k {
        0 => "raw",
        1 => "war",
        _ => "recycle-stale",
    };
    // RZ and URZ are no registers: nothing is pending in them and nothing reads them late
    let zero = |r: &(bool, u16)| *r == (false, 255) || *r == (true, 63);
    for (i, ins) in insns.iter().enumerate() {
        // a word under `@!PT` never executes (the vendor's pads): it puts nothing in flight
        if crate::sync_class::never_executes(ins) {
            continue;
        }
        // a result in flight: a scoreboarded producer that carries a write barrier
        let wb = ins.ctrl.write_bar;
        if wb < nb && sp::insn_needs_write_bar(ins, table, true) && !sp::is_warp_mma(ins.opcode.as_str()) {
            // (an atomic: the scheduler's own convention — the certified sets take the data
            // register of a form that returns nothing for its destination, `store_paths::unwaited_rewrites`)
            let mut regs = if matches!(ins.opcode.as_str(), "ATOM" | "ATOMG" | "ATOMS") { sp::dest_regs_plain(ins) } else { sp::dest_regs(ins) };
            regs.retain(|r| !zero(r));
            regs.sort_unstable();
            regs.dedup();
            for reg in regs {
                let hits = match w.readers(i, reg, wb, true) {
                    Some(h) => h,
                    None => {
                        rep.uncorrelated += 1;
                        w.readers(i, reg, wb, false).expect("the walk without correlation has one state per word")
                    }
                };
                rep.ends += hits.ended as usize;
                for ((at, kind), d) in hits.found {
                    rep.findings.push(FlowFinding { kind: kind_name(kind), at, other: i, reg, barrier: Some(wb), distance: d });
                }
            }
        }
        // late operands: a memory word with a read barrier (the probe: every memory word)
        let rb = ins.ctrl.read_bar;
        if rb < nb || rb_probe {
            let (regs, late) = late_operands(ins, table);
            let mut release: u8 = if rb < nb { 1 << rb } else { 0 };
            if wb < nb {
                release |= 1 << wb;
            }
            let mut regs = regs;
            regs.retain(|r| *r != 255);
            regs.sort_unstable();
            regs.dedup();
            for r in regs {
                let hits = match w.overwriters(i, (false, r as u16), release, late, true) {
                    Some(h) => h,
                    None => {
                        rep.uncorrelated += 1;
                        w.overwriters(i, (false, r as u16), release, late, false).expect("the walk without correlation has one state per word")
                    }
                };
                rep.ends += hits.ended as usize;
                for ((at, kind), d) in hits.found {
                    if kind == 3 {
                        rep.war_by_load.push((i, at, (false, r as u16), d));
                    } else {
                        rep.findings.push(FlowFinding { kind: "war", at, other: i, reg: (false, r as u16), barrier: (rb < nb).then_some(rb), distance: d });
                    }
                }
            }
            // the uniform register of a store's address (the descriptor, a uniform base) is read as
            // late as its general registers, and no walk of the stores names it: a rewrite with no
            // wait in front of it is a finding closer than the operand hold, and counted apart from
            // there on (the vendor's schedules rewrite it unwaited from 7 issue cycles on)
            for u in crate::sync_class::store_uniform_operands(ins) {
                let hits = match w.overwriters(i, u, release, true, true) {
                    Some(h) => h,
                    None => {
                        rep.uncorrelated += 1;
                        w.overwriters(i, u, release, true, false).expect("the walk without correlation has one state per word")
                    }
                };
                rep.ends += hits.ended as usize;
                for ((at, kind), d) in hits.found {
                    if kind == 3 {
                        rep.war_by_load.push((i, at, u, d));
                    } else if d < crate::sync_class::STORE_UNIFORM_OPERAND_HOLD as u32 {
                        rep.findings.push(FlowFinding { kind: "war", at, other: i, reg: u, barrier: (rb < nb).then_some(rb), distance: d });
                    } else {
                        rep.store_uniform_apart.push((i, at, u.1 as u8, d));
                    }
                }
            }
            // ... and of a LOAD's address: no rule names it (the vendor's schedules rewrite the descriptor
            // of a barred load a few cycles behind it) — counted, apart from the stores', never a finding
            if sp::is_long_latency(ins.opcode.as_str()) && !sp::is_store(ins.opcode.as_str()) && !sp::is_warp_mma(ins.opcode.as_str()) {
                for u in uniform_address_operands(ins) {
                    let hits = match w.overwriters(i, u, release, true, true) {
                        Some(h) => h,
                        None => {
                            rep.uncorrelated += 1;
                            w.overwriters(i, u, release, true, false).expect("the walk without correlation has one state per word")
                        }
                    };
                    rep.ends += hits.ended as usize;
                    for ((at, kind), d) in hits.found {
                        if kind != 3 {
                            rep.load_uniform_apart.push((i, at, u.1 as u8, d));
                        }
                    }
                }
            }
        }
    }
    rep.findings.sort_by_key(|f| (f.kind, f.at, f.other, f.reg));
    rep.findings.dedup_by_key(|f| (f.kind, f.at, f.other, f.reg));
    rep.store_uniform_apart.sort_unstable();
    rep.store_uniform_apart.dedup();
    rep.war_by_load.sort_unstable();
    rep.war_by_load.dedup();
    rep.load_uniform_apart.sort_unstable();
    rep.load_uniform_apart.dedup();
    rep
}

/// The summaries of the pairs counted apart, as `CUBIT_VERIFY` prints them under the variable.
pub fn describe_apart(rep: &FlowReport) -> Vec<String> {
    let mut out = Vec::new();
    if !rep.war_by_load.is_empty() {
        let nearest = rep.war_by_load.iter().map(|x| x.3).min().unwrap_or(0);
        out.push(format!(
            "CUBIT_VERIFY_FLOW: + {} late operand(s) rewritten with no wait in front by a word whose own result lands late — a load, a scoreboarded producer, a tensor instruction (the nearest at {}; not counted: the vendor's practice)",
            rep.war_by_load.len(),
            nearest
        ));
    }
    if !rep.store_uniform_apart.is_empty() {
        let nearest = rep.store_uniform_apart.iter().map(|x| x.3).min().unwrap_or(0);
        out.push(format!(
            "CUBIT_VERIFY_FLOW: + {} rewrite(s) of the uniform register of a store's address from {} issue cycles on with no wait on the store's read barrier (the nearest at {}; not counted: the vendor's schedules do it from 7 on)",
            rep.store_uniform_apart.len(),
            crate::sync_class::STORE_UNIFORM_OPERAND_HOLD,
            nearest
        ));
    }
    if !rep.load_uniform_apart.is_empty() {
        let nearest = rep.load_uniform_apart.iter().map(|x| x.3).min().unwrap_or(0);
        out.push(format!(
            "CUBIT_VERIFY_FLOW: + {} rewrite(s) of the uniform register of a load's address with no wait on the load's read barrier (the nearest at {}; not counted: no rule names a load's uniform register)",
            rep.load_uniform_apart.len(),
            nearest
        ));
    }
    out
}

/// One line per finding, as `CUBIT_VERIFY` prints it under the variable.
pub fn describe(insns: &[Instruction], f: &FlowFinding) -> String {
    let (at, other) = (&insns[f.at].opcode_full, &insns[f.other].opcode_full);
    match f.kind {
        "raw" => format!(
            "  FLOW RAW: insn[{}] {at} reads {} <- var-producer insn[{}] {other} {} issue cycles earlier on a path with no wait on barrier {}",
            f.at,
            reg_name(f.reg),
            f.other,
            f.distance,
            f.barrier.unwrap_or(7)
        ),
        "recycle-stale" => format!(
            "  FLOW RECYCLE-STALE: insn[{}] {at} reads {} <- var-producer insn[{}] {other} {} issue cycles earlier on a path where barrier {} was set again before it was waited",
            f.at,
            reg_name(f.reg),
            f.other,
            f.distance,
            f.barrier.unwrap_or(7)
        ),
        _ => format!(
            "  FLOW WAR: insn[{}] {at} overwrites {} of mem-op insn[{}] {other} {} issue cycles later on a path with no wait on {}",
            f.at,
            reg_name(f.reg),
            f.other,
            f.distance,
            match f.barrier {
                Some(b) => format!("its read barrier {b}"),
                None => "anything that releases it (probe: the mem-op has no read barrier)".to_string(),
            }
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel(lines: &[&str]) -> Vec<Instruction> {
        let text = format!(".entry k\n{}\n.endentry\n", lines.iter().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n"));
        let mut k = crate::sass_file::parse_sass_file_str(&text).unwrap().kernels.remove(0).instructions;
        for (i, ins) in k.iter_mut().enumerate() {
            ins.addr = (i * 16) as u32;
        }
        k
    }

    fn keys(rep: &FlowReport) -> Vec<(&'static str, usize, usize, String)> {
        rep.findings.iter().map(|f| (f.kind, f.at, f.other, reg_name(f.reg))).collect()
    }

    /// The store of a loop's last block, its read barrier waited by the first overwriter at the loop top, and
    /// behind the unconditional back branch an out-of-line block that rewrites the store's address register and
    /// returns by a backward branch — the layout of nvcc, in small.
    const LOOP_WITH_AN_OUT_OF_LINE_BLOCK: &[&str] = &[
        "[B------:R-:W-:Y:S01] MOV R6, 0x10 ;",
        "L_top:",
        "[B---3--:R-:W-:Y:S01] IADD3 R4, PT, PT, R6, 0x4, RZ ;",
        "[B------:R-:W-:Y:S01] MOV R5, RZ ;",
        "[B------:R-:W-:-:S13] ISETP.NE.AND P0, PT, R6, RZ, PT ;",
        "[B------:R-:W-:Y:S05] @P0 BRA L_cold ;",
        "L_back:",
        "[B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R6, 0x1, RZ ;",
        "[B------:R3:W-:Y:S04] STG.E desc[UR4][R4.64], R7 ;",
        "[B------:R-:W-:Y:S05] BRA L_top ;",
        "L_cold:",
        "[B------:R-:W-:Y:S01] MOV R4, 0x40 ;",
        "[B------:R-:W-:Y:S05] BRA L_back ;",
        "[B------:R-:W-:Y:S05] EXIT ;",
    ];

    #[test]
    fn a_read_barrier_waited_on_the_path_is_not_a_finding_behind_an_unconditional_branch() {
        let k = kernel(LOOP_WITH_AN_OUT_OF_LINE_BLOCK);
        // the text-order simulation: the pending read barrier is carried across `BRA L_top` into the block
        // behind it, where `MOV R4` rewrites the address register "before the barrier is waited"
        let (classic, _) = sp::verify_scoreboard_findings(&k, None);
        assert!(classic.war >= 1, "{classic:?}");
        // on the paths: the store's only way on is the branch to the loop top, whose first word waits barrier 3
        let rep = walk(&k, None, false);
        assert_eq!(keys(&rep), Vec::<(&str, usize, usize, String)>::new());
        assert_eq!(crate::store_paths::unwaited_store_overwrites(&k, false), vec![]);

        // without that one wait the first overwriter of each register on the path is the finding: the two
        // words at the loop top (the out-of-line block's `MOV R4` stands behind them on every path)
        let mut bare = k.clone();
        bare[1].ctrl.wait_mask = 0;
        let rep = walk(&bare, None, false);
        assert_eq!(keys(&rep), [("war", 1, 6, "R4".to_string()), ("war", 2, 6, "R5".to_string())]);
        assert_eq!(rep.findings[0].distance, 9, "the store's stall and the branch's");
    }

    /// A load in one arm of a branch, its reader in the other arm's block further down the text; the wait is
    /// where the paths from the load pass (the join behind both arms).
    #[test]
    fn a_reader_the_load_does_not_reach_is_not_a_finding_and_a_reader_it_reaches_is() {
        let text = |join_wait: &str| {
            vec![
                "[B------:R-:W-:-:S13] ISETP.NE.AND P0, PT, R6, RZ, PT ;".to_string(),
                "[B------:R-:W-:Y:S05] @P0 BRA L_other ;".to_string(),
                "[B------:R-:W1:Y:S02] LDG.E R8, desc[UR4][R2.64] ;".to_string(),
                "[B------:R-:W-:Y:S05] BRA L_join ;".to_string(),
                "L_other:".to_string(),
                "[B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R8, 0x1, RZ ;".to_string(),
                "L_join:".to_string(),
                format!("[{join_wait}:R-:W-:Y:S01] IADD3 R10, PT, PT, R8, 0x1, RZ ;"),
                "[B------:R-:W-:Y:S05] EXIT ;".to_string(),
            ]
        };
        let lines = text("B-1----");
        let k = kernel(&lines.iter().map(|s| s.as_str()).collect::<Vec<_>>());
        // text order: `IADD3 R9, …, R8` stands behind the load with barrier 1 not waited
        let (classic, found) = sp::verify_scoreboard_findings(&k, None);
        assert_eq!((classic.raw, found.iter().filter(|f| f.kind == "raw").map(|f| (f.at, f.other)).collect::<Vec<_>>()), (1, vec![(4, 2)]));
        // on the paths the load's block jumps over it: the first reader the load reaches waits
        assert_eq!(keys(&walk(&k, None, false)), Vec::<(&str, usize, usize, String)>::new());
        // and the reader it does reach, without the wait, is the finding
        let lines = text("B------");
        let k = kernel(&lines.iter().map(|s| s.as_str()).collect::<Vec<_>>());
        assert_eq!(keys(&walk(&k, None, false)), [("raw", 5, 2, "R8".to_string())]);
    }

    /// What the text order cannot see: a forward branch carries the pending result to its target. The wait
    /// stands on the fall-through only; the branch is taken while the load is in flight.
    #[test]
    fn a_forward_branch_carries_a_pending_result_to_its_target() {
        let k = kernel(&[
            "[B------:R-:W-:-:S13] ISETP.NE.AND P0, PT, R6, RZ, PT ;",
            "[B------:R-:W1:Y:S02] LDG.E R8, desc[UR4][R2.64] ;",
            "[B------:R-:W-:Y:S05] @P0 BRA L_far ;",
            "[B-1----:R-:W-:Y:S01] IADD3 R9, PT, PT, R8, 0x1, RZ ;",
            "[B------:R-:W-:Y:S05] EXIT ;",
            "L_far:",
            "[B------:R-:W-:Y:S01] IADD3 R10, PT, PT, R8, 0x1, RZ ;",
            "[B------:R-:W-:Y:S05] EXIT ;",
        ]);
        // the simulation walks the fall-through, whose reader waits, and arrives at the target with nothing pending
        let (classic, _) = sp::verify_scoreboard_findings(&k, None);
        assert_eq!((classic.raw, classic.war, classic.recycle), (0, 0, 0));
        let rep = walk(&k, None, false);
        assert_eq!(keys(&rep), [("raw", 5, 1, "R8".to_string())]);
        assert_eq!((rep.findings[0].barrier, rep.findings[0].distance), (Some(1), 7));
        // a reader under a guard that is known false on the path does not read
        let mut guarded = k.clone();
        guarded[5] = crate::parse_sass("@!P0 IADD3 R10, PT, PT, R8, 0x1, RZ", 0).unwrap();
        guarded[5].ctrl = k[5].ctrl;
        guarded[5].addr = k[5].addr;
        assert_eq!(keys(&walk(&guarded, None, false)), Vec::<(&str, usize, usize, String)>::new());
    }

    /// The barrier of a pending result set again by a producer of another class: the reader of the first result
    /// is recycle-stale on the path that passes the second producer, whether or not it waits.
    #[test]
    fn a_barrier_set_again_for_another_class_is_recycle_stale_on_the_path() {
        let k = kernel(&[
            "[B------:R-:W1:Y:S02] LDG.E R8, desc[UR4][R2.64] ;",
            "[B------:R-:W1:Y:S02] LDS R12, [R20] ;",
            "[B-1----:R-:W-:Y:S01] IADD3 R9, PT, PT, R8, R12, RZ ;",
            "[B------:R-:W-:Y:S05] EXIT ;",
        ]);
        let (classic, _) = sp::verify_scoreboard_findings(&k, None);
        assert_eq!((classic.raw, classic.war, classic.recycle), (0, 0, 1));
        assert_eq!(keys(&walk(&k, None, false)), [("recycle-stale", 2, 0, "R8".to_string())]);
        // two loads of one class and one line on one barrier complete in order: no finding
        let k = kernel(&[
            "[B------:R-:W1:Y:S02] LDS R8, [R20] ;",
            "[B------:R-:W1:Y:S02] LDS R12, [R20+0x4] ;",
            "[B-1----:R-:W-:Y:S01] IADD3 R9, PT, PT, R8, R12, RZ ;",
            "[B------:R-:W-:Y:S05] EXIT ;",
        ]);
        assert_eq!(keys(&walk(&k, None, false)), Vec::<(&str, usize, usize, String)>::new());
    }

    /// A load's address is consumed three issue cycles behind it; a shared load's is not covered by distance;
    /// and the probe's view walks from the memory words that carry no read barrier.
    #[test]
    fn the_simulations_rules_for_a_late_operand() {
        let k = |load: &str, rb: &str, stall: u8| {
            kernel(&[&format!("[B------:R{rb}:W1:Y:S0{stall}] {load} ;"), "[B------:R-:W-:Y:S01] IADD3 R2, PT, PT, R2, 0x4, RZ ;", "[B-1----:R-:W-:Y:S01] MOV R9, R8 ;", "[B------:R-:W-:Y:S05] EXIT ;"])
        };
        // the address register of a global load rewritten 2 cycles behind it without a wait on its read barrier
        assert_eq!(keys(&walk(&k("LDG.E R8, desc[UR4][R2.64]", "0", 2), None, false)), [("war", 1, 0, "R2".to_string())]);
        // ... 3 cycles behind it: covered by distance
        assert_eq!(keys(&walk(&k("LDG.E R8, desc[UR4][R2.64]", "0", 3), None, false)), Vec::<(&str, usize, usize, String)>::new());
        // a shared load can be replayed: no distance covers it
        assert_eq!(keys(&walk(&k("LDS R8, [R2]", "0", 3), None, false)), [("war", 1, 0, "R2".to_string())]);
        // without a read barrier the word is not walked — except in the probe's view
        assert_eq!(keys(&walk(&k("LDS R8, [R2]", "-", 3), None, false)), Vec::<(&str, usize, usize, String)>::new());
        let probe = walk(&k("LDS R8, [R2]", "-", 3), None, true);
        assert_eq!((keys(&probe), probe.findings[0].barrier), (vec![("war", 1, 0, "R2".to_string())], None));
        // a wait on the load's own write barrier releases its operands
        let mut waited = k("LDS R8, [R2]", "0", 3);
        waited[1].ctrl.wait_mask = 0b10;
        assert_eq!(keys(&walk(&waited, None, false)), Vec::<(&str, usize, usize, String)>::new());
        // an overwriter that is itself a load lands late: counted apart, not a finding
        let by_load = kernel(&["[B------:R0:W1:Y:S01] LDS R8, [R2] ;", "[B------:R-:W1:Y:S01] LDS R2, [R2+0x40] ;", "[B-1----:R-:W-:Y:S01] MOV R9, R8 ;", "[B------:R-:W-:Y:S05] EXIT ;"]);
        let rep = walk(&by_load, None, false);
        assert_eq!((keys(&rep), rep.war_by_load.clone()), (vec![], vec![(0, 1, (false, 2), 1)]));
        assert_eq!(describe_apart(&rep).len(), 1);
    }

    /// The uniform register of a store's address: closer than the operand hold a finding, from it on counted apart.
    #[test]
    fn the_uniform_register_of_a_stores_address_is_walked() {
        let k = |stall: u8, wait: &str| {
            kernel(&[&format!("[B------:R2:W-:Y:S0{stall}] STG.E desc[UR4][R2.64], R5 ;"), &format!("[{wait}:R-:W-:Y:S01] UMOV UR4, 0x400 ;"), "[B------:R-:W-:Y:S05] EXIT ;"])
        };
        let near = walk(&k(6, "B------"), None, false);
        assert_eq!((keys(&near), near.store_uniform_apart.len()), (vec![("war", 1, 0, "UR4".to_string())], 0));
        let far = walk(&k(7, "B------"), None, false);
        assert_eq!((keys(&far), far.store_uniform_apart.clone()), (vec![], vec![(0, 1, 4, 7)]));
        // a wait on the store's read barrier in front of the rewrite: neither
        let waited = walk(&k(1, "B--2---"), None, false);
        assert_eq!((keys(&waited), waited.store_uniform_apart.len()), (vec![], 0));
        // the uniform base of a shared store, which the simulation does not track at all
        let s = kernel(&["[B------:R2:W-:Y:S02] STS [UR4+0x10], R5 ;", "[B------:R-:W-:Y:S01] UMOV UR4, 0x400 ;", "[B------:R-:W-:Y:S05] EXIT ;"]);
        assert_eq!(keys(&walk(&s, None, false)), [("war", 1, 0, "UR4".to_string())]);
        // a load's descriptor: counted in a rubric of its own at any distance, never a finding
        let l = kernel(&["[B------:R2:W1:Y:S03] LDG.E R8, desc[UR4][R2.64] ;", "[B------:R-:W-:Y:S01] UMOV UR4, 0x400 ;", "[B-1----:R-:W-:Y:S01] MOV R9, R8 ;", "[B------:R-:W-:Y:S05] EXIT ;"]);
        let rep = walk(&l, None, false);
        assert_eq!((keys(&rep), rep.load_uniform_apart.clone(), rep.store_uniform_apart.len()), (vec![], vec![(0, 1, 4, 3)], 0));
    }

    /// A path that leaves the text is counted, not followed.
    #[test]
    fn a_walk_that_ends_at_a_return_is_counted() {
        let k = kernel(&["[B------:R-:W1:Y:S02] LDG.E R8, desc[UR4][R2.64] ;", "[B------:R-:W-:Y:S05] RET ;", "[B-1----:R-:W-:Y:S01] MOV R9, R8 ;", "[B------:R-:W-:Y:S05] EXIT ;"]);
        let rep = walk(&k, None, false);
        assert_eq!((keys(&rep), rep.ends), (Vec::<(&str, usize, usize, String)>::new(), 1));
    }
}
