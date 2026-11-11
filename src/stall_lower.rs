//! `CUBIT_SCHED2_LOWER=1` (opt-in, on top of `CUBIT_SCHED2_MEMSTALL=table`): take back the stalls
//! that no rule asks for.
//!
//! The passes that make a schedule legal only RAISE a stall. The latency legaliser
//! (`dep_stall::apply`) raises the stall in front of a consumer until every requirement of the
//! table holds on every path, one requirement after another; `sync_class::hold_operands` then
//! raises the stall in front of an overwriter until it stands behind the operand hold of its
//! reader. A stall raised for one requirement is never looked at again when a later raise — for
//! another requirement, by another pass — covers the first one too: `MOV R27, R95` in front of a
//! tensor instruction stays at 13 cycles for the spacing of two tensor instructions after the
//! operand hold put the missing cycles on another word between the two, where 7 is what its own
//! result needs. On the vendor's texts those left-over cycles are the largest part of what
//! cubit's schedule of a tensor loop stands above the vendor's.
//!
//! This pass runs behind the two and takes back what is left over. It never goes below the stall
//! a word had IN FRONT of the legaliser (the first pass's stall with its own rules: the spacing
//! of one memory pipe, the stall of a branch, a synchronisation word's floor, the recycle
//! drain), so it only undoes raises; and a raise is undone only as far as every requirement that
//! spans the word keeps its distance:
//!
//! * **the table** — every requirement `dep_stall` knows (cells, defaults, the `producer_forms`,
//!   the resource spacings, the landing rows, the arming distance), on every path of the flow
//!   graph the legaliser itself uses. `dep_stall`'s forward dataflow gives the smallest elapsed
//!   distance of every reaching definition in front of a word; a backward dataflow of the same
//!   shape gives what every reaching definition still has to have elapsed behind the word (the
//!   need of each consumer, less the stalls between). A word's stall may go down to the largest
//!   difference of the two. Both dataflows are monotone under a lowered stall and are continued
//!   after each change, so the bound is exact for the schedule as it stands at that moment;
//! * **the operand holds** — a rewrite of ANY register a tensor instruction reads (its fragment
//!   quads, its accumulator quad, every other register operand taken as a quad, its uniform
//!   operands, its guard) keeps `sync_class::MMA_OPERAND_HOLD` issue cycles behind it on every
//!   path, whatever the class of the writer; a rewrite of the uniform register of a store's
//!   address keeps `STORE_UNIFORM_OPERAND_HOLD` behind the store; a `UMOV` keeps
//!   `UNIFORM_OPERAND_HOLD` behind a uniform-datapath reader of its target. A pair that stands
//!   closer than that today (the vendor's text has a load one cycle behind a tensor
//!   instruction) keeps the distance it has;
//! * **the scoreboard simulation's one distance** — an overwriter of a global load's address
//!   register that stands three issue cycles behind the load today stays there (the only place
//!   where a count of `CUBIT_VERIFY` reads a stall), in text order and across a back edge as the
//!   simulation walks them.
//!
//! Behind the pass the legaliser and the operand hold run once more: they must have nothing to
//! raise, and what they do raise is reported. The three counts of the scoreboard simulation are
//! compared in both views before and after; if one moved the lowering is withdrawn.
//!
//! The order is the order of gain: the words of the smallest loop first (a requirement's slack
//! is spent where the word runs most often), then the text. Greedy — every word ends at its
//! floor or at a requirement that is exactly met, which is not the smallest possible stall sum.
//!
//! A lowered schedule is legal by every static check of this repository and has not been on a
//! card: its class is that of every other schedule cubit builds from the table.

use crate::dep_stall as ds;
use crate::ir::{Instruction, Operand};
use crate::scheduling_pass as sp;
use crate::table::IsaTable;
use std::collections::{HashSet, VecDeque};

/// `CUBIT_SCHED2_LOWER` as written: `Ok(true)` for `1`, `Ok(false)` when unset, empty or `0`,
/// the message of the refusal for any other value.
pub fn request() -> Result<bool, String> {
    match std::env::var("CUBIT_SCHED2_LOWER") {
        Err(_) => Ok(false),
        Ok(v) if v.is_empty() || v == "0" => Ok(false),
        Ok(v) if v == "1" => Ok(true),
        Ok(v) => Err(format!("CUBIT_SCHED2_LOWER={v}: the only value is `1` (take back the stalls no requirement asks for, behind the legaliser); unset = the legaliser's stalls as raised")),
    }
}

/// What a word carried in front of the raising passes: its stall and its yield flag.
pub type Before = (u8, bool);

/// The stalls and yield flags as they stand — taken in front of the legaliser.
pub fn snapshot(insns: &[Instruction]) -> Vec<Before> {
    insns.iter().map(|x| (x.ctrl.stall, x.ctrl.yield_flag)).collect()
}

/// What the pass did.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// words whose stall stood above the one in front of the legaliser
    pub candidates: usize,
    /// words lowered, and by how many cycles in all
    pub lowered: usize,
    pub cycles: usize,
    /// requirements kept by name beside the table's: operand holds, the simulation's distance
    pub hold_spans: usize,
    pub sim_spans: usize,
    /// the guard: what the legaliser and the operand hold raised again behind the pass
    pub guard_raised: usize,
    pub guard_cycles: usize,
    pub guard_hold: usize,
    /// the lowering was withdrawn: a count of the scoreboard simulation moved, or the legaliser
    /// could not place a requirement again
    pub withdrawn: Option<String>,
}

/// One requirement on the sum of the stalls of a list of words (a path from a reader to an
/// overwriter, or the simulation's text span from a load to an overwriter).
struct Span {
    need: u32,
    sum: u32,
}

type Req = (u16, u32, u8);

/// Pointwise maximum-merge of `b` into `a` (both sorted by (key, def)).
fn merge_max(a: &mut Vec<Req>, b: &[Req]) {
    if b.is_empty() {
        return;
    }
    let mut out: Vec<Req> = Vec::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        if j >= b.len() || (i < a.len() && (a[i].0, a[i].1) < (b[j].0, b[j].1)) {
            out.push(a[i]);
            i += 1;
        } else if i >= a.len() || (b[j].0, b[j].1) < (a[i].0, a[i].1) {
            out.push(b[j]);
            j += 1;
        } else {
            out.push((a[i].0, a[i].1, a[i].2.max(b[j].2)));
            i += 1;
            j += 1;
        }
    }
    *a = out;
}

/// The general registers a word writes: the scheduler's convention and the measured footprints
/// of the register allocator's sm_120 target (a quad for `LDSM.….4`, a pair for a 64-bit result).
fn written(ins: &Instruction) -> Vec<(bool, u16)> {
    let mut v: Vec<(bool, u16)> = sp::dest_regs(ins);
    let x = crate::ra_target::target_xfer(crate::ra_target::RaTarget::Sm120, ins);
    if x.known {
        for r in x.rdefs {
            if !v.contains(&(false, r as u16)) {
                v.push((false, r as u16));
            }
        }
    }
    v
}

/// Every register a tensor instruction reads, generously: the scheduler's sources (fragment and
/// accumulator quads, uniform operands, the guard) and each register operand behind the
/// destination as a full quad.
fn tensor_reads(ins: &Instruction) -> Vec<(bool, u16)> {
    let mut v: Vec<(bool, u16)> = sp::src_regs(ins);
    for o in ins.operands.iter().skip(1) {
        if let Operand::Reg { num, .. } = o {
            if *num < 255 {
                for r in 0..4u16 {
                    let k = *num as u16 + r;
                    if k < 255 && !v.contains(&(false, k)) {
                        v.push((false, k));
                    }
                }
            }
        }
    }
    v
}

struct Lowering<'a> {
    insns: &'a mut [Instruction],
    flow: ds::Flow,
    sem: Vec<ds::Sem>,
    /// forward: IN state per word (`None`: unreachable)
    fin: Vec<Option<Vec<ds::Entry>>>,
    /// the needs each word puts on the definitions that reach it
    needs: Vec<Vec<Req>>,
    /// backward: what a reaching definition has to have elapsed when it enters the word
    rin: Vec<Vec<Req>>,
    spans: Vec<Span>,
    spans_of: Vec<Vec<u32>>,
}

impl Lowering<'_> {
    /// What every definition has to have elapsed behind word `i`: the maximum over its successors.
    fn req_out(&self, i: usize) -> Vec<Req> {
        let mut out: Vec<Req> = Vec::new();
        for &s in &self.flow.succ[i] {
            merge_max(&mut out, &self.rin[s]);
        }
        out
    }

    /// ... and when it enters word `i`: the word's own needs, and what passes through it.
    fn req_in(&self, i: usize) -> Vec<Req> {
        let Some(st) = &self.fin[i] else { return Vec::new() };
        let stall = self.insns[i].ctrl.stall;
        let mut through: Vec<Req> = Vec::new();
        for (k, d, r) in self.req_out(i) {
            // a definition of this word starts behind it; one the word ends does not pass
            if d as usize == i || ds::ends_key(&self.sem[i], k) || r <= stall {
                continue;
            }
            if ds::elapsed_in(st, k, d as usize).is_some() {
                through.push((k, d, r - stall));
            }
        }
        let mut out = self.needs[i].clone();
        merge_max(&mut out, &through);
        out
    }

    /// The smallest stall word `i` may carry with every requirement through it kept.
    fn floor(&self, i: usize) -> u8 {
        let Some(st) = &self.fin[i] else { return self.insns[i].ctrl.stall };
        let stall = self.insns[i].ctrl.stall;
        let mut m: u8 = 0;
        for (k, d, r) in self.req_out(i) {
            if d as usize == i {
                m = m.max(r);
            } else if !ds::ends_key(&self.sem[i], k) {
                if let Some(f) = ds::elapsed_in(st, k, d as usize) {
                    m = m.max(r.saturating_sub(f));
                }
            }
        }
        for &s in &self.spans_of[i] {
            let sp = &self.spans[s as usize];
            let slack = sp.sum.saturating_sub(sp.need);
            m = m.max(stall.saturating_sub(slack.min(stall as u32) as u8));
        }
        m.min(stall)
    }

    /// Word `i` takes the stall `to` (lower than its own): both dataflows are continued.
    fn lower(&mut self, i: usize, to: u8) {
        let delta = (self.insns[i].ctrl.stall - to) as u32;
        self.insns[i].ctrl.stall = to;
        for &s in &self.spans_of[i] {
            self.spans[s as usize].sum -= delta;
        }
        // forward: the elapsed distances behind the word shrink
        let mut work: VecDeque<usize> = VecDeque::new();
        work.push_back(i);
        while let Some(j) = work.pop_front() {
            let Some(st) = &self.fin[j] else { continue };
            let out = ds::transfer(j, st, &self.sem[j], self.insns[j].ctrl.stall);
            for k in 0..self.flow.succ[j].len() {
                let s = self.flow.succ[j][k];
                let changed = match &mut self.fin[s] {
                    None => {
                        self.fin[s] = Some(out.clone());
                        true
                    }
                    Some(cur) => ds::merge(cur, &out),
                };
                if changed && !work.contains(&s) {
                    work.push_back(s);
                }
            }
        }
        // backward: what has to have elapsed in front of the word grows
        let mut work: VecDeque<usize> = VecDeque::new();
        work.push_back(i);
        while let Some(j) = work.pop_front() {
            let new = self.req_in(j);
            if new != self.rin[j] {
                self.rin[j] = new;
                for &p in &self.flow.pred[j] {
                    if !work.contains(&p) {
                        work.push_back(p);
                    }
                }
            }
        }
    }

    fn add_span(&mut self, seen: &mut HashSet<(Vec<u32>, u32)>, words: Vec<u32>, need: u32) -> bool {
        if !seen.insert((words.clone(), need)) {
            return false;
        }
        let sum: u32 = words.iter().map(|&w| self.insns[w as usize].ctrl.stall as u32).sum();
        let id = self.spans.len() as u32;
        let mut uniq = words;
        uniq.sort_unstable();
        uniq.dedup();
        for w in uniq {
            self.spans_of[w as usize].push(id);
        }
        self.spans.push(Span { need, sum });
        true
    }
}

/// The operand holds as requirements on paths: from every tensor instruction (every register it
/// reads, any writer, `MMA_OPERAND_HOLD`), every store (the uniform register of its address, any
/// writer, `STORE_UNIFORM_OPERAND_HOLD`) and every uniform-datapath reader (`hold_need`), along
/// every path of the flow graph as far as the words' lowest stalls keep a writer inside the hold.
/// Returns the number of requirements; `frozen[w]`: a word no stall of which is lowered because
/// the paths behind a reader were too many to list.
fn hold_spans(lw: &mut Lowering, lowest: &[u8], frozen: &mut [bool], seen: &mut HashSet<(Vec<u32>, u32)>) -> usize {
    const MAX_PATH: usize = 48;
    const BUDGET: usize = 20_000;
    let n = lw.insns.len();
    let mut count = 0;
    for m in 0..n {
        let tensor = sp::is_warp_mma(lw.insns[m].opcode.as_str());
        let store = sp::is_store(lw.insns[m].opcode.as_str());
        let reads: Vec<(bool, u16)> = if tensor {
            tensor_reads(&lw.insns[m])
        } else if store {
            crate::sync_class::store_uniform_operands(&lw.insns[m])
        } else {
            sp::src_regs(&lw.insns[m]).into_iter().filter(|(u, k)| *u && *k < 64).collect()
        };
        // (`hold_need`: besides a tensor instruction and a store only a word of the uniform
        // datapath or an `ISETP` holds an operand)
        if reads.is_empty() || !(tensor || store || lw.insns[m].opcode.starts_with('U') || lw.insns[m].opcode == "ISETP") {
            continue;
        }
        let horizon: u32 = if tensor {
            crate::sync_class::MMA_OPERAND_HOLD as u32
        } else if store {
            crate::sync_class::STORE_UNIFORM_OPERAND_HOLD as u32
        } else {
            crate::sync_class::UNIFORM_OPERAND_HOLD as u32
        };
        // depth-first over the paths behind m: (word, lowest sum, sum as it stands, depth of the path)
        let mut path: Vec<u32> = vec![m as u32];
        let mut stack: Vec<(usize, u32, u32, usize)> = Vec::new();
        for &s in &lw.flow.succ[m] {
            stack.push((s, lowest[m] as u32, lw.insns[m].ctrl.stall as u32, 1));
        }
        let mut pushes = stack.len();
        let mut visited: Vec<usize> = Vec::new();
        while let Some((o, low, cur, depth)) = stack.pop() {
            path.truncate(depth);
            if low >= horizon {
                continue; // no lowering brings a writer here inside the hold
            }
            visited.push(o);
            let need = if tensor || store {
                // whatever writes it: a scoreboarded writer may stand closer today and stays where it is
                let w = written(&lw.insns[o]);
                reads.iter().any(|r| w.contains(r)).then_some(horizon)
            } else {
                let w = sp::dest_regs(&lw.insns[o]);
                reads.iter().filter(|r| w.contains(r)).filter_map(|r| crate::sync_class::hold_need(&lw.insns[m], &lw.insns[o], *r)).max().map(|h| h as u32)
            };
            if let Some(h) = need {
                if cur > low && lw.add_span(seen, path.clone(), cur.min(h)) {
                    count += 1;
                }
            }
            if depth >= MAX_PATH || o == m {
                continue;
            }
            path.push(o as u32);
            for &s in &lw.flow.succ[o] {
                stack.push((s, low + lowest[o] as u32, cur + lw.insns[o].ctrl.stall as u32, depth + 1));
                pushes += 1;
            }
            if pushes > BUDGET {
                break;
            }
        }
        if pushes > BUDGET {
            frozen[m] = true;
            for w in visited {
                frozen[w] = true;
            }
        }
    }
    count
}

/// The one distance the scoreboard simulation reads: an overwriter of an address (or atomic
/// data) register of a load that is not served late stands three issue cycles behind it — in
/// text order, and across a resolved backward branch (`sb_step`, `stall_gap`). Every such pair
/// that has the three cycles today keeps them, whether or not the simulation tracks the load.
fn sim_spans(lw: &mut Lowering, lowest: &[u8], seen: &mut HashSet<(Vec<u32>, u32)>) -> usize {
    const LATCH: u32 = 3;
    let n = lw.insns.len();
    let mut count = 0;
    let late_of = |ins: &Instruction| -> Vec<u8> {
        let op = ins.opcode.as_str();
        if !sp::is_long_latency(op) || sp::is_store(op) || sp::is_warp_mma(op) || matches!(op, "LDS" | "LDSM" | "LDL") {
            return Vec::new();
        }
        let mut v = sp::load_addr_gprs(ins);
        for r in sp::atom_data_gprs(ins) {
            if !v.contains(&r) {
                v.push(r);
            }
        }
        v
    };
    let writes = |ins: &Instruction, late: &[u8]| -> bool { sp::dest_regs(ins).into_iter().any(|(u, r)| !u && r < sp::PRED_KEY && late.contains(&(r as u8))) };
    for m in 0..n {
        let late = late_of(&lw.insns[m]);
        if late.is_empty() {
            continue;
        }
        let (mut low, mut cur) = (0u32, 0u32);
        let mut words: Vec<u32> = Vec::new();
        for o in m + 1..n {
            low += lowest[o - 1] as u32;
            cur += lw.insns[o - 1].ctrl.stall as u32;
            words.push((o - 1) as u32);
            if low >= LATCH {
                break;
            }
            if cur >= LATCH && cur > low && writes(&lw.insns[o], &late) && lw.add_span(seen, words.clone(), LATCH) {
                count += 1;
            }
        }
    }
    let (edges, _, _) = sp::resolved_back_edges(lw.insns);
    for (top, back) in edges {
        let (mut tail_low, mut tail_cur) = (0u32, 0u32);
        let mut tail: Vec<u32> = Vec::new();
        for m in (top..=back).rev() {
            tail_low += lowest[m] as u32;
            tail_cur += lw.insns[m].ctrl.stall as u32;
            tail.push(m as u32);
            if tail_low >= LATCH {
                break;
            }
            let late = late_of(&lw.insns[m]);
            if late.is_empty() {
                continue;
            }
            let (mut low, mut cur) = (tail_low, tail_cur);
            let mut words = tail.clone();
            for o in top..m {
                if o > top {
                    low += lowest[o - 1] as u32;
                    cur += lw.insns[o - 1].ctrl.stall as u32;
                    words.push((o - 1) as u32);
                }
                if low >= LATCH {
                    break;
                }
                if cur >= LATCH && cur > low && writes(&lw.insns[o], &late) && lw.add_span(seen, words.clone(), LATCH) {
                    count += 1;
                }
            }
        }
    }
    count
}

/// The pass. `before`: the stalls and yield flags in front of the legaliser; `raised`: the stalls
/// behind it (in front of the operand hold). Runs behind both; see the module text.
pub fn run(insns: &mut [Instruction], t: &ds::DepLatTable, table: Option<&IsaTable>, before: &[Before], raised: &[u8]) -> Report {
    let n = insns.len();
    let mut rep = Report::default();
    if n == 0 || before.len() != n || raised.len() != n {
        return rep;
    }
    let entry: Vec<Before> = snapshot(insns);
    let mut cand: Vec<usize> = (0..n).filter(|&i| !insns[i].hand_sched && insns[i].ctrl.stall > before[i].0).collect();
    rep.candidates = cand.len();
    if cand.is_empty() {
        return rep;
    }
    let sim_before = [sp::sim_counts(insns, table, false), sp::sim_counts(insns, table, true)];
    // the lowest stall a word can end with
    let lowest: Vec<u8> = (0..n).map(|i| if insns[i].hand_sched { insns[i].ctrl.stall } else { before[i].0.min(insns[i].ctrl.stall) }).collect();

    let flow = ds::build_flow(insns);
    let sem = ds::semantics(insns, t);
    let fin = ds::analyse(insns, &flow, &sem).ins;
    let mut needs: Vec<Vec<Req>> = vec![Vec::new(); n];
    for c in 0..n {
        let Some(st) = &fin[c] else { continue };
        let mut v: Vec<Req> = ds::needs_of(insns, &sem, t, c, st, &mut None).into_iter().map(|nd| (nd.key, nd.def as u32, nd.need)).collect();
        v.sort_unstable();
        // one entry per (key, definition): the largest need
        let mut out: Vec<Req> = Vec::with_capacity(v.len());
        for e in v {
            match out.last_mut() {
                Some(l) if (l.0, l.1) == (e.0, e.1) => l.2 = l.2.max(e.2),
                _ => out.push(e),
            }
        }
        needs[c] = out;
    }
    let mut lw = Lowering { insns, flow, sem, fin, needs, rin: vec![Vec::new(); n], spans: Vec::new(), spans_of: vec![Vec::new(); n] };
    // the backward dataflow to its fixed point
    {
        let mut work: VecDeque<usize> = (0..n).rev().collect();
        let mut queued = vec![true; n];
        while let Some(j) = work.pop_front() {
            queued[j] = false;
            let new = lw.req_in(j);
            if new != lw.rin[j] {
                lw.rin[j] = new;
                for k in 0..lw.flow.pred[j].len() {
                    let p = lw.flow.pred[j][k];
                    if !queued[p] {
                        queued[p] = true;
                        work.push_back(p);
                    }
                }
            }
        }
    }
    let mut frozen = vec![false; n];
    let mut seen: HashSet<(Vec<u32>, u32)> = HashSet::new();
    rep.hold_spans = hold_spans(&mut lw, &lowest, &mut frozen, &mut seen);
    rep.sim_spans = sim_spans(&mut lw, &lowest, &mut seen);

    // the words of the smallest loop first, then the text
    let mut rank = vec![usize::MAX; n];
    for u in 0..n {
        for &h in &lw.flow.succ[u] {
            if h <= u {
                for r in rank.iter_mut().take(u + 1).skip(h) {
                    *r = (*r).min(u - h);
                }
            }
        }
    }
    cand.sort_by_key(|&i| (rank[i], i));
    for &i in &cand {
        if frozen[i] {
            continue;
        }
        let to = lw.floor(i).max(before[i].0);
        if to < lw.insns[i].ctrl.stall {
            rep.lowered += 1;
            rep.cycles += (lw.insns[i].ctrl.stall - to) as usize;
            lw.lower(i, to);
        }
    }
    let insns = lw.insns;

    // the yield flag of a lowered word: what the first pass gave the stall it is back at; on a
    // stall that still carries a requirement, the legaliser's rule for a stall it raised
    for i in 0..n {
        let s = insns[i].ctrl.stall;
        if s == entry[i].0 {
            continue;
        }
        let op = insns[i].opcode.as_str();
        let mem_like = sp::is_long_latency(op) || sp::is_store(op) || sp::is_warp_mma(op) || sp::is_control_flow(op) || op == "BAR";
        insns[i].ctrl.yield_flag = if s == before[i].0 {
            before[i].1
        } else if s >= 12 || (s >= 3 && raised[i] > before[i].0 && !mem_like) {
            false
        } else {
            before[i].1
        };
    }

    // the guard: the legaliser and the operand hold have nothing left to raise
    let g = ds::apply(insns, t);
    rep.guard_raised = g.raised;
    rep.guard_cycles = g.added_cycles;
    let (moved, _) = crate::sync_class::hold_operands(insns);
    rep.guard_hold = moved;
    let sim_after = [sp::sim_counts(insns, table, false), sp::sim_counts(insns, table, true)];
    let withdrawn = if !g.unresolved.is_empty() {
        Some(format!("{} requirement(s) the legaliser cannot place again", g.unresolved.len()))
    } else if sim_after != sim_before {
        Some(format!("the scoreboard simulation's counts moved: {:?} -> {:?}", sim_before, sim_after))
    } else {
        None
    };
    if withdrawn.is_some() {
        for (ins, e) in insns.iter_mut().zip(&entry) {
            ins.ctrl.stall = e.0;
            ins.ctrl.yield_flag = e.1;
        }
        rep.withdrawn = withdrawn;
        return rep;
    }
    // what the guard raised is not counted as lowered
    rep.cycles = entry.iter().zip(insns.iter()).map(|(e, x)| e.0.saturating_sub(x.ctrl.stall) as usize).sum();
    rep.lowered = entry.iter().zip(insns.iter()).filter(|(e, x)| x.ctrl.stall < e.0).count();
    rep
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(s: &str, stall: u8, wb: u8, rb: u8, wait: u8) -> Instruction {
        let mut i = crate::parse_sass(s, 0).unwrap();
        i.hand_sched = false;
        i.ctrl.stall = stall;
        i.ctrl.yield_flag = true;
        i.ctrl.write_bar = wb;
        i.ctrl.read_bar = rb;
        i.ctrl.wait_mask = wait;
        i
    }

    /// The words with the stall each had in front of the legaliser; `raised` = the stalls as they stand.
    fn lower(k: &mut [Instruction], before: &[u8]) -> Report {
        let t = ds::DepLatTable::from_json(ds::SM120_TABLE).unwrap();
        let b: Vec<Before> = before.iter().map(|s| (*s, true)).collect();
        let raised: Vec<u8> = k.iter().map(|x| x.ctrl.stall).collect();
        run(k, &t, None, &b, &raised)
    }

    /// Law (d) is kept for every register a tensor instruction reads and for every writer: nothing of the table
    /// spans the `MOV` (its stall was 1 in front of the legaliser), and the word behind it rewrites a register
    /// of the tensor instruction 2 + 9 = 11 issue cycles behind it. The stall goes down to 6 — eight cycles —
    /// for a load (`hold_need` has no rule for it: a load may follow a tensor instruction at once, and this
    /// pass does not move one closer), for a fixed-latency writer, and for a register of the quad that the
    /// scheduler's operand model does not list (the B fragment is a pair there).
    #[test]
    fn a_rewrite_of_a_register_a_tensor_instruction_reads_keeps_eight_cycles_whatever_writes_it() {
        for (writer, wb) in [("LDSM.16.M88.2 R72, [R20+0x40]", 0u8), ("MOV R72, RZ", 7), ("MOV R75, RZ", 7), ("MOV R67, RZ", 7)] {
            let mut k = vec![word("HMMA.16816.F32.BF16 R28, R64, R72, RZ", 2, 7, 7, 0), word("MOV R80, R20", 9, 7, 7, 0), word(writer, 1, wb, 7, 0)];
            let rep = lower(&mut k, &[2, 1, 1]);
            assert_eq!(k.iter().map(|x| x.ctrl.stall).collect::<Vec<_>>(), [2, 6, 1], "{writer}: {rep:?}");
            assert_eq!((rep.candidates, rep.lowered, rep.cycles, rep.hold_spans, rep.guard_raised, rep.guard_hold), (1, 1, 3, 1, 0, 0), "{writer}: {rep:?}");
            assert!(rep.withdrawn.is_none());
        }
        // a word that rewrites nothing the tensor instruction reads: the stall goes back to where it was
        let mut k = vec![word("HMMA.16816.F32.BF16 R28, R64, R72, RZ", 2, 7, 7, 0), word("MOV R80, R20", 9, 7, 7, 0), word("MOV R81, RZ", 1, 7, 7, 0)];
        let rep = lower(&mut k, &[2, 1, 1]);
        assert_eq!(k.iter().map(|x| x.ctrl.stall).collect::<Vec<_>>(), [2, 1, 1], "{rep:?}");
        assert_eq!((rep.lowered, rep.cycles, rep.hold_spans), (1, 8, 0));
        // a rewrite that stands closer than eight today keeps the distance it has, and is not moved away either
        let mut k = vec![word("HMMA.16816.F32.BF16 R28, R64, R72, RZ", 2, 7, 7, 0), word("MOV R80, R20", 3, 7, 7, 0), word("LDSM.16.M88.2 R72, [R20+0x40]", 1, 0, 7, 0)];
        let rep = lower(&mut k, &[2, 1, 1]);
        assert_eq!(k.iter().map(|x| x.ctrl.stall).collect::<Vec<_>>(), [2, 3, 1], "{rep:?}");
        assert_eq!((rep.lowered, rep.hold_spans), (0, 1));
    }

    /// The uniform register of a store's address: a rewrite keeps the seven cycles of the operand hold.
    #[test]
    fn a_rewrite_of_the_uniform_register_of_a_stores_address_keeps_seven_cycles() {
        for store in ["STG.E desc[UR4][R2.64], R5", "STS [UR4+0x10], R5", "STS [R20+UR4+0x20], R5"] {
            let mut k = vec![word(store, 1, 7, 7, 0), word("MOV R80, R20", 9, 7, 7, 0), word("UMOV UR4, 0x400", 1, 7, 7, 0)];
            let rep = lower(&mut k, &[1, 1, 1]);
            assert_eq!(k.iter().map(|x| x.ctrl.stall).collect::<Vec<_>>(), [1, 6, 1], "{store}: {rep:?}");
            assert_eq!((rep.lowered, rep.cycles, rep.hold_spans, rep.guard_hold), (1, 3, 1, 0), "{store}: {rep:?}");
        }
        // another uniform register: nothing holds the stall
        let mut k = vec![word("STG.E desc[UR4][R2.64], R5", 1, 7, 7, 0), word("MOV R80, R20", 9, 7, 7, 0), word("UMOV UR5, 0x400", 1, 7, 7, 0)];
        lower(&mut k, &[1, 1, 1]);
        assert_eq!(k.iter().map(|x| x.ctrl.stall).collect::<Vec<_>>(), [1, 1, 1]);
    }

    /// The one distance the scoreboard simulation reads: the overwriter of a global load's address register
    /// stands 1 + 4 = 5 issue cycles behind the load and does not wait its read barrier — covered by distance
    /// from 3 on. The table asks nothing of the `MOV` between them; its stall goes down to 2, not to 1, and
    /// the simulation's counts are what they were in both views.
    #[test]
    fn the_overwriter_of_a_global_loads_address_keeps_the_three_cycles_the_simulation_counts() {
        let kernel = |s: u8| {
            vec![
                word("LDG.E R4, desc[UR4][R2.64]", 1, 1, 0, 0),
                word("MOV R80, R20", s, 7, 7, 0),
                word("IADD3 R2, PT, PT, R2, 0x4, RZ", 1, 7, 7, 0),
                word("MOV R6, R4", 1, 7, 7, 0b10),
            ]
        };
        assert_eq!(sp::sim_counts(&kernel(4), None, false), [0, 0, 0]);
        assert_eq!(sp::sim_counts(&kernel(2), None, false), [0, 0, 0]);
        assert_eq!(sp::sim_counts(&kernel(1), None, false), [0, 1, 0], "one cycle closer the simulation counts a broken WAR");
        let mut k = kernel(4);
        let rep = lower(&mut k, &[1, 1, 1, 1]);
        assert_eq!(k.iter().map(|x| x.ctrl.stall).collect::<Vec<_>>(), [1, 2, 1, 1], "{rep:?}");
        assert_eq!((rep.lowered, rep.cycles, rep.sim_spans), (1, 2, 1));
        assert!(rep.withdrawn.is_none());
        assert_eq!(sp::sim_counts(&k, None, false), [0, 0, 0]);
        assert_eq!(sp::sim_counts(&k, None, true), sp::sim_counts(&kernel(4), None, true));
    }

    /// A stall the first pass wrote is not touched, and a hand-scheduled word never: only raises are undone.
    #[test]
    fn only_a_raise_is_undone() {
        let mut k = vec![word("MOV R80, R20", 5, 7, 7, 0), word("MOV R81, R20", 5, 7, 7, 0), word("MOV R82, R20", 5, 7, 7, 0)];
        k[2].hand_sched = true;
        let rep = lower(&mut k, &[5, 2, 1]);
        assert_eq!(k.iter().map(|x| x.ctrl.stall).collect::<Vec<_>>(), [5, 2, 5]);
        assert_eq!((rep.candidates, rep.lowered, rep.cycles), (1, 1, 3));
    }
}
