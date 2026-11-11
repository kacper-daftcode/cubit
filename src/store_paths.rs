//! Path-sensitive check of the read barriers of stores — a part of `CUBIT_VERIFY`.
//!
//! A store reads its address and data registers when the memory pipe serves it, not at issue
//! (KNOWN_ISSUES A27: measured on sm_120, no issue distance covers a bare store under load).
//! cubit's rule is therefore: the store holds a read barrier and whoever rewrites one of those
//! registers waits on it first. The scoreboard simulation of `run_verify` cannot check that
//! rule for the stores of a kernel with control flow, for two reasons:
//!
//! * it does not track shared / local stores at all (`STS`, `STL`), and
//! * its loop-carried pass re-walks the TEXT of a loop body from the loop top, so a wait that
//!   sits in a block the last iteration branches around counts as protection. That is how three
//!   `STS.128` of a hand-written production kernel had their data quads rewritten by the next
//!   chunk's `LDSM` 58 / 67 issue cycles later with nobody having waited on their read barriers
//!   while `CUBIT_VERIFY` reported "0 broken WAR" (2026-11-10; the allocator follows the same
//!   text and placed the wait where only the non-final iterations pass).
//!
//! The asynchronous global -> shared copy (`LDGSTS`) is the same case on its address registers:
//! it reads the source address pair when the copy is served. The simulation covers it "by
//! distance" as if it were a global load (three issue cycles), and so passed a schedule that
//! faults on silicon: the vendor's own kernel with the wait on the copy's read barrier dropped
//! from `MOV R61, RZ`, nine instructions behind `LDGSTS ... desc[UR8][R60.64]`, ends in
//! CUDA_ERROR_ILLEGAL_ADDRESS in 3 of 3 processes (2026-11-10).
//!
//! This check walks the control-flow graph instead: from every store — and every `LDGSTS` — that
//! carries a read barrier, along EVERY path (both outcomes of a conditional branch, loops included), up to the
//! first instruction that writes one of the registers the store reads. A path is protected
//! when an instruction on it — at or before the overwriter — waits on the store's read barrier.
//! Every overwriter reached without such a wait is a finding, reported with the smallest issue
//! distance (sum of the stall counts) at which a path reaches it.
//!
//! Predicates are correlated along a path: after `@!P5 BRA` is taken, P5 is known to be false
//! until an instruction writes P5, so a second branch on it has one outcome, and an overwriter
//! guarded by a predicate known to be false does not write. Without that, paths that cannot
//! execute would be reported.
//!
//! A dispatch (`BRX R, base`, `JMX`: the table lives in the constant section, not in the text)
//! is followed into every block that only a register-indirect branch can reach — the blocks no
//! branch names and no fall-through enters (`cfg_flow`) — and into the block behind it. That
//! is a superset of the table: a path that exists is not missed, and a pair may be reported
//! along an edge the table does not have. (Until 2026-11-11 the walk ended at a dispatch, so
//! a store in front of a `BRX` was checked against nothing behind it.)
//!
//! What it does not see: a register neither the scheduler's operand model nor the register
//! allocator's footprints list as written; what lies behind a return or an absolute jump
//! (`RET`, `JMP`: the walk ends there — a return site is not in the text, and "every
//! instruction behind a `CALL`" is a superset that reports pairs no execution has); and a
//! called routine (`CALL`: the walk goes on behind the call, the callee's own writes and waits
//! are not carried to the caller). It is read-only: no schedule changes, and the three
//! counters of `CUBIT_VERIFY` are not touched.

use crate::ir::Instruction;
use crate::scheduling_pass as sp;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};

/// One store → overwriter pair that some path reaches without a wait on the store's read barrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorePathFinding {
    /// index of the store
    pub store: usize,
    /// index of the instruction that rewrites `reg`
    pub overwriter: usize,
    /// the lowest register of the store's that the overwriter writes on that path
    pub reg: u8,
    /// `true`: a data register of the store; `false`: an address register (of a store, or of
    /// an `LDGSTS`: its source address pair or its shared destination base)
    pub data: bool,
    /// the store's read barrier (`None` only in the probe mode: a store without one)
    pub read_bar: Option<u8>,
    /// the smallest issue distance (sum of the stall counts from the store) of such a path
    pub distance: u32,
}

/// P0..P6 carry values; P7 is PT.
const NPRED: u8 = 7;
/// States one (store, register) walk may visit with predicate correlation before it falls back
/// to the walk without it (at most one state per instruction; reports a superset).
const FACT_STATE_BUDGET: usize = 60_000;

/// Predicate values known on a path: from the last conditional branch on the predicate until an
/// instruction writes it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
struct Facts {
    known: u8,
    value: u8,
}

impl Facts {
    fn get(self, n: u8) -> Option<bool> {
        ((self.known >> n) & 1 == 1).then_some((self.value >> n) & 1 == 1)
    }
    fn with(self, n: u8, v: bool) -> Facts {
        Facts { known: self.known | (1 << n), value: (self.value & !(1 << n)) | ((v as u8) << n) }
    }
    fn without(self, mask: u8) -> Facts {
        Facts { known: self.known & !mask, value: self.value & !mask }
    }
}

/// (predicate, the value it must have for the instruction to execute) of a guard on P0..P6.
fn guard_need(ins: &Instruction) -> Option<(u8, bool)> {
    match &ins.guard {
        Some(g) if !g.uniform && g.pred < NPRED => Some((g.pred, !g.negated)),
        _ => None,
    }
}

/// Does the instruction execute on a path with these facts? An unknown predicate may be true.
fn executes(ins: &Instruction, facts: Facts) -> bool {
    match guard_need(ins) {
        Some((n, need)) => facts.get(n).is_none_or(|v| v == need),
        None => true,
    }
}

/// The barriers the instruction waits on: its wait mask, or the scoreboard a `DEPBAR` drains.
fn waits(ins: &Instruction) -> u8 {
    let mut wm = ins.ctrl.wait_mask;
    if ins.opcode == "DEPBAR" {
        if let Some(crate::ir::Operand::Imm32(v)) = ins.operands.first() {
            if (0..sp::NUM_BARRIERS as i64).contains(v) {
                wm |= 1 << *v;
            }
        }
    }
    wm
}

/// The general registers an instruction writes: the scheduler's operand model, and — it lists
/// only the first register of some multi-register results (`LDSM.….4` writes four, `CS2R` a
/// pair) — the footprints of the register allocator's sm_120 target, which were measured.
fn gpr_dests(ins: &Instruction) -> Vec<u8> {
    let mut v: Vec<u8> = sp::dest_regs(ins)
        .into_iter()
        .filter(|(u, r)| !*u && *r < sp::PRED_KEY)
        .map(|(_, r)| r as u8)
        .collect();
    let x = crate::ra_target::target_xfer(crate::ra_target::RaTarget::Sm120, ins);
    if x.known {
        for r in x.rdefs {
            if !v.contains(&r) {
                v.push(r);
            }
        }
    }
    v
}

/// The predicates P0..P6 an instruction writes, as a mask.
fn pred_dests(ins: &Instruction) -> u8 {
    let mut m = 0u8;
    for (u, r) in sp::dest_regs(ins) {
        if !u && (sp::PRED_KEY..sp::PRED_KEY + NPRED as u16).contains(&r) {
            m |= 1 << (r - sp::PRED_KEY);
        }
    }
    m
}

struct Flow<'a> {
    insns: &'a [Instruction],
    addr2idx: HashMap<u32, usize>,
    /// The blocks only a register-indirect branch can reach (`cfg_flow`: no branch names them,
    /// no fall-through enters them) — where a dispatch may continue. Its table is in the
    /// constant section, not in the text, so each of them is a successor of every dispatch.
    indirect: Vec<usize>,
}

impl<'a> Flow<'a> {
    fn new(insns: &'a [Instruction]) -> Self {
        let mut addr2idx = HashMap::new();
        for (i, ins) in insns.iter().enumerate() {
            addr2idx.insert(ins.addr, i);
        }
        let indirect = crate::cfg_flow::Cfg::build(insns).indirect_targets;
        Flow { insns, addr2idx, indirect }
    }

    /// The instructions that can follow `i` on a path with `facts`, each with the facts that hold
    /// there. `correlate == false` forgets the predicates (every conditional branch has both
    /// outcomes).
    fn succ(&self, i: usize, facts: Facts, correlate: bool) -> Vec<(usize, Facts)> {
        let ins = &self.insns[i];
        let facts = facts.without(pred_dests(ins));
        let next = (i + 1 < self.insns.len()).then_some(i + 1);
        let op = ins.opcode.as_str();
        let mut out = Vec::with_capacity(2);
        match op {
            "BRA" | "EXIT" => {
                let target = if op == "BRA" {
                    sp::branch_target(ins).and_then(|t| self.addr2idx.get(&t).copied())
                } else {
                    None
                };
                // a branch on something other than a guard on P0..P6 (a uniform predicate, a
                // predicate or register operand, BRA.DIV / .CONV): both outcomes, nothing learnt
                let other_condition = ins.guard.as_ref().is_some_and(|g| g.uniform)
                    || ins.operands.iter().any(|o| {
                        matches!(
                            o,
                            crate::ir::Operand::Pred { .. }
                                | crate::ir::Operand::UPred { .. }
                                | crate::ir::Operand::Reg { .. }
                                | crate::ir::Operand::UReg { .. }
                        )
                    });
                match guard_need(ins) {
                    Some((n, need)) if correlate && !other_condition => {
                        if facts.get(n).is_none_or(|v| v == need) {
                            out.extend(target.map(|t| (t, facts.with(n, need))));
                        }
                        if facts.get(n).is_none_or(|v| v != need) {
                            out.extend(next.map(|j| (j, facts.with(n, !need))));
                        }
                    }
                    Some(_) => {
                        out.extend(target.map(|t| (t, facts)));
                        out.extend(next.map(|j| (j, facts)));
                    }
                    None if other_condition => {
                        out.extend(target.map(|t| (t, facts)));
                        out.extend(next.map(|j| (j, facts)));
                    }
                    None => {
                        // unconditional: the target only (EXIT: the path ends). `@!PT` never runs.
                        if ins.guard.as_ref().is_some_and(|g| g.pred >= NPRED && g.negated) {
                            out.extend(next.map(|j| (j, facts)));
                        } else {
                            out.extend(target.map(|t| (t, facts)));
                        }
                    }
                }
            }
            // a dispatch through a register: every block only such a branch can reach, and the
            // block behind it (the dispatch base: the first case follows the branch)
            "BRX" | "BRXU" | "JMX" | "JMXU" => {
                out.extend(self.indirect.iter().map(|&t| (t, facts)));
                out.extend(next.map(|j| (j, facts)));
            }
            // a return, a jump to an absolute address: no target in this text, the walk ends here
            "JMP" | "RET" => {}
            _ => out.extend(next.map(|j| (j, facts))),
        }
        out
    }

    /// The overwriters of `reg` reached from store `s` on a path without a wait on one of
    /// `barriers`, each with the smallest issue distance of such a path.
    fn walk(&self, s: usize, reg: u8, barriers: u8, correlate: bool) -> Option<Vec<(usize, u32)>> {
        self.walk_from(s, reg, barriers, correlate, Facts::default())
    }

    /// The overwriters of the source register `reg` of the shuffle `s` reached on a path with
    /// none of the waits that release it. `release` holds the shuffle's own barriers; a younger
    /// shuffle passed on the path adds its write barrier (the unit is served in order: when the
    /// younger result has landed, the older shuffle has read its source). A shuffle that
    /// rewrites the register is no pair and does not end the path. Each with the smallest
    /// issue distance of such a path, and `true` when every such path carries a wait of the
    /// vendor's two further covers — the READ barrier of a younger shuffle, the write barrier
    /// of a younger shared-memory load (`ShuffleSourceFinding::practice`).
    fn walk_shuffle(&self, s: usize, reg: u8, release: u8, correlate: bool, facts: Facts) -> Option<Vec<(usize, u32, bool)>> {
        // per overwriter: (smallest distance, reached on a path with no practice cover either)
        let mut found: HashMap<usize, (u32, bool)> = HashMap::new();
        // state: instruction, predicate facts, releasing barriers, practice barriers, a practice wait passed
        type State = (usize, Facts, u8, u8, bool);
        let mut seen: HashSet<State> = HashSet::new();
        let mut heap: BinaryHeap<Reverse<(u32, State)>> = BinaryHeap::new();
        let d0 = self.insns[s].ctrl.stall as u32;
        for (j, f) in self.succ(s, facts, correlate) {
            heap.push(Reverse((d0, (j, f, release, 0u8, false))));
        }
        while let Some(Reverse((d, state))) = heap.pop() {
            if !seen.insert(state) {
                continue;
            }
            if correlate && seen.len() > FACT_STATE_BUDGET {
                return None;
            }
            let (i, f, rel, soft, hit) = state;
            let ins = &self.insns[i];
            let w = waits(ins);
            if w & rel != 0 {
                continue;
            }
            let hit = hit || w & soft != 0;
            let is_shuffle = ins.opcode == "SHFL";
            if !is_shuffle && executes(ins, f) && gpr_dests(ins).contains(&reg) {
                let e = found.entry(i).or_insert((d, !hit));
                e.0 = e.0.min(d);
                e.1 |= !hit;
                continue;
            }
            // A younger word of the unit that certainly executes on this path. A shuffle — also
            // one that rewrites the register itself: the unit serves the two in order, so it is
            // no pair, and the walk goes on behind it (its write lands late; a fixed-latency
            // word behind it can still overtake both): a wait on its WRITE barrier releases the
            // older one's source too (measured); a wait on its READ barrier, or on the write
            // barrier of a younger shared-memory load, is the vendor's practice.
            let (mut rel2, mut soft2) = (rel, soft);
            if guard_need(ins).is_none_or(|(n, need)| f.get(n) == Some(need)) {
                let bar = |b: u8| if b < sp::NUM_BARRIERS as u8 { 1u8 << b } else { 0 };
                if is_shuffle {
                    rel2 |= bar(ins.ctrl.write_bar);
                    soft2 |= bar(ins.ctrl.read_bar);
                } else if ins.opcode == "LDS" {
                    soft2 |= bar(ins.ctrl.write_bar);
                }
            }
            let d2 = d + ins.ctrl.stall as u32;
            for (j, g) in self.succ(i, f, correlate) {
                let next = (j, g, rel2, soft2 & !rel2, hit);
                if !seen.contains(&next) {
                    heap.push(Reverse((d2, next)));
                }
            }
        }
        let mut v: Vec<(usize, u32, bool)> = found.into_iter().map(|(o, (d, bare))| (o, d, !bare)).collect();
        v.sort();
        Some(v)
    }

    /// [`Flow::walk`] with the predicate values that are known when `s` has executed.
    fn walk_from(&self, s: usize, reg: u8, barriers: u8, correlate: bool, facts: Facts) -> Option<Vec<(usize, u32)>> {
        let mut found: HashMap<usize, u32> = HashMap::new();
        let mut seen: HashSet<(usize, Facts)> = HashSet::new();
        let mut heap: BinaryHeap<Reverse<(u32, usize, Facts)>> = BinaryHeap::new();
        let d0 = self.insns[s].ctrl.stall as u32;
        for (j, f) in self.succ(s, facts, correlate) {
            heap.push(Reverse((d0, j, f)));
        }
        while let Some(Reverse((d, i, f))) = heap.pop() {
            if !seen.insert((i, f)) {
                continue;
            }
            if correlate && seen.len() > FACT_STATE_BUDGET {
                return None;
            }
            let ins = &self.insns[i];
            if waits(ins) & barriers != 0 {
                continue;
            }
            if executes(ins, f) && gpr_dests(ins).contains(&reg) {
                found.entry(i).and_modify(|e| *e = (*e).min(d)).or_insert(d);
                continue;
            }
            let d2 = d + ins.ctrl.stall as u32;
            for (j, g) in self.succ(i, f, correlate) {
                if !seen.contains(&(j, g)) {
                    heap.push(Reverse((d2, j, g)));
                }
            }
        }
        let mut v: Vec<(usize, u32)> = found.into_iter().collect();
        v.sort();
        Some(v)
    }
}

/// The registers an `LDGSTS` reads late: the 64-bit source address pair of its descriptor operand
/// (`desc[URn][Ra.64]` -> Ra, Ra+1) and the base of its shared destination (`[Rb+imm]` -> Rb).
fn copy_addr_gprs(ins: &Instruction) -> (Vec<u8>, Vec<u8>) {
    let (mut global, mut shared) = (Vec::new(), Vec::new());
    for o in &ins.operands {
        match o {
            crate::ir::Operand::Desc { base_reg: Some(b), base_reg_suffix, .. } if *b < 255 => {
                global.push(*b);
                if base_reg_suffix.as_deref().is_some_and(|x| x.contains("64")) && *b < 254 {
                    global.push(*b + 1);
                }
            }
            crate::ir::Operand::Addr { base_reg: Some(b), .. } if *b < 255 => shared.push(*b),
            _ => {}
        }
    }
    (global, shared)
}

/// The store → overwriter pairs of a scheduled kernel that some path of its flow graph reaches
/// without a wait on the store's read barrier, sorted by store. `bare_too`: also the stores
/// that carry no read barrier (every later overwriter of their registers is a finding) — the
/// read-barrier probe's view; without it a store nobody armed is not looked at, as in the
/// scoreboard simulation.
pub fn unwaited_store_overwrites(insns: &[Instruction], bare_too: bool) -> Vec<StorePathFinding> {
    let flow = Flow::new(insns);
    let mut out = Vec::new();
    for (s, ins) in insns.iter().enumerate() {
        let is_copy = ins.opcode == "LDGSTS";
        if !sp::is_store(ins.opcode.as_str()) && !is_copy {
            continue;
        }
        let rb = ins.ctrl.read_bar;
        let read_bar = (rb < sp::NUM_BARRIERS as u8).then_some(rb);
        if read_bar.is_none() && !bare_too {
            continue;
        }
        let barriers = read_bar.map_or(0, |b| 1u8 << b);
        let (addr, data) = if is_copy {
            let (global, shared) = copy_addr_gprs(ins);
            (global.into_iter().chain(shared).collect(), Vec::new())
        } else {
            (sp::store_addr_gprs(ins), sp::store_data_gprs(ins))
        };
        for (is_data, regs) in [(false, &addr), (true, &data)] {
            // per overwriter: the smallest distance, and the lowest register it reaches it with
            let mut found: HashMap<usize, (u32, u8)> = HashMap::new();
            let mut sorted: Vec<u8> = regs.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            for r in sorted {
                let hits = flow
                    .walk(s, r, barriers, true)
                    .or_else(|| flow.walk(s, r, barriers, false))
                    .unwrap_or_default();
                for (o, d) in hits {
                    let e = found.entry(o).or_insert((d, r));
                    if d < e.0 {
                        *e = (d, r);
                    }
                }
            }
            let mut rows: Vec<(usize, (u32, u8))> = found.into_iter().collect();
            rows.sort();
            for (o, (d, r)) in rows {
                out.push(StorePathFinding { store: s, overwriter: o, reg: r, data: is_data, read_bar, distance: d });
            }
        }
    }
    out
}

/// A pair on the ADDRESS register of a shared / local store. `CUBIT_VERIFY` counts these apart:
/// ptxas rewrites the address register of an `STS` that holds a read barrier without waiting on
/// it — 97 pairs in the 166 listings of the sm_120 census, 8 to 24 issue cycles behind the store
/// — and never a data register of any store, nor the address pair of a global one (0 pairs).
pub fn is_shared_store_address(insns: &[Instruction], f: &StorePathFinding) -> bool {
    let ins = &insns[f.store];
    match ins.opcode.as_str() {
        "STS" | "STL" => !f.data,
        // the shared destination base of a copy is the same class; its source pair is not
        "LDGSTS" => copy_addr_gprs(ins).1.contains(&f.reg) && !copy_addr_gprs(ins).0.contains(&f.reg),
        _ => false,
    }
}

/// One line per finding, as `CUBIT_VERIFY` prints it.
pub fn describe(insns: &[Instruction], f: &StorePathFinding) -> String {
    format!(
        "  STORE PATH: insn[{}] {} ({}) {} R{} <- rewritten by insn[{}] {} {} issue cycles later on a path with no wait on {}",
        f.store,
        insns[f.store].opcode_full,
        match f.read_bar {
            Some(b) => format!("read barrier {b}"),
            None => "no read barrier".to_string(),
        },
        if f.data { "data" } else { "address" },
        f.reg,
        f.overwriter,
        insns[f.overwriter].opcode_full,
        f.distance,
        match f.read_bar {
            Some(b) => format!("barrier {b}"),
            None => "anything".to_string(),
        },
    )
}

// ───────────────────────── write after write ─────────────────────────

/// A pending result written again: a producer that carries a write barrier, and an instruction
/// that writes one of its result registers on a path with no wait on that barrier between them.
///
/// The producer's writeback is asynchronous. A second writer of the register that does not wait
/// for it leaves the order of the two writes to the pipes: a fixed-latency word's value can be
/// overwritten by the older result landing behind it, and two results in flight for one
/// register land in whatever order they complete. The vendor's assembler makes the second
/// writer wait on the first's write barrier (the persistent MoE kernel: `[W3] LDC.64 R28,
/// c[0x0][0x388]` … `[B---3--:W1] @P0 LDC.64 R28, c[0x0][0x3b8]`); what it leaves without a
/// wait is a pair of writers under complementary guards — `@P2 LDG … R14` / `@!P2 LDG … R14`,
/// of which one executes — and that is not a pair here either: the walk starts with the
/// producer's guard known to hold, so a writer under the opposite guard does not write until
/// an instruction rewrites the predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewriteFinding {
    /// index of the producer (it carries the write barrier)
    pub producer: usize,
    /// index of the instruction that writes `reg` again
    pub writer: usize,
    /// the lowest result register of the producer that the writer writes on that path
    pub reg: u8,
    /// the producer's write barrier
    pub write_bar: u8,
    /// the writer's own write barrier (`None`: its result is not scoreboarded)
    pub writer_bar: Option<u8>,
    /// the smallest issue distance (sum of the stall counts from the producer) of such a path
    pub distance: u32,
}

/// The producer → second writer pairs of a scheduled kernel: for every instruction that carries
/// a write barrier and writes general registers, the instructions that write one of those
/// registers again on a path of the flow graph with no wait on that barrier (the walk of the
/// stores' read barriers, with the same predicate correlation, dispatches and limits). A
/// producer reached again by its own loop with nobody having waited is a pair with itself.
pub fn unwaited_rewrites(insns: &[Instruction]) -> Vec<RewriteFinding> {
    let flow = Flow::new(insns);
    let mut out = Vec::new();
    for (s, ins) in insns.iter().enumerate() {
        let wb = ins.ctrl.write_bar;
        if wb >= sp::NUM_BARRIERS as u8 {
            continue;
        }
        // the registers whose result is pending: what the instruction writes (`gpr_dests`) —
        // except for an atomic. The certified transfer function takes the first register
        // operand that is not `RZ` as an atomic's destination, so for a form that returns
        // nothing (`ATOMG … PT, RZ, [..], R17`) the DATA register is among its definitions, in
        // the register allocator's footprints and, under `CUBIT_SYNC_CLASSES`, in the
        // scheduler's completed model too; the scheduler's own convention has the family right
        // (BUG-482): the register behind the predicate, at the access width, nothing for `RZ`.
        let mut regs: Vec<u8> = if matches!(ins.opcode.as_str(), "ATOM" | "ATOMG" | "ATOMS") {
            sp::dest_regs_plain(ins)
                .into_iter()
                .filter(|(u, r)| !*u && *r < sp::PRED_KEY)
                .map(|(_, r)| r as u8)
                .collect()
        } else {
            gpr_dests(ins)
        };
        regs.sort_unstable();
        regs.dedup();
        if regs.is_empty() {
            continue;
        }
        // the producer has executed: its guard held
        let start = guard_need(ins).map_or(Facts::default(), |(n, need)| Facts::default().with(n, need));
        let mut found: HashMap<usize, (u32, u8)> = HashMap::new();
        for r in regs {
            let hits = flow
                .walk_from(s, r, 1u8 << wb, true, start)
                .or_else(|| flow.walk_from(s, r, 1u8 << wb, false, start))
                .unwrap_or_default();
            for (o, d) in hits {
                let e = found.entry(o).or_insert((d, r));
                if d < e.0 {
                    *e = (d, r);
                }
            }
        }
        let mut rows: Vec<(usize, (u32, u8))> = found.into_iter().collect();
        rows.sort();
        for (o, (d, r)) in rows {
            let ob = insns[o].ctrl.write_bar;
            out.push(RewriteFinding {
                producer: s,
                writer: o,
                reg: r,
                write_bar: wb,
                writer_bar: (ob < sp::NUM_BARRIERS as u8).then_some(ob),
                distance: d,
            });
        }
    }
    out
}

/// A `SHFL` without a write barrier that writes one register of a shared-memory load in flight.
/// `CUBIT_VERIFY` counts these apart: it is the one shape the vendor's assembler leaves without
/// a wait — 3 pairs in the 166 listings of the sm_120 census, one in each of three kernels of
/// one family: `[W2] LDS.128 R32, [R89+UR5]` and, 4 issue cycles behind it, `SHFL.IDX PT, R35,
/// R25, R23, 0x1f` with no write barrier (two of the three carry no barrier at all, one a read
/// barrier) into the quad's fourth register; nothing between the two names a register of the
/// quad. The vendor's practice; the stall-floor probes of 2026-11-11 measured the shape right
/// from distance 1 on one card model (a shared load and a shuffle are served in order).
/// cubit's allocator never issues a shuffle without a write barrier.
pub fn is_shuffle_into_shared_load(insns: &[Instruction], f: &RewriteFinding) -> bool {
    f.writer_bar.is_none() && insns[f.writer].opcode == "SHFL" && insns[f.producer].opcode == "LDS"
}

/// One line per pair, as `CUBIT_VERIFY` prints it.
pub fn describe_rewrite(insns: &[Instruction], f: &RewriteFinding) -> String {
    format!(
        "  WRITE AFTER WRITE: insn[{}] {} (write barrier {}) R{} <- written again by insn[{}] {} ({}) {} issue cycles later on a path with no wait on barrier {}",
        f.producer,
        insns[f.producer].opcode_full,
        f.write_bar,
        f.reg,
        f.writer,
        insns[f.writer].opcode_full,
        match f.writer_bar {
            Some(b) => format!("write barrier {b}: two results in flight"),
            None => "no write barrier".to_string(),
        },
        f.distance,
        f.write_bar,
    )
}

// ───────────────────────── a shuffle's source ─────────────────────────

/// A source register of a warp shuffle rewritten on a path with none of the waits that release
/// it (KNOWN_ISSUES A34).
///
/// A `SHFL` reads its register operands when its unit serves it, not at issue: an instruction
/// that rewrites one of them without a wait is wrong at every issue distance tried once an SM
/// runs more than one warp — the shuffle takes its source when the stores issued in front of
/// it have been served, so there is no distance to measure. Three waits release the source,
/// each measured right: a wait on the shuffle's read barrier; a wait on its own write barrier
/// (the result has landed, so the operands were read); a wait on the write barrier of a
/// younger shuffle (the unit is served in order). The scoreboard simulation does not model
/// the operand at all — a shuffle has no address — so a schedule that dropped the wait passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShuffleSourceFinding {
    /// index of the shuffle
    pub shuffle: usize,
    /// index of the instruction that rewrites `reg`
    pub overwriter: usize,
    /// the lowest source register of the shuffle that the overwriter writes on that path
    pub reg: u8,
    /// the shuffle's read barrier
    pub read_bar: Option<u8>,
    /// the shuffle's write barrier
    pub write_bar: Option<u8>,
    /// the smallest issue distance (sum of the stall counts from the shuffle) of such a path
    pub distance: u32,
    /// every such path carries a wait of the vendor's two further covers — on the READ barrier
    /// of a younger shuffle or on the write barrier of a younger shared-memory load (the unit
    /// has passed the older shuffle when a younger word of it has been served). The vendor's
    /// practice, not measured as a cover: counted apart
    pub practice: bool,
}

/// The shuffle → overwriter pairs of a scheduled kernel: for every `SHFL`, the instructions
/// that rewrite one of its general-register sources on a path of the flow graph that carries
/// none of the three releasing waits (the walk of the stores' read barriers, with the same
/// predicate correlation, dispatches and limits). An overwriter that is itself a shuffle is no
/// pair: the vendor's assembler chains shuffles through one register 4 cycles apart.
pub fn unwaited_shuffle_sources(insns: &[Instruction]) -> Vec<ShuffleSourceFinding> {
    let flow = Flow::new(insns);
    let mut out = Vec::new();
    for (s, ins) in insns.iter().enumerate() {
        if ins.opcode != "SHFL" {
            continue;
        }
        let bar = |b: u8| (b < sp::NUM_BARRIERS as u8).then_some(b);
        let (read_bar, write_bar) = (bar(ins.ctrl.read_bar), bar(ins.ctrl.write_bar));
        let release = read_bar.map_or(0, |b| 1u8 << b) | write_bar.map_or(0, |b| 1u8 << b);
        let mut regs: Vec<u8> = sp::src_regs(ins)
            .into_iter()
            .filter(|(u, r)| !*u && *r < 255)
            .map(|(_, r)| r as u8)
            .collect();
        regs.sort_unstable();
        regs.dedup();
        // the shuffle has executed: its guard held
        let start = guard_need(ins).map_or(Facts::default(), |(n, need)| Facts::default().with(n, need));
        // per overwriter: the smallest distance with its register, and whether every register's
        // every path is covered by the practice
        let mut found: HashMap<usize, (u32, u8, bool)> = HashMap::new();
        for r in regs {
            let hits = flow
                .walk_shuffle(s, r, release, true, start)
                .or_else(|| flow.walk_shuffle(s, r, release, false, start))
                .unwrap_or_default();
            for (o, d, practice) in hits {
                let e = found.entry(o).or_insert((d, r, practice));
                if d < e.0 {
                    (e.0, e.1) = (d, r);
                }
                e.2 &= practice;
            }
        }
        let mut rows: Vec<(usize, (u32, u8, bool))> = found.into_iter().collect();
        rows.sort();
        for (o, (d, r, practice)) in rows {
            out.push(ShuffleSourceFinding { shuffle: s, overwriter: o, reg: r, read_bar, write_bar, distance: d, practice });
        }
    }
    out
}

/// One line per pair, as `CUBIT_VERIFY` prints it.
pub fn describe_shuffle_source(insns: &[Instruction], f: &ShuffleSourceFinding) -> String {
    let b = |x: Option<u8>| x.map_or("-".to_string(), |v| v.to_string());
    format!(
        "  SHUFFLE SOURCE: insn[{}] {} [R{}:W{}] source R{} <- rewritten by insn[{}] {} {} issue cycles later on a path with none of the waits that release it (the shuffle's read barrier, its write barrier, a younger shuffle's write barrier)",
        f.shuffle,
        insns[f.shuffle].opcode_full,
        b(f.read_bar),
        b(f.write_bar),
        f.reg,
        f.overwriter,
        insns[f.overwriter].opcode_full,
        f.distance,
    )
}

// ───────────────────────── the operand-reuse flags ─────────────────────────

/// The operand slots of an sm_120 word that have an operand-reuse flag, as one word carries
/// them: slots A, B, C = the flag bits 122, 123 and 124. The text shows a set flag as
/// `.reuse` on the operand.
///
/// Which register field feeds which slot is a property of the word's FORM, and the table says it
/// (the `reuse` field of the operand's token): in most forms the register fields at bits 24, 32
/// and 64 feed A, B and C; `FADD` / `FHADD` / `HADD2` / `HSETP2` with two register sources take
/// the second (the field at bit 32) through slot C, and forms whose third text operand is an
/// immediate or a uniform register (`IMAD R, R, R, imm`, `FFMA R, R, R, imm`, `PRMT R, R, R, UR`
/// ...) take the register at bit 64 through slot B. A field whose token has no reuse field in
/// any modifier group of the form is placed by its position (`by_position`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReuseSlots {
    /// the general register in the slot's field (the first one of a wider operand); `None` when
    /// the word's form feeds no general register through the slot
    pub reg: [Option<u8>; 3],
    /// how many registers the word reads through the slot, from `reg` on (1; 2 for a 64-bit
    /// operand or an address pair, 4 for a tensor fragment ...) — [`ReuseSlots::widen`]
    pub width: [u8; 3],
    /// the slot's flag bit
    pub flag: [bool; 3],
    /// the slot holds a uniform register (flags there are not walked: not measured)
    pub uniform: [bool; 3],
    /// the slot was given to the field by its position, not by a reuse field of the table
    pub by_position: [bool; 3],
    /// the word carries the yield flag (without it the flag bits were read as doing nothing — a
    /// reading without a wait — and the vendor's assembler sets none on such a word)
    pub yields: bool,
}

impl ReuseSlots {
    /// Bit position of the register fields that feed the slots where the table has no reuse field.
    pub const SHIFTS: [u32; 3] = [24, 32, 64];
    /// Bit position of the slots' flags.
    pub const FLAG_BITS: [u32; 3] = [122, 123, 124];
    /// The slots' names in the reports.
    pub const NAMES: [char; 3] = ['A', 'B', 'C'];

    /// (bit position of a register field, the slot it feeds) of an instruction key: read from
    /// every modifier group of the key that carries a reuse field — the field layout of a key is
    /// one, a group that never carried a flag in the vendor's text just lacks the field.
    pub fn slots_of_key<'a>(groups: impl Iterator<Item = &'a crate::table::ModGroupEntry>) -> Vec<(u32, usize)> {
        use crate::table::Extraction as E;
        let mut out: Vec<(u32, usize)> = Vec::new();
        for g in groups {
            for f in &g.fields {
                if !matches!(f.extraction, E::Reuse) || !Self::FLAG_BITS.contains(&f.shift) {
                    continue;
                }
                let slot = (f.shift - Self::FLAG_BITS[0]) as usize;
                for r in &g.fields {
                    if r.token_idx == f.token_idx && r.bits == 8 && matches!(r.extraction, E::Reg | E::RegFf | E::UReg | E::URegFf) && !out.contains(&(r.shift, slot)) {
                        out.push((r.shift, slot));
                    }
                }
            }
        }
        out.sort();
        out
    }

    /// The slots of one decoded word; `key_slots` = [`ReuseSlots::slots_of_key`] of its key.
    pub fn of(dec: &crate::decoder::DecodedInst, key_slots: &[(u32, usize)]) -> Self {
        let mut out = ReuseSlots { width: [1; 3], ..ReuseSlots::default() };
        let is_gpr = |e: &str| matches!(e, "reg" | "reg_ff");
        let is_ureg = |e: &str| matches!(e, "ureg" | "ureg_ff");
        let field_at = |shift: u32| dec.fields.iter().find(|f| f.shift == shift && f.bits == 8 && (is_gpr(&f.extraction) || is_ureg(&f.extraction)));
        let mut taken = [false; 3];
        let mut used: Vec<u32> = Vec::new();
        let put = |out: &mut ReuseSlots, slot: usize, f: &crate::decoder::DecodedField, by_position: bool, taken: &mut [bool; 3], used: &mut Vec<u32>| {
            if taken[slot] || used.contains(&f.shift) {
                return;
            }
            taken[slot] = true;
            used.push(f.shift);
            if is_gpr(&f.extraction) {
                out.reg[slot] = Some(f.value as u8);
            } else {
                out.uniform[slot] = true;
            }
            out.by_position[slot] = by_position;
        };
        // the word's own row
        for f in dec.fields.iter().filter(|f| f.extraction == "reuse" && Self::FLAG_BITS.contains(&f.shift)) {
            let slot = (f.shift - Self::FLAG_BITS[0]) as usize;
            if let Some(r) = dec.fields.iter().find(|r| r.token_idx == f.token_idx && r.bits == 8 && (is_gpr(&r.extraction) || is_ureg(&r.extraction))) {
                put(&mut out, slot, r, false, &mut taken, &mut used);
            } else {
                // a flag bit the table gives to a token without a register field (an address): the slot
                // is not the positional field's
                taken[slot] = true;
            }
        }
        // the other modifier groups of its key
        for (shift, slot) in key_slots {
            if let Some(r) = field_at(*shift) {
                put(&mut out, *slot, r, false, &mut taken, &mut used);
            }
        }
        // by position
        for (slot, shift) in Self::SHIFTS.iter().enumerate() {
            if let Some(r) = field_at(*shift) {
                put(&mut out, slot, r, true, &mut taken, &mut used);
            }
        }
        for k in 0..3 {
            out.flag[k] = (dec.raw_code >> Self::FLAG_BITS[k]) & 1 != 0;
        }
        out.yields = dec.ctrl.yield_flag;
        out
    }

    /// The width of the operands: a slot reads its register and every following one the word
    /// reads (the upper half of a 64-bit operand or an address pair, the rest of a tensor
    /// fragment or of a wide store's data) up to the register of another slot.
    pub fn widen(&mut self, ins: &Instruction) {
        let uses = gpr_uses(ins);
        for k in 0..3 {
            let Some(r) = self.reg[k].filter(|r| *r != 255) else { continue };
            let mut w = 1u8;
            while w < 4 {
                let Some(next) = r.checked_add(w).filter(|n| *n != 255) else { break };
                if !uses.contains(&next) || (0..3).any(|j| j != k && self.reg[j] == Some(next)) {
                    break;
                }
                w += 1;
            }
            self.width[k] = w;
        }
    }

    /// Does the word read `reg` through `slot`, and as what: `Some(true)` = as a register of the
    /// operand that starts at `field` (the slot's field names `field`: the same operand as the
    /// flagged word's), `Some(false)` = as a register of another operand that covers it (the
    /// upper half of the pair below it, a later register of a fragment).
    pub fn reads(&self, slot: usize, field: u8, reg: u8) -> Option<bool> {
        let r = self.reg[slot]?;
        if r == 255 || reg < r || reg - r >= self.width[slot].max(1) {
            return None;
        }
        Some(r == field)
    }

    /// The word has a flag bit set at all.
    pub fn any_flag(&self) -> bool {
        self.flag.iter().any(|f| *f)
    }
}

/// The general registers an instruction reads: the scheduler's operand model and the footprints
/// of the register allocator's sm_120 target (the upper half of a 64-bit operand, the address
/// pair, the tuples of a tensor word).
fn gpr_uses(ins: &Instruction) -> Vec<u8> {
    let mut v: Vec<u8> = sp::src_regs(ins).into_iter().filter(|(u, r)| !*u && *r < sp::PRED_KEY).map(|(_, r)| r as u8).collect();
    let x = crate::ra_target::target_xfer(crate::ra_target::RaTarget::Sm120, ins);
    if x.known {
        for r in x.ruses {
            if !v.contains(&r) {
                v.push(r);
            }
        }
    }
    for (u, r) in crate::sync_class::wide_operand_uses(ins).into_iter().chain(crate::sync_class::wide_address_uses(ins)) {
        if !u && r < sp::PRED_KEY && !v.contains(&(r as u8)) {
            v.push(r as u8);
        }
    }
    v
}

/// A register read through a slot WITH the operand-reuse flag and written before the next word
/// that reads it through the same slot — on some path of the flow graph.
///
/// A word that reads register r through a slot with the flag leaves the operand latched for the
/// next word that reads r through that slot: that reader gets the latched value. Measured on
/// sm_120 silicon (the stall-floor probes of 2026-11-11, kind `reuse`, two card models, two
/// clock states): with r written between the two words the reader gets r's OLD content — in
/// every shape with a fixed-latency write, at every distance, also when the write is the flagged
/// word's own or another register passes through the slot in between; the same text without
/// the flag is right. So the law: between a word that reads r through a slot with the flag and
/// the next word that reads r through that slot, r is not written. Clearing a flag is always
/// right.
///
/// The WINDOW of a flag is every path from the flagged word to the next word that reads the
/// register through the slot — with the flag or without: a write behind that reader is outside
/// the window (the form of the vendor's text at most of its flags, and measured right). A
/// branch does not end the window: the probes read "a taken branch ends the entry" as right,
/// but that is a reading without a wait (a trial, not a permission), so a write behind a taken
/// branch is a finding like one on the fall-through ([`ReuseFlagFinding::BRANCH`] says which
/// it is). Nor does the yield flag matter here: a flag on a word without the yield flag was
/// read as doing nothing — a trial again — and is walked like any other.
///
/// `path` says what else the path passed. Two things may end an entry without being the law's
/// "next reader through the slot"; the vendor's own text has a write behind each of them, and
/// neither is the law — a write that only such a path reaches is counted APART, by kind, and
/// is not a finding ([`ReuseFlagFinding::is_finding`]):
/// * [`ReuseFlagFinding::GUARD`] — a word that names the register in the slot under a guard
///   that does not hold on the path (the flagged word itself where its own guard is false).
///   Whether a word that does not execute reads its operands through the slots was not probed;
///   the vendor's text is written as if it did.
/// * [`ReuseFlagFinding::WIDE`] — a word that reads the register through the slot as a register
///   of another operand (`MOV R67, R55.reuse` in front of `IADD.64 R54, R88, R54`, which reads
///   the pair R54:R55 through that slot). Not probed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReuseFlagFinding {
    /// index of the word that reads `reg` through `slot` with the flag
    pub flagged: usize,
    /// 0 / 1 / 2 = slot A / B / C
    pub slot: usize,
    pub reg: u8,
    /// index of the first word on the path that writes `reg` (the flagged word itself when it does)
    pub writer: usize,
    /// index of the next word that reads `reg` through `slot` behind that write
    pub reader: usize,
    /// the smallest issue distance (sum of the stall counts) from the flagged word to the reader
    /// on such a path
    pub distance: u32,
    /// what the cleanest path to this reader passes: [`Self::STRAIGHT`], or a set of
    /// [`Self::BRANCH`] / [`Self::GUARD`] / [`Self::WIDE`]
    pub path: u8,
}

impl ReuseFlagFinding {
    /// Nothing but fall-through words between the flagged word and the reader, every word that
    /// names the register in the slot executes, and both words name the register itself: the
    /// shape the probes measured.
    pub const STRAIGHT: u8 = 0;
    /// The path passes a taken branch (a jump, a dispatch, a call).
    pub const BRANCH: u8 = 1;
    /// The path passes a word that names the register in the slot under a guard that is false,
    /// or may be false, on it.
    pub const GUARD: u8 = 2;
    /// The path passes — or ends at — a word that reads the register through the slot as a
    /// register of ANOTHER operand than the flagged word's (the upper half of the pair below it).
    pub const WIDE: u8 = 4;
    /// The kinds that are counted apart.
    pub const APART: u8 = Self::GUARD | Self::WIDE;

    /// The law's finding (reported), as opposed to the kinds counted apart: a write inside the
    /// window, on the fall-through or behind a taken branch.
    pub fn is_finding(&self) -> bool {
        self.path & Self::APART == 0
    }

    /// The kind of path in the reports: `straight`, `branch`, `guard`, `wide`, or a `+` list.
    pub fn path_name(path: u8) -> String {
        if path == Self::STRAIGHT {
            return "straight".to_string();
        }
        let mut v = Vec::new();
        for (bit, name) in [(Self::BRANCH, "branch"), (Self::GUARD, "guard"), (Self::WIDE, "wide")] {
            if path & bit != 0 {
                v.push(name);
            }
        }
        v.join("+")
    }
}

/// What [`reuse_flag_rewrites`] looked at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReuseFlagCount {
    /// flag bits set on a slot that holds a general register other than `RZ`: the reads the walk
    /// starts from
    pub flags: usize,
    /// words with such a flag
    pub words: usize,
    /// of `flags`: on a word without the yield flag (read as doing nothing there — a reading
    /// without a wait; walked like the others)
    pub without_yield: usize,
    /// flag bits on a slot that holds no register in the word's form, or `RZ` (not walked)
    pub without_register: usize,
    /// flag bits on a slot that holds a uniform register (not measured; not walked)
    pub uniform: usize,
    /// of `flags`: the slot was given to the register field by its position
    pub by_position: usize,
    /// of `flags`: the register is written on no path the walk follows before a reader through
    /// the slot — not inside the window and not behind a guarded-off word or a wider operand
    /// either
    pub clean: usize,
    /// of `flags`: the window ends at a reader through the slot that carries no flag, on some
    /// path (a write behind it is outside the window)
    pub to_unflagged: usize,
    /// of `flags`: some path reaches the end of the kernel without another reader through the slot
    pub to_end: usize,
    /// of `flags`: on some path the next word that reads the register through the slot reads it
    /// as a register of another operand (the upper half of the pair below it), nothing written
    /// in between — the form `MOV R67, R55.reuse` / `IADD.64 R54, R88, R54`
    pub to_wide: usize,
}

/// The order in which the paths to one reader are preferred: (counted apart, the number of kinds
/// on the path, the path, the issue distance, the first writer) — a finding first, then the
/// fewest kinds, then the nearest.
type ReuseRank = (bool, u32, u8, u32, usize);

/// What one walk of a flagged read found.
#[derive(Default)]
struct ReuseWalk {
    /// (reader, the first writer on the path, the smallest issue distance, the path's kind)
    hits: Vec<(usize, usize, u32, u8)>,
    /// some path's next reader through the slot carries no flag
    to_unflagged: bool,
    /// some path's next word that reads the register through the slot reads it as a register of
    /// another operand, with nothing written in between
    to_wide: bool,
    /// some path ends without a reader
    to_end: bool,
}

/// Does the word execute on a path with these facts — (possibly, certainly) — and the predicate
/// P0..P6 its guard reads with the value it needs. A guard on a uniform predicate may hold or
/// not; `@!PT` never does.
fn runs(ins: &Instruction, facts: Facts) -> (bool, bool, Option<(u8, bool)>) {
    match &ins.guard {
        None => (true, true, None),
        Some(g) if g.uniform => (true, false, None),
        Some(g) if g.pred >= NPRED => (!g.negated, !g.negated, None),
        Some(g) => {
            let need = !g.negated;
            (facts.get(g.pred).is_none_or(|v| v == need), facts.get(g.pred) == Some(need), Some((g.pred, need)))
        }
    }
}

impl<'a> Flow<'a> {
    /// From the flagged word `s`, whose operand in `slot` starts at register `field`, along every
    /// path up to the next reader of that operand's register `reg` through `slot` behind a write
    /// of it: one row per such reader and kind of path. A branch does not end the walk; a word of
    /// the slot that does not execute and a wider operand do not end it either — each marks the
    /// path. `kind0` is the kind the walk starts with, `executed` whether the flagged word's own
    /// write happens.
    #[allow(clippy::too_many_arguments)]
    fn walk_reuse(&self, s: usize, slot: usize, field: u8, reg: u8, slots: &[ReuseSlots], correlate: bool, facts: Facts, kind0: u8, executed: bool) -> Option<ReuseWalk> {
        const NONE: usize = usize::MAX;
        const BRANCH: u8 = ReuseFlagFinding::BRANCH;
        const GUARD: u8 = ReuseFlagFinding::GUARD;
        const WIDE: u8 = ReuseFlagFinding::WIDE;
        type Item = (u32, usize, Facts, usize, u8);
        let mut out = ReuseWalk::default();
        let mut found: HashMap<(usize, u8), (u32, usize)> = HashMap::new();
        // state: instruction, predicate facts, the register has been written on the path, the path's kind
        let mut seen: HashSet<(usize, Facts, bool, u8)> = HashSet::new();
        let mut heap: BinaryHeap<Reverse<Item>> = BinaryHeap::new();
        // an edge that is not the fall-through of a word is a taken branch
        let step = |from: usize, to: usize| -> u8 {
            let op = self.insns[from].opcode.as_str();
            let transfer = matches!(op, "BRA" | "BRX" | "BRXU" | "JMX" | "JMXU" | "JMP" | "CALL" | "RET");
            if transfer && (to != from + 1 || op != "BRA") {
                BRANCH
            } else {
                0
            }
        };
        // the flagged word's own write counts: the next reader through the slot gets the value
        // the word read, not the one it wrote
        let w0 = if executed && gpr_dests(&self.insns[s]).contains(&reg) { s } else { NONE };
        let d0 = self.insns[s].ctrl.stall as u32;
        let first = self.succ(s, facts, correlate);
        out.to_end |= first.is_empty();
        for (j, f) in first {
            heap.push(Reverse((d0, j, f, w0, kind0 | step(s, j))));
        }
        while let Some(Reverse((d, i, f, w, kind))) = heap.pop() {
            if !seen.insert((i, f, w != NONE, kind)) {
                continue;
            }
            if correlate && seen.len() > FACT_STATE_BUDGET {
                return None;
            }
            let ins = &self.insns[i];
            let (may, must, pred) = runs(ins, f);
            // the facts behind the word where it ran and where it did not
            let (f_run, f_not) = match pred {
                Some((n, need)) if correlate => (f.with(n, need), f.with(n, !need)),
                _ => (f, f),
            };
            let d2 = d + ins.ctrl.stall as u32;
            let writes = gpr_dests(ins).contains(&reg);
            let mut ended = false;
            let mut push = |heap: &mut BinaryHeap<Reverse<Item>>, facts: Facts, w2: usize, kind2: u8| {
                let next = self.succ(i, facts, correlate);
                ended |= next.is_empty();
                for (j, g) in next {
                    let k = kind2 | step(i, j);
                    if !seen.contains(&(j, g, w2 != NONE, k)) {
                        heap.push(Reverse((d2, j, g, w2, k)));
                    }
                }
            };
            // the first writer on the path behind this word, where the word runs
            let written = if w == NONE && writes { i } else { w };
            match slots[i].reads(slot, field, reg) {
                Some(exact) => {
                    let k2 = if exact { kind } else { kind | WIDE };
                    if may {
                        if w != NONE {
                            // the next reader through the slot behind a write: it gets the old value
                            // (a reader that also writes the register reads first)
                            let e = found.entry((i, k2)).or_insert((d, w));
                            if d < e.0 {
                                *e = (d, w);
                            }
                            if !exact {
                                // a later register of a wider operand: whether such a word takes the
                                // entry is not measured -- the walk goes on, the path is marked
                                push(&mut heap, f_run, written, k2);
                            }
                        } else if !exact {
                            out.to_wide = true;
                            push(&mut heap, f_run, written, k2);
                        } else {
                            // the window ends at this reader, with the flag or without: a write behind
                            // it is outside the window (a flagged reader starts its own)
                            out.to_unflagged |= !slots[i].flag[slot];
                        }
                    }
                    if !must {
                        // under a guard that is false the word does not execute: whether it still
                        // takes the entry is not measured -- the walk goes on, the path is marked
                        push(&mut heap, f_not, w, k2 | GUARD);
                    }
                }
                None if writes && may => {
                    push(&mut heap, f_run, written, kind);
                    if !must {
                        push(&mut heap, f_not, w, kind);
                    }
                }
                None => push(&mut heap, f, w, kind),
            }
            out.to_end |= ended;
        }
        out.hits = found.into_iter().map(|((r, k), (d, w))| (r, w, d, k)).collect();
        out.hits.sort();
        Some(out)
    }
}

/// The operand-reuse flags of a kernel on every path of its flow graph: for every word that
/// reads a register through a slot with the flag, the next words that read that register
/// through the same slot behind a write of it — one row per
/// (flagged read, register, reader), with the cleanest kind of path that reaches it
/// ([`ReuseFlagFinding::path`]; [`ReuseFlagFinding::is_finding`] tells the law's findings from
/// the kinds counted apart). `slots[i]` are the slots of instruction `i` as its final word
/// carries them ([`ReuseSlots::of`], [`ReuseSlots::widen`]). Sorted by the flagged word; with
/// what was looked at.
pub fn reuse_flag_rewrites(insns: &[Instruction], slots: &[ReuseSlots]) -> (Vec<ReuseFlagFinding>, ReuseFlagCount) {
    let mut count = ReuseFlagCount::default();
    let mut out = Vec::new();
    if insns.len() != slots.len() || !slots.iter().any(|s| s.any_flag()) {
        return (out, count);
    }
    let flow = Flow::new(insns);
    for (s, sv) in slots.iter().enumerate() {
        let mut walked = false;
        for slot in 0..3 {
            if !sv.flag[slot] {
                continue;
            }
            if sv.uniform[slot] {
                count.uniform += 1;
                continue;
            }
            let Some(reg) = sv.reg[slot].filter(|r| *r != 255) else {
                count.without_register += 1;
                continue;
            };
            count.flags += 1;
            count.without_yield += !sv.yields as usize;
            count.by_position += sv.by_position[slot] as usize;
            walked = true;
            // the flagged word where its guard held, and -- whether a word that does not execute
            // latches its operand is not measured -- where it did not (counted apart: GUARD)
            let (_, _, pred) = runs(&insns[s], Facts::default());
            let starts: Vec<(Facts, u8, bool)> = match pred {
                Some((n, need)) => vec![(Facts::default().with(n, need), 0, true), (Facts::default().with(n, !need), ReuseFlagFinding::GUARD, false)],
                None => vec![(Facts::default(), 0, true)],
            };
            let (mut to_unflagged, mut to_end, mut to_wide, mut any) = (false, false, false, false);
            // every register of the flagged operand
            for k in 0..sv.width[slot].max(1) {
                let Some(r) = reg.checked_add(k).filter(|r| *r != 255) else { break };
                // per reader the cleanest path: a finding first, else the fewest kinds
                let mut best: HashMap<usize, ReuseRank> = HashMap::new();
                for (n, (start, kind0, executed)) in starts.iter().enumerate() {
                    let walk = flow
                        .walk_reuse(s, slot, reg, r, slots, true, *start, *kind0, *executed)
                        .or_else(|| flow.walk_reuse(s, slot, reg, r, slots, false, *start, *kind0, *executed))
                        .unwrap_or_default();
                    if k == 0 && n == 0 {
                        to_unflagged = walk.to_unflagged;
                        to_end = walk.to_end;
                    }
                    to_wide |= n == 0 && walk.to_wide;
                    for (reader, writer, distance, path) in walk.hits {
                        let rank = (path & ReuseFlagFinding::APART != 0, path.count_ones(), path, distance, writer);
                        let e = best.entry(reader).or_insert(rank);
                        if rank < *e {
                            *e = rank;
                        }
                    }
                }
                let mut rows: Vec<(usize, ReuseRank)> = best.into_iter().collect();
                rows.sort();
                any |= !rows.is_empty();
                for (reader, (_, _, path, distance, writer)) in rows {
                    out.push(ReuseFlagFinding { flagged: s, slot, reg: r, writer, reader, distance, path });
                }
            }
            count.clean += !any as usize;
            count.to_unflagged += to_unflagged as usize;
            count.to_end += to_end as usize;
            count.to_wide += to_wide as usize;
        }
        count.words += walked as usize;
    }
    (out, count)
}

/// One line of the report for a finding of [`reuse_flag_rewrites`].
pub fn describe_reuse(insns: &[Instruction], f: &ReuseFlagFinding) -> String {
    let own = if f.writer == f.flagged { " (the flagged word itself)".to_string() } else { String::new() };
    format!(
        "  REUSE FLAG: insn[{}] {} reads R{} through slot {} with the flag; R{} <- written by insn[{}] {}{} before the next reader through that slot, insn[{}] {}, {} issue cycles behind the flagged word",
        f.flagged,
        insns[f.flagged].opcode_full,
        f.reg,
        ReuseSlots::NAMES[f.slot],
        f.reg,
        f.writer,
        insns[f.writer].opcode_full,
        own,
        f.reader,
        insns[f.reader].opcode_full,
        f.distance
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel(lines: &[&str]) -> Vec<Instruction> {
        let text = format!(".entry k\n{}\n.endentry\n", lines.join("\n"));
        crate::sass_file::parse_sass_file_str(&text).unwrap().kernels.remove(0).instructions
    }

    /// The shape of the production finding: a loop whose top holds the waiter of the store's read
    /// barrier in a block the last iteration branches around.
    const LOOP: &[&str] = &[
        "L_top:",
        "    [B------:R-:W-:-:S02] IADD3 R11, PT, PT, RZ, 0x1, R22 ;",
        "    [B------:R-:W-:-:S01] @!P5 BRA L_last ;",
        "    [B---3--:R-:W1:-:S01] LDS.128 R68, [R80] ;",
        "L_last:",
        "    [B------:R-:W2:-:S03] LDSM.16.M88.4 R68, [R76+0x20] ;",
        "    [B--2---:R-:W-:-:S04] IADD3 R12, PT, PT, RZ, R68, R69 ;",
        "    [B------:R3:W-:-:S05] STS.128 [R84+0xe390], R68 ;",
        "    [B------:R-:W-:-:S06] ISETP.NE.AND P5, PT, R11, R23, PT ;",
        "    [B------:R-:W-:-:S01] @P0 BRA L_top ;",
        "    [B------:R-:W-:-:S01] EXIT ;",
    ];

    #[test]
    fn a_wait_the_last_iteration_branches_around_does_not_protect_the_store() {
        let k = kernel(LOOP);
        // the scoreboard simulation sees nothing: shared stores are not tracked there
        assert_eq!(sp::verify_scoreboard_report(&k, None).war, 0);
        let f = unwaited_store_overwrites(&k, false);
        assert_eq!(f.len(), 1, "{f:?}");
        let f = &f[0];
        assert_eq!((f.store, f.overwriter, f.reg, f.data, f.read_bar), (5, 3, 68, true, Some(3)));
        // STS S05 + ISETP S06 + BRA S01 + IADD3 S02 + the taken branch S01
        assert_eq!(f.distance, 15);
        assert!(describe(&k, f).contains("read barrier 3"));
    }

    #[test]
    fn a_wait_on_every_path_protects_it() {
        // the overwriter itself waits on the barrier
        let mut lines = LOOP.to_vec();
        lines[5] = "    [B---3--:R-:W2:-:S03] LDSM.16.M88.4 R68, [R76+0x20] ;";
        assert!(unwaited_store_overwrites(&kernel(&lines), false).is_empty());
        // the waiter is not branched around
        let mut lines = LOOP.to_vec();
        lines[2] = "    [B------:R-:W-:-:S01] NOP ;";
        assert!(unwaited_store_overwrites(&kernel(&lines), false).is_empty());
        // the loop top itself waits
        let mut lines = LOOP.to_vec();
        lines[1] = "    [B---3--:R-:W-:-:S02] IADD3 R11, PT, PT, RZ, 0x1, R22 ;";
        assert!(unwaited_store_overwrites(&kernel(&lines), false).is_empty());
    }

    #[test]
    fn predicates_are_correlated_along_a_path() {
        // behind the store a branch on P5 is not taken, so P5 is true on that path: the overwriter
        // guarded by @!P5 does not write there, and the next writer of the register waits
        let k = kernel(&[
            "    [B------:R3:W-:-:S01] STS [R84], R68 ;",
            "    [B------:R-:W-:-:S01] @!P5 BRA L_out ;",
            "    [B------:R-:W-:-:S01] @!P5 MOV R68, RZ ;",
            "    [B---3--:R-:W-:-:S01] MOV R68, RZ ;",
            "L_out:",
            "    [B---3--:R-:W-:-:S01] MOV R68, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        assert!(unwaited_store_overwrites(&k, false).is_empty());
        // an unguarded overwriter in its place is a finding, two issue cycles behind the store
        let k = kernel(&[
            "    [B------:R3:W-:-:S01] STS [R84], R68 ;",
            "    [B------:R-:W-:-:S01] @!P5 BRA L_out ;",
            "    [B------:R-:W-:-:S01] MOV R68, RZ ;",
            "L_out:",
            "    [B---3--:R-:W-:-:S01] MOV R68, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        let f = unwaited_store_overwrites(&k, false);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!((f[0].store, f[0].overwriter, f[0].distance), (0, 2, 2));
        // a write of the predicate between the branch and the guarded overwriter forgets it
        let k = kernel(&[
            "    [B------:R3:W-:-:S01] STS [R84], R68 ;",
            "    [B------:R-:W-:-:S01] @!P5 BRA L_out ;",
            "    [B------:R-:W-:-:S01] ISETP.NE.AND P5, PT, R11, R23, PT ;",
            "    [B------:R-:W-:-:S01] @!P5 MOV R68, RZ ;",
            "L_out:",
            "    [B---3--:R-:W-:-:S01] MOV R68, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        let f = unwaited_store_overwrites(&k, false);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!((f[0].store, f[0].overwriter, f[0].distance), (0, 3, 3));
        // two branches on one predicate: the second has the first one's outcome
        let k = kernel(&[
            "    [B------:R3:W-:-:S01] STS [R84], R68 ;",
            "    [B------:R-:W-:-:S01] @P5 BRA L_a ;",
            "    [B---3--:R-:W-:-:S01] NOP ;",
            "L_a:",
            "    [B------:R-:W-:-:S01] @!P5 BRA L_b ;",
            "    [B---3--:R-:W-:-:S01] NOP ;",
            "L_b:",
            "    [B------:R-:W-:-:S01] MOV R68, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        assert!(unwaited_store_overwrites(&k, false).is_empty(), "no path skips both waits");
    }

    #[test]
    fn address_registers_and_stores_without_a_read_barrier() {
        let k = kernel(&[
            "    [B------:R4:W-:-:S01] STG.E desc[UR4][R6.64], R8 ;",
            "    [B------:R-:W-:-:S02] IADD3 R9, PT, PT, RZ, 0x1, R9 ;",
            "    [B------:R-:W-:-:S03] IADD.64 R6, R6, 0x10 ;",
            "    [B------:R-:W-:-:S01] STS [R84], R68 ;",
            "    [B------:R-:W-:-:S01] MOV R68, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        let f = unwaited_store_overwrites(&k, false);
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!((f[0].store, f[0].overwriter, f[0].reg, f[0].data, f[0].distance), (0, 2, 6, false, 3));
        // the probe's view adds the store nobody armed
        let f = unwaited_store_overwrites(&k, true);
        assert_eq!(f.len(), 2, "{f:?}");
        assert_eq!((f[1].store, f[1].overwriter, f[1].read_bar), (3, 4, None));
        // the address register of a shared store is the class `CUBIT_VERIFY` counts apart
        let k = kernel(&[
            "    [B------:R1:W-:-:S01] STS.64 [R48+UR8], R28 ;",
            "    [B------:R-:W-:-:S07] MOV R48, RZ ;",
            "    [B------:R-:W-:-:S01] MOV R28, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        let f = unwaited_store_overwrites(&k, false);
        assert_eq!(f.iter().map(|x| (x.overwriter, x.reg, x.data, x.distance)).collect::<Vec<_>>(), [(1, 48, false, 1), (2, 28, true, 8)]);
        assert!(is_shared_store_address(&k, &f[0]) && !is_shared_store_address(&k, &f[1]));
        let rep = sp::verify_scoreboard_report(&k, None);
        assert_eq!((rep.store_paths, rep.store_paths_shared_addr), (1, 1));
    }

    /// The asynchronous copy: the shape of the candidate that passed every offline check and
    /// faulted on silicon — the upper register of the copy's source address pair rewritten
    /// with the wait on the copy's read barrier dropped.
    #[test]
    fn the_address_pair_of_an_asynchronous_copy_is_read_late() {
        let lines = [
            "    [B------:R1:W-:Y:S01] LDGSTS.E.BYPASS.128 [R77+0x1000], desc[UR8][R60.64], P1 ;",
            "    [B------:R-:W-:Y:S02] IADD.64 R80, R80, UR4 ;",
            "    [B------:R-:W-:Y:S01] MOV R61, RZ ;",
            "    [B------:R-:W-:Y:S01] MOV R77, RZ ;",
            "    [B------:R-:W-:Y:S01] EXIT ;",
        ];
        let k = kernel(&lines);
        // the simulation covers the copy by distance, as if it were a global load
        assert_eq!(sp::verify_scoreboard_report(&k, None).war, 0);
        let f = unwaited_store_overwrites(&k, false);
        assert_eq!(
            f.iter().map(|x| (x.store, x.overwriter, x.reg, x.data, x.read_bar, x.distance)).collect::<Vec<_>>(),
            [(0, 2, 61, false, Some(1), 3), (0, 3, 77, false, Some(1), 4)]
        );
        // the source pair counts; the shared destination base is the class counted apart
        assert!(!is_shared_store_address(&k, &f[0]) && is_shared_store_address(&k, &f[1]));
        let rep = sp::verify_scoreboard_report(&k, None);
        assert_eq!((rep.store_paths, rep.store_paths_shared_addr), (1, 1));
        // with the vendor's wait on the overwriter: clean
        let mut waited = lines;
        waited[2] = "    [B-1----:R-:W-:Y:S01] MOV R61, RZ ;";
        assert!(unwaited_store_overwrites(&kernel(&waited), false).is_empty());
        // the low register of the pair is the same operand
        let mut low = lines;
        low[2] = "    [B------:R-:W-:Y:S01] MOV R60, RZ ;";
        assert_eq!(unwaited_store_overwrites(&kernel(&low), false)[0].reg, 60);
    }

    /// A dispatch as nvcc lays it out: `BRX` through a table in the constant section, the case
    /// blocks behind it, each ending in a branch to the join. The store in front of the dispatch
    /// holds read barrier 3; the second case rewrites its data register and nobody waits.
    const DISPATCH: &[&str] = &[
        "    [B------:R3:W-:-:S01] STS.64 [R84+0x10], R28 ;",
        "    [B------:R-:W-:-:S04] BRX R44 -0x40 ;",
        "    [B------:R-:W-:-:S02] IADD3 R9, PT, PT, RZ, 0x1, R9 ;",
        "    [B------:R-:W-:-:S01] BRA L_join ;",
        "    [B------:R-:W-:-:S03] MOV R28, RZ ;",
        "    [B------:R-:W-:-:S01] BRA L_join ;",
        "    [B------:R-:W-:-:S02] IADD3 R10, PT, PT, RZ, 0x1, R10 ;",
        "L_join:",
        "    [B---3--:R-:W-:-:S01] NOP ;",
        "    [B------:R-:W-:-:S01] MOV R29, RZ ;",
        "    [B------:R-:W-:-:S01] EXIT ;",
    ];

    #[test]
    fn a_dispatch_is_followed_into_every_block_only_it_can_reach() {
        let k = kernel(DISPATCH);
        assert_eq!(crate::cfg_flow::Cfg::build(&k).indirect_targets, vec![2, 4, 6], "the three case blocks: no branch names them");
        // the second case rewrites the store's data register with no wait on barrier 3 on the way:
        // STS S01 + BRX S04 = 5 issue cycles. (The walk used to end at the BRX: no finding.)
        let f = unwaited_store_overwrites(&k, false);
        assert_eq!(f.iter().map(|x| (x.store, x.overwriter, x.reg, x.data, x.read_bar, x.distance)).collect::<Vec<_>>(), [(0, 4, 28, true, Some(3), 5)]);
        let rep = sp::verify_scoreboard_report(&k, None);
        assert_eq!((rep.store_paths, rep.store_paths_shared_addr), (1, 0));
        // the join waits on the barrier: the second register of the pair, rewritten behind it, is safe
        assert!(!f.iter().any(|x| x.overwriter == 8));
    }

    #[test]
    fn a_wait_in_the_case_block_protects_the_store_behind_a_dispatch() {
        // the overwriter itself waits
        let mut lines = DISPATCH.to_vec();
        lines[4] = "    [B---3--:R-:W-:-:S03] MOV R28, RZ ;";
        assert!(unwaited_store_overwrites(&kernel(&lines), false).is_empty());
        // the dispatch waits: every case is behind the wait
        let mut lines = DISPATCH.to_vec();
        lines[1] = "    [B---3--:R-:W-:-:S04] BRX R44 -0x40 ;";
        assert!(unwaited_store_overwrites(&kernel(&lines), false).is_empty());
        // the first case (the block behind the dispatch) is a successor too
        let mut lines = DISPATCH.to_vec();
        lines[2] = "    [B------:R-:W-:-:S02] MOV R29, RZ ;";
        lines[4] = "    [B------:R-:W-:-:S03] NOP ;";
        let f = unwaited_store_overwrites(&kernel(&lines), false);
        assert_eq!(f.iter().map(|x| (x.overwriter, x.reg, x.distance)).collect::<Vec<_>>(), [(2, 29, 5)]);
    }

    /// The limits that stay: the walk ends at a return, and a local store is a store like the
    /// shared one (the scoreboard simulation tracks neither).
    #[test]
    fn a_return_ends_the_walk_and_a_local_store_is_walked() {
        let k = kernel(&[
            "    [B------:R3:W-:-:S01] STS.64 [R84+0x10], R28 ;",
            "    [B------:R-:W-:-:S01] RET.REL.NODEC R152 0x0 ;",
            "    [B------:R-:W-:-:S01] MOV R28, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        assert!(unwaited_store_overwrites(&k, false).is_empty(), "nothing behind a return is on the walk");
        let k = kernel(&[
            "    [B------:R2:W-:-:S01] STL.64 [R1+0x28], R10 ;",
            "    [B------:R-:W-:-:S02] MOV R11, RZ ;",
            "    [B------:R-:W-:-:S01] MOV R1, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        let f = unwaited_store_overwrites(&k, false);
        assert_eq!(f.iter().map(|x| (x.overwriter, x.reg, x.data, x.distance)).collect::<Vec<_>>(), [(2, 1, false, 3), (1, 11, true, 1)]);
        assert!(is_shared_store_address(&k, &f[0]) && !is_shared_store_address(&k, &f[1]));
    }

    // ───────────── write after write ─────────────

    fn rewrites(k: &[Instruction]) -> Vec<(usize, usize, u8, u8, Option<u8>, u32)> {
        unwaited_rewrites(k).iter().map(|x| (x.producer, x.writer, x.reg, x.write_bar, x.writer_bar, x.distance)).collect()
    }

    /// The shape of the persistent MoE kernel as cubit scheduled it until 2026-11-11: two loads of
    /// one constant line into one register on ONE write barrier, the second guarded, no wait
    /// between. (The vendor's schedule of the same words: `[W3]` … `[B---3--:W1]`.)
    const TWO_IN_FLIGHT: &[&str] = &[
        "    [B------:R-:W5:Y:S04] LDC.64 R28, c[0x0][0x388] ;",
        "    [B------:R-:W-:-:S06] ISETP.NE.AND P0, PT, R58, RZ, PT ;",
        "    [B------:R-:W5:Y:S08] @P0 LDC.64 R30, c[0x0][0x3b0] ;",
        "    [B------:R-:W5:Y:S04] @P0 LDC.64 R28, c[0x0][0x3b8] ;",
        "    [B-----5:R-:W-:-:S01] IADD.64 R80, R28, R80 ;",
        "    [B------:R-:W-:-:S01] EXIT ;",
    ];

    #[test]
    fn two_results_in_flight_for_one_register_are_a_pair() {
        let k = kernel(TWO_IN_FLIGHT);
        // the scoreboard simulation drops the pending result silently: nothing in the three counts
        let rep = sp::verify_scoreboard_report(&k, None);
        assert_eq!((rep.raw, rep.war, rep.recycle), (0, 0, 0));
        // LDC.64 S04 + ISETP S06 + LDC.64 S08 = 18 issue cycles; the lower register of the pair
        assert_eq!(rewrites(&k), [(0, 3, 28, 5, Some(5), 18)]);
        assert_eq!((rep.waw, rep.waw_shuffle_into_load), (1, 0));
        let line = describe_rewrite(&k, &unwaited_rewrites(&k)[0]);
        assert!(line.contains("WRITE AFTER WRITE: insn[0] LDC.64 (write barrier 5) R28 <- written again by insn[3] LDC.64 (write barrier 5: two results in flight) 18 issue cycles later"), "{line}");
        // the vendor's form: the second producer waits on the first's barrier
        let mut waited = TWO_IN_FLIGHT.to_vec();
        waited[0] = "    [B------:R-:W3:Y:S04] LDC.64 R28, c[0x0][0x388] ;";
        waited[3] = "    [B---3--:R-:W5:Y:S04] @P0 LDC.64 R28, c[0x0][0x3b8] ;";
        assert!(rewrites(&kernel(&waited)).is_empty());
        assert_eq!(sp::verify_scoreboard_report(&kernel(&waited), None).waw, 0);
    }

    #[test]
    fn writers_under_complementary_guards_are_no_pair() {
        // one of the two executes (the vendor's census: 1 070 such pairs of loads on one barrier)
        let lines = [
            "    [B------:R-:W5:Y:S04] @P2 LDG.E.CONSTANT R14, desc[UR10][R10.64] ;",
            "    [B------:R-:W-:-:S01] NOP ;",
            "    [B------:R-:W5:Y:S01] @!P2 LDG.E.CONSTANT R14, desc[UR10][R8.64] ;",
            "    [B-----5:R-:W-:-:S01] IADD3 R15, PT, PT, R14, 0x1, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ];
        assert!(rewrites(&kernel(&lines)).is_empty());
        // ... until an instruction between them rewrites the predicate: then both may execute
        let mut rewritten = lines;
        rewritten[1] = "    [B------:R-:W-:-:S01] ISETP.NE.AND P2, PT, R4, RZ, PT ;";
        assert_eq!(rewrites(&kernel(&rewritten)), [(0, 2, 14, 5, Some(5), 5)]);
        // the same guard on both, or a guard on the second only: both execute
        let mut same = lines;
        same[2] = "    [B------:R-:W5:Y:S01] @P2 LDG.E.CONSTANT R14, desc[UR10][R8.64] ;";
        assert_eq!(rewrites(&kernel(&same)), [(0, 2, 14, 5, Some(5), 5)]);
    }

    #[test]
    fn a_fixed_latency_writer_of_a_pending_register_is_a_pair_and_a_wait_on_any_path_position_clears_it() {
        let lines = [
            "    [B------:R-:W1:-:S01] LDG.E R4, desc[UR4][R2.64] ;",
            "    [B------:R-:W-:-:S02] IADD3 R5, PT, PT, R6, 0x1, RZ ;",
            "    [B------:R-:W-:-:S01] MOV R4, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ];
        assert_eq!(rewrites(&kernel(&lines)), [(0, 2, 4, 1, None, 3)]);
        // the writer itself waits
        let mut w = lines;
        w[2] = "    [B-1----:R-:W-:-:S01] MOV R4, RZ ;";
        assert!(rewrites(&kernel(&w)).is_empty());
        // an instruction between them waits (a reader of the result, or anything else)
        let mut w = lines;
        w[1] = "    [B-1----:R-:W-:-:S02] IADD3 R5, PT, PT, R4, 0x1, RZ ;";
        assert!(rewrites(&kernel(&w)).is_empty());
    }

    #[test]
    fn the_rewrite_walk_is_path_sensitive_and_a_loop_reaches_the_producer_itself() {
        // the wait stands on one arm only: the pair is reached through the taken branch
        let k = kernel(&[
            "    [B------:R-:W1:-:S01] LDG.E R4, desc[UR4][R2.64] ;",
            "    [B------:R-:W-:-:S01] @P3 BRA L_skip ;",
            "    [B-1----:R-:W-:-:S01] IADD3 R5, PT, PT, R4, 0x1, RZ ;",
            "L_skip:",
            "    [B------:R-:W-:-:S01] MOV R4, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        assert_eq!(rewrites(&k), [(0, 3, 4, 1, None, 2)]);
        // a producer reached again by its own loop with nobody having waited: a pair with itself
        let lines = [
            "L_top:",
            "    [B------:R-:W3:-:S02] LDS R5, [R6] ;",
            "    [B------:R-:W-:-:S01] IADD3 R6, PT, PT, R6, 0x4, RZ ;",
            "    [B------:R-:W-:-:S01] @P0 BRA L_top ;",
            "    [B---3--:R-:W-:-:S01] MOV R7, R5 ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ];
        assert_eq!(rewrites(&kernel(&lines)), [(0, 0, 5, 3, Some(3), 4)]);
        // ... unless it waits on its own barrier before it issues again
        let mut w = lines;
        w[1] = "    [B---3--:R-:W3:-:S02] LDS R5, [R6] ;";
        assert!(rewrites(&kernel(&w)).is_empty());
    }

    #[test]
    fn a_shuffle_without_a_write_barrier_into_a_shared_load_is_counted_apart_and_an_atomic_without_a_result_has_no_pending_register() {
        // the vendor's one unwaited shape (3 in the sm_120 census): a shuffle without a write
        // barrier into the fourth register of a shared-memory quad in flight
        let lines = [
            "    [B------:R-:W2:Y:S01] LDS.128 R32, [R89+UR5] ;",
            "    [B------:R-:W-:Y:S03] MOV R29, RZ ;",
            "    [B------:R-:W-:Y:S01] SHFL.IDX PT, R35, R25, R23, 0x1f ;",
            "    [B--2---:R-:W-:Y:S01] MOV R8, R32 ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ];
        let k = kernel(&lines);
        assert_eq!(rewrites(&k), [(0, 2, 35, 2, None, 4)]);
        assert!(is_shuffle_into_shared_load(&k, &unwaited_rewrites(&k)[0]));
        let rep = sp::verify_scoreboard_report(&k, None);
        assert_eq!((rep.waw, rep.waw_shuffle_into_load), (0, 1));
        // the third census site: the shuffle carries a read barrier, and still no write barrier
        let mut r = lines;
        r[2] = "    [B------:R3:W-:Y:S02] SHFL.IDX PT, R35, R27, R115, 0x1f ;";
        let k = kernel(&r);
        assert!(is_shuffle_into_shared_load(&k, &unwaited_rewrites(&k)[0]));
        // behind a global load the same shuffle is a pair like any other writer
        let mut g = lines;
        g[0] = "    [B------:R-:W2:Y:S01] LDG.E.128 R32, desc[UR4][R2.64] ;";
        let k = kernel(&g);
        assert!(!is_shuffle_into_shared_load(&k, &unwaited_rewrites(&k)[0]));
        let rep = sp::verify_scoreboard_report(&k, None);
        assert_eq!((rep.waw, rep.waw_shuffle_into_load), (1, 0));
        // an atomic that returns nothing (`RZ`) leaves no register pending: its DATA register,
        // which the register allocator's footprint lists as written, may be rewritten at once
        let k = kernel(&[
            "    [B------:R0:W5:Y:S02] ATOMG.E.ADD.S32.STRONG.GPU PT, RZ, desc[UR10][R10.64], R17 ;",
            "    [B------:R-:W-:Y:S01] IADD3 R17, PT, PT, R27, -0x2, RZ ;",
            "    [B------:R-:W-:Y:S01] IADD3 R18, PT, PT, R27, -0x4, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        assert!(rewrites(&k).is_empty());
        // ... and one that returns a register leaves exactly that register pending
        let k = kernel(&[
            "    [B------:R-:W2:Y:S01] ATOMG.E.ADD.S32.STRONG.GPU PT, R9, desc[UR10][R6.64], R11 ;",
            "    [B------:R-:W-:-:S05] IADD3 R10, PT, PT, R3, -0x1, RZ ;",
            "    [B------:R-:W-:-:S01] MOV R9, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        assert_eq!(rewrites(&k), [(0, 2, 9, 2, None, 6)]);
    }

    // ───────────── a shuffle's source ─────────────

    fn shuffles(k: &[Instruction]) -> Vec<(usize, usize, u8, u32)> {
        unwaited_shuffle_sources(k).iter().map(|x| (x.shuffle, x.overwriter, x.reg, x.distance)).collect()
    }

    /// The measured shape: a shuffle, and a fixed-latency word that rewrites its source register
    /// in front of every wait.
    const SHUFFLE: &[&str] = &[
        "    [B------:R2:W1:Y:S04] SHFL.BFLY PT, R23, R13, 0x1, 0x1f ;",
        "    [B------:R-:W-:Y:S06] MOV R13, RZ ;",
        "    [B-1----:R-:W-:Y:S04] IADD3 R5, PT, PT, R23, 0x1, RZ ;",
        "    [B------:R-:W-:-:S01] EXIT ;",
    ];

    #[test]
    fn a_shuffles_source_rewritten_with_no_wait_is_a_pair() {
        let k = kernel(SHUFFLE);
        // the scoreboard simulation does not model the operand: nothing in the three counts
        let rep = sp::verify_scoreboard_report(&k, None);
        assert_eq!((rep.raw, rep.war, rep.recycle), (0, 0, 0));
        assert_eq!(shuffles(&k), [(0, 1, 13, 4)]);
        assert_eq!(rep.shfl_sources, 1);
        let f = &unwaited_shuffle_sources(&k)[0];
        assert_eq!((f.read_bar, f.write_bar), (Some(2), Some(1)));
        let line = describe_shuffle_source(&k, f);
        assert!(line.contains("SHUFFLE SOURCE: insn[0] SHFL.BFLY [R2:W1] source R13 <- rewritten by insn[1] MOV 4 issue cycles later on a path with none of the waits that release it"), "{line}");
        // a read barrier that nobody waits changes nothing, and a shuffle with no barrier at all is the same pair
        for cc in ["B------:R-:W1:Y:S04", "B------:R-:W-:Y:S04"] {
            let mut bare = SHUFFLE.to_vec();
            let first = format!("    [{cc}] SHFL.BFLY PT, R23, R13, 0x1, 0x1f ;");
            bare[0] = &first;
            bare[2] = "    [B------:R-:W-:Y:S04] IADD3 R5, PT, PT, R6, 0x1, RZ ;";
            assert_eq!(shuffles(&kernel(&bare)), [(0, 1, 13, 4)]);
        }
        // a register that is not a source of the shuffle may be rewritten at once: its destination, any other
        let mut other = SHUFFLE.to_vec();
        other[1] = "    [B-1----:R-:W-:Y:S06] MOV R23, RZ ;";
        assert!(shuffles(&kernel(&other)).is_empty());
        // a lane or mask operand in a register is a source like the value
        let k = kernel(&[
            "    [B------:R-:W1:Y:S04] SHFL.IDX PT, R35, R25, R23, 0x1f ;",
            "    [B------:R-:W-:Y:S02] MOV R23, RZ ;",
            "    [B------:R-:W-:Y:S02] MOV R25, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        assert_eq!(shuffles(&k), [(0, 1, 23, 4), (0, 2, 25, 6)]);
    }

    #[test]
    fn each_of_the_three_waits_releases_a_shuffles_source() {
        // (1) the overwriter waits on the shuffle's read barrier
        let mut rb = SHUFFLE.to_vec();
        rb[1] = "    [B--2---:R-:W-:Y:S06] MOV R13, RZ ;";
        assert!(shuffles(&kernel(&rb)).is_empty());
        // (2) a wait on the shuffle's own write barrier stands in front of the overwriter (the result
        // has landed, so the operands were read) -- on a shuffle without a read barrier, and on one
        // that carries a read barrier the overwriter does not wait
        for cc in ["B------:R-:W1:Y:S04", "B------:R2:W1:Y:S04"] {
            let first = format!("    [{cc}] SHFL.BFLY PT, R23, R13, 0x1, 0x1f ;");
            let k = kernel(&[
                &first,
                "    [B-1----:R-:W-:Y:S04] IADD3 R5, PT, PT, R23, 0x1, RZ ;",
                "    [B------:R-:W-:Y:S06] MOV R13, RZ ;",
                "    [B------:R-:W-:-:S01] EXIT ;",
            ]);
            assert!(shuffles(&k).is_empty(), "{cc}");
        }
        // (3) a shuffle with no barrier, a younger shuffle with a write barrier behind it, and the
        // wait on the younger one's barrier in front of the overwriter (the unit is served in order)
        let younger = [
            "    [B------:R-:W-:Y:S01] SHFL.BFLY PT, R23, R13, 0x1, 0x1f ;",
            "    [B------:R-:W3:Y:S04] SHFL.BFLY PT, R24, R14, 0x1, 0x1f ;",
            "    [B---3--:R-:W-:Y:S04] IADD3 R5, PT, PT, R23, R24, RZ ;",
            "    [B------:R-:W-:Y:S06] MOV R13, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ];
        assert!(shuffles(&kernel(&younger)).is_empty());
        // ... without that wait: a pair (the younger shuffle's own source R14 is not rewritten)
        let mut unwaited = younger;
        unwaited[2] = "    [B------:R-:W-:Y:S04] IADD3 R5, PT, PT, R6, 0x1, RZ ;";
        assert_eq!(shuffles(&kernel(&unwaited)), [(0, 3, 13, 9)]);
        // ... and a younger shuffle that may not execute on the path lends no barrier
        let mut guarded = younger;
        guarded[1] = "    [B------:R-:W3:Y:S04] @P0 SHFL.BFLY PT, R24, R14, 0x1, 0x1f ;";
        assert_eq!(shuffles(&kernel(&guarded)), [(0, 3, 13, 9)]);
        // an older shuffle's barrier is not a cover: only a YOUNGER result says the unit has passed
        let k = kernel(&[
            "    [B------:R-:W3:Y:S04] SHFL.BFLY PT, R24, R14, 0x1, 0x1f ;",
            "    [B------:R-:W-:Y:S01] SHFL.BFLY PT, R23, R13, 0x1, 0x1f ;",
            "    [B---3--:R-:W-:Y:S04] IADD3 R5, PT, PT, R24, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S06] MOV R13, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        assert_eq!(shuffles(&k), [(1, 3, 13, 5)]);
    }

    #[test]
    fn a_shuffle_that_rewrites_the_register_is_no_pair_and_the_walk_goes_on_behind_it() {
        // the vendor chains shuffles through one register 4 cycles apart: `SHFL R47 <- R18`, then
        // `SHFL R18 <- R45`. The second is no overwriter to report (one unit, in order) -- but its
        // write lands late, so a fixed-latency word behind it can still overtake both: the walk
        // goes on. Here the `SEL` stands behind a wait on the YOUNGER shuffle's write barrier.
        let lines = [
            "    [B------:R0:W1:Y:S04] SHFL.BFLY PT, R47, R18, 0x1, 0x1f ;",
            "    [B------:R-:W2:Y:S04] SHFL.BFLY PT, R18, R45, 0x1, 0x1f ;",
            "    [B-12---:R-:W-:Y:S02] IADD3 R5, PT, PT, R47, R18, RZ ;",
            "    [B------:R-:W-:Y:S01] SEL R18, R35, R18, !P4 ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ];
        assert!(shuffles(&kernel(&lines)).is_empty());
        // with no wait in front of the `SEL` it is the first fixed-latency overwriter of the older
        // shuffle's source, 10 issue cycles behind it
        let mut bare = lines;
        bare[2] = "    [B------:R-:W-:Y:S02] IADD3 R5, PT, PT, R6, 0x1, RZ ;";
        assert_eq!(shuffles(&kernel(&bare)), [(0, 3, 18, 10)]);
        // a shuffle whose destination is its own source: an overwriter of the result behind the wait
        // on the write barrier is released like any other
        let k = kernel(&[
            "    [B------:R0:W3:Y:S04] SHFL.IDX PT, R22, R22, R20, 0x1f ;",
            "    [B---3--:R-:W-:Y:S01] SEL R22, R35, R22, !P4 ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        assert!(shuffles(&k).is_empty());
    }

    #[test]
    fn the_vendors_two_further_covers_are_counted_apart() {
        let practice = |k: &[Instruction]| -> Vec<(usize, usize, u8, bool)> {
            unwaited_shuffle_sources(k).iter().map(|x| (x.shuffle, x.overwriter, x.reg, x.practice)).collect()
        };
        // several shuffles read one register; only the YOUNGEST carries a read barrier, and the
        // overwriter waits on that one (the vendor's shape: 121 such pairs in the sm_120 census).
        // The unit is served in order, so the older shuffles have read the register too — the
        // vendor's practice, not measured as a cover: a pair counted apart for each older shuffle.
        let lines = [
            "    [B------:R-:W1:Y:S01] SHFL.IDX PT, R7, R22, R36, 0x1f ;",
            "    [B------:R-:W2:Y:S01] SHFL.IDX PT, R3, R51, R36, 0x1f ;",
            "    [B------:R0:W4:Y:S01] SHFL.IDX PT, R5, R37, R36, 0x1f ;",
            "    [B0-----:R-:W-:Y:S01] FMUL.FTZ R36, R25, R34 ;",
            "    [B-12-4-:R-:W-:Y:S01] IADD3 R9, PT, PT, R7, R3, R5 ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ];
        let k = kernel(&lines);
        assert_eq!(practice(&k), [(0, 3, 36, true), (1, 3, 36, true)]);
        let rep = sp::verify_scoreboard_report(&k, None);
        assert_eq!((rep.shfl_sources, rep.shfl_sources_practice), (0, 2));
        // without that wait the three are pairs like any other
        let mut bare = lines;
        bare[3] = "    [B------:R-:W-:Y:S01] FMUL.FTZ R36, R25, R34 ;";
        assert_eq!(practice(&kernel(&bare)), [(0, 3, 36, false), (1, 3, 36, false), (2, 3, 36, false)]);
        // a shuffle with no barrier, a shared-memory load issued behind it, and the wait on that
        // load's write barrier in front of the overwriter (the vendor's shape: 55 such pairs)
        let lines = [
            "    [B------:R-:W-:Y:S01] SHFL.BFLY PT, R93, R92, 0x1, 0x1f ;",
            "    [B------:R-:W0:Y:S04] LDS.U8 R95, [R96+0xa90f] ;",
            "    [B0-----:R-:W-:-:S02] IMAD.SHL.U32 R98, R95, 0x800000, RZ ;",
            "    [B------:R-:W-:Y:S01] MOV R92, R0 ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ];
        assert_eq!(practice(&kernel(&lines)), [(0, 3, 92, true)]);
        // a load of the other memory pipe is no word of the shuffle's unit
        let mut global = lines;
        global[1] = "    [B------:R-:W0:Y:S04] LDG.E.U8 R95, desc[UR4][R96.64] ;";
        assert_eq!(practice(&kernel(&global)), [(0, 3, 92, false)]);
        // ... and a shared load issued IN FRONT of the shuffle says nothing about it
        let k = kernel(&[
            "    [B------:R-:W0:Y:S04] LDS.U8 R95, [R96+0xa90f] ;",
            "    [B------:R-:W-:Y:S01] SHFL.BFLY PT, R93, R92, 0x1, 0x1f ;",
            "    [B0-----:R-:W-:-:S02] IMAD.SHL.U32 R98, R95, 0x800000, RZ ;",
            "    [B------:R-:W-:Y:S01] MOV R92, R0 ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        assert_eq!(practice(&k), [(1, 3, 92, false)]);
    }

    #[test]
    fn the_shuffle_walk_is_path_sensitive() {
        // the releasing wait stands on one arm only: the pair is reached through the taken branch
        let k = kernel(&[
            "    [B------:R2:W1:Y:S04] SHFL.BFLY PT, R23, R13, 0x1, 0x1f ;",
            "    [B------:R-:W-:-:S01] @P3 BRA L_skip ;",
            "    [B-1----:R-:W-:-:S01] IADD3 R5, PT, PT, R23, 0x1, RZ ;",
            "L_skip:",
            "    [B------:R-:W-:-:S01] MOV R13, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        assert_eq!(shuffles(&k), [(0, 3, 13, 5)]);
        // an overwriter under a guard known to be false on the path does not write
        let k = kernel(&[
            "    [B------:R2:W1:Y:S04] SHFL.BFLY PT, R23, R13, 0x1, 0x1f ;",
            "    [B------:R-:W-:-:S01] @!P5 BRA L_out ;",
            "    [B------:R-:W-:-:S01] @!P5 MOV R13, RZ ;",
            "L_out:",
            "    [B--2---:R-:W-:-:S01] MOV R13, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        assert!(shuffles(&k).is_empty());
    }

    // ── the operand-reuse flags ──

    /// The slots of one word for the walk's tests: (slot A, slot B, slot C) registers, the flags.
    fn sl(reg: [Option<u8>; 3], flag: [bool; 3]) -> ReuseSlots {
        ReuseSlots { reg, flag, width: [1; 3], uniform: [false; 3], by_position: [false; 3], yields: true }
    }

    /// The law's findings: (flagged, slot, register, writer, reader, distance) of the straight paths.
    fn reuse(k: &[Instruction], slots: &[ReuseSlots]) -> Vec<(usize, usize, u8, usize, usize, u32)> {
        reuse_flag_rewrites(k, slots).0.iter().filter(|f| f.is_finding()).map(|f| (f.flagged, f.slot, f.reg, f.writer, f.reader, f.distance)).collect()
    }

    /// The findings counted apart: (flagged, writer, reader, distance, path kind).
    fn reuse_apart(k: &[Instruction], slots: &[ReuseSlots]) -> Vec<(usize, usize, usize, u32, u8)> {
        reuse_flag_rewrites(k, slots).0.iter().filter(|f| !f.is_finding()).map(|f| (f.flagged, f.writer, f.reader, f.distance, f.path)).collect()
    }

    const NO: ReuseSlots = ReuseSlots { reg: [None, None, None], flag: [false, false, false], width: [1; 3], uniform: [false; 3], by_position: [false; 3], yields: true };

    #[test]
    fn a_register_written_between_a_flagged_read_and_the_next_reader_through_the_slot_is_reported() {
        let k = kernel(&[
            "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S03] MOV R5, R7 ;",
            "    [B------:R-:W-:Y:S02] IADD3 R8, PT, PT, R5, 0x2, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        let a = |r: u8, f: bool| sl([Some(r), None, None], [f, false, false]);
        // the flag on [0] (R5 through slot A), R5 written by [1], read through slot A by [2]
        let slots = [a(5, true), sl([None, Some(7), None], [false; 3]), a(5, false), NO];
        assert_eq!(reuse(&k, &slots), [(0, 0, 5, 1, 2, 4)]);
        let (f, c) = reuse_flag_rewrites(&k, &slots);
        assert_eq!((c.flags, c.words, c.without_yield, c.without_register), (1, 1, 0, 0));
        assert!(describe_reuse(&k, &f[0]).contains("insn[0] IADD3 reads R5 through slot A with the flag; R5 <- written by insn[1] MOV before the next reader through that slot, insn[2] IADD3, 4 issue cycles"));
        // no flag: nothing is walked, nothing is reported
        let slots = [a(5, false), sl([None, Some(7), None], [false; 3]), a(5, false), NO];
        assert_eq!(reuse_flag_rewrites(&k, &slots), (vec![], ReuseFlagCount::default()));
        // the reader goes through ANOTHER slot: it is not the window's reader, and with no reader
        // through slot A behind the write there is nothing to get the old value
        let slots = [a(5, true), sl([None, Some(7), None], [false; 3]), sl([None, Some(5), None], [false; 3]), NO];
        assert!(reuse(&k, &slots).is_empty());
        // a flag on a word without the yield flag is walked like any other (that it does nothing
        // there is a reading without a wait) and counted; a flag on a slot without a register is
        // not a read: counted, not walked
        let mut off = a(5, true);
        off.yields = false;
        let (f, c) = reuse_flag_rewrites(&k, &[off, sl([None, Some(7), None], [false, false, true]), a(5, false), NO]);
        assert_eq!(f.iter().map(|f| (f.flagged, f.writer, f.reader, f.is_finding())).collect::<Vec<_>>(), [(0, 1, 2, true)]);
        assert_eq!((c.flags, c.words, c.without_yield, c.without_register), (1, 1, 1, 1));
    }

    #[test]
    fn the_window_of_a_reuse_flag_ends_at_the_next_reader_through_the_slot_and_at_nothing_else() {
        let a = |r: u8, f: bool| sl([Some(r), None, None], [f, false, false]);
        // a reader through the slot in front of the write ends the window, with the flag or without:
        // the write behind it is outside the window -- no finding and nothing counted apart
        let k = kernel(&[
            "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S01] IADD3 R8, PT, PT, R5, 0x2, RZ ;",
            "    [B------:R-:W-:Y:S01] MOV R5, R7 ;",
            "    [B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R5, 0x3, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        let unflagged = [a(5, true), a(5, false), sl([None, Some(7), None], [false; 3]), a(5, false), NO];
        assert!(reuse(&k, &unflagged).is_empty() && reuse_apart(&k, &unflagged).is_empty());
        let c = reuse_flag_rewrites(&k, &unflagged).1;
        assert_eq!((c.flags, c.clean, c.to_unflagged), (1, 1, 1));
        // ... unless that reader carries the flag itself: its own window then holds the write
        assert_eq!(reuse(&k, &[a(5, true), a(5, true), sl([None, Some(7), None], [false; 3]), a(5, false), NO]), [(1, 0, 5, 2, 3, 2)]);
        // another register through the slot does not end it; a word that reads the register through
        // the slot AND writes it reads first (the window ends, no finding)
        let k = kernel(&[
            "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S01] IADD3 R8, PT, PT, R4, 0x2, RZ ;",
            "    [B------:R-:W-:Y:S01] MOV R5, R7 ;",
            "    [B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R5, 0x3, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        assert_eq!(reuse(&k, &[a(5, true), a(4, false), sl([None, Some(7), None], [false; 3]), a(5, false), NO]), [(0, 0, 5, 2, 3, 3)]);
        let k = kernel(&[
            "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S01] IADD3 R5, PT, PT, R5, 0x2, RZ ;",
            "    [B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R5, 0x3, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        assert!(reuse(&k, &[a(5, true), a(5, false), a(5, false), NO]).is_empty());
        // the flagged word's own write counts: the next reader through the slot gets what the word read
        let k = kernel(&[
            "    [B------:R-:W-:Y:S02] IADD3 R5, PT, PT, R5, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R5, 0x3, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        assert_eq!(reuse(&k, &[a(5, true), a(5, false), NO]), [(0, 0, 5, 0, 1, 2)]);
    }

    #[test]
    fn the_reuse_walk_follows_every_path_and_says_what_the_path_passes() {
        let a = |r: u8, f: bool| sl([Some(r), None, None], [f, false, false]);
        const BRANCH: u8 = ReuseFlagFinding::BRANCH;
        const GUARD: u8 = ReuseFlagFinding::GUARD;
        // the write stands on the taken path only: a branch does not end the window, the reader
        // behind it is a finding -- its path says that it passes a taken branch (the probes read
        // "a taken branch ends the entry" as right: a trial, not a permission)
        let k = kernel(&[
            "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S05] @P3 BRA L_w ;",
            "    [B------:R-:W-:Y:S01] IADD3 R8, PT, PT, R5, 0x2, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
            "L_w:",
            "    [B------:R-:W-:Y:S01] MOV R5, R7 ;",
            "    [B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R5, 0x3, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        let slots = [a(5, true), NO, a(5, false), NO, sl([None, Some(7), None], [false; 3]), a(5, false), NO];
        assert_eq!(reuse(&k, &slots), [(0, 0, 5, 4, 5, 7)]);
        assert_eq!(reuse_flag_rewrites(&k, &slots).0[0].path, BRANCH);
        assert!(reuse_apart(&k, &slots).is_empty());
        // the write on the fall-through of a branch that is not taken: the straight path, the law's finding
        let k = kernel(&[
            "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S05] @P3 BRA L_w ;",
            "    [B------:R-:W-:Y:S01] MOV R5, R7 ;",
            "    [B------:R-:W-:Y:S01] IADD3 R8, PT, PT, R5, 0x2, RZ ;",
            "L_w:",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        let slots = [a(5, true), NO, sl([None, Some(7), None], [false; 3]), a(5, false), NO];
        assert_eq!(reuse(&k, &slots), [(0, 0, 5, 2, 3, 7)]);
        assert_eq!(reuse_flag_rewrites(&k, &slots).0[0].path, ReuseFlagFinding::STRAIGHT);
        assert!(reuse_apart(&k, &slots).is_empty());
        // a writer under a guard known to be false on the path does not write; under an unknown
        // guard it may: the straight finding
        let k = kernel(&[
            "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S05] @!P5 BRA L_out ;",
            "    [B------:R-:W-:Y:S01] @!P5 MOV R5, R7 ;",
            "L_out:",
            "    [B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R5, 0x3, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        let slots = [a(5, true), NO, sl([None, Some(7), None], [false; 3]), a(5, false), NO];
        assert!(reuse(&k, &slots).is_empty() && reuse_apart(&k, &slots).is_empty());
        let k = kernel(&[
            "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S01] @P2 MOV R5, R7 ;",
            "    [B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R5, 0x3, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        assert_eq!(reuse(&k, &[a(5, true), sl([None, Some(7), None], [false; 3]), a(5, false), NO]), [(0, 0, 5, 1, 2, 2)]);
        // a word that names the register in the slot under a guard that may be false: where it
        // executes it is the reader (the window ends, nothing written yet); where it does not, the
        // walk goes on and the path is marked -- whether such a word takes the entry is not measured
        let k = kernel(&[
            "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S01] @P2 IADD3 R8, PT, PT, R5, 0x2, RZ ;",
            "    [B------:R-:W-:Y:S01] MOV R5, R7 ;",
            "    [B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R5, 0x3, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        let slots = [a(5, true), a(5, false), sl([None, Some(7), None], [false; 3]), a(5, false), NO];
        assert!(reuse(&k, &slots).is_empty());
        assert_eq!(reuse_apart(&k, &slots), [(0, 2, 3, 3, GUARD)]);
        // around a loop: the flagged word of the next pass is the next reader through the slot,
        // behind the taken back edge
        let k = kernel(&[
            "L_top:",
            "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S01] MOV R5, R7 ;",
            "    [B------:R-:W-:Y:S05] @P0 BRA L_top ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        let slots = [a(5, true), sl([None, Some(7), None], [false; 3]), NO, NO];
        assert_eq!(reuse(&k, &slots), [(0, 0, 5, 1, 0, 7)]);
        assert_eq!(reuse_flag_rewrites(&k, &slots).0[0].path, BRANCH);
        // a reader reached both ways is reported by its cleanest path
        let k = kernel(&[
            "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S01] MOV R5, R7 ;",
            "    [B------:R-:W-:Y:S05] @P3 BRA L_r ;",
            "    [B------:R-:W-:Y:S01] MOV R9, R7 ;",
            "L_r:",
            "    [B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R5, 0x3, RZ ;",
            "    [B------:R-:W-:-:S01] EXIT ;",
        ]);
        let m = sl([None, Some(7), None], [false; 3]);
        assert_eq!(reuse(&k, &[a(5, true), m, NO, m, a(5, false), NO]), [(0, 0, 5, 1, 4, 8)]);
        assert!(reuse_apart(&k, &[a(5, true), m, NO, m, a(5, false), NO]).is_empty());
    }
}
