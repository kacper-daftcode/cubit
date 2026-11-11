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
        let mut found: HashMap<usize, u32> = HashMap::new();
        let mut seen: HashSet<(usize, Facts)> = HashSet::new();
        let mut heap: BinaryHeap<Reverse<(u32, usize, Facts)>> = BinaryHeap::new();
        let d0 = self.insns[s].ctrl.stall as u32;
        for (j, f) in self.succ(s, Facts::default(), correlate) {
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
}
