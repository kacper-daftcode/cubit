//! The control-flow graph of a kernel as nvcc lays it out, and the two scoreboard scans on it
//! (`CUBIT_SYNC_CLASSES=1`; used by `scheduling_pass::reallocate_barriers` and by
//! `dep_stall`'s dataflow under the switch).
//!
//! cubit's own kernels are straight-line code with a few loops, every branch target a label
//! below or above it; the allocator's scans walk the text and treat every backward branch as
//! a loop back-edge. A kernel of nvcc is laid out differently:
//!
//! * the slow paths sit behind the last `EXIT` — the suspend loop of an mbarrier wait, the
//!   fallback of a collective region (`WARPSYNC.COLLECTIVE`), a whole warp group's code —
//!   and return with an unconditional backward `BRA`: not a loop;
//! * `BRA.DIV UR, L` / `BRA.CONV` branch only when the warp diverged: the instruction behind
//!   them is the fast path, not dead text (every `shfl.sync` is `BRA.DIV` + `SHFL`);
//! * a dispatch is a register-indirect `BRX R, base` whose table lives in the constant
//!   section: its targets are the blocks no branch names and no fall-through enters;
//! * `WARPSYNC.COLLECTIVE R, addr` continues at `addr` as well.
//!
//! On this graph the scans are plain searches: the first consumers of a pending result on
//! every path, the first overwriters of a late-latched operand on every path, and the set of
//! instructions the barrier is live on (the occupancy the colouring needs — in execution
//! order, not from the setter's text position to the waiter's).
//!
//! Calibration: a path-aware scoreboard check built on the same graph finds 0 unprotected
//! reads in ptxas's own schedules of the served MoE cubin (35 kernels, 128 528 instructions).

use crate::ir::{Instruction, Operand};
use crate::scheduling_pass as sp;
use std::collections::HashMap;

pub struct Cfg {
    pub succ: Vec<Vec<usize>>,
    pub pred: Vec<Vec<usize>>,
    /// first index of the dead tail (the self-branch and the NOPs behind the kernel)
    pub tail: usize,
    /// blocks only a register-indirect branch can reach
    pub indirect_targets: Vec<usize>,
}

fn addr_of(insns: &[Instruction], i: usize) -> u32 {
    if insns[i].addr > 0 || i == 0 {
        insns[i].addr
    } else {
        (i * 16) as u32
    }
}

/// A branch that may fall through.
pub fn is_conditional(ins: &Instruction) -> bool {
    let guarded = ins.guard.as_ref().is_some_and(|g| g.pred < 7);
    let pred_operand = ins.operands.iter().any(|o| matches!(o, Operand::Pred { num, .. } | Operand::UPred { num, .. } if *num < 7));
    let divergence = ins.opcode == "BRA" && (ins.opcode_full.contains(".DIV") || ins.opcode_full.contains(".CONV"));
    guarded || pred_operand || divergence
}

/// The code address a `WARPSYNC.COLLECTIVE R, addr` names.
fn collective_target(ins: &Instruction) -> Option<u32> {
    if ins.opcode != "WARPSYNC" || !ins.opcode_full.contains("COLLECTIVE") {
        return None;
    }
    ins.operands.iter().find_map(|o| match o {
        Operand::BranchTarget(a) => Some(*a),
        Operand::Imm32(v) => Some(*v as u32),
        _ => None,
    })
}

impl Cfg {
    pub fn build(insns: &[Instruction]) -> Cfg {
        let n = insns.len();
        let mut addr2idx: HashMap<u32, usize> = HashMap::new();
        for i in 0..n {
            addr2idx.entry(addr_of(insns, i)).or_insert(i);
        }
        let target_of = |i: usize| -> Option<usize> {
            let ins = &insns[i];
            match ins.opcode.as_str() {
                "BRA" | "JMP" | "CALL" => sp::branch_target(ins).and_then(|t| addr2idx.get(&t).copied()),
                "WARPSYNC" => collective_target(ins).and_then(|t| addr2idx.get(&t).copied()),
                _ => None,
            }
        };
        let mut tail = n;
        while tail > 0 {
            let x = &insns[tail - 1];
            let dead = x.opcode == "NOP" || (x.opcode == "BRA" && x.guard.is_none() && sp::branch_target(x) == Some(addr_of(insns, tail - 1)));
            if !dead {
                break;
            }
            tail -= 1;
        }
        let ends_path = |i: usize| -> bool {
            let ins = &insns[i];
            matches!(ins.opcode.as_str(), "BRA" | "JMP" | "BRX" | "JMX" | "BRXU" | "JMXU" | "EXIT" | "RET") && !is_conditional(ins)
        };
        let mut named = vec![false; n];
        for i in 0..n {
            if let Some(t) = target_of(i) {
                named[t] = true;
            }
            // a reconvergence point is named by its BSSY, and entered by a fall-through or a branch
            if insns[i].opcode == "BSSY" {
                if let Some(t) = sp::branch_target(&insns[i]).and_then(|t| addr2idx.get(&t).copied()) {
                    named[t] = true;
                }
            }
        }
        let indirect_targets: Vec<usize> = (1..tail).filter(|&i| ends_path(i - 1) && !named[i]).collect();
        let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n];
        for i in 0..tail {
            let ins = &insns[i];
            let op = ins.opcode.as_str();
            let fall = i + 1 < n;
            let mut s: Vec<usize> = Vec::new();
            match op {
                "EXIT" | "RET" => {
                    if is_conditional(ins) && fall {
                        s.push(i + 1);
                    }
                }
                "BRA" | "JMP" => match target_of(i) {
                    Some(t) => {
                        s.push(t);
                        if is_conditional(ins) && fall {
                            s.push(i + 1);
                        }
                    }
                    None => {
                        if fall {
                            s.push(i + 1);
                        }
                    }
                },
                "BRX" | "JMX" | "BRXU" | "JMXU" => {
                    s.extend(indirect_targets.iter().copied());
                    if fall {
                        s.push(i + 1); // the dispatch base: the first case block follows the branch
                    }
                }
                _ => {
                    if fall {
                        s.push(i + 1);
                    }
                    if let Some(t) = target_of(i) {
                        s.push(t); // CALL, WARPSYNC.COLLECTIVE
                    }
                }
            }
            s.sort_unstable();
            s.dedup();
            succ[i] = s;
        }
        let mut pred: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, ss) in succ.iter().enumerate() {
            for &t in ss {
                if !pred[t].contains(&i) {
                    pred[t].push(i);
                }
            }
        }
        Cfg { succ, pred, tail, indirect_targets }
    }

    /// The first consumers, on every path behind the producers `setters`, of the pending
    /// registers `dsts`: an instruction that reads one — or overwrites one without reading it
    /// (the producer's writeback is asynchronous) — waits. A path ends at an unguarded waiter
    /// (`settles`: at any waiter), when every register was redefined, or back at a setter.
    /// Returns the waiters and the instructions the barrier is live on (setters and waiters
    /// included).
    pub fn first_consumers(
        &self,
        reads: &[Vec<u16>],
        writes: &[Vec<u16>],
        guarded: &[bool],
        setters: &[usize],
        dsts: &[u16],
        settles: bool,
    ) -> (Vec<usize>, Vec<usize>) {
        let n = self.succ.len();
        let mut waiters: Vec<usize> = Vec::new();
        let mut live_on = vec![false; n];
        for &s in setters {
            live_on[s] = true;
        }
        if dsts.is_empty() || setters.is_empty() {
            return (waiters, setters.to_vec());
        }
        let last = *setters.iter().max().unwrap();
        // explored live sets per instruction: a path arriving with a subset adds nothing
        let mut seen: Vec<Vec<Vec<u16>>> = vec![Vec::new(); n];
        let mut work: Vec<(usize, Vec<u16>)> = self.succ[last].iter().map(|&s| (s, dsts.to_vec())).collect();
        while let Some((j, mut live)) = work.pop() {
            if setters.contains(&j) {
                continue; // the producer issues again: a new instance
            }
            if seen[j].iter().any(|l| live.iter().all(|d| l.contains(d))) {
                continue;
            }
            seen[j].push(live.clone());
            live_on[j] = true;
            let reads_live = reads[j].iter().any(|r| live.contains(r));
            let overwrites_live = writes[j].iter().any(|w| live.contains(w));
            if reads_live || overwrites_live {
                if !waiters.contains(&j) {
                    waiters.push(j);
                }
                if !guarded[j] || settles {
                    continue;
                }
            }
            live.retain(|d| !writes[j].contains(d));
            if live.is_empty() {
                continue;
            }
            for &s in &self.succ[j] {
                work.push((s, live.clone()));
            }
        }
        waiters.sort_unstable();
        let on: Vec<usize> = (0..n).filter(|&i| live_on[i]).collect();
        (waiters, on)
    }

    /// The first overwriters, on every path behind instruction `i`, of its late-latched
    /// operands `opk`. A path ends at an overwriter, at an instruction of `stop_at` (behind it
    /// the operand is released), or back at `i`. `early = Some((dist, can_wait))`: a path that
    /// advanced `dist` instructions without an overwriter waits at its first waitable
    /// instruction (the latch is long released; the barrier does not stay reserved).
    pub fn first_overwriters(
        &self,
        writes: &[Vec<u16>],
        i: usize,
        opk: &[u16],
        stop_at: &[usize],
        early: Option<(usize, &[bool])>,
    ) -> (Vec<usize>, Vec<usize>) {
        let n = self.succ.len();
        let mut waiters: Vec<usize> = Vec::new();
        let mut live_on = vec![false; n];
        live_on[i] = true;
        let mut depth = vec![usize::MAX; n];
        let mut work: std::collections::VecDeque<(usize, usize)> = self.succ[i].iter().map(|&s| (s, 1usize)).collect();
        while let Some((j, d)) = work.pop_front() {
            if j == i || depth[j] <= d {
                continue;
            }
            depth[j] = d;
            live_on[j] = true;
            if writes[j].iter().any(|w| opk.contains(w)) {
                if !waiters.contains(&j) {
                    waiters.push(j);
                }
                continue;
            }
            if stop_at.contains(&j) {
                continue;
            }
            if let Some((dist, can_wait)) = early {
                if d >= dist && can_wait[j] {
                    if !waiters.contains(&j) {
                        waiters.push(j);
                    }
                    continue;
                }
            }
            for &s in &self.succ[j] {
                work.push_back((s, d + 1));
            }
        }
        waiters.sort_unstable();
        // without an overwriter nothing needs the barrier: no occupancy
        let on: Vec<usize> = if waiters.is_empty() { vec![i] } else { (0..n).filter(|&k| live_on[k]).collect() };
        (waiters, on)
    }
}

/// An index set as the runs the colouring iterates (`(first, last)` inclusive).
pub fn runs(on: &[usize]) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    for &i in on {
        match out.last_mut() {
            Some((_, b)) if *b + 1 == i => *b = i,
            _ => out.push((i, i)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel(body: &str) -> Vec<Instruction> {
        let src = format!(".entry t\n    .param u64 io\n{body}.endentry\n");
        crate::sass_file::parse_sass_file_str_strict(&src).unwrap().kernels[0].instructions.clone()
    }

    #[test]
    fn a_divergence_branch_falls_through() {
        let k = kernel("    UMOV UR4, 0xffffffff ;\n    BRA.DIV UR4, L_slow ;\n    SHFL.IDX PT, R8, R4, RZ, 0x1f ;\nL_join:\n    EXIT ;\nL_slow:\n    MOV R8, R4 ;\n    BRA L_join ;\n");
        let c = Cfg::build(&k);
        assert_eq!(c.succ[1], vec![2, 4], "BRA.DIV reaches its target and the instruction behind it");
        assert_eq!(c.succ[5], vec![3], "the slow path returns with an unconditional backward branch");
        assert!(c.indirect_targets.is_empty());
    }

    #[test]
    fn a_register_indirect_branch_reaches_the_unnamed_blocks() {
        let k = kernel("    LDC R50, c[0x2][R20] ;\n    BRX R50 -0x20 ;\nL_a:\n    MOV R1, R2 ;\n    BRA L_j ;\n    MOV R1, R3 ;\n    BRA L_j ;\nL_j:\n    EXIT ;\n");
        let c = Cfg::build(&k);
        assert_eq!(c.indirect_targets, vec![2, 4], "the case blocks: no branch names them, no fall-through enters them");
        assert_eq!(c.succ[1], vec![2, 4]);
        assert_eq!(c.pred[4], vec![1], "the unnamed block is reached from the dispatch only");
    }

    #[test]
    fn the_dead_tail_is_not_code() {
        let k = kernel("    MOV R1, R2 ;\n    EXIT ;\nL_t:\n    BRA L_t ;\n    NOP ;\n    NOP ;\n");
        let c = Cfg::build(&k);
        assert_eq!(c.tail, 2);
        assert!(c.succ[2].is_empty() && c.succ[1].is_empty());
    }

    #[test]
    fn first_consumers_follow_the_paths() {
        // R4 is produced at 0; the fast path reads it at 3, the slow path at 6
        let k = kernel("    LDG.E R4, desc[UR8][R2.64] ;\n    UMOV UR4, 0xffffffff ;\n    BRA.DIV UR4, L_slow ;\n    SHFL.IDX PT, R8, R4, RZ, 0x1f ;\nL_join:\n    MOV R9, R8 ;\n    EXIT ;\nL_slow:\n    MOV R8, R4 ;\n    BRA L_join ;\n");
        let c = Cfg::build(&k);
        let rk = |u: bool, r: u16| -> u16 { ((u as u16) << 9) | r };
        let reads: Vec<Vec<u16>> = k.iter().map(|x| sp::src_regs(x).into_iter().map(|(u, r)| rk(u, r)).collect()).collect();
        let writes: Vec<Vec<u16>> = k.iter().map(|x| sp::dest_regs(x).into_iter().map(|(u, r)| rk(u, r)).collect()).collect();
        let guarded = vec![false; k.len()];
        let (w, on) = c.first_consumers(&reads, &writes, &guarded, &[0], &[4], false);
        assert_eq!(w, vec![3, 6]);
        assert_eq!(on, vec![0, 1, 2, 3, 6]);
        assert_eq!(runs(&on), vec![(0, 3), (6, 6)]);
    }
}
