//! `CUBIT_VERIFY` (read-only, sm_120): the two laws of a tensor instruction that no scoreboard
//! carries and no cell of the dependency table prices, read off the schedule as it is written —
//! whoever wrote it (KNOWN_ISSUES A66).
//!
//! * **The source hold.** A tensor instruction (`HMMA`, `QMMA`, `IMMA`, `DMMA`) reads its general
//!   source registers over [`SOURCE_HOLD`] issue cycles behind its own issue: the A fragment
//!   (operand 1, four registers), the B fragment (operand 2, two), the accumulate (operand 3,
//!   four) and each further register operand (the scale registers of `QMMA.SF`, one each). A
//!   fixed-latency word that rewrites one of them closer than that changes what the tensor
//!   instruction computes (silicon: a rewrite 2 and 4 cycles behind a `QMMA` gave wrong bits, 6
//!   identical ones; the vendor's assembler keeps 8). A word whose result lands late — a load and
//!   the other variable-latency classes of the dependency table, a synchronisation word — may
//!   follow at once, and the next tensor instruction is the tensor pipe's own spacing: both are
//!   counted beside the sites, not among them.
//! * **The landing in front of a branch.** A tensor instruction stands at least
//!   [`BRANCH_LANDING`] issue cycles in front of a `BRA` — guarded, on a uniform predicate, on
//!   divergence or plain (the vendor's assembler: never closer, in every form of the word).
//!
//! **Why a check of its own.** The passes that enforce the two — `sync_class::hold_operands` and
//! the landing rows of `dep_stall` — each decide by a class of their own which writer and which
//! branch a law binds, and a form such a class leaves out is left out silently: `CS2R`, a
//! fixed-latency word that never carries a write barrier, stood in the list of slow writers, and
//! the landing row knew the conditional branch alone. The scoreboard simulation, the audit
//! (`CUBIT_HAZ`) and the table's check (`CUBIT_DEP_VERIFY`) read neither distance — the first two
//! see barriers and waits, the third the requirements the legaliser itself derives. This walk
//! asks neither pass. It reads the operands of the words, the stalls as written and the flow
//! graph of the kernel (`cfg_flow`), and names every place below a law's number: in a schedule of
//! cubit, in a hand-scheduled text and in the vendor's alike.
//!
//! A distance is the smallest sum of the stall fields from the tensor instruction (its own
//! included) to the other word (its own not included) over the paths of the flow graph; the walk
//! never passes the tensor instruction a second time. Only general registers are judged: the
//! uniform operand of a tensor instruction is rewritten one and two cycles behind it in the
//! vendor's schedules and has no measured hold.

use crate::dep_stall::DepLatTable;
use crate::ir::{Instruction, Operand};
use crate::scheduling_pass as sp;
use std::collections::HashMap;

/// The source hold of a tensor instruction, in issue cycles (`sync_class::MMA_OPERAND_HOLD`).
pub const SOURCE_HOLD: u32 = crate::sync_class::MMA_OPERAND_HOLD as u32;
/// The distance of a tensor instruction in front of a `BRA` (`sync_class::MMA_BRANCH_LANDING`).
pub const BRANCH_LANDING: u32 = crate::sync_class::MMA_BRANCH_LANDING as u32;

/// Which law a site stands below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Law {
    /// a source register rewritten by a fixed-latency word inside the hold
    Hold,
    /// a `BRA` inside the landing distance
    Landing,
}

/// One place below a law's number.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Site {
    pub law: Law,
    /// index of the tensor instruction
    pub tensor: usize,
    /// index of the overwriter (`Hold`) or of the branch (`Landing`)
    pub at: usize,
    /// the rewritten general register (`Hold`)
    pub reg: Option<u8>,
    /// the operand of the tensor instruction the register belongs to: 1 = A, 2 = B, 3 = the
    /// accumulate, 4 and more = a further register operand (`Hold`)
    pub operand: usize,
    /// issue cycles between the two words on the shortest path
    pub have: u32,
    /// the law's number
    pub need: u32,
}

/// What the walk found in one kernel.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// the places below a law, in text order of the tensor instruction
    pub sites: Vec<Site>,
    /// tensor instructions walked
    pub tensors: usize,
    /// rewrites inside the hold by a word whose result lands late (no sites)
    pub late_landing: usize,
    /// rewrites inside the hold by the next tensor instruction (no sites)
    pub next_tensor: usize,
}

impl Report {
    /// The sites of one law.
    pub fn count(&self, law: Law) -> usize {
        self.sites.iter().filter(|s| s.law == law).count()
    }
}

/// The general registers a tensor instruction reads, each with the index of its operand: A four
/// registers, B two, the accumulate four, every further register operand one.
pub fn tensor_sources(ins: &Instruction) -> Vec<(u8, usize)> {
    let mut out: Vec<(u8, usize)> = Vec::new();
    for (i, o) in ins.operands.iter().enumerate().skip(1) {
        let Operand::Reg { num, .. } = o else { continue };
        let width: u16 = match i {
            1 | 3 => 4,
            2 => 2,
            _ => 1,
        };
        for r in 0..width {
            let k = *num as u16 + r;
            if k < 255 && !out.iter().any(|(q, _)| *q as u16 == k) {
                out.push((k as u8, i));
            }
        }
    }
    out
}

/// The general registers a word writes: the scheduler's convention and the footprints of the
/// register allocator's sm_120 target (a pair for a 64-bit result, a quad for `LDSM.….4`).
fn written(ins: &Instruction) -> Vec<u8> {
    let mut v: Vec<u8> = sp::dest_regs(ins).into_iter().filter(|(u, k)| !*u && *k < 255).map(|(_, k)| k as u8).collect();
    let x = crate::ra_target::target_xfer(crate::ra_target::RaTarget::Sm120, ins);
    if x.known {
        for r in x.rdefs {
            if r < 255 && !v.contains(&r) {
                v.push(r);
            }
        }
    }
    v
}

/// A word whose result lands late: a variable-latency class of the table, one of the scoreboard
/// results the table does not list, a synchronisation word.
fn lands_late(ins: &Instruction, t: &DepLatTable) -> bool {
    t.is_variable(ins) || crate::sync_class::unlisted_scoreboard_result(ins.opcode.as_str()) || crate::sync_class::classify(ins).is_some()
}

/// The words behind `m` on the paths of the flow graph that stand closer than `limit` issue
/// cycles behind it, each with its smallest distance.
fn behind(insns: &[Instruction], succ: &[Vec<usize>], m: usize, limit: u32) -> HashMap<usize, u32> {
    let mut best: HashMap<usize, u32> = HashMap::new();
    let mut stack: Vec<(u32, usize)> = succ[m].iter().map(|&v| (insns[m].ctrl.stall as u32, v)).collect();
    while let Some((d, v)) = stack.pop() {
        if d >= limit || v == m || best.get(&v).is_some_and(|b| *b <= d) {
            continue;
        }
        best.insert(v, d);
        for &w in &succ[v] {
            stack.push((d + insns[v].ctrl.stall as u32, w));
        }
    }
    best
}

/// Every place of `insns` below one of the two laws. `t` names the variable-latency classes.
pub fn check(insns: &[Instruction], t: &DepLatTable) -> Report {
    let mut rep = Report::default();
    if !insns.iter().any(|x| sp::is_warp_mma(x.opcode.as_str())) {
        return rep;
    }
    let cfg = crate::cfg_flow::Cfg::build(insns);
    // the nearest tensor instruction in front of each branch that stands inside the landing distance
    let mut landing: HashMap<usize, (u32, usize)> = HashMap::new();
    for m in 0..insns.len() {
        if !sp::is_warp_mma(insns[m].opcode.as_str()) {
            continue;
        }
        rep.tensors += 1;
        let sources = tensor_sources(&insns[m]);
        for (v, d) in behind(insns, &cfg.succ, m, SOURCE_HOLD.max(BRANCH_LANDING)) {
            let w = &insns[v];
            if w.opcode == "BRA" && d < BRANCH_LANDING && landing.get(&v).is_none_or(|(have, _)| d < *have) {
                landing.insert(v, (d, m));
            }
            if d >= SOURCE_HOLD {
                continue;
            }
            for r in written(w) {
                let Some((_, operand)) = sources.iter().find(|(q, _)| *q == r) else { continue };
                if sp::is_warp_mma(w.opcode.as_str()) {
                    rep.next_tensor += 1;
                } else if lands_late(w, t) {
                    rep.late_landing += 1;
                } else {
                    rep.sites.push(Site { law: Law::Hold, tensor: m, at: v, reg: Some(r), operand: *operand, have: d, need: SOURCE_HOLD });
                }
            }
        }
    }
    for (b, (d, m)) in landing {
        rep.sites.push(Site { law: Law::Landing, tensor: m, at: b, reg: None, operand: 0, have: d, need: BRANCH_LANDING });
    }
    rep.sites.sort();
    rep
}

/// One line for a site.
pub fn describe(insns: &[Instruction], s: &Site) -> String {
    let text = |i: usize| insns[i].raw_text.trim().trim_end_matches(';').trim().to_string();
    match s.law {
        Law::Hold => {
            let operand = match s.operand {
                1 => "its A fragment".to_string(),
                2 => "its B fragment".to_string(),
                3 => "its accumulate".to_string(),
                n => format!("its operand {n}"),
            };
            format!(
                "  TENSOR HOLD: insn[{}] {} rewrites R{} {} issue cycle(s) behind insn[{}] {} that reads it ({}) -- a fixed-latency rewrite of a tensor instruction's source keeps {}",
                s.at,
                text(s.at),
                s.reg.unwrap_or(255),
                s.have,
                s.tensor,
                insns[s.tensor].opcode_full,
                operand,
                s.need
            )
        }
        Law::Landing => format!(
            "  TENSOR LANDING: insn[{}] {} stands {} issue cycle(s) behind insn[{}] {} -- a tensor instruction keeps {} in front of a branch",
            s.at,
            text(s.at),
            s.have,
            s.tensor,
            insns[s.tensor].opcode_full,
            s.need
        ),
    }
}

/// The count line of a kernel with tensor instructions.
pub fn summary(rep: &Report) -> String {
    format!(
        "CUBIT_VERIFY_TENSOR: {} source register(s) of a tensor instruction rewritten by a fixed-latency word closer than {} issue cycles behind it, {} branch(es) closer than {} behind a tensor instruction ({} tensor instructions walked; inside the hold and no finding: {} rewrite(s) by a word whose result lands late, {} by the next tensor instruction); not in the counts above",
        rep.count(Law::Hold),
        SOURCE_HOLD,
        rep.count(Law::Landing),
        BRANCH_LANDING,
        rep.tensors,
        rep.late_landing,
        rep.next_tensor
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The words of a kernel, 16 bytes apart, each with its stall; a branch names a code address.
    fn kernel(words: &[(&str, u8)]) -> Vec<Instruction> {
        words
            .iter()
            .enumerate()
            .map(|(i, (text, stall))| {
                let mut w = crate::parse_sass(text, (i * 16) as u32).unwrap();
                w.ctrl.stall = *stall;
                w
            })
            .collect()
    }

    fn table() -> DepLatTable {
        DepLatTable::from_json(crate::dep_stall::SM120_TABLE).unwrap()
    }

    const QMMA: &str = "QMMA.SF.16832.F32.E4M3.E2M1.E8 R20, R12, R16, R48, R70, R66, UR4";

    /// A `QMMA` at `stall` with `behind` behind it.
    fn with(stall: u8, behind: &[(&str, u8)]) -> Report {
        let mut words = vec![(QMMA, stall)];
        words.extend_from_slice(behind);
        check(&kernel(&words), &table())
    }

    /// The operands of a tensor instruction by the law's widths.
    #[test]
    fn the_sources_of_a_tensor_instruction() {
        let k = kernel(&[(QMMA, 1)]);
        let got = tensor_sources(&k[0]);
        let regs: Vec<u8> = got.iter().map(|(r, _)| *r).collect();
        assert_eq!(regs, vec![12, 13, 14, 15, 16, 17, 48, 49, 50, 51, 70, 66], "{got:?}");
        assert_eq!(got.iter().filter(|(_, o)| *o == 3).count(), 4, "the accumulate is a quad");
    }

    /// `CS2R` re-zeroes the accumulate one and two cycles behind the tensor instruction: four sites,
    /// one for each register of the two pairs; at 8 and 9 there is none.
    #[test]
    fn a_cs2r_inside_the_hold_is_named() {
        let tail = [("CS2R R50, SRZ", 1), ("CS2R R48, SRZ", 1), ("EXIT", 5)];
        let rep = with(1, &tail);
        let got: Vec<(usize, Option<u8>, u32)> = rep.sites.iter().map(|s| (s.at, s.reg, s.have)).collect();
        assert_eq!(got, vec![(1, Some(50), 1), (1, Some(51), 1), (2, Some(48), 2), (2, Some(49), 2)], "{rep:?}");
        assert!(rep.sites.iter().all(|s| s.law == Law::Hold && s.operand == 3 && s.need == 8));
        assert!(with(8, &tail).sites.is_empty(), "the vendor's 8 and 9");
        assert_eq!(with(7, &tail).count(Law::Hold), 2, "one cycle short: the first pair alone");
        let line = describe(&kernel(&[(QMMA, 1), ("CS2R R50, SRZ", 1), ("EXIT", 5)]), &rep.sites[0]);
        assert!(line.contains("insn[1] CS2R R50, SRZ rewrites R50 1 issue cycle(s) behind insn[0]") && line.contains("its accumulate"), "{line}");
    }

    /// A load may follow at once and the next tensor instruction is no finding; both are counted.
    #[test]
    fn a_late_landing_writer_is_no_site() {
        let rep = with(1, &[("LDS R12, [R80+0x100]", 1), ("EXIT", 5)]);
        assert!(rep.sites.is_empty(), "{rep:?}");
        assert_eq!((rep.late_landing, rep.next_tensor), (1, 0));
        let rep = with(1, &[("QMMA.SF.16832.F32.E4M3.E2M1.E8 R48, R24, R28, R48, R70, R66, UR4", 1), ("EXIT", 5)]);
        assert!(rep.sites.is_empty(), "{rep:?}");
        assert_eq!(rep.next_tensor, 4);
        // the uniform operand has no hold
        assert!(with(1, &[("UMOV UR4, URZ", 1), ("EXIT", 5)]).sites.is_empty());
    }

    /// A branch of every form inside the landing distance; at 14 none.
    #[test]
    fn a_branch_inside_the_landing_distance_is_named() {
        for bra in ["BRA 0x40", "@!P0 BRA 0x40", "BRA.U !UP0, 0x40"] {
            let tail = |nop: u8| [("NOP", nop), (bra, 5), ("NOP", 1), ("NOP", 1), ("EXIT", 5)];
            let rep = with(1, &tail(3));
            assert_eq!(rep.sites, vec![Site { law: Law::Landing, tensor: 0, at: 2, reg: None, operand: 0, have: 4, need: 14 }], "{bra}");
            assert!(with(1, &tail(13)).sites.is_empty(), "{bra}: 1 + 13 = the law's 14");
            assert_eq!(with(1, &tail(12)).count(Law::Landing), 1, "{bra}: 13");
        }
    }

    /// The hold follows the paths: an overwriter behind a taken branch is found, and a word that
    /// an unconditional branch jumps over is not.
    #[test]
    fn the_walk_follows_the_flow_graph() {
        let rep = with(1, &[("BRA 0x30", 2), ("MOV R12, RZ", 1), ("MOV R48, RZ", 1), ("EXIT", 5)]);
        let hold: Vec<(usize, Option<u8>, u32)> = rep.sites.iter().filter(|s| s.law == Law::Hold).map(|s| (s.at, s.reg, s.have)).collect();
        assert_eq!(hold, vec![(3, Some(48), 3)], "{rep:?}");
        assert_eq!(rep.count(Law::Landing), 1);
    }

    /// A kernel without a tensor instruction is not walked.
    #[test]
    fn no_tensor_instruction_no_walk() {
        let rep = check(&kernel(&[("MOV R1, RZ", 1), ("EXIT", 5)]), &table());
        assert_eq!((rep.tensors, rep.sites.len()), (0, 0));
    }
}
