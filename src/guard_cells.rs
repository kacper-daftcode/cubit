//! `CUBIT_DEP_CELLS_GUARD` — one more cell kind of the dump `CUBIT_DEP_CELLS`: `guard-settled`,
//! the read that rests solely on a wait carried by a word under a guard.
//!
//! A scoreboarded producer (a load) arms a write barrier, and a reader of its register waits on
//! it: a bit of the wait mask in the reader's control field. Not every reader carries the bit —
//! the first readers of a path wait, the readers behind them rest on that wait. When the only
//! words that wait the barrier between the producer and a reader stand under a guard (`@P0 …`,
//! `@!P0 …`), the read is covered by the wait only if a wait carried by a word whose guard is
//! false is honoured; otherwise it rests on the plain distance producer → reader. The vendor
//! writes such reads (the sm_120 census, 50 of 50 sites: the next unguarded reader behind a
//! guarded waiter carries no wait of its own), and cubit writes them in two places: the
//! allocator's default leaves the readers behind a guarded OVERWRITER that waited without a
//! wait of their own, and `CUBIT_GUARDED_READER_SETTLES=1` (or the wait policy, which contains
//! it) lets the first reader of a path settle the barrier guarded or not.
//!
//! The dump names them, so that a tool can count the reads of this kind whose distance in one
//! schedule of a text is below the distance another schedule of the same text gives the pair.
//! It is read-only and works on the control words a text carries — a schedule cubit built or a
//! frozen listing; no word moves, and without the switch the dump is what it was.
//!
//! What is walked: behind every word that arms a write barrier and writes a register, the
//! paths of the flow graph the dump's other cells stand on (`dep_stall::build_flow`), with the
//! scheduler's operand sets (`scheduling_pass::src_regs` / `dest_regs`). A register is followed
//! until a word that is under no guard rewrites it (a guarded rewrite may not happen); a path
//! ends back at the producer (a new instance). A word waits the barrier by its wait mask or as
//! the `DEPBAR` of that scoreboard. A waiter whose guard is the pending result itself cannot be
//! skipped before the result is there: it counts as a word under no guard.
//!
//! `all` prints every read of such a result with its cover, and the reads behind a word the
//! scheduler would scoreboard that this text leaves without a barrier (`bare`: the vendor leaves
//! loads bare whose readers stand far enough behind them) — two schedules of one text arm
//! different words, and the distance one of them gives a pair is then a line of its dump
//! whatever its cover is there.

use crate::ir::{Instruction, Operand};
use crate::scheduling_pass as sp;
use crate::table::IsaTable;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};

/// How a read of a scoreboarded result is covered on a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cover {
    /// no word waits the barrier between the producer and the reader, and the reader does not
    Unwaited,
    /// the only words that wait the barrier between them stand under a guard: `guard-settled`
    Guarded,
    /// a word under no guard waits the barrier between them
    Unguarded,
    /// the reader waits the barrier itself
    Own,
    /// the producer is a word the scheduler would give a write barrier and the text gives it
    /// none: every read of its result rests on the distance
    Bare,
}

impl Cover {
    /// The `role` of the cell.
    pub fn role(self) -> &'static str {
        match self {
            Cover::Unwaited => "none",
            Cover::Guarded => "guarded",
            Cover::Unguarded => "unguarded",
            Cover::Own => "own",
            Cover::Bare => "bare",
        }
    }

    /// The `kind` of the cell: the read under a guarded wait has a kind of its own.
    pub fn kind(self) -> &'static str {
        if self == Cover::Guarded {
            "guard-settled"
        } else {
            "barrier-read"
        }
    }
}

/// One read of a scoreboarded result under one cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierRead {
    /// the word that arms the write barrier
    pub producer: usize,
    /// a reader of a register the producer writes
    pub consumer: usize,
    pub cover: Cover,
    /// the word whose wait the read rests on: the first waiter of that kind on the tightest
    /// path (the reader itself for [`Cover::Own`], none for [`Cover::Unwaited`])
    pub via: Option<usize>,
    /// the tightest issue distance producer → reader over the paths with this cover
    pub have: u32,
}

/// A state of the walk behind one producer: (distance, word, the waits seen on the path — 0 none,
/// 1 under a guard alone, 2 one under no guard —, the registers that may still hold the result,
/// the waiter the path's reads rest on or `usize::MAX`).
type State = (u32, usize, u8, Vec<u16>, usize);

/// `CUBIT_DEP_CELLS_GUARD`: unset, empty or `0` = no such cell (`None`); `1` = the
/// `guard-settled` cells (`Some(false)`); `all` = every read of a scoreboarded result with its
/// cover (`Some(true)`).
pub fn mode() -> Result<Option<bool>, String> {
    match std::env::var("CUBIT_DEP_CELLS_GUARD") {
        Err(_) => Ok(None),
        Ok(v) if v.is_empty() || v == "0" => Ok(None),
        Ok(v) if v == "1" => Ok(Some(false)),
        Ok(v) if v == "all" => Ok(Some(true)),
        Ok(v) => Err(format!(
            "CUBIT_DEP_CELLS_GUARD={v}: the values are `1` (the reads that rest solely on a wait under a guard) and `all` (every read of a scoreboarded result with its cover, and the reads behind a load the text leaves without a barrier); it adds lines to the file CUBIT_DEP_CELLS names and changes no word"
        )),
    }
}

/// Read-only: the reads of scoreboarded results in `insns` by their cover, one entry per
/// (producer, reader, cover) with the tightest distance over the paths that give the reader
/// that cover. `all == false`: the [`Cover::Guarded`] entries alone (a path is then left at
/// the first word under no guard that waits the barrier). `all == true` also walks behind the
/// words the scheduler would give a write barrier (`scheduling_pass::insn_needs_write_bar`)
/// that carry none in this text ([`Cover::Bare`]): another schedule of the text may arm one.
pub fn barrier_reads(insns: &[Instruction], table: Option<&IsaTable>, all: bool) -> Vec<BarrierRead> {
    let n = insns.len();
    let rk = |(u, r): (bool, u16)| -> u16 { ((u as u16) << 9) | r };
    let reads: Vec<Vec<u16>> = insns.iter().map(|x| sp::src_regs(x).into_iter().map(rk).collect()).collect();
    let writes: Vec<Vec<u16>> = insns.iter().map(|x| sp::dest_regs(x).into_iter().map(rk).collect()).collect();
    let guard_key: Vec<Option<u16>> = insns
        .iter()
        .map(|x| {
            x.guard
                .as_ref()
                .filter(|g| g.pred < 7)
                .map(|g| rk((g.uniform, if g.uniform { 64 + g.pred as u16 } else { sp::PRED_KEY + g.pred as u16 })))
        })
        .collect();
    // the scoreboards a word waits: its wait mask, and the one a `DEPBAR` drains (operand 0)
    let waits: Vec<u8> = insns
        .iter()
        .map(|x| {
            let mut m = x.ctrl.wait_mask;
            if x.opcode == "DEPBAR" {
                if let Some(Operand::Imm32(v)) = x.operands.first() {
                    if (0..sp::NUM_BARRIERS as i64).contains(v) {
                        m |= 1 << *v;
                    }
                }
            }
            m
        })
        .collect();
    let flow = crate::dep_stall::build_flow(insns);
    let mut out = Vec::new();
    for p in 0..n {
        let b = insns[p].ctrl.write_bar;
        let armed = (b as usize) < sp::NUM_BARRIERS;
        if writes[p].is_empty() || !(armed || (all && sp::insn_needs_write_bar(&insns[p], table, true))) {
            continue;
        }
        let bit = if armed { 1u8 << b } else { 0 };
        let dsts = &writes[p];
        // per (reader, cover): the tightest distance and the waiter the read rests on
        let mut found: BTreeMap<(usize, Cover), (u32, Option<usize>)> = BTreeMap::new();
        let mut seen: Vec<Vec<(u8, Vec<u16>)>> = vec![Vec::new(); n];
        let mut heap: BinaryHeap<Reverse<State>> = BinaryHeap::new();
        for &s in &flow.succ[p] {
            heap.push(Reverse((insns[p].ctrl.stall as u32, s, 0, dsts.clone(), usize::MAX)));
        }
        // in order of distance: the first state at a word is the tightest one, and a later
        // one with the same waits and no register more finds nothing new
        while let Some(Reverse((d, j, seen_waits, mut live, via))) = heap.pop() {
            if j == p {
                continue; // the producer issues again: a new instance
            }
            if seen[j].iter().any(|(w, l)| *w == seen_waits && live.iter().all(|r| l.contains(r))) {
                continue;
            }
            seen[j].push((seen_waits, live.clone()));
            let waits_here = waits[j] & bit != 0;
            if reads[j].iter().any(|r| live.contains(r)) {
                let (cover, by) = if !armed {
                    (Cover::Bare, None)
                } else if waits_here {
                    (Cover::Own, Some(j))
                } else {
                    match seen_waits {
                        0 => (Cover::Unwaited, None),
                        1 => (Cover::Guarded, Some(via)),
                        _ => (Cover::Unguarded, Some(via)),
                    }
                };
                found.entry((j, cover)).or_insert((d, by));
            }
            let (mut seen_waits, mut via) = (seen_waits, via);
            if waits_here {
                let under_guard = guard_key[j].is_some_and(|k| !dsts.contains(&k));
                if !under_guard {
                    if seen_waits < 2 {
                        via = j;
                    }
                    seen_waits = 2;
                } else if seen_waits == 0 {
                    seen_waits = 1;
                    via = j;
                }
            }
            if seen_waits == 2 && !all {
                continue; // behind a wait under no guard no read rests on a guarded one
            }
            if guard_key[j].is_none() {
                live.retain(|r| !writes[j].contains(r));
            }
            if live.is_empty() {
                continue;
            }
            let d = d.saturating_add(insns[j].ctrl.stall as u32);
            for &s in &flow.succ[j] {
                heap.push(Reverse((d, s, seen_waits, live.clone(), via)));
            }
        }
        for ((c, cover), (have, via)) in found {
            if all || cover == Cover::Guarded {
                out.push(BarrierRead { producer: p, consumer: c, cover, via, have });
            }
        }
    }
    out
}

/// The line of the dump for one entry: the keys of the dump's other cells (`need` is 0: no row
/// of the table asks for a distance here) and `via`.
pub fn json_line(kernel: &str, insns: &[Instruction], c: &BarrierRead) -> String {
    format!(
        "{{\"kernel\":\"{}\",\"prod\":{},\"cons\":{},\"pc\":\"{}\",\"cc\":\"{}\",\"role\":\"{}\",\"need\":0,\"have\":{},\"kind\":\"{}\",\"defaulted\":false,\"via\":{}}}",
        kernel,
        c.producer,
        c.consumer,
        crate::dep_stall::dep_class(&insns[c.producer]),
        crate::dep_stall::dep_class(&insns[c.consumer]),
        c.cover.role(),
        c.have,
        c.cover.kind(),
        c.via.map_or("null".to_string(), |v| v.to_string())
    )
}
