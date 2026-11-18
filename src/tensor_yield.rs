//! `CUBIT_TENSOR_YIELD=holds` (opt-in, honoured only together with `CUBIT_SYNC_CLASSES=1`): in a
//! tensor loop every hold of the fixed-latency datapath yields.
//!
//! The scheduler takes the yield flag off a stall that carries a dependency (`dep_stall::apply`:
//! a datapath word at a stall of 3 or more that binds a requirement carries none), and so does
//! the vendor: in his tensor loops a word that holds in front of a tensor word carries no flag.
//! A search on a card found the opposite to be faster there. This clause of the flag pass writes
//! it, on a finished schedule, in the text range of every tensor loop
//! (`scheduling_pass::tensor_loop_words`: the innermost loop around a warp tensor word, first word
//! to backward branch): a **hold** — a word at a stall of 3 ..= 11 that carries no flag — TAKES
//! the flag.
//!
//! A hold is a word cubit scheduled whose opcode is one of the flag rule's datapath opcodes
//! (`scheduling_pass::HOLD_OPCODES`: no tensor word, no branch, convergence, event,
//! variable-latency, load or store word), that sets no barrier, waits on none and is on no path
//! the first word behind a wait on a write barrier that reads a register a setter of that
//! barrier wrote ([`first_readers_behind_a_wait`]). Those three roles are the ones a flag can be
//! more than a hint for: a waiter one cycle behind a setter that carries the flag does not see
//! the barrier, and the first reader behind a wait is the word the wait releases.
//!
//! No stall, no wait and no barrier moves and no flag is taken off: a word at a stall of 1 or 2
//! in front of a hold keeps its flag (a card read its giving up as a cost). A word at a stall
//! of 12 ..= 15 is never given the flag (a reserved code); the tensor words keep their own
//! flags; a hand-scheduled word is not touched; a kernel without a tensor loop is not touched.

use crate::ir::{Instruction, Operand};
use crate::scheduling_pass as sp;

/// `CUBIT_TENSOR_YIELD` as written: `Ok(false)` when unset, empty or `0`, and when
/// `CUBIT_SYNC_CLASSES=1` is not set (the clause is honoured only with it); `Ok(true)` for
/// `holds`; the message of the refusal for any other value.
pub fn request() -> Result<bool, String> {
    match std::env::var("CUBIT_TENSOR_YIELD") {
        Err(_) => Ok(false),
        Ok(v) if v.is_empty() || v == "0" => Ok(false),
        Ok(v) if v == "holds" => Ok(crate::sync_class::enabled()),
        Ok(v) => Err(format!(
            "CUBIT_TENSOR_YIELD={v}: the only value is `holds` (in a tensor loop a datapath word that holds at a stall of 3 ..= 11 takes the yield flag); unset = the flags as the scheduler writes them"
        )),
    }
}

/// The scoreboards a word waits: its wait mask, and the one a `DEPBAR` drains (operand 0).
fn waits_of(x: &Instruction) -> u8 {
    let mut m = x.ctrl.wait_mask;
    if x.opcode == "DEPBAR" {
        if let Some(Operand::Imm32(v)) = x.operands.first() {
            if (0..sp::NUM_BARRIERS as i64).contains(v) {
                m |= 1 << *v;
            }
        }
    }
    m
}

/// The distance behind a setter at which a wait sees its barrier.
const ARM: u32 = 2;

/// Does a wait `elapsed` issue cycles behind a setter see the setter's barrier? At two cycles
/// always; at one only when the setter carries no yield flag.
fn armed(elapsed: u32, setter_yields: bool) -> bool {
    elapsed >= ARM || (elapsed >= 1 && !setter_yields)
}

/// The words that are, on some path of the flow graph, the FIRST word behind a wait on a write
/// barrier that reads a register a setter of that barrier wrote.
///
/// For every word that sets a write barrier and writes a register: its readers (the paths
/// behind it, a register followed until a word under no guard rewrites it), the waits that
/// release it (on every path the first word that waits the barrier where the barrier is armed
/// — by its wait mask or as the `DEPBAR` of that scoreboard), and behind each such wait, on
/// every path, the first of the readers. A path ends where the setter issues again: a new
/// instance. The flow graph and the operand sets are the legaliser's
/// (`dep_stall::build_flow`, `scheduling_pass::src_regs` / `dest_regs`).
pub fn first_readers_behind_a_wait(insns: &[Instruction]) -> Vec<bool> {
    let n = insns.len();
    let rk = |(u, r): (bool, u16)| -> u16 { ((u as u16) << 9) | r };
    let reads: Vec<Vec<u16>> = insns.iter().map(|x| sp::src_regs(x).into_iter().map(rk).collect()).collect();
    let writes: Vec<Vec<u16>> = insns.iter().map(|x| sp::dest_regs(x).into_iter().map(rk).collect()).collect();
    let guarded: Vec<bool> = insns.iter().map(|x| x.guard.as_ref().is_some_and(|g| g.pred < 7)).collect();
    let waits: Vec<u8> = insns.iter().map(waits_of).collect();
    let flow = crate::dep_stall::build_flow(insns);
    let mut first = vec![false; n];
    for p in 0..n {
        let b = insns[p].ctrl.write_bar;
        if (b as usize) >= sp::NUM_BARRIERS || writes[p].is_empty() {
            continue;
        }
        let bit = 1u8 << b;
        let dsts = &writes[p];
        // the readers of p's result
        let mut reader = vec![false; n];
        {
            let mut seen: Vec<Vec<Vec<u16>>> = vec![Vec::new(); n];
            let mut stack: Vec<(usize, Vec<u16>)> = flow.succ[p].iter().map(|&s| (s, dsts.clone())).collect();
            while let Some((j, mut live)) = stack.pop() {
                if seen[j].iter().any(|l| live.iter().all(|r| l.contains(r))) {
                    continue;
                }
                seen[j].push(live.clone());
                if reads[j].iter().any(|r| live.contains(r)) {
                    reader[j] = true;
                }
                if j == p {
                    continue;
                }
                if !guarded[j] {
                    live.retain(|r| !writes[j].contains(r));
                    if live.is_empty() {
                        continue;
                    }
                }
                for &s in &flow.succ[j] {
                    stack.push((s, live.clone()));
                }
            }
        }
        if !reader.iter().any(|&x| x) {
            continue;
        }
        // the waits that release p
        let mut release: Vec<usize> = Vec::new();
        {
            let yields = insns[p].ctrl.yield_flag;
            let mut seen = vec![[false; ARM as usize + 1]; n];
            let e0 = (insns[p].ctrl.stall as u32).min(ARM);
            let mut stack: Vec<(usize, u32)> = flow.succ[p].iter().map(|&s| (s, e0)).collect();
            while let Some((j, e)) = stack.pop() {
                if seen[j][e as usize] {
                    continue;
                }
                seen[j][e as usize] = true;
                if waits[j] & bit != 0 && armed(e, yields) {
                    if !release.contains(&j) {
                        release.push(j);
                    }
                    continue;
                }
                if j == p {
                    continue;
                }
                let e = (e + insns[j].ctrl.stall as u32).min(ARM);
                for &s in &flow.succ[j] {
                    stack.push((s, e));
                }
            }
        }
        // behind each of them, the first reader of every path
        for &w in &release {
            let mut seen = vec![false; n];
            let mut stack: Vec<usize> = flow.succ[w].clone();
            while let Some(j) = stack.pop() {
                if seen[j] {
                    continue;
                }
                seen[j] = true;
                if reader[j] && reads[j].iter().any(|r| dsts.contains(r)) {
                    first[j] = true;
                    continue;
                }
                if j == p {
                    continue;
                }
                stack.extend(flow.succ[j].iter().copied());
            }
        }
    }
    first
}

/// The holds of the tensor loops of `insns` as the schedule stands, in text order. `keep[i]`
/// (where given) takes word `i` out.
pub fn holds(insns: &[Instruction], keep: &[bool]) -> Vec<usize> {
    let inside = sp::tensor_loop_words(insns);
    let mut out = Vec::new();
    if !inside.iter().any(|&x| x) {
        return out;
    }
    let first = first_readers_behind_a_wait(insns);
    for (i, w) in insns.iter().enumerate() {
        if !inside[i] || first[i] || keep.get(i).copied().unwrap_or(false) || w.hand_sched {
            continue;
        }
        let sets = (w.ctrl.write_bar as usize) < sp::NUM_BARRIERS || (w.ctrl.read_bar as usize) < sp::NUM_BARRIERS;
        if sets || waits_of(w) != 0 || !sp::HOLD_OPCODES.contains(&w.opcode.as_str()) {
            continue;
        }
        if !w.ctrl.yield_flag && (3..=11).contains(&w.ctrl.stall) {
            out.push(i);
        }
    }
    out
}

/// The clause on a finished schedule: every hold of a tensor loop takes the yield flag
/// ([`holds`]). Returns the number of flags set. `keep`: words that keep their flag as it stands
/// (empty = none) — the place of an exception to the clause.
pub fn apply(insns: &mut [Instruction], keep: &[bool]) -> usize {
    let h = holds(insns, keep);
    for &i in &h {
        insns[i].ctrl.yield_flag = true;
    }
    h.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: u8 = 7;

    fn word(s: &str, addr: u32, stall: u8, flag: bool) -> Instruction {
        let mut i = crate::parse_sass(s, addr).unwrap();
        i.hand_sched = false;
        i.ctrl.stall = stall;
        i.ctrl.yield_flag = flag;
        i.ctrl.write_bar = NONE;
        i.ctrl.read_bar = NONE;
        i.ctrl.wait_mask = 0;
        i
    }

    fn flags(k: &[Instruction]) -> Vec<bool> {
        k.iter().map(|x| x.ctrl.yield_flag).collect()
    }

    fn rest(k: &[Instruction]) -> Vec<(u8, u8, u8, u8)> {
        k.iter().map(|x| (x.ctrl.stall, x.ctrl.write_bar, x.ctrl.read_bar, x.ctrl.wait_mask)).collect()
    }

    /// [0] frame | [1 ..= 6] a loop around a tensor word | [7] frame
    fn kernel() -> Vec<Instruction> {
        vec![
            word("MOV R4, R5", 0x00, 4, false),
            word("MOV R12, R9", 0x10, 1, true),
            word("MOV R13, R9", 0x20, 2, true),
            word("MOV R16, R10", 0x30, 7, false),
            word("HMMA.16816.F32 R24, R12, R16, R24", 0x40, 1, true),
            word("IADD3 R20, PT, PT, R20, 0x1, RZ", 0x50, 5, false),
            word("BRA 0x10", 0x60, 5, true),
            word("MOV R9, R10", 0x70, 3, false),
        ]
    }

    #[test]
    fn a_hold_of_a_tensor_loop_takes_the_flag_and_nothing_else_moves() {
        let mut k = kernel();
        let before = rest(&k);
        assert_eq!(holds(&k, &[]), [3, 5]);
        assert_eq!(apply(&mut k, &[]), 2);
        // the holds [3] and [5]; the word [2] in front of a hold keeps its flag; a hold outside the loop keeps none
        assert_eq!(flags(&k), [false, true, true, true, true, true, true, false]);
        assert_eq!(rest(&k), before);
        assert_eq!(apply(&mut k, &[]), 0, "a second pass finds nothing");
    }

    #[test]
    fn a_stall_of_twelve_a_stall_of_two_and_a_word_outside_the_list_are_no_holds() {
        let mut k = kernel();
        k[3].ctrl.stall = 12;
        k[5].ctrl.stall = 2;
        assert_eq!(apply(&mut k, &[]), 0);
        let mut k = kernel();
        k[3].ctrl.stall = 11;
        k[5].ctrl.stall = 3;
        assert_eq!(holds(&k, &[]), [3, 5], "3 and 11 are the ends of the range");
        let mut k = kernel();
        k[3] = word("SHFL.IDX PT, R16, R10, RZ, 0x1f", 0x30, 7, false);
        assert_eq!(holds(&k, &[]), [5]);
    }

    #[test]
    fn a_setter_a_waiting_word_an_authors_word_and_a_kept_word_stay_as_they_are() {
        let mut k = kernel();
        k[3].ctrl.write_bar = 2;
        assert_eq!(holds(&k, &[]), [5], "a word that sets a write barrier");
        let mut k = kernel();
        k[3].ctrl.read_bar = 1;
        assert_eq!(holds(&k, &[]), [5], "a word that sets a read barrier");
        let mut k = kernel();
        k[3].ctrl.wait_mask = 0b100;
        assert_eq!(holds(&k, &[]), [5], "a word that waits");
        let mut k = kernel();
        k[3].hand_sched = true;
        assert_eq!(holds(&k, &[]), [5], "a word that came in with its control word");
        let k = kernel();
        let mut keep = vec![false; k.len()];
        keep[5] = true;
        assert_eq!(holds(&k, &keep), [3], "the list of the words that keep their flag");
    }

    /// [0] a load on scoreboard 2 | [1] its waiting reader | [2] the first reader behind the wait | [3] a later reader | ...
    fn loaded() -> Vec<Instruction> {
        let mut k = vec![
            word("LDG.E R11, desc[UR8][R2.64]", 0x00, 3, true),
            word("IADD3 R14, PT, PT, R11, R9, RZ", 0x10, 1, true),
            word("IADD3 R15, PT, PT, R11, 0x1, RZ", 0x20, 7, false),
            word("IADD3 R17, PT, PT, R11, 0x2, RZ", 0x30, 4, false),
            word("HMMA.16816.F32 R24, R12, R16, R24", 0x40, 1, true),
            word("BRA 0x0", 0x50, 5, true),
        ];
        k[0].ctrl.write_bar = 2;
        k[1].ctrl.wait_mask = 0b100;
        k
    }

    #[test]
    fn the_first_reader_behind_a_wait_is_no_hold_and_the_reader_behind_it_is() {
        let mut k = loaded();
        assert_eq!(first_readers_behind_a_wait(&k), [false, false, true, false, false, false]);
        assert_eq!(apply(&mut k, &[]), 1);
        assert_eq!(flags(&k), [true, true, false, true, true, true]);
    }

    #[test]
    fn a_register_rewritten_in_front_of_the_wait_has_no_first_reader() {
        let mut k = loaded();
        // [1] rewrites R11 itself: what [2] reads is no result of the load
        k[1] = word("IADD3 R11, PT, PT, R11, R9, RZ", 0x10, 1, true);
        k[1].ctrl.wait_mask = 0b100;
        assert_eq!(first_readers_behind_a_wait(&k), [false; 6]);
        assert_eq!(holds(&k, &[]), [2, 3]);
    }

    #[test]
    fn a_wait_one_cycle_behind_a_setter_that_yields_releases_nothing() {
        let mut k = loaded();
        k[0].ctrl.stall = 1;
        // the barrier is not armed for [1]; no other word waits it: no wait releases the load
        assert_eq!(first_readers_behind_a_wait(&k), [false; 6]);
        k[0].ctrl.yield_flag = false;
        assert_eq!(first_readers_behind_a_wait(&k), [false, false, true, false, false, false], "without the flag one cycle arms it");
    }

    #[test]
    fn a_kernel_without_a_tensor_loop_is_not_touched() {
        let mut k = vec![word("MOV R4, R5", 0x00, 4, false), word("IADD3 R6, PT, PT, R4, 0x40, RZ", 0x10, 5, false), word("BRA 0x0", 0x20, 5, true)];
        assert_eq!(apply(&mut k, &[]), 0);
        assert_eq!(flags(&k), [false, false, true]);
    }
}
