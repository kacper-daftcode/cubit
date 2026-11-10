//! Control classes of the synchronisation words (`CUBIT_SYNC_CLASSES=1`, opt-in; sm_120).
//!
//! A kernel built from warp groups talks through words the scheduler had no class for:
//! mbarriers (`SYNCS.*`, `ARRIVES.*`), bulk copies (`UBLKCP`, `UTMALDG` / `UTMASTG`,
//! `UTMACMDFLUSH`, `DEPBAR.LE SB0`, `LDGDEPBAR`), the async-proxy fence (`FENCE.VIEW.ASYNC`),
//! the memory-ordering chains (`MEMBAR.*`, `ERRBAR`, `CGAERRBAR`, `CCTL.IVALL`), named
//! barriers (`BAR.ARV`), `USETMAXREG`, and the words nvcc wraps warp-wide operations in
//! (`WARPSYNC`, `ENDCOLLECTIVE`, `YIELD`, `NANOSLEEP`). Their rows are `ctrl_class none` or a
//! static class, so a cubit-scheduled kernel got them without a barrier and at the ISA default
//! stall: `SYNCS.PHASECHK.TRANS64.TRYWAIT P0, ...` followed one cycle later by `@!P0 BRA`
//! reads the stale predicate.
//!
//! This module is what ptxas does with them, as the frozen census shows it (the served
//! MoE cubin of vLLM-Moet, 35 kernels, and the primitive probe of `docs/SM120_ASYNC_IDIOMS.md`)
//! and as the floor probes of `tools/stallfloor/syncfloor_*.py` measure it on silicon:
//!
//! | word | write barrier | read barrier on | stall | waits |
//! |---|---|---|---|---|
//! | `SYNCS.PHASECHK.TRANS64[.TRYWAIT] P, [a], R` | on the predicate (a scoreboard result) | `a`, `R` | 2 | the fence / init token |
//! | `USETMAXREG.TRY_ALLOC.CTAPOOL UP, n` | on the uniform predicate | – | 2 | – |
//! | `SYNCS.EXCH.64 URZ, [a], UR` (init) | a token the next mbarrier word / `BAR` waits | `a`, `UR` | 2 | the fence token |
//! | `SYNCS.ARRIVE.TRANS64[.A1T0] RZ, [a], R` | – | `a`, `R` | 1 | the fence / init token |
//! | `SYNCS.CCTL.IVALL` | a token the next mbarrier word / `BAR` waits | – | 2 | the fence token |
//! | `ARRIVES.LDGSTSBAR.64.ARVCNT [a]` | – | – | 1 (8 in front of a branch) | – |
//! | `FENCE.VIEW.ASYNC.{S,G}` | a token the next mbarrier / bulk word waits | – | 2 | – |
//! | `UBLKCP.S.G`, `UTMALDG` (the loads) | – | every operand | 12 | the fence token |
//! | `UBLKCP.G.S`, `UTMASTG` (the stores) | – | every operand | 1 | the fence token |
//! | `UTMACMDFLUSH` | – | scoreboard 0 (the group) | 1 | – |
//! | `LDGDEPBAR` | scoreboard 0 (the group) | – | 1 | – |
//! | `DEPBAR.LE SB0, n` | – | – | 4, no yield | – |
//! | `MEMBAR.{ALL,SC}.{GPU,SYS}` | – | – | 6 | – |
//! | `MEMBAR.*.CTA` | – | – | 6 (0 in front of another `MEMBAR`) | – |
//! | `ERRBAR` | – | – | 0, no yield | – |
//! | `CGAERRBAR` | – | – | 6 | – |
//! | `CCTL.IVALL` | – | – | 1 (4 in front of a memory instruction) | the barrier of the `.STRONG` load / atomic in front of it (the acquire) |
//! | `BAR.ARV` | – | – | 8 | – |
//! | `NANOSLEEP[.SYNCS]`, `YIELD`, `WARPSYNC.*`, `ENDCOLLECTIVE` | – | – | 5 | their guard's producer |
//!
//! Three laws of ptxas's schedules that a plain nvcc text needs and cubit's own kernels never met:
//! every control transfer is issued at stall 5 or more (`is_unlisted_transfer`: `BRX`, `JMX`,
//! `PRET`, `BPT` were scheduled as ALU); a reuse flag stands only on a word with yield and a
//! stall of 1 or 2 (`settle_reuse`); `LDGSTS`, `SYNCS.ARRIVE`, the re-check `SYNCS.PHASECHK` and
//! `FENCE` never carry a wait mask (`never_waits`).
//!
//! A collective region — `WARPSYNC.COLLECTIVE R, L ; SHFL ... ; ENDCOLLECTIVE`, the fallback
//! nvcc emits behind the `BRA.DIV` of every `shfl.sync` — has its own shape under ptxas
//! (1 808 of 1 808 regions of the census): the instruction in front of the `WARPSYNC` carries
//! stall 7 without yield (6 on a local store), the shuffle sets a write barrier AND a read
//! barrier on two scoreboards at stall 2, and `ENDCOLLECTIVE` waits both: nothing of the
//! region is in flight when the warp's mask is restored.
//!
//! Scoreboard 0 belongs to the copy group in a kernel that commits one (`LDGDEPBAR`,
//! `UTMACMDFLUSH`): ptxas gives it to nothing else there (10 of 10 kernels of the census; a
//! kernel that only waits, `DEPBAR.LE SB0, 0` in front of its `EXIT`, uses it freely).
//!
//! The hooks are in `scheduling_pass.rs` (`insn_needs_write_bar`, the wait / barrier
//! capability, `dest_regs` / `src_regs`, the stall of `schedule`, the uses and the colouring
//! of `reallocate_barriers`) and in the assembler (the encoder's static classes get the
//! scheduler's control code injected; the legacy convergence-barrier byte is not written).
//! With the switch unset none of them runs: the default path is byte for byte.

use crate::ir::{Instruction, Operand};

/// `CUBIT_SYNC_CLASSES=1`.
pub fn enabled() -> bool {
    std::env::var("CUBIT_SYNC_CLASSES").ok().as_deref() == Some("1")
}

/// Ordering tokens: pseudo-registers of the barrier allocator (never a real register key —
/// GPRs are 0..=255, predicates 256.., uniform keys carry bit 9).
pub const TOKEN_FENCE: u16 = 0x4000;
/// The mbarrier state behind `SYNCS.EXCH.64` (init) / `SYNCS.CCTL.IVALL`.
pub const TOKEN_MBAR: u16 = 0x4001;

/// What a write barrier of a synchronisation word stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteBar {
    None,
    /// the word's predicate / uniform-predicate result (variable latency: a scoreboard result)
    Result,
    /// an ordering token: no register, the next word of the family waits it
    Token(u16),
    /// the copy group's scoreboard, always 0 (`LDGDEPBAR`)
    Group,
}

/// The control class of one synchronisation word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncClass {
    pub name: &'static str,
    pub write_bar: WriteBar,
    /// every register operand is read late (asynchronously): a read barrier protects it
    pub late_operands: bool,
    /// the word's read barrier is the copy group's scoreboard 0 (`UTMACMDFLUSH`)
    pub group_read_bar: bool,
    /// tokens the word waits for
    pub waits: &'static [u16],
    /// issue floor: the word's stall
    pub stall: u8,
    pub yield_flag: bool,
}

impl SyncClass {
    const fn new(name: &'static str, stall: u8, yield_flag: bool) -> Self {
        SyncClass { name, write_bar: WriteBar::None, late_operands: false, group_read_bar: false, waits: &[], stall, yield_flag }
    }
    const fn wb(mut self, w: WriteBar) -> Self {
        self.write_bar = w;
        self
    }
    const fn late(mut self) -> Self {
        self.late_operands = true;
        self
    }
    const fn waits(mut self, w: &'static [u16]) -> Self {
        self.waits = w;
        self
    }
    pub fn sets_write_barrier(&self) -> bool {
        self.write_bar != WriteBar::None
    }
}

fn has(insn: &Instruction, m: &str) -> bool {
    insn.opcode_full.split('.').any(|x| x == m)
}

/// An instruction under `@!PT` never executes: ptxas places `@!PT LDS RZ, [RZ]` in front of a
/// run of `LDGSTS` as padding. It sets no barrier and waits for nothing.
pub fn never_executes(insn: &Instruction) -> bool {
    insn.guard.as_ref().is_some_and(|g| g.pred == 7 && g.negated)
}

/// The class of `insn`, or `None` when it is not a synchronisation word.
pub fn classify(insn: &Instruction) -> Option<SyncClass> {
    let op = insn.opcode.as_str();
    if never_executes(insn) {
        return Some(SyncClass::new("never-executed pad", 1, true));
    }
    let c = match op {
        "SYNCS" => {
            if has(insn, "PHASECHK") {
                SyncClass::new("mbarrier phase check", 2, true).wb(WriteBar::Result).late().waits(&[TOKEN_FENCE, TOKEN_MBAR])
            } else if has(insn, "EXCH") {
                SyncClass::new("mbarrier init", 2, true).wb(WriteBar::Token(TOKEN_MBAR)).late().waits(&[TOKEN_FENCE])
            } else if has(insn, "ARRIVE") {
                SyncClass::new("mbarrier arrive", 1, true).late().waits(&[TOKEN_FENCE, TOKEN_MBAR])
            } else if has(insn, "CCTL") {
                SyncClass::new("mbarrier cache control", 2, true).wb(WriteBar::Token(TOKEN_MBAR)).waits(&[TOKEN_FENCE])
            } else {
                SyncClass::new("mbarrier word", 2, true).late().waits(&[TOKEN_FENCE, TOKEN_MBAR])
            }
        }
        "ARRIVES" => SyncClass::new("copy arrive", 1, true).waits(&[TOKEN_MBAR]),
        "FENCE" => SyncClass::new("async-proxy fence", 2, true).wb(WriteBar::Token(TOKEN_FENCE)),
        "UBLKCP" => {
            // `.S.G` = global -> shared (the load: ptxas issues it at S12), `.G.S` the store
            let load = insn.opcode_full.contains(".S.G") || insn.opcode_full.contains(".S.S");
            SyncClass::new("bulk copy", if load { 12 } else { 1 }, !load).late().waits(&[TOKEN_FENCE])
        }
        "UTMALDG" => SyncClass::new("tensor-map load", 12, false).late().waits(&[TOKEN_FENCE]),
        "UTMASTG" => SyncClass::new("tensor-map store", 1, true).late().waits(&[TOKEN_FENCE]),
        "UTMACMDFLUSH" => {
            let mut c = SyncClass::new("bulk commit", 1, true);
            c.group_read_bar = true;
            c
        }
        "LDGDEPBAR" => SyncClass::new("copy-group commit", 1, true).wb(WriteBar::Group),
        "DEPBAR" => SyncClass::new("copy-group wait", 4, false),
        "MEMBAR" => SyncClass::new("memory barrier", 6, true),
        "ERRBAR" => SyncClass::new("error barrier", 0, false),
        "CGAERRBAR" => SyncClass::new("cga error barrier", 6, true),
        "CCTL" if has(insn, "IVALL") => SyncClass::new("L1 invalidate", 1, true),
        "BAR" if has(insn, "ARV") => SyncClass::new("named-barrier arrive", 8, true),
        "USETMAXREG" => {
            if has(insn, "TRY_ALLOC") {
                SyncClass::new("register-pool allocation", 2, true).wb(WriteBar::Result)
            } else {
                // DEALLOC: a hardware interlock (ptxas: S00)
                SyncClass::new("register-pool release", 0, false)
            }
        }
        "NANOSLEEP" => SyncClass::new("sleep", 5, true),
        "YIELD" => SyncClass::new("yield", 5, true),
        "WARPSYNC" => SyncClass::new("warp sync", 5, true),
        "ENDCOLLECTIVE" => SyncClass::new("end of a collective region", 5, true),
        _ => return None,
    };
    Some(c)
}

/// The stall of `insns[i]` under its class, with the two context rules of ptxas's practice.
pub fn stall_of(insns: &[Instruction], i: usize, c: &SyncClass) -> u8 {
    let next = insns.get(i + 1).map(|x| x.opcode.as_str()).unwrap_or("");
    match insns[i].opcode.as_str() {
        // `MEMBAR.ALL.CTA [S00]; MEMBAR.ALL.GPU [S06]`: the chain's first word carries no stall
        "MEMBAR" if next == "MEMBAR" => 0,
        // the invalidate in front of a memory instruction keeps the memory-pipe spacing
        "CCTL" if is_memory_op(next) => 4,
        // an `ARRIVES` in front of a branch settles first (ptxas: S08, 49 of 49)
        "ARRIVES" if matches!(next, "BRA" | "BRX" | "JMP" | "EXIT" | "RET") => 8,
        _ => c.stall,
    }
}

fn is_memory_op(op: &str) -> bool {
    matches!(op, "LDG" | "LD" | "LDS" | "LDL" | "LDSM" | "STG" | "ST" | "STS" | "STL" | "STSM" | "LDGSTS" | "ATOM" | "ATOMG" | "ATOMS" | "RED" | "REDG")
}

/// Predicate result of a phase check: `(uniform, predicate number)`.
pub fn result_pred(insn: &Instruction) -> Option<(bool, u8)> {
    match classify(insn)?.write_bar {
        WriteBar::Result => match insn.operands.first() {
            Some(Operand::Pred { num, .. }) if *num < 7 => Some((false, *num)),
            Some(Operand::UPred { num, .. }) if *num < 7 => Some((true, *num)),
            _ => None,
        },
        _ => None,
    }
}

/// Every register a synchronisation word reads: `(uniform, number)`; RZ / URZ never count.
/// The words name their operands in forms the generic source scan does not see (an address
/// that is a uniform register alone, a first operand that is a source).
pub fn source_regs(insn: &Instruction) -> Vec<(bool, u16)> {
    let mut out: Vec<(bool, u16)> = Vec::new();
    if never_executes(insn) {
        return out;
    }
    let mut push = |u: bool, r: u16| {
        // RZ is 255, URZ is 63 (and 255 where an address names it: `[R26+URZ]`)
        let zero = if u { r >= 63 } else { r == 255 };
        if !zero && !out.contains(&(u, r)) {
            out.push((u, r));
        }
    };
    for o in insn.operands.iter() {
        match o {
            Operand::Reg { num, .. } => push(false, *num as u16),
            Operand::UReg { num, is_zero, .. } if !*is_zero => push(true, *num as u16),
            Operand::Addr { base_reg, ur_reg, .. } => {
                if let Some(b) = base_reg {
                    push(false, *b as u16);
                }
                if let Some(u) = ur_reg {
                    push(true, *u as u16);
                }
            }
            Operand::Desc { ur_idx, base_reg, .. } => {
                push(true, *ur_idx as u16);
                if let Some(b) = base_reg {
                    push(false, *b as u16);
                }
            }
            _ => {}
        }
    }
    out
}

/// True when the word names its operands itself (see `source_regs`): the generic scan of
/// `scheduling_pass::src_regs` treats operand 0 as a destination.
pub fn owns_operands(insn: &Instruction) -> bool {
    never_executes(insn)
        || matches!(insn.opcode.as_str(), "SYNCS" | "ARRIVES" | "UBLKCP" | "UTMALDG" | "UTMASTG" | "UTMACMDFLUSH" | "LDGDEPBAR" | "DEPBAR" | "FENCE" | "USETMAXREG" | "WARPSYNC")
}

/// The collective region instruction `i` stands in: `(WARPSYNC.COLLECTIVE, ENDCOLLECTIVE)`.
/// The region is straight-line code of a few instructions (a shuffle, or a pad).
pub fn collective_region(insns: &[Instruction], i: usize) -> Option<(usize, usize)> {
    const SPAN: usize = 6;
    let is_entry = |x: &Instruction| x.opcode == "WARPSYNC" && has(x, "COLLECTIVE");
    if is_entry(&insns[i]) || insns[i].opcode == "ENDCOLLECTIVE" {
        return None;
    }
    let straight = |x: &Instruction| !matches!(x.opcode.as_str(), "BRA" | "BRX" | "JMP" | "EXIT" | "RET" | "CALL" | "BSYNC" | "BSSY" | "WARPSYNC" | "ENDCOLLECTIVE");
    let mut a = i;
    loop {
        if a == 0 || i - a >= SPAN {
            return None;
        }
        a -= 1;
        if is_entry(&insns[a]) {
            break;
        }
        if !straight(&insns[a]) {
            return None;
        }
    }
    let mut e = i;
    loop {
        e += 1;
        if e >= insns.len() || e - i > SPAN {
            return None;
        }
        if insns[e].opcode == "ENDCOLLECTIVE" {
            return Some((a, e));
        }
        if !straight(&insns[e]) {
            return None;
        }
    }
}

/// The stall an instruction in front of a collective region carries (ptxas: 7, no yield).
pub const COLLECTIVE_ENTRY_STALL: u8 = 7;
/// The stall of the shuffle inside a collective region (ptxas: 2, with its two barriers).
pub const COLLECTIVE_BODY_STALL: u8 = 2;

/// True when the next instruction opens a collective region.
pub fn enters_collective(insns: &[Instruction], i: usize) -> bool {
    insns.get(i + 1).is_some_and(|x| x.opcode == "WARPSYNC" && has(x, "COLLECTIVE"))
}

/// A control transfer the scheduler has no class for. ptxas issues every transfer at stall 5 or
/// more, with yield (`BRX` 58 of 58 at `[Y:S05]`, `RET`, `CALL`, `BPT`, `BREAK` likewise): the
/// instruction behind a branch must not issue before the branch has resolved. The scheduler's
/// own list (`BRA`, `JMP`, `CALL`, `RET`, `EXIT`, ...) lacks the register-indirect forms -- a
/// `BRX` got an ALU stall of 1 under `CUBIT_SCHED2`, and the warp ran the instruction behind its
/// dispatch (silicon: CUDA_ERROR_ILLEGAL_ADDRESS in every kernel with a jump table).
pub fn is_unlisted_transfer(insn: &Instruction) -> bool {
    matches!(insn.opcode.as_str(), "BRX" | "BRXU" | "JMX" | "JMXU" | "PRET" | "BPT")
}

/// The stall floor of a control transfer.
pub const TRANSFER_STALL: u8 = 5;

/// Words ptxas never puts a wait mask on (the served MoE cubin, 128 528 instructions: `LDGSTS`
/// 0 of 1 163, `SYNCS.ARRIVE*` 0 of 168, the re-check `SYNCS.PHASECHK.TRANS64` 0 of 200, `FENCE`
/// 0 of 27, the never-executed pads 0 of 875): the wait goes on the instruction in front. `CUBIT_SYNC_WAIT_ALL=1` lets them wait
/// (an experiment switch: whether the words can carry a wait is not measured).
pub fn never_waits(insn: &Instruction) -> bool {
    if std::env::var("CUBIT_SYNC_WAIT_ALL").ok().as_deref() == Some("1") {
        return false;
    }
    if never_executes(insn) {
        return true; // a pad under `@!PT` (ptxas: 0 of 875 wait)
    }
    match insn.opcode.as_str() {
        "LDGSTS" | "FENCE" => true,
        "SYNCS" => has(insn, "ARRIVE") || (has(insn, "PHASECHK") && !has(insn, "TRYWAIT")),
        _ => false,
    }
}

/// The operand-reuse flag (`R6.reuse`) under a changed schedule. ptxas sets it only on a word
/// with yield and a stall of 1 or 2 (10 155 of 10 155 reuse words of the served MoE cubin: 7 476
/// at S01, 2 679 at S02; nvdisasm does not even render `.reuse` without the yield bit). A plain
/// instruction text of nvcc carries the flags of ptxas's schedule: where this schedule gives the
/// word another stall the flag is dropped (the operand is read from the register file -- always
/// correct), where it keeps a stall of 1 or 2 the word keeps its yield.
pub fn settle_reuse(insns: &mut [Instruction]) -> usize {
    let mut dropped = 0;
    for ins in insns.iter_mut().filter(|x| !x.hand_sched) {
        let flagged = ins.operands.iter().any(|o| matches!(o, Operand::Reg { reuse: true, .. } | Operand::UReg { reuse: true, .. }));
        if !flagged {
            continue;
        }
        if (1..=2).contains(&ins.ctrl.stall) {
            ins.ctrl.yield_flag = true;
        } else {
            for o in ins.operands.iter_mut() {
                if let Operand::Reg { reuse, .. } | Operand::UReg { reuse, .. } = o {
                    *reuse = false;
                }
            }
            dropped += 1;
        }
    }
    dropped
}

/// A kernel that commits a copy group keeps scoreboard 0 for it.
pub fn commits_group(insn: &Instruction) -> bool {
    matches!(insn.opcode.as_str(), "LDGDEPBAR" | "UTMACMDFLUSH")
}

/// `BAR.SYNC` (and the other `BAR` forms) drain the mbarrier tokens: ptxas waits the init's /
/// `SYNCS.CCTL.IVALL`'s barrier on the `__syncthreads` behind it.
pub fn token_reads(insn: &Instruction) -> Vec<u16> {
    if let Some(c) = classify(insn) {
        return c.waits.to_vec();
    }
    if insn.opcode == "BAR" {
        return vec![TOKEN_MBAR];
    }
    Vec::new()
}

/// The acquire idiom: `CCTL.IVALL` behind a `.STRONG` load / atomic invalidates L1 AFTER the
/// load returned — it waits the load's write barrier. Returns the index of that load.
pub fn acquire_load(insns: &[Instruction], i: usize) -> Option<usize> {
    if insns[i].opcode != "CCTL" || !has(&insns[i], "IVALL") {
        return None;
    }
    let mut k = i;
    let mut steps = 0;
    while k > 0 && steps < 4 {
        k -= 1;
        steps += 1;
        let op = insns[k].opcode.as_str();
        if matches!(op, "LDG" | "LD" | "ATOMG" | "ATOM") && insns[k].opcode_full.contains("STRONG") {
            return Some(k);
        }
        if matches!(op, "BRA" | "BRX" | "JMP" | "EXIT" | "RET" | "CALL" | "BSYNC" | "BSSY" | "MEMBAR" | "CGAERRBAR") {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first(body: &str) -> Instruction {
        let src = format!(".entry t\n    .param u64 io\n{body}    EXIT ;\n.endentry\n");
        let f = crate::sass_file::parse_sass_file_str_strict(&src).unwrap();
        f.kernels[0].instructions[0].clone()
    }

    #[test]
    fn the_phase_check_is_a_scoreboard_result_with_late_operands() {
        let i = first("    SYNCS.PHASECHK.TRANS64.TRYWAIT P3, [R4+URZ], R7 ;\n");
        let c = classify(&i).unwrap();
        assert_eq!(c.write_bar, WriteBar::Result);
        assert!(c.late_operands);
        assert_eq!(c.stall, 2);
        assert_eq!(result_pred(&i), Some((false, 3)));
        let s = source_regs(&i);
        assert!(s.contains(&(false, 4)) && s.contains(&(false, 7)), "{s:?}");
        let j = first("    SYNCS.PHASECHK.TRANS64 P0, [R3+URZ], R0 ;\n");
        assert_eq!(classify(&j).unwrap().write_bar, WriteBar::Result);
    }

    #[test]
    fn arrive_and_init_read_their_operands_late() {
        let a = first("    SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R26+URZ], RZ ;\n");
        let c = classify(&a).unwrap();
        assert_eq!(c.write_bar, WriteBar::None);
        assert!(c.late_operands);
        assert_eq!(source_regs(&a), vec![(false, 26)]);
        let e = first("    SYNCS.EXCH.64 URZ, [UR37], UR4 ;\n");
        let c = classify(&e).unwrap();
        assert_eq!(c.write_bar, WriteBar::Token(TOKEN_MBAR));
        let s = source_regs(&e);
        assert!(s.contains(&(true, 37)) && s.contains(&(true, 4)), "{s:?}");
        let u = first("    ARRIVES.LDGSTSBAR.64.ARVCNT [UR4] ;\n");
        assert_eq!(source_regs(&u), vec![(true, 4)]);
    }

    #[test]
    fn bulk_words() {
        let l = first("    UBLKCP.S.G [UR42], [UR4], UR6 ;\n");
        let c = classify(&l).unwrap();
        assert_eq!((c.stall, c.yield_flag, c.late_operands), (12, false, true));
        assert_eq!(source_regs(&l).len(), 3);
        let s = first("    UBLKCP.G.S [UR38], [UR42], UR4 ;\n");
        assert_eq!(classify(&s).unwrap().stall, 1);
        let f = first("    UTMACMDFLUSH ;\n");
        assert!(classify(&f).unwrap().group_read_bar && commits_group(&f));
        let g = first("    LDGDEPBAR ;\n");
        assert_eq!(classify(&g).unwrap().write_bar, WriteBar::Group);
        let d = first("    DEPBAR.LE SB0, 0x0 ;\n");
        let c = classify(&d).unwrap();
        assert_eq!((c.stall, c.yield_flag), (4, false));
    }

    #[test]
    fn the_release_chain_and_the_acquire() {
        let src = ".entry t\n    .param u64 io\n    MEMBAR.ALL.CTA ;\n    MEMBAR.ALL.GPU ;\n    ERRBAR ;\n    CGAERRBAR ;\n    LDG.E.STRONG.GPU R0, desc[UR6][R4.64] ;\n    CCTL.IVALL ;\n    CCTL.IVALL ;\n    STG.E desc[UR6][R4.64], R0 ;\n    EXIT ;\n.endentry\n";
        let f = crate::sass_file::parse_sass_file_str_strict(src).unwrap();
        let k = &f.kernels[0].instructions;
        let st = |i: usize| stall_of(k, i, &classify(&k[i]).unwrap());
        assert_eq!((st(0), st(1), st(2), st(3)), (0, 6, 0, 6));
        assert_eq!(acquire_load(k, 5), Some(4));
        assert_eq!(st(5), 1);
        assert_eq!(st(6), 4, "in front of a store the invalidate keeps the memory spacing");
        assert_eq!(acquire_load(k, 1), None);
    }

    #[test]
    fn setmaxnreg_and_the_named_arrive() {
        let t = first("    USETMAXREG.TRY_ALLOC.CTAPOOL UP0, 0x68 ;\n");
        assert_eq!(classify(&t).unwrap().write_bar, WriteBar::Result);
        assert_eq!(result_pred(&t), Some((true, 0)));
        let d = first("    USETMAXREG.DEALLOC.CTAPOOL 0x20 ;\n");
        assert_eq!(classify(&d).unwrap().stall, 0);
        let a = first("    BAR.ARV 0x1, 0x400 ;\n");
        assert_eq!(classify(&a).unwrap().stall, 8);
        let s = first("    BAR.SYNC.DEFER_BLOCKING 0x1, 0x400 ;\n");
        assert!(classify(&s).is_none(), "BAR.SYNC keeps the scheduler's existing floor");
        assert_eq!(token_reads(&s), vec![TOKEN_MBAR]);
    }

    #[test]
    fn a_pad_under_not_pt_sets_and_reads_nothing() {
        let p = first("    @!PT LDS RZ, [RZ] ;\n");
        assert!(never_executes(&p));
        let c = classify(&p).unwrap();
        assert_eq!((c.write_bar, c.late_operands, c.stall), (WriteBar::None, false, 1));
        assert!(owns_operands(&p) && source_regs(&p).is_empty());
    }

    #[test]
    fn a_collective_region_is_found_from_its_body() {
        let src = ".entry t\n    .param u64 io\n    MOV R10, 0xffffffff ;\n    MOV R21, R18 ;\n    WARPSYNC.COLLECTIVE R10, L_c ;\nL_c:\n    SHFL.BFLY P6, R18, R19, R16, R17 ;\n    ENDCOLLECTIVE ;\n    SEL R40, R40, R21, !P3 ;\n    EXIT ;\n.endentry\n";
        let f = crate::sass_file::parse_sass_file_str_strict(src).unwrap();
        let k = &f.kernels[0].instructions;
        assert_eq!(collective_region(k, 3), Some((2, 4)));
        assert!(owns_operands(&k[2]), "WARPSYNC.COLLECTIVE R10 reads its mask: no destination");
        assert_eq!(source_regs(&k[2]), vec![(false, 10)]);
        assert_eq!(collective_region(k, 1), None);
        assert_eq!(collective_region(k, 5), None);
        assert!(enters_collective(k, 1) && !enters_collective(k, 0));
    }

    #[test]
    fn a_reuse_flag_follows_the_vendor_law() {
        let src = ".entry t\n    .param u64 io\n    IADD3 R4, PT, PT, R6.reuse, R7, RZ ;\n    IADD3 R5, PT, PT, R6.reuse, R8, RZ ;\n    IADD3 R9, PT, PT, R6, R8, RZ ;\n    EXIT ;\n.endentry\n";
        let mut k = crate::sass_file::parse_sass_file_str_strict(src).unwrap().kernels[0].instructions.clone();
        k[0].ctrl.stall = 2;
        k[0].ctrl.yield_flag = false;
        k[1].ctrl.stall = 5;
        k[1].ctrl.yield_flag = false;
        assert_eq!(settle_reuse(&mut k), 1);
        let reuse = |i: &Instruction| i.operands.iter().any(|o| matches!(o, Operand::Reg { reuse: true, .. }));
        assert!(reuse(&k[0]) && k[0].ctrl.yield_flag, "S02: the flag stays, with yield");
        assert!(!reuse(&k[1]) && !k[1].ctrl.yield_flag && k[1].ctrl.stall == 5, "S05: the flag is dropped, the control code is untouched");
    }

    #[test]
    fn transfers_and_words_that_never_wait() {
        assert!(is_unlisted_transfer(&first("    BRX R50 -0x1330 ;\n")));
        assert!(!is_unlisted_transfer(&first("    BRA.DIV UR4, L_x ;\nL_x:\n")));
        assert!(never_waits(&first("    LDGSTS.E.BYPASS.128 [R41], desc[UR8][R34.64] ;\n")));
        assert!(never_waits(&first("    SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R26+URZ], RZ ;\n")));
        assert!(never_waits(&first("    @!P0 SYNCS.PHASECHK.TRANS64 P0, [R3+URZ], R0 ;\n")));
        assert!(!never_waits(&first("    SYNCS.PHASECHK.TRANS64.TRYWAIT P0, [R3+URZ], R0 ;\n")));
        assert!(!never_waits(&first("    LDS R4, [R5] ;\n")));
    }

    #[test]
    fn ordinary_instructions_have_no_class() {
        for t in ["    IADD3 R4, PT, PT, R4, 0x1, RZ ;\n", "    LDG.E R0, desc[UR6][R4.64] ;\n", "    CCTL.E.RML2 [R4.64] ;\n", "    NOP ;\n"] {
            assert!(classify(&first(t)).is_none(), "{t}");
        }
    }
}
