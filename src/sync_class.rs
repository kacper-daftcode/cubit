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
//! MoE cubin of vLLM-Moet, 36 kernels, and the primitive probe of `docs/SM120_ASYNC_IDIOMS.md`)
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
//! What a plain instruction text of nvcc needs beyond the classes (found on the served MoE
//! kernels `fc1` / `fc2`; "law" = broken ALONE on ptxas's own schedule of the kernel the bits are
//! wrong or the launch faults on sm_120 silicon, "practice" = ptxas never does otherwise but the
//! single break gives identical bits; `docs/SM120_ASYNC_IDIOMS.md`, "What an nvcc kernel needs"):
//!
//! * **law — every definition and use**: the scheduler's operand convention misses the predicate
//!   destination of `LOP3` and the register behind it, the second register of `LDCU.64`,
//!   `UISETP`'s uniform predicate, `R2P` / `P2R`, the high half of a `.64` address base and of a
//!   64-bit register operand (`certified_xfer`, `predicate_register_xfer`, `wide_address_uses`,
//!   `wide_operand_uses`) — a guarded instruction one cycle behind its `LOP3` gives wrong bits
//!   (ptxas: 13), a load one cycle behind the `LEA.HI.X` of its address faults (ptxas: 5);
//! * **law — a reader holds its operands against a fast overwriter** (`hold_need`, a
//!   write-after-read distance no barrier covers): an MMA its source registers for 8 cycles (a
//!   register of its A or B fragment: wrong bits at 2 and at 4, identical at 6; of its accumulator:
//!   wrong at 7), a uniform-datapath instruction its uniform operands for 3 against a `UMOV` (a fault at 1 and at 2);
//! * **law — `F2F` is a scoreboard result** (`unlisted_scoreboard_result`): no variable-latency
//!   list named it; its reader 2 … 15 cycles behind and without a wait gives wrong bits (`BREV`
//!   the same by census);
//! * **law — the collective region** (below): the instruction in front of `WARPSYNC.COLLECTIVE`
//!   at S01 / S02 is an illegal-instruction fault, the region's `SHFL` at S01 gives wrong bits;
//! * practice — a result has landed before the warp's thread set changes (`settle_need`): 7 cycles
//!   for an ALU result, 13 for a predicate, 29 for an MMA in front of `BSYNC` / `CALL` /
//!   `WARPSYNC.COLLECTIVE` / `NANOSLEEP.SYNCS` / `EXIT`, 4 in front of `BRX` / `RET`, an MMA 14 in
//!   front of a conditional branch (11 single-row controls on the register and MMA rows:
//!   identical bits);
//! * practice — control transfers at stall 5 or more with yield (`is_unlisted_transfer`: `BRX`,
//!   `JMX`, `PRET`, `BPT` were ALU instructions for the scheduler; a `BRX` at S01 alone:
//!   identical bits);
//! * practice — a reuse flag only on a word with yield and a stall of 1 or 2 (`settle_reuse`;
//!   10 155 of 10 155 reuse words; ten flags at S03 / S05 without yield: identical bits);
//! * practice — no wait mask on `LDGSTS`, `SYNCS.ARRIVE`, the re-check `SYNCS.PHASECHK`, `FENCE`,
//!   the pads (`never_waits`; 0 of 2 433; such a wait: identical bits).
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
        // cache control on ONE line (`CCTL.E.RML2 [R48]` behind a `.STRONG` load, `CCTL.E.PF2
        // [R4+0x80]`): the address is read late, like a store's -- ptxas puts a read barrier on
        // every one of them (52 of 52 in the two censuses) and the next writer of the address
        // waits it. Without the class the word had no late operand: the next work item's
        // `IMAD.WIDE R48, ...` overwrote the address of a line control still in flight (served
        // fc2: wrong bits with cubit's barriers under the vendor's own stalls).
        "CCTL" if line_address(insn).is_some() => SyncClass::new("cache-line control", 1, true).late(),
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
        // a run of line controls keeps the spacing too (ptxas: `@P1 CCTL.E.RML2 [R48]` ... at S04)
        "CCTL" if next == "CCTL" && line_address(&insns[i]).is_some() => 4,
        // an `ARRIVES` in front of a branch settles first (ptxas: S08, 49 of 49)
        "ARRIVES" if matches!(next, "BRA" | "BRX" | "JMP" | "EXIT" | "RET") => 8,
        _ => c.stall,
    }
}

/// The base register of the line a `CCTL.E.*` word names.
fn line_address(insn: &Instruction) -> Option<u8> {
    insn.operands.iter().find_map(|o| match o {
        Operand::Addr { base_reg: Some(b), .. } if *b != 255 => Some(*b),
        _ => None,
    })
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
                    // the line of a cache control is a 64-bit address without the suffix
                    if insn.opcode == "CCTL" && *b < 254 {
                        push(false, *b as u16 + 1);
                    }
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
/// `BRX` got an ALU stall of 1 under `CUBIT_SCHED2`. ptxas's practice, followed here; alone on
/// ptxas's own schedule of the served `fc1` a `BRX` at S01 gives identical bits (2026-11-10).
pub fn is_unlisted_transfer(insn: &Instruction) -> bool {
    matches!(insn.opcode.as_str(), "BRX" | "BRXU" | "JMX" | "JMXU" | "PRET" | "BPT")
}

/// The stall floor of a control transfer.
pub const TRANSFER_STALL: u8 = 5;

/// Words ptxas never puts a wait mask on (the served MoE cubin, 128 528 instructions: `LDGSTS`
/// 0 of 1 163, `SYNCS.ARRIVE*` 0 of 168, the re-check `SYNCS.PHASECHK.TRANS64` 0 of 200, `FENCE`
/// 0 of 27, the never-executed pads 0 of 875): the wait goes on the instruction in front.
/// Practice, not a law: a wait on every `LDGSTS` (27), `SYNCS.ARRIVE` (4) and re-check (5) of the
/// served `fc1` gives identical bits on silicon. `CUBIT_SYNC_WAIT_ALL=1` lets them wait.
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

/// The operand-reuse flag (`R6.reuse`) under a changed schedule (ptxas's practice, followed
/// conservatively: ten flags at S03 / S05 without yield give identical bits on silicon, which
/// does not show the flag is safe at any stall). ptxas sets it only on a word
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

/// Instructions whose result is a scoreboard result and that the scheduler's variable-latency
/// lists do not name. The lists were learned from cubit's own kernels and a production census;
/// an instruction those corpora do not have, or have rarely, is in none of them and was priced
/// as a fixed-latency instruction with the table's default.
///
/// * **`F2F`** (`F2F.BF16.F32 R17, R88`, the float-format conversion): the served MoE cubin has
///   104, and ptxas reads every one of their results behind a scoreboard wait — 52 carry a write
///   barrier, and the first reader of each of the other 52 waits the barrier of a later `F2F` it
///   reads as well (the conversions complete in issue order; smallest distance 4, never without
///   a wait). cubit had `F2F.BF16.F32 R87, R87 ; ... ; PRMT R16, R16, 0x5410, R87` six cycles
///   apart and no wait, and the served `fc2` packed stale halves into its BF16 output: wrong
///   bits in every call. Silicon, alone on ptxas's own schedule of that kernel (the write
///   barriers of its four barriered `F2F` and the waits of their `PRMT` removed): wrong bits with
///   the reader 2, 6, 9, 12 and 15 cycles behind — no distance replaces the barrier. With `F2F`
///   a scoreboard result the whole `fc2` scheduled by cubit is bit-identical (190 calls).
/// * **`BREV`** — by census only: all 48 of the production census carry a write barrier (cubit:
///   none, stall 5 – 6). No kernel of ours has one and no silicon run exists; the vendor's
///   practice is followed.
///
/// `tools/stallfloor/scoreboard_class_census.py` lists the opcodes whose results a corpus never
/// reads without a scoreboard: `LDG`, `LDCU`, `LDC`, `LD`, `S2R`, `S2UR`, `F2I`, `FLO`, `POPC`,
/// `ATOM`, `ATOMG`, the `SYNCS` results — and these two.
pub fn unlisted_scoreboard_result(op: &str) -> bool {
    matches!(op, "F2F" | "BREV")
}

/// How long a reader HOLDS a source register against a fast overwriter: the minimum issue
/// distance from `reader` to `writer` when `writer` rewrites a register `reader` reads. The
/// vendor covers these two cases by distance, never by a barrier (the censuses of the served MoE
/// cubin and of the 166 production cubins, 1.9 M instructions; `tools/stallfloor/war_census.py`):
///
/// * **an MMA reads its fragment / scale registers over 8 cycles**: a fixed-latency overwriter
///   (`MOV`, `PRMT`, `IADD3`, `SEL`, `F2FP`, `HADD2`, ...) never comes sooner (56 723 sites,
///   16 524 at exactly 8, 28 below in two classes; a load may follow at 1 -- its result lands
///   late), and no MMA carries a read barrier (0 of 39 624). cubit's read barrier on the MMA
///   (`CUBIT_MMA_SRC_RB`) does not hold such an overwriter: `QMMA R56, R96, R26, ... [R0:S02] ;
///   [B0] IADD3 R26, ...` gave wrong bits in the consumer loop of the served fc1;
/// * **a uniform-datapath instruction reads its uniform operands 3 cycles deep against a
///   `UMOV`**, which lands at once: `ULEA UR4, UR5, UR4, 0x18 [S03] ; UMOV UR5, 0xffffffff`
///   (`UIADD3` / `ULEA` / `UIMAD` / `UISETP` / `ULOP3` / `USHF` -> `UMOV`: 3 in every class,
///   2 246 sites, none below; a per-thread reader of the same register may be followed at 1).
///   One cycle there computed the shared-memory address of an mbarrier from 0xffffffff: the
///   ILLEGAL_ADDRESS of the producer loop of the served fc1.
/// * **a store reads the uniform register of its address late** — `STG.E.128 desc[UR4][R22.64],
///   R16 [S02] ; BSYNC [S05] ; UMOV UR4, 0xffffffff`: where no word waits the store's read
///   barrier the vendor rewrites it from 7 issue cycles on (the flow view over the ptxas census:
///   656 such rewrites at 7 or more, 82 at exactly 7; 14 stand closer -- one `ULOP3` at 3 behind
///   an `STS.128`, the same place in 14 builds). A fixed-latency writer of the register keeps 7,
///   whatever its opcode; a scoreboarded one lands late (KNOWN_ISSUES A45).
pub fn hold_need(reader: &Instruction, writer: &Instruction, key: RegKey) -> Option<u8> {
    let (uniform, k) = key;
    let w = writer.opcode.as_str();
    if !uniform && k < 255 && crate::scheduling_pass::is_warp_mma(reader.opcode.as_str()) {
        let slow = crate::scheduling_pass::is_long_latency(w)
            || writer.ctrl.write_bar != 7
            || crate::scheduling_pass::is_warp_mma(w)
            || classify(writer).is_some();
        return if slow { None } else { Some(MMA_OPERAND_HOLD) };
    }
    // a store reads the uniform register of its address — the descriptor of a global store, the
    // uniform base of a shared one — when the memory pipe serves it, like its general registers;
    // the read barrier it carries is waited by the overwriters of those, and a uniform register
    // is not among them. The vendor's schedules keep a rewrite of it 7 issue cycles behind the
    // store where nothing waits the barrier (the flow view over the ptxas census: 656 such
    // rewrites at 7 or more, 82 at exactly 7; 14 closer, one `ULOP3` at 3 in 14 builds). The rule
    // is the safe side of that practice: 7 for every fixed-latency writer (KNOWN_ISSUES A45).
    if uniform && k < 63 && crate::scheduling_pass::is_store(reader.opcode.as_str()) {
        let slow = crate::scheduling_pass::is_long_latency(w) || writer.ctrl.write_bar != 7 || classify(writer).is_some();
        return if slow { None } else { Some(STORE_UNIFORM_OPERAND_HOLD) };
    }
    // `CUBIT_WAIT_POLICY`: a plain shared load carries no read barrier for a base that a younger
    // plain shared load rewrites (`LDS R151, [R153+0x3300] ; LDS R153, [R153+0x3320]`); the
    // younger load stands 4 issue cycles behind it or later, the vendor's smallest distance in
    // every pair of the kind.
    if !uniform
        && k < 255
        && crate::scheduling_pass::wait_policy()
        && reader.opcode_full == "LDS"
        && writer.opcode_full == "LDS"
        && reader.ctrl.read_bar == 7
        && reader.guard.as_ref().is_none_or(|g| g.pred >= 7)
    {
        return Some(SHARED_LOAD_BASE_HOLD);
    }
    if uniform && k < 64 && w == "UMOV" {
        let r = reader.opcode.as_str();
        // (`ISETP` on a uniform operand keeps 3 as well: 44 + 6 sites, none below; `IADD3`,
        // `IMAD`, `LEA`, `MOV`, a load, an MMA are followed at 1)
        let uniform_pipe = (r.starts_with('U') && r != "UMOV" && classify(reader).is_none()) || r == "ISETP";
        return if uniform_pipe { Some(UNIFORM_OPERAND_HOLD) } else { None };
    }
    None
}

/// The uniform registers of a store's address: the descriptor of `desc[URn][Ra.64]`, the uniform
/// base of `[URn+imm]` / `[Ra+URn+imm]` (the scheduler's convention does not list the base of
/// the form without a general register). Empty for a word that is not a store.
pub fn store_uniform_operands(insn: &Instruction) -> Vec<RegKey> {
    let mut out: Vec<RegKey> = Vec::new();
    if !crate::scheduling_pass::is_store(insn.opcode.as_str()) {
        return out;
    }
    for o in &insn.operands {
        let u = match o {
            Operand::Desc { ur_idx, .. } => Some(*ur_idx),
            Operand::Addr { ur_reg: Some(u), .. } => Some(*u),
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

/// An MMA's source registers are read over this many issue cycles.
pub const MMA_OPERAND_HOLD: u8 = 8;
/// A uniform-datapath reader against a `UMOV` of one of its operands.
pub const UNIFORM_OPERAND_HOLD: u8 = 3;
/// A store against a fixed-latency rewrite of the uniform register of its address (the vendor's
/// smallest distance; no measurement below it).
pub const STORE_UNIFORM_OPERAND_HOLD: u8 = 7;
/// A plain shared load without a read barrier against a younger plain shared load that rewrites
/// its base register (`CUBIT_WAIT_POLICY`): the vendor's smallest distance. Measured right from
/// 1 cycle on two card models; the rule keeps the vendor's 4.
pub const SHARED_LOAD_BASE_HOLD: u8 = 4;

/// Raises stalls until every overwriter stands `hold_need` cycles behind the readers in front of
/// it on the straight-line text (a transfer that cannot fall through ends the walk; the stall of
/// the last schedulable instruction in front of the overwriter carries the difference). Runs
/// behind the stall model and the latency legaliser: a longer stall breaks none of their
/// distances. Returns `(overwriters moved, cycles added)`.
pub fn hold_operands(insns: &mut [Instruction]) -> (usize, u32) {
    const WINDOW: usize = 12;
    let (mut moved, mut cycles) = (0usize, 0u32);
    for j in 1..insns.len() {
        let defs = crate::scheduling_pass::dest_regs(&insns[j]);
        if defs.is_empty() {
            continue;
        }
        let mut short: u8 = 0;
        let mut d: u32 = 0;
        for i in (j.saturating_sub(WINDOW)..j).rev() {
            d += insns[i].ctrl.stall as u32;
            if d >= MMA_OPERAND_HOLD as u32 {
                break;
            }
            let op = insns[i].opcode.as_str();
            if matches!(op, "EXIT" | "RET" | "BRX" | "JMX") || (op == "BRA" && !crate::cfg_flow::is_conditional(&insns[i])) {
                break;
            }
            let mut uses = crate::scheduling_pass::src_regs(&insns[i]);
            for k in store_uniform_operands(&insns[i]) {
                if !uses.contains(&k) {
                    uses.push(k);
                }
            }
            for key in defs.iter().filter(|k| uses.contains(k)) {
                if let Some(h) = hold_need(&insns[i], &insns[j], *key) {
                    if (h as u32) > d {
                        short = short.max((h as u32 - d) as u8);
                    }
                }
            }
        }
        if short == 0 {
            continue;
        }
        // the nearest instruction in front of the overwriter that this schedule owns
        let Some(c) = (j.saturating_sub(WINDOW)..j).rev().find(|&c| !insns[c].hand_sched && insns[c].ctrl.stall as u32 + short as u32 <= 15) else {
            continue;
        };
        insns[c].ctrl.stall += short;
        if insns[c].ctrl.stall >= 12 {
            insns[c].ctrl.yield_flag = false;
        }
        moved += 1;
        cycles += short as u32;
    }
    (moved, cycles)
}

/// A register key of the scheduler: `(uniform, key)`.
pub type RegKey = (bool, u16);
/// `(definitions, uses)` of one instruction.
pub type Xfer = (Vec<RegKey>, Vec<RegKey>);

/// Definitions and uses the certified transfer functions (`reg_liveness::reg_xfer`,
/// `pred_liveness::pred_xfer`) list for `insn` — `(uniform, key)` in the scheduler's key space
/// (GPR number, `256 + predicate`, uniform register number, `64 + uniform predicate`). `None` when
/// either function does not know the instruction's family.
///
/// The scheduler's own operand convention (`scheduling_pass::dest_regs` / `src_regs`) was written
/// for cubit's kernels: it takes operand 0 for the destination and knows a short list of
/// predicate writers. An instruction of nvcc such as `LOP3.LUT P4, RZ, R21, 0x7fffff, RZ, 0xc0, !PT`
/// (a predicate AND a register destination) had no destination at all for it: the guarded
/// instruction behind it was scheduled one cycle later (ptxas: 13) and ran on the stale
/// predicate. Under the switch the two functions take the union with these sets.
pub fn certified_xfer(insn: &Instruction) -> Option<Xfer> {
    use crate::pred_liveness::{pred_xfer, XferMode};
    let rx = crate::reg_liveness::reg_xfer(insn);
    let px = pred_xfer(insn, XferMode::Strict);
    if !rx.known || !px.known {
        return None;
    }
    const PRED_KEY: u16 = 256;
    let mut defs: Vec<(bool, u16)> = Vec::new();
    let mut uses: Vec<(bool, u16)> = Vec::new();
    defs.extend(rx.rdefs.iter().filter(|r| **r != 255).map(|r| (false, *r as u16)));
    defs.extend(rx.udefs.iter().filter(|r| **r != 63).map(|r| (true, *r as u16)));
    defs.extend(px.defs.iter().map(|p| (false, PRED_KEY + *p as u16)));
    defs.extend(px.udefs.iter().map(|p| (true, 64 + *p as u16)));
    uses.extend(rx.ruses.iter().filter(|r| **r != 255).map(|r| (false, *r as u16)));
    uses.extend(rx.uuses.iter().filter(|r| **r != 63).map(|r| (true, *r as u16)));
    uses.extend(px.uses.iter().map(|p| (false, PRED_KEY + *p as u16)));
    uses.extend(px.uuses.iter().map(|p| (true, 64 + *p as u16)));
    // `LOP3.LUT Pd, Rd, Ra, Rb, Rc, lut, Pin` / `ULOP3.LUT UPd, URd, ...`: the register behind the
    // predicate destination is the result register (RZ when only the predicate is wanted), not a
    // source -- `reg_xfer` lists it as a use. ptxas: `[S04] LOP3.LUT P5, R4, R31, 0xff, RZ, 0xc0, !PT`
    // in front of `IADD3 R4, PT, PT, -R4, 0x7f, RZ`.
    if matches!(insn.opcode.as_str(), "LOP3" | "ULOP3") {
        match (insn.operands.first(), insn.operands.get(1)) {
            (Some(Operand::Pred { .. }), Some(Operand::Reg { num, .. })) if *num != 255 => {
                let k = (false, *num as u16);
                let read_elsewhere = insn.operands.iter().skip(2).any(|o| matches!(o, Operand::Reg { num: n, .. } if n == num));
                if !read_elsewhere {
                    uses.retain(|x| *x != k);
                }
                if !defs.contains(&k) {
                    defs.push(k);
                }
            }
            (Some(Operand::UPred { .. }), Some(Operand::UReg { num, is_zero: false, .. })) => {
                let k = (true, *num as u16);
                let read_elsewhere = insn.operands.iter().skip(2).any(|o| matches!(o, Operand::UReg { num: n, .. } if n == num));
                if !read_elsewhere {
                    uses.retain(|x| *x != k);
                }
                if !defs.contains(&k) {
                    defs.push(k);
                }
            }
            _ => {}
        }
    }
    Some((defs, uses))
}

/// The predicate register as a whole: `R2P PR, R, mask` writes the predicates of its mask,
/// `P2R R, PR, R, mask` reads them (no family rule in the certified functions; the scheduler's
/// convention sees neither). Returns `(written, read)` predicate numbers.
pub fn predicate_register_xfer(insn: &Instruction) -> (Vec<u8>, Vec<u8>) {
    let op = insn.opcode.as_str();
    if op != "R2P" && op != "P2R" {
        return (Vec::new(), Vec::new());
    }
    let mask = insn
        .operands
        .iter()
        .rev()
        .find_map(|o| match o {
            Operand::Imm32(v) => Some(*v as u32),
            _ => None,
        })
        .unwrap_or(0x7f);
    let preds: Vec<u8> = (0..7u8).filter(|p| mask & (1 << p) != 0).collect();
    if op == "R2P" {
        (preds, Vec::new())
    } else {
        (Vec::new(), preds)
    }
}

/// What has to have landed before a word that changes the warp's thread set or transfers control
/// through a register: the minimum issue distance from a fixed-latency result in flight to `word`.
///
/// ptxas keeps it everywhere (the served MoE cubin; nearest producer in front of the word on the
/// straight-line text): in front of `BSYNC[.RECONVERGENT]`, `CALL`, `WARPSYNC.COLLECTIVE` and
/// `NANOSLEEP.SYNCS` the last ALU result is 7 cycles old (1 170 / 828 / 167 / 1 938 / 180 sites,
/// never less; 376 + 161 + 1 938 + 180 exactly 7), a predicate 13, an MMA 29 (47 sites, 35 at
/// exactly 29); in front of `BRX` / `RET` an ALU result 4 (58 / 13 sites, all exactly 4); in
/// front of a conditional `BRA` an MMA 14 (166 sites, 53 at exactly 14) — the `NOP [S13]` /
/// `@!P6 BRA [S15]` behind a QMMA in ptxas's consumer loops is these two rows.
///
/// **ptxas's practice, not a law of the silicon** where it could be tested: broken alone on
/// ptxas's own schedule of the served `fc1` / `fc2` (the stall in front of the word moved behind
/// it) — a register result 1 / 4 cycles in front of `BSYNC.RECONVERGENT` (both kernels; in
/// `fc2`'s chain of per-thread branches the warp really splits and rejoins), 6 / 2 in front of
/// `BSYNC`, a `QMMA` 8 / 2 (`fc1`) and 6 / 7 (`fc2`) cycles in front of a guarded `BRA`, 19 in
/// front of `BSYNC` (both) — 11 controls, identical bits in 10 of 10 calls each (test host,
/// 2026-11-10). Not tested alone: the predicate rows, `CALL`, `NANOSLEEP.SYNCS`, `EXIT`; the
/// `BRX` / `RET` row is the transfer's own 64-bit operand (`wide_operand_uses`); the entry of a
/// collective region has a measured floor of 3 (`COLLECTIVE_ENTRY_STALL` keeps ptxas's 7). The
/// scheduler keeps the rows under the switch because ptxas has no site below them in 1.9 M
/// instructions — a schedule below the vendor's minimum has run nowhere else; they are not what
/// made the first cubit schedules of these kernels fault (that was the operand model and the
/// operand hold above).
pub fn settle_need(word: &Instruction, what: Landing) -> Option<u8> {
    let op = word.opcode.as_str();
    let row = |reg: u8, pred: u8, mma: u8| -> Option<u8> {
        Some(match what {
            Landing::Register => reg,
            Landing::Predicate => pred,
            Landing::Mma => mma,
        })
    };
    match op {
        "BSYNC" | "CALL" | "BREAK" => row(7, 13, 29),
        "WARPSYNC" if has(word, "COLLECTIVE") => row(7, 13, 29),
        "NANOSLEEP" if has(word, "SYNCS") => row(7, 13, 29),
        "EXIT" => row(6, 13, 29),
        "BRX" | "BRXU" | "JMX" | "JMXU" | "RET" | "PRET" => row(4, 4, 14),
        // a conditional branch splits the warp: a cooperative MMA has to be through
        "BRA" if what == Landing::Mma && crate::cfg_flow::is_conditional(word) => Some(14),
        _ => None,
    }
}

/// What is in flight in front of a settle word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Landing {
    /// a register or uniform-register result of a fixed-latency instruction
    Register,
    /// a predicate / uniform-predicate result
    Predicate,
    /// the accumulator of a warp-cooperative MMA
    Mma,
}

/// True for a word `settle_need` has a row for.
pub fn is_settle_word(word: &Instruction) -> bool {
    matches!(word.opcode.as_str(), "BSYNC" | "CALL" | "EXIT" | "BREAK" | "BRX" | "BRXU" | "JMX" | "JMXU" | "RET" | "PRET" | "BRA")
        || (word.opcode == "WARPSYNC" && has(word, "COLLECTIVE"))
        || (word.opcode == "NANOSLEEP" && has(word, "SYNCS"))
}

/// The registers of a 64-bit address that neither the scheduler's convention nor `reg_xfer`
/// lists: the HIGH half of a `.64` base (`desc[UR8][R4.64]` reads R4 and R5) and the second
/// uniform register of the descriptor (`LDCU.64 UR8` fills UR8:UR9). nvcc builds the base as
/// `LEA R4, P2, ... ; LEA.HI.X R5, ..., P2 ; LDG ... [R4.64]`: without the use the load was issued
/// ONE cycle behind the `LEA.HI.X` (ptxas: never below 5 in 34 581 sites of the two censuses) and
/// read a stale upper half of its address. Silicon: that one distance alone on ptxas's schedule
/// of the served `fc1` is CUDA_ERROR_ILLEGAL_ADDRESS.
pub fn wide_address_uses(insn: &Instruction) -> Vec<(bool, u16)> {
    let mut out: Vec<(bool, u16)> = Vec::new();
    for o in insn.operands.iter() {
        match o {
            Operand::Addr { base_reg: Some(b), base_reg_suffix: Some(sfx), .. } if sfx.contains("64") && *b < 254 => out.push((false, *b as u16 + 1)),
            Operand::Desc { ur_idx, base_reg, base_reg_suffix, .. } => {
                if let (Some(b), Some(sfx)) = (base_reg, base_reg_suffix) {
                    if sfx.contains("64") && *b < 254 {
                        out.push((false, *b as u16 + 1));
                    }
                }
                if *ur_idx < 62 {
                    out.push((true, *ur_idx as u16 + 1));
                }
            }
            _ => {}
        }
    }
    out
}

/// The HIGH half of a 64-bit REGISTER operand, which neither the scheduler's convention nor the
/// certified functions list (`IADD.64` has no family rule at all): `IADD.64 R28, R28, UR4` reads
/// R28:R29 and UR4:UR5, `ISETP.GT.U64.AND P0, PT, R14, UR6, PT` reads R14:R15 and UR6:UR7,
/// `MOV.64 R34, UR4` reads UR4:UR5, `BRX R44 -0xe50` / `RET.REL.NODEC R152 0x0` read the 64-bit
/// target R44:R45. nvcc builds the high half with its own instruction
/// (`SHF.L.U64.HI R29, R26, 0x2, R27 ; IADD.64 R28, R28, UR4`, `SHF.R.S32.HI R45, RZ, 0x1f, R44 ;
/// BRX R44`): without the use the add was issued ONE cycle behind the shift (ptxas: never below 5
/// in 15 681 sites of the two censuses; a `BRX` / `RET` target 4). The law of `wide_address_uses`
/// for an operand instead of an address base; its silicon run is the address form's (this form
/// has no single-distance control of its own).
pub fn wide_operand_uses(insn: &Instruction) -> Vec<(bool, u16)> {
    let op = insn.opcode.as_str();
    let wide = |full: &str| full.split('.').any(|m| m == "64" || m == "U64" || m == "S64");
    // (64-bit operands, the destination is operand 0)
    let (is_wide, skip_dest) = match op {
        "IADD" | "MOV" | "UMOV" | "SEL" | "USEL" | "UIADD3" | "I2F" => (wide(insn.opcode_full.as_str()), true),
        "ISETP" | "UISETP" => (wide(insn.opcode_full.as_str()), false),
        "BRX" | "JMX" | "RET" => (true, false),
        _ => (false, false),
    };
    if !is_wide {
        return Vec::new();
    }
    let mut out: Vec<(bool, u16)> = Vec::new();
    let mut first_reg = skip_dest;
    for o in insn.operands.iter() {
        match o {
            Operand::Reg { num, .. } => {
                if std::mem::take(&mut first_reg) {
                    continue;
                }
                if *num < 254 && !out.contains(&(false, *num as u16 + 1)) {
                    out.push((false, *num as u16 + 1));
                }
            }
            Operand::UReg { num, is_zero, .. } => {
                if std::mem::take(&mut first_reg) {
                    continue;
                }
                if !*is_zero && *num < 62 && !out.contains(&(true, *num as u16 + 1)) {
                    out.push((true, *num as u16 + 1));
                }
            }
            _ => {}
        }
    }
    out
}

/// The scheduler's view of `insn` under the current switches: `(definitions, uses)` (for
/// `examples/opgaps.rs --dump`).
pub fn scheduler_xfer(insn: &Instruction) -> Xfer {
    (crate::scheduling_pass::dest_regs(insn), crate::scheduling_pass::src_regs(insn))
}

/// What the scheduler's operand convention misses against `certified_xfer`: `(missing
/// definitions, missing uses)` (a census tool: `examples/opgaps.rs`).
pub fn operand_gaps(insn: &Instruction) -> Xfer {
    let Some((defs, uses)) = certified_xfer(insn) else { return (Vec::new(), Vec::new()) };
    let d = crate::scheduling_pass::dest_regs_plain(insn);
    let u = crate::scheduling_pass::src_regs_plain(insn);
    (defs.into_iter().filter(|k| !d.contains(k)).collect(), uses.into_iter().filter(|k| !u.contains(k)).collect())
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

    /// The third reader of the operand hold: a store, for the uniform register of its address, against a
    /// fixed-latency writer.
    #[test]
    fn the_hold_names_the_uniform_registers_of_a_store_and_fixed_latency_writers_only() {
        let ins = |s: &str| crate::parse_sass(s, 0).unwrap();
        assert_eq!(STORE_UNIFORM_OPERAND_HOLD, 7);
        assert_eq!(store_uniform_operands(&ins("STG.E.128 desc[UR4][R22.64], R16")), [(true, 4)]);
        assert_eq!(store_uniform_operands(&ins("STS.128 [UR4+0x10], R8")), [(true, 4)]);
        assert_eq!(store_uniform_operands(&ins("STS [R20+UR5+0x20], R6")), [(true, 5)]);
        assert_eq!(store_uniform_operands(&ins("STS [R20+0x20], R6")), []);
        assert_eq!(store_uniform_operands(&ins("LDG.E R4, desc[UR4][R2.64]")), [], "a load is not a store");
        let store = ins("@P0 STG.E.128 desc[UR4][R22.64], R16");
        assert_eq!(hold_need(&store, &ins("UMOV UR4, 0xffffffff"), (true, 4)), Some(7));
        assert_eq!(hold_need(&store, &ins("R2UR UR4, R20"), (true, 4)), Some(7));
        assert_eq!(hold_need(&store, &ins("UIADD3 UR4, UPT, UPT, UR4, 0x1, URZ"), (true, 4)), Some(7));
        // a load of the register lands late: no distance is asked of it
        assert_eq!(hold_need(&store, &ins("LDCU.64 UR4, c[0x0][0x358]"), (true, 4)), None);
        // the store's general registers are the read barrier's, not the hold's
        assert_eq!(hold_need(&store, &ins("MOV R22, RZ"), (false, 22)), None);
        // a load that reads the descriptor is followed at once, as before; the uniform datapath keeps its 3
        assert_eq!(hold_need(&ins("LDG.E R4, desc[UR4][R2.64]"), &ins("UMOV UR4, 0x400"), (true, 4)), None);
        assert_eq!(hold_need(&ins("ULEA UR4, UR5, UR4, 0x18"), &ins("UMOV UR5, 0xffffffff"), (true, 5)), Some(UNIFORM_OPERAND_HOLD));
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
        assert!(!never_waits(&first("    BRX R50 -0x1330 ;\n")), "a dispatch directly behind its load waits itself");
        assert!(!is_unlisted_transfer(&first("    BRA.DIV UR4, L_x ;\nL_x:\n")));
        assert!(never_waits(&first("    LDGSTS.E.BYPASS.128 [R41], desc[UR8][R34.64] ;\n")));
        assert!(never_waits(&first("    SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R26+URZ], RZ ;\n")));
        assert!(never_waits(&first("    @!P0 SYNCS.PHASECHK.TRANS64 P0, [R3+URZ], R0 ;\n")));
        assert!(!never_waits(&first("    SYNCS.PHASECHK.TRANS64.TRYWAIT P0, [R3+URZ], R0 ;\n")));
        assert!(!never_waits(&first("    LDS R4, [R5] ;\n")));
        // what the vendor scoreboards and no list of the scheduler names
        assert!(unlisted_scoreboard_result(first("    F2F.BF16.F32 R17, R88 ;\n").opcode.as_str()));
        assert!(unlisted_scoreboard_result(first("    BREV R5, R4 ;\n").opcode.as_str()));
        assert!(!unlisted_scoreboard_result(first("    F2FP.BF16.F32.PACK_AB R17, R88, R89 ;\n").opcode.as_str()));
    }

    #[test]
    fn the_certified_sets_complete_the_operand_convention() {
        const P: u16 = 256;
        // a predicate destination, and the register behind it
        let (d, u) = certified_xfer(&first("    LOP3.LUT P4, RZ, R21, 0x7fffff, RZ, 0xc0, !PT ;\n")).unwrap();
        assert_eq!((d, u), (vec![(false, P + 4)], vec![(false, 21)]));
        let (d, u) = certified_xfer(&first("    LOP3.LUT P5, R4, R31, 0xff, RZ, 0xc0, !PT ;\n")).unwrap();
        assert!(d.contains(&(false, P + 5)) && d.contains(&(false, 4)), "{d:?}");
        assert_eq!(u, vec![(false, 31)], "the result register is not a source");
        // the second register of a 64-bit uniform load, a uniform predicate
        let (d, _) = certified_xfer(&first("    LDCU.64 UR16, c[0x0][0x358] ;\n")).unwrap();
        assert_eq!(d, vec![(true, 16), (true, 17)]);
        let (d, u) = certified_xfer(&first("    UISETP.NE.AND UP0, UPT, UR8, 0x3, UPT ;\n")).unwrap();
        assert_eq!((d, u), (vec![(true, 64)], vec![(true, 8)]));
        // what has to land before a reconvergence point / a dispatch
        use Landing::{Mma, Predicate, Register};
        let bsync = first("    BSYNC.RECONVERGENT B2 ;\n");
        assert_eq!((settle_need(&bsync, Register), settle_need(&bsync, Predicate), settle_need(&bsync, Mma)), (Some(7), Some(13), Some(29)));
        assert_eq!(settle_need(&first("    BRX R50 -0x1330 ;\n"), Register), Some(4));
        assert_eq!(settle_need(&first("    EXIT ;\n"), Register), Some(6));
        let bra = first("    @!P6 BRA L_x ;\nL_x:\n");
        assert_eq!((settle_need(&bra, Mma), settle_need(&bra, Register)), (Some(14), None));
        assert_eq!(settle_need(&first("    BRA L_x ;\nL_x:\n"), Mma), None, "an unconditional branch does not split the warp");
        assert_eq!(settle_need(&first("    BSSY B0, L_x ;\nL_x:\n"), Register), None);
        // the high half of a 64-bit address base, the descriptor's second register
        assert_eq!(wide_address_uses(&first("    LDG.E.CONSTANT R7, desc[UR8][R4.64] ;\n")), vec![(false, 5), (true, 9)]);
        assert_eq!(wide_address_uses(&first("    LDS R7, [R4+0x10] ;\n")), vec![]);
        // the high half of a 64-bit register operand (the destination is not a source)
        assert_eq!(wide_operand_uses(&first("    IADD.64 R28, R28, UR4 ;\n")), vec![(false, 29), (true, 5)]);
        assert_eq!(wide_operand_uses(&first("    IADD.64 R32, R32, 0x8 ;\n")), vec![(false, 33)]);
        assert_eq!(wide_operand_uses(&first("    ISETP.GT.U64.AND P0, PT, R14, UR6, PT ;\n")), vec![(false, 15), (true, 7)]);
        assert_eq!(wide_operand_uses(&first("    ISETP.NE.S64.AND P0, PT, RZ, UR6, PT ;\n")), vec![(true, 7)]);
        assert_eq!(wide_operand_uses(&first("    MOV.64 R34, UR4 ;\n")), vec![(true, 5)]);
        assert_eq!(wide_operand_uses(&first("    BRX R44 -0xe50 ;\n")), vec![(false, 45)]);
        assert_eq!(wide_operand_uses(&first("    IADD3 R28, PT, PT, R28, R4, RZ ;\n")), vec![]);
        assert_eq!(wide_operand_uses(&first("    ISETP.GE.AND P0, PT, R22, UR24, PT ;\n")), vec![]);
        // what a reader holds its operands for: an MMA 8 cycles against an ALU overwriter (a load may
        // follow at once), a uniform-datapath reader 3 against a UMOV
        let qmma = first("    QMMA.SF.16832.F32.E4M3.E2M1.E8 R56, R96, R26, R56, R164, R152, UR4 ;\n");
        assert_eq!(hold_need(&qmma, &first("    IADD3 R26, PT, PT, R149, 0x1, RZ ;\n"), (false, 26)), Some(8));
        assert_eq!(hold_need(&qmma, &first("    LDS R26, [R161] ;\n"), (false, 26)), None);
        let ulea = first("    ULEA UR4, UR5, UR4, 0x18 ;\n");
        assert_eq!(hold_need(&ulea, &first("    UMOV UR5, 0xffffffff ;\n"), (true, 5)), Some(3));
        assert_eq!(hold_need(&ulea, &first("    USHF.L.U32 UR5, UR6, 0x8, URZ ;\n"), (true, 5)), None);
        assert_eq!(hold_need(&first("    LEA R65, R13, UR5, 0x3 ;\n"), &first("    UMOV UR5, 0xffffffff ;\n"), (true, 5)), None);
        // the predicate register
        assert_eq!(predicate_register_xfer(&first("    R2P PR, R72, 0x7e ;\n")), (vec![1, 2, 3, 4, 5, 6], vec![]));
        assert_eq!(predicate_register_xfer(&first("    P2R R37, PR, RZ, 0x20 ;\n")), (vec![], vec![5]));
        // what the scheduler's own convention misses of them
        let (md, _) = operand_gaps(&first("    LOP3.LUT P4, RZ, R21, 0x7fffff, RZ, 0xc0, !PT ;\n"));
        assert_eq!(md, vec![(false, P + 4)], "LOP3 with a predicate destination has no destination for the plain convention");
    }

    #[test]
    fn ordinary_instructions_have_no_class() {
        for t in ["    IADD3 R4, PT, PT, R4, 0x1, RZ ;\n", "    LDG.E R0, desc[UR6][R4.64] ;\n", "    NOP ;\n"] {
            assert!(classify(&first(t)).is_none(), "{t}");
        }
        // a cache control on one line reads its address late (both halves)
        let c = classify(&first("    @P1 CCTL.E.RML2 [R48] ;\n")).unwrap();
        assert_eq!((c.name, c.late_operands, c.write_bar), ("cache-line control", true, WriteBar::None));
        assert_eq!(source_regs(&first("    @P1 CCTL.E.RML2 [R48] ;\n")), vec![(false, 48), (false, 49)]);
        assert_eq!(classify(&first("    CCTL.IVALL ;\n")).unwrap().name, "L1 invalidate");
    }
}
