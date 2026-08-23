//! Scheduling pass: register dependency tracking, barrier allocation,
//! stall-count computation, and convergence-barrier assignment.
//!
//! Replaces the simple single-barrier pass with a proper multi-barrier
//! scheduler modeled after ptxas behavior on SM120.
//!
//! When an `IsaTable` is provided, per-InsKey `ctrl_class` information
//! is used to enforce hardware-verified scheduling constraints:
//! - MUFU: wait_mask forbidden (corrupts TABLES_opex_0 decode)
//! - IADD3+RZ: wait_mask and write_bar forbidden (hi[7:0]=0xFF forced)
//! - Correct long-latency detection (write_bar assignment) per class

use crate::ctrl_class::{CtrlClass, iadd3_rc2_is_rz};
use crate::ir::{Instruction, Operand};
use crate::table::IsaTable;

// ── Latency model (SM120 / Blackwell) ────────────────────────────────────────

const LATENCY_ALU: u8 = 4;      // IADD3, LOP3, SHF, SEL, MOV, PRMT
const LATENCY_FMA: u8 = 5;      // IMAD, LEA, FFMA, FMUL, FADD
const LATENCY_FP64: u8 = 8;     // DFMA, DMUL, DADD
const LATENCY_PRED: u8 = 13;    // ISETP, FSETP — predicate write (consumed by ALU)
const LATENCY_PRED_BRANCH: u8 = 9; // ISETP/UISETP whose predicate is consumed by a branch
const STORE_LATCH: u8 = 9;      // store operand-latch latency across a loop back-edge (WAR)
const LOAD_LOOPCARRY_STALL: u8 = 10; // load whose result is loop-carried: retire before back-edge
const LATENCY_CTRL: u8 = 5;     // EXIT, BRA, RET
const LATENCY_S2R: u8 = 4;      // S2R, CS2R
// Stores latch their source operands (address + data) a few cycles after issue.
// A following writer of a store source reg (pointer bump / accumulator re-zero)
// must be held off this long so the store reads the intended values (WAR).
const STORE_OPERAND_READ_STALL: u8 = 4;
// Empirically measured on SM120: IADD3 carry-pred → @P BRA requires ~10 cycles.
// This is higher than the ALU data latency (4 cycles) because the branch
// predicate evaluation pipeline has extra stages.
// Note: 9 is insufficient (BRA reads P1 one cycle before it's available),
// causing the loop to always use the stale P1 value (0 from ISETP) and run 0 times.
const LATENCY_CARRY_PRED_BRANCH: u8 = 10;

fn is_long_latency(op: &str) -> bool {
    matches!(op,
        "LDG" | "LDL" | "LDS" | "LDC" | "LDCU" | "LDGX" | "LDSM" | "LDGSTS" |
        "LD"  | "LDGDEPBAR" |
        "S2R" | "CS2R" | "LEPC" | "GETLMEMBASE" |
        "TEX" | "TLD" | "TXQ" |
        "ATOM" | "ATOMS" | "ATOMG" | "RED" | "REDG" |
        "REDUX" | // warp reduction -> uniform reg; long-latency, requires a write barrier
        "SHFL"    // cross-lane shuffle -> register; long-latency, requires a write barrier
    )
}

/// tcgen05 / uniform-datapath control ops whose result arrives asynchronously
/// (SM103a F1): UTCATOMSWS.* returns (UP, UR) — the TMEM bitmap find/set completes
/// unboundedly late (pool contention in the retry loop). Without a scoreboard write
/// barrier a consumer reads the STALE UP/UR (observed: UP0=0 on the first attempt ->
/// the retry re-enters FIND_AND_SET while the in-flight one completes -> ILLEGAL_
/// INSTRUCTION). nvcc/ptxas assigns these a write barrier and puts the matching wait
/// bit on every UR/UP consumer (probe.cubin: wbar=4/0 on the op, wait bit4/bit0 on the
/// consuming IMAD.U32; the UR4 consumer covers BRA.U UP0 transitively). LDTM returns
/// GPRs from TMEM with the same async behavior (nvcc: wbar on LDTM, waited consumers),
/// so it belongs to the same producer class.
fn is_udp_async_result(op: &str) -> bool {
    matches!(op, "UTCATOMSWS" | "LDTM")
}

fn is_store(op: &str) -> bool {
    matches!(op, "STG" | "STS" | "STL" | "ST" | "STGX")
}

/// Data (non-address) source GPRs of a store — the values it latches asynchronously a
/// few cycles AFTER issue. A later writer of one of these before the latch is a store-
/// operand WAR (the store commits stale data); ptxas protects it with a read-barrier on
/// the store (e.g. the `STS.64_AR` gather-address staging). Excludes the address base.
fn store_data_gprs(insn: &Instruction) -> Vec<u8> {
    if !is_store(insn.opcode.as_str()) { return Vec::new(); }
    let bases: Vec<u8> = mem_addr_base_regs(insn).into_iter()
        .filter(|(u, _)| !*u).map(|(_, r)| r).collect();
    src_regs(insn).into_iter()
        .filter(|(u, r)| !*u && *r < 128 && !bases.contains(r))
        .map(|(_, r)| r).collect()
}

/// Source GPRs a warp-cooperative MMA (QMMA/HMMA/IMMA/DMMA) latches over its long
/// multi-cycle read window after issue: A/B fragments, the C accumulator and the QMMA.SF
/// scale-factor registers. Exactly the store-data situation: a later writer of one of
/// these (typically the next iteration's LDG refilling the same fragment register) lands
/// inside that window whenever the load completes fast — e.g. L2/TLB-hot lines after other
/// kernels ran in the process — and the MMA computes on torn operands. Issue distance does
/// NOT cover this against a warm cache (observed: deterministic wrong logits on the first
/// QK tiles of the leading warp per SMSP, cold-context runs pass). ptxas avoids the hazard
/// structurally (double-buffered fragments); cubit reuses fragment registers, so it must
/// protect them with a read-barrier on the MMA, waited by the overwriting load.
fn mma_src_gprs(insn: &Instruction) -> Vec<u8> {
    if !is_warp_mma(insn.opcode.as_str()) { return Vec::new(); }
    let mut out: Vec<u8> = Vec::new();
    for (u, r) in src_regs(insn) {
        if !u && r < 128 && !out.contains(&r) { out.push(r); }
    }
    out
}

/// The GPR(s) holding a store's ADDRESS (a store latches its address late, exactly like
/// its data). If that pointer is overwritten before the store retires its address read
/// (e.g. a loop-carried `IADD.64 Rptr, Rptr, stride` bumping the output pointer), the
/// store lands at the wrong location — a real WAR that ptxas protects with a read-barrier
/// and that races only at high occupancy (>1 CTA/SM). Global stores use a 64-bit address
/// pair (base, base+1); shared/local use a single register.
fn store_addr_gprs(insn: &Instruction) -> Vec<u8> {
    let op = insn.opcode.as_str();
    if !is_store(op) { return Vec::new(); }
    let wide = matches!(op, "STG" | "STGX" | "ST" | "ATOMG" | "RED" | "REDG" | "ATOM");
    let mut out = Vec::new();
    for (u, r) in mem_addr_base_regs(insn) {
        if u { continue; }
        out.push(r);
        if wide && r < 255 { out.push(r + 1); }
    }
    out
}

/// CUBIT_SCHED2 load memory-class, used to batch consecutive same-class loads onto
/// one (counting) write barrier. 2 = shared/predictable (LDS/LDSM/LDL — fixed,
/// in-order latency); 1 = global/variable (LDG/LDC/LD/… — variable latency).
/// Loads of the *same* class issued back-to-back share a barrier; a class change
/// (or a consumer waiting the open batch) starts a fresh barrier. This mirrors
/// ptxas's PV discipline (e.g. 6 consecutive `LDG` all set `W5`, the consumer waits
/// `B5` once) instead of cubit's default one-barrier-per-load over-allocation.
fn load_kind_sched2(op: &str) -> u8 {
    match op {
        "LDS" | "LDSM" | "LDL" => 2,
        _ => 1,
    }
}

/// Address key of a load's memory operand: (stream key, immediate offset). Two loads
/// belong to the same *stream* only when they use the same base register (or same
/// UR/const base). Used to restrict write-barrier batching of GLOBAL loads to
/// provably same-line accesses — see the batching rule in `reallocate_barriers`.
fn load_addr_key(insn: &Instruction) -> Option<(u16, i64)> {
    for o in &insn.operands {
        match o {
            Operand::Addr { base_reg, ur_reg, offset, .. } => {
                let k = match (base_reg, ur_reg) {
                    (Some(r), _) => *r as u16,
                    (None, Some(u)) => 0x100 | (*u as u16),
                    _ => 0x3FF,
                };
                return Some((k, *offset));
            }
            Operand::Desc { base_reg, ur_idx, offset, .. } => {
                let k = match base_reg { Some(r) => *r as u16, None => 0x200 | (*ur_idx as u16) };
                return Some((k, *offset));
            }
            Operand::ConstMem { base_reg, offset, .. } => {
                let k = 0x300 | base_reg.unwrap_or(0xFF) as u16;
                return Some((k, *offset));
            }
            _ => {}
        }
    }
    None
}

fn is_control_flow(op: &str) -> bool {
    matches!(op, "EXIT" | "BRA" | "RET" | "BREAK" | "CONT" | "KILL" | "JMP" | "CALL" |
                 "BSSY" | "BSYNC" | "BBREAK" | "BMOV")
}

/// CUBIT_SCHED2 (RULE 3): opcodes whose scheduling the encoder treats as "fully
/// static" (it keeps the ISA-table default and drops the scheduler's stall/yield).
/// main.rs re-injects the scheduler's `[stall|yield]` for these under sched2 so the
/// learned branch / back-edge settle stalls reach the encoded bytes. NOP is excluded
/// (the encoder already honours NOP's scheduling override).
pub fn is_static_sched_reinject(op: &str) -> bool {
    // Control-flow AND barrier-sync are "static-ctrl": the encoder leaves their schedule at
    // the ISA default, so a real (frozen or learned) stall/yield must be re-injected or it
    // silently becomes S01 (e.g. ptxas's `BAR.SYNC ... S06` -> cubit S01).
    is_control_flow(op) || op == "BAR" || op == "BARRIER"
}

fn is_barrier_insn(op: &str) -> bool {
    matches!(op, "BAR" | "BARRIER" | "FENCE" | "MEMBAR" | "NOP" | "DEPBAR")
}

// ── ctrl_class-aware wrappers ─────────────────────────────────────────────────

/// Returns true when the instruction is long-latency and needs a write_bar.
/// Uses ctrl_class when available (preferred); falls back to opcode string.
///
/// Only memory loads and special-register reads use write barriers.
/// ALU instructions (including IMAD.WIDE) use stall-based synchronization
/// instead — matching nvcc behavior where IMAD.WIDE gets stall=6, wbar=7.
fn insn_needs_write_bar(insn: &Instruction, table: Option<&IsaTable>, sched2: bool) -> bool {
    let op = insn.opcode.as_str();
    // Cooperative MMA writeback is NOT scoreboardable on SM120 (write_bar ignored by HW;
    // empirically re-confirmed). It is synced by a timing drain in the main.rs post-pass.
    if is_warp_mma(op) {
        return false;
    }
    // CS2R (copy special-register, e.g. accumulator zero-init from SR) is FAST on SM120 —
    // ptxas synchronises it with a stall, NOT a write barrier (unlike S2R which it does
    // barrier). Giving CS2R a write barrier consumes a scoreboard slot that then gets
    // recycled in the tight slice-setup/inner-loop region, corrupting the schedule
    // (pinpointed: cubit's CS2R barriers break the pipelined PV at 1 CTA/SM). The corpus
    // confirms this: CS2R sets a write barrier 0% of the time.
    if op == "CS2R" {
        return false;
    }
    // Opcode-level long-latency producers (loads, S2R, ATOM, REDUX, SHFL, …) ALWAYS
    // need a write barrier. This takes precedence over a mis-assigned ctrl_class —
    // e.g. SHFL is tagged 'alu_simple' in the table, which would otherwise drop the
    // barrier and let a consumer read a stale cross-lane result.
    if is_long_latency(op) && !is_store(op) { return true; }
    // tcgen05 UDP-result producers (UTCATOMSWS, LDTM): asynchronous UR/UP/GPR result
    // — unconditionally need a scoreboard write barrier (takes precedence like the
    // long-latency class above; ctrl_class has no opinion for these keys).
    if is_udp_async_result(op) { return true; }
    // CUBIT_SCHED2: enforce the learned variable-latency set so the consumer WAITS the
    // write barrier (occupancy-robust) rather than using a fixed stall. Covers the
    // special-register / conversion / bit-count producers (S2UR/B2R/MUFU/F2I/I2F/FLO/POPC)
    // that the opcode path misses and ctrl_class may not tag. Gated → default unchanged.
    if sched2 && is_variable_latency_sched2(op) && !is_store(op) { return true; }
    if let Some(cc) = table.and_then(|t| t.ctrl_class(&insn.key)) {
        return cc.needs_write_bar();
    }
    matches!(op, "MUFU")
}

/// Warp-cooperative tensor-core MMA ops. On SM120 these all use the same
/// writeback-sync path (no usable write_bar; stall + @!UPT drains).
fn is_warp_mma(op: &str) -> bool {
    matches!(op, "QMMA" | "HMMA" | "IMMA" | "DMMA")
}

/// Returns true when the instruction is a store (no result, fire-and-forget).
#[allow(dead_code)]
fn insn_is_store(insn: &Instruction, table: Option<&IsaTable>) -> bool {
    if let Some(cc) = table.and_then(|t| t.ctrl_class(&insn.key)) {
        return cc.is_store();
    }
    is_store(insn.opcode.as_str())
}

/// Returns true when the instruction is control flow or a barrier.
#[allow(dead_code)]
fn insn_is_ctrl(insn: &Instruction, table: Option<&IsaTable>) -> bool {
    if let Some(cc) = table.and_then(|t| t.ctrl_class(&insn.key)) {
        return cc.is_static_ctrl();
    }
    is_control_flow(insn.opcode.as_str()) || is_barrier_insn(insn.opcode.as_str())
}

/// Returns true when the scheduler may set wait_mask for this instruction.
///
/// Hardware-verified restrictions:
/// - MUFU: wait_mask corrupts opex_0 table decode → FORBIDDEN
/// - IADD3+RZ: hi[7:0]=0xFF forced; wait_mask causes ILLEGAL_INSTRUCTION
fn insn_can_set_wait_mask(insn: &Instruction, table: Option<&IsaTable>) -> bool {
    if let Some(cc) = table.and_then(|t| t.ctrl_class(&insn.key)) {
        if !cc.can_set_wait_mask() {
            return false;
        }
        // IADD3+RZ special case: Rc2=RZ forces hi[7:0]=0xFF, no wait_mask allowed
        if *cc == CtrlClass::AluIadd3 && iadd3_rc2_is_rz(insn) {
            return false;
        }
        return true;
    }
    // Fallback (no ctrl_class): apply conservative restrictions
    let op = insn.opcode.as_str();
    if matches!(op, "MUFU") { return false; }
    if matches!(op, "IADD3" | "UIADD3") && iadd3_rc2_is_rz(insn) { return false; }
    true
}

/// Returns true when the scheduler may assign write_bar for this instruction.
///
/// Hardware-verified: IADD3+RZ cannot set write_bar (hi[7:0]=0xFF forced).
fn insn_can_set_write_bar(insn: &Instruction, table: Option<&IsaTable>) -> bool {
    if let Some(cc) = table.and_then(|t| t.ctrl_class(&insn.key)) {
        if !cc.can_set_write_bar() {
            return false;
        }
        if *cc == CtrlClass::AluIadd3 && iadd3_rc2_is_rz(insn) {
            return false;
        }
        return true;
    }
    // Fallback
    let op = insn.opcode.as_str();
    if matches!(op, "IADD3" | "UIADD3") && iadd3_rc2_is_rz(insn) { return false; }
    true
}

fn is_pred_writer(op: &str) -> bool {
    matches!(op,
        "ISETP" | "ISETP3" | "FSETP" | "DSETP" | "HSETP2" |
        "PSETP" | "PLOP3" | "UPLOP3" | "UISETP" | "UFSETP" |
        "IMNMX" | "UIMNMX" | "VIMNMX" | "UVIMNMX"
    )
}

/// Instructions that write carry predicates (IADD3, HADD2 — NOT IADD3.X).
/// Carry predicates have ALU latency (4 cycles), not full LATENCY_PRED (13).
/// Uses opcode_full to distinguish IADD3 (no .X) from IADD3.X.
fn is_carry_pred_writer(op_full: &str) -> bool {
    matches!(op_full, "IADD3" | "HADD2" | "UIADD3")
}

/// All carry-predicate writers including .X variants (IADD3 and IADD3.X).
/// Used when tracking whether a predicate def is a carry pred for latency.
fn is_any_carry_pred_writer(op_full: &str) -> bool {
    op_full == "IADD3" || op_full == "IADD3.X"
        || op_full == "HADD2" || op_full.starts_with("HADD2.")
        || op_full == "UIADD3" || op_full == "UIADD3.64"
}

/// True when the predicate(s) written by `insns[i]` (a SETP-like compare) are
/// consumed FIRST by a control-flow (branch) instruction — the loop-guard pattern.
/// Such a predicate only needs the branch-resolve latency (~9), not the full
/// register-predicate forwarding latency (13). If an ALU instruction reads the
/// predicate first, returns false (that path needs the full latency).
fn pred_feeds_branch(insns: &[Instruction], i: usize) -> bool {
    // Only the UNIFORM datapath compare (UISETP → BRA.U) qualifies: the uniform
    // predicate→branch resolve latency (~9) is shorter than the vector
    // predicate→branch latency (~13), and over-stalling a uniform loop-guard compare
    // desynchronises cooperative-MMA loop timing. Vector ISETP→@P BRA is left at the
    // full latency (lowering it caused OOB regressions on other kernels).
    let mut written: Vec<(bool, u8)> = Vec::new();
    for o in insns[i].operands.iter().take(2) {
        if let Operand::UPred { num, .. } = o {
            if *num < 7 { written.push((true, *num)); }
        }
    }
    if written.is_empty() { return false; }
    for j in (i + 1)..insns.len() {
        let cons_writes_pred = is_pred_writer(insns[j].opcode.as_str())
            || is_carry_pred_writer(insns[j].opcode_full.as_str());
        // Does j READ the predicate — as a guard (`@P0 BRA`) or an operand
        // (`BRA.U !UP0`, `SEL`, …)? Skip the destination predicate slots of a
        // SETP-like consumer (those are writes, not reads).
        let mut reads = false;
        if let Some(g) = &insns[j].guard {
            if g.pred < 7 && written.contains(&(g.uniform, g.pred)) { reads = true; }
        }
        for (oi, o) in insns[j].operands.iter().enumerate() {
            if cons_writes_pred && oi < 2 { continue; }
            match o {
                Operand::Pred { num, .. } if written.contains(&(false, *num)) => reads = true,
                Operand::UPred { num, .. } if written.contains(&(true, *num)) => reads = true,
                _ => {}
            }
        }
        if reads {
            // First consumer wins: a branch needs only branch-resolve latency; an ALU
            // consumer needs the full predicate-forward latency.
            return is_control_flow(insns[j].opcode.as_str());
        }
        // Redefinition of the predicate ends the search (a later writer owns it).
        let redefined = insns[j].operands.iter().take(2).any(|o| match o {
            Operand::Pred { num, .. } => written.contains(&(false, *num)),
            Operand::UPred { num, .. } => written.contains(&(true, *num)),
            _ => false,
        });
        if redefined { return false; }
    }
    false
}

/// True when a store at index `i` is followed (within a few instructions) by a
/// backward branch — its asynchronous operand latch then races the NEXT loop
/// iteration's overwrite of the same registers (accumulator re-init / MMA), a WAR
/// across the back-edge that the default few-cycle store stall does not cover.
fn store_precedes_backedge(insns: &[Instruction], i: usize) -> bool {
    const WINDOW: usize = 4;
    let end = (i + 1 + WINDOW).min(insns.len());
    for j in (i + 1)..end {
        if !is_control_flow(insns[j].opcode.as_str()) { continue; }
        let ja = if insns[j].addr > 0 { insns[j].addr } else { (j * 16) as u32 };
        if let Some(target) = insns[j].operands.iter().find_map(|o| match o {
            Operand::Imm32(v) => Some(*v as u32),
            Operand::BranchTarget(a) => Some(*a),
            _ => None,
        }) {
            if target < ja { return true; }
        }
    }
    false
}

fn branch_target(insn: &Instruction) -> Option<u32> {
    insn.operands.iter().find_map(|o| match o {
        Operand::Imm32(v) => Some(*v as u32),
        Operand::BranchTarget(a) => Some(*a),
        _ => None,
    })
}

/// True when the long-latency load at index `i` produces a LOOP-CARRIED result: one
/// of its destination registers is read by an instruction earlier in program order
/// but within the enclosing loop body (i.e. the value is consumed by a later
/// iteration across the back-edge — e.g. a gather load feeding the next iteration's
/// loop-guard compare). Such a load must be sufficiently retired before the back-edge;
/// the default load stall is too short at high occupancy (>1 CTA/SM).
fn load_result_loop_carried(insns: &[Instruction], i: usize) -> bool {
    let dsts = dest_regs(&insns[i]);
    if dsts.is_empty() { return false; }
    let my_addr = if insns[i].addr > 0 { insns[i].addr } else { (i * 16) as u32 };
    // Outermost enclosing loop top = smallest backward-branch target after i.
    let mut top: Option<u32> = None;
    for k in (i + 1)..insns.len() {
        if is_control_flow(insns[k].opcode.as_str()) {
            if let Some(t) = branch_target(&insns[k]) {
                if t < my_addr { top = Some(top.map_or(t, |x: u32| x.min(t))); }
            }
        }
    }
    let top = match top { Some(t) => t, None => return false };
    for j in 0..i {
        let ja = if insns[j].addr > 0 { insns[j].addr } else { (j * 16) as u32 };
        if ja < top { continue; }
        // Only the loop-GUARD path qualifies: the loop-carried result is consumed by a
        // compare (predicate writer) that drives the back-edge — that load must retire
        // before the next iteration's guard at high occupancy. A loop-carried result
        // feeding the MMA/ALU datapath is barrier-synced by its consumer and must NOT be
        // extra-stalled (over-stalling pre-MMA loads desyncs cooperative-MMA timing —
        // breaks pv_cache and similar single-warp cooperative kernels).
        if is_pred_writer(insns[j].opcode.as_str())
            && src_regs(&insns[j]).iter().any(|s| dsts.contains(s)) {
            return true;
        }
    }
    false
}

// Constant-bank load (LDC/LDCU) pipeline latency, MEASURED on RTX 5090 silicon
// (tools/ldc_latency_test.sass + tools/ldc_latency_validate.py): a barrier-less
// LDC -> consumer distance of 15 cycles is stale 100% of the time, 30 cycles is
// always fresh on an idle GPU (constant-cache hit path). Under load (4096 CTAs,
// first-touch constants) even 60 cycles still missed 1.3% of samples — a
// constant-cache MISS cannot be bounded by any stall, so the ONLY occupancy-
// robust sync for LDC is its write barrier (which the normal scheduling path
// always assigns; hand-scheduled producers get theirs tracked via record_defs).
// This fixed latency is the fallback used when an LDC def carries no barrier;
// it was previously 1 (the generic long-latency arm), which let a consumer sit
// 1-2 instructions after a hand-prologue LDC and read garbage CTA-dependently.
const LATENCY_LDC: u8 = 30;

fn base_latency(op: &str) -> u8 {
    if is_pred_writer(op) { return LATENCY_PRED; }
    if is_control_flow(op) { return LATENCY_CTRL; }
    match op {
        "S2R" | "CS2R" => LATENCY_S2R,
        // Cross-datapath transfers (vector<->uniform). The result lands in the uniform
        // register file several cycles after issue; a consumer (e.g. UIADD3 UR reading
        // an R2UR'd counter at a loop top) must wait or it reads a stale uniform value.
        // Modeled higher than vector ALU (4) — verified: R2UR'd loop counters mis-iterate
        // at <8 cycles when the consumer is the immediate next instruction.
        "R2UR" | "S2UR" | "R2P" | "P2R" | "R2B" => 8,
        "DFMA" | "DMUL" | "DADD" | "DSETP" => LATENCY_FP64,
        "IMAD" | "LEA" | "FFMA" | "FMUL" | "FADD" | "HFMA2" | "HMMA" |
        "QMMA" | "IMMA" | "DMMA" => LATENCY_FMA,
        // Constant loads: real hit latency (hardware-measured, see LATENCY_LDC).
        // Only consulted for barrier-less defs — stall arithmetic clamps at 15,
        // so consumers also pick up the deficit across intervening issue slots.
        "LDC" | "LDCU" => LATENCY_LDC,
        _ if is_long_latency(op) => 1,
        _ if is_store(op) => 1,
        _ if is_barrier_insn(op) => 1,
        _ => LATENCY_ALU,
    }
}

/// CUBIT_SCHED2 — learned variable-latency producer set (model.json `variable`: these
/// set a write barrier in ≈90-100% of the corpus). The consumer must WAIT the barrier
/// — the scoreboard enforces the true, occupancy-robust memory/pipe latency — instead
/// of substituting a fixed stall. Loads / S2R / ATOMG / REDUX / SHFL are already
/// covered by `is_long_latency`; this adds the special-register, conversion and
/// bit-count producers that the opcode path would otherwise miss.
///
/// Deliberately EXCLUDED: CS2R (corpus: 0% wbar — ptxas syncs it with a stall; a write
/// barrier here breaks the pipelined PV at 1 CTA/SM) and FP64 (DADD/DMUL/DFMA, "mixed":
/// kept on their existing ctrl_class-driven handling). LDS is also "mixed" and stays on
/// its existing handling (it is already a load, barriered when ctrl_class says so).
fn is_variable_latency_sched2(op: &str) -> bool {
    matches!(op,
        "S2UR" | "B2R" |
        "MUFU" |
        "F2I" | "I2F" |
        "FLO" | "POPC"
    )
}

// ── CUBIT_SCHED2 stage-3 learned rules ────────────────────────────────────────

/// CUBIT_SCHED2 RULE 1 — per-opcode RAW latency used for the deficit (the `mode`
/// from stage3 model.json / report 1c: the d=1 stall mode, held-out-confirmed). This
/// is the value that lands as the producer's own stall when its consumer is the very
/// next instruction. Distinct from `sched2_latency` (the p1 write-barrier floor):
/// e.g. IMAD/IADD3/LEA mode=5 (not 4), IADD mode=6, FFMA/FADD/FMUL=4, preds=13.
fn sched2_deficit_lat(op: &str) -> u8 {
    match op {
        // 4-cycle FMA-pipe results
        "FFMA" | "FADD" | "FMUL" => 4,
        // 5-cycle ALU / select / convert / min-max (mode=5)
        "IMAD" | "IADD3" | "LEA" | "LOP3" | "SHF" | "HADD2" | "HFMA2"
        | "MOV" | "SEL" | "FSEL" | "FMNMX" | "VIMNMX" | "F2FP" | "PRMT"
        | "I2FP" | "IDP" | "HMUL2" | "F2IP" => 5,
        // 6-cycle int add
        "IADD" => 6,
        // predicate writers (consumed by ALU/branch) — full predicate forward latency
        "ISETP" | "FSETP" | "DSETP" | "HSETP2" | "PLOP3" | "UPLOP3"
        | "UISETP" | "UFSETP" => LATENCY_PRED,
        // uniform datapath (mode column)
        "UIADD3" | "UIMAD" | "USHF" | "USEL" | "UVIMNMX" | "UPRMT" => 4,
        "UMOV" => 2,
        "ULEA" | "UFLO" => 6,
        "UI2F" => 9,
        "R2UR" | "S2UR" | "R2P" | "P2R" | "R2B" => 8,
        "DADD" | "DMUL" | "DFMA" => LATENCY_FP64,
        _ => base_latency(op),
    }
}

/// CUBIT_SCHED2 issue-throughput pipe. Some multi-cycle units only accept a new op
/// every few cycles, so ptxas spaces CONSECUTIVE same-pipe ops by `spacing` regardless
/// of data deps (the report's "+1 same-unit throughput floor", generalised). Returns
/// `(pipe_id, spacing)`; `None` = not throughput-limited (use the RAW deficit only).
///   global mem (LDG/STG/…) = 4,  shared mem (LDS/STS/…) = 4,  IMAD.WIDE = 4.
fn issue_pipe(insn: &Instruction) -> Option<(u8, u8)> {
    if insn.opcode_full.contains("WIDE") { return Some((3, 4)); }
    match insn.opcode.as_str() {
        "LDG" | "LD" | "LDGSTS" | "LDGDEPBAR" | "LDGX"
        | "STG" | "ST" | "STGX" => Some((1, 4)),
        "LDS" | "LDSM" | "LDL" | "STS" | "STSM" | "STL" => Some((2, 4)),
        _ => None,
    }
}

/// RULE 1 (stall placement / deficit model). Returns how many cycles the gap
/// BEFORE consumer `cons` must be, so that `cons` safely reads its fixed-latency
/// (non-barrier) RAW producers, given that `cons` issues at `ref_clock` PLUS that
/// gap. i.e. `stall = max(1, L(producer) − elapsed)` charged to the pre-consumer
/// gap (the producer's own stall, when the consumer is the next instruction;
/// otherwise distributed across the intervening issue slots — see report Rule 1).
///
/// Only fixed-latency producers (no write barrier) contribute: barrier'd producers
/// (loads, etc.) are synchronised by the consumer's `wait_mask`, not a stall.
/// Both register/uniform and predicate RAW deps are considered (predicate latency
/// follows the carry/branch model used elsewhere in this pass).
fn sched2_raw_deficit(insns: &[Instruction], st: &SchedulerState, cons: usize, ref_clock: usize) -> u8 {
    if cons >= insns.len() { return 0; }
    let cons_is_ctrl = is_control_flow(insns[cons].opcode.as_str());
    // A cooperative MMA reads its A/B fragments with a longer input latency than a plain
    // ALU consumer (gt: F2FP → HMMA = S07). Under-stalling this feeds the tensor core a
    // STALE fragment → wrong result (and a racing address → OOB). The C accumulator read
    // is loop-carried (far → deficit 0), so a flat floor on all MMA reads is safe.
    let cons_is_mma = is_warp_mma(insns[cons].opcode.as_str());
    let mma_in_lat = std::env::var("CUBIT_MMA_INPUT_LAT").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(7usize);
    let mut need: usize = 0;
    for (is_u, reg) in src_regs(&insns[cons]) {
        if reg >= 128 {
            // predicate RAW
            if let Some(pd) = st.pred_defs.get((reg - 128) as usize).and_then(|d| d.as_ref()) {
                let lat = if pd.is_carry {
                    if cons_is_ctrl { LATENCY_CARRY_PRED_BRANCH as usize } else { LATENCY_ALU as usize }
                } else {
                    LATENCY_PRED as usize
                };
                let elapsed = ref_clock.saturating_sub(pd.clock);
                if elapsed < lat { need = need.max(lat - elapsed); }
            }
            continue;
        }
        let def = if is_u {
            st.ureg_defs.get(reg as usize).and_then(|d| d.as_ref())
        } else {
            st.gpr_defs.get(reg as usize).and_then(|d| d.as_ref())
        };
        if let Some(def) = def {
            if def.barrier.is_some() { continue; } // synced by wait_mask, not a stall
            let def_op = insns[def.insn_idx].opcode.as_str();
            let mut lat = sched2_deficit_lat(def_op) as usize + st.deficit_margin;
            if cons_is_mma { lat = lat.max(mma_in_lat); }
            let elapsed = ref_clock.saturating_sub(def.clock);
            if elapsed < lat { need = need.max(lat - elapsed); }
        }
    }
    need.min(15) as u8
}

/// RULE 2 helper: does the NEXT instruction read a result this instruction writes?
fn sched2_next_insn_depends(insns: &[Instruction], i: usize) -> bool {
    let j = i + 1;
    if j >= insns.len() { return false; }
    let dsts = dest_regs(&insns[i]);
    if dsts.is_empty() { return false; }
    src_regs(&insns[j]).iter().any(|s| dsts.contains(s))
}

/// RULE 3 (branch / back-edge stall). Returns the learned settle stall for a
/// control-flow instruction, or `None` to leave it at the scheduler baseline.
///   forward branch / non-MMA back-edge / BSYNC / EXIT / RET / CALL = 5
///   back-edge whose IMMEDIATE loop body has a cooperative MMA (HMMA/QMMA/IMMA)
///       = CUBIT_MMA_BACKEDGE (default 11; the PV reference uses 15)
///   back-edge whose immediate loop body has a DMMA = 8
/// Back-edges wait no barrier (handled by the existing drain logic).
fn sched2_branch_stall(insns: &[Instruction], i: usize) -> Option<u8> {
    let op = insns[i].opcode.as_str();
    let my_addr = if insns[i].addr > 0 { insns[i].addr } else { (i * 16) as u32 };
    let tgt = branch_target(&insns[i]);
    // self-loop / dead tail branch: leave at baseline (ptxas uses S00 there).
    if let Some(t) = tgt { if t == my_addr { return None; } }
    let is_be = matches!(op, "BRA" | "JMP") && tgt.is_some_and(|t| t < my_addr);
    if is_be {
        let t = tgt.unwrap();
        let body_idx = |a: u32| -> usize { (a / 16) as usize };
        let top = body_idx(t);
        // Classify the MMA(s) DIRECTLY in this loop (not inside a nested back-edge).
        let mut low = false;
        let mut dmma = false;
        for k in top..i {
            let kop = insns[k].opcode.as_str();
            let is_low = matches!(kop, "HMMA" | "QMMA" | "IMMA");
            let is_d = kop == "DMMA";
            if !(is_low || is_d) { continue; }
            let ka = if insns[k].addr > 0 { insns[k].addr } else { (k * 16) as u32 };
            // tighter (nested) back-edge enclosing k?  then k is not in THIS loop body.
            let nested = (k + 1..i).any(|j| {
                matches!(insns[j].opcode.as_str(), "BRA" | "JMP")
                    && branch_target(&insns[j]).is_some_and(|tj| tj <= ka)
            });
            if nested { continue; }
            if is_low { low = true; }
            if is_d { dmma = true; }
        }
        if low {
            let v: u8 = std::env::var("CUBIT_MMA_BACKEDGE").ok()
                .and_then(|s| s.parse().ok()).unwrap_or(11);
            return Some(v);
        }
        if dmma { return Some(8); }
        return Some(5);
    }
    // forward branch / BSYNC / EXIT / RET / CALL / uncond BRA: settle 5.
    // BSSY (convergence setup) is left at baseline (report: mode 1, kernel-specific).
    if matches!(op, "BSSY") { return None; }
    Some(5)
}

// ── Register tracking ────────────────────────────────────────────────────────

const NUM_BARRIERS: usize = 6;
const BARRIER_MASK: u8 = (1u8 << NUM_BARRIERS) - 1; // 0x3F

/// Max loads CUBIT_SCHED2 will batch onto a single counting write barrier. Generous
/// (the PV loop's largest run is 8 consecutive `LDG`); bounds the scoreboard count.
const SCHED2_MAX_BATCH: u8 = 16;

/// Barrier-recycling strategy for `alloc_barrier`. Selected once via the
/// `CUBIT_BARRIER_ALLOC` env var (default `Lru`).
///
/// Both strategies enforce the same correctness invariant — a barrier with a
/// *pending consumer* (a producer whose result no instruction has waited on yet)
/// is never silently reassigned; reuse of a pending barrier always forces a drain
/// so "its consumer has waited it" holds. They differ only in *which* truly-free
/// barrier they prefer:
/// - `Lru` (default): the least-recently-allocated free barrier, i.e. the one that
///   has been free the longest. This maximises the idle gap before a barrier is
///   reused (so its previous producer is the most likely to have fully retired —
///   the safest choice at high occupancy) while still spreading in-flight loads
///   across distinct barriers the way nvcc's PV loop does.
/// - `Legacy`: the historical round-robin from `next_barrier`. Functionally
///   equivalent to `Lru` for fully-pipelined loops (only the barrier *ids* differ);
///   kept as an A/B and rollback escape hatch for this core-scheduler change.
///
/// (A `compact`/lowest-index policy was evaluated and rejected: it reuses a barrier
/// the instant its consumer drains it, which serialises independent loads through a
/// single barrier and collapsed the 2-CTA sparse-MLA pass rate from ~10/16 to 0/16.)
#[derive(Clone, Copy, PartialEq, Eq)]
enum BarrierAlloc {
    Lru,
    Legacy,
}

impl BarrierAlloc {
    fn from_env() -> Self {
        match std::env::var("CUBIT_BARRIER_ALLOC").ok().as_deref() {
            Some("legacy") => BarrierAlloc::Legacy,
            _ => BarrierAlloc::Lru,
        }
    }
}

struct RegDef {
    insn_idx: usize,
    barrier: Option<u8>,
    clock: usize,   // issue clock of the defining instruction
}

struct PredDef {
    clock: usize,
    is_carry: bool,  // true if written by IADD3/IADD3.X carry pred
}

struct SchedulerState {
    gpr_defs: [Option<RegDef>; 256],
    /// 0..63 = uniform registers; 64..70 = uniform predicates UP0..UP6
    ureg_defs: [Option<RegDef>; 72],
    pred_defs: [Option<PredDef>; 8],
    barrier_age: [usize; NUM_BARRIERS],
    /// Bitmask: bit i set = barrier i has a *pending consumer* — it has been
    /// assigned to a long-latency producer (write_bar=i) that no instruction has
    /// waited on yet. Such a barrier must NOT be recycled without a drain. A clear
    /// bit means the barrier is "truly free" (never used, or its producer's result
    /// has already been waited and is therefore complete).
    barrier_pending: u8,
    next_barrier: u8,
    clock: usize,
    /// Bitmask of barriers that were recycled and need draining before next use.
    pending_drain: u8,
    current_load_barrier: Option<u8>,
    current_batch_count: u8,
    /// CUBIT_SCHED2: memory class of the currently open load batch (see `load_kind_sched2`).
    current_batch_kind: u8,
    /// CUBIT_SCHED2: ptxas-like barrier batching + MMA-waits-its-barrier discipline.
    sched2: bool,
    /// Stage-3 learned rules active (= sched2 AND not CUBIT_SCHED2_LEGACY). When false but
    /// sched2 is true, the pre-rules SCHED2 behavior runs (larger occupancy-safe stalls).
    /// This is the A/B + rollback switch for the stall-placement / yield / branch rules.
    stage3: bool,
    /// RULE 2 yield model: false = literal compact rule (prompt, the default and best),
    /// true = the experimental settle-LUT refinement (CUBIT_SCHED2_YIELD=lut). The
    /// refinement was measured WORSE on the gt diff (ptxas keeps Y=1 for most ALU at
    /// settle stalls), so the compact rule is the default.
    yield_lut: bool,
    /// RULE 2 disabled (CUBIT_SCHED2_NOYIELD=1): leave yields untouched (GPU on/off A/B).
    no_yield: bool,
    /// CUBIT_SCHED2 RULE 1 safety margin (CUBIT_SCHED2_MARGIN, default 1). The deficit
    /// uses the LEARNED MODE latency, which under-predicts ~12% of RAW pairs (report 1d) —
    /// a stale read on cubit's fragile cooperative-MMA / dequant chains. A small +margin
    /// over-stalls (gap = L+margin) to stay on the safe side. margin=0 = pure mode latency
    /// (best diff, but breaks the MMA kernels); margin=1 is the correctness default.
    deficit_margin: usize,
    /// CUBIT_SCHED2: keep the load/store WAR-protection producer stalls (occupancy-safe
    /// gather-address / store-operand latch margin). ptxas protects these with read-
    /// barriers instead; cubit's rb pass does not yet cover every case, so the stalls are
    /// kept ON by default for GPU correctness. CUBIT_SCHED2_NOMEMSTALL=1 drops them
    /// (smaller stalls, closer to the gt diff — but exposes the WAR at high occupancy).
    mem_war_stall: bool,
    strategy: BarrierAlloc,
    /// When set (`CUBIT_GATHER_RDBAR`), reserve barrier 0 for read-barriers and set
    /// `rb=0` on every gather load — mirroring nvcc's PV discipline (experimental).
    reserve_rb: bool,
    /// When set, reserve barrier 0 exclusively for the cooperative-MMA accumulator
    /// store WAR read-barrier (set in main.rs). Unlike `reserve_rb` this ONLY removes
    /// barrier 0 from the load write-barrier pool; it does NOT put rb on loads.
    /// Auto-enabled when the kernel has an MMA whose accumulator is read by a store.
    reserve_war_rb: bool,
    /// Bitmask of barriers kept out of the write-barrier pool so they are available
    /// as read-barriers for load-address WAR hazards (`assign_war_read_barriers`).
    /// Computed once per kernel: {0,1} when the kernel has tight load-operand reuse
    /// (a gather load whose address reg is overwritten before the load latches it,
    /// the pattern nvcc/ptxas protects with rb). 0 (no reservation) otherwise.
    rb_reserve_mask: u8,
}

impl SchedulerState {
    fn new() -> Self {
        Self {
            gpr_defs: std::array::from_fn(|_| None),
            ureg_defs: std::array::from_fn(|_| None),
            pred_defs: std::array::from_fn(|_| None),
            barrier_age: [0; NUM_BARRIERS],
            barrier_pending: 0, // all barriers start truly free (no pending consumer)
            next_barrier: 0,
            clock: 0,
            pending_drain: 0,
            current_load_barrier: None,
            current_batch_count: 0,
            current_batch_kind: 0,
            sched2: std::env::var("CUBIT_SCHED2").is_ok(),
            stage3: std::env::var("CUBIT_SCHED2").is_ok(),
            yield_lut: std::env::var("CUBIT_SCHED2_YIELD").ok().as_deref() == Some("lut"),
            no_yield: std::env::var("CUBIT_SCHED2_NOYIELD").is_ok(),
            mem_war_stall: std::env::var("CUBIT_SCHED2_NOMEMSTALL").is_err(),
            deficit_margin: std::env::var("CUBIT_SCHED2_MARGIN").ok()
                .and_then(|s| s.parse().ok()).unwrap_or(1),
            strategy: BarrierAlloc::from_env(),
            reserve_rb: std::env::var("CUBIT_GATHER_RDBAR").is_ok(),
            reserve_war_rb: false,
            rb_reserve_mask: 0,
        }
    }

    /// An instruction waited on `wait_mask`: every barrier it names now has its
    /// pending producer drained, so those barriers become truly free again.
    fn mark_consumed(&mut self, wait_mask: u8) {
        self.barrier_pending &= !(wait_mask & BARRIER_MASK);
    }

    /// Record that barrier `b` now tracks a (newly issued) long-latency producer
    /// whose result has not been consumed yet — i.e. it has a pending consumer.
    /// Re-asserting this AFTER `mark_consumed` is what makes a self-draining reuse
    /// safe: the drain waits the *previous* producer, then the barrier is correctly
    /// left pending for the new one.
    fn mark_pending(&mut self, b: u8) {
        if (b as usize) < NUM_BARRIERS {
            self.barrier_pending |= 1 << b;
            self.barrier_age[b as usize] = self.clock;
        }
    }

    /// Allocate a barrier for a new long-latency producer.
    ///
    /// Prefers a *truly-free* barrier (no pending consumer) so we never reuse a
    /// barrier whose producer hasn't been waited on. Only when every barrier still
    /// has a pending consumer do we recycle one, and then we queue a forced drain
    /// (`pending_drain`) so the new producer waits the displaced one first — at
    /// which point "its consumer has waited it" holds for the recycled barrier too.
    ///
    /// Returns the barrier id; the returned barrier is left marked pending (it now
    /// tracks the new producer).
    fn alloc_barrier(&mut self) -> u8 {
        // Barriers reserved for read-barriers are kept out of the write-barrier pool:
        // - bit 0: nvcc-style gather-load rb / cooperative-MMA accumulator-store WAR rb
        // - rb_reserve_mask: barriers held for load-address WAR rb (assign_war_read_barriers)
        let mut reserved = self.rb_reserve_mask;
        if self.reserve_rb || self.reserve_war_rb { reserved |= 1u8; }
        let pool = BARRIER_MASK & !reserved;
        let free = !self.barrier_pending & pool;
        if free != 0 {
            let b = match self.strategy {
                // Least-recently-allocated free barrier (largest idle gap before reuse).
                BarrierAlloc::Lru => {
                    let mut best = 0u8;
                    let mut best_age = usize::MAX;
                    for b in 0..NUM_BARRIERS {
                        if free & (1 << b) != 0 && self.barrier_age[b] < best_age {
                            best_age = self.barrier_age[b];
                            best = b as u8;
                        }
                    }
                    best
                }
                // Historical round-robin from next_barrier over free barriers.
                BarrierAlloc::Legacy => {
                    let mut chosen = free.trailing_zeros() as u8;
                    for offset in 0..NUM_BARRIERS {
                        let b = ((self.next_barrier as usize + offset) % NUM_BARRIERS) as u8;
                        if free & (1 << b) != 0 { chosen = b; break; }
                    }
                    chosen
                }
            };
            self.mark_pending(b);
            self.next_barrier = (b + 1) % NUM_BARRIERS as u8;
            return b;
        }
        // No truly-free barrier — every one still has a pending consumer. Recycle
        // the oldest (its producer is the most likely to have already retired) and
        // force a drain so its consumer "waits it" before the new producer reuses it.
        // Never recycle a reserved (read-barrier) slot.
        let mut reserved = self.rb_reserve_mask;
        if self.reserve_rb || self.reserve_war_rb { reserved |= 1u8; }
        let mut oldest = (reserved.trailing_ones() as u8).min(NUM_BARRIERS as u8 - 1);
        let mut oldest_age = usize::MAX;
        for b in 0..NUM_BARRIERS {
            if reserved & (1 << b) != 0 { continue; }
            if self.barrier_age[b] < oldest_age {
                oldest_age = self.barrier_age[b];
                oldest = b as u8;
            }
        }
        self.pending_drain |= 1 << oldest;
        self.barrier_age[oldest as usize] = self.clock; // stays pending (new producer)
        self.next_barrier = (oldest + 1) % NUM_BARRIERS as u8;
        oldest
    }
}

// ── Operand extraction helpers ───────────────────────────────────────────────

fn dest_regs(insn: &Instruction) -> Vec<(bool, u8)> {
    let mut out = Vec::new();
    let op = insn.opcode.as_str();
    if is_store(op) || is_control_flow(op) || is_barrier_insn(op) {
        return out;
    }
    if let Some(first) = insn.operands.first() {
        match first {
            Operand::Reg { num, .. } => {
                out.push((false, *num));
                if (insn.opcode_full.contains(".64") || insn.opcode_full.contains(".128")
                    || insn.opcode_full.contains("WIDE")) && *num < 255 {
                    out.push((false, num + 1));
                }
                if insn.opcode_full.contains(".128") {
                    if *num < 254 { out.push((false, num + 2)); }
                    if *num < 253 { out.push((false, num + 3)); }
                }
                // BUG-101: .256 memory forms (LDG_R_R_dARI family) write a 256-bit
                // payload; per the M3.5 census doctrine the two printed base registers
                // each name a 128-bit dest quad (Rhi -> Rhi+0..=3, Rlo likewise).
                // Without the span, a consumer of e.g. Rhi+1 or any reg of the second
                // quad never sees the load as producer -> no write-barrier / wait ->
                // stale read (TS2-LDG-WAIT sibling class). Mirror reg_liveness.rs.
                if insn.opcode_full.contains(".256") {
                    for r in 1..4u8 {
                        if *num <= 255 - r { out.push((false, num + r)); }
                    }
                }
                // MMA writes a multi-register accumulator: m16n8 F32 = 4 regs, F16 = 2.
                // Without this, consumers of D[1..] (e.g. R1..R3) never see the MMA as
                // the producer and the stall/dep tracking is wrong (stale tensor readout).
                if matches!(op, "QMMA" | "HMMA" | "IMMA" | "DMMA") {
                    let w: u16 = if insn.opcode_full.contains(".F32") { 4 } else { 2 };
                    for r in 1..w {
                        if (*num as u16) + r < 256 { out.push((false, (*num as u16 + r) as u8)); }
                    }
                }
            }
            Operand::UReg { num, .. } => out.push((true, *num)),
            _ => {}
        }
    }
    // BUG-101 (cont.): the second leading register of a .256 two-reg memory
    // form is the second dest quad, not a source (stores returned empty above).
    if insn.opcode_full.contains(".256") && !is_store(insn.opcode.as_str()) {
        if let Some(Operand::Reg { num: n2, .. }) = insn.operands.get(1) {
            for r in 0..4u8 {
                if *n2 <= 255 - r { out.push((false, n2 + r)); }
            }
        }
    }
    // UDP async results (see is_udp_async_result): in the predicated form
    // `UTCATOMSWS.* UPk, URr, URn` the op writes BOTH its uniform predicate
    // (operand 0) and its uniform register (operand 1, the bitmap find/set result).
    // The generic first-operand match above misses the UPred form entirely; track
    // both so the write-barrier/wait machinery covers every consumer. (The 2-operand
    // `UTCATOMSWS.* URd, URn` form is already covered by the generic UReg match.)
    if op == "UTCATOMSWS" {
        if let Some(Operand::UPred { num, .. }) = insn.operands.first() {
            if *num < 7 { out.push((true, 64 + *num)); }
            if let Some(Operand::UReg { num, .. }) = insn.operands.get(1) {
                if *num < 255 { out.push((true, *num)); }
            }
        }
    }
    // SHFL: operand 0 is the dst PREDICATE, the register result is operand 1.
    // Record the register so consumers see SHFL (with its write barrier) as producer.
    if op == "SHFL" {
        if let Some(Operand::Reg { num, .. }) = insn.operands.get(1) {
            out.push((false, *num));
        }
    }
    // Pred outputs for ISETP, LEA, IADD3, etc.
    // ISETP: operand 0 = P0 (primary result), operand 1 = PT (secondary)
    // IADD3: operand 1 = carry pred, operand 2 = overflow pred
    if is_pred_writer(op) || op == "LEA" || is_carry_pred_writer(op) {
        // Capture pred from operand 0 (ISETP primary result)
        if let Some(Operand::Pred { num, .. }) = insn.operands.first() {
            out.push((false, 128 + *num));
        }
        // Capture pred from operand 1 (ISETP secondary / IADD3 carry)
        if let Some(Operand::Pred { num, .. }) = insn.operands.get(1) {
            out.push((false, 128 + *num));
        }
    }
    out
}

fn src_regs(insn: &Instruction) -> Vec<(bool, u8)> {
    let mut out = Vec::new();
    let op = insn.opcode.as_str();
    let is_mma = matches!(op, "QMMA" | "HMMA" | "IMMA" | "DMMA");
    let is_wide_src = insn.opcode_full.contains("WIDE");
    // BUG-101: .256 loads name TWO dest base registers (each a 128-bit quad);
    // the second leading Reg is a destination, not a source.
    let start = if is_store(op) { 0 }
        else if insn.opcode_full.contains(".256")
            && matches!(insn.operands.first(), Some(Operand::Reg { .. }))
            && matches!(insn.operands.get(1), Some(Operand::Reg { .. })) { 2 }
        else { 1 };
    for (op_idx, operand) in insn.operands.iter().enumerate().skip(start) {
        match operand {
            Operand::Reg { num, .. } if *num < 255 => {
                out.push((false, *num));
                // MMA instructions read multi-register operands:
                // operand 1 (A): 4 regs, operand 2 (B): 2 regs, operand 3 (C/acc): 4 regs
                if is_mma {
                    let width = match op_idx {
                        1 => 4, // A fragment
                        2 => 2, // B fragment
                        3 => 4, // C accumulator
                        _ => 1,
                    };
                    for r in 1..width {
                        if *num + r < 255 { out.push((false, num + r)); }
                    }
                } else if is_store(op) {
                    // Store data operand spans multiple regs for wide stores:
                    // .128 = 4 regs, .64 = 2. Without this, STG.E.128 reading a tensor
                    // accumulator (R0..R3) only registers R0 as a source → the scheduler
                    // misses the dep on the MMA writeback of R1..R3 (stale store).
                    // BUG-101: .256 stores name two data base registers (STG_dARI_R_R),
                    // each a 128-bit source quad (M3.5 doctrine) -> 4 per reg here.
                    let w: u16 = if insn.opcode_full.contains(".256") { 4 }
                                 else if insn.opcode_full.contains(".128") { 4 }
                                 else if insn.opcode_full.contains(".64") { 2 } else { 1 };
                    for r in 1..w {
                        if (*num as u16) + r < 256 { out.push((false, (*num as u16 + r) as u8)); }
                    }
                } else if is_wide_src && op_idx > 1 {
                    // IMAD.WIDE accumulator is 64-bit (last register operand)
                    if *num < 255 { out.push((false, num + 1)); }
                }
            }
            Operand::UReg { num, .. } if *num < 63 => out.push((true, *num)),
            Operand::Pred { num, .. } if *num < 7 => out.push((false, 128 + *num)),
            Operand::UPred { num, .. } if *num < 7 => out.push((true, 64 + *num)),
            Operand::Addr { base_reg: Some(r), ur_reg, .. } => {
                out.push((false, *r));
                if let Some(u) = ur_reg { out.push((true, *u)); }
            }
            Operand::Desc { ur_idx, base_reg, .. } => {
                out.push((true, *ur_idx));
                if let Some(r) = base_reg { out.push((false, *r)); }
            }
            Operand::ConstMem { base_reg: Some(r), ur_reg, .. } => {
                out.push((false, *r));
                if let Some(u) = ur_reg { out.push((true, *u)); }
            }
            _ => {}
        }
    }
    // A control-flow op carries its branch predicate as OPERAND 0 (`BRA.U UP0, lbl`),
    // not as a guard — the skip-1 loop above misses it. Track it so the producer of
    // that uniform/vector predicate (UTCATOMSWS UP0, ...) is waited before the branch
    // resolves (same mechanism as the guard-operand below).
    if is_control_flow(op) {
        if let Some(first) = insn.operands.first() {
            match first {
                Operand::Pred { num, .. } if *num < 7 => out.push((false, 128 + *num)),
                Operand::UPred { num, .. } if *num < 7 => out.push((true, 64 + *num)),
                _ => {}
            }
        }
    }
    // Guard predicate is a source
    if let Some(g) = &insn.guard {
        if g.pred < 7 {
            out.push((g.uniform, if g.uniform { 64 + g.pred } else { 128 + g.pred }));
        }
    }
    out
}

// ── Load-address WAR (write-after-read) helpers ──────────────────────────────

/// Source GPRs that a load latches asynchronously from the register file a few
/// cycles AFTER issue: the address registers. SM120 64-bit addressing reads a
/// register pair (base, base+1), so both are exposed to a WAR if a later
/// instruction overwrites them before the memory pipe latches them.
///
/// Returns the address GPR numbers read by a long-latency load. Empty for
/// non-loads (we only protect the memory-pipe operand read here).
fn load_addr_gprs(insn: &Instruction) -> Vec<u8> {
    let op = insn.opcode.as_str();
    if !is_long_latency(op) || is_store(op) { return Vec::new(); }
    // Global memory uses a 64-bit address pair (base, base+1); shared/local (LDS/LDL)
    // use a single 32-bit address register.
    let wide = matches!(op,
        "LDG" | "LDGX" | "LDGSTS" | "LD" | "ATOM" | "ATOMG" | "RED" | "REDG" | "LDGDEPBAR");
    let mut out = Vec::new();
    let mut push = |r: u8| {
        out.push(r);
        if wide && r < 255 { out.push(r + 1); }
    };
    for operand in &insn.operands {
        match operand {
            Operand::Addr { base_reg: Some(r), .. } => push(*r),
            Operand::Desc { base_reg: Some(r), .. } => push(*r),
            Operand::ConstMem { base_reg: Some(r), .. } => push(*r),
            _ => {}
        }
    }
    out
}

/// GPR destinations of an instruction (numbers < 128), for WAR-writer detection.
fn dest_gprs(insn: &Instruction) -> Vec<u8> {
    dest_regs(insn).into_iter()
        .filter(|(u, r)| !*u && *r < 128)
        .map(|(_, r)| r)
        .collect()
}

/// True when the kernel contains a load-address WAR: a long-latency load whose
/// address register is overwritten by a later instruction within the same basic
/// block (before the next control-flow edge). This is the pattern nvcc/ptxas
/// protect with a read-barrier; when present we reserve barriers {0,1} so
/// `assign_war_read_barriers` has slots that never alias a load write-barrier.
fn detect_load_war(insns: &[Instruction]) -> bool {
    const WINDOW: usize = 40;
    for (i, insn) in insns.iter().enumerate() {
        let addrs = load_addr_gprs(insn);
        if addrs.is_empty() { continue; }
        let end = (i + 1 + WINDOW).min(insns.len());
        for j in (i + 1)..end {
            if is_control_flow(insns[j].opcode.as_str()) { break; }
            let dsts = dest_gprs(&insns[j]);
            if addrs.iter().any(|a| dsts.contains(a)) { return true; }
        }
    }
    false
}

/// Address base registers referenced by a memory instruction's operands (the regs
/// whose VALUE forms the effective address). Used to seed the address-feeding taint.
fn mem_addr_base_regs(insn: &Instruction) -> Vec<(bool, u8)> {
    let op = insn.opcode.as_str();
    if !(is_long_latency(op) || is_store(op)) { return Vec::new(); }
    let mut out = Vec::new();
    for o in &insn.operands {
        match o {
            Operand::Addr { base_reg: Some(r), ur_reg, .. } => {
                out.push((false, *r));
                if let Some(u) = ur_reg { out.push((true, *u)); }
            }
            Operand::Desc { base_reg, ur_idx, .. } => {
                if let Some(r) = base_reg { out.push((false, *r)); }
                out.push((true, *ur_idx));
            }
            Operand::ConstMem { base_reg: Some(r), ur_reg, .. } => {
                out.push((false, *r));
                if let Some(u) = ur_reg { out.push((true, *u)); }
            }
            _ => {}
        }
    }
    out
}

/// CUBIT_SCHED2: identify loads whose *result* feeds (transitively) a memory ADDRESS —
/// i.e. a gather/scatter pointer chain (`LDS.128 → IADD.64 → LDG[Raddr]`). Such loads
/// must NOT share a (last-only) write barrier: at high occupancy variable load latency
/// (e.g. shared-mem bank conflicts) lets the consumer proceed on the batch's LAST load
/// while an earlier one is still in flight → a stale address register → OOB. ptxas gives
/// every address-feeding load its own barrier; only pure-compute loads (e.g. the PV
/// dequant `LDG.E.U8 → F2FP → HMMA`, whose data never forms an address) are batched.
///
/// Single backward pass with per-def kill (so a register reused first as an address and
/// then as load data — common in gather loops — is classified per live-range, not
/// conflated). Conservative: only the address-BASE of a memory op seeds the taint (a
/// store's DATA does not), so the output-store path does not taint the dequant loads.
fn compute_addr_feeding(insns: &[Instruction]) -> Vec<bool> {
    let n = insns.len();
    let mut feeds = vec![false; n];
    let mut tg = [false; 256];
    let mut tu = [false; 64];
    for i in (0..n).rev() {
        let insn = &insns[i];
        let op = insn.opcode.as_str();
        let dests = dest_regs(insn);
        let dest_tainted = dests.iter().any(|(u, r)| {
            if *u { (*r as usize) < 64 && tu[*r as usize] }
            else { (*r as usize) < 256 && tg[*r as usize] }
        });
        if dest_tainted && is_long_latency(op) && !is_store(op) {
            feeds[i] = true;
        }
        // Kill: this instruction defines its dests; taint above comes from uses above.
        for (u, r) in &dests {
            if *u { if (*r as usize) < 64 { tu[*r as usize] = false; } }
            else if (*r as usize) < 256 { tg[*r as usize] = false; }
        }
        // Propagate: an instruction computing an address-feeding value taints its sources.
        if dest_tainted {
            for (u, r) in src_regs(insn) {
                if u { if (r as usize) < 64 { tu[r as usize] = true; } }
                else if (r as usize) < 128 { tg[r as usize] = true; }
            }
        }
        // Seed: the address-base registers of a memory op carry an address.
        for (u, r) in mem_addr_base_regs(insn) {
            if u { if (r as usize) < 64 { tu[r as usize] = true; } }
            else if (r as usize) < 256 { tg[r as usize] = true; }
        }
        // Seed: a value stored to SHARED/LOCAL scratch may be re-loaded and used as a
        // gather address later (the slot/address staging pattern: QK computes pointers,
        // `STS`s them to smem, the PV phase `LDS`es them back as `LDG` bases). Taint such
        // store DATA so the load producing it isn't batched either. GLOBAL stores (`STG`)
        // are final outputs — NOT tainted (so the PV dequant loads stay batchable).
        if matches!(op, "STS" | "STSM" | "STL") {
            for (u, r) in src_regs(insn) {
                if u { if (r as usize) < 64 { tu[r as usize] = true; } }
                else if (r as usize) < 128 { tg[r as usize] = true; }
            }
        }
    }
    feeds
}

// ── Main scheduling pass ─────────────────────────────────────────────────────

/// Full scheduling pass: register dependency tracking + multi-barrier allocation.
///
/// For each instruction (in program order):
/// 1. Compute wait_mask from source register dependencies
/// 2. Compute stall count from def-use distances (short-latency producers)
/// 3. Assign write_bar for long-latency producers
/// 4. Handle pred-only stall counts (no barrier mechanism for predicates)
///
/// When `table` is provided, per-InsKey `ctrl_class` constraints are enforced:
/// - MUFU: wait_mask not assigned (use NOP gap for dependencies)
/// - IADD3+RZ: neither wait_mask nor write_bar are assigned
///
/// Skips instructions that have user-specified control codes.
pub fn schedule(insns: &mut [Instruction], table: Option<&IsaTable>) {
    let mut st = SchedulerState::new();

    // CUBIT_SCHED2: loads whose result feeds a memory address are kept out of barrier
    // batches (one barrier each) so a gather pointer never reads a stale address at high
    // occupancy. Disable-able via CUBIT_SCHED2_ADDRBATCH=1 for A/B.
    let addr_feeding: Vec<bool> = if st.sched2
        && std::env::var("CUBIT_SCHED2_ADDRBATCH").ok().as_deref() != Some("1") {
        compute_addr_feeding(insns)
    } else {
        vec![false; insns.len()]
    };

    // Reserve barrier 0 for the cooperative-MMA accumulator-store WAR read-barrier
    // when the kernel has an MMA whose accumulator (dest..dest+4) is later read by a
    // store. The unscoreboarded MMA writeback means a later MMA can overwrite the
    // accumulator before that store finishes reading it (WAR), wrong at >=2 CTAs/SM
    // (and across the loop back-edge, where a stall can't reach). main.rs sets rb=0 on
    // the store and makes each MMA input-drain wait B0; here we just keep B0 out of the
    // load write-barrier pool so the rb/wait pair is never aliased by a gather load.
    if !st.reserve_rb {
        let mma_accs: Vec<u8> = insns.iter()
            .filter(|x| is_warp_mma(x.opcode.as_str()))
            .filter_map(|x| match x.operands.first() {
                Some(Operand::Reg { num, .. }) => Some(*num),
                _ => None,
            }).collect();
        if !mma_accs.is_empty() {
            let store_reads_acc = insns.iter().any(|x| is_store(x.opcode.as_str())
                && x.operands.iter().any(|o| matches!(o,
                    Operand::Reg { num, .. } if mma_accs.iter().any(|&a| *num >= a && *num < a.saturating_add(4)))));
            // Reserving barrier 0 for the WAR rb reassigns ALL load barriers, which on the
            // fused MLA kernel only phase-shifts the separate cooperative-writeback resonance
            // (clock-pinned A/B measured WORSE). So the rb is set on the store WITHOUT a
            // global reservation (main.rs uses barrier 0, shared with loads — the drain
            // over-waits, which is safe). Reservation is opt-in for experiments only.
            let _ = store_reads_acc;
            st.reserve_war_rb = std::env::var("CUBIT_WAR_RESERVE").ok().as_deref() == Some("1");
        }
    }

    // Reserve barriers {0,1} for load-address WAR read-barriers when the kernel has
    // tight load-operand reuse (a gather load whose address reg is overwritten before
    // the async memory pipe latches it). `assign_war_read_barriers` (run after this
    // pass) sets rb on those loads and waits it on the overwriting instruction.
    // Disable-able via CUBIT_LOAD_WAR_RB=0 for A/B.
    // Default reserves {0,1} for rb. Under CUBIT_SCHED2 we instead MULTIPLEX read-barriers
    // onto the full 6-barrier pool (ptxas discipline) via the liveness-aware assignment in
    // `assign_war_read_barriers`, so loads may use all 6 — reserving 2 here would starve the
    // PV-loop top (5 loads: 4×LDS.128 + LDC) and force a premature recycle → OOB at 2 CTAs/SM.
    let load_war_rb_enabled = std::env::var("CUBIT_LOAD_WAR_RB").ok().as_deref() != Some("0");
    if load_war_rb_enabled && !st.sched2 && detect_load_war(insns) {
        st.rb_reserve_mask |= 0b11; // barriers 0 and 1
    }

    for i in 0..insns.len() {
        let op = insns[i].opcode.as_str();
        let op_full = insns[i].opcode_full.as_str();

        // st.clock = issue clock of instruction i (= sum of stall[0..i-1])
        let issue_clock = st.clock;

        // Skip user-overridden control codes.
        // `hand_sched` (a `[CC]` prefix in source) freezes the instruction outright.
        // Otherwise: stall==1 is the default reset value, so we only skip when the
        // user has explicitly set a non-default scheduling field.
        let user_specified = insns[i].hand_sched
            || insns[i].ctrl.write_bar != 7
            || insns[i].ctrl.wait_mask != 0
            || insns[i].ctrl.stall != 1
            || insns[i].ctrl.read_bar != 7;
        if user_specified {
            // Still track register defs so downstream instructions get correct deps.
            // Order matters: clear pending for barriers this insn waits on, THEN mark
            // its own write barrier pending (a user insn may both wait and set a bar).
            st.mark_consumed(insns[i].ctrl.wait_mask);
            // Track the author's write barrier on the defs: an auto-scheduled
            // consumer of a hand-scheduled load must WAIT that barrier. Previously
            // the def was recorded barrier-less, so the consumer fell back to the
            // fixed-latency stall path — for LDC that latency was modeled as 1
            // cycle, and a consumer 1-2 instructions after a hand-prologue LDC
            // read garbage CTA-dependently under load (hardware-confirmed; the
            // measured barrier-less LDC->consumer minimum is 30 cycles on an idle
            // GPU and UNBOUNDED under load — see tools/ldc_latency_validate.py).
            let hand_bar = insns[i].ctrl.write_bar;
            let hand_bar = (hand_bar < NUM_BARRIERS as u8).then_some(hand_bar);
            record_defs(&mut st, &insns[i], i, hand_bar, issue_clock);
            if insns[i].ctrl.write_bar < NUM_BARRIERS as u8 {
                st.mark_pending(insns[i].ctrl.write_bar);
            }
            st.clock += insns[i].ctrl.stall as usize;
            continue;
        }

        // MEMBAR/FENCE: clears all pending barrier deps on GPR/UReg registers.
        // After a memory barrier, all previously issued LDG/LDS/LDC results are
        // guaranteed visible.  Without this, IADD3+RZ instructions (which cannot
        // encode wait_mask due to a hardware constraint) would get an inflated
        // LONG_LATENCY_ESTIMATE stall for every LDG-sourced register they read.
        if matches!(op, "MEMBAR" | "FENCE") {
            for d in st.gpr_defs.iter_mut().chain(st.ureg_defs.iter_mut()).flatten() {
                if d.barrier.is_some() {
                    d.barrier = None; // barrier satisfied by MEMBAR
                }
            }
            // Also release all barriers: reset age and clear pending consumers, so
            // subsequent loads see them as truly free (MEMBAR drained everything).
            st.barrier_age = [0; NUM_BARRIERS];
            st.barrier_pending = 0;
        }

        // Phase 1: compute wait_mask and stall from source dependencies.
        // Uses clock-based distance (not instruction-index distance) to correctly
        // handle interleaved chains where intermediate instructions have stall > 1.
        let mut wait_mask: u8 = 0;
        let mut min_stall: u8 = 1; // nvcc uses 0-2; dep tracking adds more when needed
        let can_wait  = insn_can_set_wait_mask(&insns[i], table);
        let can_write = insn_can_set_write_bar(&insns[i], table);

        let srcs = src_regs(&insns[i]);
        for (is_uniform, reg) in &srcs {
            let def = if *is_uniform {
                st.ureg_defs.get(*reg as usize).and_then(|d| d.as_ref())
            } else if *reg >= 128 {
                // Predicate register — stall only, no barrier
                if let Some(pdef) = st.pred_defs.get((*reg - 128) as usize).and_then(|d| d.as_ref()) {
                    let clock_dist = issue_clock.saturating_sub(pdef.clock);
                    let lat = if pdef.is_carry {
                        // Carry pred → @P BRA needs extra cycles (branch pred pipeline)
                        if is_control_flow(op) {
                            LATENCY_CARRY_PRED_BRANCH as usize
                        } else {
                            LATENCY_ALU as usize
                        }
                    } else {
                        LATENCY_PRED as usize
                    };
                    // CUBIT_SCHED2 (RULE 1): the predicate RAW stall is charged to the
                    // gap BEFORE this consumer (= the previous instruction's look-ahead
                    // deficit), not to the consumer itself. Skip here under stage-3.
                    if !st.stage3 && clock_dist < lat {
                        min_stall = min_stall.max((lat - clock_dist) as u8);
                    }
                }
                continue;
            } else {
                st.gpr_defs.get(*reg as usize).and_then(|d| d.as_ref())
            };

            if let Some(def) = def {
                if let Some(b) = def.barrier {
                    if can_wait {
                        wait_mask |= 1 << b;
                    } else {
                        let clock_dist = issue_clock.saturating_sub(def.clock);
                        const LONG_LATENCY_ESTIMATE: usize = 16;
                        if clock_dist < LONG_LATENCY_ESTIMATE {
                            min_stall = min_stall.max((LONG_LATENCY_ESTIMATE - clock_dist) as u8);
                        }
                    }
                } else if !st.stage3 {
                    let clock_dist = issue_clock.saturating_sub(def.clock);
                    let def_op = insns[def.insn_idx].opcode.as_str();
                    let lat = base_latency(def_op) as usize;
                    if clock_dist < lat {
                        // Tungsten adds +2 margin for SM120 ALU pipeline
                        let need = (lat - clock_dist).min(15);
                        min_stall = min_stall.max(need as u8);
                    }
                }
                // CUBIT_SCHED2 (RULE 1): a fixed-latency producer's RAW stall is charged
                // to the gap BEFORE its consumer (the look-ahead deficit applied to the
                // previous instruction), NOT to the consumer here — see sched2_raw_deficit.
            }
        }

        // Phase 1b: WAW (write-after-write) dependencies.
        // If this instruction writes a register that a pending long-latency
        // producer also writes, we must wait for the producer to complete.
        // Otherwise our write lands first and the late producer overwrites it.
        // Example: LDC.64 R2 writes R2:R3, then MOV R3 writes R3 — without
        // WAW check, LDC.64's late writeback overwrites MOV's R3 value.
        {
            let dsts = dest_regs(&insns[i]);
            for (is_uniform, reg) in &dsts {
                let def = if *is_uniform {
                    st.ureg_defs.get(*reg as usize).and_then(|d| d.as_ref())
                } else if *reg < 128 {
                    st.gpr_defs.get(*reg as usize).and_then(|d| d.as_ref())
                } else {
                    None
                };
                if let Some(def) = def {
                    if let Some(b) = def.barrier {
                        if can_wait {
                            wait_mask |= 1 << b;
                        } else {
                            let clock_dist = issue_clock.saturating_sub(def.clock);
                            const LONG_LATENCY_ESTIMATE: usize = 16;
                            if clock_dist < LONG_LATENCY_ESTIMATE {
                                min_stall = min_stall.max((LONG_LATENCY_ESTIMATE - clock_dist) as u8);
                            }
                        }
                    }
                }
            }
        }

        // CUBIT_SCHED2: an instruction that waits the currently open load-batch barrier
        // is that batch's consumer — close the batch so the next load opens a fresh
        // (counting) barrier instead of piling onto an already-consumed one.
        if st.sched2 {
            if let Some(b) = st.current_load_barrier {
                if (wait_mask & (1 << b)) != 0 {
                    st.current_load_barrier = None;
                    st.current_batch_count = 0;
                    st.current_batch_kind = 0;
                }
            }
        }

        // Phase 2: apply scheduling
        insns[i].ctrl.wait_mask = wait_mask;
        insns[i].ctrl.stall = min_stall;

        // Tungsten per-class constraints:
        // IADD3: stall 1-3 hardware forbidden; with wait_mask: min stall=5
        // CUBIT_SCHED2: ptxas freely uses IADD3 S01-S03 (corpus + gt), so this
        // "1-3 forbidden" bump is disabled under sched2 (it over-stalls IADD3).
        if matches!(op, "IADD3" | "UIADD3") && !st.stage3 {
            if insns[i].ctrl.stall >= 1 && insns[i].ctrl.stall <= 3 {
                insns[i].ctrl.stall = 4;
            }
            if wait_mask != 0 && insns[i].ctrl.stall < 5 {
                insns[i].ctrl.stall = 5;
            }
        }

        // QMMA: SM120 warp-cooperative mode requires:
        // - No write_bar (already excluded from needs_write_bar)
        // - stall >= 11 (matching nvcc behavior for accumulation pipeline)
        // - yield = true (let other warps run during accumulation)
        //
        // wait_mask is computed normally (for LDG/LDC/S2R deps) but MUST NOT
        // remain on the QMMA instruction itself (each bit halves K-accumulation).
        // The main.rs drain pass moves it to a preceding UIADD3 URZ.
        if is_warp_mma(op) {
            // The MMA's own stall must stay ~11 (nvcc value): the @!UPT writeback drains
            // (inserted in main.rs) must fire within a short window after the MMA, so
            // a larger stall pushes them out of the window and the cooperative
            // writeback is never forced. Full accumulator commit is covered by the drain
            // stalls AFTER the MMA, not by inflating the MMA stall here.
            //
            // CUBIT_SCHED2: ptxas runs the cooperative HMMA TIGHT (S01) — it waits its input
            // barrier directly and settles the writeback on the FOLLOWING instruction
            // (`NOP S13`, applied in main.rs). Don't inflate the MMA's own stall here.
            if st.sched2 {
                insns[i].ctrl.stall = insns[i].ctrl.stall.max(1);
            } else {
                insns[i].ctrl.stall = insns[i].ctrl.stall.max(11);
            }
            insns[i].ctrl.yield_flag = true;
            insns[i].ctrl.write_bar = 7; // SM120 ignores write_bar on warp MMA (QMMA/HMMA/…)
            // wait_mask is LEFT IN PLACE for main.rs drain pass to extract and move
        }

        // Memory loads: yield to allow warp switching during memory access.
        // stall=4 matches nvcc behavior: gives memory subsystem time to queue
        // requests before issuing next instruction from same warp.
        // CUBIT_SCHED2: ptxas does NOT blanket-stall every load by 4 — it spaces only
        // CONSECUTIVE same-pipe loads (memory issue throughput) and lets isolated loads
        // run at S01. That spacing + the load yield are applied in the stage-3 end-block.
        if is_long_latency(op) && !is_store(op) {
            if !st.stage3 {
                insns[i].ctrl.yield_flag = true;
            }
            // Memory-issue / address-WAR margin (delays the overwriter so the load latches
            // its address). ptxas uses a read-barrier; cubit's rb pass does not cover every
            // case, so the 4-cycle margin is kept for GPU correctness (drop via NOMEMSTALL).
            if !st.stage3 || st.mem_war_stall {
                insns[i].ctrl.stall = insns[i].ctrl.stall.max(4);
            }
            // A load whose result is loop-carried (read by the next iteration across the
            // back-edge, e.g. a gather load feeding the loop-guard compare) must be more
            // retired before the back-edge; the default 4 is too short at high occupancy
            // (>1 CTA/SM). (Root-caused by stall minimisation vs ptxas at 4-CTA.)
            // CUBIT_SCHED2: kept as a WAR-protection stall (ptxas uses a read-barrier; the
            // diff cost is small — only loop-carried gather loads). Drop with NOMEMSTALL.
            if (!st.stage3 || st.mem_war_stall)
                && load_result_loop_carried(insns, i)
                && std::env::var("CUBIT_FIX_LOAD").as_deref() != Ok("0") {
                insns[i].ctrl.stall = insns[i].ctrl.stall.max(LOAD_LOOPCARRY_STALL);
            }
        }

        // Stores latch their address+data operands a few cycles AFTER issue (the
        // memory pipe reads them post-issue), but the scheduler tracks no WAR
        // (write-after-read) hazard. A following instruction that overwrites a
        // store source register — e.g. `IADD.64 Raddr` bumping the store address
        // in a pointer-walk loop, or `MOV Rdata, RZ` re-zeroing an accumulator —
        // would clobber it before the store consumes it (store writes to the
        // wrong address / stores stale data). Hold the next instruction off with
        // a producer-side stall so the store finishes reading its operands.
        // CUBIT_SCHED2: ptxas keeps store stalls small (S01-S04) and protects the
        // operand-latch WAR with a READ-BARRIER (assign_war_read_barriers), not a big
        // producer stall. The store→store issue spacing is applied in the end-block.
        if is_store(op) {
            // Store-operand latch WAR margin (delays the overwriter so the store reads its
            // intended address+data). ptxas uses a read-barrier; kept as a stall for cubit's
            // partial rb coverage (drop via NOMEMSTALL to study the pure ptxas-style schedule).
            if !st.stage3 || st.mem_war_stall {
                insns[i].ctrl.stall = insns[i].ctrl.stall.max(STORE_OPERAND_READ_STALL);
            }
            // A store right before a loop back-edge has its async operand latch racing
            // the next iteration's overwrite of the same registers (e.g. the cooperative
            // MMA accumulator). The few-cycle default is too short across the back-edge;
            // use the full operand-latch latency. (Root-caused by stall minimisation vs
            // ptxas on the fused PV loop: STG.E.128 reading the accumulator needed 9.)
            // CUBIT_SCHED2: kept as a WAR-protection stall (small diff cost). Drop with
            // NOMEMSTALL to study the pure ptxas-style schedule.
            if (!st.stage3 || st.mem_war_stall)
                && store_precedes_backedge(insns, i)
                && std::env::var("CUBIT_FIX_STORE").as_deref() != Ok("0") {
                insns[i].ctrl.stall = insns[i].ctrl.stall.max(STORE_LATCH);
            }
        }

        // ISETP: stall capped at 7 (opex_8 table restriction from tungsten)
        // CUBIT_SCHED2: the predicate latency is charged to the pre-consumer gap
        // (RULE 1), so the SETP itself is NOT force-stalled/capped here.
        if matches!(op, "ISETP" | "FSETP" | "DSETP" | "UISETP") && !st.stage3 {
            insns[i].ctrl.stall = insns[i].ctrl.stall.min(7);
        }

        if is_pred_writer(op) && !st.stage3 {
            // SM120, measured (tools/predguard_validate.py + sass/predguard_test.sass):
            // the YIELD flag forfeits the stall's latency guarantee for a @P-guard
            // consumer at multi-warp occupancy — `ISETP ... S15+Y` still delivers a
            // STALE predicate to a following `@P` instruction at 8 warps, while a
            // yield-free S13 is always sufficient (1 and 8 warps). A stale guard is
            // catastrophic and environment-dependent: predicate registers are NOT
            // cleared between launches, so the consumer executes under the PREVIOUS
            // kernel's leftover predicate. (Root cause of the warm-context mw8 bug:
            // the slot-clamp `@P1 MOV R22, RZ` fired with leftover P1=true after
            // torch/cuBLAS kernels ran, sending every first-tile QK gather to slot 0;
            // cold contexts pass only because leftover P1 happens to be false.)
            // Vector predicate writers therefore issue YIELD-FREE; the uniform
            // datapath writers (UISETP -> BRA.U loop guards) keep the yield — they
            // are modeled separately (LATENCY_PRED_BRANCH) and extensively validated.
            insns[i].ctrl.yield_flag =
                matches!(op, "UISETP" | "UFSETP" | "UPLOP3" | "UIMNMX" | "UVIMNMX");
        }
        if is_any_carry_pred_writer(op_full) && !st.stage3 {
            insns[i].ctrl.stall = insns[i].ctrl.stall.max(LATENCY_ALU + 1);
        }
        if is_control_flow(op) && !st.stage3 {
            insns[i].ctrl.stall = insns[i].ctrl.stall.max(LATENCY_CTRL);
        }

        // Producer-side stall for multi-cycle ALU without write barriers.
        // nvcc uses stall-based synchronization (not barriers) for ALU results:
        //   IMAD.WIDE → stall=6 (LATENCY_FMA+1), MUFU → stall based on latency
        // The +1 margin matches nvcc behavior and covers pipeline forwarding delay.
        // CUBIT_SCHED2 (RULE 1): DON'T put the full latency on the producer — that is
        // exactly cubit's over-stall bug (S05 where ptxas uses S01). The latency is
        // charged to the gap before the consumer via the look-ahead deficit instead.
        if !st.stage3
            && !insn_needs_write_bar(&insns[i], table, st.sched2) && !is_store(op) && !is_control_flow(op) {
            let lat = base_latency(op);
            if lat > 1 {
                let s = ((lat as u16) + 1).min(15) as u8;
                insns[i].ctrl.stall = insns[i].ctrl.stall.max(s);
            }
        }
        if matches!(op, "ISETP" | "FSETP" | "DSETP" | "UISETP") && !st.stage3 {
            insns[i].ctrl.stall = insns[i].ctrl.stall.max(LATENCY_PRED);
            // A predicate consumed FIRST by a branch (loop-guard compare) needs only the
            // branch-resolve latency (~9), not the full register-predicate forwarding
            // latency (13/14). Over-stalling the loop-guard compare lengthens every
            // iteration and desynchronises the timing-based cooperative-MMA writeback,
            // corrupting the fused PV result. (Root-caused by stall minimisation vs ptxas.)
            if pred_feeds_branch(insns, i)
                && std::env::var("CUBIT_FIX_PRED").as_deref() != Ok("0") {
                insns[i].ctrl.stall = LATENCY_PRED_BRANCH;
            }
        }

        // Retroactive stall correction for carry pred → conditional branch.
        // BRA is fully static → encoder ignores scheduling pass stall.
        // Increase preceding instruction's stall for carry preds (IADD3→@P BRA).
        // Non-carry preds (ISETP→@P BRA) are handled by the manual drain in SASS
        // which provides enough delay via barrier waits.
        // CUBIT_SCHED2 (RULE 1): the carry-pred → branch latency is charged to the
        // pre-branch gap by the look-ahead deficit, so skip the retroactive bump.
        if is_control_flow(op) && !st.stage3 {
            if let Some(g) = &insns[i].guard {
                if !g.uniform && g.pred < 7 {
                    if let Some(pdef) = st.pred_defs.get(g.pred as usize).and_then(|d| d.as_ref()) {
                        if pdef.is_carry {
                            let need_t = pdef.clock + LATENCY_CARRY_PRED_BRANCH as usize;
                            if issue_clock < need_t {
                                let deficit = need_t - issue_clock;
                                if i > 0 {
                                    let prev_user_specified = insns[i-1].ctrl.write_bar != 7
                                        || insns[i-1].ctrl.wait_mask != 0
                                        || insns[i-1].ctrl.read_bar != 7;
                                    if !prev_user_specified {
                                        insns[i-1].ctrl.stall += deficit as u8;
                                    }
                                }
                                st.clock = need_t;
                            }
                        }
                    }
                }
            }
        }

        // Phase 3: assign write_bar — with barrier batching.
        let mut assigned_barrier: Option<u8> = None;
        let is_load = insn_needs_write_bar(&insns[i], table, st.sched2) && can_write;
        // REDUX/SHFL (warp reduction / cross-lane shuffle) are NOT batchable async ops
        // like LDG: multiple sharing one write barrier is illegal on SM120. Force a
        // fresh barrier per op and don't let it join or extend a load batch.
        // CUBIT_SCHED2: the learned non-load variable-latency producers (S2UR/B2R/MUFU/
        // F2I/I2F/FLO/POPC) likewise get their OWN barrier — they are not memory loads and
        // must not share a counting load batch (ptxas gives each its own scoreboard).
        let no_batch = op == "REDUX" || op == "SHFL"
            || (st.sched2 && is_variable_latency_sched2(op));
        if !is_load || no_batch { st.current_load_barrier = None; st.current_batch_count = 0; st.current_batch_kind = 0; }
        if is_load && st.sched2 && !no_batch {
            // CUBIT_SCHED2: ptxas-like barrier batching. Consecutive loads of the same
            // memory class share ONE counting write barrier; the consumer waits it once
            // (drains the whole group). The batch was already closed above if a consumer
            // waited it; a class change also starts a fresh barrier. This keeps the
            // PV loop inside the 6-barrier budget (no premature recycle → no stale read),
            // unlike the default one-barrier-per-load allocation.
            let kind = load_kind_sched2(op);
            // Experiment knob: CUBIT_SCHED2_NOGBATCH disables batching of global/variable
            // loads (kind 1), giving each its own barrier (A/B for the last-only question).
            let no_gbatch = kind == 1 && std::env::var("CUBIT_SCHED2_NOGBATCH").is_ok();
            // Address-feeding loads never join a batch (own barrier — see compute_addr_feeding).
            // Such a load also doesn't anchor a batch the next load could join.
            let solo = addr_feeding[i];
            let reuse = st.current_load_barrier.is_some()
                && st.current_batch_kind == kind
                && st.current_batch_count < SCHED2_MAX_BATCH
                && !no_gbatch
                && !solo;
            let b = if reuse {
                st.current_batch_count += 1;
                st.current_load_barrier.unwrap()
            } else {
                let nb = st.alloc_barrier();
                // Only fires if every barrier is still pending (budget exhausted) — with
                // batching this is rare; keep the drain for safety on pathological inputs.
                if st.pending_drain != 0 {
                    insns[i].ctrl.wait_mask |= st.pending_drain;
                    st.pending_drain = 0;
                    insns[i].ctrl.stall = insns[i].ctrl.stall.max(8);
                }
                st.current_load_barrier = Some(nb);
                st.current_batch_kind = kind;
                st.current_batch_count = 1;
                nb
            };
            insns[i].ctrl.write_bar = b;
            assigned_barrier = Some(b);
            if st.reserve_rb && can_write {
                insns[i].ctrl.read_bar = 0;
            }
            // A solo (address-feeding) load must not anchor a batch for the following load.
            if solo { st.current_load_barrier = None; st.current_batch_count = 0; st.current_batch_kind = 0; }
        } else if is_load {
            // SM120 write barriers are LAST-ONLY (not counting): if N in-flight loads share
            // one write barrier, the barrier only tracks the most-recently-issued load. At
            // high occupancy (>1 CTA/SM) loads complete out of order, so a consumer waiting
            // the shared barrier can proceed while an *earlier* batched load is still in
            // flight -> stale read -> wrong result / bad address (OOB). nvcc never shares a
            // barrier among independently-consumed loads; it uses one barrier per in-flight
            // load (max 6) and recycles via drains. Default to that (batch=1). The env knob
            // is retained for experiments only; >1 is UNSAFE on SM120 at multi-CTA occupancy.
            let max_batch: u8 = std::env::var("CUBIT_MAX_BATCH").ok()
                .and_then(|s| s.parse().ok()).unwrap_or(1);
            // Recycle drain: Finding 1 — a barrier-drain (wait_mask set) needs a stall for the
            // displaced producer to retire at high occupancy (>1 CTA/SM); without it a recycled
            // wbar slot's previous load isn't retired -> stale read at 2 CTAs/SM. The wait_mask
            // is the correctness part; this stall is the retirement margin. 8 is the largest
            // value that still retires the 2-CTA case (validated on mla_decode_cache @ 2-CTA)
            // WITHOUT over-stalling single-warp cooperative-MMA kernels — a drain of 12 sits in
            // the pre-MMA load window and desynchronises the timing-based cooperative writeback
            // (corrupts pv_cache: O = half/zero). Tunable for experiments.
            let recycle_drain: u8 = std::env::var("CUBIT_RECYCLE_DRAIN").ok()
                .and_then(|s| s.parse().ok()).unwrap_or(8);
            let needs_new = st.current_load_barrier.is_none() || st.current_batch_count >= max_batch;
            let b = if needs_new {
                let b = st.alloc_barrier();
                if st.pending_drain != 0 { insns[i].ctrl.wait_mask |= st.pending_drain; st.pending_drain = 0; insns[i].ctrl.stall = insns[i].ctrl.stall.max(recycle_drain); }
                st.current_load_barrier = Some(b); st.current_batch_count = 1; b
            } else {
                if st.pending_drain != 0 { insns[i].ctrl.wait_mask |= st.pending_drain; st.pending_drain = 0; insns[i].ctrl.stall = insns[i].ctrl.stall.max(recycle_drain); }
                st.current_batch_count += 1; st.current_load_barrier.unwrap()
            };
            insns[i].ctrl.write_bar = b;
            assigned_barrier = Some(b);
            // nvcc-style: set a read-barrier on the load (address-operand WAR), on the
            // reserved barrier 0. Experimental (CUBIT_GATHER_RDBAR).
            if st.reserve_rb && can_write {
                insns[i].ctrl.read_bar = 0;
            }
            if no_batch { st.current_load_barrier = None; st.current_batch_count = 0; }
        }

        // Phase 4: drain all outstanding barriers before kernel exit.
        //
        // EXIT is static-ctrl — it CANNOT encode wait_mask (the encoder uses
        // epoch_upper32_static which discards scheduling fields).  Apply the
        // drain to the LAST non-static instruction before EXIT instead.
        //
        // Only drain barriers that are still pending (not yet consumed) and
        // skip any barrier owned by the drain target instruction itself
        // (waiting for your own write_bar would deadlock the warp).
        if matches!(op, "EXIT" | "RET") {
            let mut exit_wait: u8 = 0;
            for b in 0..NUM_BARRIERS {
                if st.barrier_age[b] > 0 && (st.barrier_pending & (1 << b)) != 0 {
                    exit_wait |= 1 << b;
                }
            }
            if exit_wait != 0 {
                for j in (0..i).rev() {
                    if insn_can_set_wait_mask(&insns[j], table) {
                        // Don't wait for our own write barrier
                        let own_bar = insns[j].ctrl.write_bar;
                        let safe_wait = if own_bar < NUM_BARRIERS as u8 {
                            exit_wait & !(1u8 << own_bar)
                        } else {
                            exit_wait
                        };
                        if safe_wait != 0 {
                            insns[j].ctrl.wait_mask |= safe_wait;
                            break;
                        }
                        // If nothing safe to drain here, try earlier instruction
                    }
                }
            }
        }

        // Phase 5: drain active barriers on backward branches (loop back-edges).
        // When a BRA jumps backwards (loop iteration), any barriers set within
        // the loop body must be drained before the next iteration's LDGs reuse
        // the same barrier slots. Without this drain, LDG data from the previous
        // iteration leaks into the next iteration's QMMA reads.
        //
        // Fix: set wait_mask on the backward BRA itself to drain all active barriers.
        // Previous attempt (on ISETP) failed due to stall cap; BRA has no such limit.
        if is_control_flow(op) {
            // Detect backward branch: target address < current address.
            // During scheduling, addr may not be assigned yet (== 0).
            // Use instruction index as fallback: addr = index * 16.
            let my_addr = if insns[i].addr > 0 { insns[i].addr } else { (i * 16) as u32 };
            if let Some(target) = insns[i].operands.iter().find_map(|o| {
                match o {
                    crate::ir::Operand::Imm32(v) => Some(*v as u32),
                    crate::ir::Operand::BranchTarget(a) => Some(*a),
                    _ => None,
                }
            }) {
                if target < my_addr {
                    // Backward branch — drain all barriers that still have a pending
                    // consumer (their producer's result hasn't been waited on yet) so
                    // the next iteration's loads don't reuse a still-in-flight slot.
                    let mut drain: u8 = 0;
                    for b in 0..NUM_BARRIERS {
                        if st.barrier_age[b] > 0 && (st.barrier_pending & (1 << b)) != 0 {
                            drain |= 1 << b;
                        }
                    }
                    // Don't wait for own write barrier
                    if insns[i].ctrl.write_bar < NUM_BARRIERS as u8 {
                        drain &= !(1u8 << insns[i].ctrl.write_bar);
                    }
                    if drain != 0 {
                        insns[i].ctrl.wait_mask |= drain;
                    }
                }
            }
        }

        // Update pending-consumer state. Clear pending for every barrier this insn
        // waited on (their producers are now drained), THEN re-assert pending for the
        // barrier this insn itself just allocated. The ordering is essential for a
        // self-draining reuse (write_bar == a waited bar): the wait drained the OLD
        // producer, but the barrier must stay pending for the NEW one.
        st.mark_consumed(insns[i].ctrl.wait_mask);
        if let Some(b) = assigned_barrier {
            st.mark_pending(b);
        }

        // Record definitions
        record_defs(&mut st, &insns[i], i, assigned_barrier, issue_clock);

        // ── CUBIT_SCHED2 stage-3 rules: stall placement (1), branch (3), yield (2) ──
        let mut spaced_compute = false;
        if st.stage3 {
            if is_control_flow(op) {
                // RULE 3: branch / back-edge settle stall (overrides the baseline).
                if let Some(s) = sched2_branch_stall(insns, i) {
                    insns[i].ctrl.stall = s;
                }
            } else {
                // RULE 1: charge the binding RAW latency to the gap BEFORE the next
                // instruction (the deficit), now that i (and all prior) are recorded.
                let deficit = sched2_raw_deficit(insns, &st, i + 1, issue_clock);
                let mut s = insns[i].ctrl.stall.max(deficit).max(1);
                // Issue-throughput spacing: consecutive same-pipe ops (global/shared
                // memory, IMAD.WIDE) are spaced regardless of data deps.
                if i + 1 < insns.len() {
                    if let (Some((p0, sp)), Some((p1, _))) =
                        (issue_pipe(&insns[i]), issue_pipe(&insns[i + 1])) {
                        if p0 == p1 {
                            s = s.max(sp);
                            // A COMPUTE-throughput stall (IMAD.WIDE, pipe 3) holds the warp
                            // on a busy ALU pipe → ptxas clears Y. (A MEMORY-throughput stall,
                            // pipes 1/2, keeps Y=1 — the warp yields during memory latency.)
                            if p0 == 3 { spaced_compute = true; }
                        }
                    }
                }
                // 64-bit integer ALU (IADD.64 / IADD3.64) occupies 2 issue slots.
                if matches!(op, "IADD" | "IADD3") && insns[i].opcode_full.contains(".64") {
                    s = s.max(2);
                }
                insns[i].ctrl.stall = s;
            }
            // RULE 2: yield bit.  Compact rule (prompt):
            //   Y=0 if stall==0 OR stall>=12 OR (next-dep AND stall>=4); else Y=1.
            // Refinement (default; report 2a/2b/2c): loads (write-barrier producers) and
            // branches keep Y=1; a non-load non-branch ALU also clears Y at the "settle"
            // stalls {3,4,5,7,9} (where ptxas holds the warp even with no i+1 dependence).
            if !st.no_yield {
                let s = insns[i].ctrl.stall;
                let next_dep = sched2_next_insn_depends(insns, i);
                let mut clear = s == 0 || s >= 12 || (next_dep && s >= 4) || spaced_compute;
                if st.yield_lut {
                    let wb = assigned_barrier.is_some()
                        || insns[i].ctrl.write_bar < NUM_BARRIERS as u8;
                    if !wb && !is_control_flow(op) && matches!(s, 3 | 4 | 5 | 7 | 9) {
                        clear = true;
                    }
                }
                insns[i].ctrl.yield_flag = !clear;
            }
        }

        st.clock += insns[i].ctrl.stall as usize;
    }

    // CUBIT_SCHED2: dead padding after the final EXIT (the tail self-branch + NOPs)
    // carries S00 / no-yield in ptxas. Zero them so the diff isn't polluted by the
    // scheduler's default S01 on unreachable instructions.
    if st.stage3 {
        if let Some(last_exit) = insns.iter().rposition(|x| x.opcode == "EXIT") {
            for x in insns.iter_mut().skip(last_exit + 1) {
                if x.hand_sched { continue; }
                x.ctrl.stall = 0;
                x.ctrl.yield_flag = false;
            }
        }
    }
}

/// A single hazard finding of `report_hazards`.
/// `frozen` = the hazard involves at least one hand_sched (`[CC]`-prefixed)
/// instruction: the auto-scheduler could not repair it by construction, so callers
/// print these unconditionally (fail-closed doctrine) instead of gating on CUBIT_HAZ.
pub struct HazardReport {
    pub msg: String,
    pub frozen: bool,
}

/// Accurate barrier-RAW hazard checker: simulates the scoreboard over the final
/// control codes using the EXACT src/dest extraction, replaying the first backward-
/// branch body once to expose loop-carried hazards. Reports each source register read
/// whose producer set a write-barrier that no intervening instruction waited (i.e. a
/// missing wait → stale read). Also reports reads of a long-latency producer that
/// carries NO write barrier (reachable via a hand_sched `[W-]` tag on a load-like op,
/// which freezes the barrier field off) when the issue-clock distance is below the
/// fixed-latency floor — the consumer reads a stale value with zero tool indication
/// (probe: tagged LDG + white consumer → S05, no wait, silent; BUG-046 family).
/// Used to diff a broken cubit schedule against a known-
/// good (frozen) one: hazards present only in the broken schedule are the bug.
pub fn report_hazards(insns: &[Instruction]) -> Vec<HazardReport> {
    // Build the replay sequence: linear, plus one replay of the first conditional
    // backward-branch loop body (to surface loop-carried deps).
    let mut seq: Vec<usize> = (0..insns.len()).collect();
    for (i, x) in insns.iter().enumerate() {
        if !is_control_flow(x.opcode.as_str()) { continue; }
        let cond = x.guard.is_some() || x.operands.iter().any(|o| matches!(o,
            Operand::Pred { num, .. } | Operand::UPred { num, .. } if *num != 7));
        if !cond { continue; }
        let tgt = x.operands.iter().find_map(|o| match o {
            Operand::Imm32(v) => Some(*v as u32),
            Operand::BranchTarget(a) => Some(*a),
            _ => None,
        });
        if let Some(t) = tgt {
            if t < x.addr {
                if let Some(ti) = insns.iter().position(|y| y.addr == t) {
                    seq.extend(ti..=i);
                    break;
                }
            }
        }
    }

    let mut gpr_owner: [Option<(usize, Option<u8>, usize)>; 256] = [None; 256];
    let mut ureg_owner: [Option<(usize, Option<u8>, usize)>; 72] = [None; 72];
    let mut armed: [Option<usize>; NUM_BARRIERS] = [None; NUM_BARRIERS];
    let mut out: Vec<HazardReport> = Vec::new();
    let mut seen: std::collections::HashSet<(u32, bool, u8)> = std::collections::HashSet::new();
    let mut clock: usize = 0;
    // Floor for barrier-less long-latency RAW: mirrors the LONG_LATENCY_ESTIMATE used
    // by the auto path when a consumer cannot encode a wait. A producer->consumer
    // issue gap below this with no scoreboard cover is a stale-read candidate.
    const NOBAR_FLOOR: usize = 16;
    // BUG-062 (sm120 i134/i135): flag-latency floor for PLOP3/ISETP predicate
    // producers. Silicon fact: a consumer of a fresh flag (guard @Pn or predicate
    // operand) issued less than 13 issue-clocks after the producer's issue reads
    // the STALE predicate (BUG-046 family: trunc-loops / total-fail on INV bodies
    // whose hand tags lowered flag stalls below the floor). Calibration: i134
    // autosched census (flags S14), global class sweep (S12 FAIL / S13 SAFE) and
    // the per-slot map (15/15 flag slots SAFE @ S13); i135 re-confirmed S13 as the
    // target-safe point at production occupancy (24 warp/SM). Floors are
    // occupancy-CONTEXTUAL (values measured @ low-occ ~1-2 warp/SMSP on the i134
    // harness do NOT transfer verbatim to other kernels) -> this class is a WARN,
    // never a hard gate.
    const FLAG_FLOOR: usize = 13;
    // Only the silicon-measured flag producer classes get a tracked producer;
    // every other predicate writer (carry-outs, VOTE, LEA, FSETP, ...) resets the
    // owner to None so we never invent floors for unmeasured classes.
    let mut pred_owner: [Option<(usize, usize)>; 7] = [None; 7];
    let mut seen_flag: std::collections::HashSet<(u32, u8)> = std::collections::HashSet::new();

    for &i in &seq {
        let insn = &insns[i];
        let my_clock = clock;
        clock += insn.ctrl.stall as usize;
        // 1) apply wait_mask: those barriers' producers are now satisfied.
        for b in 0..NUM_BARRIERS {
            if insn.ctrl.wait_mask & (1 << b) != 0 { armed[b] = None; }
        }
        // 2) check sources.
        for (is_u, reg) in src_regs(insn) {
            if reg >= 128 { continue; } // predicate — no barrier mechanism
            let owner = if is_u { ureg_owner.get(reg as usize).copied().flatten() }
                        else { gpr_owner[reg as usize] };
            if let Some((pidx, maybe_wb, pclock)) = owner {
                let frozen = insn.hand_sched || insns[pidx].hand_sched;
                match maybe_wb {
                    Some(b) => {
                        if armed[b as usize] == Some(pidx) {
                            let key = (insn.addr, is_u, reg);
                            if seen.insert(key) {
                                out.push(HazardReport { frozen, msg: format!("RAW @0x{:04x} {:38} reads {}{} <- 0x{:04x} {} (wb{}, NOT waited)",
                                    insn.addr, insn.raw_text.split('/').next().unwrap_or(&insn.opcode).trim(),
                                    if is_u {"UR"} else {"R"}, reg,
                                    insns[pidx].addr, insns[pidx].opcode, b)});
                            }
                        }
                    }
                    None => {
                        // Barrier-less producer: no scoreboard cover exists at all. Only
                        // long-latency classes can outlive the issue gap; fixed-latency
                        // ALU producers are covered by stalls and never reach this.
                        let pop = insns[pidx].opcode.as_str();
                        if is_long_latency(pop) && my_clock.saturating_sub(pclock) < NOBAR_FLOOR {
                            let key = (insn.addr, is_u, reg);
                            if seen.insert(key) {
                                out.push(HazardReport { frozen, msg: format!("RAW @0x{:04x} {:38} reads {}{} <- 0x{:04x} {} (NO barrier, gap {}cy < {}cy floor)",
                                    insn.addr, insn.raw_text.split('/').next().unwrap_or(&insn.opcode).trim(),
                                    if is_u {"UR"} else {"R"}, reg,
                                    insns[pidx].addr, insns[pidx].opcode,
                                    my_clock.saturating_sub(pclock), NOBAR_FLOOR)});
                            }
                        }
                    }
                }
            }
        }
        // 2b) BUG-062 flag-latency: a consumer of a freshly produced predicate
        // (guard @Pn or predicate source operand) issued below the silicon floor
        // reads the STALE flag. Same issue-clock model as the RAW audit
        // (stall(i) spans issue(i) -> issue(i+1), so the producer's own stall is
        // part of the gap, matching the i134 slotmap convention).
        {
            let mut flag_srcs: Vec<u8> = Vec::new();
            if let Some(g) = &insn.guard {
                if !g.uniform && g.pred < 7 { flag_srcs.push(g.pred); }
            }
            for (is_u, reg) in src_regs(insn) {
                if !is_u && (128..135).contains(&reg) { flag_srcs.push(reg - 128); }
            }
            flag_srcs.sort_unstable();
            flag_srcs.dedup();
            for p in flag_srcs {
                if let Some((pidx, pclock)) = pred_owner[p as usize] {
                    let gap = my_clock.saturating_sub(pclock);
                    if gap < FLAG_FLOOR && seen_flag.insert((insn.addr, p)) {
                        // Falsified as an unconditional (fail-loud) class on the
                        // certified R0b publish text (rt98, 5640 ins): 193 findings
                        // at gaps 1..12cy on a kernel that passes silicon EXACT —
                        // the i134 floor does NOT generalise across kernels
                        // (i135's occupancy-context warning, confirmed by direct
                        // measurement). Therefore this class is always reported
                        // with frozen=false, i.e. printed only under CUBIT_HAZ as
                        // a manual probe aid, never into a publish pipeline.
                        out.push(HazardReport { frozen: false, msg: format!("FLAG-LATENCY @0x{:04x} {:36} reads P{} <- 0x{:04x} {} (gap {}cy < {}cy flag floor, i134 low-occ; heuristic - FP on high-quality schedules, see BUG-062 report)",
                            insn.addr, insn.raw_text.split('/').next().unwrap_or(&insn.opcode).trim(),
                            p, insns[pidx].addr, insns[pidx].opcode,
                            gap, FLAG_FLOOR)});
                    }
                }
            }
        }
        // 3) record defs.
        let wb = if insn.ctrl.write_bar < NUM_BARRIERS as u8 { Some(insn.ctrl.write_bar) } else { None };
        for (is_u, reg) in dest_regs(insn) {
            if reg >= 128 {
                // predicate defs for the BUG-062 flag-latency audit: only the
                // silicon-measured producer classes (ISETP*/PLOP3* family of the
                // i134 census) register a floor; any other predicate writer makes
                // the producer unknown (None) so unmeasured classes stay silent.
                if !is_u && reg < 135 {
                    let op = insn.opcode.as_str();
                    pred_owner[(reg - 128) as usize] =
                        if op.starts_with("ISETP") || op.starts_with("PLOP3") {
                            Some((i, my_clock))
                        } else {
                            None
                        };
                }
                continue;
            }
            if is_u { if (reg as usize) < 72 { ureg_owner[reg as usize] = Some((i, wb, my_clock)); } }
            else { gpr_owner[reg as usize] = Some((i, wb, my_clock)); }
        }
        if let Some(b) = wb {
            // RECYCLE conflict: setting barrier b while it's still armed by a DIFFERENT
            // producer means no instruction waited b since (no drain). On SM120 a write
            // barrier is LAST-ONLY, so the prior producer's pending consumers will wait
            // THIS producer instead -> stale read. ptxas always drains before reuse.
            if let Some(prev) = armed[b as usize] {
                if prev != i {
                    let frozen = insn.hand_sched || insns[prev].hand_sched;
                    out.push(HazardReport { frozen, msg: format!("RECYCLE @0x{:04x} {:34} sets wb{} still armed by 0x{:04x} {} (no drain -> prior consumers orphaned)",
                        insn.addr, insn.raw_text.split('/').next().unwrap_or(&insn.opcode).trim(),
                        b, insns[prev].addr, insns[prev].opcode)});
                }
            }
            armed[b as usize] = Some(i);
        }
    }
    out
}

fn record_defs(st: &mut SchedulerState, insn: &Instruction, idx: usize, barrier: Option<u8>, clock: usize) {
    let is_carry = is_any_carry_pred_writer(insn.opcode_full.as_str());
    let dests = dest_regs(insn);
    for (is_uniform, reg) in dests {
        let def = RegDef { insn_idx: idx, barrier, clock };
        if is_uniform {
            if (reg as usize) < st.ureg_defs.len() {
                st.ureg_defs[reg as usize] = Some(def);
            }
        } else if reg >= 128 {
            let pidx = (reg - 128) as usize;
            if pidx < st.pred_defs.len() {
                st.pred_defs[pidx] = Some(PredDef { clock, is_carry });
            }
        } else {
            st.gpr_defs[reg as usize] = Some(def);
        }
    }
}

// ── Correct, interval-based SM120 scoreboard allocator ───────────────────────

/// RAW consumers of the destination set `dsts` produced by the batch ending at
/// `last_setter`. Returns (waiters, wrap) where `wrap` means a consumer reads the
/// value in the NEXT loop iteration (loop-carried). Forward consumers are found
/// until each destination is redefined; loop-carried consumers are the reads in
/// `[ltop, last_setter)` that precede a redefinition.
#[allow(clippy::too_many_arguments)]
fn raw_consumers(reads: &[Vec<u16>], writes: &[Vec<u16>], guarded: &[bool], last_setter: usize,
                 dsts: &[u16], ltop: usize, lback: usize, n: usize) -> (Vec<usize>, bool) {
    // Only the FIRST consumer on each control path needs to wait the write-barrier — once
    // it waits, the load has completed and the destination registers are ready for every
    // later reader. Collect consumers up to and INCLUDING the first UNGUARDED one per path
    // (a guarded first reader may be skipped, so a following reader still needs the wait).
    let mut waiters: Vec<usize> = Vec::new();
    let scan = |waiters: &mut Vec<usize>, lo: usize, hi: usize, dsts: &[u16]| -> bool {
        let mut live: Vec<u16> = dsts.to_vec();
        let mut j = lo;
        while j < hi && !live.is_empty() {
            if reads[j].iter().any(|r| live.contains(r)) {
                if !waiters.contains(&j) { waiters.push(j); }
                if !guarded[j] { return true; }
            }
            live.retain(|d| !writes[j].contains(d));
            j += 1;
        }
        false
    };
    let fwd_end = if lback != usize::MAX { (lback + 1).min(n) } else { n };
    let done = scan(&mut waiters, last_setter + 1, fwd_end, dsts);
    if lback != usize::MAX && !done {
        scan(&mut waiters, lback + 1, n, dsts);
    }
    let mut wrap = false;
    if ltop != usize::MAX && last_setter <= lback {
        let before = waiters.len();
        scan(&mut waiters, ltop, last_setter, dsts);
        if waiters.len() > before { wrap = true; }
    }
    (waiters, wrap)
}

/// Instructions that overwrite a late-latched operand GPR `opk` of a memory op at
/// `i` (WAR hazards) — there can be TWO distinct first-overwriters that must each
/// wait the read-barrier: the linear fall-through one (covers the last loop
/// iteration / straight-line code) and the loop-carried one across the back-edge
/// (covers every non-last iteration). Returns each as (overwriter, wrap).
fn war_overwriter(writes: &[Vec<u16>], i: usize, opk: &[u16],
                  ltop: usize, lback: usize, n: usize) -> Vec<(usize, bool)> {
    let mut out = Vec::new();
    // Fall-through: first overwriter in linear program order (within loop or after it).
    let mut j = i + 1;
    while j < n {
        if writes[j].iter().any(|w| opk.contains(w)) { out.push((j, false)); break; }
        j += 1;
    }
    // Loop-carried: first overwriter at/after the loop top in the next iteration.
    if ltop != usize::MAX && i <= lback {
        let mut k = ltop;
        while k < i {
            if writes[k].iter().any(|w| opk.contains(w)) { out.push((k, true)); break; }
            k += 1;
        }
    }
    out
}

#[derive(Clone)]
struct BarUse {
    setters: Vec<usize>,        // instructions that SET the barrier (>1 only for a batched load group)
    waiters: Vec<usize>,        // instructions that must WAIT it
    is_rb: bool,                // true = read-barrier (WAR), false = write-barrier (RAW)
    segs: Vec<(usize, usize)>,  // occupied program-order index ranges (2 for a loop-carried use)
}

/// Build the occupied index segments of a barrier use from its first setter and
/// waiters. A use with only forward waiters occupies one interval [first, maxFwd].
/// A loop-carried use (some waiter is the NEXT iteration's, i.e. index < first)
/// occupies TWO disjoint segments — [first, loopEnd] this iteration and
/// [loopTop, wrapWaiter] the next — leaving the loop's middle free (so it does NOT
/// reserve the whole loop body, unlike a coarse single interval).
fn build_segs(first: usize, waiters: &[usize], ltop: usize, lback: usize) -> Vec<(usize, usize)> {
    let mut fwd_hi = first;
    let mut wrap_hi: Option<usize> = None;
    for &w in waiters {
        if w >= first { fwd_hi = fwd_hi.max(w); }
        else { wrap_hi = Some(wrap_hi.map_or(w, |x: usize| x.max(w))); }
    }
    match wrap_hi {
        Some(wh) => {
            let lb = if lback != usize::MAX { lback } else { fwd_hi };
            let top = if ltop != usize::MAX { ltop } else { first };
            vec![(first, fwd_hi.max(lb)), (top, wh)]
        }
        None => vec![(first, fwd_hi)],
    }
}

/// Correct unified SM120 scoreboard barrier allocator.
///
/// Replaces the legacy greedy per-op write-barrier pass + the separate load-WAR
/// pass with one interval allocation that is occupancy-robust by construction:
///   * every variable-latency producer with a consumer gets a write-barrier and
///     each consumer waits it (RAW); consecutive same-class loads share one
///     counting barrier (batch);
///   * every memory op whose late-latched operand (load address / store data) is
///     overwritten later gets a read-barrier, waited by the overwriter (WAR),
///     including loop-carried overwrites across the back-edge;
///   * the live barrier intervals are coloured onto the 6 physical scoreboards;
///     loop-carried (wrapping) uses reserve a scoreboard for the whole loop body,
///     transient uses time-multiplex the rest; on overflow it DRAINS (forces the
///     reusing instruction to wait the displaced barrier) instead of silently
///     dropping protection or falling back to an occupancy-blind stall.
///
/// MMAs get NO write-barrier (SM120 cooperative-MMA writeback is unscoreboarded,
/// synchronised by issue distance, which the stall pass already provides); an MMA
/// is treated only as a CONSUMER of its input loads.
/// Make an unwaitable `IADD3 ..., RZ` waitable by swapping the RZ last-source
/// with a plain non-RZ earlier source. The wait/barrier denial is purely
/// POSITIONAL (Rc2==RZ forces hi[7:0]=0xFF); the add is commutative, so the
/// swapped form is semantically identical and encodes wait_mask normally.
/// Returns true when the instruction can now carry a wait.
///
/// This matters for the shared-load address WAR: `LDS R, [R5]` followed
/// immediately by `IADD3 R5, PT, PT, R4, imm, RZ` has NO waitable slot in
/// between, and the old producer-side stall fallback does NOT bound the
/// address-latch window — at >=2 CTAs/SM the LDS can be REPLAYED by MIO
/// arbitration and re-latch its address AFTER the bump (measured: skinny
/// tree-reduce, nondeterministic stale-address gathers, 0/16 at 2 CTAs/SM
/// with stall=9; exact with the swapped-IADD3 wait).
fn try_make_waitable(insn: &mut Instruction) -> bool {
    if insn.opcode != "IADD3" || !iadd3_rc2_is_rz(insn) { return false; }
    let reg_idx: Vec<usize> = insn.operands.iter().enumerate().skip(1)
        .filter(|(_, o)| matches!(o, Operand::Reg { .. }))
        .map(|(i, _)| i).collect();
    let Some(&last) = reg_idx.last() else { return false; };
    if !matches!(&insn.operands[last],
                 Operand::Reg { num: 255, neg: false, abs: false, inv: false, .. }) {
        return false;
    }
    for &i in &reg_idx {
        if i == last { break; }
        let ok = matches!(&insn.operands[i],
            Operand::Reg { num, neg: false, abs: false, inv: false, .. } if *num != 255);
        if ok {
            insn.operands.swap(i, last);
            for o in insn.operands.iter_mut() {
                if let Operand::Reg { reuse, .. } = o { *reuse = false; }
            }
            return true;
        }
    }
    false
}

pub fn reallocate_barriers(insns: &mut [Instruction], table: Option<&IsaTable>) {
    let n = insns.len();
    if n == 0 { return; }
    // Preserve mode: a fully hand-scheduled kernel owns its schedule verbatim
    // (still run the read-only scoreboard verifier on it when requested).
    if insns.iter().all(|x| x.hand_sched) {
        if std::env::var("CUBIT_VERIFY").is_ok() {
            verify_scoreboard(insns, table);
        }
        return;
    }

    let rk = |u: bool, r: u8| -> u16 { ((u as u16) << 8) | r as u16 };

    // Clear barrier fields on non-frozen insns (keep stalls/yields from `schedule`).
    for ins in insns.iter_mut() {
        if !ins.hand_sched {
            ins.ctrl.write_bar = 7;
            ins.ctrl.read_bar = 7;
            ins.ctrl.wait_mask = 0;
        }
    }

    // addr -> index, and innermost loop [top, back] per instruction.
    use std::collections::HashMap;
    let mut addr2idx: HashMap<u32, usize> = HashMap::new();
    for (i, ins) in insns.iter().enumerate() { addr2idx.insert(ins.addr, i); }
    let mut ltop = vec![usize::MAX; n];
    let mut lback = vec![usize::MAX; n];
    for (j, ins) in insns.iter().enumerate() {
        if !is_control_flow(ins.opcode.as_str()) { continue; }
        let Some(t) = branch_target(ins) else { continue; };
        let Some(&ti) = addr2idx.get(&t) else { continue; };
        if ti > j { continue; }
        for k in ti..=j {
            let cur = if ltop[k] == usize::MAX { usize::MAX } else { lback[k] - ltop[k] };
            if j - ti < cur { ltop[k] = ti; lback[k] = j; }
        }
    }

    let writes: Vec<Vec<u16>> = insns.iter()
        .map(|x| dest_regs(x).into_iter().map(|(u, r)| rk(u, r)).collect()).collect();
    let reads: Vec<Vec<u16>> = insns.iter()
        .map(|x| src_regs(x).into_iter().map(|(u, r)| rk(u, r)).collect()).collect();
    let mut can_wait: Vec<bool> = insns.iter().map(|x| insn_can_set_wait_mask(x, table)).collect();
    let can_wb: Vec<bool> = insns.iter().map(|x| insn_can_set_write_bar(x, table)).collect();
    // A consumer is "guarded" if it executes under a non-PT predicate (may be skipped) —
    // then a following reader still needs the producer's write-barrier wait.
    let guarded: Vec<bool> = insns.iter()
        .map(|x| x.guard.as_ref().is_some_and(|g| g.pred < 7)).collect();

    let mut uses: Vec<BarUse> = Vec::new();

    // ---- RAW: variable-latency producers (loads batched, MMA excluded) ----
    let mut i = 0usize;
    while i < n {
        let op = insns[i].opcode.as_str();
        // EXPERIMENT (CUBIT_MMA_WB): also scoreboard the MMA so its loop-carried accumulator
        // writeback is deterministic (consumers wait it) instead of distance/phasing-based.
        let mma_wb = std::env::var("CUBIT_MMA_WB").is_ok();
        let is_prod = (insn_needs_write_bar(&insns[i], table, true) || (mma_wb && is_warp_mma(op)))
            && can_wb[i] && !insns[i].hand_sched;
        if !is_prod { i += 1; continue; }
        // Batch consecutive same-LATENCY memory loads onto one counting barrier (not the
        // learned scalar variable-latency producers, REDUX/SHFL — those get their own
        // barrier). A SM120 write barrier is last-only, so a consumer waiting it only
        // guarantees the most-recently-issued load on it. Sharing is therefore safe ONLY
        // among loads that complete in issue order — i.e. the SAME opcode and SAME access
        // width. Mixing e.g. LDG.E.128 with LDG.E (different latency) lets the wide/slow
        // load finish AFTER the barrier clears → the consumer reads a stale value.
        let width_of = |of: &str| -> u8 {
            if of.contains(".256") { 32 } else if of.contains(".128") { 16 } else if of.contains(".64") { 8 }
            else if of.contains(".U16") || of.contains(".S16") { 2 }
            else if of.contains(".U8") || of.contains(".S8") { 1 } else { 4 }
        };
        // Batch only consecutive loads of identical opcode AND width (same latency class):
        // a last-only barrier waited once then drains the whole group because same-class
        // loads retire in issue order. Mixing classes (e.g. LDG.E.128 + LDG.E) is unsafe
        // (the slow one finishes after the barrier clears) and is excluded by the key below.
        //
        // MEMORY loads additionally require the SAME ADDRESS STREAM (same base register,
        // immediate offsets within one 128-byte line, base not redefined in between).
        // Same opcode+width does NOT imply in-order completion:
        //  - GLOBAL: two LDG.E from different streams (e.g. a small L2-resident table vs
        //    scattered cache rows) complete in cache-outcome order, so the last-only
        //    barrier clears on the fast one while the slow one is still in flight -> the
        //    consumer reads a STALE register. (Observed: deterministic wrong QK logits
        //    whenever prior kernels left the L2 warm; cold-context runs pass because all
        //    streams miss alike. ptxas batches only contiguous same-line loads — e.g. its
        //    4 slot-index loads on one barrier — and gives scattered loads separate
        //    barriers.)
        //  - SHARED/LOCAL: retirement is NOT issue-ordered across different smem addresses
        //    at >=2 CTAs/SM (cross-CTA MIO/LSU arbitration). Measured (skinny_fp8_mm
        //    split-K reduce, 8x LDS from 1KB-apart addresses batched on one barrier with
        //    a single consumer wait): nondeterministic stale reads, 0/10 at 2 CTAs/SM;
        //    per-load barriers, same kernel: 10/10. Same-base nearby-offset LDS batches
        //    (e.g. mw8's PV 4x LDS.128 [R+0..0x30]) remain provably in-order and batch.
        // Non-memory producers (no address operand) stay class-batchable (in-order on
        // their pipe). CUBIT_SHARED_BATCH=1 restores the old unsafe shared batching (A/B).
        let shared_batch_unsafe =
            std::env::var("CUBIT_SHARED_BATCH").ok().as_deref() == Some("1");
        let batchable = !is_variable_latency_sched2(op) && op != "REDUX" && op != "SHFL";
        let kind = load_kind_sched2(op);
        let w0 = width_of(insns[i].opcode_full.as_str());
        let key0 = load_addr_key(&insns[i]);
        let mut group = vec![i];
        if batchable {
            let mut gd: Vec<u16> = writes[i].clone();
            let mut j = i + 1;
            while j < n {
                let opj = insns[j].opcode.as_str();
                if is_control_flow(opj) { break; }
                // stop if this insn consumes a value already loaded by the group
                if reads[j].iter().any(|r| gd.contains(r)) { break; }
                let prodj = insn_needs_write_bar(&insns[j], table, true)
                    && !is_warp_mma(opj) && can_wb[j] && !insns[j].hand_sched;
                if prodj {
                    let batchablej = !is_variable_latency_sched2(opj) && opj != "REDUX" && opj != "SHFL";
                    if !batchablej || load_kind_sched2(opj) != kind
                        || opj != op || width_of(insns[j].opcode_full.as_str()) != w0 { break; }
                    if !(kind == 2 && shared_batch_unsafe) {
                        // memory loads: provably same-line only; non-memory producers
                        // (no address operand -> (None, None)) stay class-batchable
                        // (in-order on their pipe)
                        let same_line = match (key0, load_addr_key(&insns[j])) {
                            (Some((k0, o0)), Some((kj, oj))) => k0 == kj && (oj - o0).abs() < 0x80,
                            (None, None) => true,
                            _ => false,
                        };
                        if !same_line { break; }
                    }
                    group.push(j);
                    for w in &writes[j] { if !gd.contains(w) { gd.push(*w); } }
                } else if !(kind == 2 && shared_batch_unsafe) {
                    // a gap instruction redefining the stream's base register splits the
                    // line (the next "same-key" load actually targets a different line)
                    if let Some((k0, _)) = key0 {
                        if k0 < 0x100 {
                            let b = k0 as u8;
                            let pair = [rk(false, b), rk(false, b.saturating_add(1))];
                            if writes[j].iter().any(|w| pair.contains(w)) { break; }
                        }
                    }
                }
                j += 1;
            }
        }
        let last = *group.last().unwrap();
        let mut gd: Vec<u16> = group.iter().flat_map(|&g| writes[g].clone()).collect();
        gd.sort_unstable(); gd.dedup();
        let (waiters, _wrap) = raw_consumers(&reads, &writes, &guarded, last, &gd, ltop[last], lback[last], n);
        if !waiters.is_empty() {
            let segs = build_segs(group[0], &waiters, ltop[last], lback[last]);
            uses.push(BarUse { setters: group.clone(), waiters, is_rb: false, segs });
        }
        i = last + 1;
    }

    // ---- WAR: read-barriers on memory ops whose late operands are overwritten ----
    for idx in 0..n {
        if insns[idx].hand_sched { continue; }
        let op = insns[idx].opcode.as_str();
        let is_store_war = insn_is_store(&insns[idx], table);
        let late: Vec<u8> = if is_store_war {
            // A store latches BOTH its data AND its address late — protect both against a
            // later overwriter (the store-address WAR is what ptxas guards on the output
            // pointer bump; cubit previously protected only the data, so the bump raced the
            // in-flight store at 2 CTAs/SM and the result landed at the wrong address).
            let mut v = store_data_gprs(&insns[idx]);
            for r in store_addr_gprs(&insns[idx]) { if !v.contains(&r) { v.push(r); } }
            v
        } else if is_warp_mma(op) {
            // MMA source-operand WAR (third late-latcher class, see mma_src_gprs): the
            // cooperative MMA reads its fragments/scale-factors over a long window; the
            // next iteration's load refilling the same registers must wait the MMA's rb.
            // Without it the kernel is correct only while those loads are slow (cold
            // L2/TLB) — fast completions land inside the read window and tear the
            // operands (warm-context corruption, first tiles of the leading warps).
            mma_src_gprs(&insns[idx])
        } else if is_long_latency(op) {
            // Self-referencing load (`LDG.E.U8 R12, [R12.64]`: an address reg is also the
            // dest) consumes its address at issue, before writing the dest — there is no
            // cross-iteration address-WAR. ptxas leaves these bare; read-barriering them
            // over-allocates the PV-loop scoreboards (recycle pressure → wrong at 2 CTAs/SM).
            let dests = dest_gprs(&insns[idx]);
            let a = load_addr_gprs(&insns[idx]);
            if a.iter().any(|x| dests.contains(x)) { Vec::new() } else { a }
        } else { Vec::new() };
        if late.is_empty() { continue; }
        if !insn_can_set_write_bar(&insns[idx], table) { continue; } // rb shares the same field encoding
        let opk: Vec<u16> = late.iter().map(|&r| rk(false, r)).collect();
        // Protect BOTH the within-iteration (fall-through) and the loop-carried
        // (next-iteration) overwriter of every late-latched operand (load address or store
        // data). Both are real WARs at high occupancy and are load-bearing for correctness
        // (dropping the loop-carried load-address rb corrupts the gather: 337/340 wrong).
        let mut waiters: Vec<usize> = Vec::new();
        for (ow, _w) in war_overwriter(&writes, idx, &opk, ltop[idx], lback[idx], n) {
            if !waiters.contains(&ow) { waiters.push(ow); }
        }
        if waiters.is_empty() { continue; }
        let segs = build_segs(idx, &waiters, ltop[idx], lback[idx]);
        uses.push(BarUse { setters: vec![idx], waiters, is_rb: true, segs });
    }

    // ---- colour the uses onto 6 scoreboards via per-instruction occupancy ----
    // `occ[i]` = bitmask of scoreboards live at instruction i. A use takes a barrier
    // free across ALL of its occupied indices (its 1-2 segments). Loop-carried uses
    // (2 segments) are coloured first since they are the most constrained.
    let mut order: Vec<usize> = (0..uses.len()).collect();
    order.sort_by_key(|&u| (uses[u].segs.len() == 1, uses[u].segs[0].0));
    let mut occ = vec![0u8; n];
    let mut assigned: Vec<u8> = vec![7; uses.len()];
    let mut inject_wait = vec![0u8; n];
    let idxset = |segs: &[(usize, usize)]| -> Vec<usize> {
        let mut v = Vec::new();
        for &(a, b) in segs { let b = b.min(n - 1); for i in a..=b { v.push(i); } }
        v
    };

    for &u in &order {
        let sidx = idxset(&uses[u].segs);
        let mut chosen: Option<u8> = None;
        for b in 0..NUM_BARRIERS as u8 {
            if sidx.iter().all(|&i| occ[i] & (1 << b) == 0) { chosen = Some(b); break; }
        }
        let b = match chosen {
            Some(b) => b,
            None => {
                // Overflow (>6 simultaneously live): drain. Force the first setter to WAIT
                // a displaced barrier so its prior producers retire, then share it. Pick a
                // barrier NOT already live at the setter (so it never aliases this insn's own
                // other barrier → no rb==wb) and least-occupied over our segments. Displaced
                // waiters keep their wait (they harmlessly over-wait) — protection is never
                // dropped, only serialised.
                let first = uses[u].setters[0];
                let mut best = 0u8;
                let mut best_cost = usize::MAX;
                for b in 0..NUM_BARRIERS as u8 {
                    if occ[first] & (1 << b) != 0 { continue; }
                    let cost = sidx.iter().filter(|&&i| occ[i] & (1 << b) != 0).count();
                    if cost < best_cost { best_cost = cost; best = b; }
                }
                inject_wait[first] |= 1 << best;
                best
            }
        };
        assigned[u] = b;
        for &i in &sidx { occ[i] |= 1 << b; }
    }

    if std::env::var("CUBIT_DUMP_USES").is_ok() {
        for (u, use_) in uses.iter().enumerate() {
            eprintln!("USE b={} {} setters={:?} waiters={:?} segs={:?}",
                assigned[u], if use_.is_rb {"rb"} else {"wb"}, use_.setters, use_.waiters, use_.segs);
        }
    }

    // ---- emit barrier fields ----
    for (u, use_) in uses.iter().enumerate() {
        let b = assigned[u];
        if b >= NUM_BARRIERS as u8 { continue; }
        for &s in &use_.setters {
            if insns[s].hand_sched { continue; }
            if use_.is_rb { insns[s].ctrl.read_bar = b; }
            else { insns[s].ctrl.write_bar = b; }
        }
        let earliest_setter = use_.setters.iter().copied().min().unwrap_or(0);
        for &w in &use_.waiters {
            if can_wait[w] {
                inject_wait[w] |= 1 << b;
            } else if !insns[w].hand_sched && try_make_waitable(&mut insns[w]) {
                // The dependent was unwaitable only POSITIONALLY (IADD3+RZ):
                // operand-swap it into a waitable form and put the wait where it
                // belongs — on the dependent itself. (The old fallbacks below are
                // occupancy-fragile: a producer-side stall does not bound a shared
                // load's address latch under >=2-CTA MIO replay.)
                can_wait[w] = true;
                inject_wait[w] |= 1 << b;
            } else {
                // The dependent instruction can't encode a wait (e.g. IADD3+RZ). Place the
                // wait on the LATEST waitable instruction strictly between the producer and
                // the dependent — that still drains the barrier before the dependent runs
                // (over-waits, but correct). Never push it before the producer (which sets the
                // barrier) — that wait would target a stale/previous use of the scoreboard.
                let lb = use_.setters.iter().copied().filter(|&s| s < w).max().unwrap_or(earliest_setter);
                let mut placed = false;
                let mut k = w;
                while k > lb + 1 { k -= 1; if can_wait[k] { inject_wait[k] |= 1 << b; placed = true; break; } }
                if !placed {
                    // No waitable slot between producer and dependent: fall back to a
                    // producer-side latch stall (occupancy-blind, last resort).
                    let s = use_.setters.iter().copied().filter(|&s| s < w).max().unwrap_or(earliest_setter);
                    let latch = if use_.is_rb { 9u8 } else { 6u8 };
                    insns[s].ctrl.stall = insns[s].ctrl.stall.max(latch);
                }
            }
        }
    }
    for j in 0..n {
        if inject_wait[j] != 0 && !insns[j].hand_sched && can_wait[j] {
            insns[j].ctrl.wait_mask |= inject_wait[j];
        }
    }

    if std::env::var("CUBIT_VERIFY").is_ok() {
        verify_scoreboard(insns, table);
    }
}

/// Public wrapper so main.rs can run the verifier on fully-frozen kernels (where
/// `reallocate_barriers` is skipped in preserve mode).
pub fn verify_scoreboard_public(insns: &[Instruction], table: Option<&IsaTable>) {
    verify_scoreboard(insns, table);
}

/// Debug: simulate the per-warp scoreboard over the final schedule and report any
/// variable-latency result that is READ before its write-barrier is waited (an
/// unprotected RAW → nondeterministic stale read), or a barrier recycled before
/// its result was waited. Gated by CUBIT_VERIFY.
fn verify_scoreboard(insns: &[Instruction], table: Option<&IsaTable>) {
    use std::collections::HashMap;
    let rk = |u: bool, r: u8| -> u16 { ((u as u16) << 8) | r as u16 };
    let mut pending: HashMap<u16, (u8, usize)> = HashMap::new(); // reg -> (barrier, producer idx)
    let mut lost: HashMap<u16, usize> = HashMap::new(); // reg -> producer idx (barrier recycled before waited)
    // WAR: late-latched operand reg -> (rb barrier, memop idx). Cleared when the rb is waited.
    let mut rbp: HashMap<u8, (u8, usize)> = HashMap::new(); // GPR -> (rb barrier, memop idx)
    let mut nbad = 0;
    let mut nwar = 0;
    let mut nrec = 0;
    for i in 0..insns.len() {
        let wm = insns[i].ctrl.wait_mask;
        if wm != 0 {
            pending.retain(|_, &mut (b, _)| (wm & (1 << b)) == 0);
            rbp.retain(|_, &mut (b, _)| (wm & (1 << b)) == 0);
        }
        for (u, r) in src_regs(&insns[i]) {
            if let Some(&(b, pidx)) = pending.get(&rk(u, r)) {
                eprintln!("  UNPROTECTED RAW: insn[{i}] {} reads {}{} <- var-producer insn[{pidx}] {} (barrier {b} not waited)",
                    insns[i].opcode_full, if u {"UR"} else {"R"}, r, insns[pidx].opcode_full);
                nbad += 1;
            }
            if let Some(&pidx) = lost.get(&rk(u, r)) {
                eprintln!("  RECYCLE-STALE: insn[{i}] {} reads {}{} <- var-producer insn[{pidx}] {} (barrier recycled before waited)",
                    insns[i].opcode_full, if u {"UR"} else {"R"}, r, insns[pidx].opcode_full);
                nrec += 1;
            }
        }
        // WAR: this insn writes a GPR that is an in-flight late-latched operand whose rb
        // it did NOT wait → the memory op may latch the overwritten value (broken rb).
        for r in dest_regs(&insns[i]).into_iter().filter(|(u, _)| !*u).map(|(_, r)| r) {
            if let Some(&(b, midx)) = rbp.get(&r) {
                // Distance coverage: a GLOBAL LOAD consumes its address ~at issue, so an
                // overwriter that issues a few cycles later is safe even without waiting the
                // rb (the within-iteration pointer bump). A GLOBAL STORE queues and latches
                // its operands very late at >1 CTA/SM — distance does NOT cover it (the
                // store-address WAR raced even at 25 cycles), so the overwriter MUST wait the
                // rb. A warp-cooperative MMA likewise latches its source fragments over a
                // long window — distance does not cover an overwriting load that completes
                // fast (L2-hot), so MMA-source overwriters must wait the rb too.
                // A SHARED/LOCAL LOAD can be REPLAYED by MIO arbitration at >=2 CTAs/SM
                // and re-latch its address after the bump — distance does NOT cover it
                // (measured: skinny tree-reduce, stall=9 between LDS and the IADD3 bump,
                // nondeterministic stale-address gathers at 2 CTAs/SM; exact at 1 CTA/SM).
                // (Loop-carried load WARs aren't covered here: the rb is waited at the
                // loop top, which clears `rbp` before the next-iter overwriter is seen.)
                const LOAD_ADDR_LATCH: u32 = 3;
                let dist: u32 = (midx..i).map(|k| insns[k].ctrl.stall as u32).sum();
                let late_latcher = insn_is_store(&insns[midx], table)
                    || is_warp_mma(insns[midx].opcode.as_str())
                    || matches!(insns[midx].opcode.as_str(), "LDS" | "LDSM" | "LDL");
                let covered = !late_latcher && dist >= LOAD_ADDR_LATCH;
                if !covered {
                    eprintln!("  BROKEN WAR: insn[{i}] {} overwrites R{r} before rb (barrier {b}) of mem-op insn[{midx}] {} is waited",
                        insns[i].opcode_full, insns[midx].opcode_full);
                    nwar += 1;
                }
            }
        }
        let var = insn_needs_write_bar(&insns[i], table, true) && !is_warp_mma(insns[i].opcode.as_str());
        let wb = insns[i].ctrl.write_bar;
        let dsts: Vec<u16> = dest_regs(&insns[i]).into_iter().map(|(u, r)| rk(u, r)).collect();
        for d in &dsts { pending.remove(d); lost.remove(d); }
        if var && wb < NUM_BARRIERS as u8 {
            // recycle: regs still pending on wb from an EARLIER producer of a DIFFERENT
            // latency class (opcode/width) become unprotected — the last-only barrier now
            // tracks this producer, which may complete first. Same-opcode/width batch-mates
            // complete in issue order, so they stay protected (not a recycle).
            let wof = |of: &str| if of.contains(".128") {16u8} else if of.contains(".64") {8}
                else if of.contains(".U16")||of.contains(".S16") {2}
                else if of.contains(".U8")||of.contains(".S8") {1} else {4};
            // Same completion-latency class = same opcode + width AND (for MEMORY loads)
            // the same address stream/line — completion order across different streams is
            // not issue order: global is cache-outcome order; shared/local reorders under
            // cross-CTA MIO arbitration at >=2 CTAs/SM (the skinny_fp8_mm tree-reduce
            // repro). Non-memory variable-latency producers (MUFU, S2R, ...) of the same
            // opcode complete in order on their pipe. CUBIT_SHARED_BATCH=1 restores the
            // old (unsafe) shared assumption to mirror the allocator's A/B gate.
            let shared_batch_unsafe =
                std::env::var("CUBIT_SHARED_BATCH").ok().as_deref() == Some("1");
            let same_lat = |p: usize| {
                if insns[p].opcode != insns[i].opcode { return false; }
                if wof(insns[p].opcode_full.as_str()) != wof(insns[i].opcode_full.as_str()) { return false; }
                if load_kind_sched2(insns[i].opcode.as_str()) == 2 && shared_batch_unsafe {
                    return true;
                }
                match (load_addr_key(&insns[p]), load_addr_key(&insns[i])) {
                    (Some((kp, op_)), Some((ki, oi))) => kp == ki && (oi - op_).abs() < 0x80,
                    (None, None) => true,
                    _ => false,
                }
            };
            let losers: Vec<u16> = pending.iter()
                .filter(|(_, &(b, p))| b == wb && !same_lat(p)).map(|(&k, _)| k).collect();
            for l in losers { let (_, pidx) = pending.remove(&l).unwrap(); lost.insert(l, pidx); }
            for d in &dsts { pending.insert(*d, (wb, i)); }
        }
        // register this mem-op's rb-protected late operands
        let rb = insns[i].ctrl.read_bar;
        if rb < NUM_BARRIERS as u8 {
            let op = insns[i].opcode.as_str();
            let late = if matches!(op, "STS" | "STSM" | "STL") {
                // Shared/local stores latch their operands fast (on-chip) and any reader is
                // gated by a CTA barrier, so a later overwrite is covered by issue distance —
                // tracking them only yields false positives.
                Vec::new()
            } else if insn_is_store(&insns[i], table) {
                // GLOBAL stores latch BOTH address and data late and queue at >1 CTA/SM —
                // a later overwrite of either races the in-flight store (the store-ADDRESS
                // WAR bug). Track both; the rb must be waited by the overwriter.
                let mut v = store_addr_gprs(&insns[i]);
                for r in store_data_gprs(&insns[i]) { if !v.contains(&r) { v.push(r); } }
                v
            } else if is_warp_mma(op) {
                // MMA fragments/scale-factors latch over a long read window (see
                // mma_src_gprs) — an overwriting load must wait the MMA's rb.
                mma_src_gprs(&insns[i])
            } else if is_long_latency(op) { load_addr_gprs(&insns[i]) } else { Vec::new() };
            for l in late { rbp.insert(l, (rb, i)); }
        }
    }
    eprintln!("CUBIT_VERIFY: {nbad} unprotected RAW, {nwar} broken WAR, {nrec} recycle-stale");
}

// ── Stall-gap insertion for non-standard scheduling classes ──────────────────

/// Insert IADD3+RZ delay instructions where the scheduler computed a stall
/// that cannot be encoded in the instruction's non-standard scheduling layout.
///
/// IADD3 with Rc2=RZ forces hi_lower32[7:0]=0xFF, giving a hardware-enforced
/// 15-cycle stall regardless of upper32 scheduling bits.
pub fn insert_stall_gaps(insns: &mut Vec<Instruction>, table: Option<&IsaTable>) {
    // Preserve mode: never widen stalls on a fully hand-scheduled kernel.
    if !insns.is_empty() && insns.iter().all(|x| x.hand_sched) { return; }
    let mut i = 0;
    while i < insns.len() {
        let cc = table.and_then(|t| t.ctrl_class(&insns[i].key));
        let can_encode_stall = cc.is_none_or(|c| c.has_standard_upper32_sched() || c.is_static_ctrl());

        if !can_encode_stall && insns[i].ctrl.stall > 1 {
            let needed = insns[i].ctrl.stall as usize;
            let nops = needed.div_ceil(15); // each IADD3+RZ gives 15 cycles
            insns[i].ctrl.stall = 1;

            for j in 0..nops {
                let delay_insn = Instruction {
                    addr: 0,
                    opcode: "IADD3".into(),
                    opcode_full: "IADD3".into(),
                    key: "IADD3_R_P_P_R_R_R".into(),
                    guard: None,
                    operands: vec![
                        Operand::Reg { num: 255, neg: false, abs: false, inv: false, reuse: false },
                        Operand::Pred { num: 7, neg: false },
                        Operand::Pred { num: 7, neg: false },
                        Operand::Reg { num: 255, neg: false, abs: false, inv: false, reuse: false },
                        Operand::Reg { num: 255, neg: false, abs: false, inv: false, reuse: false },
                        Operand::Reg { num: 255, neg: false, abs: false, inv: false, reuse: false },
                    ],
                    modifiers: vec![],
                    ctrl: crate::ir::ControlCode { stall: 15, ..Default::default() },
                    hand_sched: false,
                    rsd: None,
                    raw_text: format!("/* stall gap {}/{} */", j + 1, nops),
                };
                insns.insert(i, delay_insn);
                i += 1;
            }
        }
        i += 1;
    }

    // Re-assign addresses
    for (idx, insn) in insns.iter_mut().enumerate() {
        insn.addr = (idx * 16) as u32;
    }
}

/// Check if an instruction is a backward branch (target < own address).
#[allow(dead_code)]
fn insn_is_backward_branch(insn: &Instruction) -> bool {
    if !is_control_flow(insn.opcode.as_str()) { return false; }
    // Check operands for BranchTarget with address < insn.addr
    for op in &insn.operands {
        if let Operand::BranchTarget(target) = op {
            return *target <= insn.addr;
        }
    }
    false
}

// ── Convergence barrier pass ─────────────────────────────────────────────────

/// Post-encoding pass: set BRA bits[31:24] to the convergence barrier ID.
///
/// Algorithm:
/// 1. Scan for BSSY instructions → record (barrier_id, bssy_addr, target_addr)
/// 2. For each BRA in the encoded bytes, check if it falls inside a BSSY region
/// 3. If so, patch byte at offset+3 (bits[31:24]) with the barrier number
///
/// A BRA at address A is "inside" a BSSY region if bssy_addr < A < target_addr.
/// Handles nesting: innermost BSSY wins (highest start address).
pub fn apply_convergence_barriers(code_bytes: &mut [u8], insns: &[Instruction]) {
    struct BssyRegion { barrier: u8, start: u32, end: u32 }

    let mut regions: Vec<BssyRegion> = Vec::new();
    for insn in insns {
        if insn.opcode != "BSSY" { continue; }
        let barrier = insn.operands.iter().find_map(|op| {
            if let Operand::Barrier(b) = op { Some(*b) } else { None }
        });
        let target = insn.operands.iter().find_map(|op| {
            if let Operand::BranchTarget(t) = op { Some(*t) } else { None }
        });
        if let (Some(b), Some(t)) = (barrier, target) {
            regions.push(BssyRegion { barrier: b, start: insn.addr, end: t });
        }
    }

    if regions.is_empty() { return; }

    for insn in insns {
        if !matches!(insn.opcode.as_str(), "BRA" | "JMP" | "CALL") { continue; }
        let addr = insn.addr;
        // Find innermost enclosing BSSY region
        let best = regions.iter()
            .filter(|r| addr > r.start && addr < r.end)
            .max_by_key(|r| r.start);
        if let Some(region) = best {
            let off = addr as usize;
            if off + 3 < code_bytes.len() {
                code_bytes[off + 3] = region.barrier;
            }
        }
    }
}
