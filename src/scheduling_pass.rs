//! Scheduling pass: register dependency tracking, barrier allocation,
//! stall-count computation, and convergence-barrier assignment.
//!
//! Replaces the simple single-barrier pass with a proper multi-barrier
//! scheduler modeled after ptxas behavior on SM120.
//!
//! When an `IsaTable` is provided, per-InsKey `ctrl_class` information
//! is used to enforce hardware-verified scheduling constraints:
//! - MUFU: wait_mask forbidden (corrupts TABLES_opex_0 decode)
//! - IADD3+RZ: wait_mask and write_bar forbidden (hi\[7:0\]=0xFF forced)
//! - Correct long-latency detection (write_bar assignment) per class

use crate::ctrl_class::{CtrlClass, iadd3_rc2_is_rz};
use crate::ir::{Instruction, Operand};
use crate::table::IsaTable;

/// Set by a caller of [`schedule`] that runs the dependency-latency legaliser
/// (`dep_stall::apply` with the table of `CUBIT_SCHED2_LAT`) on the result - `cubit asm` does,
/// and refuses to write a kernel the legaliser cannot make legal.
///
/// Under `CUBIT_SCHED2` + `CUBIT_SCHED2_LAT`, `schedule()` leaves the fixed-latency RAW deficits
/// to that legaliser. The environment alone must not switch them off: `cubit::assemble`, the
/// Python module and anything else that calls the passes directly have no legaliser behind
/// them, and with the switch in the environment they emitted every fixed-latency pair one cycle
/// apart (`ISETP` -> its guard at S01). Without this flag `schedule()` charges the fixed
/// latencies itself, as under plain `CUBIT_SCHED2`.
pub static DEP_LEGALISER_FOLLOWS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `CUBIT_SCHED2_MEMSTALL=table` (opt-in; `cubit asm` with `CUBIT_SCHED2=1` and a table in
/// `CUBIT_SCHED2_LAT`): the stall behind a memory word is the dependency table's.
///
/// Under `CUBIT_SCHED2` [`schedule`] still writes stalls of its own on memory words. They are
/// older than the table and than the allocator that runs behind this pass:
///
/// * **4** on every load and special-register read ("memory-issue / address-WAR margin") and on
///   every store (the operand-latch margin; **9** in front of a back edge) - the cover of a time
///   when the read-barrier pass did not reach every overwriter. `reallocate_barriers` sets the
///   read barriers by liveness, and `CUBIT_VERIFY` checks them on every path
///   (`CUBIT_VERIFY_RBPROBE=1`: also for a word that carries no read barrier);
/// * **10** on a load whose destination register number a predicate writer reads earlier in the
///   text of the loop (`load_result_loop_carried`, "retired before the back edge") - a reader of
///   the result waits the load's write barrier on every path, whatever the register is called.
///
/// ptxas writes neither. Behind a shared-memory load it stalls 4 where the next word is a
/// memory word (27 718 of 32 718 sites in the 381 distinct kernels of the sm_120 census, never
/// more than 7) and 1 where it is not (32 628 of 38 298). With the variable neither is written.
/// A memory word is then held to what the table says - its `mem`, `ldc` and `bar` rows and the
/// scoreboard arming distance, which `dep_stall::apply` enforces on every control-flow path
/// behind the allocator - and to this pass's spacing of two adjacent words of one memory pipe
/// (`issue_pipe`).
///
/// Two distances that those margins kept by accident become requirements by name under the
/// variable, as under `CUBIT_SYNC_CLASSES` (`cubit asm` sets both up): what has to have landed
/// in front of `EXIT` and the other settle words (`dep_stall`'s landing rows,
/// `sync_class::settle_need`), and the operand hold of an MMA and of a uniform-datapath reader
/// (`sync_class::hold_operands`).
///
/// **One stall of this pass stays where the final allocation needs it:** **8** on a load for
/// which the pass's own text-order barrier allocation had no free barrier (its "recycle
/// drain"). `reallocate_barriers` replaces that allocation, and [`settle_recycle_drains`] judges
/// the word on the final one: the stall goes where nothing is in flight on the barrier the word
/// sets, where the word waits that barrier and sets it again behind a load of a measured pair,
/// and where the producers that share the barrier up to its wait are a measured set of shared
/// loads; it stays where the set is anything else (KNOWN_ISSUES A32, A38). Under the variable
/// the stall has its name, `CUBIT_RECYCLE_DRAIN=<n>` (default 8; the knob of the default
/// scheduler's drain): lowering it for every word is an experiment, not a form for production.
///
/// Honoured only where the legaliser follows ([`DEP_LEGALISER_FOLLOWS`] with a table in
/// `CUBIT_SCHED2_LAT`): without it the margins are all that stands behind a memory word.
/// `cubit asm` refuses the variable without the table, and any value but `table`
/// ([`mem_stall_request`]). Unset: nothing changes.
pub fn mem_stall_from_table() -> bool {
    matches!(mem_stall_request(), Ok(true))
        && std::env::var("CUBIT_SCHED2").is_ok()
        && std::env::var("CUBIT_SCHED2_LAT").is_ok_and(|v| !v.is_empty() && v != "0")
        && DEP_LEGALISER_FOLLOWS.load(std::sync::atomic::Ordering::Relaxed)
}

// `CUBIT_SCHED2_MEMSTALL=table`: the words on which the first pass wrote the retirement stall of
// its recycle drain -- (the word, its ordinal among the words of the same text, its stall in front
// of the drain, its stall with it) -- for `settle_recycle_drains`, which runs behind the allocator
// on the final instruction list (instructions are inserted in between: an index would not hold).
thread_local! {
    static DRAIN_WORDS: std::cell::RefCell<Vec<(Instruction, usize, u8, u8)>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// The (older, younger) pairs of the recycle of a write barrier behind a wait that were measured
/// right: the older load on the barrier, the younger load's own word waits it and sets it again,
/// the reader of the older register one cycle behind that word with no wait (the stall-floor
/// probes of 2026-11-11, result file b29 `rc_*` and its `_ws_` files: two card models, both
/// clock states).
pub const MEASURED_RECYCLE_PAIRS: &[(&str, &str)] = &[("LDS", "LDS"), ("LDS", "LDS.128"), ("LDS.64", "LDS.64"), ("LDG.E", "LDG.E")];

/// The sets of producers that were measured right with ALL of them on one write barrier in front
/// of one wait, by their forms in text order (result files b16 `m2|m4|m8_*_all`, b29
/// `my2|my4|my8_*_all`, b30 `mx6_mix_all` and their `_ws_` files): two, four and eight plain
/// shared loads, and one mixed set of six.
pub const MEASURED_SHARED_SETS: &[&[&str]] = &[
    &["LDS", "LDS"],
    &["LDS", "LDS", "LDS", "LDS"],
    &["LDS", "LDS", "LDS", "LDS", "LDS", "LDS", "LDS", "LDS"],
    &["LDS", "LDS.64", "LDS", "LDS.128", "LDS", "LDS.64"],
];

/// Two instructions are the same word of the text: guard, opcode with its modifiers, operands.
fn same_word(a: &Instruction, b: &Instruction) -> bool {
    a.opcode_full == b.opcode_full && a.operands == b.operands && format!("{:?}", a.guard) == format!("{:?}", b.guard)
}

/// `CUBIT_SCHED2_MEMSTALL=table`, behind the barrier allocator: the retirement stall of the first
/// pass's recycle drain (`CUBIT_RECYCLE_DRAIN`, default 8) is kept only where the FINAL
/// allocation needs it. The first pass writes it on a load for which its own text-order
/// allocation had no free barrier; `reallocate_barriers` replaces that allocation, and what the
/// word then does with its write barrier is one of three things:
///
/// * nothing is in flight on the barrier when the word sets it (the last producer was waited):
///   no producer is displaced and the stall guards nothing -- the table's value;
/// * the word WAITS the barrier and sets it again over ONE producer in flight (the recycle
///   behind a wait): measured right with the reader of the older register one cycle behind the
///   word for the pairs of [`MEASURED_RECYCLE_PAIRS`] -- the table's value for those, the stall
///   for every other;
/// * the word sets the barrier WITHOUT waiting it while producers are in flight on it (a shared
///   barrier: one wait releases the set): measured right for the sets of
///   [`MEASURED_SHARED_SETS`] -- the table's value when the producers on the barrier up to its
///   wait are one of those sets, the stall when they are anything else (another number of
///   loads, an `LDSM`, an `LDC`, a global load, a shuffle ...).
///
/// The sets and the pairs are the measured ones, not a range: nothing between two numbers of
/// loads and nothing above the largest.
///
/// That every reader of a pending result stands behind a wait is the allocator's rule and the
/// verifier's first count; it is not judged again here. Returns (words that take the table's
/// value, words that keep the stall because of what stands on their barrier, words left alone:
/// a stall some pass in between has changed, a word that is not on the final list).
pub fn settle_recycle_drains(insns: &mut [Instruction]) -> (usize, usize, usize) {
    let recorded = DRAIN_WORDS.with(|d| std::mem::take(&mut *d.borrow_mut()));
    if recorded.is_empty() {
        return (0, 0, 0);
    }
    // the recorded words on the final list
    let at: Vec<(usize, u8, u8)> = recorded
        .iter()
        .filter_map(|(word, ordinal, base, drained)| insns.iter().enumerate().filter(|(_, x)| same_word(x, word)).nth(*ordinal).map(|(i, _)| (i, *base, *drained)))
        .collect();
    let sets = crate::store_paths::barrier_sets(insns, &at.iter().map(|x| x.0).collect::<Vec<_>>());
    let form = |k: usize| insns[k].opcode_full.as_str();
    let mut lower: Vec<(usize, u8)> = Vec::new();
    let mut kept = 0;
    for ((i, base, drained), set) in at.iter().zip(&sets) {
        if insns[*i].ctrl.stall != *drained {
            continue;
        }
        let not_needed = match set {
            None => true,
            Some((in_flight, _)) if in_flight.is_empty() => true,
            Some((in_flight, joiners)) => {
                if insns[*i].ctrl.wait_mask & (1 << insns[*i].ctrl.write_bar) != 0 {
                    in_flight.len() == 1 && MEASURED_RECYCLE_PAIRS.contains(&(form(in_flight[0]), form(*i)))
                } else {
                    let mut set: Vec<usize> = in_flight.iter().chain(joiners).chain(std::iter::once(i)).copied().collect();
                    set.sort_unstable();
                    set.dedup();
                    let forms: Vec<&str> = set.iter().map(|&k| form(k)).collect();
                    MEASURED_SHARED_SETS.contains(&forms.as_slice())
                }
            }
        };
        if not_needed {
            lower.push((*i, *base));
        } else {
            kept += 1;
        }
    }
    for (i, base) in &lower {
        insns[*i].ctrl.stall = *base;
    }
    (lower.len(), kept, recorded.len() - lower.len() - kept)
}

/// `CUBIT_SCHED2_MEMSTALL` as written: `Ok(true)` for `table`, `Ok(false)` when unset or empty,
/// the message of the refusal for any other value (a misspelt opt-in must not build the default
/// schedule silently).
pub fn mem_stall_request() -> Result<bool, String> {
    match std::env::var("CUBIT_SCHED2_MEMSTALL") {
        Err(_) => Ok(false),
        Ok(v) if v.is_empty() => Ok(false),
        Ok(v) if v == "table" => Ok(true),
        Ok(v) => Err(format!(
            "CUBIT_SCHED2_MEMSTALL={v}: the only value is `table` (the stall behind a memory word from the dependency table); unset = the scheduler's own margins"
        )),
    }
}

// ── Latency model (SM120 / Blackwell) ────────────────────────────────────────

const LATENCY_ALU: u8 = 4;      // IADD3, LOP3, SHF, SEL, MOV, PRMT
const LATENCY_FMA: u8 = 5;      // IMAD, LEA, FFMA, FMUL, FADD
const LATENCY_FP64: u8 = 8;     // DFMA, DMUL, DADD
const LATENCY_PRED: u8 = 13;    // ISETP, FSETP — predicate write (consumed by ALU)
const LATENCY_PRED_BRANCH: u8 = 9; // ISETP/UISETP whose predicate is consumed by a branch
const STORE_LATCH: u8 = 9;      // store operand-latch latency across a loop back-edge (WAR)
const LOAD_LOOPCARRY_STALL: u8 = 10; // load whose result is loop-carried: retire before back-edge
const LATENCY_CTRL: u8 = 5;     // EXIT, BRA, RET
/// BUG-479: minimum stall on BAR.SYNC/BAR.RED before the next instruction — a shared-memory
/// access issued within 5 cycles of the barrier slips past it (silicon sm120; ptxas floor 6).
const LATENCY_BAR_SYNC: u8 = 6;
const LATENCY_S2R: u8 = 4;      // S2R, CS2R
/// BUG-480: key of vector predicate P<n> in the `(uniform, reg)` register-key space of
/// `src_regs` / `dest_regs`. GPRs occupy 0..=254 (R255 = RZ is never keyed), so predicates sit
/// above the GPR file; before 2026-11-05 they were keyed as `128 + n` in a `u8`, which made every
/// GPR R128..R254 look like a predicate (no scoreboard, no read barrier — session V's "BUG gpr128").
pub(crate) const PRED_KEY: u16 = 256;
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

pub(crate) fn is_long_latency(op: &str) -> bool {
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

pub(crate) fn is_store(op: &str) -> bool {
    matches!(op, "STG" | "STS" | "STL" | "ST" | "STGX")
}

/// Data (non-address) source GPRs of a store — the values it latches asynchronously a
/// few cycles AFTER issue. A later writer of one of these before the latch is a store-
/// operand WAR (the store commits stale data); ptxas protects it with a read-barrier on
/// the store (e.g. the `STS.64_AR` gather-address staging). Excludes the address base.
pub(crate) fn store_data_gprs(insn: &Instruction) -> Vec<u8> {
    if !is_store(insn.opcode.as_str()) { return Vec::new(); }
    let bases: Vec<u8> = mem_addr_base_regs(insn).into_iter()
        .filter(|(u, _)| !*u).map(|(_, r)| r).collect();
    src_regs(insn).into_iter()
        .filter(|(u, r)| !*u && *r < PRED_KEY && !bases.contains(&(*r as u8)))
        .map(|(_, r)| r as u8).collect()
}

/// Data GPRs of an atomic / reduction (`Rb`, and `Rc` of CAS, at the access width) — latched
/// asynchronously after issue exactly like a store's data (BUG-482: ptxas tags every
/// `ATOMS.MAX.S32 RZ, [R157+UR7+0x15100], R58` of the sparse-MLA kernels with a read barrier;
/// cubit protected only the address registers of the family). A later writer of one of these
/// before the latch is a WAR the overwriter must wait.
pub(crate) fn atom_data_gprs(insn: &Instruction) -> Vec<u8> {
    let op = insn.opcode.as_str();
    if !(is_atom_with_return(op) || is_reduction(op)) { return Vec::new(); }
    let bases: Vec<u8> = mem_addr_base_regs(insn).into_iter()
        .filter(|(u, _)| !*u).map(|(_, r)| r).collect();
    src_regs(insn).into_iter()
        .filter(|(u, r)| !*u && *r < PRED_KEY && !bases.contains(&(*r as u8)))
        .map(|(_, r)| r as u8).collect()
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
pub(crate) fn mma_src_gprs(insn: &Instruction) -> Vec<u8> {
    if !is_warp_mma(insn.opcode.as_str()) { return Vec::new(); }
    // NEEDS 38 (T-10, 2026-11-06): `CUBIT_MMA_SRC_RB=0` switches the rule OFF -- no read barrier on an
    // MMA for its source fragments, so an overwriting load does not wait it (ptxas sets a read barrier
    // on 0 of the 39 624 HMMA/QMMA of the sm_120 census and overwrites fragments with LDS/LDSM at S01).
    // An A/B switch for the owner's decision, measured with K's harness (bits + time); the default is
    // today's rule, which the 2026-06 warm-cache corruption above was measured against.
    if !mma_src_rb_enabled() { return Vec::new(); }
    let mut out: Vec<u8> = Vec::new();
    for (u, r) in src_regs(insn) {
        if !u && r < PRED_KEY && !out.contains(&(r as u8)) { out.push(r as u8); }
    }
    out
}

/// NEEDS 38 switch: the MMA-source read-barrier rule is on unless `CUBIT_MMA_SRC_RB=0`.
pub fn mma_src_rb_enabled() -> bool {
    std::env::var("CUBIT_MMA_SRC_RB").ok().as_deref() != Some("0")
}

/// NEEDS 37 switch (T-11, 2026-11-06): with `CUBIT_GUARDED_READER_SETTLES=1` the FIRST reader of a
/// load on an execution path settles its write barrier whether or not that reader is guarded --
/// the readers behind it carry no wait of their own. The ptxas evidence (50 / 50 census sites,
/// NEEDS_OWNER 37): a wait carried by a predicated instruction is honoured whether or not the guard
/// is true, so the barrier is released at the first reader either way. Today's rule (the default)
/// collects consumers up to and including the first UNGUARDED one per path, so a guarded first
/// reader makes the next reader wait too (V's `sparse_mla_prefill_v41`: 2 extra waits since BUG-485;
/// the production MoE set: see `T/REPORT.md` part 11). An A/B switch for the owner's decision.
pub fn guarded_reader_settles() -> bool {
    std::env::var("CUBIT_GUARDED_READER_SETTLES").ok().as_deref() == Some("1")
}

/// The GPR(s) holding a store's ADDRESS (a store latches its address late, exactly like
/// its data). If that pointer is overwritten before the store retires its address read
/// (e.g. a loop-carried `IADD.64 Rptr, Rptr, stride` bumping the output pointer), the
/// store lands at the wrong location — a real WAR that ptxas protects with a read-barrier
/// and that races only at high occupancy (>1 CTA/SM). Global stores use a 64-bit address
/// pair (base, base+1); shared/local use a single register.
pub(crate) fn store_addr_gprs(insn: &Instruction) -> Vec<u8> {
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

/// BUG-489: does the barrier allocator close its schedule under `store_paths::unwaited_rewrites`
/// -- a second writer of a pending result that its scans do not see (two loads of one batch
/// into one register, a fixed-latency overwriter between two batch-mates, a producer issued
/// again by its own loop) waits the producer's write barrier? Under `CUBIT_SYNC_CLASSES` yes;
/// on the default path no: it stays byte for byte what it was, and the verifier names such a
/// pair. `CUBIT_WAW_WAIT=1` turns the pass on there too, `CUBIT_WAW_WAIT=0` off under the
/// switch (the allocator as it was until 2026-11-11, for an A/B measurement).
pub fn waw_wait_enabled() -> bool {
    match std::env::var("CUBIT_WAW_WAIT").ok().as_deref() {
        Some("0") => false,
        Some("1") => true,
        _ => crate::sync_class::enabled(),
    }
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

pub(crate) fn is_control_flow(op: &str) -> bool {
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
pub(crate) fn insn_needs_write_bar(insn: &Instruction, table: Option<&IsaTable>, sched2: bool) -> bool {
    let op = insn.opcode.as_str();
    // CUBIT_SYNC_CLASSES: a synchronisation word's class decides. The predicate of a phase check
    // (`SYNCS.PHASECHK.TRANS64[.TRYWAIT]`) and of `USETMAXREG.TRY_ALLOC` is a scoreboard result;
    // the fence, the mbarrier init and `SYNCS.CCTL.IVALL` set a barrier the next word of their
    // family waits (an ordering token). The copy group's scoreboard 0 is pinned by the allocator.
    if crate::sync_class::enabled() {
        if let Some(c) = crate::sync_class::classify(insn) {
            return matches!(c.write_bar, crate::sync_class::WriteBar::Result | crate::sync_class::WriteBar::Token(_));
        }
        // ... and `F2F` / `BREV` are scoreboard results (ptxas: every reader of one waits)
        if crate::sync_class::unlisted_scoreboard_result(op) {
            return true;
        }
    }
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
    // BUG-108 (TS2-WIDEX i235): IMAD/UIMAD (all forms, INCLUDING the .WIDE
    // pair-writers) are fixed-latency ALU — hardware does NOT scoreboard
    // them, consumers are synchronised by the producer stall only
    // (nvcc: stall=6, wbar=7). The sm120 table tags the imm-src2 carry
    // forms (IMAD_R_P_R_II_R[_P], UIMAD.WIDE.U32_UR_UR_*_UR) ctrl_class
    // "imad_wide" with needs_write_bar=true, which let the scheduler
    // substitute a write barrier for the stall: Q got S01+wb, the consumer
    // read the WIDE result pair +2 slots in (< S0c floor lo=3 / hi=5) and
    // silicon deterministically returned torn/stale values. An ALU barrier
    // is also batchable garbage for the load-batching pass (last-only
    // semantics). Force the stall path here, table-side tag or not.
    if matches!(op, "IMAD" | "UIMAD") {
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
pub(crate) fn is_warp_mma(op: &str) -> bool {
    matches!(op, "QMMA" | "HMMA" | "IMMA" | "DMMA")
}

/// Returns true when the instruction is a store (no result, fire-and-forget).
#[allow(dead_code)]
pub(crate) fn insn_is_store(insn: &Instruction, table: Option<&IsaTable>) -> bool {
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
    // CUBIT_SYNC_CLASSES: the synchronisation words, control flow and `BAR` carry their wait
    // themselves, as ptxas schedules them (`[B-1----] @!P0 BRA` behind a phase check,
    // `[B--2---] @!P0 NANOSLEEP.SYNCS`, `[B---3--] CCTL.IVALL` behind an acquire load). Their
    // static table classes are honoured by the assembler's control-code injection.
    // The two "cannot wait" laws of the default path are not ptxas's on sm_120 either: 131 `MUFU`
    // words and 689 `IADD3 ..., RZ` words of the served MoE cubin carry a wait mask
    // (`[B0-----] MUFU.RCP R8, R8` behind `I2F.RP R8 [W0]`). Under the switch every instruction
    // waits itself -- no operand swap, no producer-side latch stall, no wait parked on the
    // instruction that happens to stand in front in the text.
    if crate::sync_class::enabled() {
        // ... except the words ptxas never lets wait (`LDGSTS`, `SYNCS.ARRIVE`, the re-check
        // `SYNCS.PHASECHK`, `FENCE`): their wait goes on the instruction in front.
        return !crate::sync_class::never_waits(insn);
    }
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
    // CUBIT_SYNC_CLASSES: a synchronisation word carries its write / read barrier whatever
    // its table class says (`SYNCS.*` rows are `none`, `FENCE` has no class).
    if crate::sync_class::enabled() && crate::sync_class::classify(insn).is_some() {
        return true;
    }
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

pub(crate) fn branch_target(insn: &Instruction) -> Option<u32> {
    // BUG-486: register-indirect control flow has no static target. `RET.REL.NODEC R2, 0x0`
    // returns to R2 + imm, `BRX R4, 0x10` / `JMX` dispatch through the register and
    // `CALL.ABS.NOINC 0x0` carries a relocation; their immediate must not resolve to an
    // in-kernel address (0x0 is instruction 0 — every subroutine return used to become a
    // back-edge over the whole kernel, and the loop-aware verifier / allocator walked it).
    // Mirrors `unresolved_edge_class`: a non-RZ GPR on a control-flow op = register-indirect.
    let op = insn.opcode.as_str();
    if matches!(op, "RET" | "PRET" | "BRX" | "BRXU" | "JMX" | "JMXU") {
        return None;
    }
    if op == "CALL" && insn.opcode_full.contains(".ABS") {
        return None;
    }
    if insn.operands.iter().any(|o| matches!(o, Operand::Reg { num, .. } if *num != 255)) {
        return None;
    }
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

/// BUG-170 (2026-08-26, front-M iter88): the opclasses `uplop3_lut_2out_` /
/// `plop3_lut_2out_` (every PLOP3.LUT / UPLOP3.LUT form) reinterpret ctrl word
/// bits [105:110) = stall[0:4) | yield<<4 as an index into TABLES_opex_1
/// (nvdisasm 13.3.73, "Opclass '`<u>`plop3_lut_2out_', undefined value 0x1e for
/// table 'TABLES_opex_1'" + dataflow abort). Empirical law, 32-value bit-scan
/// on corpus payloads + vendor census (hexdb 32.2M: 5,970 UPLOP3 + 144,796
/// PLOP3 rows, zero outliers): DEFINED = 0x00..=0x0F and 0x11..=0x1B;
/// undefined = 0x10 (yield with stall 0) and 0x1C..=0x1F (yield with stall
/// 12..=15). The stage-3 RULE-2 shaping already clears yield at stall==0 /
/// stall>=12 for every op, i.e. its ptxas-derived shape IS this law on the
/// LOP3 class; the legacy path set yield on UPLOP3 unconditionally and stacked
/// the predicate-latency stall (13+1=14) on top => 0x1e on every standalone
/// text-assembled UPLOP3 (170 repro).
/// Repair maps to the NEAREST vendor-observed legal shape and preserves the
/// wanted delay: stall 0 -> 1 next to yield (0x11, the dominant vendor yield
/// form); stall >= 12 keeps its stall and drops the yield bit (yield-free
/// S12..S15 forms exist in the corpus: 0x0C/0x0F). R/W/wait bits are never
/// touched. Legal-set boundary (0x0F / 0x10 hole / 0x1B / 0x1C) is the load-
/// bearing detail; do not "tidy" it into a plain 5-bit cap.
pub fn opex1_lop3_legalize(op: &str, ctrl: &mut crate::ir::ControlCode) -> bool {
    if !matches!(op, "UPLOP3" | "PLOP3") || !ctrl.yield_flag {
        return false;
    }
    if ctrl.stall == 0 {
        ctrl.stall = 1;
    } else if ctrl.stall >= 12 {
        ctrl.yield_flag = false;
    } else {
        return false;
    }
    true
}

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
    // CUBIT_SYNC_CLASSES: `F2F` and `BREV` belong to the set (their own barrier, never in a load batch)
    || (crate::sync_class::enabled() && crate::sync_class::unlisted_scoreboard_result(op))
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
        if reg >= PRED_KEY {
            // predicate RAW
            if let Some(pd) = st.pred_defs.get((reg - PRED_KEY) as usize).and_then(|d| d.as_ref()) {
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
            // `CUBIT_MMA_PTXAS=1`: the MMA -> consumer distances around the back-edge are the
            // legaliser's (dep_stall), so the branch keeps the plain settle stall.
            let dflt: u8 = if std::env::var("CUBIT_MMA_PTXAS").ok().as_deref() == Some("1") { 5 } else { 11 };
            let v: u8 = std::env::var("CUBIT_MMA_BACKEDGE").ok()
                .and_then(|s| s.parse().ok()).unwrap_or(dflt);
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

pub(crate) const NUM_BARRIERS: usize = 6;
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
    /// `CUBIT_SCHED2_YIELD=loads`: the DEFAULT scheduler's yield policy under SCHED2's stalls --
    /// loads / special-register reads / SHFL and the MMAs yield, nothing else does (no RULE 2).
    /// The policy the attention kernel's SCHED2 stalls are bit-exact with on silicon (2026-11-10).
    yield_loads: bool,
    /// CUBIT_SCHED2 RULE 1 safety margin (CUBIT_SCHED2_MARGIN, default 1). The deficit
    /// uses the LEARNED MODE latency, which under-predicts ~12% of RAW pairs (report 1d) —
    /// a stale read on cubit's fragile cooperative-MMA / dequant chains. A small +margin
    /// over-stalls (gap = L+margin) to stay on the safe side. margin=0 = pure mode latency
    /// (best diff, but breaks the MMA kernels); margin=1 is the correctness default.
    deficit_margin: usize,
    /// `CUBIT_SCHED2_LAT` (with `CUBIT_SCHED2`): the fixed-latency RAW deficits are NOT charged
    /// here on the instruction text — `dep_stall::apply` charges them after the barrier allocator
    /// on the final instruction list, per pair of the latency table and on every control-flow
    /// path. `schedule()` then leaves only the structural stalls (memory issue spacing, BAR,
    /// branches, the store / load WAR margins). Only for a caller that runs that legaliser
    /// ([`DEP_LEGALISER_FOLLOWS`]).
    dep_lat: bool,
    /// CUBIT_SCHED2: keep the load/store WAR-protection producer stalls (occupancy-safe
    /// gather-address / store-operand latch margin). ptxas protects these with read-
    /// barriers instead; cubit's rb pass does not yet cover every case, so the stalls are
    /// kept ON by default for GPU correctness. CUBIT_SCHED2_NOMEMSTALL=1 drops them
    /// (smaller stalls, closer to the gt diff — but exposes the WAR at high occupancy).
    mem_war_stall: bool,
    /// `CUBIT_SCHED2_MEMSTALL=table` ([`mem_stall_from_table`]): behind a memory word this pass
    /// writes what the table's rows ask for and no margin of its own -- `mem_war_stall` is off.
    mem_table: bool,
    /// Under `mem_table`: the retirement stall of this pass's recycle drain (`CUBIT_RECYCLE_DRAIN`,
    /// default 8 -- what the pass writes without the variable).
    recycle_drain: u8,
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
            no_yield: std::env::var("CUBIT_SCHED2_NOYIELD").is_ok()
                || std::env::var("CUBIT_SCHED2_YIELD").ok().as_deref() == Some("loads"),
            yield_loads: std::env::var("CUBIT_SCHED2").is_ok()
                && std::env::var("CUBIT_SCHED2_YIELD").ok().as_deref() == Some("loads"),
            dep_lat: std::env::var("CUBIT_SCHED2").is_ok()
                && std::env::var("CUBIT_SCHED2_LAT").is_ok_and(|v| !v.is_empty() && v != "0")
                && DEP_LEGALISER_FOLLOWS.load(std::sync::atomic::Ordering::Relaxed),
            mem_war_stall: std::env::var("CUBIT_SCHED2_NOMEMSTALL").is_err() && !mem_stall_from_table(),
            mem_table: mem_stall_from_table(),
            recycle_drain: std::env::var("CUBIT_RECYCLE_DRAIN").ok().and_then(|s| s.parse().ok()).unwrap_or(8),
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

/// Atomics with a register return: `ATOM` / `ATOMG` (global) and `ATOMS` (shared).
/// `RED` / `REDG` are the reductions without a return (see `is_reduction`).
fn is_atom_with_return(op: &str) -> bool {
    matches!(op, "ATOM" | "ATOMG" | "ATOMS")
}

/// Reductions: `RED.E.ADD.STRONG.GPU desc[UR4][R2.64], R7` — operand 0 is the ADDRESS,
/// operand 1 the data; there is no destination (BUG-482: the generic skip-1 source rule
/// used to drop the address registers of a reduction).
fn is_reduction(op: &str) -> bool {
    matches!(op, "RED" | "REDG")
}

/// BUG-482 (KNOWN_ISSUES A17): index of the register destination of an atomic with a
/// register return. The family prints `[Pd,] Rd, [addr], Rb[, Rc]`; nvcc's shape carries
/// the predicate destination first (`ATOMG.E.ADD.STRONG.GPU PT, R6, desc[UR4][R2.64], R7`),
/// so `Rd` is operand 1 whenever operand 0 is a predicate. `ATOMS.CAST.SPIN P0, [R2], R4,
/// R5` has a predicate result and no register result → `None`. Mirrors the "atom" role
/// class of `reg_liveness.rs` (the first register operand is the destination). Before
/// the fix `dest_regs` took operand 0 — the predicate — so `Rd` had no producer, the write
/// barrier the long-latency class requests was dropped as waiter-less, and a consumer of
/// `Rd` read the register before the atomic returned (silicon: wrong old values,
/// `T/gpu/kernels/atomg_*.sass`, 2026-11-05).
fn atom_rd_index(insn: &Instruction) -> Option<usize> {
    if !is_atom_with_return(insn.opcode.as_str()) {
        return None;
    }
    match (insn.operands.first(), insn.operands.get(1)) {
        (Some(Operand::Reg { .. }), _) => Some(0),
        (Some(Operand::Pred { .. }), Some(Operand::Reg { .. })) => Some(1),
        _ => None,
    }
}

/// Access width of an atomic / reduction in 32-bit registers, from the opcode modifiers:
/// `.64` / `.S64` / `.U64` / `.F64` / `.F32x2` / `.F16x4` = a pair, `.128` / `.F32x4` /
/// `.F16x8` = a quad, else one register. Both the destination and the data operands
/// (`Rb`, and `Rc` of CAS) are read/written at this width.
fn atom_access_regs(opcode_full: &str) -> u16 {
    let has = |m: &str| opcode_full.contains(m);
    if has(".128") || has(".F32x4") || has(".F16x8") {
        4
    } else if has(".64") || has(".S64") || has(".U64") || has(".F64") || has(".F32x2") || has(".F16x4") {
        2
    } else {
        1
    }
}

pub(crate) fn dest_regs(insn: &Instruction) -> Vec<(bool, u16)> {
    let mut out = dest_regs_plain(insn);
    // CUBIT_SYNC_CLASSES: the convention below (`dest_regs_plain`) completed by the certified
    // transfer functions -- a predicate destination of `LOP3`, the register behind it, the second
    // register of `LDCU.64`, a uniform predicate (`sync_class::certified_xfer`)
    if crate::sync_class::enabled() && !crate::sync_class::owns_operands(insn) && !is_store(insn.opcode.as_str()) {
        if let Some((defs, _)) = crate::sync_class::certified_xfer(insn) {
            for k in defs {
                if !out.contains(&k) { out.push(k); }
            }
        }
        for p in crate::sync_class::predicate_register_xfer(insn).0 {
            let k = (false, PRED_KEY + p as u16);
            if !out.contains(&k) { out.push(k); }
        }
    }
    out
}

/// The scheduler's own destination convention (see `dest_regs`).
pub(crate) fn dest_regs_plain(insn: &Instruction) -> Vec<(bool, u16)> {
    let mut out = Vec::new();
    let op = insn.opcode.as_str();
    // CUBIT_SYNC_CLASSES: the words that name their operands themselves write no register
    // (`SYNCS.ARRIVE.TRANS64 RZ, ...`, `SYNCS.EXCH.64 URZ, ...`); a phase check and
    // `USETMAXREG.TRY_ALLOC` write their predicate -- a result the generic scan does not see.
    if crate::sync_class::enabled() && crate::sync_class::owns_operands(insn) {
        if let Some((u, p)) = crate::sync_class::result_pred(insn) {
            out.push((u, if u { 64 + p as u16 } else { PRED_KEY + p as u16 }));
        }
        return out;
    }
    if is_store(op) || is_control_flow(op) || is_barrier_insn(op) {
        return out;
    }
    // BUG-482: the ATOM family — `Rd` is the first REGISTER operand (operand 1 behind a
    // predicate destination), spanning the access width; a real predicate destination
    // (`Pn`, not `PT`) is a result too. Nothing else of the instruction is written.
    if is_atom_with_return(op) {
        if let Some(idx) = atom_rd_index(insn) {
            if let Some(Operand::Reg { num, .. }) = insn.operands.get(idx) {
                if *num < 255 {
                    for r in 0..atom_access_regs(&insn.opcode_full) {
                        if (*num as u16) + r < 255 { out.push((false, *num as u16 + r)); }
                    }
                }
            }
        }
        if let Some(Operand::Pred { num, .. }) = insn.operands.first() {
            if *num < 7 { out.push((false, PRED_KEY + *num as u16)); }
        }
        return out;
    }
    if is_reduction(op) {
        return out;
    }
    if let Some(first) = insn.operands.first() {
        match first {
            Operand::Reg { num, .. } => {
                out.push((false, *num as u16));
                if (insn.opcode_full.contains(".64") || insn.opcode_full.contains(".128")
                    || insn.opcode_full.contains("WIDE")) && *num < 255 {
                    out.push((false, *num as u16 + 1));
                }
                // BUG-491: `CS2R Rd, <SR>` without `.32` writes the pair `Rd:Rd+1` (`CS2R R8, SRZ`
                // zeroes R8 and R9; the encoder's register grid and the register allocator's target
                // have had the pair since BUG-488). Without the second register here a store that
                // reads `Rd+1` got no read barrier against the `CS2R` that rewrites it, a `CS2R` that
                // rewrites a pending result in `Rd+1` did not wait its producer, the scoreboard
                // verifier counted neither, and a reader of `Rd+1` had no producer in the dependency
                // walk (which took the pair on its own from 2026-11-11 until this line).
                if op == "CS2R" && !insn.modifiers.iter().any(|m| m == ".32") && *num < 254 {
                    out.push((false, *num as u16 + 1));
                }
                if insn.opcode_full.contains(".128") {
                    if *num < 254 { out.push((false, *num as u16 + 2)); }
                    if *num < 253 { out.push((false, *num as u16 + 3)); }
                }
                // BUG-101: .256 memory forms (LDG_R_R_dARI family) write a 256-bit
                // payload; per the M3.5 census doctrine the two printed base registers
                // each name a 128-bit dest quad (Rhi -> Rhi+0..=3, Rlo likewise).
                // Without the span, a consumer of e.g. Rhi+1 or any reg of the second
                // quad never sees the load as producer -> no write-barrier / wait ->
                // stale read (TS2-LDG-WAIT sibling class). Mirror reg_liveness.rs.
                if insn.opcode_full.contains(".256") {
                    for r in 1..4u8 {
                        if *num <= 255 - r { out.push((false, *num as u16 + r as u16)); }
                    }
                }
                // MMA writes a multi-register accumulator: m16n8 F32 = 4 regs, F16 = 2.
                // Without this, consumers of D[1..] (e.g. R1..R3) never see the MMA as
                // the producer and the stall/dep tracking is wrong (stale tensor readout).
                if matches!(op, "QMMA" | "HMMA" | "IMMA" | "DMMA") {
                    let w: u16 = if insn.opcode_full.contains(".F32") { 4 } else { 2 };
                    for r in 1..w {
                        if (*num as u16) + r < 256 { out.push((false, *num as u16 + r)); }
                    }
                }
            }
            Operand::UReg { num, .. } => {
                out.push((true, *num as u16));
                // UIMAD.WIDE.* writes a 64-bit uniform result = UR pair
                // (M3.5 doctrine). Without the +1, a consumer of the hi
                // half (URd+1) never sees this producer (BUG-108 sibling
                // of the BUG-101 span hole, uniform domain).
                if insn.opcode_full.contains("WIDE") && *num < 62 {
                    out.push((true, *num as u16 + 1));
                }
            }
            _ => {}
        }
    }
    // BUG-101 (cont.): the second leading register of a .256 two-reg memory
    // form is the second dest quad, not a source (stores returned empty above).
    if insn.opcode_full.contains(".256") && !is_store(insn.opcode.as_str()) {
        if let Some(Operand::Reg { num: n2, .. }) = insn.operands.get(1) {
            for r in 0..4u8 {
                if *n2 <= 255 - r { out.push((false, *n2 as u16 + r as u16)); }
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
            if *num < 7 { out.push((true, 64 + *num as u16)); }
            if let Some(Operand::UReg { num, .. }) = insn.operands.get(1) {
                if *num < 255 { out.push((true, *num as u16)); }
            }
        }
    }
    // `R2UR Pd, URd, Rs` -- the broadcast form of the register -> uniform move writes the uniform
    // register (operand 1) AND a per-thread predicate (operand 0). The generic match above sees
    // neither (operand 0 is a predicate), so no reader waited for them: the guard of
    // `@!P1 ARRIVES.LDGSTSBAR.64.ARVCNT [UR4]` behind `@P0 R2UR P1, UR4, R3` was scheduled 4 / 9 /
    // 9 / 12 issue cycles behind it and `PLOP3.LUT P0, PT, P1, ...` one. ptxas (93 sites + 40 with
    // a modifier in the sm_120 census, the served MoE cubin and the persistent kernel): the guard
    // 13 at 53 of 53 sites, the predicate as an operand 8 at 133 of 133, the uniform register 13.
    if op == "R2UR" {
        if let Some(Operand::Pred { num, .. }) = insn.operands.first() {
            if *num < 7 { out.push((false, PRED_KEY + *num as u16)); }
            if let Some(Operand::UReg { num, .. }) = insn.operands.get(1) {
                if *num < 63 { out.push((true, *num as u16)); }
            }
        }
    }
    // SHFL: operand 0 is the dst PREDICATE, the register result is operand 1.
    // Record the register so consumers see SHFL (with its write barrier) as producer.
    if op == "SHFL" {
        if let Some(Operand::Reg { num, .. }) = insn.operands.get(1) {
            out.push((false, *num as u16));
        }
        // CUBIT_SYNC_CLASSES: ... and a real predicate destination is a result of the same
        // write-back (`SHFL.BFLY P6, R18, R19, R16, R17` in every collective region of nvcc):
        // the `ISETP P6` behind it must not overtake it.
        if crate::sync_class::enabled() {
            if let Some(Operand::Pred { num, .. }) = insn.operands.first() {
                if *num < 7 { out.push((false, PRED_KEY + *num as u16)); }
            }
        }
    }
    // Pred outputs for ISETP, LEA, IADD3, etc.
    // ISETP: operand 0 = P0 (primary result), operand 1 = PT (secondary)
    // IADD3: operand 1 = carry pred, operand 2 = overflow pred
    if is_pred_writer(op) || op == "LEA" || is_carry_pred_writer(op) {
        // Capture pred from operand 0 (ISETP primary result)
        if let Some(Operand::Pred { num, .. }) = insn.operands.first() {
            out.push((false, PRED_KEY + *num as u16));
        }
        // Capture pred from operand 1 (ISETP secondary / IADD3 carry)
        if let Some(Operand::Pred { num, .. }) = insn.operands.get(1) {
            out.push((false, PRED_KEY + *num as u16));
        }
    }
    out
}

pub(crate) fn src_regs(insn: &Instruction) -> Vec<(bool, u16)> {
    let mut out = src_regs_plain(insn);
    // CUBIT_SYNC_CLASSES: the convention below (`src_regs_plain`) completed by the certified
    // transfer functions, by the high half of a 64-bit address base and the descriptor's second
    // register ...
    if crate::sync_class::enabled() && !crate::sync_class::owns_operands(insn) {
        if let Some((_, uses)) = crate::sync_class::certified_xfer(insn) {
            for k in uses {
                if !out.contains(&k) { out.push(k); }
            }
        }
        for p in crate::sync_class::predicate_register_xfer(insn).1 {
            let k = (false, PRED_KEY + p as u16);
            if !out.contains(&k) { out.push(k); }
        }
        for k in crate::sync_class::wide_address_uses(insn) {
            if !out.contains(&k) { out.push(k); }
        }
        // ... and by the high half of a 64-bit register operand (`IADD.64`, `ISETP.*64`, `BRX`)
        for k in crate::sync_class::wide_operand_uses(insn) {
            if !out.contains(&k) { out.push(k); }
        }
    }
    out
}

/// The scheduler's own source convention (see `src_regs`).
pub(crate) fn src_regs_plain(insn: &Instruction) -> Vec<(bool, u16)> {
    let mut out = Vec::new();
    let op = insn.opcode.as_str();
    // CUBIT_SYNC_CLASSES: every register operand of these words is a source (the address of
    // `ARRIVES.LDGSTSBAR.64.ARVCNT [UR4]` is operand 0; a bulk copy reads all three operands).
    if crate::sync_class::enabled() && crate::sync_class::owns_operands(insn) {
        out = crate::sync_class::source_regs(insn);
        if let Some(g) = &insn.guard {
            if g.pred < 7 {
                out.push((g.uniform, if g.uniform { 64 + g.pred as u16 } else { PRED_KEY + g.pred as u16 }));
            }
        }
        return out;
    }
    let is_mma = matches!(op, "QMMA" | "HMMA" | "IMMA" | "DMMA");
    let is_wide_src = insn.opcode_full.contains("WIDE");
    // BUG-110: for WIDE forms the 64-bit addend is the last NON-PREDICATE
    // operand (certified reg_liveness.rs M3.5 shape law): [dest,a,b,c] and
    // [dest,Pout,a,b,c,Pin]; multiplicands a/b are 32-bit (BUG-108). If the
    // addend slot is RZ/an immediate there is no pair read at all.
    let wide_addend_idx: Option<usize> = if is_wide_src && !is_store(op) {
        insn.operands.iter().rposition(|o| !matches!(o, Operand::Pred { .. } | Operand::UPred { .. }))
    } else {
        None
    };
    // BUG-101: .256 loads name TWO dest base registers (each a 128-bit quad);
    // the second leading Reg is a destination, not a source.
    // BUG-482: a reduction's operand 0 is its ADDRESS (a source); an atomic with a
    // register return starts its sources after `Rd` (operand 1 behind a `Pd`); the
    // predicate-only `ATOMS.CAST.SPIN Pd, [addr], …` starts after `Pd` like everything else.
    // BUG-486: `SHFL.* Pd, Rd, Ra, Rb, imm` — operand 0 is the predicate result, operand 1 the
    // register result (dest_regs records it); the sources start behind it. Counting Rd as a
    // source made the verifier report a false RAW (`SHFL.IDX PT, R35, …` "reads" the R35 an
    // LDS.128 was still writing) and gave the allocator a false waiter.
    let shfl_pd_rd = op == "SHFL" && matches!(insn.operands.first(), Some(Operand::Pred { .. }));
    // `R2UR Pd, URd, Rs`: operand 0 is the predicate result, operand 1 the uniform result
    // (`dest_regs_plain`); the one source is the register behind them.
    let r2ur_pd_urd = op == "R2UR" && matches!(insn.operands.first(), Some(Operand::Pred { .. }));
    let start = if is_store(op) || is_reduction(op) { 0 }
        else if let Some(rd) = atom_rd_index(insn) { rd + 1 }
        else if shfl_pd_rd || r2ur_pd_urd
            || (insn.opcode_full.contains(".256")
                && matches!(insn.operands.first(), Some(Operand::Reg { .. }))
                && matches!(insn.operands.get(1), Some(Operand::Reg { .. }))) { 2 }
        else { 1 };
    for (op_idx, operand) in insn.operands.iter().enumerate().skip(start) {
        match operand {
            Operand::Reg { num, .. } if *num < 255 => {
                out.push((false, *num as u16));
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
                        if *num + r < 255 { out.push((false, *num as u16 + r as u16)); }
                    }
                } else if is_atom_with_return(op) || is_reduction(op) {
                    // BUG-482: the data operands of an atomic / reduction (`Rb`, and `Rc`
                    // of CAS) are read at the access width — `.64` forms read a pair.
                    for r in 1..atom_access_regs(&insn.opcode_full) {
                        if (*num as u16) + r < 255 { out.push((false, *num as u16 + r)); }
                    }
                } else if is_store(op) {
                    // Store data operand spans multiple regs for wide stores:
                    // .128 = 4 regs, .64 = 2. Without this, STG.E.128 reading a tensor
                    // accumulator (R0..R3) only registers R0 as a source → the scheduler
                    // misses the dep on the MMA writeback of R1..R3 (stale store).
                    // BUG-101: .256 stores name two data base registers (STG_dARI_R_R),
                    // each a 128-bit source quad (M3.5 doctrine) -> 4 per reg here.
                    let w: u16 = if insn.opcode_full.contains(".256") || insn.opcode_full.contains(".128") { 4 }
                                 else if insn.opcode_full.contains(".64") { 2 } else { 1 };
                    for r in 1..w {
                        if (*num as u16) + r < 256 { out.push((false, *num as u16 + r)); }
                    }
                } else if is_wide_src && op_idx > 1 && Some(op_idx) == wide_addend_idx {
                    // BUG-110: WIDE pair span applies ONLY to the addend
                    // (last non-predicate operand — mirror of the certified
                    // reg_liveness.rs M3.5 doctrine, BUG-108: multiplicands
                    // are 32-bit). Extending it to every register past op 1
                    // fabricated phantom R(n+1) reads (~78 FP on rt98).
                    if *num < 255 { out.push((false, *num as u16 + 1)); }
                }
            }
            Operand::UReg { num, .. } if *num < 63 => {
                out.push((true, *num as u16));
                // UIMAD.WIDE reads its 64-bit uniform addend as a UR pair;
                // the addend is the last non-predicate operand — same
                // BUG-110 doctrine as the register arm above.
                if is_wide_src && op_idx > 1 && Some(op_idx) == wide_addend_idx && *num + 1 < 63 {
                    out.push((true, *num as u16 + 1));
                }
            }
            Operand::Pred { num, .. } if *num < 7 => out.push((false, PRED_KEY + *num as u16)),
            Operand::UPred { num, .. } if *num < 7 => out.push((true, 64 + *num as u16)),
            Operand::Addr { base_reg: Some(r), ur_reg, .. } => {
                out.push((false, *r as u16));
                if let Some(u) = ur_reg { out.push((true, *u as u16)); }
            }
            Operand::Desc { ur_idx, base_reg, .. } => {
                out.push((true, *ur_idx as u16));
                if let Some(r) = base_reg { out.push((false, *r as u16)); }
            }
            Operand::ConstMem { base_reg: Some(r), ur_reg, .. } => {
                out.push((false, *r as u16));
                if let Some(u) = ur_reg { out.push((true, *u as u16)); }
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
                Operand::Pred { num, .. } if *num < 7 => out.push((false, PRED_KEY + *num as u16)),
                Operand::UPred { num, .. } if *num < 7 => out.push((true, 64 + *num as u16)),
                _ => {}
            }
        }
    }
    // Guard predicate is a source
    if let Some(g) = &insn.guard {
        if g.pred < 7 {
            out.push((g.uniform, if g.uniform { 64 + g.pred as u16 } else { PRED_KEY + g.pred as u16 }));
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
pub(crate) fn load_addr_gprs(insn: &Instruction) -> Vec<u8> {
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

/// GPR destinations of an instruction (R0..R254), for WAR-writer detection.
fn dest_gprs(insn: &Instruction) -> Vec<u8> {
    dest_regs(insn).into_iter()
        .filter(|(u, r)| !*u && *r < PRED_KEY)
        .map(|(_, r)| r as u8)
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
                else if r < PRED_KEY { tg[r as usize] = true; }
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
                else if r < PRED_KEY { tg[r as usize] = true; }
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
    DRAIN_WORDS.with(|d| d.borrow_mut().clear());
    // The pass also accepts explicit controls supplied directly through IR,
    // without a source [CC] marker. Do not silently repair those either.
    let generated_controls: Vec<bool> = insns.iter().map(|x| {
        !x.hand_sched && x.ctrl.write_bar == 7 && x.ctrl.wait_mask == 0
            && x.ctrl.stall == 1 && x.ctrl.read_bar == 7
    }).collect();

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
            } else if *reg >= PRED_KEY {
                // Predicate register — stall only, no barrier
                if let Some(pdef) = st.pred_defs.get((*reg - PRED_KEY) as usize).and_then(|d| d.as_ref()) {
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
                } else if *reg < PRED_KEY {
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
        // the stall the instruction's own sources ask for (before the per-class producer stalls)
        let phase1_stall = min_stall;

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
            if !st.stage3 || st.yield_loads {
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
            // CUBIT_SYNC_CLASSES: not there -- the heuristic reads loops off the text (every
            // backward branch a back-edge), so on nvcc's layout, where the out-of-line slow
            // paths return backwards, it holds half the loads of a hot loop at S10; the
            // allocator's scans run on the control-flow graph under the switch and the next
            // iteration's reader waits the load's barrier.
            if (!st.stage3 || st.mem_war_stall)
                && !crate::sync_class::enabled()
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
        // BUG-479: `BAR.SYNC` / `BAR.RED` block *deferred* — the warp keeps issuing for a
        // few cycles after the barrier instruction, and a shared-memory access issued
        // within 5 cycles of it slips past the barrier. Silicon (sm120, sparse-MLA
        // softmax: cross-warp max/sum reduction `STS; BAR.SYNC; LDS x8`): S01..S05 on the
        // BAR -> nondeterministic stale LDS values (wrong output in ~40 % of the tokens),
        // S06 -> bit-exact. ptxas never goes below 6 cycles between a BAR.SYNC and the next
        // shared-memory instruction (`BAR.SYNC ... S06` before an LDS, or S01 followed by a
        // non-memory S05). The floor is applied to every BAR form; the encoder re-injects
        // the scheduler's stall for barrier-class instructions (main.rs, static-ctrl
        // reinject), so this reaches the bytes in the default path as well.
        if op == "BAR" {
            insns[i].ctrl.stall = insns[i].ctrl.stall.max(LATENCY_BAR_SYNC);
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
                    // (CUBIT_SYNC_CLASSES: this pass's barriers are re-derived on the control-flow
                    // graph by `reallocate_barriers`; the drain's retirement stall of its text-order
                    // allocation would stay behind as eight idle cycles on a load that drains nothing.
                    // CUBIT_SCHED2_MEMSTALL=table: the stall is written under its name -- `CUBIT_RECYCLE_DRAIN`,
                    // the knob of the default scheduler's drain below -- and judged again behind the
                    // allocator: `settle_recycle_drains` keeps it only where the final allocation sets a
                    // barrier with producers in flight that are not a measured set)
                    if !crate::sync_class::enabled() {
                        let drain = if st.mem_table { st.recycle_drain } else { 8 };
                        let base = insns[i].ctrl.stall;
                        insns[i].ctrl.stall = insns[i].ctrl.stall.max(drain);
                        if st.mem_table && insns[i].ctrl.stall != base {
                            // judged again on the final allocation: `settle_recycle_drains`
                            let ordinal = insns[..i].iter().filter(|x| same_word(x, &insns[i])).count();
                            DRAIN_WORDS.with(|d| d.borrow_mut().push((insns[i].clone(), ordinal, base, insns[i].ctrl.stall)));
                        }
                    }
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
                let deficit = if st.dep_lat { 0 } else { sched2_raw_deficit(insns, &st, i + 1, issue_clock) };
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

        // CUBIT_SYNC_CLASSES: a synchronisation word's stall is its class's issue floor -- not an
        // ALU latency. Under the stage-3 rules it keeps what the next instruction's fixed-latency
        // sources charged to it (the look-ahead deficit); in the default model what its own
        // sources asked for.
        if crate::sync_class::enabled() {
            if let Some(c) = crate::sync_class::classify(&insns[i]) {
                let floor = crate::sync_class::stall_of(insns, i, &c);
                let carried = if st.stage3 { insns[i].ctrl.stall } else { phase1_stall };
                // (a never-executed pad carries nothing of its opcode's class: the legaliser
                // adds what the instruction behind it needs)
                let s = if crate::sync_class::never_executes(&insns[i]) {
                    floor
                } else if floor == 0 && carried <= 1 {
                    0
                } else {
                    carried.max(floor)
                };
                insns[i].ctrl.stall = s;
                insns[i].ctrl.yield_flag = c.yield_flag && s != 0 && s < 12;
            } else if crate::sync_class::is_unlisted_transfer(&insns[i]) {
                // a register-indirect branch is a branch: S05 with yield (ptxas: 58 of 58 `BRX`)
                insns[i].ctrl.stall = insns[i].ctrl.stall.max(crate::sync_class::TRANSFER_STALL);
                insns[i].ctrl.yield_flag = insns[i].ctrl.stall < 12;
            } else if !st.dep_lat && insns.get(i + 1).is_some_and(|w| crate::sync_class::is_settle_word(w) && w.opcode != "BRA")
                && !is_control_flow(op) && !insn_is_store(&insns[i], table)
            {
                // without the latency legaliser: the instruction in front of a reconvergence point /
                // a dispatch carries what has to land (ptxas: S07 in front of BSYNC / CALL, S04 in
                // front of BRX); with the legaliser the distances hold on every path
                let dests = dest_regs(&insns[i]);
                let what = if is_warp_mma(op) {
                    crate::sync_class::Landing::Mma
                } else if dests.iter().all(|(u, k)| if *u { *k >= 64 } else { *k >= PRED_KEY }) {
                    crate::sync_class::Landing::Predicate
                } else {
                    crate::sync_class::Landing::Register
                };
                if let Some(l) = crate::sync_class::settle_need(&insns[i + 1], what).filter(|_| !dests.is_empty()) {
                    if !insn_needs_write_bar(&insns[i], table, true) && insns[i].ctrl.stall < l.min(15) {
                        insns[i].ctrl.stall = l.min(15);
                        insns[i].ctrl.yield_flag = false; // ptxas: `[-:S07]`
                    }
                }
            } else if crate::sync_class::enters_collective(insns, i) {
                // nothing is in flight when the warp's mask changes (ptxas: S07, no yield)
                insns[i].ctrl.stall = insns[i].ctrl.stall.max(crate::sync_class::COLLECTIVE_ENTRY_STALL);
                insns[i].ctrl.yield_flag = false;
            } else if crate::sync_class::collective_region(insns, i).is_some() && insn_needs_write_bar(&insns[i], table, true) {
                // the region's shuffle: both barriers, waited by ENDCOLLECTIVE right behind it
                insns[i].ctrl.stall = crate::sync_class::COLLECTIVE_BODY_STALL;
                insns[i].ctrl.yield_flag = true;
            }
        }

        st.clock += insns[i].ctrl.stall as usize;
    }

    // CUBIT_SCHED2: dead padding after the final EXIT (the tail self-branch + NOPs)
    // carries S00 / no-yield in ptxas. Zero them so the diff isn't polluted by the
    // scheduler's default S01 on unreachable instructions.
    if st.stage3 {
        if let Some(last_exit) = insns.iter().rposition(|x| x.opcode == "EXIT") {
            // CUBIT_SYNC_CLASSES: only the dead tail (the self-branch and the NOPs behind it). A
            // kernel of nvcc keeps live out-of-line blocks behind its last EXIT -- the suspend
            // loops of its mbarrier waits, the fallbacks of its collective regions, a whole
            // warp group's code: zeroing every stall there left them to the legaliser alone.
            let mut tail = last_exit + 1;
            if crate::sync_class::enabled() {
                let n = insns.len();
                tail = n;
                while tail > last_exit + 1 {
                    let x = &insns[tail - 1];
                    let xa = if x.addr > 0 { x.addr } else { ((tail - 1) * 16) as u32 };
                    let dead = x.opcode == "NOP" || (x.opcode == "BRA" && x.guard.is_none() && branch_target(x) == Some(xa));
                    if !dead { break; }
                    tail -= 1;
                }
            }
            for x in insns.iter_mut().skip(tail) {
                if x.hand_sched { continue; }
                x.ctrl.stall = 0;
                x.ctrl.yield_flag = false;
            }
        }
    }

    // SM120 OPEX legality applies to every generated native instruction. Keep
    // the earlier BUG-170 LOP3-only rule on other architectures. Author-owned
    // controls are validated at encoding, never silently normalized here.
    for (i, x) in insns.iter_mut().enumerate() {
        if x.hand_sched {
            continue;
        }
        if table.is_some_and(|t| t.target_sm() == 120) {
            if generated_controls[i] {
                crate::scheduling::legalize_generated_sm120_control(&mut x.ctrl);
            }
        } else {
            opex1_lop3_legalize(&x.opcode, &mut x.ctrl);
        }
    }
}

/// Apply SM120 OPEX legality after CLI scheduling post-passes. Only controls
/// owned by the generator may be passed here; \[CC\] instructions stay frozen.
/// The encoder rejects reserved author controls instead of calling this helper.
pub fn legalize_generated_sm120_controls(insns: &mut [Instruction]) {
    for insn in insns.iter_mut().filter(|x| !x.hand_sched) {
        crate::scheduling::legalize_generated_sm120_control(&mut insn.ctrl);
    }
}

/// BUG-102: write-barrier batchability class for the RECYCLE audit. TRUE for
/// producers with an asynchronous scoreboard write-back (the `is_long_latency`
/// set minus stores), which ptxas legitimately accumulates on ONE shared write
/// barrier with a single downstream drain (certified rt98 text, silicon-EXACT).
/// FALSE for everything else (fixed-latency ALU, conversions like MUFU, stores),
/// so re-arming an armed barrier from those classes still warns fail-closed.
/// S2UR/B2R (special->register reads) are batchable on the same evidence as
/// S2R (rt98 prologue batches S2UR with the S2R/LDCU run on wb0); they sit
/// outside is_long_latency because the default scheduler reaches them via the
/// learned variable-latency class instead. MUFU/F2I/I2F/FLO/POPC stay loud
/// (each gets its own scoreboard by doctrine; no batching evidence). REDUX
/// stays loud deliberately: no corpus evidence of legal batching and the
/// allocator marks it no-batch on SM120.
fn hazard_recycle_batchable(op: &str) -> bool {
    (is_long_latency(op) || matches!(op, "S2UR" | "B2R")) && !is_store(op) && op != "REDUX"
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
    // BUG-110: a barrier may be armed by a WHOLE BATCH of producers between
    // drains (legal vendor doctrine, BUG-102): the HW scoreboard barrier is a
    // counter, not a last-writer slot, and a wait clears all of its pending
    // producers. Tracking only the last armer (previous `Option<usize>`)
    // silently passed a no-wait read of any non-last batch member (false
    // negative): `armed[b] == Some(pidx)` fired only for the newest armer.
    let mut armed: [Vec<usize>; NUM_BARRIERS] = std::array::from_fn(|_| Vec::new());
    let mut out: Vec<HazardReport> = Vec::new();
    let mut seen: std::collections::HashSet<(u32, bool, u16)> = std::collections::HashSet::new();
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
            if insn.ctrl.wait_mask & (1 << b) != 0 { armed[b].clear(); }
        }
        // DEPBAR is the instruction-level scoreboard drain: it carries NO
        // ctrl wait_mask bit (its barrier operand lives in the payload), so
        // step (1) above misses it and every read after a DEPBAR drained
        // barrier falsely warned "NOT waited" on the certified rt98 publish
        // text (9x KernelB pipelined-loop MOV consumers; kernel is
        // silicon-EXACT). Model: `DEPBAR.<m> SBb, imm` (operand 0 = barrier
        // index) satisfies all current armers of b. The second immediate
        // (LE threshold, 0x9 in rt98) is treated as a full drain: the
        // certified text arms up to 48 producers on wb0 in the prologue
        // batch yet reads them right after DEPBAR with silicon-EXACT
        // results, i.e. HW retires the batch by drain time. Fail-closed
        // by construction: an unrecognised operand shape clears nothing.
        if insn.opcode == "DEPBAR" {
            if let Some(Operand::Imm32(v)) = insn.operands.first() {
                if (*v as usize) < NUM_BARRIERS && *v >= 0 {
                    armed[*v as usize].clear();
                }
            }
        }
        // 2) check sources.
        for (is_u, reg) in src_regs(insn) {
            if reg >= PRED_KEY { continue; } // predicate — no barrier mechanism
            let owner = if is_u { ureg_owner.get(reg as usize).copied().flatten() }
                        else { gpr_owner[reg as usize] };
            if let Some((pidx, maybe_wb, pclock)) = owner {
                let frozen = insn.hand_sched || insns[pidx].hand_sched;
                match maybe_wb {
                    Some(b) => {
                        if armed[b as usize].contains(&pidx) {
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
                if !is_u && (PRED_KEY..PRED_KEY + 7).contains(&reg) { flag_srcs.push((reg - PRED_KEY) as u8); }
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
            if reg >= PRED_KEY {
                // predicate defs for the BUG-062 flag-latency audit: only the
                // silicon-measured producer classes (ISETP*/PLOP3* family of the
                // i134 census) register a floor; any other predicate writer makes
                // the producer unknown (None) so unmeasured classes stay silent.
                if !is_u && reg < PRED_KEY + 7 {
                    let op = insn.opcode.as_str();
                    pred_owner[(reg - PRED_KEY) as usize] =
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
            // producer means no instruction waited b since (no drain).
            //
            // BUG-102 (102-kand): shared-barrier load batching is a LEGAL vendor
            // doctrine, so the naive "armed by a different producer -> warn" rule was
            // all noise on real code: on the certified, silicon-EXACT rt98 publish
            // text (S2R/S2UR/LDCU prologue runs on wb0, ALU-interleaved LDG batches,
            // 55x SHFL.BFLY on wb0) 160/160 findings were false positives. ptxas
            // accumulates many async producers on ONE barrier and drains the batch
            // once (e.g. the `[B0-----] NOP` stall point); RAW under-waiting of batch
            // members is audited separately above. Suppress the warn when BOTH the
            // previous armer and the new setter are async write-back producer classes
            // (hazard_recycle_batchable). The warn stays fail-closed for setters with
            // no async write-back (e.g. a stray W-tag on ALU / MUFU), where re-arming
            // an armed barrier still indicates an authoring mistake, not a batch.
            // The RECYCLE message names the most recent armer (`last`) for
            // continuity with the BUG-102 report; with batch tracking the set
            // may hold earlier armers too, but the newest one is the member
            // the new setter races with first.
            if let Some(&prev) = armed[b as usize].last() {
                if prev != i {
                    let batch = hazard_recycle_batchable(insns[prev].opcode.as_str())
                        && hazard_recycle_batchable(insn.opcode.as_str());
                    if !batch {
                        let frozen = insn.hand_sched || insns[prev].hand_sched;
                        out.push(HazardReport { frozen, msg: format!("RECYCLE @0x{:04x} {:34} sets wb{} still armed by 0x{:04x} {} (no drain -> prior consumers orphaned)",
                            insn.addr, insn.raw_text.split('/').next().unwrap_or(&insn.opcode).trim(),
                            b, insns[prev].addr, insns[prev].opcode)});
                    }
                }
            }
            armed[b as usize].push(i);
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
        } else if reg >= PRED_KEY {
            // CUBIT_SYNC_CLASSES: a phase check's predicate is synchronised by its write barrier,
            // not by the fixed predicate latency (no stall is charged for it)
            if crate::sync_class::enabled() && crate::sync_class::result_pred(insn).is_some() {
                continue;
            }
            let pidx = (reg - PRED_KEY) as usize;
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
/// (The doc block above describes `raw_consumers` below; `FlowInfo` sits between them.)
///
/// BUG-478: forward control flow of the kernel, consulted by the consumer / overwriter
/// scans so they follow EXECUTION paths instead of textual order.
///
/// * `fwd[j] = Some(target)` for a branch at `j` whose resolved target lies AFTER `j`;
///   `cond[j]` = its condition: `None` = unconditional (`BRA join` closing an if/else arm:
///   the scan CONTINUES AT THE TARGET — the code textually after it is the other arm, dead
///   on this path), `Some(Some((p, neg)))` = vector-predicate guard `@P`/`@!P`,
///   `Some(None)` = other condition (uniform guard / predicate operand: always a fork).
/// * `term[j]` — unguarded `EXIT` / `RET`: the path ends here.
/// * Predicate knowledge along a path (`Known`): after `@!P5 BRA skip` falls through, P5
///   is known TRUE until something redefines it, so a later `@!P5 BRA skip2` on the same
///   path is NOT a fork (the same uniform predicate guards both blocks: the infeasible
///   "skip the first block, execute the second" path would otherwise manufacture
///   loop-carried consumers whose segments span the whole loop and exhaust the six
///   scoreboards — every load then overflows onto one barrier with drains).
///
/// Backward branches (loop back-edges) keep the existing treatment: the scan falls
/// through (= the loop-exit path, the guard known FALSE there) and the loop-carried
/// paths are covered by the `edges` / wrap logic of the callers.
struct FlowInfo {
    fwd: Vec<Option<usize>>,
    cond: Vec<Option<Option<(u8, bool)>>>,
    /// Backward guarded branch at `j`: `(p, neg)` of its vector guard (fall-through knowledge).
    back_guard: Vec<Option<(u8, bool)>>,
    term: Vec<bool>,
}

/// Known value of P0..P6 along a scan path: -1 unknown, 0 false, 1 true.
type Known = [i8; 7];

/// Debug bisection of the BUG-478 refinements (CUBIT_BUG478_LEGACY bitmask): 1 = no
/// predicate knowledge, 2 = no RAW-waiter stop, 4 = loop-carried overwriter always,
/// 8 = loop-carried consumer scan always.
fn bug478_legacy(bit: u8) -> bool {
    std::env::var("CUBIT_BUG478_LEGACY").ok().and_then(|v| v.parse::<u8>().ok()).is_some_and(|m| m & bit != 0)
}
const KNOWN_NONE: Known = [-1; 7];

/// `a` knows no more than `b` (every fact of `a` holds in `b`).
fn known_le(a: &Known, b: &Known) -> bool {
    (0..7).all(|p| a[p] == -1 || a[p] == b[p])
}

impl FlowInfo {
    fn build(insns: &[Instruction]) -> FlowInfo {
        use std::collections::HashMap;
        let n = insns.len();
        let mut addr2idx: HashMap<u32, usize> = HashMap::new();
        for (i, ins) in insns.iter().enumerate() {
            addr2idx.insert(ins.addr, i);
        }
        let mut fwd = vec![None; n];
        let mut cond = vec![None; n];
        let mut back_guard = vec![None; n];
        let mut term = vec![false; n];
        for (j, ins) in insns.iter().enumerate() {
            let op = ins.opcode.as_str();
            let vguard: Option<(u8, bool)> = ins
                .guard
                .as_ref()
                .filter(|g| g.pred < 7 && !g.uniform)
                .map(|g| (g.pred, g.negated));
            let guarded = ins.guard.as_ref().is_some_and(|g| g.pred < 7);
            // `BRA.U UP0, lbl` / `BRA !P0, lbl`: a predicate OPERAND makes it conditional.
            let pred_operand = ins
                .operands
                .iter()
                .any(|o| matches!(o, Operand::Pred { num, .. } | Operand::UPred { num, .. } if *num < 7));
            let unconditional = !guarded && !pred_operand;
            if matches!(op, "EXIT" | "RET") {
                // `@P0 EXIT` (the early-out of a CTA-index guard) is NOT a terminator:
                // the path continues when the predicate is false.
                term[j] = unconditional;
                continue;
            }
            if !matches!(op, "BRA" | "JMP") {
                continue;
            }
            let Some(t) = branch_target(ins) else { continue };
            let Some(&ti) = addr2idx.get(&t) else { continue };
            if ti <= j {
                if !pred_operand { back_guard[j] = vguard; }
                continue;
            }
            fwd[j] = Some(ti);
            cond[j] = if unconditional { None } else if pred_operand { Some(None) } else { Some(vguard) };
        }
        FlowInfo { fwd, cond, back_guard, term }
    }

    /// Forget what is known about every predicate written by instruction `j`.
    fn kill(writes_j: &[u16], known: &mut Known) {
        for w in writes_j {
            if (PRED_KEY..PRED_KEY + 7).contains(w) { known[(*w - PRED_KEY) as usize] = -1; }
        }
    }

    /// Successors of `j` in scan order with the predicate knowledge of each path.
    /// Empty = path ends. Two entries = fork (taken first).
    fn next(&self, j: usize, n: usize, known: &Known) -> Vec<(usize, Known)> {
        if self.term[j] {
            return Vec::new();
        }
        let fall = |k: Known| -> Vec<(usize, Known)> { if j + 1 < n { vec![(j + 1, k)] } else { Vec::new() } };
        match self.fwd[j] {
            Some(t) => match self.cond[j] {
                None => vec![(t, *known)],
                Some(Some((p, neg))) => {
                    let taken_val: i8 = if neg { 0 } else { 1 };
                    if bug478_legacy(1) {
                        let mut v = vec![(t, *known)];
                        v.extend(fall(*known));
                        return v;
                    }
                    if known[p as usize] != -1 {
                        if known[p as usize] == taken_val { vec![(t, *known)] } else { fall(*known) }
                    } else {
                        let mut kt = *known; kt[p as usize] = taken_val;
                        let mut kf = *known; kf[p as usize] = 1 - taken_val;
                        let mut v = vec![(t, kt)];
                        v.extend(fall(kf));
                        v
                    }
                }
                Some(None) => {
                    let mut v = vec![(t, *known)];
                    v.extend(fall(*known));
                    v
                }
            },
            None => {
                // backward guarded branch: on the fall-through its guard is known false
                let mut k = *known;
                if let Some((p, neg)) = self.back_guard[j] {
                    if k[p as usize] == -1 { k[p as usize] = if neg { 1 } else { 0 }; }
                }
                fall(k)
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn raw_consumers(
    reads: &[Vec<u16>],
    writes: &[Vec<u16>],
    guarded: &[bool],
    flow: &FlowInfo,
    last_setter: usize,
    dsts: &[u16],
    ltop: usize,
    lback: usize,
    edges: &[(usize, usize)],
    n: usize,
) -> (Vec<usize>, bool) {
    // Only the FIRST consumer on each control path needs to wait the write-barrier — once
    // it waits, the load has completed and the destination registers are ready for every
    // later reader. Collect consumers up to and INCLUDING the first UNGUARDED one per path
    // (a guarded first reader may be skipped, so a following reader still needs the wait).
    //
    // BUG-478: "path" is an EXECUTION path — the scan follows forward control flow
    // (`FlowInfo`): an unconditional forward branch continues at its target, a guarded
    // forward branch forks unless the predicate's value is already known on the path.
    // `seen[j]` = (live set, knowledge) pairs already scanned from `j`; a path arriving
    // with no new live register and at least the knowledge of an earlier walk is
    // redundant (that walk explored a superset of its paths and found the same first
    // consumers), which bounds the walk on diamonds and joins.
    let mut waiters: Vec<usize> = Vec::new();
    let mut seen: Vec<Vec<(Vec<u16>, Known)>> = vec![Vec::new(); n];
    let settles = guarded_reader_settles();
    // Back-edges of the loops enclosing the producer: a path reaching one of them with
    // live destinations still unconsumed makes the NEXT iteration's readers consumers.
    let is_backedge = |j: usize| -> bool {
        edges.iter().any(|&(t, b)| t <= last_setter && last_setter <= b && j == b)
    };
    // Returns (exits, open_back): `exits` = the states `(index, live, known)` of every path
    // that left [lo, hi) with unconsumed live destinations — at `hi` itself (the loop-exit
    // fall-through) or at the target of a forward jump out of the range (`@P BRA out` from
    // inside the loop; T-5 refinement: before, every such path was resumed at `lback + 1`,
    // so a consumer at the jump target never waited when an earlier instruction of the
    // fall-through exit code read the register); `open_back` = some path reached an
    // enclosing back-edge with unconsumed live destinations.
    type Exit = (usize, Vec<u16>, Known);
    let scan = |waiters: &mut Vec<usize>, seen: &mut Vec<Vec<(Vec<u16>, Known)>>, lo: usize, hi: usize, dsts: &[u16], known_lo: Known| -> (Vec<Exit>, bool) {
        let mut exits: Vec<Exit> = Vec::new();
        if lo >= hi || dsts.is_empty() { return (exits, false); }
        let mut work: Vec<(usize, Vec<u16>, Known)> = vec![(lo, dsts.to_vec(), known_lo)];
        let mut open_back = false;
        while let Some((start, live0, known0)) = work.pop() {
            let mut live = live0;
            let mut known = known0;
            let mut j = start;
            let mut done = false;
            while j < hi && !live.is_empty() {
                if seen[j].iter().any(|(l, k)| live.iter().all(|d| l.contains(d)) && known_le(k, &known)) {
                    done = true;
                    break;
                }
                seen[j].push((live.clone(), known));
                // BUG-485 (NEEDS_OWNER 34, 2026-11-06): an instruction that OVERWRITES a still-live
                // destination without reading it is a waiter too (WAW). The producer's writeback is
                // asynchronous: without the wait it can land AFTER the overwriter's value and the
                // register ends up holding the dead load's result (ptxas waits the barrier on such
                // overwriters). Before, the register merely dropped out of the live set and a dead
                // load with no reader before an overwriter of another class got no barrier at all
                // (same-class loads of one address stream are issue-ordered and batched instead).
                let reads_live = reads[j].iter().any(|r| live.contains(r));
                let overwrites_live = writes[j].iter().any(|w| live.contains(w));
                if reads_live || overwrites_live {
                    if !waiters.contains(&j) { waiters.push(j); }
                    // NEEDS 37 (`CUBIT_GUARDED_READER_SETTLES=1`): the first reader settles the
                    // barrier guarded or not (its wait is honoured either way -- the ptxas evidence
                    // below); today's rule needs an unguarded one.
                    if !guarded[j] || settles { done = true; break; }
                }
                // (ptxas evidence, 2026-11-06, 50 / 50 sites in the sm_120 census: a wait carried by a
                // PREDICATED instruction is honoured whether or not the guard is true — the next
                // unguarded reader of the same load behind `@P0 SHF … R10` carries no wait of its
                // own — so a guarded overwriter that waited here settles the register for the readers
                // behind it, and the live set drops it like before.)
                live.retain(|d| !writes[j].contains(d));
                if is_backedge(j) && !live.is_empty() { open_back = true; }
                FlowInfo::kill(&writes[j], &mut known);
                let succ = flow.next(j, n, &known);
                match succ.len() {
                    0 => { done = true; break; }       // EXIT / RET / end of text
                    1 => { j = succ[0].0; known = succ[0].1; }
                    _ => {
                        // fork: taken arm on the worklist, fall-through continues here
                        work.push((succ[0].0, live.clone(), succ[0].1));
                        j = succ[1].0;
                        known = succ[1].1;
                    }
                }
            }
            if !done && !live.is_empty() && j >= hi { exits.push((j, live, known)); }
        }
        (exits, open_back)
    };
    let fwd_end = if lback != usize::MAX { (lback + 1).min(n) } else { n };
    let (exits, mut open_back) = scan(&mut waiters, &mut seen, last_setter + 1, fwd_end, dsts, KNOWN_NONE);
    if lback != usize::MAX {
        // the loop-exit paths: each resumes where it left the loop (the fall-through at
        // `lback + 1`, or the target of a forward jump out of the loop) with its own live
        // set and predicate knowledge
        for (j, live, known) in exits {
            let (_, ob) = scan(&mut waiters, &mut seen, j, n, &live, known);
            open_back |= ob;
        }
    }
    let done = !open_back;
    let mut wrap = false;
    // BUG-478: when EVERY forward path found an unguarded consumer inside the iteration
    // (`done`), the barrier is waited before the back-edge and the next iteration's
    // readers are covered — no loop-carried waiter (which would stretch the use over
    // the whole loop and starve the scoreboard colouring).
    if ltop != usize::MAX && last_setter <= lback && (!done || bug478_legacy(8)) {
        // BUG-342: consumers reachable via ANY enclosing back-edge, not only the
        // innermost loop. A producer inside a nested loop whose consumer sits in
        // an outer loop head (textually above, below the outer top) is a genuine
        // loop-carried RAW; scanning only [innermost_top, setter) misses it, so
        // the producer was emitted with NO write barrier (wbar=7) while its
        // consumer waited a barrier armed on a different path -> stale reads on
        // silicon (sm120 i290). Scan the head region of every enclosing loop,
        // innermost first, each with a fresh live set (per-path doctrine).
        let mut enc: Vec<(usize, usize)> = edges
            .iter()
            .copied()
            .filter(|&(t, b)| t <= last_setter && last_setter <= b)
            .collect();
        enc.sort_by_key(|&(t, b)| b - t);
        let mut hi = last_setter;
        for (t, _b) in enc {
            let before = waiters.len();
            scan(&mut waiters, &mut seen, t, hi, dsts, KNOWN_NONE);
            if waiters.len() > before {
                wrap = true;
            }
            hi = t;
        }
    }
    (waiters, wrap)
}

/// Instructions that overwrite a late-latched operand GPR `opk` of a memory op at
/// `i` (WAR hazards) — there can be TWO distinct first-overwriters that must each
/// wait the read-barrier: the linear fall-through one (covers the last loop
/// iteration / straight-line code) and the loop-carried one across the back-edge
/// (covers every non-last iteration). Returns each as (overwriter, wrap).
#[allow(clippy::too_many_arguments)]
fn war_overwriter(
    writes: &[Vec<u16>],
    flow: &FlowInfo,
    i: usize,
    opk: &[u16],
    stop_at: &[usize],
    early: Option<(usize, &[bool])>,
    ltop: usize,
    lback: usize,
    edges: &[(usize, usize)],
    n: usize,
) -> Vec<(usize, bool)> {
    // `early = Some((dist, can_wait))` (CUBIT_SB_SHARE policy): a path that has advanced
    // `dist` instructions from the memory op without meeting an overwriter gets the read
    // barrier waited RIGHT THERE (first waitable instruction) instead of at the far
    // overwriter. A wait is always correct wherever it sits; by then the latch is long
    // released, so it costs nothing — and the use no longer reserves a scoreboard across
    // hundreds of instructions (a gather's address pair rewritten only by the softmax, a
    // reduction store's data rewritten only in the epilogue: such uses took every colour
    // of the HMMA chain between them).
    // `stop_at`: instructions after which the late operand is certainly released on any
    // path through them — for a LOAD, its unguarded RAW waiters: the address is read when
    // the load issues to the memory pipe, strictly before its data (write barrier) returns,
    // so an overwriter beyond such a waiter needs no read-barrier wait (BUG-478 colouring
    // relief: without it the WAR of e.g. a softmax mask `LDS R2, [R0]` stayed pending until
    // the loop's next iteration and reserved a scoreboard over the whole loop body).
    let mut out = Vec::new();
    // Fall-through: first overwriter on EVERY forward execution path (BUG-478: follow
    // forward control flow — an unconditional `BRA join` continues at the join instead
    // of walking into the other, dead arm; a guarded forward branch forks). Within the
    // loop or after it.
    // `need_carried`: some path reaches the loop back-edge (index > lback, or the end of
    // the walk inside the loop) WITHOUT an overwriter — only then can the next iteration's
    // first overwriter be the first to touch the operand. When every path overwrites (and
    // therefore waits the read barrier) inside the iteration, the loop-carried waiter is
    // redundant: it would stretch the use over the whole loop body, and 64 such uses (one
    // per HMMA of a QK chain) exhaust the six scoreboards -> every load overflows onto one
    // barrier with drains (observed: all QK fragment loads on B0, each HMMA waiting for the
    // loads of the NEXT k-step, software pipelining defeated).
    // A path that LEAVES the loop (forward jump past the back-edge, fall-through of the
    // back-edge branch) never re-enters: only a path that reaches an enclosing loop's
    // back-edge instruction itself without an overwriter needs the next iteration's one.
    let in_loop = ltop != usize::MAX && i <= lback;
    let is_backedge_of_i = |j: usize| -> bool {
        edges.iter().any(|&(t, b)| t <= i && i <= b && j == b)
    };
    let mut need_carried = false;
    let mut visited: Vec<Vec<Known>> = vec![Vec::new(); n];
    let mut work: Vec<(usize, Known, usize)> = flow.next(i, n, &KNOWN_NONE)
        .into_iter().map(|(j, k)| (j, k, 1usize)).collect();
    while let Some((start, known0, dist0)) = work.pop() {
        let mut j = start;
        let mut known = known0;
        let mut dist = dist0;
        loop {
            if j >= n { break; }
            if visited[j].iter().any(|k| known_le(k, &known)) { break; }
            visited[j].push(known);
            if writes[j].iter().any(|w| opk.contains(w)) {
                if !out.contains(&(j, false)) { out.push((j, false)); }
                break;
            }
            if !bug478_legacy(2) && stop_at.contains(&j) { break; }
            if let Some((d, can_wait)) = early {
                if dist >= d && can_wait[j] {
                    if !out.contains(&(j, false)) { out.push((j, false)); }
                    break;
                }
            }
            if in_loop && is_backedge_of_i(j) { need_carried = true; }
            FlowInfo::kill(&writes[j], &mut known);
            let succ = flow.next(j, n, &known);
            dist += 1;
            match succ.len() {
                0 => break,
                1 => { j = succ[0].0; known = succ[0].1; }
                _ => { work.push((succ[0].0, succ[0].1, dist)); j = succ[1].0; known = succ[1].1; }
            }
        }
    }
    // Loop-carried: first overwriter at/after the OUTERMOST enclosing loop top in
    // the next iteration (BUG-342): an overwriter in an outer loop head is earlier
    // in re-entry order than any inner one; scanning only [innermost_top, i)
    // missed it and left the late-latched operand unprotected across that edge.
    if in_loop && (need_carried || bug478_legacy(4)) {
        let outer_top = edges
            .iter()
            .filter(|&&(t, b)| t <= i && i <= b)
            .map(|&(t, _)| t)
            .min()
            .unwrap_or(ltop);
        let mut k = outer_top;
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
fn build_segs(
    first: usize,
    waiters: &[usize],
    ltop: usize,
    lback: usize,
    edges: &[(usize, usize)],
) -> Vec<(usize, usize)> {
    let mut fwd_hi = first;
    let mut wraps: Vec<usize> = Vec::new();
    for &w in waiters {
        if w >= first {
            fwd_hi = fwd_hi.max(w);
        } else {
            wraps.push(w);
        }
    }
    if wraps.is_empty() {
        return vec![(first, fwd_hi)];
    }
    // BUG-342: pair each wrap waiter with the TIGHTEST back-edge that encloses
    // both the producer and the waiter. The setter segment must span to that
    // edge (seg_hi) and the head segment starts at that edge's loop top;
    // waiters in different enclosing loops get one head segment per loop top.
    // Identical to the legacy two-segment shape whenever every wrap waiter
    // lives in the innermost loop (all previously-correct uses unchanged).
    let mut seg_hi = fwd_hi;
    let mut heads: Vec<(usize, usize)> = Vec::new(); // (loop_top, max waiter)
    for &w in &wraps {
        let pick = edges
            .iter()
            .filter(|&&(t, b)| t <= w && w <= b && t <= first && first <= b)
            .min_by_key(|&&(t, b)| b - t)
            .copied();
        let (top, lb) = match pick {
            Some(e) => e,
            None => {
                let lb = if lback != usize::MAX { lback } else { fwd_hi };
                let top = if ltop != usize::MAX { ltop } else { first };
                (top, lb)
            }
        };
        seg_hi = seg_hi.max(lb);
        match heads.iter_mut().find(|(ht, _)| *ht == top) {
            Some(h) => h.1 = h.1.max(w),
            None => heads.push((top, w)),
        }
    }
    let mut out = vec![(first, seg_hi)];
    for (t, hw) in heads {
        out.push((t, hw));
    }
    out
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

/// Resolved backward branches (loop back-edges), shared by the barrier
/// allocator (BUG-342 wrap liveness) and the scoreboard verifier (BUG-347
/// loop-aware wrap pass).
///
/// Returns (`edges`, `ltop`, `lback`): `edges` = (target_idx, branch_idx) for
/// every backward control-flow edge whose target is STATICALLY resolvable
/// (register-indirect / addr-missing targets are excluded -- the verifier
/// flags those loudly, BUG-347). `ltop[i]`/`lback[i]` = innermost enclosing
/// resolved loop for instruction i (usize::MAX when outside any).
fn resolved_back_edges(insns: &[Instruction]) -> (Vec<(usize, usize)>, Vec<usize>, Vec<usize>) {
    use std::collections::HashMap;
    let n = insns.len();
    let mut addr2idx: HashMap<u32, usize> = HashMap::new();
    for (i, ins) in insns.iter().enumerate() {
        addr2idx.insert(ins.addr, i);
    }
    let mut ltop = vec![usize::MAX; n];
    let mut lback = vec![usize::MAX; n];
    let mut edges: Vec<(usize, usize)> = Vec::new();
    for (j, ins) in insns.iter().enumerate() {
        if !is_control_flow(ins.opcode.as_str()) {
            continue;
        }
        let Some(t) = branch_target(ins) else {
            continue;
        };
        let Some(&ti) = addr2idx.get(&t) else {
            continue;
        };
        if ti > j {
            continue;
        }
        edges.push((ti, j));
        for k in ti..=j {
            let cur = if ltop[k] == usize::MAX {
                usize::MAX
            } else {
                lback[k] - ltop[k]
            };
            if j - ti < cur {
                ltop[k] = ti;
                lback[k] = j;
            }
        }
    }
    (edges, ltop, lback)
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

    let rk = |u: bool, r: u16| -> u16 { ((u as u16) << 9) | r };

    // Clear barrier fields on non-frozen insns (keep stalls/yields from `schedule`).
    for ins in insns.iter_mut() {
        if !ins.hand_sched {
            ins.ctrl.write_bar = 7;
            ins.ctrl.read_bar = 7;
            ins.ctrl.wait_mask = 0;
        }
    }

    // addr -> index, and innermost loop [top, back] per instruction.
    // `edges` = every resolved backward branch (target_idx, branch_idx): the
    // loop-NEST view for BUG-342 wrap-liveness (consumers / WAR overwriters can
    // sit in ANY enclosing loop, not only the innermost one).
    let (edges, ltop, lback) = resolved_back_edges(insns);
    // BUG-478: forward control flow for path-following consumer / overwriter scans.
    let flow = FlowInfo::build(insns);

    #[allow(unused_mut)]
    let mut writes: Vec<Vec<u16>> = insns.iter()
        .map(|x| dest_regs(x).into_iter().map(|(u, r)| rk(u, r)).collect()).collect();
    #[allow(unused_mut)]
    let mut reads: Vec<Vec<u16>> = insns.iter()
        .map(|x| src_regs(x).into_iter().map(|(u, r)| rk(u, r)).collect()).collect();
    // CUBIT_SYNC_CLASSES: the ordering tokens of the synchronisation words (the async-proxy
    // fence, the mbarrier init) are pseudo-registers here -- the word that sets one gets a write
    // barrier, the next word of the family waits it; and the acquire's `CCTL.IVALL` reads what
    // the `.STRONG` load in front of it writes (the invalidate waits the load's barrier).
    let sync_on = crate::sync_class::enabled();
    if sync_on {
        for i in 0..n {
            if let Some(crate::sync_class::WriteBar::Token(t)) = crate::sync_class::classify(&insns[i]).map(|c| c.write_bar) {
                writes[i].push(t);
            }
            for t in crate::sync_class::token_reads(&insns[i]) {
                if !reads[i].contains(&t) { reads[i].push(t); }
            }
            if let Some(k) = crate::sync_class::acquire_load(insns, i) {
                for w in writes[k].clone() {
                    if !reads[i].contains(&w) { reads[i].push(w); }
                }
            }
            // the end of a collective region waits what the region produced
            if let Some((_, e)) = crate::sync_class::collective_region(insns, i) {
                for w in writes[i].clone() {
                    if !reads[e].contains(&w) { reads[e].push(w); }
                }
            }
        }
    }
    // A kernel that commits a copy group (`LDGDEPBAR`, `UTMACMDFLUSH`) keeps scoreboard 0 for it.
    let sb0_reserved = sync_on && insns.iter().any(crate::sync_class::commits_group);
    // CUBIT_SYNC_CLASSES: the scans run on the control-flow graph (`cfg_flow`) instead of the
    // text: nvcc's layout keeps slow paths behind the last EXIT that return with a backward
    // `BRA` (not loops), `BRA.DIV` falls through, `BRX` dispatches through a table.
    let cfg = if sync_on { Some(crate::cfg_flow::Cfg::build(insns)) } else { None };
    let mut can_wait: Vec<bool> = insns.iter().map(|x| insn_can_set_wait_mask(x, table)).collect();
    let can_wb: Vec<bool> = insns.iter().map(|x| insn_can_set_write_bar(x, table)).collect();
    // A consumer is "guarded" if it executes under a non-PT predicate (may be skipped) —
    // then a following reader still needs the producer's write-barrier wait.
    let guarded: Vec<bool> = insns.iter()
        .map(|x| x.guard.as_ref().is_some_and(|g| g.pred < 7)).collect();
    // (the register key of each instruction's guard predicate, for CUBIT_SYNC_CLASSES)
    let guard_key: Vec<Option<u16>> = insns.iter()
        .map(|x| x.guard.as_ref().filter(|g| g.pred < 7)
            .map(|g| rk(g.uniform, if g.uniform { 64 + g.pred as u16 } else { PRED_KEY + g.pred as u16 })))
        .collect();

    let mut uses: Vec<BarUse> = Vec::new();
    // Fixed barrier colour for uses pushed by the PINNED pass below (None for
    // normal allocator-coloured uses).
    let mut pin_of: Vec<Option<u8>> = Vec::new();
    // BUG-478: per load, its UNGUARDED RAW waiters — past them the load's address latch
    // is certainly released (see `war_overwriter::stop_at`).
    let mut raw_stop: Vec<Vec<usize>> = vec![Vec::new(); n];

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
        // (a synchronisation word's result / token is never batched: its own scoreboard)
        let is_sync_word = |k: usize| sync_on && crate::sync_class::classify(&insns[k]).is_some();
        let batchable = !is_variable_latency_sched2(op) && op != "REDUX" && op != "SHFL" && !is_sync_word(i);
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
                // (an instruction that WRITES one of them again does not end the batch: under
                // CUBIT_SYNC_CLASSES it is made to wait by the pass at the end of this function,
                // BUG-489; on the default path `CUBIT_VERIFY` names the pair)
                let prodj = insn_needs_write_bar(&insns[j], table, true)
                    && !is_warp_mma(opj) && can_wb[j] && !insns[j].hand_sched;
                if prodj {
                    let batchablej = !is_variable_latency_sched2(opj) && opj != "REDUX" && opj != "SHFL" && !is_sync_word(j);
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
                            let pair = [rk(false, b as u16), rk(false, b as u16 + 1)];
                            if writes[j].iter().any(|w| pair.contains(w)) { break; }
                        }
                    }
                }
                j += 1;
            }
        }
        let last = *group.last().unwrap();
        let mut gd: Vec<u16> = group.iter().flat_map(|&g| writes[g].clone()).collect();
        gd.sort_unstable();
        gd.dedup();
        // CUBIT_SYNC_CLASSES: a reader whose GUARD is the pending result cannot be skipped
        // before the result is there (`SYNCS...TRYWAIT P5 [W0]` / `@!P5 BRA [B0]`): it settles
        // the barrier like an unguarded reader (ptxas: no second waiter behind it).
        let guarded_here: Vec<bool> = if cfg.is_some() {
            (0..n).map(|j| guarded[j] && !guard_key[j].is_some_and(|k| gd.contains(&k))).collect()
        } else {
            Vec::new()
        };
        let (waiters, live_on) = match &cfg {
            Some(c) => {
                let (w, on) = c.first_consumers(&reads, &writes, &guarded_here, &group, &gd, guarded_reader_settles());
                (w, Some(on))
            }
            None => {
                let (w, _wrap) = raw_consumers(
                    &reads,
                    &writes,
                    &guarded,
                    &flow,
                    last,
                    &gd,
                    ltop[last],
                    lback[last],
                    &edges,
                    n,
                );
                (w, None)
            }
        };
        if !waiters.is_empty() {
            // the waiters after which the load has certainly issued: the unguarded ones -- every
            // waiter under the NEEDS 37 switch (a guarded waiter's wait is honoured too)
            let settles = guarded_reader_settles();
            let stops: Vec<usize> = waiters.iter().copied()
                .filter(|&w| settles || !(if cfg.is_some() { guarded_here[w] } else { guarded[w] }))
                .collect();
            for &g in &group { raw_stop[g] = stops.clone(); }
            let segs = match &live_on {
                Some(on) => crate::cfg_flow::runs(on),
                None => build_segs(group[0], &waiters, ltop[last], lback[last], &edges),
            };
            uses.push(BarUse {
                setters: group.clone(),
                waiters,
                is_rb: false,
                segs,
            });
            pin_of.push(None);
        }
        i = last + 1;
    }

    // ---- WAR: read-barriers on memory ops whose late operands are overwritten ----
    // CUBIT_SB_SHARE policy: early release of far WAR uses (see war_overwriter::early).
    let sb_share_policy = std::env::var("CUBIT_SB_SHARE").ok().as_deref() == Some("1");
    let rb_early_dist: usize = std::env::var("CUBIT_RB_EARLY").ok().and_then(|s| s.parse().ok()).unwrap_or(64);
    let rb_early: Option<(usize, &[bool])> = if sb_share_policy { Some((rb_early_dist, &can_wait)) } else { None };
    // Late-latched operand set of memory op `idx` (address regs of loads, data+address
    // of stores, fragment regs of cooperative MMA). Shared by the auto WAR pass and the
    // PINNED pass below (BUG-117: a hand_sched memory op whose tag carries `R{b}`).
    let late_operands = |idx: usize| -> Vec<u8> {
        let op = insns[idx].opcode.as_str();
        if insn_is_store(&insns[idx], table) {
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
            let mut v = if a.iter().any(|x| dests.contains(x)) { Vec::new() } else { a.clone() };
            // BUG-482: an atomic / reduction latches its DATA late like a store (ptxas: a
            // read barrier on every `ATOMS.MAX.S32 RZ, [..], R58`); protect it too.
            for r in atom_data_gprs(&insns[idx]) { if !v.contains(&r) { v.push(r); } }
            // CUBIT_SYNC_CLASSES: the address of a self-referencing load is read late as well
            // (ptxas: `[R0:W5] LDG.E.CONSTANT R4, desc[UR8][R4.64]` -- the pair R4:R5 is the
            // address, an overwriter of R5 waits).
            if sync_on && v.is_empty() {
                for r in a { if !dests.contains(&r) && !v.contains(&r) { v.push(r); } }
            }
            // ... and a producer of this class without an address (`SHFL`) reads its register
            // operands late: see the arm below.
            if sync_on && v.is_empty() && load_addr_gprs(&insns[idx]).is_empty() {
                for (u, r) in src_regs(&insns[idx]) {
                    if !u && r < 255 && !dests.contains(&(r as u8)) && !v.contains(&(r as u8)) { v.push(r as u8); }
                }
            }
            v
        } else if sync_on && insn_needs_write_bar(&insns[idx], table, true) && crate::sync_class::classify(&insns[idx]).is_none() {
            // CUBIT_SYNC_CLASSES: every scoreboarded producer reads its register operands in its
            // own pipe, after issue -- `SHFL` (62 of the 64 in fc1 carry a read barrier under
            // ptxas: `[R2:W3] SHFL.IDX PT, R8, R4, RZ, 0x1f` ... `[B--2---] MOV R4, R9`), `MUFU`,
            // `F2I` / `I2F`, `POPC` / `FLO`. The barrier is set only where an overwriter stands
            // in front of the result's first waiter.
            let dests = dest_gprs(&insns[idx]);
            let mut v: Vec<u8> = Vec::new();
            for (u, r) in src_regs(&insns[idx]) {
                if !u && r < 255 && !dests.contains(&(r as u8)) && !v.contains(&(r as u8)) { v.push(r as u8); }
            }
            v
        } else { Vec::new() }
    };
    for idx in 0..n {
        if insns[idx].hand_sched { continue; }
        let late: Vec<u8> = late_operands(idx);
        if late.is_empty() { continue; }
        if !insn_can_set_write_bar(&insns[idx], table) { continue; } // rb shares the same field encoding
        let opk: Vec<u16> = late.iter().map(|&r| rk(false, r as u16)).collect();
        // Protect BOTH the within-iteration (fall-through) and the loop-carried
        // (next-iteration) overwriter of every late-latched operand (load address or store
        // data). Both are real WARs at high occupancy and are load-bearing for correctness
        // (dropping the loop-carried load-address rb corrupts the gather: 337/340 wrong).
        let mut waiters: Vec<usize> = Vec::new();
        let region = if sync_on && insn_needs_write_bar(&insns[idx], table, true) { crate::sync_class::collective_region(insns, idx) } else { None };
        let segs = match &cfg {
            Some(_) if region.is_some() => {
                // CUBIT_SYNC_CLASSES: inside a collective region the read barrier is set
                // whatever follows, and the region's end waits it
                let e = region.unwrap().1;
                waiters = vec![e];
                vec![(idx, e)]
            }
            Some(c) => {
                let (w, on) = c.first_overwriters(&writes, idx, &opk, &raw_stop[idx], rb_early);
                waiters = w;
                crate::cfg_flow::runs(&on)
            }
            None => {
                for (ow, _w) in war_overwriter(&writes, &flow, idx, &opk, &raw_stop[idx], rb_early, ltop[idx], lback[idx], &edges, n) {
                    if !waiters.contains(&ow) {
                        waiters.push(ow);
                    }
                }
                Vec::new()
            }
        };
        if waiters.is_empty() { continue; }
        let segs = if cfg.is_some() { segs } else { build_segs(idx, &waiters, ltop[idx], lback[idx], &edges) };
        uses.push(BarUse {
            setters: vec![idx],
            waiters,
            is_rb: true,
            segs,
        });
        pin_of.push(None);
    }

    // ---- CUBIT_SYNC_CLASSES: read barriers on the late operands of the synchronisation words ----
    // An mbarrier word and a bulk copy read their operands (the barrier's address, the parity /
    // transaction count, the copy's two addresses and size -- GPRs or uniform registers) after
    // issue, like a store; ptxas puts a read barrier on the word and the overwriter waits it
    // (`[R2:W3] SYNCS.EXCH.64 URZ, [UR37], UR4` ... `[B--2---] UMOV UR4, UR36`).
    if sync_on {
        for idx in 0..n {
            if insns[idx].hand_sched { continue; }
            let Some(c) = crate::sync_class::classify(&insns[idx]) else { continue };
            if !c.late_operands { continue; }
            let opk: Vec<u16> = crate::sync_class::source_regs(&insns[idx]).into_iter().map(|(u, r)| rk(u, r)).collect();
            if opk.is_empty() { continue; }
            let c = cfg.as_ref().expect("the control-flow graph exists under the switch");
            let (waiters, on) = c.first_overwriters(&writes, idx, &opk, &raw_stop[idx], rb_early);
            if waiters.is_empty() { continue; }
            uses.push(BarUse { setters: vec![idx], waiters, is_rb: true, segs: crate::cfg_flow::runs(&on) });
            pin_of.push(None);
        }
    }

    // ---- A19 experiment (CUBIT_RB_CHAIN=1, default off; KNOWN_ISSUES A19, T-9 2026-11-06) ----
    // The 2026-06 `5912400` schedules of the MC4 MoE prefill kernels (the shipped cubins, +34…58 %
    // faster than today's default on `mc4_k4096` / `mc4_k6144`) carry a read barrier on every
    // sub-word global load (`LDG.E.U8` scale bytes) that the NEXT global load in program order
    // waits — a chain that paces the issue of consecutive scalar loads (T-8 report part 8 §5:
    // 32 of the 41 extra read barriers). Not a WAR protection (the address register is never
    // rewritten in the loop), so the WAR pass above never produces it. Under the switch the
    // chain is reproduced as plain rb uses (setter = the sub-word load, waiter = the next global
    // load before the next control-flow instruction; merged into the load's WAR use when it has
    // one). Legality is unaffected either way (a wait is never a hazard); the switch exists to
    // measure the mechanism on silicon — the default flip is the owner's decision (NEEDS 31).
    if std::env::var("CUBIT_RB_CHAIN").ok().as_deref() == Some("1") {
        let is_global_load = |i: usize| -> bool {
            matches!(insns[i].opcode.as_str(), "LDG" | "LD") && !insns[i].hand_sched
        };
        let sub_word = |i: usize| -> bool {
            let f = insns[i].opcode_full.as_str();
            f.contains(".U8") || f.contains(".S8") || f.contains(".U16") || f.contains(".S16")
        };
        for i in 0..n {
            if !is_global_load(i) || !sub_word(i) || !insn_can_set_write_bar(&insns[i], table) {
                continue;
            }
            let mut waiter: Option<usize> = None;
            for j in (i + 1)..n {
                if is_control_flow(insns[j].opcode.as_str()) {
                    break;
                }
                if is_global_load(j) {
                    waiter = Some(j);
                    break;
                }
            }
            let Some(j) = waiter else { continue };
            let existing = uses
                .iter()
                .enumerate()
                .position(|(k, u)| u.is_rb && u.setters == [i] && pin_of[k].is_none());
            if let Some(u) = existing {
                if !uses[u].waiters.contains(&j) {
                    uses[u].waiters.push(j);
                    let w = uses[u].waiters.clone();
                    uses[u].segs = build_segs(i, &w, ltop[i], lback[i], &edges);
                }
            } else {
                let segs = build_segs(i, &[j], ltop[i], lback[i], &edges);
                uses.push(BarUse { setters: vec![i], waiters: vec![j], is_rb: true, segs });
                pin_of.push(None);
            }
        }
    }

    // ---- PINNED producers (BUG-117 / TS2-LDG256-AUTOWAIT exp-5): a hand_sched
    // `[CC]`-tagged variable-latency producer (e.g. an LDG.E.NA.ELL2.256.STRONG.GPU
    // carrying a verbatim champion tag) keeps its write-barrier word untouched,
    // but the auto RAW pass above skips it, so without this block its AUTO
    // consumers get NO wait bit — they read the register file before the load
    // retires (deterministic garbage limbs on silicon; spacers do not help,
    // only a wait does). Register the pinned producer as a fixed-colour use:
    // its tag's write-barrier index is honoured verbatim (never reallocated —
    // it is the author's), the auto waiters up to the next redefinition get
    // the wait injected by the common emit path (frozen waiters keep their
    // own tags), and the barrier index is marked occupied over the use's
    // segments so the allocator never hands it to an auto producer while the
    // pinned one may still be in flight. A `[W-]`-tagged producer has no
    // pinned barrier to wait — that shape belongs to the stall doctrine and
    // is reported by report_hazards, not repaired here.
    for i in 0..n {
        if !insns[i].hand_sched { continue; }
        let b = insns[i].ctrl.write_bar;
        if b >= NUM_BARRIERS as u8 { continue; }
        if !insn_needs_write_bar(&insns[i], table, true) { continue; }
        let gd = writes[i].clone();
        if gd.is_empty() {
            continue;
        }
        let (waiters, live_on) = match &cfg {
            Some(c) => {
                let guarded_here: Vec<bool> = (0..n).map(|j| guarded[j] && !guard_key[j].is_some_and(|k| gd.contains(&k))).collect();
                let (w, on) = c.first_consumers(&reads, &writes, &guarded_here, &[i], &gd, guarded_reader_settles());
                (w, Some(on))
            }
            None => {
                let (w, _wrap) = raw_consumers(&reads, &writes, &guarded, &flow, i, &gd, ltop[i], lback[i], &edges, n);
                (w, None)
            }
        };
        let auto_waiters: Vec<usize> = waiters
            .into_iter()
            .filter(|&w| !insns[w].hand_sched)
            .collect();
        if auto_waiters.is_empty() {
            continue;
        }
        let segs = match &live_on {
            Some(on) => crate::cfg_flow::runs(on),
            None => build_segs(i, &auto_waiters, ltop[i], lback[i], &edges),
        };
        uses.push(BarUse {
            setters: vec![i],
            waiters: auto_waiters,
            is_rb: false,
            segs,
        });
        pin_of.push(Some(b));
    }
    // PINNED read-barrier arm: a hand_sched memory op whose tag claims `R{b}`
    // (verbatim champion tags do; TS2-LDG256-AUTOWAIT exp-5 wore `R4`) has its
    // late-latched operands protected against AUTO overwriters — the WAR pass
    // above skips frozen instructions, so without this a white address-bump
    // after a tagged load races the in-flight latch. The pinned rb index is
    // honoured verbatim and reserved over the use's segments exactly like wb.
    for i in 0..n {
        if !insns[i].hand_sched { continue; }
        let b = insns[i].ctrl.read_bar;
        if b >= NUM_BARRIERS as u8 { continue; }
        let late: Vec<u8> = late_operands(i);
        if late.is_empty() { continue; }
        let opk: Vec<u16> = late.iter().map(|&r| rk(false, r as u16)).collect();
        let mut waiters: Vec<usize> = Vec::new();
        let mut live_on: Option<Vec<usize>> = None;
        match &cfg {
            Some(c) => {
                let (w, on) = c.first_overwriters(&writes, i, &opk, &raw_stop[i], rb_early);
                waiters = w.into_iter().filter(|&ow| !insns[ow].hand_sched).collect();
                live_on = Some(on);
            }
            None => {
                for (ow, _w) in war_overwriter(&writes, &flow, i, &opk, &raw_stop[i], rb_early, ltop[i], lback[i], &edges, n) {
                    if !insns[ow].hand_sched && !waiters.contains(&ow) { waiters.push(ow); }
                }
            }
        }
        if waiters.is_empty() { continue; }
        let segs = match &live_on {
            Some(on) => crate::cfg_flow::runs(on),
            None => build_segs(i, &waiters, ltop[i], lback[i], &edges),
        };
        uses.push(BarUse { setters: vec![i], waiters, is_rb: true, segs });
        pin_of.push(Some(b));
    }

    // ---- colour the uses onto 6 scoreboards via per-instruction occupancy ----
    // `occ[i]` = bitmask of scoreboards live at instruction i. A use takes a barrier
    // free across ALL of its occupied indices (its 1-2 segments). Loop-carried uses
    // (2 segments) are coloured first since they are the most constrained.
    let mut order: Vec<usize> = (0..uses.len()).collect();
    order.sort_by_key(|&u| (uses[u].segs.len() == 1, uses[u].segs[0].0));
    // CUBIT_SB_LONG_KEEP=1 (with CUBIT_SB_SHARE=1; default off): a prefetch keeps its scoreboard
    // to itself. Scoreboards are counters, so every wait on a scoreboard waits for everything
    // counted on it. Without the switch three kinds of use end up on the scoreboard of a long
    // prefetch (loads whose readers are a chunk of compute away) and their waits drain it in
    // the middle of the compute it was issued to overlap:
    //  * a short use whose setter comes earlier in the text is coloured first and takes
    //    scoreboard 4 or 5 while it is still free;
    //  * a short use that overflows shares "the busiest" scoreboard over its segment - the
    //    long one, live all across it;
    //  * the READ barrier of a store whose data registers are next written far away on some
    //    path is itself a long use, coloured from the top two - and its waiter is the first
    //    instruction that rewrites the register (sm_120 sparse_mla_prefill_v42: the dequant's
    //    last STS.128 of chunk c, waited by the second LDSM of chunk c+1's QK: `[B--2-4-]` /
    //    the fifth: `[B-1---5]` - the gather was in flight for four k-steps, not for the chunk;
    //    one extra load in the loop moved the gather to scoreboard 4, where the FIRST
    //    instruction of QK waited for it).
    // Under the switch: long uses are coloured before short ones; long WRITE uses (the loads)
    // share the top scoreboard, long READ-barrier uses (store latches) the one below it; a
    // short use neither takes nor shares a scoreboard on which a long use is live anywhere
    // over its segment. Waits only move between scoreboards - protection is never dropped.
    let sb_long_keep = std::env::var("CUBIT_SB_SHARE").ok().as_deref() == Some("1")
        && std::env::var("CUBIT_SB_LONG_KEEP").ok().as_deref() == Some("1");
    let sb_long_thr: usize = std::env::var("CUBIT_SB_LONG").ok().and_then(|s| s.parse().ok()).unwrap_or(256);
    let use_span = |u: usize| -> usize { uses[u].segs.iter().map(|&(a, b)| b.saturating_sub(a)).sum() };
    if sb_long_keep {
        order.sort_by_key(|&u| (pin_of[u].is_some() || use_span(u) <= sb_long_thr, uses[u].segs.len() == 1, uses[u].segs[0].0));
    }
    let mut occ_long = vec![0u8; n];
    if cfg.is_some() && !sb_long_keep {
        // (CUBIT_SYNC_CLASSES, occupancy by execution paths: the long-lived uses first, then in text order)
        let span_of = |u: usize| -> usize { uses[u].segs.iter().map(|&(a, b)| b - a + 1).sum() };
        order.sort_by_key(|&u| (span_of(u) <= 64, uses[u].segs[0].0));
    }
    let mut occ = vec![0u8; n];
    let mut assigned: Vec<u8> = vec![7; uses.len()];
    let mut inject_wait = vec![0u8; n];
    let idxset = |segs: &[(usize, usize)]| -> Vec<usize> {
        let mut v = Vec::new();
        for &(a, b) in segs { let b = b.min(n - 1); for i in a..=b { v.push(i); } }
        v
    };

    // BUG-478 (colouring policy, CUBIT_SB_SHARE=1): SM120 scoreboards are COUNTERS — ptxas
    // puts several in-flight loads of different widths and address streams on one
    // scoreboard with no drain between them and lets the consumer wait once (spec B,
    // sparse_mla_prefill_dsv41_bf16: `LDG.E.U8 R67 … W5`, `LDG.E.U8 R66 … W5`,
    // `LDG.E.64 R64 … W5`, `LDG.E.64 R62 … W5`, consumer `[B-----5]`). Sharing is therefore
    // safe; its only cost is a coarser wait. Under this policy:
    //  * a use that finds no free scoreboard SHARES the one whose occupants overlap it the
    //    most (long-lived uses cluster together) instead of forcing its setter to DRAIN a
    //    displaced barrier (the drain serialised a register-prefetch stream: each gather
    //    load waited for the previous one to RETURN — 1/3 of all stall samples of the
    //    sparse-MLA kernel sat on those loads);
    //  * a LONG use (span > CUBIT_SB_LONG, default 256 instructions: a prefetch whose
    //    consumer is far away) is coloured only from the top two scoreboards, so the short
    //    uses of the compute between (fragment loads of an HMMA chain) keep four colours of
    //    their own instead of overflowing onto the prefetch barrier and waiting for DRAM.
    // Default (unset) keeps the drain-on-overflow behaviour.
    let sb_share = std::env::var("CUBIT_SB_SHARE").ok().as_deref() == Some("1");
    let sb_long: usize = std::env::var("CUBIT_SB_LONG").ok().and_then(|s| s.parse().ok()).unwrap_or(256);
    for &u in &order {
        let sidx = idxset(&uses[u].segs);
        if let Some(b) = pin_of[u] {
            // PINNED use: the colour is the author's, never reallocated; only
            // reserve it so auto uses stay off the in-flight window.
            assigned[u] = b;
            for &i in &sidx { occ[i] |= 1 << b; }
            continue;
        }
        let span: usize = uses[u].segs.iter().map(|&(a, b)| b.saturating_sub(a)).sum();
        let is_long = sb_share && span > sb_long;
        // (CUBIT_SYNC_CLASSES: scoreboard 0 is the copy group's in a kernel that commits one)
        let lowest: u8 = if sb0_reserved { 1 } else { 0 };
        let first_colour: u8 = if is_long { (NUM_BARRIERS as u8).saturating_sub(2) } else { lowest };
        let mut chosen: Option<u8> = None;
        if sb_long_keep && is_long {
            // CUBIT_SB_LONG_KEEP: the long WRITE uses (prefetch loads) share the top scoreboard, the long
            // READ-barrier uses (a store's operands whose next writer is far, on some path) the one
            // below it - a wait for a store's latch never drains the loads in flight.
            chosen = Some(if uses[u].is_rb { NUM_BARRIERS as u8 - 2 } else { NUM_BARRIERS as u8 - 1 });
        }
        for b in first_colour..NUM_BARRIERS as u8 {
            if chosen.is_some() { break; }
            if sidx.iter().all(|&i| occ[i] & (1 << b) == 0) { chosen = Some(b); break; }
        }
        if chosen.is_none() && sb_share {
            // share: the scoreboard already busiest over our segment (clustering)
            let mut best = first_colour;
            let mut best_cost = usize::MAX;
            for b in first_colour..NUM_BARRIERS as u8 {
                // CUBIT_SB_LONG_KEEP: a short use never shares with a long one
                if sb_long_keep && !is_long && sidx.iter().any(|&i| occ_long[i] & (1 << b) != 0) { continue; }
                let free = sidx.iter().filter(|&&i| occ[i] & (1 << b) == 0).count();
                if free < best_cost { best_cost = free; best = b; }
            }
            chosen = Some(best);
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
                let mut best = lowest;
                let mut best_cost = usize::MAX;
                for b in lowest..NUM_BARRIERS as u8 {
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
        if is_long { for &i in &sidx { occ_long[i] |= 1 << b; } }
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
    // CUBIT_SYNC_CLASSES: the copy group's scoreboard is 0 -- `LDGDEPBAR` sets it as a write
    // barrier, `UTMACMDFLUSH` as a read barrier, `DEPBAR.LE SB0, n` names it.
    if sync_on {
        for ins in insns.iter_mut().filter(|x| !x.hand_sched) {
            match crate::sync_class::classify(ins) {
                Some(c) if c.write_bar == crate::sync_class::WriteBar::Group => ins.ctrl.write_bar = 0,
                Some(c) if c.group_read_bar => ins.ctrl.read_bar = 0,
                _ => {}
            }
        }
    }

    // ---- BUG-489: write after write the scans above do not see ----
    // A register whose scoreboarded result is pending, written again on some path with no wait
    // on the producer's write barrier:
    //  * the second load of a batch into a register the batch already produced -- the batch
    //    loop ends at a READER of the group's results, not at a second writer (the persistent
    //    MoE kernel: `LDC.64 R28, c[0x0][0x388]` ... `@P0 LDC.64 R28, c[0x0][0x3b8]`, both on
    //    one barrier with no wait between; ptxas: `[W3]` ... `[B---3--:W1]`);
    //  * a fixed-latency overwriter between two batch-mates -- the scan for a group's first
    //    consumers starts behind its last setter;
    //  * a producer issued again by its own loop when nobody read or rewrote its last result
    //    on the way round -- that scan ends back at the setter.
    // Outside those the overwriter of a pending result is a waiter already (BUG-485). Here the
    // schedule is closed under the verifier's own walk of the flow graph
    // (`store_paths::unwaited_rewrites`; predicates are correlated along a path, so writers
    // under complementary guards -- `@P2 LDG ... R14` / `@!P2 LDG ... R14`, one of them
    // executes, ptxas keeps them on one barrier -- are no pair): the second writer waits the
    // producer's write barrier. Only waits are added; a wait is legal wherever it stands. A
    // writer that cannot carry one is left to `CUBIT_VERIFY`, which reports the pair.
    // Under `CUBIT_SYNC_CLASSES` (or `CUBIT_WAW_WAIT=1`); the default path is not touched.
    if waw_wait_enabled() {
        for f in crate::store_paths::unwaited_rewrites(insns) {
            let w = f.writer;
            if insns[w].hand_sched {
                continue;
            }
            if !can_wait[w] && try_make_waitable(&mut insns[w]) {
                can_wait[w] = true;
            }
            if can_wait[w] {
                insns[w].ctrl.wait_mask |= 1 << f.write_bar;
            }
        }
    }

    if std::env::var("CUBIT_VERIFY").is_ok() {
        verify_scoreboard(insns, table);
    }
}

/// Structured result of the read-only scoreboard verifier (BUG-347). The three
/// classic counters are EXACTLY the numbers on the CUBIT_VERIFY line (wrap
/// findings are included in them and additionally broken out in `wrap_*`);
/// `unresolved_edges` drives the separate, additive CUBIT_VERIFY_LOOP line.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct VerifyReport {
    /// variable-latency result read before its write-barrier was waited
    pub raw: usize,
    /// late-latched mem-op operand overwritten before its read-barrier was waited
    pub war: usize,
    /// result read after its barrier was recycled by a different-latency producer
    pub recycle: usize,
    /// of `raw`: findings only visible across a resolved loop back-edge
    pub wrap_raw: usize,
    /// of `war`: wrap findings
    pub wrap_war: usize,
    /// of `recycle`: wrap findings
    pub wrap_recycle: usize,
    /// control-flow edges whose target is not statically resolvable
    /// (register-indirect BRA/BRX/BRXU/JMP/CALL or a target outside the
    /// kernel): loop-carried scoreboard relations across them are UNVERIFIED.
    pub unresolved_edges: usize,
    /// of `unresolved_edges` (BUG-370 decomposition, additive): the target
    /// role carries a NON-ZERO register (GPR != RZ on any branch-class op,
    /// or UR != URZ on BRX/BRXU-class) -- genuinely data-dependent dispatch.
    pub unresolved_reg_target: usize,
    /// of `unresolved_edges` (BUG-370): BRX/BRXU with a ZERO base (URZ/RZ) --
    /// the target is raw-immediate based (constant in principle, but the
    /// immediate's unit is not interpreted by the verifier, so the relation
    /// across the edge stays UNVERIFIED). Attribution class only.
    pub unresolved_const_base: usize,
    /// of `unresolved_edges` (BUG-370): static-target class whose target is
    /// outside this kernel, or whose Label operand never resolved.
    pub unresolved_outtarget: usize,
    /// store -> overwriter pairs that some path of the flow graph reaches without a wait on the
    /// store's read barrier (`store_paths::unwaited_store_overwrites`; not part of `war`, which
    /// is the count of the scoreboard simulation along the text)
    pub store_paths: usize,
    /// of `store_paths`: pairs of a store that carries no read barrier (probe mode only)
    pub store_paths_bare: usize,
    /// such pairs on the ADDRESS register of a shared / local store — not in `store_paths`: the
    /// vendor's assembler rewrites those registers from 8 issue cycles behind the store without
    /// a wait (97 pairs in the sm_120 census; 0 on a data register, 0 on a global store)
    pub store_paths_shared_addr: usize,
    /// producer -> second writer pairs: a register whose scoreboarded result is pending, written
    /// again on some path of the flow graph with no wait on the producer's write barrier
    /// (`store_paths::unwaited_rewrites`; not part of the three classic counts)
    pub waw: usize,
    /// such pairs of a shared-memory load and a shuffle without a write barrier — not in `waw`:
    /// the one shape the vendor's assembler leaves without a wait (3 pairs in the sm_120 census)
    pub waw_shuffle_into_load: usize,
    /// shuffle -> overwriter pairs: a source register of a `SHFL` rewritten on some path of the
    /// flow graph with none of the three waits that release it
    /// (`store_paths::unwaited_shuffle_sources`; not part of the three classic counts)
    pub shfl_sources: usize,
    /// such pairs behind a wait of the vendor's two further covers only (a younger shuffle's read
    /// barrier, a younger shared-memory load's write barrier) — not in `shfl_sources`
    pub shfl_sources_practice: usize,
}

/// BUG-370: classification of a statically UNRESOLVABLE control-flow edge,
/// grounded in the vendor ISA reference (SM120_ISA_REFERENCE: BRA = "Branch.
/// PC-relative target" on EVERY form incl. DIV/CONV; BRX = "Indirect branch
/// via register"; BRXU = "Indirect branch via uniform register"; CALL/JMP/JMX
/// carried over from the BUG-347 linter). The 347 detector used a flat
/// "any Reg/UReg operand in {BRA,BRX,BRXU,JMP,JMX,CALL}" heuristic which
/// misflagged two rt98 classes (census: results/cubitfix/370.md):
///   (a) BRA.DIV P0, URZ, <label> / BRA.CONV !P5, URZ, <label> — the UR is an
///       AUXILIARY operand (convergence bookkeeping), the branch target is the
///       PC-relative label and is statically resolved. These edges must not be
///       reported as unresolved (they were 20/64 of the rt98 LOOP lines).
///   (b) BRXU.U URZ, <imm> — URZ-based indirect: constant-in-principle, but
///       the immediate's unit is not interpreted here; reported under the
///       distinct `ConstBase` class instead of "register-indirect".
/// Zero-count rules: RZ (GPR 255) and URZ (UR 63) are the architectural zero
/// registers and never make a target data-dependent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnresClass {
    /// genuine data-dependent target (non-zero GPR, or non-zero UR on
    /// BRX/BRXU-class, or non-zero GPR on JMP/JMX/CALL-class).
    RegTarget,
    /// zero-base indirect (BRX/BRXU via URZ/RZ): constant-in-principle raw
    /// immediate target; unit uninterpreted -> stays UNVERIFIED.
    ConstBase,
    /// static-target branch whose resolved address is outside this kernel.
    OutKernel,
    /// control-flow op whose Label operand never resolved to an address.
    UnresolvedLabel,
}

impl UnresClass {
    fn reason(self) -> &'static str {
        match self {
            UnresClass::RegTarget => "register-indirect target",
            UnresClass::ConstBase => {
                "constant-base indirect target (zero register base; raw immediate unit uninterpreted)"
            }
            UnresClass::OutKernel => "branch target outside this kernel",
            UnresClass::UnresolvedLabel => "unresolved label target",
        }
    }
}

/// Classify one instruction for the BUG-347/370 unresolved-edge linter.
/// Returns None when the edge is statically resolvable (or not control flow).
fn unresolved_edge_class(
    ins: &Instruction,
    addr2idx: &std::collections::HashMap<u32, usize>,
) -> Option<UnresClass> {
    let op = ins.opcode.as_str();
    let mut any_gpr_nonzero = false;
    let mut any_ureg_nonzero = false;
    let mut any_zero_reg = false;
    for o in &ins.operands {
        match o {
            Operand::Reg { num, .. } => {
                if *num == 255 {
                    any_zero_reg = true;
                } else {
                    any_gpr_nonzero = true;
                }
            }
            Operand::UReg { num, .. } => {
                if *num == 63 {
                    any_zero_reg = true;
                } else {
                    any_ureg_nonzero = true;
                }
            }
            _ => {}
        }
    }
    if matches!(op, "BRX" | "BRXU") {
        // Indirect-branch class: the register IS the target base.
        if any_gpr_nonzero || any_ureg_nonzero {
            return Some(UnresClass::RegTarget);
        }
        if any_zero_reg {
            return Some(UnresClass::ConstBase);
        }
        // single-token absolute/label form (BUG-027): fall through to the
        // static-target arms below.
    } else if matches!(op, "JMP" | "JMX" | "JMXU" | "CALL") {
        if any_gpr_nonzero || any_ureg_nonzero {
            return Some(UnresClass::RegTarget);
        }
    } else if is_control_flow(op) {
        // BRA-family (all modifiers): PC-relative static target, auxiliary
        // P/UR operands (incl. real URs) are NOT the target (vendor law).
        if any_gpr_nonzero {
            return Some(UnresClass::RegTarget); // defensive: GPR in a BRA-class target role
        }
    } else if !(matches!(op, "RET" | "PRET") && ins.operands.is_empty()) {
        // Not a control-flow op the linter watches (BUG-347 set + EXIT/RET/
        // BREAK/CONT/KILL/BSSY/BSYNC/BBREAK/BMOV via is_control_flow).
        return None;
    }
    if !is_control_flow(op) && !matches!(op, "BRX" | "BRXU" | "JMP" | "JMX" | "JMXU" | "CALL") {
        return None;
    }
    // Static-target arms.
    match branch_target(ins) {
        Some(t) if !addr2idx.contains_key(&t) => Some(UnresClass::OutKernel),
        Some(_) => None,
        None => {
            if ins.operands.iter().any(|o| matches!(o, Operand::Label(_))) {
                Some(UnresClass::UnresolvedLabel)
            } else {
                None
            }
        }
    }
}

/// Read-only scoreboard verification as a pure report (no printing) so tests
/// and tooling can assert on it. Same analysis the CUBIT_VERIFY path runs.
pub fn verify_scoreboard_report(insns: &[Instruction], table: Option<&IsaTable>) -> VerifyReport {
    run_verify(insns, table, false, false)
}

/// One finding behind the three classic counts of `CUBIT_VERIFY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreboardFinding {
    /// `"raw"` (a variable-latency result read before its write barrier was waited), `"war"` (a
    /// late operand of a memory operation overwritten before its read barrier was waited),
    /// `"recycle-stale"`; and, from the walk of the flow graph and outside the three counts,
    /// `"waw"` (a register whose scoreboarded result is pending, written again with no wait on
    /// the producer's write barrier) or `"waw-shuffle-into-load"` (that on the one shape the
    /// vendor's assembler leaves unwaited, counted apart)
    pub kind: &'static str,
    /// the reader of the result (`raw`, `recycle-stale`) / the overwriter (`war`) / the second
    /// writer (`waw`)
    pub at: usize,
    /// the producer of the result / the memory operation
    pub other: usize,
    /// the register as it is printed: `R12`, `P3`, `UR4`, `UP1`
    pub register: String,
}

/// The same read-only verification with its findings as data (no printing): the report and one
/// entry per distinct (kind, instruction pair, register). The counts of the report are per event
/// of the walk and can exceed the number of entries.
pub fn verify_scoreboard_findings(insns: &[Instruction], table: Option<&IsaTable>) -> (VerifyReport, Vec<ScoreboardFinding>) {
    let (rep, keys) = run_verify_keys(insns, table, false, false);
    let name = |regk: u16| -> String {
        let (uniform, k) = (regk >> 9 != 0, regk & 0x1ff);
        match (uniform, k) {
            (false, k) if k >= PRED_KEY => format!("P{}", k - PRED_KEY),
            (false, k) => format!("R{k}"),
            (true, k) if k >= 64 => format!("UP{}", k - 64),
            (true, k) => format!("UR{k}"),
        }
    };
    let findings = keys
        .into_iter()
        .map(|(kind, at, other, regk)| ScoreboardFinding {
            kind: match kind {
                0 => "raw",
                1 => "war",
                2 => "recycle-stale",
                3 => "waw",
                4 => "waw-shuffle-into-load",
                5 => "shfl-source",
                _ => "shfl-source-practice",
            },
            at,
            other,
            register: name(regk),
        })
        .collect();
    (rep, findings)
}

/// The scheduling-legality oracle's read-barrier coverage probe (KNOWN_ISSUES A4,
/// `tools/sched_oracle.py`): the same read-only verification, but every late-latching
/// mem-op WITHOUT a read barrier is tracked as if it carried one that nothing ever waits
/// (the virtual barrier `VIRTUAL_RB`). A schedule that never SET a store's read barrier
/// is invisible to the plain verifier by construction (the 2026-06 `ebbd1dc` shape); in
/// this mode every overwriter of such a mem-op's late-latched operands is a BROKEN WAR
/// (released only by the mem-op's waited write barrier, BUG-486). Replaces the tool's
/// first design (inject a free barrier index into the R slot and re-verify), which has no
/// barrier to inject on the kernels that matter — nvcc uses all six on most census kernels.
pub fn verify_scoreboard_rb_probe(insns: &[Instruction], table: Option<&IsaTable>) -> VerifyReport {
    run_verify(insns, table, false, true)
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
///
/// BUG-347: the simulation is LOOP-AWARE. A single linear pass is blind to
/// loop-carried (wrap) relations in both directions: a loop-head consumer of a
/// body-tail producer is checked BEFORE the producer is ever seen (real bugs
/// silently pass — BUG-342's class was exactly this), and in-flight state
/// armed inside the body is never re-checked against the head of the next
/// iteration. After the classic pass, the walk therefore re-runs every resolved
/// loop body once from its end-of-body snapshot (innermost first), deduping
/// against first-pass findings; genuinely new violations join the classic
/// counters and are tagged "(loop-carried wrap)". Control-flow edges whose
/// target cannot be statically resolved (register-indirect BRA/BRX/BRXU/JMP, or
/// a target missing from the kernel) bound loops the wrap pass CANNOT walk —
/// those are counted in `unresolved_edges` and printed on a separate
/// CUBIT_VERIFY_LOOP line instead of being silently skipped (fail-loud).
fn verify_scoreboard(insns: &[Instruction], table: Option<&IsaTable>) {
    let probe = std::env::var("CUBIT_VERIFY_RBPROBE").ok().as_deref() == Some("1");
    run_verify(insns, table, true, probe);
}

/// Barrier id of the rb-coverage probe (`verify_scoreboard_rb_probe`): outside the six
/// real scoreboards, so no wait mask ever releases it.
const VIRTUAL_RB: u8 = NUM_BARRIERS as u8;

/// Live barrier state of the simulated warp scoreboard. Cloned at loop backs so
/// the BUG-347 wrap pass can re-run a loop body from its end-of-iteration
/// state.
#[derive(Clone, Default)]
struct SbState {
    pending: std::collections::HashMap<u16, (u8, usize)>, // reg -> (barrier, producer idx)
    lost: std::collections::HashMap<u16, usize>, // reg -> producer idx (barrier recycled before waited)
    rbp: std::collections::HashMap<u8, (u8, usize)>, // GPR -> (rb barrier, memop idx) late-latched operand
}

/// Issue distance (sum of stalls) between two slots. On a wrap re-walk with
/// `wrap = Some((top, back))`, a pair (midx > i) sits one iteration apart:
/// midx..=back then top..i.
fn stall_gap(insns: &[Instruction], midx: usize, i: usize, wrap: Option<(usize, usize)>) -> u32 {
    match wrap {
        Some((top, back)) if midx > i => (midx..=back)
            .chain(top..i)
            .map(|k| insns[k].ctrl.stall as u32)
            .sum(),
        _ => (midx..i).map(|k| insns[k].ctrl.stall as u32).sum(),
    }
}

/// Two producers on one write barrier complete in issue order (the younger does not displace
/// the older's result from the barrier): the same completion-latency class = same opcode +
/// width AND (for MEMORY loads) the same address stream/line — completion order across
/// different streams is not issue order: global is cache-outcome order; shared/local reorders
/// under cross-CTA MIO arbitration at >=2 CTAs/SM (the skinny_fp8_mm tree-reduce repro).
/// Non-memory variable-latency producers (MUFU, S2R, ...) of the same opcode complete in order
/// on their pipe. CUBIT_SHARED_BATCH=1 restores the old (unsafe) shared assumption to mirror
/// the allocator's A/B gate.
pub(crate) fn same_completion_class(older: &Instruction, younger: &Instruction) -> bool {
    let wof = |of: &str| {
        if of.contains(".128") {
            16u8
        } else if of.contains(".64") {
            8
        } else if of.contains(".U16") || of.contains(".S16") {
            2
        } else if of.contains(".U8") || of.contains(".S8") {
            1
        } else {
            4
        }
    };
    if older.opcode != younger.opcode {
        return false;
    }
    if wof(older.opcode_full.as_str()) != wof(younger.opcode_full.as_str()) {
        return false;
    }
    if load_kind_sched2(younger.opcode.as_str()) == 2 && std::env::var("CUBIT_SHARED_BATCH").ok().as_deref() == Some("1") {
        return true;
    }
    match (load_addr_key(older), load_addr_key(younger)) {
        (Some((kp, op_)), Some((ki, oi))) => kp == ki && (oi - op_).abs() < 0x80,
        (None, None) => true,
        _ => false,
    }
}

/// One instruction of the scoreboard simulation: checks first (RAW / recycle /
/// WAR), then state updates — the exact internal order the pre-347 single
/// pass used. `wrap = Some(..)` marks a wrap re-walk: findings dedupe against
/// the linear pass through `seen` and count additionally as wrap findings.
#[allow(clippy::too_many_arguments)]
fn sb_step(
    insns: &[Instruction],
    i: usize,
    table: Option<&IsaTable>,
    st: &mut SbState,
    rep: &mut VerifyReport,
    seen: &mut std::collections::HashSet<(u8, usize, usize, u16)>,
    wrap: Option<(usize, usize)>,
    print: bool,
    rb_probe: bool,
) {
    let rk = |u: bool, r: u16| -> u16 { ((u as u16) << 9) | r };
    // kind: 0 = unprotected RAW, 1 = broken WAR, 2 = recycle-stale. The linear
    // pass always counts/prints (identical to pre-347, per-event) and only
    // RECORDS its keys; the wrap pass counts/prints strictly-new keys.
    // Keys carry the (UR<<8|reg) code so several registers of one pair do
    // not collapse.
    let mut note =
        |kind: u8, at: usize, other: usize, regk: u16, msg: String, rep: &mut VerifyReport| {
            if wrap.is_some() && !seen.insert((kind, at, other, regk)) {
                return;
            }
            if wrap.is_none() {
                seen.insert((kind, at, other, regk));
            }
            match kind {
                0 => {
                    rep.raw += 1;
                    if wrap.is_some() {
                        rep.wrap_raw += 1;
                    }
                }
                1 => {
                    rep.war += 1;
                    if wrap.is_some() {
                        rep.wrap_war += 1;
                    }
                }
                _ => {
                    rep.recycle += 1;
                    if wrap.is_some() {
                        rep.wrap_recycle += 1;
                    }
                }
            }
            if print {
                eprintln!(
                    "{msg}{}",
                    if wrap.is_some() {
                        " (loop-carried wrap)"
                    } else {
                        ""
                    }
                );
            }
        };
    let mut wm = insns[i].ctrl.wait_mask;
    // `DEPBAR.<m> SBb, imm` is the instruction-level drain of scoreboard b: it carries no
    // wait-mask bit (the barrier index is operand 0), so without this the verifier reported
    // every read behind a DEPBAR-drained barrier as an unprotected RAW (the allocator's hazard
    // audit has modelled it since rt98; BUG-486 brings the verifier in line, same full-drain
    // reading of the LE threshold).
    if insns[i].opcode == "DEPBAR" {
        if let Some(Operand::Imm32(v)) = insns[i].operands.first() {
            if (0..NUM_BARRIERS as i64).contains(v) {
                wm |= 1 << *v;
            }
        }
    }
    if wm != 0 {
        st.pending.retain(|_, &mut (b, _)| (wm & (1 << b)) == 0);
        // A late-latched operand is released by a wait on the mem-op's read barrier, and
        // (BUG-486) by a wait on the mem-op's WRITE barrier: a variable-latency op whose
        // result has landed has consumed its operands (ptxas schedules `LDS R3, [R2]` W0 →
        // `… R3` B0 → `MOV R2, …` with no read barrier on the LDS — the address cannot be
        // re-latched after completion). Stores have no write barrier and keep the rb rule.
        st.rbp.retain(|_, &mut (b, midx)| {
            if (wm & (1 << b)) != 0 {
                return false;
            }
            let wb = insns[midx].ctrl.write_bar;
            !(wb < NUM_BARRIERS as u8 && (wm & (1 << wb)) != 0)
        });
    }
    for (u, r) in src_regs(&insns[i]) {
        if let Some(&(b, pidx)) = st.pending.get(&rk(u, r)) {
            note(
                0,
                i,
                pidx,
                rk(u, r),
                format!(
                    "  UNPROTECTED RAW: insn[{i}] {} reads {}{} <- var-producer insn[{pidx}] {} (barrier {b} not waited)",
                    insns[i].opcode_full,
                    if u { "UR" } else { "R" },
                    r,
                    insns[pidx].opcode_full
                ),
                rep,
            );
        }
        if let Some(&pidx) = st.lost.get(&rk(u, r)) {
            note(
                2,
                i,
                pidx,
                rk(u, r),
                format!(
                    "  RECYCLE-STALE: insn[{i}] {} reads {}{} <- var-producer insn[{pidx}] {} (barrier recycled before waited)",
                    insns[i].opcode_full,
                    if u { "UR" } else { "R" },
                    r,
                    insns[pidx].opcode_full
                ),
                rep,
            );
        }
    }
    // WAR: this insn writes a GPR that is an in-flight late-latched operand whose rb
    // it did NOT wait → the memory op may latch the overwritten value (broken rb).
    for r in dest_regs(&insns[i])
        .into_iter()
        .filter(|(u, r)| !*u && *r < PRED_KEY)
        .map(|(_, r)| r as u8)
    {
        if let Some(&(b, midx)) = st.rbp.get(&r) {
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
            // On a wrap re-walk (BUG-347) the distance wraps the back-edge: the rb is
            // normally waited at the loop top, which clears `rbp` before the next-iter
            // overwriter; an un-waited head overwriter races the tail mem-op.
            const LOAD_ADDR_LATCH: u32 = 3;
            let dist: u32 = stall_gap(insns, midx, i, wrap);
            let late_latcher = insn_is_store(&insns[midx], table)
                || is_warp_mma(insns[midx].opcode.as_str())
                || matches!(insns[midx].opcode.as_str(), "LDS" | "LDSM" | "LDL");
            let covered = !late_latcher && dist >= LOAD_ADDR_LATCH;
            if !covered {
                note(
                    1,
                    i,
                    midx,
                    rk(false, r as u16),
                    format!(
                        "  BROKEN WAR: insn[{i}] {} overwrites R{r} before rb (barrier {b}) of mem-op insn[{midx}] {} is waited{}",
                        insns[i].opcode_full,
                        insns[midx].opcode_full,
                        if b == VIRTUAL_RB { " (probe: the mem-op has no read barrier)" } else { "" }
                    ),
                    rep,
                );
            }
        }
    }
    let var =
        insn_needs_write_bar(&insns[i], table, true) && !is_warp_mma(insns[i].opcode.as_str());
    let wb = insns[i].ctrl.write_bar;
    let dsts: Vec<u16> = dest_regs(&insns[i])
        .into_iter()
        .map(|(u, r)| rk(u, r))
        .collect();
    for d in &dsts {
        st.pending.remove(d);
        st.lost.remove(d);
    }
    if var && wb < NUM_BARRIERS as u8 {
        // recycle: regs still pending on wb from an EARLIER producer of a DIFFERENT
        // latency class (opcode/width) become unprotected — the last-only barrier now
        // tracks this producer, which may complete first. Same-opcode/width batch-mates
        // complete in issue order, so they stay protected (not a recycle).
        let same_lat = |p: usize| same_completion_class(&insns[p], &insns[i]);
        let losers: Vec<u16> = st
            .pending
            .iter()
            .filter(|(_, &(b, p))| b == wb && !same_lat(p))
            .map(|(&k, _)| k)
            .collect();
        for l in losers {
            let (_, pidx) = st.pending.remove(&l).unwrap();
            st.lost.insert(l, pidx);
        }
        for d in &dsts {
            st.pending.insert(*d, (wb, i));
        }
    }
    // register this mem-op's rb-protected late operands (in probe mode also the operands
    // of a mem-op that carries NO read barrier, under the never-waited virtual barrier)
    let rb = match insns[i].ctrl.read_bar {
        b if b < NUM_BARRIERS as u8 => b,
        _ if rb_probe => VIRTUAL_RB,
        _ => 7,
    };
    if rb <= VIRTUAL_RB {
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
            for r in store_data_gprs(&insns[i]) {
                if !v.contains(&r) {
                    v.push(r);
                }
            }
            v
        } else if is_warp_mma(op) {
            // MMA fragments/scale-factors latch over a long read window (see
            // mma_src_gprs) — an overwriting load must wait the MMA's rb.
            mma_src_gprs(&insns[i])
        } else if is_long_latency(op) {
            // BUG-482: the data registers of an atomic / reduction are late-latched too.
            let mut v = load_addr_gprs(&insns[i]);
            for r in atom_data_gprs(&insns[i]) {
                if !v.contains(&r) {
                    v.push(r);
                }
            }
            v
        } else {
            Vec::new()
        };
        for l in late {
            st.rbp.insert(l, (rb, i));
        }
    }
}

fn run_verify(insns: &[Instruction], table: Option<&IsaTable>, print: bool, rb_probe: bool) -> VerifyReport {
    run_verify_keys(insns, table, print, rb_probe).0
}

/// `run_verify` with the keys of its findings: (kind, at, other, register) -- kind 0 an unprotected
/// RAW (`at` reads the result of `other`), 1 a broken WAR (`at` overwrites a late operand of the
/// memory operation `other`), 2 recycle-stale (as 0), 3 write after write (`at` writes a register
/// whose result of `other` is pending; 4: that on the shuffle-into-load shape); the register as
/// `(uniform << 9) | key`.
#[allow(clippy::type_complexity)]
fn run_verify_keys(
    insns: &[Instruction],
    table: Option<&IsaTable>,
    print: bool,
    rb_probe: bool,
) -> (VerifyReport, Vec<(u8, usize, usize, u16)>) {
    use std::collections::{HashMap, HashSet};
    let mut rep = VerifyReport::default();
    let mut seen: HashSet<(u8, usize, usize, u16)> = HashSet::new();
    // BUG-347 (wrap): resolved loop back-edges + end-of-body state snapshots.
    let (edges, _, _) = resolved_back_edges(insns);
    let mut back2edge: HashMap<usize, usize> = HashMap::new();
    for (ei, &(_, b)) in edges.iter().enumerate() {
        back2edge.insert(b, ei);
    }
    let mut snaps: Vec<Option<SbState>> = vec![None; edges.len()];
    let mut st = SbState::default();
    for i in 0..insns.len() {
        sb_step(insns, i, table, &mut st, &mut rep, &mut seen, None, print, rb_probe);
        if let Some(&ei) = back2edge.get(&i) {
            snaps[ei] = Some(st.clone());
        }
    }
    // Wrap re-walks (innermost first): re-run every resolved loop body once
    // from its end-of-iteration snapshot, so loop-carried protection (or the
    // LACK of it) is checked against the head of the next iteration — the
    // class the single-pass walk could not see in either direction.
    let mut order: Vec<usize> = (0..edges.len()).collect();
    order.sort_by_key(|&ei| edges[ei].1 - edges[ei].0);
    for ei in order {
        let Some(snap) = snaps[ei].take() else {
            continue;
        };
        let (top, back) = edges[ei];
        let mut wst = snap;
        for i in top..=back {
            sb_step(
                insns,
                i,
                table,
                &mut wst,
                &mut rep,
                &mut seen,
                Some((top, back)),
                print,
                rb_probe,
            );
        }
    }
    // Unresolvable control flow: register-indirect branches bound loops the
    // wrap pass cannot walk (the allocator's `edges` skip them for the same
    // reason), and targets missing from the kernel are not indexable. Fail
    // LOUD on the class instead of leaving it silently blind (BUG-347).
    let mut addr2idx: HashMap<u32, usize> = HashMap::new();
    for (i, ins) in insns.iter().enumerate() {
        addr2idx.insert(ins.addr, i);
    }
    for (j, ins) in insns.iter().enumerate() {
        let Some(class) = unresolved_edge_class(ins, &addr2idx) else {
            continue;
        };
        rep.unresolved_edges += 1;
        match class {
            UnresClass::RegTarget => rep.unresolved_reg_target += 1,
            UnresClass::ConstBase => rep.unresolved_const_base += 1,
            UnresClass::OutKernel | UnresClass::UnresolvedLabel => rep.unresolved_outtarget += 1,
        }
        if print {
            eprintln!(
                "  UNRESOLVED-EDGE: insn[{j}] {} — {}; loop-carried scoreboard protection across this edge is UNVERIFIED",
                ins.opcode_full,
                class.reason(),
            );
        }
    }
    // The stores' read barriers on every path of the flow graph (`store_paths`): the simulation
    // above follows the text and does not track shared stores, so a wait the last iteration
    // branches around passed as protection. Reported next to the three counts, not inside them.
    let (shared_addr, paths): (Vec<_>, Vec<_>) = crate::store_paths::unwaited_store_overwrites(insns, rb_probe)
        .into_iter()
        .partition(|f| crate::store_paths::is_shared_store_address(insns, f));
    rep.store_paths = paths.len();
    rep.store_paths_bare = paths.iter().filter(|f| f.read_bar.is_none()).count();
    rep.store_paths_shared_addr = shared_addr.len();
    // Write after write on every path of the flow graph (`store_paths::unwaited_rewrites`): the
    // simulation above drops a pending result silently when its register is written again.
    // Reported next to the three counts, not inside them.
    let (shuffle_into_load, rewrites): (Vec<_>, Vec<_>) = crate::store_paths::unwaited_rewrites(insns)
        .into_iter()
        .partition(|f| crate::store_paths::is_shuffle_into_shared_load(insns, f));
    rep.waw = rewrites.len();
    rep.waw_shuffle_into_load = shuffle_into_load.len();
    // A shuffle's source registers on every path (`store_paths::unwaited_shuffle_sources`): the
    // simulation above registers under a read barrier only address registers (and an atomic's
    // data); a shuffle has none, so its sources were protected by nothing here (KNOWN_ISSUES A34).
    let (shuffle_practice, shuffle_sources): (Vec<_>, Vec<_>) =
        crate::store_paths::unwaited_shuffle_sources(insns).into_iter().partition(|f| f.practice);
    rep.shfl_sources = shuffle_sources.len();
    rep.shfl_sources_practice = shuffle_practice.len();
    if print {
        for f in &paths {
            eprintln!("{}", crate::store_paths::describe(insns, f));
        }
        for f in &rewrites {
            eprintln!("{}", crate::store_paths::describe_rewrite(insns, f));
        }
        for f in &shuffle_sources {
            eprintln!("{}", crate::store_paths::describe_shuffle_source(insns, f));
        }
        eprintln!(
            "CUBIT_VERIFY: {} unprotected RAW, {} broken WAR, {} recycle-stale",
            rep.raw, rep.war, rep.recycle
        );
        // CUBIT_VERIFY_FLOW=1: the same three kinds on the paths of the flow graph (`sb_flow`): the
        // simulation above follows the text, also across a word that never falls through. A view
        // of its own, next to the three counts; nothing above changes with it.
        if crate::sb_flow::enabled() {
            let flow = crate::sb_flow::walk(insns, table, rb_probe);
            for f in &flow.findings {
                eprintln!("{}", crate::sb_flow::describe(insns, f));
            }
            eprintln!(
                "CUBIT_VERIFY_FLOW: {} unprotected RAW, {} broken WAR, {} recycle-stale on the paths of the flow graph ({} walk(s) end at a return or an absolute jump with their barrier unwaited, {} without the correlation of predicates)",
                flow.count("raw"),
                flow.count("war"),
                flow.count("recycle-stale"),
                flow.ends,
                flow.uncorrelated
            );
            for line in crate::sb_flow::describe_apart(&flow) {
                eprintln!("{line}");
            }
        }
        if rep.waw > 0 {
            eprintln!(
                "CUBIT_VERIFY_WAW: {} pending result(s) written again on a path with no wait on the producer's write barrier; not in the counts above",
                rep.waw
            );
        }
        if rep.shfl_sources > 0 {
            eprintln!(
                "CUBIT_VERIFY_SHFL: {} source register(s) of a shuffle rewritten on a path with none of the waits that release it; not in the counts above",
                rep.shfl_sources
            );
        }
        if rep.shfl_sources_practice > 0 {
            eprintln!(
                "CUBIT_VERIFY_SHFL: + {} such pair(s) behind a wait on a younger shuffle's read barrier or a younger shared-memory load's write barrier only (not counted: the vendor's practice, the unit is served in order)",
                rep.shfl_sources_practice
            );
        }
        if rep.waw_shuffle_into_load > 0 {
            eprintln!(
                "CUBIT_VERIFY_WAW: + {} such pair(s) of a shared-memory load and a shuffle without a write barrier into one register of its result (not counted: the vendor's assembler leaves that shape without a wait)",
                rep.waw_shuffle_into_load
            );
        }
        if rep.store_paths > 0 {
            eprintln!(
                "CUBIT_VERIFY_PATHS: {} store -> overwriter pair(s) reached on a path with no wait on the store's read barrier ({} of them on a store without one); not in the counts above",
                rep.store_paths, rep.store_paths_bare
            );
        }
        if rep.store_paths_shared_addr > 0 {
            eprintln!(
                "CUBIT_VERIFY_PATHS: + {} such pair(s) on the address register of a shared / local store (not counted: the vendor's assembler rewrites those from 8 issue cycles behind the store)",
                rep.store_paths_shared_addr
            );
        }
        if rep.unresolved_edges > 0 {
            eprintln!(
                "CUBIT_VERIFY_LOOP: {} unresolvable control-flow edge(s); loop-carried scoreboard relations across them are UNVERIFIED",
                rep.unresolved_edges
            );
        }
    }
    let mut keys: Vec<(u8, usize, usize, u16)> = seen.into_iter().collect();
    // kind 3: write after write (`at` writes a register whose result of `other` is pending);
    // kind 4: the same on the vendor's shuffle-into-load shape, counted apart
    keys.extend(rewrites.iter().map(|f| (3u8, f.writer, f.producer, f.reg as u16)));
    keys.extend(shuffle_into_load.iter().map(|f| (4u8, f.writer, f.producer, f.reg as u16)));
    // kind 5: a shuffle's source rewritten (`at` rewrites a source register of the shuffle `other`)
    keys.extend(shuffle_sources.iter().map(|f| (5u8, f.overwriter, f.shuffle, f.reg as u16)));
    keys.extend(shuffle_practice.iter().map(|f| (6u8, f.overwriter, f.shuffle, f.reg as u16)));
    keys.sort_unstable();
    (rep, keys)
}

// ── Stall-gap insertion for non-standard scheduling classes ──────────────────

/// Insert IADD3+RZ delay instructions where the scheduler computed a stall
/// that cannot be encoded in the instruction's non-standard scheduling layout.
///
/// IADD3 with Rc2=RZ forces hi_lower32\[7:0\]=0xFF, giving a hardware-enforced
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

/// Post-encoding pass: set BRA bits\[31:24\] to the convergence barrier ID.
///
/// Algorithm:
/// 1. Scan for BSSY instructions → record (barrier_id, bssy_addr, target_addr)
/// 2. For each BRA in the encoded bytes, check if it falls inside a BSSY region
/// 3. If so, patch byte at offset+3 (bits\[31:24\]) with the barrier number
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

#[cfg(test)]
mod bug102_tests {
    //! White-box pins for the BUG-102 batchability classes used by the
    //! RECYCLE audit: async write-back producer classes (the ones vendors
    //! batch on one shared barrier) stay quiet; everything else re-arms
    //! loudly.
    use super::*;

    #[test]
    fn batchable_classes_match_certified_batches() {
        // Classes OBSERVED batched on the silicon-EXACT rt98 publish text.
        for op in ["S2R", "S2UR", "LDC", "LDCU", "LDG", "SHFL", "LDS", "LDL", "LDSM", "LDGSTS"] {
            assert!(hazard_recycle_batchable(op), "{op} must be batchable");
        }
        // Classes without async scoreboard write-back (stray W-tag case) and
        // the deliberately loud REDUX (allocator no-batch, no corpus evidence).
        for op in ["IMAD", "IADD3", "MOV", "UIMAD", "MUFU", "F2I", "POPC", "ISETP", "STG", "STS", "REDUX", "EXIT"] {
            assert!(!hazard_recycle_batchable(op), "{op} must warn on re-arm");
        }
    }
}

#[cfg(test)]
mod bug108_tests {
    //! White-box pins for the BUG-108 span halves: the uniform-domain
    //! UIMAD.WIDE UR-pair spans are invisible in the default pipeline
    //! (the producer-side stall floor swamps the observable effect), so
    //! they are pinned here directly on dest_regs/src_regs.
    use super::*;

    fn first_insn(body: &str) -> Instruction {
        let src = format!(".entry t\n    .param u64 io\n{body}    EXIT ;\n");
        let f = crate::sass_file::parse_sass_file_str_strict(&src).unwrap();
        f.kernels[0].instructions[0].clone()
    }

    #[test]
    fn uimad_wide_dest_ur_pair() {
        let i = first_insn("    UIMAD.WIDE.U32 UR10, UR20, 0x5, UR22 ;\n");
        let d = dest_regs(&i);
        assert!(d.contains(&(true, 10)), "dest pair lo UR10 missing: {d:?}");
        assert!(d.contains(&(true, 11)), "dest pair hi (UR11) missing: {d:?}");
    }

    #[test]
    fn uimad_wide_addend_ur_pair_not_multiplicand() {
        let i = first_insn("    UIMAD.WIDE.U32 UR10, UR20, 0x5, UR22 ;\n");
        let s = src_regs(&i);
        assert!(s.contains(&(true, 22)) && s.contains(&(true, 23)),
            "64-bit addend must register as UR pair (UR22/UR23): {s:?}");
        assert!(!s.contains(&(true, 21)),
            "A multiplicand is 32-bit: UR21 must NOT be spanned: {s:?}");
    }

    #[test]
    fn vector_wide_dest_pair_unchanged() {
        let i = first_insn("    IMAD.WIDE.U32.X R212, P0, R233, 0x3d1, R232, P6 ;\n");
        let d = dest_regs(&i);
        assert!(d.contains(&(false, 212)) && d.contains(&(false, 213)),
            "vector WIDE dest pair pre-existing span must hold: {d:?}");
    }

    #[test]
    fn imad_wide_never_needs_write_bar() {
        let tab = crate::table::IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap();
        let i = first_insn("    IMAD.WIDE.U32.X R212, P0, R233, 0x3d1, R232, P6 ;\n");
        assert!(!insn_needs_write_bar(&i, Some(&tab), false),
            "imad_wide class must not force a scoreboard barrier (fixed-latency ALU)");
        assert!(!insn_needs_write_bar(&i, Some(&tab), true),
            "same under sched2");
    }
}

#[cfg(test)]
mod bug170_opex1_unit {
    //! White-box matrix for the TABLES_opex_1 law on (U)PLOP3 (BUG-170):
    //! legal index set = 0x00..=0x0F | 0x11..=0x1B; repair = stall 0 -> 1
    //! beside yield, stall >= 12 drops yield and keeps its stall. Bars, wait
    //! mask and already-legal pairs are bit-exact untouched; non-LOP3 ops and
    //! hand-scheduled words are out of scope by contract.
    use super::*;

    fn cc(stall: u8, yield_flag: bool) -> crate::ir::ControlCode {
        crate::ir::ControlCode {
            stall,
            yield_flag,
            write_bar: 3,
            read_bar: 5,
            wait_mask: 0b10101,
        }
    }

    fn low5(c: &crate::ir::ControlCode) -> u8 {
        (c.stall & 0xF) | ((c.yield_flag as u8) << 4)
    }

    #[test]
    fn law_set_boundary() {
        for s in 0u8..=15 {
            assert!(matches!(s | 0x10, 0x11..=0x1B) == (1..=11).contains(&s),
                "yield legality must hold exactly for stall 1..=11 (s={s})");
        }
    }

    #[test]
    fn repair_matrix() {
        // (0, Y) -> (1, Y): delay minimum is the dominant vendor yield form 0x11.
        let mut c = cc(0, true);
        assert!(opex1_lop3_legalize("UPLOP3", &mut c));
        assert_eq!((c.stall, c.yield_flag), (1, true));
        // (12..=15, Y) -> (s, no-Y): delay preserved, vendor 0x0C/0x0F shape.
        for s in 12u8..=15 {
            let mut c = cc(s, true);
            assert!(opex1_lop3_legalize("PLOP3", &mut c));
            assert_eq!((c.stall, c.yield_flag), (s, false));
            assert_eq!((c.write_bar, c.read_bar, c.wait_mask), (3, 5, 0b10101));
        }
        // Already-legal pairs are untouched (both arms).
        for s in [1u8, 2, 5, 10, 11] {
            let mut c = cc(s, true);
            assert!(!opex1_lop3_legalize("UPLOP3", &mut c));
            assert_eq!(low5(&c), s | 0x10);
        }
        for s in [0u8, 1, 9, 12, 15] {
            let mut c = cc(s, false);
            assert!(!opex1_lop3_legalize("UPLOP3", &mut c));
            assert_eq!(low5(&c), s);
        }
        // Scope: sibling uniform-LOP3 and pred writers are NOT the opex_1 class.
        for op in ["ULOP3", "UISETP", "ISETP", "LOP3", "QMMA"] {
            let mut c = cc(13, true);
            assert!(!opex1_lop3_legalize(op, &mut c), "{op} must be out of scope");
            assert_eq!((c.stall, c.yield_flag), (13, true));
        }
    }
}
