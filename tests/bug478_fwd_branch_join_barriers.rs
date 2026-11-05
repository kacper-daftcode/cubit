//! BUG-478 (reported by session V as "BUG-421" on 2026-11-04 — that number was already
//! taken by the LDSM enum pins of `bug421422_ldsm_enum_s16.rs`, hence 478 here; the
//! sparse-MLA prefill SASS on sm_120): the barrier
//! allocator `reallocate_barriers` walked program order LINEARLY when looking for
//! the consumers of a variable-latency producer (`raw_consumers`) and for the
//! overwriters of a late-latched memory operand (`war_overwriter`). Forward control
//! flow was ignored:
//!
//!  * after an unconditional forward `BRA join` the scan fell into the textually
//!    following code — the OTHER arm of an if/else diamond, dead on this path — and
//!    took its first matching instruction as the waiter;
//!  * a guarded forward branch `@P BRA arm2` did not fork the scan, so the taken
//!    arm's first consumer / overwriter never waited.
//!
//! Silicon symptom (sparse_mla_prefill_v41, GPU 4, rtx-pro-6000): the fp8 arm's last
//! `STS.128 [..], R8` carried read barrier SB1, the fp4 arm's SB0; the first
//! instruction after the join (`IADD3 R11, ...`) waited `B0----5` (derived from the
//! textually last arm) and clobbered R11 before the fp8 path's store had latched its
//! data -> nondeterministic wrong KV rows in ~1 % of the tokens (single chunk, 1 CTA/SM).
//! One explicit `[B012345]` wait at the join: 6/6 bit-identical. Fix: the scans follow
//! forward control flow (unconditional forward branch = continue at the target,
//! guarded forward branch = fork; first consumer / overwriter on EVERY path).

use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, schedule};
use cubit::table::IsaTable;
use cubit::Instruction;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn pipeline(src: &str) -> Vec<Instruction> {
    let f = parse_sass_file_str_strict(src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    let tab = t120();
    schedule(&mut insns, Some(&tab));
    reallocate_barriers(&mut insns, Some(&tab));
    insns
}

fn idx_of(insns: &[Instruction], op_full: &str, nth: usize) -> usize {
    insns
        .iter()
        .enumerate()
        .filter(|(_, x)| x.opcode_full == op_full)
        .nth(nth)
        .map(|(i, _)| i)
        .unwrap_or_else(|| panic!("no {op_full} #{nth}"))
}

fn waits(insns: &[Instruction], waiter: usize, bar: u8) -> bool {
    bar < 6 && (insns[waiter].ctrl.wait_mask >> bar) & 1 == 1
}

/// t478_1 (WAR across an if/else JOIN): arm 1 stores R4; arm 2 redefines R4 (dead on
/// the arm-1 path) and stores R5; the first instruction after the join overwrites R4
/// and must wait the arm-1 store's read barrier. Pre-fix the arm-1 store's only
/// waiter was arm 2's `MOV R4, 0x5`, so on the arm-1 path `MOV R4, RZ` clobbered the
/// store data before the STS latched it (the sparse-MLA fp8/fp4 dequant join).
#[test]
fn t478_1_war_read_barrier_survives_join() {
    let src = "\
.entry t
    .param u64 io
    ISETP.NE.AND P0, PT, R0, RZ, PT ;
    @P0 BRA arm2 ;
    MOV R4, 0x3 ;
    STS [R2], R4 ;
    BRA join ;
arm2:
    MOV R4, 0x5 ;
    MOV R5, 0x6 ;
    STS [R2+0x10], R5 ;
join:
    MOV R4, RZ ;
    MOV R5, RZ ;
    EXIT ;
";
    let insns = pipeline(src);
    let sts1 = idx_of(&insns, "STS", 0);
    let sts2 = idx_of(&insns, "STS", 1);
    let join_mov4 = idx_of(&insns, "MOV", 3); // MOV R4, RZ
    let join_mov5 = idx_of(&insns, "MOV", 4); // MOV R5, RZ
    let rb1 = insns[sts1].ctrl.read_bar;
    let rb2 = insns[sts2].ctrl.read_bar;
    assert!(rb1 < 6, "arm-1 STS must carry a read barrier (got R{rb1})");
    assert!(rb2 < 6, "arm-2 STS must carry a read barrier (got R{rb2})");
    assert!(
        waits(&insns, join_mov4, rb1),
        "join `MOV R4, RZ` must wait the arm-1 STS read barrier R{rb1} (wait_mask {:#04x})",
        insns[join_mov4].ctrl.wait_mask
    );
    assert!(
        waits(&insns, join_mov5, rb2),
        "join `MOV R5, RZ` must wait the arm-2 STS read barrier R{rb2} (wait_mask {:#04x})",
        insns[join_mov5].ctrl.wait_mask
    );
}

/// t478_2 (RAW across an if/else SPLIT): a load before `@P0 BRA arm2` is consumed
/// in BOTH arms; each arm's first consumer must wait the write barrier. Pre-fix only
/// the textually first consumer (arm 1) waited; arm 2 read the register file before
/// the load retired.
#[test]
fn t478_2_raw_write_barrier_reaches_both_arms() {
    let src = "\
.entry t
    .param u64 io
    LDG.E R4, desc[UR4][R2.64] ;
    @P0 BRA arm2 ;
    IADD3 R6, PT, PT, R4, 0x1, RZ ;
    BRA join ;
arm2:
    IADD3 R7, PT, PT, R4, 0x2, RZ ;
join:
    MOV R8, RZ ;
    EXIT ;
";
    let insns = pipeline(src);
    let ldg = idx_of(&insns, "LDG.E", 0);
    let c1 = idx_of(&insns, "IADD3", 0);
    let c2 = idx_of(&insns, "IADD3", 1);
    let wb = insns[ldg].ctrl.write_bar;
    assert!(wb < 6, "LDG must carry a write barrier (got W{wb})");
    assert!(waits(&insns, c1, wb), "arm-1 consumer must wait W{wb} (wait_mask {:#04x})", insns[c1].ctrl.wait_mask);
    assert!(waits(&insns, c2, wb), "arm-2 consumer must wait W{wb} (wait_mask {:#04x})", insns[c2].ctrl.wait_mask);
}

/// t478_3 (RAW across a JOIN after an unconditional branch): the consumer sits after
/// the join; arm 2 (textually between the load and the join) redefines the loaded
/// register on ITS path only. Pre-fix the linear scan saw arm 2's redefinition, dropped
/// R4 from the live set and left the join consumer WITHOUT a wait on the arm-1 path.
#[test]
fn t478_3_raw_join_consumer_waits_despite_other_arm_redefinition() {
    let src = "\
.entry t
    .param u64 io
    LDG.E R4, desc[UR4][R2.64] ;
    @P0 BRA arm2 ;
    MOV R6, 0x1 ;
    BRA join ;
arm2:
    MOV R4, 0x7 ;
join:
    IADD3 R8, PT, PT, R4, 0x1, RZ ;
    EXIT ;
";
    let insns = pipeline(src);
    let ldg = idx_of(&insns, "LDG.E", 0);
    let cons = idx_of(&insns, "IADD3", 0);
    let wb = insns[ldg].ctrl.write_bar;
    assert!(wb < 6, "LDG must carry a write barrier (got W{wb})");
    assert!(waits(&insns, cons, wb), "join consumer must wait W{wb} (wait_mask {:#04x})", insns[cons].ctrl.wait_mask);
}

/// t478_4 (regression guard): straight-line and loop shapes keep their waiters —
/// a loop-carried store-data WAR (the back-edge overwriter) and the fall-through
/// overwriter both still wait the store's read barrier.
#[test]
fn t478_4_loop_shape_unchanged() {
    let src = "\
.entry t
    .param u64 io
    MOV R4, 0x3 ;
    MOV R9, 0x4 ;
top:
    STS [R2], R4 ;
    IADD3 R4, PT, PT, R4, 0x1, RZ ;
    IADD3 R9, PT, PT, R9, -0x1, RZ ;
    ISETP.NE.AND P0, PT, R9, RZ, PT ;
    @P0 BRA top ;
    MOV R4, RZ ;
    EXIT ;
";
    let insns = pipeline(src);
    let sts = idx_of(&insns, "STS", 0);
    let bump = idx_of(&insns, "IADD3", 0);
    let rb = insns[sts].ctrl.read_bar;
    assert!(rb < 6, "STS must carry a read barrier (got R{rb})");
    assert!(waits(&insns, bump, rb), "in-loop overwriter must wait R{rb} (wait_mask {:#04x})", insns[bump].ctrl.wait_mask);
}

/// t478_5 (address latch released by the load's own RAW wait): the mask load's address
/// register R0 is overwritten only in the next iteration / after the loop, but the load's
/// unguarded data consumer (`ISETP ... R2`) sits right behind it. Past that consumer the
/// address has certainly been read (data cannot return before the address was consumed),
/// so NO read barrier / loop-carried WAR use is owed — pre-refinement every such load
/// reserved a scoreboard over the whole loop body (colouring starvation in the sparse-MLA
/// QK chain). With a GUARDED consumer the read barrier must still be waited.
#[test]
fn t478_5_load_rb_released_by_unguarded_raw_waiter() {
    let src_unguarded = "\
.entry t
    .param u64 io
    MOV R0, 0x100 ;
    MOV R9, 0x4 ;
top:
    LDS R2, [R0] ;
    ISETP.GE.AND P0, PT, R2, RZ, PT ;
    IADD3 R9, PT, PT, R9, -0x1, RZ ;
    ISETP.NE.AND P1, PT, R9, RZ, PT ;
    @P1 BRA top ;
    IADD3 R0, PT, PT, R0, 0x20, RZ ;
    EXIT ;
";
    let insns = pipeline(src_unguarded);
    let lds = idx_of(&insns, "LDS", 0);
    let bump = idx_of(&insns, "IADD3", 1); // IADD3 R0 after the loop
    assert_eq!(insns[lds].ctrl.read_bar, 7, "address latch covered by the RAW wait: no read barrier expected");
    assert_eq!(insns[bump].ctrl.wait_mask & 0x3f, 0, "post-loop bump owes no wait");

    let src_guarded = src_unguarded.replace("    ISETP.GE.AND P0, PT, R2, RZ, PT ;", "    @P2 ISETP.GE.AND P0, PT, R2, RZ, PT ;");
    let insns = pipeline(&src_guarded);
    let lds = idx_of(&insns, "LDS", 0);
    let bump = idx_of(&insns, "IADD3", 1);
    let rb = insns[lds].ctrl.read_bar;
    assert!(rb < 6, "guarded consumer: the load must keep a read barrier (got R{rb})");
    assert!(waits(&insns, bump, rb), "post-loop bump must wait R{rb} (wait_mask {:#04x})", insns[bump].ctrl.wait_mask);
}

/// t478_6 (T-5 maintainer refinement, 2026-11-05): a guarded forward jump OUT of a loop.
/// The load's consumer on the `@P3 BRA out` path sits at `out`, textually after the
/// fall-through exit code, which has its own (unguarded) consumer. The original scan
/// resumed every path that left the loop at `lback + 1`, found the fall-through consumer
/// first and stopped — the consumer at `out` never waited. Each exit path now resumes at
/// the index it actually reached.
#[test]
fn t478_6_forward_exit_from_loop_resumes_at_its_target() {
    let src = "\
.entry t
    .param u64 io
    MOV R9, 0x4 ;
top:
    LDG.E R4, desc[UR4][R2.64] ;
    @P3 BRA out ;
    IADD3 R9, PT, PT, R9, -0x1, RZ ;
    ISETP.NE.AND P0, PT, R9, RZ, PT ;
    @P0 BRA top ;
    IADD3 R6, PT, PT, R4, 0x1, RZ ;
    EXIT ;
out:
    IADD3 R7, PT, PT, R4, 0x2, RZ ;
    EXIT ;
";
    let insns = pipeline(src);
    let ldg = idx_of(&insns, "LDG.E", 0);
    let fall = idx_of(&insns, "IADD3", 1); // IADD3 R6 (fall-through exit)
    let out = idx_of(&insns, "IADD3", 2); // IADD3 R7 (jump exit)
    let wb = insns[ldg].ctrl.write_bar;
    assert!(wb < 6, "LDG must carry a write barrier (got W{wb})");
    assert!(waits(&insns, fall, wb), "fall-through exit consumer must wait W{wb} (wait_mask {:#04x})", insns[fall].ctrl.wait_mask);
    assert!(waits(&insns, out, wb), "jump-exit consumer at `out` must wait W{wb} (wait_mask {:#04x})", insns[out].ctrl.wait_mask);
}
