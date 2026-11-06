//! BUG-482 (KNOWN_ISSUES A17, found 2026-11-05 by the NEEDS 28 silicon probe; fixed 2026-11-06):
//! the scheduler took operand 0 as the destination of every instruction, so the atomics with
//! a predicate destination first — nvcc's shape `ATOMG.E.ADD.STRONG.GPU PT, R6, desc[UR4][R2.64],
//! R7` and every `ATOM* Pd, Rd, …` form — had no register destination at all: `Rd` had no
//! producer, the write barrier the long-latency class requests was dropped as waiter-less, and
//! a consumer of `Rd` read the register before the atomic returned. On silicon (test host GPU 0,
//! RTX PRO 6000 Server Edition, `T/gpu/kernels/atomg_{desc_ctl,el_plain,el_pair}.sass`) the
//! auto-scheduled kernels stored old values `0xac0799b5` / `0x9d0c99b5` / `0x8d059935` instead of
//! `0x100`; with a hand-written `W2` on the ATOMG and `B--2---` on the STG the values were right.
//! `Rd` was also counted as a *source* (false RAW), a reduction's address (operand 0 of
//! `RED/REDG [addr], Rb`) was not a source at all, and `.64` data operands were single registers.
//!
//! Fix (`scheduling_pass.rs`: `atom_rd_index`, `atom_access_regs`, `is_reduction`): on `ATOM` /
//! `ATOMG` / `ATOMS` the first REGISTER operand is the destination (operand 1 behind a `Pd`),
//! spanning the access width; a real `Pn` destination is a result too; sources start after
//! `Rd`; `RED`/`REDG` sources start at operand 0; `Rb`/`Rc` span the access width. Mirrors the
//! "atom" role class of `reg_liveness.rs`. Pins: the probe shape carries the barrier and the
//! consumer waits it; the `Pd, Rd` shape schedules exactly like the plain `Rd` shape of `ATOMS`
//! and like an `LDG` into the same register; production sources (no atomics) are untouched.

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

fn ctrl_of(insns: &[Instruction]) -> Vec<(u8, u8, u8, u8, bool)> {
    insns
        .iter()
        .map(|x| (x.ctrl.write_bar, x.ctrl.read_bar, x.ctrl.wait_mask, x.ctrl.stall, x.ctrl.yield_flag))
        .collect()
}

fn idx_of(insns: &[Instruction], op: &str, nth: usize) -> usize {
    insns
        .iter()
        .enumerate()
        .filter(|(_, x)| x.opcode == op)
        .nth(nth)
        .map(|(i, _)| i)
        .unwrap_or_else(|| panic!("no {op} #{nth}"))
}

/// The producer at `prod` must carry a write barrier and the instruction at `cons` must wait it.
fn assert_raw(insns: &[Instruction], prod: usize, cons: usize, what: &str) {
    let wb = insns[prod].ctrl.write_bar;
    assert!(wb < 6, "{what}: `{}` must carry a write barrier (got W{wb})", insns[prod].raw_text.trim());
    assert!(
        (insns[cons].ctrl.wait_mask >> wb) & 1 == 1,
        "{what}: `{}` must wait W{wb} of `{}` (wait_mask {:#04x})",
        insns[cons].raw_text.trim(),
        insns[prod].raw_text.trim(),
        insns[cons].ctrl.wait_mask
    );
}

/// The NEEDS 28 probe shape (`T/gpu/kernels/atomg_desc_ctl.sass` without its hand-written
/// control codes): the old value returned by the ATOMG is stored by the next instruction.
const PROBE: &str = "\
.entry atomg_old_value
    .reg R0-R15
    .param ptr out
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    MOV R7, 0x5 ;
    ATOMG.E.ADD.STRONG.GPU PT, R6, desc[UR4][R2.64], R7 ;
    STG.E desc[UR4][R2.64+0x8], R6 ;
    MOV R8, 0xc0dec0de ;
    STG.E desc[UR4][R2.64+0xc], R8 ;
    EXIT ;
";

#[test]
fn t482_1_probe_shape_rd_consumer_waits_the_atomic() {
    let insns = pipeline(PROBE);
    let atom = idx_of(&insns, "ATOMG", 0);
    let stg = idx_of(&insns, "STG", 0);
    assert_raw(&insns, atom, stg, "ATOMG PT, R6 -> STG R6");
    // The unrelated second store must not wait the atomic's barrier.
    let stg2 = idx_of(&insns, "STG", 1);
    let wb = insns[atom].ctrl.write_bar;
    assert!(
        (insns[stg2].ctrl.wait_mask >> wb) & 1 == 0 || insns[stg2].ctrl.wait_mask == insns[stg].ctrl.wait_mask,
        "the store of R8 does not read R6"
    );
}

/// The `.EL` plain form (`[Rn.U32+URm]`) and the `.EL` descriptor pair (BUG-041 lifted) are the
/// same shape for the scheduler: `Pd, Rd, addr, Rb`.
#[test]
fn t482_2_el_forms_carry_the_barrier_too() {
    for text in [
        "ATOMG.E.ADD.EL.STRONG.GPU PT, R6, [R4.U32+UR6], R7 ;",
        "ATOM.E.ADD.STRONG.GPU PT, R6, [R2.64], R7 ;",
        "ATOMG.E.EXCH.STRONG.GPU PT, R6, desc[UR4][R2.64], R7 ;",
    ] {
        let src = PROBE.replace("ATOMG.E.ADD.STRONG.GPU PT, R6, desc[UR4][R2.64], R7 ;", text);
        let insns = pipeline(&src);
        let atom = insns.iter().position(|x| x.opcode.starts_with("ATOM")).expect("atomic");
        let stg = idx_of(&insns, "STG", 0);
        assert_raw(&insns, atom, stg, text);
    }
}

/// A 64-bit atomic returns a pair: the consumer of the HIGH half (`Rd+1`) waits the barrier.
#[test]
fn t482_3_dot64_returns_a_pair() {
    let src = "\
.entry atomg64
    .reg R0-R15
    .param ptr out
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    MOV R8, 0x5 ;
    MOV R9, 0x0 ;
    ATOMG.E.ADD.64.STRONG.GPU PT, R6, desc[UR4][R2.64], R8 ;
    STG.E desc[UR4][R2.64+0xc], R7 ;
    EXIT ;
";
    let insns = pipeline(src);
    let atom = idx_of(&insns, "ATOMG", 0);
    let stg = idx_of(&insns, "STG", 0);
    assert_raw(&insns, atom, stg, "ATOMG.64 PT, R6 -> STG R7 (high half)");
}

/// The `Pd, Rd` shape schedules like the plain `Rd` shape (`ATOMS Rd, [addr], Rb`) and like a
/// load into the same register: identical control codes on the consumer side.
#[test]
fn t482_4_pd_rd_shape_schedules_like_the_plain_shape() {
    let pd = "\
.entry a
    .reg R0-R15
    .param ptr out
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    MOV R7, 0x5 ;
    ATOMS.ADD PT, R6, [R2], R7 ;
    STG.E desc[UR4][R2.64+0x8], R6 ;
    EXIT ;
";
    let plain = pd.replace("ATOMS.ADD PT, R6, [R2], R7 ;", "ATOMS.ADD R6, [R2], R7 ;");
    let a = pipeline(pd);
    let b = pipeline(&plain);
    assert_eq!(ctrl_of(&a), ctrl_of(&b), "`ATOMS PT, R6` must schedule exactly like `ATOMS R6`");
    let atom = idx_of(&a, "ATOMS", 0);
    let stg = idx_of(&a, "STG", 0);
    assert_raw(&a, atom, stg, "ATOMS PT, R6 -> STG R6");
}

/// A reduction's address registers ARE sources: a `RED` whose address pair comes from a load
/// must wait that load's barrier, exactly like the `STG` twin (pre-fix the generic skip-1 rule
/// dropped operand 0 — the address — of `RED`/`REDG`, so the reduction did not wait).
#[test]
fn t482_5_red_address_is_a_source() {
    let red = "\
.entry r
    .reg R0-R15
    .param ptr out
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    MOV R7, 0x5 ;
    LDG.E.64 R4, desc[UR4][R2.64] ;
    RED.E.ADD.STRONG.GPU desc[UR4][R4.64], R7 ;
    EXIT ;
";
    let stg = red.replace("RED.E.ADD.STRONG.GPU desc[UR4][R4.64], R7 ;", "STG.E desc[UR4][R4.64], R7 ;");
    let a = pipeline(red);
    let b = pipeline(&stg);
    let ldg = idx_of(&a, "LDG", 0);
    let r = idx_of(&a, "RED", 0);
    assert_raw(&a, ldg, r, "LDG.E.64 R4 -> RED desc[UR4][R4.64]");
    let s = idx_of(&b, "STG", 0);
    assert_eq!(a[r].ctrl.wait_mask, b[s].ctrl.wait_mask, "RED waits the address load like its STG twin");
}

/// WAR on the DATA of an atomic: ptxas tags `ATOMS.MAX.S32 RZ, [R157+UR7+0x15100], R58` with a
/// read barrier (sparse-MLA census kernels, 1 248 sites) because the data register is latched
/// after issue like a store's; an overwriter of `Rb` must wait that read barrier. Pre-fix cubit
/// protected only the address registers of the family. The `STG` twin pins the same mechanism.
#[test]
fn t482_7_data_war_read_barrier() {
    let src = "\
.entry w
    .reg R0-R15
    .param ptr out
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    MOV R7, 0x5 ;
    ATOMS.MAX.S32 RZ, [R2+0x100], R7 ;
    MOV R7, 0x9 ;
    STG.E desc[UR4][R2.64+0x8], R7 ;
    EXIT ;
";
    let insns = pipeline(src);
    let atom = idx_of(&insns, "ATOMS", 0);
    let ow = idx_of(&insns, "MOV", 1);
    let rb = insns[atom].ctrl.read_bar;
    assert!(rb < 6, "ATOMS RZ, [..], R7 must carry a read barrier for its data (got R{rb})");
    assert!(
        (insns[ow].ctrl.wait_mask >> rb) & 1 == 1,
        "the overwriter of R7 must wait R{rb} (wait_mask {:#04x})",
        insns[ow].ctrl.wait_mask
    );
    // `RZ` is not a destination: no write barrier is requested for the no-return form.
    assert_eq!(insns[atom].ctrl.write_bar, 7, "ATOMS … RZ has no register result");
    let twin = pipeline(&src.replace("ATOMS.MAX.S32 RZ, [R2+0x100], R7 ;", "STG.E desc[UR4][R2.64], R7 ;"));
    let stg = idx_of(&twin, "STG", 0);
    assert_eq!(twin[stg].ctrl.read_bar, rb, "the STG twin uses the same read barrier");
}

/// The production MoE sources carry no atomics; a kernel without atomics must schedule exactly as
/// before the fix — pinned on a representative load/ALU/store shape (the BUG-480 RAW twin).
#[test]
fn t482_6_non_atomic_kernels_unchanged() {
    let src = "\
.entry t
    .reg R0-R31
    .param u64 io
    LDG.E.64 R8, desc[UR4][R2.64] ;
    IADD3 R6, PT, PT, R8, 0x1, RZ ;
    IADD3 R7, PT, PT, R9, 0x1, RZ ;
    STG.E.64 desc[UR4][R4.64], R6 ;
    EXIT ;
";
    let insns = pipeline(src);
    let ldg = idx_of(&insns, "LDG", 0);
    let cons = idx_of(&insns, "IADD3", 0);
    assert_raw(&insns, ldg, cons, "LDG.E.64 R8 -> IADD3 R8");
    assert_eq!(insns[ldg].ctrl.write_bar, 0, "the first load takes barrier 0 as before");
}
