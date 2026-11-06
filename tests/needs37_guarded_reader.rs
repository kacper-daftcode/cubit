//! NEEDS_OWNER 37 — the `CUBIT_GUARDED_READER_SETTLES=1` experiment (T-11, 2026-11-06; default OFF =
//! today's rule, the decision is the owner's).
//!
//! The allocator collects the consumers of a load up to and INCLUDING the first UNGUARDED one on each
//! execution path: a guarded first reader may be skipped, so the reader behind it waits the write
//! barrier too. The ptxas evidence (NEEDS 37, 50 / 50 sites of the sm_120 census): a wait carried by a
//! predicated instruction is honoured whether or not its guard is true — the barrier is released at
//! the first reader either way, and the next unguarded reader of the same load behind `@P0 SHF … R10`
//! carries no wait of its own. With the switch the first reader settles the barrier guarded or not,
//! and a guarded waiter counts as the point after which the load has certainly issued (its address
//! registers released for the WAR pass). On the production set the switch changes nothing in the 89
//! MoE sources and removes 6 waits from V's `sparse_mla_prefill_v41` prologue (the guarded `VIMNMX`
//! readers of `LDG` / `LDC` results, BUG-485's neighbourhood) — `T/REPORT.md` part 11 §3.
//!
//! Pins: (1) default: the unguarded reader behind a guarded first reader waits the load's barrier;
//! (2) with the switch it does not (instruction words identical, the guarded reader still waits);
//! (3) the default rule is back once the variable is gone.

use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, schedule};
use cubit::table::IsaTable;
use cubit::Instruction;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

/// A load whose first reader is guarded (`@P0 VIMNMX`), followed by an unguarded reader.
const SRC: &str = ".entry guarded_first_reader
    .reg R0-R31
    .param u64 p0 offset=0x0
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R0, c[0x0][0x380] ;
    S2R R3, SR_TID.X ;
    ISETP.NE.U32.AND P0, PT, R3, RZ, PT ;
    LDG.E R2, desc[UR4][R0.64] ;
    @P0 VIMNMX.S32 R18, R2, RZ, !PT ;
    IADD3 R19, R2, 0x10, RZ ;
    STG.E desc[UR4][R0.64], R19 ;
    EXIT ;
";

fn pipeline(src: &str) -> Vec<Instruction> {
    let f = parse_sass_file_str_strict(src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    let tab = t120();
    schedule(&mut insns, Some(&tab));
    reallocate_barriers(&mut insns, Some(&tab));
    insns
}

fn at(insns: &[Instruction], opcode: &str) -> usize {
    insns.iter().position(|x| x.opcode == opcode).unwrap_or_else(|| panic!("an {opcode}"))
}

#[test]
fn needs37_switch_lets_the_guarded_first_reader_settle_the_barrier_and_is_off_by_default() {
    // --- default (today's rule): both readers of R2 wait the LDG's write barrier ---
    std::env::remove_var("CUBIT_GUARDED_READER_SETTLES");
    let on = pipeline(SRC);
    let (ldg, vimnmx, iadd3) = (at(&on, "LDG"), at(&on, "VIMNMX"), at(&on, "IADD3"));
    assert!(ldg < vimnmx && vimnmx < iadd3, "the order of the source is kept");
    let wb = on[ldg].ctrl.write_bar;
    assert!(wb < 6, "`{}` carries a write barrier", on[ldg].raw_text.trim());
    assert_eq!((on[vimnmx].ctrl.wait_mask >> wb) & 1, 1, "default: the guarded first reader waits W{wb}");
    assert_eq!((on[iadd3].ctrl.wait_mask >> wb) & 1, 1,
        "default: the unguarded reader behind it waits W{wb} too (wait_mask {:#04x})", on[iadd3].ctrl.wait_mask);

    // --- CUBIT_GUARDED_READER_SETTLES=1: the guarded reader settles the barrier ---
    std::env::set_var("CUBIT_GUARDED_READER_SETTLES", "1");
    let off = pipeline(SRC);
    std::env::remove_var("CUBIT_GUARDED_READER_SETTLES");
    assert_eq!(off.len(), on.len());
    for (a, b) in off.iter().zip(on.iter()) {
        assert_eq!(a.raw_text, b.raw_text, "the switch changes control codes only");
    }
    let wb = off[ldg].ctrl.write_bar;
    assert!(wb < 6);
    assert_eq!((off[vimnmx].ctrl.wait_mask >> wb) & 1, 1, "the guarded first reader still waits W{wb}");
    assert_eq!((off[iadd3].ctrl.wait_mask >> wb) & 1, 0,
        "with the switch the reader behind it carries no wait of its own (wait_mask {:#04x})", off[iadd3].ctrl.wait_mask);

    // the default rule is restored once the variable is gone
    let again = pipeline(SRC);
    let wb = again[ldg].ctrl.write_bar;
    assert_eq!((again[iadd3].ctrl.wait_mask >> wb) & 1, 1);
}
