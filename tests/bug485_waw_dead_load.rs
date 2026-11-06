//! BUG-485 (KNOWN_ISSUES A17 closing text / NEEDS_OWNER 34, owner's decision 2026-11-06: "a BUG item
//! with a test"): the barrier allocator had no WAW rule. `raw_consumers` collected the READERS of a
//! variable-latency producer's destinations as the waiters of its write barrier; an instruction that
//! OVERWROTE a still-live destination without reading it merely dropped the register from the live
//! set. A load whose result is never read before another instruction writes the same register (a
//! dead load — a loop prologue's speculative fetch, a predicated-off path's value, a register reused
//! after a dropped consumer) therefore got no write barrier at all, and the overwriter no wait: the
//! load's asynchronous writeback could land AFTER the overwriter's value and leave the dead result
//! in the register. Same-class loads of one address stream were covered by batching (issue-ordered,
//! one counting barrier); every other overwriter class — ALU ops, loads of another kind, loads of
//! another address stream — was not.
//!
//! Fix (`scheduling_pass.rs::raw_consumers`): an overwriter of a live destination is a waiter like a
//! reader (ptxas waits the producer's barrier on such overwriters too); an unguarded one ends the
//! scan on its path (the producer is complete past it), a guarded one does not. Pins below: the
//! dead-load shapes carry the barrier and the overwriter waits it; a reader-first shape is unchanged
//! (the first unguarded reader waits, the later overwriter needs nothing); the 97 production sources
//! re-assemble byte-identical in `.text` (checked outside the suite, `T/t8/moe/`).

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
fn assert_waits(insns: &[Instruction], prod: usize, cons: usize, what: &str) {
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

fn kernel(body: &str) -> String {
    format!(
        ".entry waw_probe\n    .reg R0-R31\n    .param ptr out\n    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n{body}    EXIT ;\n"
    )
}

/// A dead global load overwritten by an ALU op: before the fix `LDG` got `W-` and the `MOV` no wait.
#[test]
fn dead_load_overwritten_by_an_alu_op_waits_the_load() {
    let insns = pipeline(&kernel(
        "    LDG.E R4, desc[UR4][R2.64] ;\n    MOV R4, 0x1 ;\n    STG.E desc[UR4][R2.64+0x8], R4 ;\n",
    ));
    assert_waits(&insns, idx_of(&insns, "LDG", 0), idx_of(&insns, "MOV", 0), "WAW through an ALU overwrite");
}

/// A dead global load overwritten by a load of another class (shared memory): no batching covers
/// the pair, the `LDS` must wait the `LDG`.
#[test]
fn dead_load_overwritten_by_another_load_class_waits_the_load() {
    let insns = pipeline(&kernel(
        "    MOV R6, 0x40 ;\n    LDG.E R4, desc[UR4][R2.64] ;\n    LDS R4, [R6] ;\n    STG.E desc[UR4][R2.64+0x8], R4 ;\n",
    ));
    assert_waits(&insns, idx_of(&insns, "LDG", 0), idx_of(&insns, "LDS", 0), "WAW through another load class");
}

/// Two global loads into the same register from DIFFERENT address streams are not batched (the
/// completion order follows the cache outcome): the second must wait the first.
#[test]
fn same_class_loads_of_different_streams_into_one_register_are_ordered() {
    let insns = pipeline(&kernel(
        "    LDC.64 R6, c[0x0][0x388] ;\n    LDG.E R4, desc[UR4][R2.64] ;\n    LDG.E R4, desc[UR4][R6.64] ;\n    STG.E desc[UR4][R2.64+0x8], R4 ;\n",
    ));
    let a = idx_of(&insns, "LDG", 0);
    let b = idx_of(&insns, "LDG", 1);
    assert_waits(&insns, a, b, "WAW between two address streams");
    // the second load's own barrier is waited by the store (RAW), as before
    assert_waits(&insns, b, idx_of(&insns, "STG", 0), "RAW of the live load");
}

/// A load that IS read first keeps the pre-fix schedule: the reader waits, the overwriter after it
/// needs nothing (the scan ends at the first unguarded reader on the path).
#[test]
fn a_read_load_schedules_as_before() {
    let insns = pipeline(&kernel(
        "    LDG.E R4, desc[UR4][R2.64] ;\n    IADD3 R5, R4, R2, RZ ;\n    MOV R4, 0x1 ;\n    STG.E desc[UR4][R2.64+0x8], R5 ;\n",
    ));
    let ldg = idx_of(&insns, "LDG", 0);
    assert_waits(&insns, ldg, idx_of(&insns, "IADD3", 0), "RAW");
    let wb = insns[ldg].ctrl.write_bar;
    let mov = idx_of(&insns, "MOV", 0);
    assert_eq!((insns[mov].ctrl.wait_mask >> wb) & 1, 0, "the overwriter behind the reader does not wait again");
}

/// A guarded overwriter waits (its wait is honoured whether or not the guard is true — ptxas relies
/// on that: in the sm_120 census, 50 / 50 unguarded readers behind a guarded waiter of a load carry no
/// wait of their own), and the scan continues past it like past a guarded reader.
#[test]
fn a_guarded_overwriter_waits_the_load() {
    let insns = pipeline(&kernel(
        "    ISETP.NE.AND P0, PT, R2, RZ, PT ;\n    LDG.E R4, desc[UR4][R2.64] ;\n    @P0 MOV R4, 0x1 ;\n    STG.E desc[UR4][R2.64+0x8], R4 ;\n",
    ));
    assert_waits(&insns, idx_of(&insns, "LDG", 0), idx_of(&insns, "MOV", 0), "guarded WAW overwriter");
}
