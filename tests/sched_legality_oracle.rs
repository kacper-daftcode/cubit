//! The scheduling-legality oracle of KNOWN_ISSUES A4 / docs/SCHED_LEGALITY_ORACLE.md,
//! core properties as a test (R order C11, 2026-11-06).
//!
//! The full oracle is `tools/sched_oracle.py` (drives this same verifier over the
//! census corpus via `CUBIT_VERIFY=1 cubit asm`); this test pins the three
//! load-bearing properties in-tree so they cannot regress with the tool absent:
//!
//!   P1  a frozen nvcc-style schedule verifies clean (0 findings);
//!   P2a the `ebbd1dc` class, wait-stripped variant (the store carries its read
//!       barrier; the overwriter of the store's address pair does NOT wait it)
//!       is REJECTED as a broken WAR;
//!   P2b the pure 2026-06 shape (the read barrier was never set at all --
//!       invisible to the verifier by construction) is caught by the oracle's
//!       rb-coverage probe: inject a read barrier into the bare store, re-run
//!       the same read-only verifier, and the race fires.
//!
//! Fixtures under tests/fixtures/sched/ are frozen nvcc kernels of the publish
//! corpus (one sm103a, one sm100a): the oracle must accept them (P1 at scale
//! is the tool's corpus run; these keep a permanent in-tree sample).

use cubit::ir::Operand;
use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::verify_scoreboard_report;
use cubit::table::IsaTable;

fn table(name: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{name}.json"))).unwrap()
}

fn kernel_insns(src: &str) -> Vec<cubit::ir::Instruction> {
    let f = parse_sass_file_str_strict(src).unwrap();
    assert_eq!(f.kernels.len(), 1, "expected exactly one kernel in the repro");
    f.kernels[0].instructions.clone()
}

const HEADER: &str = ".entry war_repro\n    .reg R0-R15\n    .param ptr p0 offset=0x0\n";
const TAIL: &str = "    .endentry\n";

fn repro(store_rb: &str, writer_wait: &str) -> String {
    format!(
        "{HEADER}\
         \x20   [B------:R-:W-:Y:S01] LDCU.64 UR4, c[0x0][0x358] ;\n\
         \x20   [B------:R-:W-:Y:S01] LDC.64 R2, c[0x0][0x380] ;\n\
         \x20   [B------:R-:W-:Y:S01] LDC.64 R4, c[0x0][0x388] ;\n\
         \x20   [B0-----:R-:W-:Y:S01] LDG.E.64 R8, desc[UR4][R4.64] ;\n\
         \x20   [B------:R{store_rb}:W-:Y:S01] STG.E.64 desc[UR4][R2.64], R8 ;\n\
         \x20   [{writer_wait}:R-:W-:Y:S01] IADD3 R2, R2, RZ, 0x10 ;\n\
         \x20   [B------:R-:W-:Y:S01] EXIT ;\n{TAIL}"
    )
}

/// P1: the protected schedule (store rb set, the address overwriter waits it)
/// is clean, on all three counters.
#[test]
fn a4_oracle_p1_clean_frozen_schedule_accepted() {
    let t = table("sm103a");
    let insns = kernel_insns(&repro("0", "B0-----"));
    let rep = verify_scoreboard_report(&insns, Some(&t));
    assert_eq!((rep.raw, rep.war, rep.recycle), (0, 0, 0),
        "the clean schedule must verify clean");
}

/// P2a: the wait-stripped `ebbd1dc` variant is a broken WAR.
#[test]
fn a4_oracle_p2a_wait_stripped_war_rejected() {
    let t = table("sm103a");
    let insns = kernel_insns(&repro("0", "B------"));
    let rep = verify_scoreboard_report(&insns, Some(&t));
    assert_eq!(rep.raw, 0);
    assert!(rep.war >= 1, "the missing wait on the store's read barrier \
        must fire at least one BROKEN WAR (got {})", rep.war);
}

/// P2b: the historical shape -- the read barrier was never set, so the race is
/// invisible to the bare verifier. The oracle's rb-coverage probe (see
/// tools/sched_oracle.py) injects a free barrier index into the bare store and
/// re-runs the same read-only verifier; the race must now fire. Barrier 1 is
/// free in this kernel (nothing arms or waits it).
#[test]
fn a4_oracle_p2b_rb_missing_caught_by_the_probe() {
    let t = table("sm103a");
    let src = repro("-", "B------");
    let insns = kernel_insns(&src);

    // bare schedule: the verifier is blind to the never-set read barrier ...
    let bare = verify_scoreboard_report(&insns, Some(&t));
    assert_eq!((bare.raw, bare.war, bare.recycle), (0, 0, 0),
        "a never-set read barrier is invisible by construction (that is the bug)");

    // ... the probe makes it visible: inject rb=1 into the STG, re-verify.
    let mut probed = insns.clone();
    let mut injected = 0;
    for ins in probed.iter_mut() {
        if ins.opcode == "STG" && ins.ctrl.read_bar == 7 {
            ins.ctrl.read_bar = 1;
            injected += 1;
        }
    }
    assert_eq!(injected, 1, "expected exactly one bare global store to probe");
    let rep = verify_scoreboard_report(&probed, Some(&t));
    assert!(rep.war >= 1, "the injected read barrier must expose the \
        store-address race (got war={})", rep.war);
}

/// The probe must not invent hazards on a protected schedule: injecting an rb
/// where the overwriter already waits it changes nothing.
#[test]
fn a4_oracle_probe_no_false_positive_on_protected_store() {
    let t = table("sm103a");
    let mut insns = kernel_insns(&repro("0", "B0-----"));
    // keep the protection, just re-colour the barrier to a free index (0 -> 1)
    let stg_idx = insns.iter().position(|x| x.opcode == "STG").expect("store");
    insns[stg_idx].ctrl.read_bar = 1;
    for w in insns.iter_mut() {
        if w.ctrl.wait_mask & 1 != 0 {
            w.ctrl.wait_mask = (w.ctrl.wait_mask & !1) | (1 << 1);
        }
    }
    let rep = verify_scoreboard_report(&insns, Some(&t));
    assert_eq!((rep.raw, rep.war, rep.recycle), (0, 0, 0),
        "re-coloured but complete protection must stay clean");
}

/// P1 fixtures: frozen nvcc kernels of the publish corpus (sm103a + sm100a)
/// are accepted by the oracle.
#[test]
fn a4_oracle_p1_corpus_fixtures_accepted() {
    for (fixture, table_name) in [
        ("tests/fixtures/sched/alloc_c1_n128.sm103a.frozen.sass", "sm103a"),
        ("tests/fixtures/sched/alloc_c1_n128.sm100a.frozen.sass", "sm100a"),
    ] {
        let t = table(table_name);
        let src = std::fs::read_to_string(fixture)
            .unwrap_or_else(|e| panic!("cannot read {fixture}: {e}"));
        let f = parse_sass_file_str_strict(&src)
            .unwrap_or_else(|e| panic!("cannot parse {fixture}: {e}"));
        assert!(!f.kernels.is_empty());
        for k in &f.kernels {
            assert!(k.instructions.iter().all(|x| x.hand_sched),
                "{fixture}: expected a fully frozen (hand-scheduled) kernel");
            let rep = verify_scoreboard_report(&k.instructions, Some(&t));
            assert_eq!(
                (rep.raw, rep.war, rep.recycle),
                (0, 0, 0),
                "{fixture} / {}: the frozen nvcc schedule must verify clean",
                k.name
            );
        }
    }
}

/// The repro's shape sanity: the store really carries a memory address operand
/// whose base register the writer overwrites (guards the fixture itself).
#[test]
fn a4_oracle_repro_shape_is_a_real_address_war() {
    let insns = kernel_insns(&repro("0", "B0-----"));
    let stg = insns.iter().find(|x| x.opcode == "STG").expect("store");
    let has_r2 = stg.operands.iter().any(|o| matches!(o, Operand::Addr { base_reg: Some(2), .. }
        | Operand::Desc { base_reg: Some(2), .. }));
    assert!(has_r2, "the store must address through R2");
    let writer = insns.iter().find(|x| x.opcode == "IADD3").expect("writer");
    let writes_r2 = matches!(writer.operands.first(),
        Some(Operand::Reg { num: 2, .. }));
    assert!(writes_r2, "the writer must overwrite R2 (the address pair base)");
}
