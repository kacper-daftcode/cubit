//! BUG-347 (F2 queue 347-kand LOW, registered F2-iter172 in the BUG-342
//! report): `verify_scoreboard` (the CUBIT_VERIFY-gated read-only checker)
//! simulated the scoreboard as ONE linear pass and was blind to the
//! loop-carried (wrap) class in BOTH directions — a loop-head consumer of a
//! body-tail producer is checked textually BEFORE the producer is ever
//! armed (BUG-342's allocator class passed it silently), and state armed
//! inside the body was never re-checked against the head of the next
//! iteration. Control-flow edges with statically unresolvable targets
//! (register-indirect BRA/BRX/BRXU/JMP, target outside the kernel) bound
//! loops the checker could not even walk — previously skipped silently.
//!
//! Fix (tables/suite untouched, engine-verify only): the walk is loop-aware.
//! After the classic pass it re-runs every RESOLVED loop body once from the
//! end-of-body snapshot (innermost first, `resolved_back_edges` — the same
//! loop view BUG-342 gave the allocator), deduping against first-pass keys;
//! genuinely-new violations join the classic counters as "(loop-carried
//! wrap)". Unresolvable edges are counted loudly (`CUBIT_VERIFY_LOOP`).
//! The public surface gains `verify_scoreboard_report` (no printing) so the
//! behaviour is machine-checkable here.
//!
//! Flow: parse -> schedule() -> reallocate_barriers() (the production path,
//! bug117/342 idiom), optional ctrl corruption to emulate a misallocation,
//! then verify_scoreboard_report() assertions.

use cubit::ir::Operand;
use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, schedule, verify_scoreboard_report};
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

/// BUG-342 SINGLE shape: single loop, tail LDG.E.128 R20-R23 consumed by the
/// head IMAD. The (post-342) allocator arms a wrap-protected barrier.
const SINGLE: &str = ".entry t
    .param u64 io
    LDC R6, c[0x0][0x28] ;
    LDG.E.128 R20, [R2.64] ;
LOOP_TOP:
    IMAD R24, R20, R21, R24 ;
    IADD3 R2, PT, PT, R2, 0x400, RZ ;
    LDG.E.128 R20, [R2.64] ;
    ISETP.GT.AND P0, PT, R6, 0x100, PT ;
    @P0 BRA LOOP_TOP ;
    EXIT ;
";

/// Nested variant (342 HOLE): inner-loop LDG consumed at the outer head.
const HOLE: &str = ".entry t
    .param u64 io
    LDC R6, c[0x0][0x28] ;
    S2R R8, SR_TID.X ;
    MOV R24, RZ ;
    LDG.E.128 R20, [R2.64] ;
    MOV R10, RZ ;
OUTER_TOP:
    IMAD R24, R20, R21, R24 ;
    IMAD R25, R22, R23, RZ ;
    IADD3 R24, PT, PT, R24, R25, RZ ;
    IADD3 R10, PT, PT, R10, 0x1, RZ ;
    ISETP.GT.AND P1, PT, R10, 0x8, PT ;
INNER_TOP:
    LDG.E.128 R20, [R2.64] ;
    IADD3 R6, PT, PT, R6, 0x1, RZ ;
    ISETP.GT.AND P0, PT, R6, 0x100, PT ;
    @P0 BRA INNER_TOP ;
    @P1 BRA OUTER_TOP ;
    EXIT ;
";

/// WAR variant (342 WAR_NESTED): outer-head pointer bump overwrites the
/// inner-loop load address.
const WAR_NESTED: &str = ".entry t
    .param u64 io
    LDC R6, c[0x0][0x28] ;
    MOV R10, RZ ;
OUTER_TOP:
    IADD3 R2, PT, PT, R2, 0x400, RZ ;
    IADD3 R10, PT, PT, R10, 0x1, RZ ;
    ISETP.GT.AND P1, PT, R10, 0x4, PT ;
INNER_TOP:
    LDG.E.128 R20, [R2.64] ;
    IMAD R24, R20, R21, RZ ;
    IADD3 R6, PT, PT, R6, 0x1, RZ ;
    ISETP.GT.AND P0, PT, R6, 0x100, PT ;
    @P0 BRA INNER_TOP ;
    @P1 BRA OUTER_TOP ;
    EXIT ;
";

fn pipeline(src: &str, tab: &IsaTable) -> Vec<cubit::ir::Instruction> {
    let f = parse_sass_file_str_strict(src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    schedule(&mut insns, Some(tab));
    reallocate_barriers(&mut insns, Some(tab));
    insns
}

fn find_pattern(insns: &[cubit::ir::Instruction], pat: &str, from: usize) -> usize {
    (from..insns.len())
        .find(|&i| format!("{} {:?}", insns[i].opcode_full, insns[i].operands).contains(pat))
        .unwrap_or_else(|| panic!("pattern {pat:?} not found from {from}"))
}

/// t347_1: THE CATCH. Allocator-good SINGLE output verifies clean; corrupt
/// the loop-head consumer by dropping the tail producer's barrier from its
/// wait mask (exactly BUG-342's misallocation shape) and the loop-aware
/// verifier must report it — as a wrap finding (the pre-347 single pass
/// structurally CANNOT see this class).
#[test]
fn t347_1_wrap_raw_caught() {
    for tab in [t120(), t103()] {
        let good = pipeline(SINGLE, &tab);
        let clean = verify_scoreboard_report(&good, Some(&tab));
        assert_eq!(
            (clean.raw, clean.war, clean.recycle, clean.unresolved_edges),
            (0, 0, 0, 0),
            "allocator-good SINGLE must verify clean"
        );
        let pro = find_pattern(&good, "LDG.E.128", 0);
        let cons = find_pattern(&good, "IMAD", pro + 1);
        let tail = find_pattern(&good, "LDG.E.128", pro + 1);
        assert!(cons < tail, "shape drift");
        let wb = good[tail].ctrl.write_bar;
        assert_ne!(wb, 7);
        assert_ne!(
            good[cons].ctrl.wait_mask & (1 << wb),
            0,
            "precondition: wrap wait armed"
        );
        let mut bad = good.clone();
        bad[cons].ctrl.wait_mask &= !(1 << wb);
        let rep = verify_scoreboard_report(&bad, Some(&tab));
        assert!(
            rep.raw >= 1,
            "dropped wrap wait must be caught as unprotected RAW"
        );
        assert_eq!(
            rep.wrap_raw, rep.raw,
            "finding must be visible ONLY via the wrap re-walk (wrap_raw == raw)"
        );
        assert_eq!((rep.war, rep.recycle, rep.unresolved_edges), (0, 0, 0));
    }
}

/// t347_2: NO FALSE POSITIVES on the nested wrap shape — the loop-aware
/// verifier must stay silent on allocator-good output (innermost-first
/// re-walks of BOTH enclosing loops included).
#[test]
fn t347_2_nested_good_shape_stays_silent() {
    for tab in [t120(), t103()] {
        let insns = pipeline(HOLE, &tab);
        let rep = verify_scoreboard_report(&insns, Some(&tab));
        assert_eq!(
            rep,
            Default::default(),
            "allocator-good nested-wrap output must not produce any finding"
        );
    }
}

/// t347_3: the fail-LOUD linter. (a) A register-indirect branch bounds loops
/// the wrap pass cannot walk: `BRXU.U UR30, imm` must count as an unresolved
/// edge. (b) A resolved BRA mutated to target an address outside the kernel
/// (addr-less) must count too. Both were previously skipped in silence.
#[test]
fn t347_3_unresolvable_edges_are_loud() {
    for tab in [t120(), t103()] {
        // (a) register-indirect BRXU.U: pure-ALU body so no classic findings.
        let src = ".entry t\n    .param u64 io\n    LDC R6, c[0x0][0x28] ;\n    IADD3 R10, PT, PT, R10, 0x1, RZ ;\n    BRXU.U UR30, -0x1 ;\n    EXIT ;\n";
        let f = parse_sass_file_str_strict(src).unwrap();
        let insns = f.kernels[0].instructions.clone();
        assert!(
            insns.iter().any(|x| x.opcode == "BRXU"),
            "BRXU.U must parse"
        );
        let rep = verify_scoreboard_report(&insns, Some(&tab));
        assert!(
            rep.unresolved_edges >= 1,
            "register-indirect BRXU.U must be counted as unresolvable"
        );
        assert_eq!((rep.raw, rep.war, rep.recycle), (0, 0, 0));

        // (b) backward BRA forced addr-less: mutate the resolved target to an
        // address not present in the kernel.
        let mut insns = pipeline(SINGLE, &tab);
        let bra = insns
            .iter()
            .position(|x| x.opcode == "BRA")
            .expect("SINGLE must contain BRA");
        let mut patched = false;
        for op in insns[bra].operands.iter_mut() {
            if let Operand::BranchTarget(t) = op {
                *t = 0x9990;
                patched = true;
            }
        }
        assert!(patched, "BRA must carry a BranchTarget");
        let rep = verify_scoreboard_report(&insns, Some(&tab));
        assert!(
            rep.unresolved_edges >= 1,
            "an addr-less branch target must be counted as unresolvable"
        );
    }
}

/// t347_4: wrap-WAR catch. Allocator-good WAR_NESTED verifies clean; drop the
/// read-barrier wait from the outer-head pointer bump and the verifier must
/// catch the loop-carried broken-rb against the INNER-loop load — again only
/// via the wrap re-walk. Stalls are zeroed post-pipeline so the issue-distance
/// coverage heuristic cannot mask the missing wait.
#[test]
fn t347_4_wrap_war_caught() {
    for tab in [t120(), t103()] {
        let good = pipeline(WAR_NESTED, &tab);
        let clean = verify_scoreboard_report(&good, Some(&tab));
        assert_eq!(
            (clean.raw, clean.war, clean.recycle, clean.unresolved_edges),
            (0, 0, 0, 0),
            "allocator-good WAR_NESTED must verify clean"
        );
        let bump = (0..good.len())
            .find(|&i| {
                format!("{} {:?}", good[i].opcode_full, good[i].operands).contains("IADD3")
                    && format!("{:?}", good[i].operands).contains("Imm32(1024)")
                    && format!("{:?}", good[i].operands).contains("num: 2")
            })
            .expect("outer-head R2 bump not found");
        let ldg = find_pattern(&good, "LDG.E.128", 0);
        assert!(ldg > bump, "shape drift");
        let rb = good[ldg].ctrl.read_bar;
        assert_ne!(rb, 7);
        assert_ne!(
            good[bump].ctrl.wait_mask & (1 << rb),
            0,
            "precondition: WAR wait armed"
        );
        let mut bad = good.clone();
        bad[bump].ctrl.wait_mask &= !(1 << rb);
        for x in bad.iter_mut() {
            x.ctrl.stall = 0;
        }
        let rep = verify_scoreboard_report(&bad, Some(&tab));
        assert!(
            rep.war >= 1,
            "dropped wrap rb wait must be caught as broken WAR"
        );
        assert_eq!(
            rep.wrap_war, rep.war,
            "finding must be visible ONLY via the wrap re-walk"
        );
        assert_eq!((rep.raw, rep.recycle, rep.unresolved_edges), (0, 0, 0));
    }
}

/// t347_5: classic (linear) detection RETAINED and no new noise on
/// straight-line code. Allocator-good straight-line verifies clean; a
/// same-iteration wait-drop is caught in the FIRST pass (not as a wrap
/// finding). Encoder sanity: the corrupted stream still encodes (ctrl is
/// textually legal), matching the 342 pin idiom.
#[test]
fn t347_5_straight_line_classic_detection_retained() {
    use cubit::encoder::encode_instruction;
    const STRAIGHT: &str = ".entry t
    .param u64 io
    LDC R6, c[0x0][0x28] ;
    LDG.E.128 R20, [R2.64] ;
    IMAD R24, R20, R21, R24 ;
    IADD3 R2, PT, PT, R2, 0x400, RZ ;
    EXIT ;
";
    for tab in [t120(), t103()] {
        let good = pipeline(STRAIGHT, &tab);
        let clean = verify_scoreboard_report(&good, Some(&tab));
        assert_eq!(
            clean,
            Default::default(),
            "straight-line good must be silent"
        );
        let ldg = find_pattern(&good, "LDG.E.128", 0);
        let cons = find_pattern(&good, "IMAD", ldg + 1);
        let wb = good[ldg].ctrl.write_bar;
        assert_ne!(wb, 7);
        assert_ne!(good[cons].ctrl.wait_mask & (1 << wb), 0);
        let mut bad = good.clone();
        bad[cons].ctrl.wait_mask &= !(1 << wb);
        let rep = verify_scoreboard_report(&bad, Some(&tab));
        assert!(rep.raw >= 1, "same-iteration wait drop must be caught");
        assert_eq!(
            (rep.wrap_raw, rep.wrap_war, rep.wrap_recycle),
            (0, 0, 0),
            "no loop => no wrap-class findings"
        );
        assert_eq!(rep.unresolved_edges, 0);
        for (k, x) in bad.iter().enumerate() {
            assert!(
                encode_instruction(x, &tab).is_ok(),
                "corrupted-but-legal ctrl must still encode at insn[{k}]"
            );
        }
    }
}
