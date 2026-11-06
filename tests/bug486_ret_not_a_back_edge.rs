//! BUG-486 (found 2026-11-06 reviewing coldface's scheduling-legality oracle, C11: 16 of its REJECT
//! verdicts on frozen nvcc kernels were this): `branch_target` took the first immediate of ANY
//! control-flow instruction as a static target. `RET.REL.NODEC R2, 0x0` — the return of an
//! in-kernel subroutine (`CALL.REL.NOINC`) — returns to R2 + 0x0; its `0x0` resolved to address 0 =
//! instruction 0, so `resolved_back_edges` saw a loop from the kernel entry to the RET, the loop-aware
//! verifier re-walked the whole kernel as a loop body (bogus "(loop-carried wrap)" WAR findings
//! against the prologue's `S2R` / `MOV` / `LEA`), and `load_result_loop_carried` / the allocator's
//! loop logic saw the same phantom loop. Register-indirect control flow (RET/PRET, BRX/BRXU,
//! JMX/JMXU, `CALL.ABS` with its relocation, any control-flow op carrying a non-RZ GPR) has no static
//! target — the rule `unresolved_edge_class` already applied for the UNRESOLVED-EDGE report.
//!
//! Second part, the verifier's late-latch release: a mem-op's late-latched operands (`rbp`) were
//! released only by a wait on its READ barrier. ptxas schedules `LDS R3, [R2+0x14]` W0 → `LOP3 R3, R3`
//! B0 → … → `MOV R2, …` with no read barrier on the LDS: once the load's result has landed (its write
//! barrier waited) the address cannot be re-latched. The verifier now releases `rbp` entries on a wait
//! of the mem-op's write barrier too (stores have none and keep the rb rule) — the oracle's "LDS
//! replay-window divergence" class on frozen nvcc kernels was mostly this.

use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::verify_scoreboard_report;
use cubit::table::IsaTable;
use cubit::Instruction;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn kernel(src: &str) -> Vec<Instruction> {
    let f = parse_sass_file_str_strict(src).unwrap();
    assert_eq!(f.kernels.len(), 1);
    f.kernels[0].instructions.clone()
}

/// The mk296 `kdealloc` shape (nvcc sm_100a/sm_103a, frozen): a prologue that writes R2/R3, a bare
/// epilogue store of R2:R3, EXIT, then two out-of-line subroutines ending in `RET.REL.NODEC R2, 0x0`.
/// `store_rb` is the read barrier the oracle's probe injects into the bare STG.
fn dealloc_shape(store_rb: &str) -> String {
    format!(
        ".entry kdealloc\n    .reg R0-R7\n    .param ptr p0 offset=0x0\n\
         \x20   [B------:R-:W-:Y:S01] LDC R1, c[0x0][0x37c] ;\n\
         \x20   [B------:R-:W0:Y:S02] S2R R0, SR_TID.X ;\n\
         \x20   [B0-----:R-:W-:-:S13] ISETP.GT.U32.AND P0, PT, R0, 0x1f, PT ;\n\
         \x20   [B------:R-:W-:Y:S05] @P0 BRA L_tail ;\n\
         \x20   [B------:R-:W0:Y:S01] S2R R3, SR_CgaCtaId ;\n\
         \x20   [B------:R-:W-:Y:S01] MOV R2, 0x40 ;\n\
         \x20   [B0-----:R-:W-:-:S05] LEA R2, R3, R2, 0x18 ;\n\
         \x20   [B------:R-:W0:Y:S02] LDS R3, [R2+0x14] ;\n\
         \x20   [B0-----:R-:W-:-:S04] LOP3.LUT R3, R3, 0xf, RZ, 0xc0, !PT ;\n\
         \x20   [B------:R-:W-:-:S13] ISETP.NE.AND P0, PT, R3, 0xf, PT ;\n\
         \x20   [B------:R-:W-:Y:S05] @P0 BRA L_sub1 ;\n\
         \x20   [B------:R-:W-:-:S07] MOV R2, 0x210 ;\n\
         \x20   [B------:R-:W-:Y:S05] CALL.REL.NOINC L_sub2 ;\n\
         L_tail:  [B------:R-:W0:Y:S01] LDC.64 R4, c[0x0][0x380] ;\n\
         \x20   [B------:R-:W1:Y:S01] LDCU.64 UR4, c[0x0][0x358] ;\n\
         \x20   [B------:R-:W-:Y:S01] LOP3.LUT R2, R3, R0, RZ, 0x3c, !PT ;\n\
         \x20   [B------:R-:W-:Y:S02] IMAD.MOV.U32 R3, RZ, RZ, RZ ;\n\
         \x20   [B0-----:R-:W-:-:S05] IMAD.WIDE.U32 R4, R0, 0x8, R4 ;\n\
         \x20   [B-1----:R{store_rb}:W-:Y:S01] STG.E.64 desc[UR4][R4.64], R2 ;\n\
         \x20   [B------:R-:W-:Y:S05] EXIT ;\n\
         L_sub1:  [B------:R-:W-:Y:S05] BPT.TRAP 0x1 ;\n\
         \x20   [B------:R-:W-:-:S04] IMAD.MOV.U32 R3, RZ, RZ, 0x0 ;\n\
         \x20   [B------:R-:W-:Y:S05] RET.REL.NODEC R2, 0x0 ;\n\
         L_sub2:  [B------:R-:W-:Y:S05] BPT.TRAP 0x1 ;\n\
         \x20   [B------:R-:W-:-:S04] IMAD.MOV.U32 R3, RZ, RZ, 0x0 ;\n\
         \x20   [B------:R-:W-:Y:S05] RET.REL.NODEC R2, 0x0 ;\n\
         .endentry\n"
    )
}

/// The frozen nvcc schedule verifies clean, and its two RETs are reported as unresolved
/// (register-indirect) edges — not as resolved loops.
#[test]
fn bug486_frozen_dealloc_shape_is_clean_and_rets_are_unresolved() {
    let t = t120();
    let insns = kernel(&dealloc_shape("-"));
    let rep = verify_scoreboard_report(&insns, Some(&t));
    assert_eq!((rep.raw, rep.war, rep.recycle), (0, 0, 0), "{rep:?}");
    assert_eq!(rep.unresolved_edges, 2, "two RET.REL.NODEC R2 = two register-indirect edges: {rep:?}");
    assert_eq!(rep.unresolved_reg_target, 2, "{rep:?}");
}

/// The oracle's probe (a free read barrier injected into the bare STG): before BUG-486 the RETs'
/// `0x0` made instruction 0 a loop top and the wrap pass reported the prologue's `S2R R3`, `MOV R2`,
/// `LEA R2`, `LDS R3` as loop-carried overwriters of the store's operands (4 wrap WARs). Now no
/// back-edge exists, so no wrap finding exists; the only findings left are the linear walk's
/// `IMAD.MOV.U32 R3` of the two subroutines (unreachable from the store by control flow — the
/// oracle tool classifies those, the verifier's linear walk does not).
#[test]
fn bug486_ret_immediate_is_not_a_back_edge() {
    let t = t120();
    let insns = kernel(&dealloc_shape("3"));
    let rep = verify_scoreboard_report(&insns, Some(&t));
    assert_eq!(rep.wrap_war, 0, "RET.REL.NODEC R2, 0x0 must not create a back-edge to insn 0: {rep:?}");
    assert_eq!(rep.wrap_raw + rep.wrap_recycle, 0, "{rep:?}");
    assert_eq!(rep.war, 2, "the two subroutine `IMAD.MOV.U32 R3` overwriters, linear walk: {rep:?}");
}

/// The same shape with a REAL loop (a backward `BRA` from the end of the body to the LDS) keeps its
/// wrap findings: the back-edge resolution itself is intact.
#[test]
fn bug486_real_back_edge_still_walked() {
    let t = t120();
    let src = ".entry kloop\n    .reg R0-R7\n    .param ptr p0 offset=0x0\n\
         \x20   [B------:R-:W-:Y:S01] LDCU.64 UR4, c[0x0][0x358] ;\n\
         \x20   [B------:R-:W0:Y:S01] LDC.64 R4, c[0x0][0x380] ;\n\
         \x20   [B------:R-:W-:Y:S01] MOV R2, 0x40 ;\n\
         L_top:  [B0-----:R-:W-:Y:S01] MOV R3, 0x1 ;\n\
         \x20   [B------:R3:W-:Y:S01] STG.E.64 desc[UR4][R4.64], R2 ;\n\
         \x20   [B------:R-:W-:Y:S01] IADD3 R4, R4, 0x8, RZ ;\n\
         \x20   [B------:R-:W-:Y:S05] BRA L_top ;\n\
         \x20   [B------:R-:W-:Y:S05] EXIT ;\n\
         .endentry\n";
    let insns = kernel(src);
    let rep = verify_scoreboard_report(&insns, Some(&t));
    assert_eq!(rep.unresolved_edges, 0, "{rep:?}");
    // linear: IADD3 R4 overwrites the store's address base without waiting rb 3;
    // wrap: next iteration's `MOV R3` overwrites the store's data pair without waiting it.
    assert!(rep.war >= 2 && rep.wrap_war >= 1, "{rep:?}");
}

/// Verifier late-latch release (second part): a waited WRITE barrier of a load releases its address
/// latch. `LDS R3, [R2]` W0 → `LOP3 R3` B0 → `MOV R2` is ptxas's schedule (no read barrier on the
/// LDS); with a read barrier injected and never waited, the verifier used to flag the `MOV R2` for
/// ever (LDS is never distance-covered). Control: without the B0 wait the finding stays.
#[test]
fn bug486_waited_write_barrier_releases_the_address_latch() {
    let t = t120();
    let shape = |lop3_wait: &str| {
        format!(
            ".entry klds\n    .reg R0-R7\n    .param ptr p0 offset=0x0\n\
             \x20   [B------:R-:W-:Y:S01] MOV R2, 0x40 ;\n\
             \x20   [B------:R1:W0:Y:S02] LDS R3, [R2+0x14] ;\n\
             \x20   [{lop3_wait}:R-:W-:-:S04] LOP3.LUT R5, R3, 0xf, RZ, 0xc0, !PT ;\n\
             \x20   [B------:R-:W-:Y:S01] MOV R2, 0x210 ;\n\
             \x20   [B-1----:R-:W-:Y:S05] EXIT ;\n\
             .endentry\n"
        )
    };
    let waited = verify_scoreboard_report(&kernel(&shape("B0-----")), Some(&t));
    assert_eq!(waited.war, 0, "the LDS completed (B0 waited) before `MOV R2`: {waited:?}");
    assert_eq!(waited.raw, 0, "{waited:?}");
    let unwaited = verify_scoreboard_report(&kernel(&shape("B------")), Some(&t));
    assert!(unwaited.war >= 1, "control: with the result unwaited the address latch is live: {unwaited:?}");
    assert!(unwaited.raw >= 1, "control: the LOP3 reads R3 before the LDS landed: {unwaited:?}");
}

/// The oracle's rb-coverage probe as a verifier mode (`verify_scoreboard_rb_probe`): a bare store
/// whose data register is overwritten is invisible to the plain verifier and a BROKEN WAR in probe
/// mode; the same store with the overwriter's write placed BEFORE it is clean in both; a bare LDS
/// whose result is waited before its address is overwritten is clean in probe mode too (the
/// write-barrier release) — nvcc's everyday shape.
#[test]
fn bug486_rb_probe_mode_sees_the_ebbd1dc_shape_without_a_free_barrier() {
    use cubit::scheduling_pass::verify_scoreboard_rb_probe;
    let t = t120();
    // all six scoreboards in use (W0..W5 armed and waited) — the injection probe had nothing to inject
    let src = ".entry kprobe\n    .reg R0-R31\n    .param ptr p0 offset=0x0\n\
         \x20   [B------:R-:W0:Y:S01] LDCU.64 UR4, c[0x0][0x358] ;\n\
         \x20   [B------:R-:W1:Y:S01] LDC.64 R2, c[0x0][0x380] ;\n\
         \x20   [B------:R-:W2:Y:S01] LDC.64 R4, c[0x0][0x388] ;\n\
         \x20   [B------:R-:W3:Y:S01] LDC R6, c[0x0][0x390] ;\n\
         \x20   [B------:R-:W4:Y:S01] LDC R7, c[0x0][0x394] ;\n\
         \x20   [B------:R-:W5:Y:S01] LDC R9, c[0x0][0x398] ;\n\
         \x20   [B012345:R-:W-:Y:S01] IADD3 R8, R6, R7, R9 ;\n\
         \x20   [B------:R-:W-:Y:S01] STG.E desc[UR4][R2.64], R8 ;\n\
         \x20   [B------:R-:W-:Y:S01] IADD3 R8, R8, 0x1, RZ ;\n\
         \x20   [B------:R-:W-:Y:S01] STG.E desc[UR4][R4.64], R8 ;\n\
         \x20   [B------:R-:W-:Y:S05] EXIT ;\n\
         .endentry\n";
    let insns = kernel(src);
    let plain = verify_scoreboard_report(&insns, Some(&t));
    assert_eq!((plain.raw, plain.war, plain.recycle), (0, 0, 0), "plain verifier is blind: {plain:?}");
    let probed = verify_scoreboard_rb_probe(&insns, Some(&t));
    assert_eq!(probed.war, 1, "`IADD3 R8` overwrites the first bare store's data register: {probed:?}");
    assert_eq!(probed.raw, 0, "{probed:?}");

    // the protected shape (rb on the store, the overwriter waits it) is clean in probe mode as well
    let fixed = src
        .replace("[B------:R-:W-:Y:S01] STG.E desc[UR4][R2.64], R8", "[B------:R0:W-:Y:S01] STG.E desc[UR4][R2.64], R8")
        .replace("[B------:R-:W-:Y:S01] IADD3 R8, R8, 0x1, RZ", "[B0-----:R-:W-:Y:S01] IADD3 R8, R8, 0x1, RZ");
    let ok = verify_scoreboard_rb_probe(&kernel(&fixed), Some(&t));
    assert_eq!((ok.raw, ok.war), (0, 0), "{ok:?}");

    // nvcc's bare LDS: result waited, then the address register overwritten — no finding in probe mode
    let lds = ".entry klds2\n    .reg R0-R7\n    .param ptr p0 offset=0x0\n\
         \x20   [B------:R-:W-:Y:S01] MOV R2, 0x40 ;\n\
         \x20   [B------:R-:W0:Y:S02] LDS R3, [R2+0x14] ;\n\
         \x20   [B0-----:R-:W-:-:S04] LOP3.LUT R5, R3, 0xf, RZ, 0xc0, !PT ;\n\
         \x20   [B------:R-:W-:Y:S01] MOV R2, 0x210 ;\n\
         \x20   [B------:R-:W-:Y:S05] EXIT ;\n\
         .endentry\n";
    let p = verify_scoreboard_rb_probe(&kernel(lds), Some(&t));
    assert_eq!((p.raw, p.war), (0, 0), "{p:?}");
}
