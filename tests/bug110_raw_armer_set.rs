//! BUG-110 (110-kand, ex-F2Q z raportu 102): RAW-audyt w `report_hazards`
//! tracked only the LAST barrier armer (`armed[b] == Some(pidx)`)
//! and did not model DEPBAR as a drain. Effects on the certified rt98_v2 publish
//! text (silicon-EXACT on B300): 160 WARN "NOT waited" (frozen -> printed
//! unconditionally on every asm), of which:
//!   - 9x KernelB MOV R71,R10x: software-pipelined loop, drain = DEPBAR.LE
//!     SB0, 0x9 (the audit did not understand DEPBAR) => FP;
//!   - approx. 78x KernelA IMAD.WIDE reads R(n+1): src_regs added +1 for EVERY
//!     reg operand with op_idx>1, but WIDE multiplicands are 32-bit (reg_liveness
//!     M3.5/BUG-108: "addend = last non-predicate operand") => FP;
//!   - approx. 63x KernelA true reads R116..R123 (LDG .256 wb2) read 100-710
//!     instructions past the producer without a wait mask (covered by timing, silicon EXACT)
//!     => these stay LOUD (the distance-amnesty doctrine = cand-112, a decision after
//!     silicon calibration, NOT in this fix);
//! meanwhile the detection hole: with a batch of N producers on one barrier
//! reading a MEMBER != last without a wait passed silently (false
//! negative — the `armed[b] == Some(pidx)` guard fires only for the last one).
//!
//! Fix: (a) `armed[b]` = the set of ALL armers since the last drain
//! (wait_mask clears the set, as before); (b) `DEPBAR.<m> SBb, imm` clears
//! the set of barrier b (HW: DEPBAR waits on the scoreboard counter; evidence from
//! the rt98 certificate: a 48-batch prologue + 9 subsequent batches on wb0, kernel
//! EXACT); (c) WIDE src_regs: the (n,n+1) pair ONLY for the addend (last
//! non-predicate operand, mirroring reg_liveness.rs M3.5); multiplicands
//! stay 32-bit. RECYCLE (BUG-102) preserved: prev = last armer.
//!
//! Kontrola pozytywna: pre-fix t110_1/t110_2/t110_7 FAIL, reszta PASS.
//!
//! Fixture: prolog LDCU/LDC na wb0/wb1 + drenaz [B01----] (izolacja od
//! scenariusza, ktory pracuje na wb2/wb3).

use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::report_hazards;

fn hazards(body: &str) -> Vec<cubit::scheduling_pass::HazardReport> {
    let prolog = "    [B------:R-:W0:-:S01] LDCU.64 UR4, c[0x0][0x358] ;\n    [B------:R-:W1:-:S01] LDC.64 R2, c[0x0][0x380] ;\n    [B01----:R-:W-:-:S12] IADD3 R8, PT, PT, R2, 0x1, RZ ;\n";
    let src = format!(".entry t\n    .param u64 io\n{prolog}{body}    EXIT ;\n");
    let f = parse_sass_file_str_strict(&src).unwrap();
    // Production contract for this bug class: the audit sees the FROZEN
    // publish text (all ctrl fields authored by [B..] tags); the auto
    // scheduler never runs on it (fully_frozen path in cmd_asm). Running
    // schedule()+reallocate here would silently repair the authored waits
    // and mask the exact holes under test, so the pins audit the parsed
    // (frozen) control directly — same input cmd_asm hands report_hazards.
    let insns = f.kernels[0].instructions.clone();
    report_hazards(&insns)
}

fn raw(hs: &[cubit::scheduling_pass::HazardReport]) -> Vec<String> {
    hs.iter().filter(|h| h.msg.contains("RAW")).map(|h| h.msg.clone()).collect()
}

// 1) DEPBAR as a drain: batch of 2x LDG on wb2, DEPBAR.LE SB2, then readers of
//    both members -> quiet. Pre-fix: DEPBAR did not clear armed -> WARN.
#[test]
fn t110_1_depbar_drains_barrier_read_after_quiet() {
    let hs = hazards(
        "    [B------:R-:W2:-:S02] LDG.E R20, desc[UR4][R2.64] ;\n    [B------:R-:W2:-:S02] LDG.E R24, desc[UR4][R2.64+0x100] ;\n    [B------:R-:W-:-:S04] DEPBAR.LE 0x2, 0x9 ;\n    [B------:R-:W-:-:S05] MOV R30, R24 ;\n    [B------:R-:W-:-:S05] MOV R31, R20 ;\n",
    );
    assert!(raw(&hs).is_empty(), "reads after DEPBAR SB2 must be quiet: {:?}", raw(&hs));
}

// 2) Dziura last-only zamknieta: batch 2x LDG wb2 BEZ draina, reader
//    PIERWSZEGO membera -> WARN. Pre-fix: armed==Some(last) -> cicho (FAIL).
#[test]
fn t110_2_batch_first_member_no_wait_warns() {
    let hs = hazards(
        "    [B------:R-:W2:-:S02] LDG.E R20, desc[UR4][R2.64] ;\n    [B------:R-:W2:-:S02] LDG.E R24, desc[UR4][R2.64+0x100] ;\n    [B------:R-:W-:-:S05] MOV R30, R20 ;\n",
    );
    let r = raw(&hs);
    assert!(r.iter().any(|m| m.contains("reads R20")), "first-batch-member read with no wait must warn: {:?}", r);
}

// 3) Reg-guard: a reader of the LAST member without a wait -> WARN (as before).
#[test]
fn t110_3_batch_last_member_no_wait_still_warns() {
    let hs = hazards(
        "    [B------:R-:W2:-:S02] LDG.E R20, desc[UR4][R2.64] ;\n    [B------:R-:W2:-:S02] LDG.E R24, desc[UR4][R2.64+0x100] ;\n    [B------:R-:W-:-:S05] MOV R30, R24 ;\n",
    );
    let r = raw(&hs);
    assert!(r.iter().any(|m| m.contains("reads R24")), "last batch member no-wait must still warn: {:?}", r);
}

// 4) Reg-guard: wait_mask drain czysci caly zbior (zachowane pokrycie).
#[test]
fn t110_4_wait_mask_drain_clears_whole_batch() {
    let hs = hazards(
        "    [B------:R-:W2:-:S02] LDG.E R20, desc[UR4][R2.64] ;\n    [B------:R-:W2:-:S02] LDG.E R24, desc[UR4][R2.64+0x100] ;\n    [B--2---:R-:W-:-:S12] IADD3 R28, PT, PT, R20, R24, RZ ;\n    [B------:R-:W-:-:S05] MOV R30, R20 ;\n",
    );
    assert!(raw(&hs).is_empty(), "wait-mask drain must clear all batch armers: {:?}", raw(&hs));
}

// 5) DEPBAR on a DIFFERENT barrier does not drain wb2.
#[test]
fn t110_5_depbar_other_barrier_does_not_drain() {
    let hs = hazards(
        "    [B------:R-:W2:-:S02] LDG.E R20, desc[UR4][R2.64] ;\n    [B------:R-:W-:-:S04] DEPBAR.LE 0x3, 0x9 ;\n    [B------:R-:W-:-:S05] MOV R30, R20 ;\n",
    );
    let r = raw(&hs);
    assert!(r.iter().any(|m| m.contains("reads R20")), "DEPBAR SB3 must not drain wb2: {:?}", r);
}

// 6) Drain does not work backwards: DEPBAR, then a re-arm of wb2, reader without wait -> WARN.
#[test]
fn t110_6_depbar_then_rearm_still_needs_wait() {
    let hs = hazards(
        "    [B------:R-:W-:-:S04] DEPBAR.LE 0x2, 0x9 ;\n    [B------:R-:W2:-:S02] LDG.E R20, desc[UR4][R2.64] ;\n    [B------:R-:W-:-:S05] MOV R30, R20 ;\n",
    );
    let r = raw(&hs);
    assert!(r.iter().any(|m| m.contains("reads R20")), "re-arm after DEPBAR must still require a wait: {:?}", r);
}

// 7) A WIDE multiplicand is NOT a pair: the producer (wb2, armed) writes R76;
//    IMAD.WIDE.U32.X with multiplicand R75 reads only R75 (32-bit) ->
//    zaden RAW na R76. Pre-fix: src_regs fabrykowal R76 -> WARN (FAIL).
#[test]
fn t110_7_wide_multiplicand_is_32bit_no_phantom_pair() {
    let hs = hazards(
        "    [B------:R-:W2:-:S01] LDC.64 R76, c[0x0][0x400] ;\n    [B------:R-:W-:-:S05] IMAD.WIDE.U32.X R100, P3, R75, R17, R100, P4 ;\n",
    );
    let r = raw(&hs);
    assert!(!r.iter().any(|m| m.contains("reads R76") || m.contains("reads R77")),
        "32-bit multiplicand must not fabricate R76/R77 reads: {:?}", r);
}

// 8) Reg-guard: a WIDE addend STILL is a pair: the producer writes R100 (wb2
//    armed, no drain); IMAD.WIDE with addend R100 reads R101 -> WARN.
#[test]
fn t110_8_wide_addend_pair_still_tracked() {
    let hs = hazards(
        "    [B------:R-:W2:-:S01] LDC.64 R100, c[0x0][0x400] ;\n    [B------:R-:W-:-:S05] IMAD.WIDE.U32.X R104, P3, R75, R17, R100, P4 ;\n",
    );
    let r = raw(&hs);
    assert!(r.iter().any(|m| m.contains("reads R101")), "64-bit addend pair (R100,R101) must stay tracked: {:?}", r);
}

// 9) Reg-guard: WIDE with an RZ addend does not fabricate a pair from the multiplicand —
//    the producer writes R76, a form without a reg addend: quiet on R76.
#[test]
fn t110_9_wide_rz_addend_keeps_multiplicand_scalar() {
    let hs = hazards(
        "    [B------:R-:W2:-:S01] LDC.64 R76, c[0x0][0x400] ;\n    [B------:R-:W-:-:S05] IMAD.WIDE.U32.X R104, P3, R75, R17, RZ, P4 ;\n",
    );
    let r = raw(&hs);
    assert!(!r.iter().any(|m| m.contains("reads R76") || m.contains("reads R77")),
        "RZ-addend (.X form: multiplicand sits at op_idx>1) must never span multiplicands: {:?}", r);
}
