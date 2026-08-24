//! BUG-110 (110-kand, ex-F2Q z raportu 102): RAW-audyt w `report_hazards`
//! sledzil wylacznie OSTATNIEGO armera bariery (`armed[b] == Some(pidx)`)
//! i nie modelowal DEPBAR jako draina. Skutki na certified rt98_v2 publish
//! text (silicon-EXACT na B300): 160 WARN "NOT waited" (frozen -> drukowane
//! bezwarunkowo przy kazdym asm), z czego:
//!   - 9x KernelB MOV R71,R10x: software-pipelined loop, drain = DEPBAR.LE
//!     SB0, 0x9 (audyt nie rozumial DEPBAR) => FP;
//!   - ~78x KernelA IMAD.WIDE reads R(n+1): src_regs dodawal +1 dla KAZDEGO
//!     reg-operandu op_idx>1, ale multiplikandy WIDE sa 32-bit (reg_liveness
//!     M3.5/BUG-108: "addend = ostatni nie-predykat operand") => FP;
//!   - ~63x KernelA true-reads R116..R123 (LDG .256 wb2) czytane 100-710
//!     instrukcji po producencie bez wait-mask (pokryte czasem, krzem EXACT)
//!     => zostaja GLOSNE (doktryna distance-amnesty = kand-112, decyzja po
//!     kalibracji krzemowej, NIE w tym fixie);
//! natomiast dziura wykrywania: przy batchu N producentow na jednej barierze
//! czytanie MEMBERA != ostatni bez wait przechodzilo milczaco (false
//! negative — guard `armed[b] == Some(pidx)` bije tylko dla ostatniego).
//!
//! Fix: (a) `armed[b]` = zbior WSZYSTKICH armerow od ostatniego draina
//! (wait_mask czysci zbior, jak dawniej); (b) `DEPBAR.<m> SBb, imm` czysci
//! zbior bariery b (HW: DEPBAR czeka na liczniku scoreboardu; dowod z
//! certyfikatu rt98: 48-batch prolog + 9 kolejnych batchy na wb0, kernel
//! EXACT); (c) src_regs WIDE: para (n,n+1) TYLKO dla addendu (ostatni
//! nie-predykat operand, lustrzane reg_liveness.rs M3.5), multiplikandy
//! zostaja 32-bit. RECYCLE (BUG-102) zachowany: prev = ostatni armer.
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

// 1) DEPBAR jako drain: batch 2x LDG na wb2, DEPBAR.LE SB2, potem readerzy
//    obu memberow -> cicho. Pre-fix: DEPBAR nie czyscil armed -> WARN.
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

// 3) Reg-guard: reader OSTATNIEGO membera bez wait -> WARN (jak dawniej).
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

// 5) DEPBAR na INNEJ barierze nie drainuje wb2.
#[test]
fn t110_5_depbar_other_barrier_does_not_drain() {
    let hs = hazards(
        "    [B------:R-:W2:-:S02] LDG.E R20, desc[UR4][R2.64] ;\n    [B------:R-:W-:-:S04] DEPBAR.LE 0x3, 0x9 ;\n    [B------:R-:W-:-:S05] MOV R30, R20 ;\n",
    );
    let r = raw(&hs);
    assert!(r.iter().any(|m| m.contains("reads R20")), "DEPBAR SB3 must not drain wb2: {:?}", r);
}

// 6) Drain nie dziala wstecz: DEPBAR, potem re-arm wb2, reader bez wait -> WARN.
#[test]
fn t110_6_depbar_then_rearm_still_needs_wait() {
    let hs = hazards(
        "    [B------:R-:W-:-:S04] DEPBAR.LE 0x2, 0x9 ;\n    [B------:R-:W2:-:S02] LDG.E R20, desc[UR4][R2.64] ;\n    [B------:R-:W-:-:S05] MOV R30, R20 ;\n",
    );
    let r = raw(&hs);
    assert!(r.iter().any(|m| m.contains("reads R20")), "re-arm after DEPBAR must still require a wait: {:?}", r);
}

// 7) WIDE multiplikand NIE jest para: producent (wb2, armed) pisze R76;
//    IMAD.WIDE.U32.X z multiplikandem R75 czyta tylko R75 (32-bit) ->
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

// 8) Reg-guard: WIDE addend NADAL jest para: producent pisze R100 (wb2
//    armed, bez draina); IMAD.WIDE z addendem R100 czyta R101 -> WARN.
#[test]
fn t110_8_wide_addend_pair_still_tracked() {
    let hs = hazards(
        "    [B------:R-:W2:-:S01] LDC.64 R100, c[0x0][0x400] ;\n    [B------:R-:W-:-:S05] IMAD.WIDE.U32.X R104, P3, R75, R17, R100, P4 ;\n",
    );
    let r = raw(&hs);
    assert!(r.iter().any(|m| m.contains("reads R101")), "64-bit addend pair (R100,R101) must stay tracked: {:?}", r);
}

// 9) Reg-guard: WIDE z RZ-addendem nie fabrykuje pary z multiplikanda —
//    producent pisze R76, forma bez reg-addendu: cicho na R76.
#[test]
fn t110_9_wide_rz_addend_keeps_multiplicand_scalar() {
    let hs = hazards(
        "    [B------:R-:W2:-:S01] LDC.64 R76, c[0x0][0x400] ;\n    [B------:R-:W-:-:S05] IMAD.WIDE.U32.X R104, P3, R75, R17, RZ, P4 ;\n",
    );
    let r = raw(&hs);
    assert!(!r.iter().any(|m| m.contains("reads R76") || m.contains("reads R77")),
        "RZ-addend (.X form: multiplicand sits at op_idx>1) must never span multiplicands: {:?}", r);
}
