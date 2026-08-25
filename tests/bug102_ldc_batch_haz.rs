//! BUG-102 (102-kand, ex-F2Q "102-kand" z raportu 101): `report_hazards` WARN
//! RECYCLE byl falszywie glosny na legalnym vendorowym batchingu barrierow.
//!
//! Evidence (certified rt98_v2 publish text, silicon-EXACT na B300): ptxas
//! kumuluje WIELE async-producentow na JEDNEJ barierze zapisu z pojedynczym
//! drainem nizej (prologi S2R/S2UR/LDCU xN na wb0, batchy LDG xN na wb0 z
//! przeplatanym ALU, runy SHFL.BFLY x55) — 160/160 warnow RECYCLE bylo FP.
//! Under the `in-order / counting` shared-barrier doctrine, a barrier re-armed by
//! the next async producer without an intervening drain does NOT orphan consumers;
//! RAW gating is audited separately.
//!
//! What STAYS loud (fail-closed): a re-arm by a class without async writeback
//! (stray W-tag na ALU/konwersji) — to dalej wyglada na prawdziwy blad autora.

use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, report_hazards, schedule};
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn hazards(body: &str) -> Vec<cubit::scheduling_pass::HazardReport> {
    let src = format!(".entry t\n    .param u64 io\n{body}    EXIT ;\n");
    let f = parse_sass_file_str_strict(&src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    schedule(&mut insns, Some(&t120()));
    reallocate_barriers(&mut insns, Some(&t120()));
    report_hazards(&insns)
}

fn recycle(hs: &[cubit::scheduling_pass::HazardReport]) -> Vec<String> {
    hs.iter().filter(|h| h.msg.contains("RECYCLE")).map(|h| h.msg.clone()).collect()
}

// 1) Scenariusz z noty 101: frozen batch LDC na wspolnej barierze + drain.
#[test]
fn t102_1_frozen_ldc_batch_shared_barrier_quiet() {
    let hs = hazards(
        "    LDCU.64 UR4, c[0x0][0x358] ;\n    [B------:R-:W2:-:S01] LDC.64 R10, c[0x0][0x100] ;\n    [B------:R-:W2:-:S01] LDC.64 R12, c[0x0][0x108] ;\n    [B------:R-:W2:-:S01] LDC.64 R14, c[0x0][0x110] ;\n    [B--2---:R-:W-:-:S12] IADD3 R16, PT, PT, R10, R12, RZ ;\n    IADD3 R18, PT, PT, R14, R16, RZ ;\n",
    );
    assert!(recycle(&hs).is_empty(), "legal LDC batch must not warn: {:?}", recycle(&hs));
}

// 2) Vendor pattern: batch LDG z przeplatanym ALU (adresy) miedzy memberami,
//    jeden drain NOP-side przed konsumpcja (rt98 KernelB @0x570/0x590 ...).
#[test]
fn t102_2_vendor_ldg_batch_with_alu_interleave_quiet() {
    let hs = hazards(
        "    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n    [B------:R-:W4:-:S02] LDG.E R20, desc[UR4][R2.64] ;\n    [B------:R-:W4:-:S02] LDG.E R24, desc[UR4][R2.64+0x100] ;\n    [B------:R-:W-:-:S06] IADD3 R28, PT, PT, R2, 0x8, RZ ;\n    [B------:R-:W4:-:S02] LDG.E R32, desc[UR4][R28.64] ;\n    [B----4-:R-:W-:-:S12] IADD3 R36, PT, PT, R20, R24, RZ ;\n",
    );
    assert!(recycle(&hs).is_empty(), "vendor-style interleaved LDG batch must not warn: {:?}", recycle(&hs));
}

// 3) rt98 KernelB: run SHFL.BFLY x55 na wb0 — certified EXACT na krzemie.
#[test]
fn t102_3_shfl_run_shared_barrier_quiet() {
    let hs = hazards(
        "    LDCU.64 UR4, c[0x0][0x358] ;\n    [B------:R-:W3:-:S01] SHFL.BFLY PT, R40, R10, 0x1, 0x1f ;\n    [B------:R-:W3:-:S01] SHFL.BFLY PT, R41, R11, 0x1, 0x1f ;\n    [B------:R-:W3:-:S01] SHFL.BFLY PT, R42, R12, 0x1, 0x1f ;\n    [B---3--:R-:W-:-:S12] IADD3 R44, PT, PT, R40, R41, RZ ;\n",
    );
    assert!(recycle(&hs).is_empty(), "certified SHFL run must not warn: {:?}", recycle(&hs));
}

// 4) NEGATIVE: a stray W-tag on ALU (IMAD) mid-run — re-arm by a class without
//    async-writeback dalej wrzeski (fail-closed).
#[test]
fn t102_4_stray_alu_wtag_still_warns() {
    let hs = hazards(
        "    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n    [B------:R-:W2:-:S01] LDC.64 R10, c[0x0][0x100] ;\n    [B------:R-:W2:-:S05] IMAD R20, R2, R2, RZ ;\n    [B------:R-:W2:-:S01] LDC.64 R12, c[0x0][0x108] ;\n",
    );
    let rec = recycle(&hs);
    let alu_edge = rec.iter().filter(|m| m.contains("IMAD")).count();
    assert!(alu_edge >= 1, "stray ALU W-tag on armed barrier must warn, got: {:?}", rec);
}

// 5) NEGATIVE: MUFU (not a long-latency class) re-arming the shared barrier.
#[test]
fn t102_5_mufu_rearm_still_warns() {
    let hs = hazards(
        "    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n    [B------:R-:W2:-:S01] LDC.64 R10, c[0x0][0x100] ;\n    [B------:R-:W2:-:S05] MUFU.RCP R20, R2 ;\n",
    );
    let rec = recycle(&hs);
    assert!(rec.iter().any(|m| m.contains("MUFU")), "MUFU re-arm must warn, got: {:?}", rec);
}

// 6) Drain miedzy producentami = czyste re-arm (cicho pre- i post-fix):
//    pinuje, ze suppressia NIE polega na kasowaniu sledzenia drain.
#[test]
fn t102_6_drain_then_rearm_quiet() {
    let hs = hazards(
        "    LDCU.64 UR4, c[0x0][0x358] ;\n    [B------:R-:W2:-:S01] LDC.64 R10, c[0x0][0x100] ;\n    [B--2---:R-:W-:-:S12] IADD3 R16, PT, PT, R10, R10, RZ ;\n    [B------:R-:W2:-:S01] LDC.64 R12, c[0x0][0x108] ;\n    [B--2---:R-:W-:-:S12] IADD3 R18, PT, PT, R12, R12, RZ ;\n",
    );
    assert!(recycle(&hs).is_empty(), "drained re-arm must stay quiet: {:?}", recycle(&hs));
}

// 7) Auto path: reallocate_barriers itself batches consecutive same-line/same-class
//    loads onto one barrier (ptxas-like PV discipline, default pipeline) —
//    the audit must stay quiet on such a produced batch (pre-102: a RECYCLE
//    warn per extra member under CUBIT_HAZ).
#[test]
fn t102_7_auto_same_line_batch_no_recycle() {
    let src = ".entry t\n    .param u64 io\n    LDCU.64 UR4, c[0x0][0x358] ;
    LDG.E R20, desc[UR4][R2.64+0x0] ;
    LDG.E R24, desc[UR4][R2.64+0x8] ;
    LDG.E R28, desc[UR4][R2.64+0x10] ;
    IADD3 R32, PT, PT, R20, R24, RZ ;
    IADD3 R36, PT, PT, R32, R28, RZ ;
    EXIT ;
";
    let f = parse_sass_file_str_strict(src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    schedule(&mut insns, Some(&t120()));
    reallocate_barriers(&mut insns, Some(&t120()));
    // Sanity: the allocator really batched the run (one shared write barrier),
    // otherwise the quietness assertion below is vacuous.
    let ldg_bars: Vec<u8> = insns
        .iter()
        .filter(|i| i.opcode == "LDG")
        .map(|i| i.ctrl.write_bar)
        .collect();
    assert_eq!(ldg_bars.len(), 3, "expected 3 LDG, got {:?}", ldg_bars);
    assert_eq!(
        ldg_bars.iter().collect::<std::collections::HashSet<_>>().len(), 1,
        "allocator must batch the same-line LDG run onto one barrier, got {:?}", ldg_bars
    );
    let hs = report_hazards(&insns);
    let rec = recycle(&hs);
    assert!(rec.is_empty(), "auto-batched same-line loads must not warn: {:?}", rec);
}
