//! BUG-046 family (sm120 register 046 + addendum i130): hand_sched `[CC]`
//! instructions freeze their whole control word, so at a tagged/white
//! boundary the auto-scheduler cannot inject a wait/stall into the frozen
//! side. The tool must therefore REPORT boundary hazards loudly (fail-closed
//! doctrine). These tests pin the detection classes:
//!   A) frozen consumer under-waits a white barrier'd producer  -> RAW finding
//!   B) frozen `[W-]` barrier-less long-latency producer + near white
//!      consumer -> RAW-NOBAR finding (was completely invisible pre-fix)
//!   C) clean all-white schedule -> no findings; consistent frozen flow -> no FP
//! Plus the byte-isolation fact underlying the 046 assessment: tagging a span
//! changes only the tagged slots' sched words, never the white neighbours.

use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, report_hazards, schedule};
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

const HDR: &str = ".entry t\n    .param u64 io\n    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n";

fn hazards(body: &str) -> Vec<cubit::scheduling_pass::HazardReport> {
    let src = format!("{HDR}{body}    EXIT ;\n");
    let f = parse_sass_file_str_strict(&src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    // Mirror the `cubit asm` flow: schedule() first, reallocate_barriers()
    // after (main.rs), then the hazard audit on the final control words.
    schedule(&mut insns, Some(&t120()));
    reallocate_barriers(&mut insns, Some(&t120()));
    report_hazards(&insns)
}

// A) frozen consumer `[B------:..:S01]` of a white LDG: the producer gets a
// write barrier from the auto pass, the frozen consumer never waits it.
#[test]
fn t_a_frozen_consumer_underwaited_white_load() {
    let hs = hazards(
        "    LDG.E R10, desc[UR4][R2.64] ;\n    [B------:R-:W-:-:S01] IADD3 R11, PT, PT, R10, 0x1, RZ ;\n",
    );
    let raw = hs.iter().find(|h| h.msg.contains("reads R10 <- 0x0020 LDG"));
    let h = raw.expect("frozen consumer of white LDG must be flagged");
    assert!(h.frozen, "finding touches a hand_sched insn -> frozen=true");
    assert!(h.msg.contains("NOT waited"), "RAW class, got: {}", h.msg);
}

#[test]
fn t_a_ctrl_all_white_is_quiet() {
    let hs = hazards(
        "    LDG.E R10, desc[UR4][R2.64] ;\n    IADD3 R11, PT, PT, R10, 0x1, RZ ;\n",
    );
    assert!(hs.is_empty(), "all-white schedule must be hazard-free: {:?}", hs.iter().map(|h| h.msg.clone()).collect::<Vec<_>>());
}

// B) the producer side: a frozen `[W-]` LDG carries no scoreboard cover; a
// white consumer right after it reads a stale value. Previously zero signal.
#[test]
fn t_b_frozen_bare_load_producer_nobar() {
    let hs = hazards(
        "    [B------:R-:W-:-:S01] LDG.E R10, desc[UR4][R2.64] ;\n    IADD3 R11, PT, PT, R10, 0x1, RZ ;\n",
    );
    let nobar = hs
        .iter()
        .find(|h| h.msg.contains("reads R10 <- 0x0020 LDG"));
    let h = nobar.expect("frozen bare-LDG producer read must be flagged");
    assert!(h.msg.contains("NO barrier"), "NOBAR class, got: {}", h.msg);
    assert!(h.frozen);
}

#[test]
fn t_b_nobar_respects_gap_floor() {
    // Same frozen bare LDG, but the user gave S15 and interposed stall so the
    // consumer's issue gap clears the 16cy floor: not a NOBAR finding.
    let hs = hazards(
        "    [B------:R-:W-:-:S15] LDG.E R10, desc[UR4][R2.64] ;\n    MOV R20, 0x0 ;\n    IADD3 R11, PT, PT, R10, 0x1, RZ ;\n",
    );
    assert!(
        !hs.iter().any(|h| h.msg.contains("NO barrier") && h.msg.contains("reads R10")),
        "gap >= floor must not fire NOBAR: {:?}", hs.iter().map(|h| h.msg.clone()).collect::<Vec<_>>()
    );
}

// Consistency: a fully-frozen kernel whose tags correctly wait the barrier is
// quiet for the RAW class of the frozen pair.
#[test]
fn t_c_frozen_pair_with_wait_is_quiet() {
    let hs = hazards(
        "    [B------:R-:W1:-:S01] LDG.E R10, desc[UR4][R2.64] ;\n    [B-1----:R-:W-:-:S10] IADD3 R11, PT, PT, R10, 0x1, RZ ;\n",
    );
    assert!(
        !hs.iter().any(|h| h.msg.contains("reads R10 <-")),
        "correctly-waited frozen pair must stay quiet: {:?}", hs.iter().map(|h| h.msg.clone()).collect::<Vec<_>>()
    );
}

// Byte-isolation pin (the assessment fact): a `[CC]` prefix freezes ONLY the
// sched field of its own slot; the surrounding white auto-schedule is
// invariant. Verified here at the pass level: white slots' control codes are
// identical with/without a tagged sibling.
#[test]
fn t_d_tag_inplace_never_touches_white_slots() {
    let body_white = "    ISETP.EQ.AND P4, PT, RZ, RZ, PT ;\n    MOV R40, 0x0 ;\n    IMAD.WIDE.U32 R92, R32, R81, RZ ;\n    IADD3.X R94, PT, PT, RZ, RZ, RZ, P0, P6 ;\n";
    let body_tagged = "    ISETP.EQ.AND P4, PT, RZ, RZ, PT ;\n    [B------:R-:W-:Y:S05] MOV R40, 0x0 ;\n    [B------:R-:W-:Y:S05] IMAD.WIDE.U32 R92, R32, R81, RZ ;\n    [B------:R-:W-:Y:S05] IADD3.X R94, PT, PT, RZ, RZ, RZ, P0, P6 ;\n";
    let run = |b: &str| {
        let src = format!("{HDR}{b}    EXIT ;\n");
        let f = parse_sass_file_str_strict(&src).unwrap();
        let mut insns = f.kernels[0].instructions.clone();
        schedule(&mut insns, Some(&t120()));
        insns.iter().map(|i| (i.addr, i.hand_sched, cubit::scheduling::encode_control_code(&i.ctrl))).collect::<Vec<_>>()
    };
    let w = run(body_white);
    let t = run(body_tagged);
    assert_eq!(w.len(), t.len());
    for ((addr, _, cw), (addr2, tz, ct)) in w.iter().zip(t.iter()) {
        assert_eq!(addr, addr2);
        if *tz { continue; } // tagged slots legitimately differ (verbatim tag)
        assert_eq!(cw, ct, "white slot @{:#x} control changed by a sibling tag", addr);
    }
}
