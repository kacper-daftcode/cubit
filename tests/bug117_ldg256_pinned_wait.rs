//! BUG-117 (sm120 registry TS2-LDG256-AUTOWAIT, i245 2026-08-24): the note's
//! primary claim (auto-ctrl allocates no dest waits for LDG.E.*.256 forms)
//! is ALREADY fixed on main (BUG-101/dfcfb0d span doctrine; verified end to
//! end across both tables, pins bug101 + bug111 t111_4). Their binary-side
//! experiment 5, however, exposed a REAL surviving hole: a hand_sched
//! `[CC]`-tagged variable-latency producer (verbatim champion tag with a
//! write barrier, e.g. `[B------:R4:W1:Y:S02] LDG.E.NA.ELL2.256...`) kept its
//! sched word verbatim, but reallocate_barriers() skipped hand_sched
//! producers, so AUTO consumers received NO wait bit — they read the
//! register file before the load retired (deterministic garbage limbs on
//! silicon; spacers cannot cover it, only a wait does). Same for a pinned
//! read barrier `R{b}` on a tagged memory op vs white late-operand
//! overwriters. These tests pin the fix: pinned producers become
//! fixed-colour barrier uses — their index is honoured verbatim (never
//! reallocated), white waiters get the wait injected, and the allocator
//! reserves the colour over the use's in-flight segments.
//!
//! Flow: parse -> schedule() -> reallocate_barriers() -> encode_instruction()
//! (the exact `cubit asm` production path; BUG-103/bug111 test idiom).

use cubit::encoder::encode_instruction;
use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, report_hazards, schedule};
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

struct Encoded {
    opcode_full: String,
    addr: u64,
    hand_sched: bool,
    upper32: u32,
}

fn pipeline_encode(src: &str, tab: &IsaTable) -> Vec<Encoded> {
    let f = parse_sass_file_str_strict(src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    schedule(&mut insns, Some(tab));
    reallocate_barriers(&mut insns, Some(tab));
    insns.iter()
        .map(|x| {
            let w = encode_instruction(x, tab)
                .unwrap_or_else(|e| panic!("encode failed for {}: {:?}", x.opcode_full, e));
            Encoded {
                opcode_full: x.opcode_full.clone(),
                addr: x.addr as u64,
                hand_sched: x.hand_sched,
                upper32: (w >> 96) as u32,
            }
        })
        .collect()
}

/// (stall, yield, wbar, rbar, wait) out of the encoded sched field.
fn d3(ctrl: &Encoded) -> (u8, u8, u8, u8, u8) {
    let code = (ctrl.upper32 >> 9) & 0x1FFFF;
    (
        (code & 0xF) as u8,
        ((code >> 4) & 1) as u8,
        ((code >> 5) & 7) as u8,
        ((code >> 8) & 7) as u8,
        ((code >> 11) & 0x3F) as u8,
    )
}

const HDR: &str = ".entry t\n    .param u64 io\n    S2R R10, SR_TID.X ;\n    LDCU.64 UR4, c[0x0][0x380] ;\n    IMAD.WIDE.U32 R10, R10, 0x20, RZ ;\n";

/// i245 experiment-5 verbatim shape: pinned W1/R4 LDG.256, white consumers of
/// both dest quads, white STG reader.
const EXP5: &str = "    [B------:R4:W1:Y:S02] LDG.E.NA.ELL2.256.STRONG.GPU R48, R52, desc[UR4][R10.64] ;\n    LOP3.LUT R62, R48, 0xf, RZ, 0xc0, !PT ;\n    LOP3.LUT R63, R54, 0xf, RZ, 0xc0, !PT ;\n    STG.E desc[UR4][R10.64], R62 ;\n";

#[test]
fn t117_1_pinned_ldg256_arms_white_consumers() {
    for tab in [t120(), t103()] {
        let src = format!("{HDR}{EXP5}    EXIT ;\n");
        let e = pipeline_encode(&src, &tab);
        let ldg = e.iter().find(|x| x.opcode_full.contains("LDG.E.NA.ELL2.256")).unwrap();
        assert!(ldg.hand_sched, "tagged load stays frozen");
        assert_eq!(
            d3(ldg),
            (2, 1, 1, 4, 0),
            "the author's tag is honoured VERBATIM on the pinned slot"
        );
        let l0 = e.iter().find(|x| x.opcode_full == "LOP3.LUT" && x.addr == ldg.addr + 0x10).unwrap();
        assert!(
            d3(l0).4 & (1 << 1) != 0,
            "first white consumer of the pinned .256 load must WAIT its barrier 1, got {:?}",
            d3(l0)
        );
        // Second white consumer may elide (barrier drained by the first wait)
        // but must never precede the drain.
        let l1 = e.iter().find(|x| x.opcode_full == "LOP3.LUT" && x.addr == ldg.addr + 0x20).unwrap();
        assert!(l1.addr > l0.addr, "program order preserved");
        let _ = l1;
    }
}

/// Only the SECOND quad is read by the white side: the wait must still land
/// (BUG-101 span wired into the pinned path).
#[test]
fn t117_2_pinned_ldg256_second_quad_only() {
    for tab in [t120(), t103()] {
        let body = "    [B------:R-:W3:Y:S02] LDG.E.NA.ELL2.256.STRONG.GPU R48, R52, desc[UR4][R10.64] ;\n    LOP3.LUT R63, R55, 0xf, RZ, 0xc0, !PT ;\n";
        let src = format!("{HDR}{body}    EXIT ;\n");
        let e = pipeline_encode(&src, &tab);
        let c = e.iter().find(|x| x.opcode_full == "LOP3.LUT").unwrap();
        assert!(
            d3(c).4 & (1 << 3) != 0,
            "second-quad white consumer must wait the pinned barrier 3, got {:?}",
            d3(c)
        );
        let ldg = e.iter().find(|x| x.opcode_full.contains("LDG.E.NA.ELL2.256")).unwrap();
        assert_eq!(d3(ldg).2, 3, "pinned W3 verbatim");
    }
}

/// The pinned barrier colour is RESERVED over its in-flight window: a white
/// load whose own use-window overlaps the pinned use must not be coloured
/// onto the pinned barrier (both consumers still covered).
#[test]
fn t117_3_allocator_respects_pinned_window() {
    for tab in [t120(), t103()] {
        let body = "    LDG.E.128 R40, desc[UR4][R10.64] ;\n    LOP3.LUT R60, R40, 0xf, RZ, 0xc0, !PT ;\n    [B------:R-:W1:Y:S02] LDG.E.NA.ELL2.256.STRONG.GPU R48, R52, desc[UR4][R10.64+0x40] ;\n    LDG.E.128 R44, desc[UR4][R10.64+0x80] ;\n    LOP3.LUT R62, R48, 0xf, RZ, 0xc0, !PT ;\n    LOP3.LUT R61, R44, 0xf, RZ, 0xc0, !PT ;\n";
        let src = format!("{HDR}{body}    EXIT ;\n");
        let e = pipeline_encode(&src, &tab);
        let pin = e.iter().find(|x| x.hand_sched && x.opcode_full.contains("LDG.E.NA.ELL2.256")).unwrap();
        let d_pin = d3(pin);
        assert_eq!(d_pin.2, 1, "pinned W1 verbatim");
        // white consumer of the pinned load waits bar 1
        let c62 = e.iter().find(|x| x.opcode_full == "LOP3.LUT" && x.addr == pin.addr + 0x20).unwrap();
        assert!(d3(c62).4 & (1 << 1) != 0, "pinned-load consumer waits bar1, got {:?}", d3(c62));
        // the white LDG.E.128 AFTER the pinned load (its consumer c61 is the
        // last instruction, inside the pinned window) must NOT take wb=1
        let l44 = e.iter().find(|x| x.opcode_full == "LDG.E.128" && x.addr == pin.addr + 0x10).unwrap();
        assert_ne!(d3(l44).2, 1, "white load inside the pinned window must keep off barrier 1, got {:?}", d3(l44));
        let c61 = e.iter().rev().find(|x| x.opcode_full == "LOP3.LUT").unwrap();
        assert!(d3(c61).4 & (1 << d3(l44).2) != 0, "white-load consumer waits its own barrier");
    }
}

/// Regression anchor: the fully-white .256 path (BUG-101 doctrine) is
/// untouched by the pinned extension — mixed-width batching keeps separate
/// colours for the .256 load and the .128 batch, every consumer covered.
#[test]
fn t117_4_white_path_unchanged() {
    for tab in [t120(), t103()] {
        let body = "    LDG.E.128 R40, desc[UR4][R10.64] ;\n    LDG.E.128 R44, desc[UR4][R10.64+0x40] ;\n    LDG.E.NA.ELL2.256.STRONG.GPU R48, R52, desc[UR4][R10.64+0x80] ;\n    LOP3.LUT R60, R40, 0xf, RZ, 0xc0, !PT ;\n    LOP3.LUT R61, R44, 0xf, RZ, 0xc0, !PT ;\n    LOP3.LUT R62, R48, 0xf, RZ, 0xc0, !PT ;\n    LOP3.LUT R63, R53, 0xf, RZ, 0xc0, !PT ;\n";
        let src = format!("{HDR}{body}    EXIT ;\n");
        let e = pipeline_encode(&src, &tab);
        let ldg256 = e.iter().find(|x| x.opcode_full.contains("LDG.E.NA.ELL2.256")).unwrap();
        let (s256, _, wb256, _, _) = d3(ldg256);
        assert!(wb256 < 7, "white .256 load must carry a write barrier");
        assert!(s256 >= 1);
        let c62 = e.iter().find(|x| x.opcode_full == "LOP3.LUT" && x.addr == ldg256.addr + 0x30).unwrap();
        assert!(d3(c62).4 & (1 << wb256) != 0, "quad0 consumer waits the .256 barrier");
        let ldg128s: Vec<&Encoded> = e.iter().filter(|x| x.opcode_full == "LDG.E.128").collect();
        assert_eq!(ldg128s.len(), 2);
        assert_eq!(d3(ldg128s[0]).2, d3(ldg128s[1]).2, "same-width consecutive batch shares one barrier");
        assert_ne!(d3(ldg128s[0]).2, wb256, "mixed widths never share a barrier");
    }
}

/// Pinned READ barrier arm: a tagged load claiming `R{b}` protects its
/// late-latched address registers against white overwriters.
#[test]
fn t117_5_pinned_read_bar_arms_white_overwriter() {
    for tab in [t120(), t103()] {
        let body = "    [B------:R4:W1:Y:S02] LDG.E.NA.ELL2.256.STRONG.GPU R48, R52, desc[UR4][R10.64] ;\n    LOP3.LUT R62, R48, 0xf, RZ, 0xc0, !PT ;\n    IADD3 R10, PT, PT, R10, 0x2000, RZ ;\n    STG.E desc[UR4][R10.64], R62 ;\n";
        let src = format!("{HDR}{body}    EXIT ;\n");
        let e = pipeline_encode(&src, &tab);
        let bump = e.iter().find(|x| x.opcode_full == "IADD3").unwrap();
        assert!(
            d3(bump).4 & (1 << 4) != 0,
            "white address-bump after the pinned R4 load must wait read-barrier 4, got {:?}",
            d3(bump)
        );
    }
}

/// Hazard-audit contract after the fix: the exp-5 shape is consumer-side
/// quiet (the waits now exist), while the AUTHOR's own under-waited source
/// (the tagged load's desc-UR / address reads) stays loudly reported —
/// frozen fields are never repaired, only named.
#[test]
fn t117_6_hazard_report_contract() {
    let src = format!("{HDR}{EXP5}    EXIT ;\n");
    let f = parse_sass_file_str_strict(&src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    let tab = t120();
    schedule(&mut insns, Some(&tab));
    reallocate_barriers(&mut insns, Some(&tab));
    let hs = report_hazards(&insns);
    assert!(
        !hs.iter().any(|h| h.msg.contains("reads R48 <-") || h.msg.contains("reads R54 <-")),
        "consumer-side RAW hazards must be REPAIRED (wait injected), got: {:?}",
        hs.iter().map(|h| h.msg.clone()).collect::<Vec<_>>()
    );
    assert!(
        hs.iter().any(|h| h.msg.contains("reads UR4 <-") && h.frozen),
        "the author's own under-waited desc source stays loudly reported, got: {:?}",
        hs.iter().map(|h| h.msg.clone()).collect::<Vec<_>>()
    );
}

/// Negative control for the new cover: a `[W-]`-tagged load has no pinned
/// barrier to wait — shape stays author-owned and loudly NOBAR-reported
/// (bug046 contract, unchanged).
#[test]
fn t117_7_wminus_tag_still_nobar_reported() {
    let body = "    [B------:R-:W-:-:S02] LDG.E.NA.ELL2.256.STRONG.GPU R48, R52, desc[UR4][R10.64] ;\n    LOP3.LUT R62, R48, 0xf, RZ, 0xc0, !PT ;\n";
    let src = format!("{HDR}{body}    EXIT ;\n");
    let f = parse_sass_file_str_strict(&src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    let tab = t120();
    schedule(&mut insns, Some(&tab));
    reallocate_barriers(&mut insns, Some(&tab));
    let hs = report_hazards(&insns);
    assert!(
        hs.iter().any(|h| h.msg.contains("NO barrier") && h.msg.contains("reads R48")),
        "bare tagged load must keep the NOBAR finding, got: {:?}",
        hs.iter().map(|h| h.msg.clone()).collect::<Vec<_>>()
    );
}
