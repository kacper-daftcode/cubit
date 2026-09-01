//! BUG-342 (sm120 registry NOTE_i290 2026-08-31; F2 queue 342-kand, fixed
//! F2-iter172): cubit's barrier allocator found loop-carried RAW consumers and
//! WAR overwriters only within the producer's INNERMOST enclosing loop. A
//! long-latency producer placed in a nested loop whose consumer sits in an
//! OUTER loop head (textually above the producer but below the outer top —
//! the loop-tail precompute idiom) registered NO use: it was emitted with
//! wbar=7 (no write barrier) while the outer-head consumer kept waiting the
//! barrier of the first-iteration prologue producer, i.e. a barrier last
//! armed on a different path. On sm120 silicon (4 warps, NT=128, L2-hot) the
//! consumer read stale lanes nondeterministically (29/128 exact). Fix: the
//! wrap scan walks the head regions of EVERY enclosing loop (innermost
//! first, fresh live set per region); WAR overwriter scan starts at the
//! OUTERMOST enclosing top; use segments pair each wrap waiter with its
//! tightest shared back-edge. Single-loop shapes are bit-identical to the
//! pre-fix allocation (regression pin t342_2).
//!
//! Flow: parse -> schedule() -> reallocate_barriers() -> ctrl fields read
//! directly (the `cubit asm` production path; bug117 test idiom), then one
//! encode pass to prove the scheduled forms remain encodable.

use cubit::encoder::encode_instruction;
use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, schedule};
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

struct Slot {
    text: String,
    wbar: u8,
    rbar: u8,
    wait: u8,
}

fn pipeline(src: &str, tab: &IsaTable) -> Vec<Slot> {
    let f = parse_sass_file_str_strict(src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    schedule(&mut insns, Some(tab));
    reallocate_barriers(&mut insns, Some(tab));
    insns
        .iter()
        .map(|x| Slot {
            text: x.opcode_full.clone() + &format!(" {:?}", x.operands),
            wbar: x.ctrl.write_bar,
            rbar: x.ctrl.read_bar,
            wait: x.ctrl.wait_mask,
        })
        .collect()
}

fn fst(slots: &[Slot], pat: &str, from: usize) -> usize {
    (from..slots.len())
        .find(|&i| slots[i].text.contains(pat))
        .unwrap_or_else(|| panic!("pattern {pat:?} not found from {from}"))
}

/// sm120 i290 shape: LDG.E.128 inside an INNER loop, consumed at the OUTER
/// loop head (textually above the producer). Prologue LDG covers iteration 1.
/// Pre-fix: tail LDG had wbar=7 and the consumer waited only the prologue's
/// barrier. Post-fix: tail LDG carries a write barrier and the consumer waits it.
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

/// Same register flow as HOLE but with a single (non-nested) loop: the
/// pre-fix allocator already protected this shape — pin NO DELTA semantics:
/// the consumer's mask covers exactly the tail producer's barrier AND the
/// prologue's barrier (two distinct colours, both waited).
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

/// WAR arm: the pointer of an inner-loop load is bumped at the OUTER loop
/// head. Pre-fix the loop-carried overwriter was missed (scan started at the
/// INNNERMOST top), leaving the late-latched address unprotected; post-fix
/// the overwriter waits the load's read barrier.
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

#[test]
fn t342_1_nested_tail_ldg_gets_barrier_waited_at_outer_head() {
    for tab in [t120(), t103()] {
        let s = pipeline(HOLE, &tab);
        let pro = fst(&s, "LDG.E.128", 0);
        let cons = fst(&s, "IMAD", pro + 1);
        let tail = fst(&s, "LDG.E.128", pro + 1);
        assert!(
            tail > cons,
            "shape drift: tail LDG must sit below the consumer"
        );
        assert_ne!(
            s[tail].wbar, 7,
            "loop-carried tail LDG must carry a write barrier"
        );
        let wb = s[tail].wbar;
        assert_ne!(
            s[cons].wait & (1 << wb),
            0,
            "outer-head consumer must wait the tail producer's barrier {wb}"
        );
    }
}

#[test]
fn t342_2_single_loop_wrap_semantics_unchanged() {
    for tab in [t120(), t103()] {
        let s = pipeline(SINGLE, &tab);
        let pro = fst(&s, "LDG.E.128", 0);
        let cons = fst(&s, "IMAD", pro + 1);
        let tail = fst(&s, "LDG.E.128", pro + 1);
        assert!(tail > cons);
        assert_ne!(s[tail].wbar, 7);
        assert_ne!(s[pro].wbar, 7);
        // Prologue and tail uses overlap at the consumer index -> distinct colours.
        assert_ne!(
            s[pro].wbar, s[tail].wbar,
            "overlapping wrap/prologue uses must not share a colour"
        );
        let mask = s[cons].wait;
        assert_ne!(
            mask & (1 << s[tail].wbar),
            0,
            "consumer must wait the tail barrier"
        );
        assert_ne!(
            mask & (1 << s[pro].wbar),
            0,
            "consumer must wait the prologue barrier (iter 1)"
        );
    }
}

#[test]
fn t342_3_hole_shape_consumer_waits_both_producers() {
    for tab in [t120(), t103()] {
        let s = pipeline(HOLE, &tab);
        let pro = fst(&s, "LDG.E.128", 0);
        let cons = fst(&s, "IMAD", pro + 1);
        let tail = fst(&s, "LDG.E.128", pro + 1);
        assert_ne!(s[pro].wbar, 7);
        assert_ne!(s[tail].wbar, 7);
        assert_ne!(s[pro].wbar, s[tail].wbar);
        let mask = s[cons].wait;
        assert_ne!(
            mask & (1 << s[pro].wbar),
            0,
            "first iteration still covered by prologue barrier"
        );
        assert_ne!(mask & (1 << s[tail].wbar), 0);
    }
}

#[test]
fn t342_4_outer_head_overwriter_waits_load_read_barrier() {
    for tab in [t120(), t103()] {
        let s = pipeline(WAR_NESTED, &tab);
        // outer-head R2 bump: the IADD3 whose operands mention R2 and imm 0x400
        let bump = (0..s.len())
            .find(|&i| {
                s[i].text.contains("IADD3")
                    && s[i].text.contains("Imm32(1024)")
                    && s[i].text.contains("num: 2")
            })
            .expect("outer-head R2 bump not found");
        let ldg = fst(&s, "LDG.E.128", 0);
        assert!(
            ldg > bump,
            "shape drift: load must sit below the outer-head bump"
        );
        assert_ne!(
            s[ldg].rbar, 7,
            "inner-loop load with an outer-head address overwriter must carry a read barrier"
        );
        let rb = s[ldg].rbar;
        assert_ne!(
            s[bump].wait & (1 << rb),
            0,
            "outer-head pointer bump must wait the load's read barrier {rb}"
        );
    }
}

#[test]
fn t342_5_straight_line_control_and_encodable() {
    // Control: no loops at all — the producer/consumer wait relation is a
    // forward-only use and unrelated instructions stay mask-free; the whole
    // scheduled stream must still encode (both tables).
    const STRAIGHT: &str = ".entry t
    .param u64 io
    LDC R6, c[0x0][0x28] ;
    LDG.E.128 R20, [R2.64] ;
    MOV R24, RZ ;
    IMAD R24, R20, R21, R24 ;
    EXIT ;
";
    for tab in [t120(), t103()] {
        let s = pipeline(STRAIGHT, &tab);
        let ldg = fst(&s, "LDG.E.128", 0);
        let cons = fst(&s, "IMAD", ldg + 1);
        assert_ne!(s[ldg].wbar, 7);
        assert_ne!(s[cons].wait & (1 << s[ldg].wbar), 0);
        let mov = fst(&s, "MOV", ldg + 1);
        assert_eq!(
            s[mov].wait, 0,
            "unrelated straight-line insn must not gain wait bits"
        );
        // Encodability of the scheduled forms (production encode path).
        let f = parse_sass_file_str_strict(HOLE).unwrap();
        let mut insns = f.kernels[0].instructions.clone();
        schedule(&mut insns, Some(&tab));
        reallocate_barriers(&mut insns, Some(&tab));
        for x in &insns {
            if x.hand_sched {
                continue;
            }
            encode_instruction(x, &tab)
                .unwrap_or_else(|e| panic!("encode failed for {}: {:?}", x.opcode_full, e));
        }
    }
}
