//! b8 PHASE-1 pins: canonical pricing chain (render -> reparse -> credit_of)
//! used by the profiler must price identically to the M4.6 scheduler's
//! direct credit_of on parsed text, and the readback must be fail-visible.

use cubit::sched::CostModel;
use cubit::IsaTable;

fn table_103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn cost_103a() -> CostModel {
    CostModel::load(std::path::Path::new("tables/cost_sm103a.json")).unwrap()
}

fn credits_of(cost: &CostModel, sass: &str) -> (f64, bool) {
    let ins = cubit::parse_sass(sass, 0).unwrap();
    let mut d = 0usize;
    let c = cost.credit_of(&ins, &mut d);
    (c, d > 0)
}

/// Candidate-order pin: full opcode beats base+modifier beats base.
#[test]
fn b8_credit_candidate_order() {
    let cost = cost_103a();
    let (c_full, _) = credits_of(&cost, "IMAD.WIDE.U32.X R4, R5, R6, R7, R8;");
    assert_eq!(c_full, 2.0, "IMAD.WIDE.U32.X must price via IMAD.WIDE=2");
    let (c_base, d_base) = credits_of(&cost, "IMAD R4, R5, R6, R7;");
    assert_eq!(c_base, 1.0);
    assert!(!d_base);
    // unpriced-but-real op hits the counted default (tripwire semantics)
    let (c_ldg, d_ldg) = credits_of(&cost, "LDG.E R4, [R6.64];");
    assert_eq!(c_ldg, 1.0, "credits_default=1 in tables/cost_sm103a.json");
    assert!(d_ldg, "LDG has no credit row -> counted default");
    // WIDE pair: UIMAD.WIDE prices 2 like IMAD.WIDE
    let (c_uwide, _) = credits_of(&cost, "UIMAD.WIDE.U32 R4, UR5, R6, R7;");
    assert_eq!(c_uwide, 2.0);
}

/// Round-trip pricing pin: word -> decode -> render -> reparse -> credit_of
/// gives the same credit and the same opcode_full as direct text parsing.
#[test]
fn b8_decode_canon_price_eq_text() {
    let t = table_103a();
    let idx = cubit::decoder::DecodeIndex::build(&t);
    let cost = cost_103a();
    for sass in [
        "IMAD.WIDE.U32 R4, R5, R6, R7;",
        "IMAD R4, R5, R6, R7;",
        "IADD3 R4, PT, PT, R5, R6, R7;",
        "FFMA R4, R5, R6, R7;",
    ] {
        let (bytes, n) = cubit::assemble(sass, 0, &t).unwrap();
        assert_eq!(n, 1);
        let lo = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let code = ((hi as u128) << 64) | (lo as u128);
        let inst = idx.decode(code, 0, &t).unwrap();
        let line = cubit::printer::to_sass(&inst);
        let ins_text = cubit::parse_sass(sass, 0).unwrap();
        let ins_re = cubit::parse_sass(&line, inst.addr).unwrap();
        let (mut d1, mut d2) = (0usize, 0usize);
        let c1 = cost.credit_of(&ins_text, &mut d1);
        let c2 = cost.credit_of(&ins_re, &mut d2);
        assert_eq!(c1, c2, "credit drift text-vs-readback for {sass}");
        assert_eq!(d1, d2, "defaulted drift for {sass}");
        assert_eq!(ins_text.opcode_full, ins_re.opcode_full,
                   "opcode_full drift text-vs-readback for {sass} (render: {line})");
    }
}

/// Control-word readback: decoder exposes the embedded stall/yield/bars
/// fields; UNKNOWN words stay fail-visible (never silently priced).
#[test]
fn b8_ctrl_fields_present_and_unknown_loud() {
    let t = table_103a();
    let idx = cubit::decoder::DecodeIndex::build(&t);
    let (bytes, _) = cubit::assemble("IMAD R4, R5, R6, R7;", 0, &t).unwrap();
    let lo = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let hi = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let inst = idx.decode(((hi as u128) << 64) | (lo as u128), 0, &t).unwrap();
    // scheduling-pass-authored control present, fields readable
    let _ = inst.ctrl.stall;
    let _ = inst.ctrl.yield_flag;
    let _ = inst.ctrl.write_bar;
    let _ = inst.ctrl.read_bar;
    let _ = inst.ctrl.wait_mask;
    // garbage word must NOT decode (fail-closed -> UNKNOWN row upstream)
    assert!(idx.decode(u128::MAX, 0, &t).is_err());
}
