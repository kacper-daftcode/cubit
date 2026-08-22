//! BUG-072 (F2Q; sm120 REQ-063 i139/i140): `cubit sched` fail-closed on
//! FLO.U32 (31 uses in the hopb divstep body = ~61% of that kernel's time)
//! and POPC (safgcd lane-side) -- the M3.5 operand_roles.json table simply
//! had no FLO/POPC rows (`reg_xfer` known=false), and pred_liveness had no
//! VOTE family arm (`VOTE.ALL P1, !P0` loop-exits -> known=false in
//! Strict). sched never saw hopb: "31 instruction(s) with unknown operand
//! roles: FLO.U32 @0x27e0 ...".
//!
//! Fix at source (works for both problems):
//!   1. tables/operand_roles.json: +FLO, +POPC = class "alu" (dest-first
//!      ALU, same class semantics as IABS/MOV/I2FP; base-op scope covers
//!      the .SH variant too). Role table is include_str!-compiled, so the
//!      shipped sched/liveness passes follow the repo data only.
//!   2. src/pred_liveness.rs: P-domain "VOTE" arm -- first predicate
//!      operand is the warp-aggregate DEF, the rest are vote-source USEs;
//!      negation does not change the read, PT dest drops out. Active in
//!      both modes (predcheck.py has no VOTE arm; the certified corpus
//!      carries no VOTE, so G8a parity is untouched).
//! Both layers resolve ctrl-class via the grounded NEUTRAL_ALU fallback
//! (FLO/POPC/VOTE/VOTEU are base-op listed), so identity/list run clean.
//! Pins are repro-first: the sched test failed pre-fix with the sm120
//! error shape; reg/pred pins pin the exact transfer sets.

use cubit::parser::parse_sass;
use cubit::pred_liveness::{pred_xfer, XferMode};
use cubit::reg_liveness::reg_xfer;
use cubit::sass_file::parse_sass_file_str_strict;
use cubit::sched::{run_file, SchedMode};
use cubit::table::IsaTable;
use std::collections::BTreeSet;

fn v(xs: &[u8]) -> BTreeSet<u8> {
    xs.iter().copied().collect()
}

fn table() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

// ------------------------------------------------------- reg roles (layer 1)

#[test]
fn t_reg_roles_flo_popc() {
    // FLO.U32 Rd, Ra, imm  (sm120 R-form and I-form both in hopb)
    let ins = parse_sass("FLO.U32 R4, R8, 0x10 ;", 0).unwrap();
    let x = reg_xfer(&ins);
    assert!(x.known, "FLO.U32 reg xfer must be known post-fix");
    assert_eq!(x.rdefs, v(&[4]));
    assert_eq!(x.ruses, v(&[8]));

    let ins = parse_sass("FLO.U32 R4, R8, R3 ;", 0).unwrap();
    let x = reg_xfer(&ins);
    assert!(x.known);
    assert_eq!(x.rdefs, v(&[4]));
    assert_eq!(x.ruses, v(&[3, 8]));

    // .SH variant: same base op, same roles (REQ-063 explicitly).
    let ins = parse_sass("FLO.U32.SH R12, R20, R21 ;", 0).unwrap();
    let x = reg_xfer(&ins);
    assert!(x.known);
    assert_eq!(x.rdefs, v(&[12]));
    assert_eq!(x.ruses, v(&[20, 21]));

    // POPC Rd, Ra
    let ins = parse_sass("POPC R5, R9 ;", 0).unwrap();
    let x = reg_xfer(&ins);
    assert!(x.known, "POPC reg xfer must be known post-fix");
    assert_eq!(x.rdefs, v(&[5]));
    assert_eq!(x.ruses, v(&[9]));

    // PDF (pred-dest FLO twin shape does not exist; FLO/POPC never carry
    // preds) -- guard predicate still counts as a use in BOTH modes.
    let x = pred_xfer(
        &parse_sass("@P2 POPC R5, R9 ;", 0).unwrap(),
        XferMode::Compat,
    );
    assert!(x.known);
    assert_eq!(x.uses, v(&[2]));
}

// ------------------------------------------------------ pred VOTE (layer 2)

#[test]
fn t_pred_vote_arm() {
    // REQ shape: VOTE.ALL P1, !P0
    for mode in [XferMode::Compat, XferMode::Strict] {
        let x = pred_xfer(&parse_sass("VOTE.ALL P1, !P0 ;", 0).unwrap(), mode);
        assert!(x.known, "VOTE must be known in {mode:?} post-fix");
        assert_eq!(x.defs, v(&[1]));
        assert_eq!(x.uses, v(&[0]));
        assert!(x.udefs.is_empty() && x.uuses.is_empty());

        let x = pred_xfer(&parse_sass("VOTE.ANY P4, P3 ;", 0).unwrap(), mode);
        assert_eq!(x.defs, v(&[4]));
        assert_eq!(x.uses, v(&[3]));

        let x = pred_xfer(&parse_sass("VOTE.EQ P6, !P5 ;", 0).unwrap(), mode);
        assert_eq!(x.defs, v(&[6]));
        assert_eq!(x.uses, v(&[5]));

        // PT dest drops out of tracking; the source read stays.
        let x = pred_xfer(&parse_sass("VOTE.ALL PT, !P0 ;", 0).unwrap(), mode);
        assert!(x.defs.is_empty());
        assert_eq!(x.uses, v(&[0]));

        // Guard predicate is a plain use, both modes.
        let x = pred_xfer(&parse_sass("@P2 VOTE.ALL P1, !P3 ;", 0).unwrap(), mode);
        assert_eq!(x.defs, v(&[1]));
        assert_eq!(x.uses, v(&[2, 3]));
    }
}

// ---------------------------- fail-closed doctrine survives the new coverage

#[test]
fn t_unknown_still_fail_closed() {
    // An out-of-family register-carrying op must stay fail-closed.
    let ins = parse_sass("WIDGET.EXOTIC R4, R8, R3 ;", 0).unwrap();
    let x = reg_xfer(&ins);
    assert!(!x.known, "unknown reg op silently accepted");
    // An out-of-family pred-carrying op likewise (P domain).
    let ins = parse_sass("WIDGET.EXOTIC P1, !P0 ;", 0).unwrap();
    let x = pred_xfer(&ins, XferMode::Strict);
    assert!(!x.known, "unknown pred op silently accepted");
}

// ------------------------------------------- sm120 repro shape, end to end

#[test]
fn t_sched_identity_accepts_flo_popc_vote() {
    let src = ".entry k\n\
        \x20   ISETP.GT.AND P0, PT, R1, R2, PT ;\n\
        \x20   FLO.U32 R4, R8, 0x10 ;\n\
        \x20   FLO.U32 R6, R10, R3 ;\n\
        \x20   POPC R5, R9 ;\n\
        \x20   VOTE.ALL P1, !P0 ;\n\
        \x20   @P1 IADD3 R7, R4, R5, R6 ;\n\
        \x20   EXIT ;\n";
    let file = parse_sass_file_str_strict(src).unwrap();
    let r = run_file(src, SchedMode::Identity, &table());
    assert!(
        r.is_ok(),
        "sched identity must run clean post-fix: {:?}",
        r.err()
    );
    let rep = &r.unwrap().report.kernels[0];
    assert!(rep.unknown_ops.is_empty());
    assert!(rep.unknown_classes.is_empty());
    // Identity mode truthfully re-emits (no movers).
    assert_eq!(rep.moved, 0);
    // VOTE def/use chain is visible in the graph: P0 produced @0, consumed
    // @4; P1 produced @4, consumed by the guarded consumer @5. Pre-fix this
    // whole run bailed with the sm120 "unknown operand roles" shape.
    assert!(rep.edges_total >= 4, "graph too thin: {:?}", rep);
    let _ = file;
}
