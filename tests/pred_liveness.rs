//! M2: predicate liveness pass unit tests (synthetic kernels; certified
//! corpus parity lives in the BARRACUDA G8 gates).

use cubit::pred_liveness::{XferMode, cfg_successors, liveness_file, pred_xfer};
use cubit::parser::parse_sass;

fn xfer(sass: &str) -> cubit::pred_liveness::PredXfer {
    let ins = parse_sass(sass, 0).unwrap();
    pred_xfer(&ins, XferMode::Compat)
}

fn xfer_strict(sass: &str) -> cubit::pred_liveness::PredXfer {
    let ins = parse_sass(sass, 0).unwrap();
    pred_xfer(&ins, XferMode::Strict)
}

fn v(xs: &[u8]) -> std::collections::BTreeSet<u8> {
    xs.iter().copied().collect()
}

#[test]
fn t_iadd3_dual_carry_out() {
    let x = xfer("IADD3 R0, P0, P1, R1, R2, R3 ;");
    assert_eq!(x.defs, v(&[0, 1]));
    assert!(x.uses.is_empty());
    assert!(x.known);
}

#[test]
fn t_iadd3x_carry_in_read() {
    let x = xfer("IADD3.X R0, P0, P1, R1, R2, R3, P2, P3 ;");
    assert_eq!(x.defs, v(&[0, 1]));
    assert_eq!(x.uses, v(&[2, 3]));
    // PT sinks are never tracked.
    let x2 = xfer("IADD3.X.RCNEG R68, P0, P2, R44, -0x7a2, R28, PT, PT ;");
    assert_eq!(x2.defs, v(&[0, 2]));
    assert!(x2.uses.is_empty());
}

#[test]
fn t_isetp_writes_two_reads_combine() {
    let x = xfer("ISETP.GT.AND P0, P1, R4, R5, P2 ;");
    assert_eq!(x.defs, v(&[0, 1]));
    assert_eq!(x.uses, v(&[2]));
}

#[test]
fn t_imad_wide_x_forms() {
    let x = xfer("IMAD.WIDE.U32 R4, P2, R96, R97, RZ ;");
    assert_eq!(x.defs, v(&[2]));
    assert!(x.uses.is_empty());
    let x = xfer("IMAD.WIDE.U32.X R4, P2, R96, R97, RZ, P3 ;");
    assert_eq!(x.defs, v(&[2]));
    assert_eq!(x.uses, v(&[3]));
    // .B90 modifier keeps WIDE.X semantics by modifier, not name order.
    let x = xfer("IMAD.WIDE.U32.X.B90 R86, P2, R97, 0x3d1, R96, PT ;");
    assert_eq!(x.defs, v(&[2]));
    assert!(x.uses.is_empty());
    let x = xfer("@P3 IMAD.X R66, R8, R100, R93, P2 ;");
    assert!(x.defs.is_empty());
    assert_eq!(x.uses, v(&[2, 3])); // guard + carry-in
}

#[test]
fn t_lop3_forms_and_pand() {
    let x = xfer("LOP3.LUT P0, RZ, R1, R2, R3, 0xfc, P1 ;");
    assert_eq!(x.defs, v(&[0]));
    assert_eq!(x.uses, v(&[1]));
    let x = xfer("LOP3.LUT.PAND P4, RZ, R71, 0x800, RZ, 0xc0, P5 ;");
    assert_eq!(x.defs, v(&[4]));
    assert_eq!(x.uses, v(&[5]));
    // No destination predicate: last predicate is the AND-input.
    let x = xfer("LOP3.LUT R0, R1, R2, 0xfc, P3 ;");
    assert!(x.defs.is_empty());
    assert_eq!(x.uses, v(&[3]));
}

#[test]
fn t_plop3_strict_delta_third_input() {
    // Compat mirrors predcheck.py exactly: reads Pa,Pb only.
    let c = xfer("PLOP3.LUT P0, PT, P1, P2, P3, 0xfe, 0x0 ;");
    assert_eq!(c.defs, v(&[0]));
    assert_eq!(c.uses, v(&[1, 2]));
    // Strict additionally reads Pc (superset => more conservative).
    let s = xfer_strict("PLOP3.LUT P0, PT, P1, P2, P3, 0xfe, 0x0 ;");
    assert_eq!(s.defs, v(&[0]));
    assert_eq!(s.uses, v(&[1, 2, 3]));
}

#[test]
fn t_voteu_shfl_imnmx_atomg_bra() {
    let x = xfer("VOTEU.ANY UP0, P0 ;");
    assert_eq!(x.defs, v(&[0]));
    let xs = xfer_strict("VOTEU.ANY UP0, P0 ;");
    assert_eq!(xs.udefs, v(&[0]));
    assert!(matches!(xfer("VOTEU.ANY UP0, P0 ;").udefs.len(), 0));

    let x = xfer("SHFL.BFLY PT, R140, R116, 0x1, 0x1f ;");
    assert!(x.defs.is_empty()); // PT dropped
    let x = xfer("SHFL.IDX P1, R4, R5, 0x0, 0x1f ;");
    assert_eq!(x.defs, v(&[1]));

    let x = xfer("IMNMX.S64 P0, P0, |R218|, R218, 0x3ffff, PT, P0 ;");
    assert_eq!(x.defs, v(&[0]));
    assert_eq!(x.uses, v(&[0]));

    let x = xfer("ATOMG.E.ADD.EL.STRONG.GPU PT, R214, desc[UR38][R82.64], R77 ;");
    assert!(x.defs.is_empty());
    let x = xfer("REDG.E.ADD.EL.STRONG.GPU P2, R4, desc[UR6][RZ.64], R8 ;");
    assert_eq!(x.defs, v(&[2]));

    let x = xfer("BRA.DIV P0, URZ, L_32c0 ;");
    assert_eq!(x.defs, v(&[0]));
}

#[test]
fn t_plain_bra_pred_operand_strict_use() {
    // Era frozen decode: `BRA PT, L_2160` -- the operand is the branch
    // condition. Compat keeps the reference's silence (empty, known),
    // Strict reads it as a use (PT drops as the sink; try P2 as well).
    let c = xfer("BRA PT, L_2160 ;");
    assert!(c.known && c.defs.is_empty() && c.uses.is_empty());
    let s = xfer_strict("BRA PT, L_2160 ;");
    assert!(s.known && s.defs.is_empty() && s.uses.is_empty()); // PT = sink
    let s = xfer_strict("BRA P2, L_2160 ;");
    assert!(s.known && s.uses == v(&[2]));
    let c = xfer("BRA P2, L_2160 ;");
    assert!(c.known && c.uses.is_empty(), "compat mirrors the reference");
}

#[test]
fn t_uniform_domain_strict_only() {
    let c = xfer("UISETP.GE.AND UP0, UPT, UR29, UR35, UPT ;");
    assert!(c.udefs.is_empty() && c.uuses.is_empty() && c.known);
    let s = xfer_strict("UISETP.GE.AND UP0, UP1, UR29, UR35, UP2 ;");
    assert_eq!(s.udefs, v(&[0, 1]));
    assert_eq!(s.uuses, v(&[2]));

    let s = xfer_strict("UIADD3.X UR53, UP3, UP4, UR2, 0xa, URZ, UP5 ;");
    assert_eq!(s.udefs, v(&[3, 4]));
    assert_eq!(s.uuses, v(&[5]));

    let s = xfer_strict("ULOP3.LUT UP1, UR63, UR19, 0x1, UR63, 0xc0, !UP2 ;");
    assert_eq!(s.udefs, v(&[1]));
    assert_eq!(s.uuses, v(&[2]));

    let s = xfer_strict("@UP4 IADD3 R0, P0, PT, R1, R2, R3 ;");
    assert_eq!(s.uuses, v(&[4]));
    assert_eq!(s.defs, v(&[0]));
}

#[test]
fn t_unknown_family_fail_closed() {
    // Predicate operand in an unrecognized family -> known=false, operand
    // sets empty; guard knowledge retained.
    let x = xfer("@P1 FPSETP.GE.AND P2, P3, R1, R2, P4 ;");
    assert!(!x.known);
    assert!(x.defs.is_empty());
    assert_eq!(x.uses, v(&[1]), "guard use retained on unknown-family");
}

#[test]
fn t_cfg_edges() {
    let src = r#"
.entry k
    IADD3 R0, P0, PT, R1, R2, R3 ;
@P0 BRA L_done ;
    ISETP.GT.AND P1, PT, R0, R1, PT ;
L_done:
    EXIT ;
"#;
    let file = cubit::sass_file::parse_sass_file_str_strict(src).unwrap();
    let ins = &file.kernels[0].instructions;
    // guarded BRA: branch target + fallthrough
    assert_eq!(cfg_successors(ins, 1), vec![3, 2]);
    // fallthrough plain
    assert_eq!(cfg_successors(ins, 0), vec![1]);
    // EXIT terminal
    assert!(cfg_successors(ins, 3).is_empty());
}

#[test]
fn t_cfg_brxu_abs_and_u() {
    let src = r#"
.entry k
    S2R R4, SR_TID.X ;
    BRXU 0x20 ;
    IADD3 R0, PT, PT, R1, R2, R3 ;
    BRXU.U URZ, 0x11 ;
    EXIT ;
"#;
    let file = cubit::sass_file::parse_sass_file_str_strict(src).unwrap();
    let ins = &file.kernels[0].instructions;
    assert_eq!(cfg_successors(ins, 1), vec![2], "BRXU abs -> addr/16 idx");
    assert_eq!(cfg_successors(ins, 3), vec![4], "BRXU.U fallthrough only");
}

#[test]
fn t_dataflow_loop_backedge() {
    // P1 defined before the loop, read inside it, redefined inside; the
    // backedge must keep P1 live at the loop head until the redefine.
    let src = r#"
.entry k
    ISETP.GT.AND P1, PT, R0, R1, PT ;
L_loop:
    IADD3.X R2, P2, PT, R2, R3, R4, PT, P1 ;
@P2 BRA L_loop ;
    EXIT ;
"#;
    let res = liveness_file(src, XferMode::Compat).unwrap();
    let k = &res[0];
    assert_eq!(k.ins[0].live_out, v(&[1]));
    assert_eq!(k.ins[1].live_in, v(&[1]), "P1 live at loop head");
    assert!(k.ins[3].live_in.is_empty());
}

#[test]
fn t_strict_parse_fails_closed_on_garbage() {
    // "@ P0" is not a valid guard lexeme, so the line is structurally unparseable.
    let src = ".entry k\n    @ P0 IADD3 R0, P0, PT, R1, R2, R3 ;\n";
    assert!(cubit::sass_file::parse_sass_file_str(src).unwrap().kernels[0]
        .instructions
        .is_empty());
    assert!(cubit::sass_file::parse_sass_file_str_strict(src).is_err());
}

#[test]
fn t_liveness_file_unknown_list() {
    let src = r#"
.entry k
    FPSETP.GE.AND P2, P3, R1, R2, P4 ;
    EXIT ;
"#;
    let res = liveness_file(src, XferMode::Compat).unwrap();
    assert_eq!(res[0].unknown_ops.len(), 1);
    assert!(res[0].unknown_ops[0].contains("FPSETP"));
}
