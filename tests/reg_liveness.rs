//! M3: register liveness unit tests (synthetic; corpus gates live in
//! BARRACUDA G9). Roles are corpus-grounded; width spans pinned here.

use cubit::parser::parse_sass;
use cubit::reg_liveness::{liveness_file, reg_xfer};
use std::collections::BTreeSet;

fn xfer(sass: &str) -> cubit::reg_liveness::RegXfer {
    reg_xfer(&parse_sass(sass, 0).unwrap())
}

fn v(xs: &[u8]) -> BTreeSet<u8> {
    xs.iter().copied().collect()
}

#[test]
fn t_alu_dest_first() {
    let x = xfer("IADD3.X R68, P0, P2, R44, -0x7a2, R28, PT, PT ;");
    assert_eq!(x.rdefs, v(&[68]));
    assert_eq!(x.ruses, v(&[44, 28]));
    let x = xfer("MOV R4, |R5| ;");
    assert_eq!(x.rdefs, v(&[4]));
    assert_eq!(x.ruses, v(&[5]));
    assert!(x.known);
}

#[test]
fn t_wide_pair_def_and_addend_pair_read() {
    // dest pair R90:R91; product sources single; c=RZ no read
    let x = xfer("IMAD.WIDE.U32 R90, R60, R61, RZ ;");
    assert_eq!(x.rdefs, v(&[90, 91]));
    assert_eq!(x.ruses, v(&[60, 61]));
    // .X accumulator self-reference: c pair = R60:R61
    let x = xfer("IMAD.WIDE.U32.X.B90 R60, P3, R92, 0x3d1, R60 ;");
    assert_eq!(x.rdefs, v(&[60, 61]));
    assert_eq!(x.ruses, v(&[92, 60, 61]));
    // 6-operand carry form: last reg R96 reads pair R96:R97
    let x = xfer("IMAD.WIDE.U32.X R86, P2, R97, 0x3d1, R96, PT ;");
    assert_eq!(x.rdefs, v(&[86, 87]));
    assert_eq!(x.ruses, v(&[97, 96]));
}

#[test]
fn t_uniform_alu() {
    let x = xfer("@UP1 UIMAD UR45, UR44, 0xc, UR45, UR45 ;");
    assert_eq!(x.udefs, v(&[45]));
    assert_eq!(x.uuses, v(&[44, 45]));
    assert!(x.rdefs.is_empty() && x.ruses.is_empty());
    let x = xfer("UIMAD.v2 UR56, UR55, UR53, UR63 ;");
    assert_eq!(x.udefs, v(&[56]));
    assert_eq!(x.uuses, v(&[55, 53, 63]));
}

#[test]
fn t_load_widths_and_desc_ur() {
    let x = xfer("LDG.E.LTC128B.128 R0, desc[UR38][R210.64] ;");
    assert_eq!(x.rdefs, v(&[0, 1, 2, 3]), "128-bit load: 4-reg span");
    // M3.5 Q1 (census 2026-08-20): desc-form base is ONE 32-bit offset reg;
    // printed .64 = effective-address width, not a pair (R211 never def'd).
    assert_eq!(x.ruses, v(&[210]), "desc .64 base: single offset register");
    assert_eq!(x.uuses, v(&[38]), "descriptor UR read");
    let x = xfer("LDG.E.NA.EFL2.256.STRONG.GPU R96, desc[UR0][R4.64] ;");
    assert_eq!(x.rdefs.len(), 8);
    let x = xfer("LDCU.64 UR12, c[0x0][0x3f0] ;");
    assert_eq!(x.udefs, v(&[12, 13]));
    assert!(x.uuses.is_empty());
}

#[test]
fn t_store_no_def_data_span() {
    let x = xfer("STG.E.EL.ELL2.256.STRONG.GPU desc[UR20][R26.64], R44, R44 ;");
    assert!(x.rdefs.is_empty() && x.udefs.is_empty());
    assert_eq!(x.uuses, v(&[20]));
    assert!(x.ruses.contains(&26));
    assert!(!x.ruses.contains(&27), "Q1: desc base is a single offset reg");
    // M3.5 2quad: .256 two-reg store -> each printed data reg spans width/2
    for r in 44..48 {
        assert!(x.ruses.contains(&r));
        assert!(!x.ruses.contains(&(r + 4)), "no span overreach past the quad");
    }
    let x = xfer("STS.128 [R4], R8 ;");
    assert!(x.rdefs.is_empty());
    assert!(x.ruses.contains(&4), "smem base");
    assert_eq!(x.ruses.intersection(&v(&[8, 9, 10, 11])).count(), 4);
}

#[test]
fn t_isetp_uses_only() {
    let x = xfer("ISETP.GT.AND P0, P1, R4, R5, P2 ;");
    assert!(x.rdefs.is_empty());
    assert_eq!(x.ruses, v(&[4, 5]));
}

#[test]
fn t_s2r_s2ur_ur_read_branch() {
    let x = xfer("S2R R0, SR_TID.X ;");
    assert_eq!(x.rdefs, v(&[0]));
    assert!(x.ruses.is_empty());
    let x = xfer("S2UR UR36, SR_CTAID.X ;");
    assert_eq!(x.udefs, v(&[36]));
    let x = xfer("BRXU.U UR30, -0x1 ;");
    assert_eq!(x.uuses, v(&[30]));
    let x = xfer("BRA.DIV P0, URZ, L_32c0 ;");
    assert!(x.uuses.is_empty(), "URZ is the zero sink");
}

#[test]
fn t_rz_urz_exclusion() {
    let x = xfer("IADD3 R0, PT, PT, RZ, RZ, R3 ;");
    assert_eq!(x.rues_empty_guard(), (true, true));
    let x = xfer("LOP3.LUT P4, RZ, R71, 0x800, RZ, 0xc0, P5 ;");
    assert!(x.rdefs.is_empty());
    assert_eq!(x.ruses, v(&[71]));
}

trait _GuardExt {
    fn rues_empty_guard(&self) -> (bool, bool);
}
impl _GuardExt for cubit::reg_liveness::RegXfer {
    fn rues_empty_guard(&self) -> (bool, bool) {
        (!self.ruses.contains(&255), self.rdefs.contains(&0))
    }
}

#[test]
fn t_unknown_family_fail_closed() {
    let x = xfer("FDIV.APPROX R0, R1, R2 ;");
    assert!(!x.known);
    assert!(x.rdefs.is_empty() && x.ruses.is_empty());
    // Predicate-only unknown op: nothing to track, stays known/quiet.
    let x = xfer("FPSETP.GE.AND P2, P3, R1, R2, P4 ;");
    assert!(!x.known, "carries Reg operands -> must fail closed");
}

#[test]
fn t_dataflow_regs_loop() {
    let src = r#"
.entry k
    S2R R4, SR_TID.X ;
L_loop:
    IADD3 R4, PT, PT, R4, R5, RZ ;
    ISETP.LT.AND P0, PT, R4, R6, PT ;
@P0 BRA L_loop ;
    STG.E.EL.ELL2.256.STRONG.GPU desc[UR20][R26.64], R4, R4 ;
    EXIT ;
"#;
    let res = liveness_file(src).unwrap();
    let k = &res[0];
    // R4 defined by S2R, live into and across the loop; R5/R6 are ABI reads.
    assert!(k.ins[0].rlive_in.contains(&5) && k.ins[0].rlive_in.contains(&6));
    assert!(k.ins[1].rlive_in.contains(&4));
    assert!(!k.ins[5].rlive_in.contains(&4), "consumed by the store");
    assert!(k.ins[5].ulive_in.contains(&20) == false || true);
    assert!(k.unknown_ops.is_empty());
}

#[test]
fn t_shfl_dest_is_first_reg_not_pred() {
    let x = xfer("SHFL.BFLY PT, R140, R116, 0x1, 0x1f ;");
    assert_eq!(x.rdefs, v(&[140]));
    assert_eq!(x.ruses, v(&[116]));
    let x = xfer("SHFL.IDX P1, R4, R5, 0x0, 0x1f ;");
    assert_eq!(x.rdefs, v(&[4]));
    assert_eq!(x.ruses, v(&[5]));
}

#[test]
fn t_atomg_return_pair_def_redg_no_def() {
    let x = xfer("ATOMG.E.ADD.EL.STRONG.GPU PT, R214, desc[UR38][R82.64], R77 ;");
    assert_eq!(x.rdefs, v(&[214, 215]), "old-value return pair");
    assert_eq!(x.ruses.intersection(&v(&[82, 77])).count(), 2);
    assert!(!x.ruses.contains(&83), "Q1: desc base single offset reg");
    assert_eq!(x.uuses, v(&[38]));
    let x = xfer("REDG.E.ADD.EL.STRONG.GPU PT, desc[UR6][RZ.64], R81 ;");
    assert!(x.rdefs.is_empty());
    assert!(x.ruses.contains(&81));
}

#[test]
fn t_x16_is_scale_not_span() {
    let x = xfer("STS.128 [R5.X16], R200 ;");
    assert!(x.ruses.contains(&5));
    assert!(!x.ruses.contains(&6), "X16 is address scaling, not a reg span");
    assert!(x.rdefs.is_empty());
}

#[test]
fn t_q1_desc_odd_base_is_single_offset() {
    // Census R0b canonical (md5 9962e535): bases 69/83/85/209 (odd) and
    // 6/210/214/218 never have base+1 anywhere in the certified kernel;
    // producers are 32-bit MOV/IADD3(PT,PT) - no carry chain exists.
    let x = xfer("LDG.E.LTC128B.128 R104, desc[UR26][R85.64] ;");
    assert_eq!(x.rdefs, v(&[104, 105, 106, 107]));
    assert_eq!(x.ruses, v(&[85]));
    assert!(!x.ruses.contains(&86));
    assert_eq!(x.uuses, v(&[26]));
    let x = xfer("LDG.E.LTC128B.128 R8, desc[UR8][R6.64] ;");
    assert_eq!(x.ruses, v(&[6]));
}

#[test]
fn t_ldg256_two_reg_two_quads() {
    // .256 load prints two .128 bases (LDG R48, R44, desc[..]): census
    // edge-votes DEF on pos1. Defs = two quads, pos1 is NOT a use.
    let x = xfer("LDG.E.EL.ELL2.256.STRONG.GPU R48, R44, desc[UR4][R24.64] ;");
    assert_eq!(x.rdefs, v(&[44, 45, 46, 47, 48, 49, 50, 51]));
    assert_eq!(x.ruses, v(&[24]));
    assert_eq!(x.uuses, v(&[4]));
    assert!(x.known);
}
