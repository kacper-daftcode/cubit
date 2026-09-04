//! BUG-370 (F2 queue 370-kand LOW, registered F2-iter186 in the BUG-347
//! report): attribution/census of the 52 (+12 KernelB) CUBIT_VERIFY_LOOP
//! unresolved edges on the frozen rt98 corpus. The census (results/
//! cubitfix/370.md, work/bug370/census370.json) found the BUG-347 detector's
//! flat "any Reg/UReg operand in {BRA,BRX,BRXU,JMP,JMX,CALL}" heuristic
//! misflagged statically resolvable classes; the vendor ISA reference
//! (SM120_ISA_REFERENCE) grounds the target roles:
//!   - BRA = "Branch. PC-relative target" on EVERY form (incl. .DIV/.CONV
//!     with an auxiliary UR operand) -> static label target, resolvable;
//!     must NOT be flagged (rt98: 10 BRA.DIV KernelB + 10 BRA.CONV
//!     KernelA, all forward dispatch skips).
//!   - BRXU = "Indirect branch via uniform register" -> the UR is the TARGET
//!     base. Non-URZ base = genuinely data-dependent (38 rt98, still
//!     flagged as `RegTarget`); URZ base + raw immediate = constant-in-
//!     principle but unit-uninterpreted (6 rt98, new `ConstBase` class --
//!     still UNVERIFIED, honestly attributed).
//!   - static target outside the kernel / unresolved Label -> `OutTarget`.
//! rt98 totals post-classification: KernelA 52 -> 42 (36 RegTarget + 6
//! ConstBase), KernelB 12 -> 2 (RegTarget); classic counters untouched.
//!
//! Flow: parse -> schedule() -> reallocate_barriers() (the production path,
//! bug117/342/347 idiom), then verify_scoreboard_report() assertions.

use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, schedule, verify_scoreboard_report};
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn pipeline(src: &str, tab: &IsaTable) -> Vec<cubit::ir::Instruction> {
    let f = parse_sass_file_str_strict(src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    schedule(&mut insns, Some(tab));
    reallocate_barriers(&mut insns, Some(tab));
    insns
}

/// t370_1: BRA.DIV / BRA.CONV with an auxiliary URZ operand and a static
/// label target are NOT unresolved edges (vendor: BRA is PC-relative on every
/// form). Both forward and backward spellings must stay out of the count.
#[test]
fn t370_1_bra_aux_ur_unflagged() {
    const K: &str = ".entry t
    .param u64 io
    LDC R6, c[0x0][0x28] ;
    ISETP.GT.AND P0, PT, R6, 0x10, PT ;
    @P0 BRA SKIP ;
    IMAD R8, R7, 0x3, RZ ;
SKIP:
    BRA.DIV P0, URZ, AHEAD ;
    IMAD R9, R8, 0x5, RZ ;
AHEAD:
    BRA.CONV !P0, URZ, BACK ;
BACK:
    IMAD R10, R9, 0x7, RZ ;
    @!P0 BRA SKIP ;
    EXIT ;
";
    for tab in [t120(), t103()] {
        let insns = pipeline(K, &tab);
        let rep = verify_scoreboard_report(&insns, Some(&tab));
        assert_eq!(
            rep.unresolved_edges, 0,
            "BRA.DIV/BRA.CONV with aux UR must not be flagged: {rep:?}"
        );
    }
}

/// t370_2: BRXU.U with a NON-ZERO uniform base is a genuine register-indirect
/// target -> RegTarget class (the only flag pre-370 as well).
#[test]
fn t370_2_brxu_real_ur_reg_target() {
    const K: &str = ".entry t
    .param u64 io
    LDC R6, c[0x0][0x28] ;
    UMOV UR7, UR2 ;
    BRXU.U UR7, 0x30 ;
    EXIT ;
";
    for tab in [t120(), t103()] {
        let insns = pipeline(K, &tab);
        let rep = verify_scoreboard_report(&insns, Some(&tab));
        assert_eq!(rep.unresolved_edges, 1);
        assert_eq!(rep.unresolved_reg_target, 1);
        assert_eq!(rep.unresolved_const_base, 0);
        assert_eq!(rep.unresolved_outtarget, 0);
    }
}

/// t370_3: BRXU.U URZ, <imm> is the constant-base class: still UNVERIFIED
/// (total count kept) but attributed separately from RegTarget.
#[test]
fn t370_3_brxu_urz_const_base() {
    const K: &str = ".entry t
    .param u64 io
    LDC R6, c[0x0][0x28] ;
    BRXU.U URZ, 0x11 ;
    EXIT ;
";
    for tab in [t120(), t103()] {
        let insns = pipeline(K, &tab);
        let rep = verify_scoreboard_report(&insns, Some(&tab));
        assert_eq!(rep.unresolved_edges, 1);
        assert_eq!(rep.unresolved_reg_target, 0);
        assert_eq!(rep.unresolved_const_base, 1);
        assert_eq!(rep.unresolved_outtarget, 0);
    }
}

/// t370_4: static-target arms still fire: BRA with an out-of-kernel numeric
/// target -> OutTarget; JMX with a GPR register operand -> RegTarget.
#[test]
fn t370_4_outtarget_and_jmx_reg() {
    const OUT: &str = ".entry t
    .param u64 io
    LDC R6, c[0x0][0x28] ;
    BRA 0x9990 ;
    EXIT ;
";
    const JMX: &str = ".entry t
    .param u64 io
    LDC R6, c[0x0][0x28] ;
    JMX R8, LOOP ;
LOOP:
    EXIT ;
";
    for tab in [t120(), t103()] {
        let insns = pipeline(OUT, &tab);
        let rep = verify_scoreboard_report(&insns, Some(&tab));
        assert_eq!((rep.unresolved_edges, rep.unresolved_outtarget), (1, 1));
        assert_eq!(rep.unresolved_reg_target, 0);

        let insns = pipeline(JMX, &tab);
        let rep = verify_scoreboard_report(&insns, Some(&tab));
        assert_eq!((rep.unresolved_edges, rep.unresolved_reg_target), (1, 1));
        assert_eq!(rep.unresolved_outtarget, 0);
    }
}

/// t370_5: decomposition invariant (`unresolved_edges` == class sum, the
/// BUG-347 total contract) on a mixed kernel, AND the wrap walk still sees
/// through a BRA.DIV-carrying resolved loop: a loop-carried RAW across the
/// back-edge must remain catchable (the resolution machinery is unchanged).
#[test]
fn t370_5_decomposition_and_wrap_through_bradiv() {
    const MIX: &str = ".entry t
    .param u64 io
    LDC R6, c[0x0][0x28] ;
    BRXU.U UR7, 0x30 ;
    BRXU.U URZ, 0x11 ;
    BRA 0x9990 ;
    EXIT ;
";
    const WRAPDIV: &str = ".entry t
    .param u64 io
    LDC R6, c[0x0][0x28] ;
    LDG.E.128 R20, [R2.64] ;
LOOP_TOP:
    IMAD R24, R20, R21, R24 ;
    IADD3 R2, PT, PT, R2, 0x400, RZ ;
    LDG.E.128 R20, [R2.64] ;
    ISETP.GT.AND P0, PT, R6, 0x100, PT ;
    @P0 BRA.DIV P0, URZ, LOOP_TOP ;
    EXIT ;
";
    for tab in [t120(), t103()] {
        let insns = pipeline(MIX, &tab);
        let rep = verify_scoreboard_report(&insns, Some(&tab));
        assert_eq!(rep.unresolved_edges, 3);
        assert_eq!(
            rep.unresolved_edges,
            rep.unresolved_reg_target + rep.unresolved_const_base + rep.unresolved_outtarget
        );

        // allocator-good BRA.DIV loop verifies clean; corrupt the head
        // consumer's wait mask (BUG-342 shape) and the wrap pass MUST catch
        // it through the resolved BRA.DIV back-edge (zero unresolved edges).
        let mut bad = pipeline(WRAPDIV, &tab);
        let clean = verify_scoreboard_report(&bad, Some(&tab));
        assert_eq!(clean.unresolved_edges, 0, "BRA.DIV loop stays resolved");
        let n_ldg = bad
            .iter()
            .filter(|i| i.opcode_full.starts_with("LDG"))
            .count();
        assert_eq!(n_ldg, 2);
        // drop the tail LDG's barrier from the head IMAD's wait mask
        let tail_bar = bad
            .iter()
            .rev()
            .find(|i| i.opcode_full.starts_with("LDG"))
            .unwrap()
            .ctrl
            .write_bar;
        assert!(tail_bar < 6, "allocator armed the tail LDG");
        let mut it = bad.iter_mut().filter(|i| i.opcode == "IMAD");
        let imad = it.next().unwrap();
        imad.ctrl.wait_mask &= !(1 << tail_bar);
        let rep = verify_scoreboard_report(&bad, Some(&tab));
        assert!(
            rep.raw > 0 && rep.wrap_raw > 0,
            "wrap RAW through BRA.DIV back-edge must be caught: {rep:?}"
        );
    }
}
