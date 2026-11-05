//! BUG-480 (session V's "BUG gpr128", 2026-11-04; fixed 2026-11-05): the scheduler keyed
//! registers as `(uniform, u8)` with vector predicates at `128 + n`, so every GPR R128..R254
//! was taken for a predicate: a load into R128+ got no scoreboard / its consumers no wait
//! (`LDG.E.64 R128` → `F2FP … R184, R128` with `[B------]`), a store whose data lived in
//! R128+ got no read barrier (`STS.128 [R84], R184` then `F2FP … R184` three instructions
//! later), and a write to R128..R134 silently "redefined" P0..P6 for the predicate-latency
//! model. Session V kept its kernel in R0–R125 because of this.
//!
//! Fix: predicates live at `PRED_KEY + n` (= 256 + n) in a `u16` key space; every
//! `< 128` / `>= 128` register-class test in `scheduling_pass.rs` became a `PRED_KEY`
//! test; the per-key tables were already 256 wide. Pins: the R128+ kernel and its R<128
//! twin (register numbers are the only difference in the text) get IDENTICAL control
//! codes (write/read barriers, wait masks, stalls).

use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, schedule};
use cubit::table::IsaTable;
use cubit::Instruction;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn pipeline(src: &str) -> Vec<Instruction> {
    let f = parse_sass_file_str_strict(src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    let tab = t120();
    schedule(&mut insns, Some(&tab));
    reallocate_barriers(&mut insns, Some(&tab));
    insns
}

fn ctrl_of(insns: &[Instruction]) -> Vec<(String, u8, u8, u8, u8, bool)> {
    insns
        .iter()
        .map(|x| {
            (
                x.opcode_full.clone(),
                x.ctrl.write_bar,
                x.ctrl.read_bar,
                x.ctrl.wait_mask,
                x.ctrl.stall,
                x.ctrl.yield_flag,
            )
        })
        .collect()
}

fn idx_of(insns: &[Instruction], op_full: &str, nth: usize) -> usize {
    insns
        .iter()
        .enumerate()
        .filter(|(_, x)| x.opcode_full == op_full)
        .nth(nth)
        .map(|(i, _)| i)
        .unwrap_or_else(|| panic!("no {op_full} #{nth}"))
}

/// RAW: a load into R128 (pair R128:R129) consumed by an ALU op — the load must carry a
/// write barrier and the consumer must wait it, exactly like the R28 twin.
const RAW_HI: &str = "\
.entry t
    .reg R0-R199
    .param u64 io
    LDG.E.64 R128, desc[UR4][R2.64] ;
    IADD3 R6, PT, PT, R128, 0x1, RZ ;
    IADD3 R7, PT, PT, R129, 0x1, RZ ;
    STG.E.64 desc[UR4][R4.64], R6 ;
    EXIT ;
";

#[test]
fn t480_1_raw_wait_for_r128_load() {
    let hi = pipeline(RAW_HI);
    let lo = pipeline(&RAW_HI.replace("R128", "R28").replace("R129", "R29"));
    let ldg = idx_of(&hi, "LDG.E.64", 0);
    let cons = idx_of(&hi, "IADD3", 0);
    let wb = hi[ldg].ctrl.write_bar;
    assert!(wb < 6, "LDG.E.64 R128 must carry a write barrier (got W{wb})");
    assert!(
        (hi[cons].ctrl.wait_mask >> wb) & 1 == 1,
        "consumer of R128 must wait W{wb} (wait_mask {:#04x})",
        hi[cons].ctrl.wait_mask
    );
    assert_eq!(ctrl_of(&hi), ctrl_of(&lo), "R128 kernel must schedule like its R28 twin");
}

/// WAR: a store whose data quad is R184..R187 is followed by a writer of R184 — the store
/// must carry a read barrier and the writer must wait it, exactly like the R84 twin.
const WAR_HI: &str = "\
.entry t
    .reg R0-R199
    .param u64 io
    MOV R184, 0x1 ;
    MOV R185, 0x2 ;
    MOV R186, 0x3 ;
    MOV R187, 0x4 ;
    STS.128 [R8], R184 ;
    MOV R184, RZ ;
    MOV R185, RZ ;
    EXIT ;
";

#[test]
fn t480_2_war_read_barrier_for_r184_store_data() {
    let hi = pipeline(WAR_HI);
    let lo = pipeline(&WAR_HI.replace("R18", "R8"));
    let sts = idx_of(&hi, "STS.128", 0);
    let ow = idx_of(&hi, "MOV", 4); // MOV R184, RZ
    let rb = hi[sts].ctrl.read_bar;
    assert!(rb < 6, "STS.128 [..], R184 must carry a read barrier (got R{rb})");
    assert!(
        (hi[ow].ctrl.wait_mask >> rb) & 1 == 1,
        "overwriter of R184 must wait R{rb} (wait_mask {:#04x})",
        hi[ow].ctrl.wait_mask
    );
    assert_eq!(ctrl_of(&hi), ctrl_of(&lo), "R184 kernel must schedule like its R84 twin");
}

/// R128..R134 are GPRs, not P0..P6: a kernel whose data registers are R128..R134 schedules
/// like the same kernel on R64..R70 (pre-fix the MOV into R130 "redefined" P2 for the
/// predicate-latency model). Guard only: this shape already scheduled identically before the
/// fix (the branch settle stall covers the distance); t480_1 / t480_2 are the pre-fix failures.
const PRED_ALIAS_HI: &str = "\
.entry t
    .reg R0-R199
    .param u64 io
    ISETP.NE.AND P2, PT, R1, RZ, PT ;
    MOV R130, 0x7 ;
    MOV R131, 0x8 ;
    @P2 BRA skip ;
    IADD3 R130, PT, PT, R130, R131, RZ ;
skip:
    STG.E desc[UR4][R4.64], R130 ;
    EXIT ;
";

#[test]
fn t480_3_r130_is_not_p2() {
    let hi = pipeline(PRED_ALIAS_HI);
    let lo = pipeline(&PRED_ALIAS_HI.replace("R130", "R66").replace("R131", "R67"));
    assert_eq!(ctrl_of(&hi), ctrl_of(&lo), "R130/R131 kernel must schedule like its R66/R67 twin");
}
