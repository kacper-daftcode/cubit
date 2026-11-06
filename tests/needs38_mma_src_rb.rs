//! NEEDS_OWNER 38 — the `CUBIT_MMA_SRC_RB=0` experiment (T-10, 2026-11-06; default ON = today's rule,
//! the decision is the owner's).
//!
//! cubit's allocator puts a read barrier on a warp-cooperative MMA whose source fragments a later
//! load overwrites (`mma_src_gprs`: "the MMA reads its fragments over a long window"), waited by that
//! load. The legality oracle over the sm_120 census (KNOWN_ISSUES A4, T-9) measured ptxas's practice:
//! a read barrier on 0 of 39 624 HMMA/QMMA, fragments overwritten by `LDS`/`LDSM` at S01 on 717 720
//! sites — ptxas double-buffers fragment registers structurally and never needs the barrier; cubit's
//! hand-written kernels reuse fragment registers, and the rule guards that reuse (the 2026-06
//! warm-cache corruption recorded on `mma_src_gprs`). The switch drops the rule so the cost and the
//! correctness of the relaxation can be measured on silicon (K's harness: bits over repeated warm
//! runs + time per production kernel); it changes control codes only.
//!
//! Pins: (1) default: the QMMA whose A fragment the next LDS refills carries a read barrier and the
//! LDS waits it; (2) `CUBIT_MMA_SRC_RB=0`: the same source gets no read barrier on the QMMA (the
//! instruction words identical, the write barriers identical) — the frozen round trips and the
//! production sources are untouched by construction (the switch is read inside the allocator and the
//! scoreboard verifier only). The two runs are sequential in one test body (environment variable).

use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, schedule};
use cubit::table::IsaTable;
use cubit::Instruction;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

/// A fragment loop in miniature: A / B fragments from shared memory, the QMMA, then the refill of
/// the A fragment (the next k-step's load into the SAME registers) and a dependent store.
const SRC: &str = ".entry qmma_refill
    .reg R0-R63
    .param u64 p0 offset=0x0
    .shared smem[4096]
    S2R R0, SR_TID.X ;
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    SHF.L.U32 R1, R0, 0x4, RZ ;
    LDS.128 R8, [R1] ;
    LDS.64 R12, [R1+0x400] ;
    LDS.128 R20, [R1+0x800] ;
    QMMA.16832.F32.E4M3.E4M3 R20, R8, R12, R20 ;
    LDS.128 R8, [R1+0x1000] ;
    LDS.64 R12, [R1+0x1400] ;
    QMMA.16832.F32.E4M3.E4M3 R20, R8, R12, R20 ;
    STG.E.128 desc[UR4][R2.64], R20 ;
    EXIT ;
";

fn pipeline(src: &str) -> Vec<Instruction> {
    let f = parse_sass_file_str_strict(src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    let tab = t120();
    schedule(&mut insns, Some(&tab));
    reallocate_barriers(&mut insns, Some(&tab));
    insns
}

fn first_qmma(insns: &[Instruction]) -> usize {
    insns.iter().position(|x| x.opcode == "QMMA").expect("a QMMA")
}

fn refill_after(insns: &[Instruction], i: usize) -> usize {
    ((i + 1)..insns.len())
        .find(|&j| insns[j].opcode == "LDS" && insns[j].raw_text.contains("R8,"))
        .expect("the A-fragment refill")
}

#[test]
fn needs38_switch_drops_the_mma_source_read_barrier_and_is_on_by_default() {
    // --- default (today's rule): the first QMMA carries an rb, the refill of R8 waits it ---
    std::env::remove_var("CUBIT_MMA_SRC_RB");
    let on = pipeline(SRC);
    let q = first_qmma(&on);
    let rb = on[q].ctrl.read_bar;
    assert!(rb < 6, "default: `{}` must carry a read barrier (fragment reuse)", on[q].raw_text.trim());
    let refill = refill_after(&on, q);
    assert!(
        (on[refill].ctrl.wait_mask >> rb) & 1 == 1,
        "default: `{}` must wait R{rb} of the QMMA (wait_mask {:#04x})",
        on[refill].raw_text.trim(),
        on[refill].ctrl.wait_mask
    );

    // --- CUBIT_MMA_SRC_RB=0: no read barrier on the QMMA; words and write barriers unchanged ---
    std::env::set_var("CUBIT_MMA_SRC_RB", "0");
    let off = pipeline(SRC);
    std::env::remove_var("CUBIT_MMA_SRC_RB");
    assert_eq!(off.len(), on.len());
    for (a, b) in off.iter().zip(on.iter()) {
        assert_eq!(a.raw_text, b.raw_text, "the switch changes control codes only");
        assert_eq!(a.ctrl.write_bar, b.ctrl.write_bar, "`{}`: write barriers unchanged", a.raw_text.trim());
    }
    let q = first_qmma(&off);
    assert_eq!(off[q].ctrl.read_bar, 7, "CUBIT_MMA_SRC_RB=0: `{}` carries no read barrier", off[q].raw_text.trim());
    assert!(off.iter().all(|x| x.opcode != "QMMA" || x.ctrl.read_bar == 7), "no QMMA carries a read barrier under the switch");
    // the default rule is restored once the variable is gone
    let again = pipeline(SRC);
    assert!(again[first_qmma(&again)].ctrl.read_bar < 6);
}
