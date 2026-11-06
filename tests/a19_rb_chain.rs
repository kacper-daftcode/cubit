//! KNOWN_ISSUES A19 — the `CUBIT_RB_CHAIN=1` experiment (T-9, 2026-11-06; default OFF, the flip is
//! the owner's decision, NEEDS_OWNER 31).
//!
//! The 2026-06 `5912400` schedules of the MC4 MoE prefill kernels (the shipped cubins, which run
//! `mc4_k4096` / `mc4_k6144` 34–58 % faster than today's default re-assembly) carry a read barrier
//! on every sub-word global load (`LDG.E.U8` scale bytes) that the NEXT global load in program
//! order waits: byte load k → byte load k+1 of the same stream, the last of a group → the first
//! load of the next stream (T-8 report part 8 §5: 32 of the 41 extra read barriers of the shipped
//! `mc4_k4096` schedule; the other 9 are WAR protections today's allocator covers through a RAW
//! wait). The address register is never rewritten inside the loop, so this is not a WAR and the
//! WAR pass never produces it. Under the switch `reallocate_barriers` reproduces the chain as an
//! rb use per sub-word global load (merged into the load's WAR use when it has one); a wait is
//! never a hazard, so legality is unchanged either way.
//!
//! Pins: (1) with the switch, every sub-word global load that has a following global load before
//! the next control-flow instruction carries a read barrier and that load waits it, exactly like
//! the shipped schedule (out of tree: `T/t9/a19/` — 32 / 32 byte loads of `mc4_k4096` chained,
//! the `@P2 LDG.E` group leaders waiting the last byte load, as in `5912400`); (2) without the
//! switch the same source gets no chain (today's default: 0 of the byte loads carry an rb) and the
//! instruction words are identical — the frozen round trips and the census are untouched by
//! construction (the switch is read only inside the allocator). The two runs are sequential in
//! one test body because the switch is an environment variable.

use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, schedule};
use cubit::table::IsaTable;
use cubit::Instruction;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

/// The MC4 shape in miniature: a 64-bit fragment load, a group of four scale-byte loads from
/// one base with immediate offsets, the next stream's guarded loads, the consumers, a store.
const SRC: &str = ".entry mc4_shape
    .reg R0-R63
    .param u64 p0 offset=0x0
    .param u32 p1 offset=0x8
    S2R R34, SR_TID.X ;
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R8, c[0x0][0x380] ;
    LDC.64 R16, c[0x0][0x380] ;
    LDC.64 R58, c[0x0][0x380] ;
    LDC.64 R2, c[0x0][0x380] ;
    ISETP.NE.AND P2, PT, R34, RZ, PT ;
    LDG.E.64 R24, desc[UR4][R8.64] ;
    LDG.E.U8 R26, desc[UR4][R16.64] ;
    LDG.E.U8 R29, desc[UR4][R16.64+0x8] ;
    LDG.E.U8 R56, desc[UR4][R16.64+0x10] ;
    LDG.E.U8 R57, desc[UR4][R16.64+0x18] ;
    @P2 LDG.E R4, desc[UR4][R58.64] ;
    @P2 LDG.E R6, desc[UR4][R58.64+0x10] ;
    SHF.L.U32 R26, R26, 0x17, RZ ;
    SHF.L.U32 R29, R29, 0x17, RZ ;
    SHF.L.U32 R56, R56, 0x17, RZ ;
    SHF.L.U32 R57, R57, 0x17, RZ ;
    IADD3 R4, R4, R24, RZ ;
    IADD3 R6, R6, R25, RZ ;
    IADD3 R4, R4, R26, R29 ;
    IADD3 R6, R6, R56, R57 ;
    STG.E.64 desc[UR4][R2.64], R4 ;
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

fn is_global_load(x: &Instruction) -> bool {
    matches!(x.opcode.as_str(), "LDG" | "LD")
}

fn byte_loads(insns: &[Instruction]) -> Vec<usize> {
    insns
        .iter()
        .enumerate()
        .filter(|(_, x)| is_global_load(x) && x.opcode_full.contains(".U8"))
        .map(|(i, _)| i)
        .collect()
}

fn next_global_load(insns: &[Instruction], i: usize) -> Option<usize> {
    ((i + 1)..insns.len()).find(|&j| is_global_load(&insns[j]))
}

#[test]
fn a19_rb_chain_switch_reproduces_the_shipped_chain_and_is_off_by_default() {
    // --- off (the default): no chain, exactly today's allocator ---
    std::env::remove_var("CUBIT_RB_CHAIN");
    let off = pipeline(SRC);
    let bl = byte_loads(&off);
    assert_eq!(bl.len(), 4, "the shape has four scale-byte loads");
    for &i in &bl {
        assert_eq!(off[i].ctrl.read_bar, 7, "default: `{}` carries no read barrier", off[i].raw_text.trim());
    }

    // --- on: byte load k sets an rb, the next global load waits it ---
    std::env::set_var("CUBIT_RB_CHAIN", "1");
    let on = pipeline(SRC);
    std::env::remove_var("CUBIT_RB_CHAIN");
    assert_eq!(on.len(), off.len());
    for (a, b) in on.iter().zip(off.iter()) {
        assert_eq!(a.raw_text, b.raw_text, "the switch changes control codes only");
    }
    let bl = byte_loads(&on);
    let mut chained = 0;
    for &i in &bl {
        let rb = on[i].ctrl.read_bar;
        assert!(rb < 6, "CUBIT_RB_CHAIN=1: `{}` must carry a read barrier", on[i].raw_text.trim());
        let j = next_global_load(&on, i).expect("a following global load");
        assert!(
            (on[j].ctrl.wait_mask >> rb) & 1 == 1,
            "`{}` must wait R{rb} of `{}` (wait_mask {:#04x})",
            on[j].raw_text.trim(),
            on[i].raw_text.trim(),
            on[j].ctrl.wait_mask
        );
        chained += 1;
    }
    assert_eq!(chained, 4, "the four byte loads form the chain: 3 same-stream links + the `@P2 LDG.E` leader");
    // the leader of the next stream is the waiter of the last byte load, as in `5912400`
    let last = *bl.last().unwrap();
    let leader = next_global_load(&on, last).unwrap();
    assert!(on[leader].raw_text.contains("@P2 LDG.E R4"), "{}", on[leader].raw_text);
    // write barriers and RAW waits are untouched by the chain
    for (a, b) in on.iter().zip(off.iter()) {
        assert_eq!(a.ctrl.write_bar, b.ctrl.write_bar, "`{}`: write barriers unchanged", a.raw_text.trim());
    }
}
