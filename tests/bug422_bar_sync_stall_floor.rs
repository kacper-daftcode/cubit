//! BUG-422 (session V, sparse-MLA prefill SASS on sm_120, 2026-11-04): `BAR.SYNC` /
//! `BAR.RED` block *deferred* — the warp keeps issuing for a few cycles after the barrier
//! instruction, so a shared-memory access issued within 5 cycles of it slips past the
//! barrier and reads stale data. Silicon (rtx-pro-6000, 1 CTA/SM, 8 warps): the softmax
//! cross-warp max/sum reduction `@!P2 STS [R81], R2 ; BAR.SYNC ; LDS R4, [R82] ...` was
//! wrong in ~40 % of the tokens with the BAR encoded S01..S05 and bit-exact with S06.
//! ptxas never emits less than 6 cycles between a BAR.SYNC and the next shared-memory
//! instruction (`BAR.SYNC.DEFER_BLOCKING 0x0 ; [Y:S06]` before an LDS, or `S01` followed
//! by a non-memory instruction with S05).
//!
//! cubit's `schedule()` gave BAR no stall floor (`is_control_flow` does not include it, the
//! barrier class falls to `base_latency = 1`), and the encoder's static-control path then
//! emitted S01 — the main.rs re-injection comment already promised "BAR=6" without anything
//! computing it. The hazard was masked in every earlier cubit kernel by scoreboard waits
//! on the first load after the barrier (overflow drains); the BUG-421 colouring relief
//! removed those waits and exposed it.

use cubit::encoder::encode_instruction;
use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, schedule};
use cubit::scheduling::inject_sched_into_code128;
use cubit::scheduling::encode_control_code;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

const SRC: &str = "\
.entry t
    .param u64 io
    FMNMX.FTZ R2, R28, R29, !PT ;
    ISETP.NE.AND P2, PT, R16, RZ, PT ;
    @!P2 STS [R81], R2 ;
    BAR.SYNC.DEFER_BLOCKING 0x0 ;
    LDS R4, [R82] ;
    LDS R5, [R82+0x40] ;
    FMNMX.FTZ R2, R24, R4, !PT ;
    FMNMX.FTZ R2, R2, R5, !PT ;
    EXIT ;
";

/// t422_1: the scheduler assigns BAR.SYNC a stall of at least 6.
#[test]
fn t422_1_bar_sync_stall_floor_in_schedule() {
    let f = parse_sass_file_str_strict(SRC).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    let tab = t120();
    schedule(&mut insns, Some(&tab));
    reallocate_barriers(&mut insns, Some(&tab));
    let bar = insns.iter().position(|x| x.opcode == "BAR").unwrap();
    assert!(
        insns[bar].ctrl.stall >= 6,
        "BAR.SYNC must carry a stall >= 6 (got S{:02})",
        insns[bar].ctrl.stall
    );
}

/// t422_2: the stall reaches the encoded word through the static-control re-injection
/// (the path main.rs takes for barrier-class instructions): bits [44:41] of the high
/// word hold the stall count.
#[test]
fn t422_2_bar_sync_stall_reaches_the_bytes() {
    let f = parse_sass_file_str_strict(SRC).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    let tab = t120();
    schedule(&mut insns, Some(&tab));
    reallocate_barriers(&mut insns, Some(&tab));
    let bar = insns.iter().position(|x| x.opcode == "BAR").unwrap();
    let code = encode_instruction(&insns[bar], &tab).unwrap();
    let sched = encode_control_code(&insns[bar].ctrl);
    let code = inject_sched_into_code128(code, sched);
    let hi = (code >> 64) as u64;
    let stall = (hi >> 41) & 0xf;
    assert!(stall >= 6, "encoded BAR.SYNC stall field must be >= 6 (got {stall}; word hi {hi:#018x})");
}
