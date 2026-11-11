//! The scheduler's view of the words the certified transfer functions do not know (2026-11-11).
//!
//! `reg_liveness::reg_xfer` / `pred_liveness::pred_xfer` are fail-closed: a family outside their table has
//! `known: false` and EMPTY definition / use sets — in the vendor's schedule of a served MoE kernel 111 of 2 576
//! instructions (`QMMA.SF` 48, `IADD.64` 37, `P2R` 11, `ULEA` 6, `USHF` 4, `ARRIVES.LDGSTSBAR` 3, `CS2UR` 1, `R2P` 1),
//! in the sm_120 census 59 008 of 1 811 600 (28 opcodes). A tool that builds a dependency graph from
//! `examples/depdump.rs` saw those words read and write nothing and patched them by hand. The sets exist: under
//! `CUBIT_SYNC_CLASSES=1` the scheduler's own operand model (`sync_class::scheduler_xfer` — what the verifier and the
//! barrier allocator judge an nvcc-shaped kernel with) lists them, with the high half of a 64-bit operand and of a
//! 64-bit address base and the fragments of a tensor instruction; `depdump --scheduler` prints them as `sd` / `su`.
//! This file pins that view for those words, and the two places where it is NOT complete (measured the same day on
//! the census: 741 instructions with an empty view, and the shared destination base of the three-operand `LDGSTS`).

use cubit::sync_class::scheduler_xfer;

type Key = (bool, u16);
const P: u16 = 256; // predicate keys
const UP: u16 = 64; // uniform predicate keys

fn view(line: &str) -> (Vec<Key>, Vec<Key>) {
    // every test of this file wants the switch; a test binary is its own process
    std::env::set_var("CUBIT_SYNC_CLASSES", "1");
    let text = format!(".entry k\n    [B------:R-:W-:-:S01] {line} ;\n.endentry\n");
    let k = cubit::sass_file::parse_sass_file_str(&text).unwrap().kernels.remove(0).instructions;
    let (mut d, mut u) = scheduler_xfer(&k[0]);
    d.sort_unstable();
    d.dedup();
    u.sort_unstable();
    u.dedup();
    (d, u)
}

fn r(v: &[u16]) -> Vec<Key> {
    v.iter().map(|x| (false, *x)).collect()
}

fn ur(v: &[u16]) -> Vec<Key> {
    v.iter().map(|x| (true, *x)).collect()
}

#[test]
fn the_words_of_a_served_kernel_that_the_certified_functions_do_not_know() {
    // a 64-bit add: the pair of the destination and of every register source
    assert_eq!(view("IADD.64 R28, R2, R28"), (r(&[28, 29]), r(&[2, 3, 28, 29])));
    assert_eq!(view("IADD.64 R32, R32, 0x8"), (r(&[32, 33]), r(&[32, 33])));
    assert_eq!(view("IADD.64 R28, R28, UR4"), (r(&[28, 29]), [r(&[28, 29]), ur(&[4, 5])].concat()));
    // the uniform datapath
    assert_eq!(view("ULEA UR5, UR6, UR5, 0x18"), (ur(&[5]), ur(&[5, 6])));
    assert_eq!(view("USHF.L.U32 UR5, UR5, 0x14, URZ"), (ur(&[5]), ur(&[5])));
    assert_eq!(view("USHF.R.S32.HI UR11, URZ, 0x1f, UR10"), (ur(&[11]), ur(&[10])));
    // the predicate register as a whole: the predicates of the mask
    assert_eq!(view("P2R R62, PR, RZ, 0x2"), (r(&[62]), r(&[P + 1])));
    assert_eq!(view("R2P PR, R72, 0x7e"), (r(&[P + 1, P + 2, P + 3, P + 4, P + 5, P + 6]), r(&[72])));
    // the arrival of a copy group: its address
    assert_eq!(view("ARRIVES.LDGSTSBAR.64.ARVCNT [UR4]"), (vec![], ur(&[4])));
    assert_eq!(view("CS2UR UR4, SR_GLOBALTIMERLO"), (ur(&[4]), vec![]));
}

#[test]
fn the_fragments_of_a_scaled_tensor_instruction() {
    // D and C four registers, A four, B two, the two scale registers one each
    let (d, u) = view("QMMA.SF.16832.F32.E4M3.E2M1.E8 R28, R16, R12, R28, R91, R86, URZ");
    assert_eq!(d, r(&[28, 29, 30, 31]));
    assert_eq!(u, r(&[12, 13, 16, 17, 18, 19, 28, 29, 30, 31, 86, 91]));
    let (d, u) = view("QMMA.16832.F32.E4M3.E4M3 R4, R24, R4, RZ");
    assert_eq!(d, r(&[4, 5, 6, 7]));
    assert_eq!(u, r(&[4, 5, 24, 25, 26, 27]));
}

#[test]
fn the_high_half_of_a_wide_address_and_a_guard() {
    // desc[UR8][R60.64] reads R60:R61 and UR8:UR9; the guard is a use
    let (d, u) = view("@!P0 LDG.E R4, desc[UR8][R60.64]");
    assert_eq!(d, r(&[4]));
    assert_eq!(u, [r(&[60, 61, P]), ur(&[8, 9])].concat());
    let (_, u) = view("@!UP1 ULEA UR10, UR11, UR10, 0x18");
    assert_eq!(u, ur(&[10, 11, UP + 1]));
}

/// Where the view is NOT complete — pinned so that a repair shows up here. A graph built from `sd` / `su` alone
/// misses these; the certified sets (`rd` / `ru` of depdump) have the first.
#[test]
fn what_the_view_does_not_list() {
    // the shared destination base of the copy's three-operand form (R77): the two-operand form has it, through
    // the certified sets; with a predicate operand the certified functions do not know the word. (Its
    // overwriters are covered by the store-path check; a producer in front of it is not.)
    let (_, u) = view("LDGSTS.E.BYPASS.128 [R77+0x1000], desc[UR8][R60.64], P1");
    assert_eq!(u, [r(&[60, 61, P + 1]), ur(&[8, 9])].concat());
    let (_, u) = view("LDGSTS.E.BYPASS.128 [R72], desc[UR12][R22.64]");
    assert_eq!(u, [r(&[22, 23, 72]), ur(&[12, 13])].concat());
    // a 4-bit tensor instruction: one destination register, single-register sources (the 8-bit one above: fragments)
    let (d, u) = view("OMMA.SF.16864.F32.E2M1.E2M1.E8 R20, R40, R118, R44, R97, R116, URZ");
    assert_eq!((d, u), (r(&[20]), r(&[40, 44, 97, 116, 118])));
    // a uniform predicate written from true inputs, an address in a uniform register: nothing at all
    assert_eq!(view("UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8"), (vec![], vec![]));
    assert_eq!(view("UTMACCTL.PF [UR12]"), (vec![], vec![]));
}
