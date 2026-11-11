//! BUG-490 (2026-11-11): the certified transfer function `reg_liveness::reg_xfer` took "the first operand that is
//! not `RZ` / `URZ`" as the destination of an atomic, a `SYNCS` word, a shuffle and a uniform-result warp word — so
//! when the destination slot held `RZ` (a word that returns nothing), or when the word has no destination slot at
//! all, the NEXT register became the definition and was no use, with `known: true`:
//!
//! ```text
//! ATOMS.MAX.S32 RZ, [R157+UR7+0x15100], R58                 rd [58]      ru [157]        the DATA defined, not read
//! ATOMG.E.ADD.64.STRONG.GPU PT, RZ, desc[UR8][R2.64], R40   rd [40, 41]  ru [2]
//! SYNCS.EXCH.64 URZ, [UR6+0x16700], UR4                     ud [4]       uu [6]
//! SYNCS.ARRIVE.TRANS64 RZ, [UR12+0xf200], R0                rd [0]
//! SYNCS.PHASECHK.TRANS64.TRYWAIT P0, [R3+URZ+0xf200], R2    rd [2]                       no destination slot at all
//! ```
//!
//! The register allocator stands on these sets (a value read only by such a word was dead to it from its last other
//! reader on), so do the reordering pass and `stallfix`, the path walks of `CUBIT_VERIFY` (168 false write-after-write
//! pairs on the vendor's text when the walk took a producer's result from them) and, under `CUBIT_SYNC_CLASSES`,
//! the scheduler's operand model. Nothing that serves carries such a word (no production source, attention build or
//! committed cubin has an atomic or a `SYNCS`), and the default assembly path does not read these sets.
//!
//! The rule now: the destination slot is POSITIONAL — for a word with a memory operand it is the register in front
//! of that operand, otherwise the first register operand; `RZ` / `URZ` there defines nothing and does not hand the
//! role on; every register behind the memory operand is read. What the vendor's own text says (the sm_120 census,
//! 154 listings; an edge vote inside one basic block): the register behind the memory operand of these five shapes,
//! 12 620 sites — written immediately in front of the word with no other reader in 4 972 (a dead write if the word
//! did not read it), read behind the word before it is written again in 0, written again first in 3 899 (a dead
//! definition if the word had defined it).

use cubit::parser::parse_sass;
use cubit::ra::{run_file, run_file_opts, RaMode, RaOptions};
use cubit::ra_target::RaTarget;
use cubit::reg_liveness::{liveness_file, reg_xfer, RegXfer};
use std::collections::{BTreeMap, BTreeSet};

fn xfer(sass: &str) -> RegXfer {
    reg_xfer(&parse_sass(sass, 0).unwrap())
}

fn v(xs: &[u8]) -> BTreeSet<u8> {
    xs.iter().copied().collect()
}

#[test]
fn an_atomic_that_returns_nothing_reads_its_data_and_defines_nothing() {
    // the vendor's shapes (sm_120 census): 3 864 x `ATOMS … RZ, [..], R`, 18 x `ATOMG … PT, RZ, desc[..][..], R`
    let x = xfer("ATOMS.MAX.S32 RZ, [R157+UR7+0x15100], R58 ;");
    assert!(x.known);
    assert!(x.rdefs.is_empty(), "the data register is no definition: {:?}", x.rdefs);
    assert_eq!(x.ruses, v(&[157, 58]));
    assert_eq!(x.uuses, v(&[7]));
    let x = xfer("ATOMS.ADD RZ, [R4], R7 ;");
    assert!(x.rdefs.is_empty(), "{:?}", x.rdefs);
    assert_eq!(x.ruses, v(&[4, 7]));
    let x = xfer("ATOMG.E.ADD.S32.STRONG.GPU PT, RZ, desc[UR10][R10.64], R17 ;");
    assert!(x.known && x.rdefs.is_empty(), "{:?}", x.rdefs);
    assert_eq!(x.ruses, v(&[10, 17]));
    // a 64-bit datum is a pair
    let x = xfer("ATOMG.E.ADD.64.STRONG.GPU PT, RZ, desc[UR8][R2.64], R40 ;");
    assert!(x.rdefs.is_empty(), "{:?}", x.rdefs);
    assert_eq!(x.ruses, v(&[2, 40, 41]));
    // compare and swap: both registers behind the memory operand are read
    let x = xfer("ATOMG.E.CAS.STRONG.GPU PT, RZ, desc[UR10][R10.64], R20, R21 ;");
    assert!(x.rdefs.is_empty(), "{:?}", x.rdefs);
    assert_eq!(x.ruses, v(&[10, 20, 21]));
    // every span of such a word is a use
    assert!(x.spans.iter().all(|s| !s.is_def), "{:?}", x.spans.iter().map(|s| (s.base, s.width, s.is_def)).collect::<Vec<_>>());
}

#[test]
fn an_atomic_that_returns_a_value_is_what_it_was() {
    let x = xfer("ATOMG.E.ADD.STRONG.GPU PT, R9, desc[UR8][R32.64+0x8], R9 ;");
    assert_eq!(x.rdefs, v(&[9, 10]), "the old-value pair");
    assert_eq!(x.ruses, v(&[32, 9]));
    let x = xfer("ATOMG.E.ADD.S32.STRONG.GPU PT, R6, desc[UR10][R14.64], R19 ;");
    assert_eq!(x.rdefs, v(&[6, 7]));
    assert_eq!(x.ruses, v(&[14, 19]));
    let x = xfer("ATOM.E.CAS.STRONG.GPU PT, R15, [R10], R14, R15 ;");
    assert_eq!(x.rdefs, v(&[15]));
    assert_eq!(x.ruses, v(&[10, 14, 15]));
    let x = xfer("ATOMS.ADD R6, [R2], R7 ;");
    assert_eq!(x.rdefs, v(&[6]));
    assert_eq!(x.ruses, v(&[2, 7]));
    let x = xfer("ATOMS.ADD PT, R6, [R2], R7 ;");
    assert_eq!(x.rdefs, v(&[6]));
    assert_eq!(x.ruses, v(&[2, 7]));
}

#[test]
fn the_register_behind_the_memory_operand_of_a_syncs_word_is_read() {
    // 2 670 x in the census: the exchanged value, with the old one discarded
    let x = xfer("SYNCS.EXCH.64 URZ, [UR6+0x16700], UR4 ;");
    assert!(x.known);
    assert!(x.udefs.is_empty(), "{:?}", x.udefs);
    assert_eq!(x.uuses, v(&[6, 4]));
    // 1 100 x: the count of an arrive
    let x = xfer("SYNCS.ARRIVE.TRANS64 RZ, [UR12+0xf200], R0 ;");
    assert!(x.rdefs.is_empty(), "{:?}", x.rdefs);
    assert_eq!(x.ruses, v(&[0]));
    assert_eq!(x.uuses, v(&[12]));
    // 4 968 x: a phase check has a predicate result and NO register destination slot; the register is the phase
    let x = xfer("SYNCS.PHASECHK.TRANS64.TRYWAIT P0, [R3+URZ+0xf200], R2 ;");
    assert!(x.rdefs.is_empty(), "{:?}", x.rdefs);
    assert_eq!(x.ruses, v(&[3, 2]));
    // 827 x: nothing behind the memory operand either -- as before
    let x = xfer("SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R54+URZ], RZ ;");
    assert!(x.rdefs.is_empty() && x.udefs.is_empty());
    assert_eq!(x.ruses, v(&[54]));
}

#[test]
fn a_shuffle_and_a_uniform_result_word_keep_their_destination_slot() {
    // the vendor never writes these with a zero destination and a register behind it; the slot is positional all the same
    let x = xfer("SHFL.IDX PT, R11, R6, RZ, 0x1f ;");
    assert_eq!((x.rdefs, x.ruses), (v(&[11]), v(&[6])));
    let x = xfer("SHFL.BFLY P0, R20, R35, R36, R37 ;");
    assert_eq!((x.rdefs, x.ruses), (v(&[20]), v(&[35, 36, 37])));
    let x = xfer("SHFL.IDX PT, RZ, R6, R7, 0x1f ;");
    assert!(x.rdefs.is_empty(), "a shuffle into RZ defines nothing: {:?}", x.rdefs);
    assert_eq!(x.ruses, v(&[6, 7]));
    // (the vendor's scratch register UR79 lies outside the tracked file UR0 - UR63: a tracked one here)
    let x = xfer("ELECT P0, UR5, PT ;");
    assert_eq!(x.udefs, v(&[5]));
    let x = xfer("ELECT P2, URZ, PT ;");
    assert!(x.udefs.is_empty() && x.uuses.is_empty());
    let x = xfer("REDUX.SUM UR5, R6 ;");
    assert_eq!((x.udefs, x.ruses), (v(&[5]), v(&[6])));
    let x = xfer("REDUX.SUM URZ, R6 ;");
    assert!(x.udefs.is_empty());
    assert_eq!(x.ruses, v(&[6]));
}

fn kernel(body: &str) -> String {
    format!(".entry k\n    .reg R0-R253\n{body}    EXIT ;\n.endentry\n")
}

fn rplan(run: &cubit::ra::RaRun) -> BTreeMap<u8, u8> {
    run.report.kernels[0].plan.as_ref().unwrap().r.iter().map(|(k, v)| (k.parse().unwrap(), *v)).collect()
}

/// What the wrong set did to its first consumer: R1 is written, R2 lives and dies, then the atomic adds R1 to
/// memory. With R1 "defined" by the atomic and not read by it, R1 was dead from its write on, and the allocator gave
/// R1 and R2 one register — the atomic would have added 7, not 5.
#[test]
fn the_register_allocator_keeps_an_atomics_data_alive_up_to_it() {
    let src = kernel(
        "    S2R R9, SR_TID.X ;\n    MOV R1, 0x5 ;\n    MOV R2, 0x7 ;\n    STS [R9], R2 ;\n    ATOMS.ADD RZ, [R9], R1 ;\n",
    );
    let live = liveness_file(&src).unwrap();
    let atom = live[0].ins.iter().position(|r| r.opcode_full.starts_with("ATOMS")).unwrap();
    assert!(live[0].ins[atom].rlive_in.contains(&1), "R1 is live into the atomic: {:?}", live[0].ins[atom].rlive_in);
    assert!(live[0].ins[atom - 1].rlive_in.contains(&1), "... and across the store in front of it");
    for (what, run) in [
        ("target-neutral", run_file(&src, RaMode::Full).unwrap()),
        ("sm120", run_file_opts(&src, RaMode::Full, &RaOptions { target: Some(RaTarget::Sm120), ..RaOptions::default() }).unwrap()),
    ] {
        let m = rplan(&run);
        assert_ne!(m[&1], m[&2], "{what}: the atomic's data and a value that lives in between share a register: {m:?}");
    }
    // the same with the vendor's global form and a 64-bit datum: the pair stays a pair and stays alive
    let src = kernel(
        "    S2R R9, SR_TID.X ;\n    LDC.64 R2, c[0x0][0x380] ;\n    IMAD.WIDE.U32 R4, R9, 0x8, RZ ;\n    MOV R6, 0x7 ;\n    STS [R9], R6 ;\n    \
         ATOMG.E.ADD.64.STRONG.GPU PT, RZ, desc[UR8][R2.64], R4 ;\n",
    );
    let live = liveness_file(&src).unwrap();
    let atom = live[0].ins.iter().position(|r| r.opcode_full.starts_with("ATOMG")).unwrap();
    assert!(live[0].ins[atom].rlive_in.is_superset(&v(&[2, 4, 5])), "{:?}", live[0].ins[atom].rlive_in);
    let m = rplan(&run_file(&src, RaMode::Full).unwrap());
    assert!(m[&6] != m[&4] && m[&6] != m[&5], "{m:?}");
}

/// The sm_120 target refuses a register that is read before any instruction wrote it. An atomic's data was no read.
#[test]
fn an_atomic_that_reads_a_register_nobody_wrote_is_refused() {
    let src = kernel("    S2R R9, SR_TID.X ;\n    ATOMS.ADD RZ, [R9], R200 ;\n");
    let e = run_file_opts(&src, RaMode::Full, &RaOptions { target: Some(RaTarget::Sm120), ..RaOptions::default() })
        .expect_err("R200 is read by the atomic and never written");
    assert!(format!("{e:#}").contains("R200"), "{e:#}");
}
