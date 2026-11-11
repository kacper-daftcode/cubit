//! `cubit ra` on a production sm_120 kernel (2026-11-10): the register allocator run on the
//! sparse-MLA prefill attention kernel (fixture `ra_sm120/sparse_mla_prefill_v42.sass`, 1 449
//! instructions, every register number written by hand in its generator).
//!
//! What failed, in the order the kernel met it:
//!   1. `cubit ra` refused the kernel in every mode: the strict predicate families knew neither
//!      the min/max selector (`FMNMX.FTZ R2, R28, R29, !PT`, `VIMNMX.S32 R2, R2, R18, PT`) nor
//!      `FSETP`.
//!   2. `--mode full` printed the renamed kernel without its register operand selectors
//!      (`.H1`, `.H0_H0`, `.H1_H1`, `.B0`..`.B3`): they live in the source text only, the encoder
//!      reads them from there, the renderer printed operands from the structured form and its
//!      proof compared two parses that both lack them. On the v41 text 608 selectors went and
//!      the output still assembled, with a clean scoreboard verifier, into another kernel.
//!   3. the plan put 64-bit pairs on odd registers and 128-bit quads off the 4-grid: 55 words
//!      of the BUG-008 kind (an `IMAD.WIDE` with an odd addend pair faults the launch, CUDA 715)
//!      that the assembler takes in the 5-operand spelling and only the strict round trip
//!      refuses.
//!
//! 1 and 2 are fixes of the pass and are pinned here. 3 is answered by `--target sm120`
//! (`src/ra_target.rs`; `tests/ra_sm120_target.rs`, `tests/ra_sm120_target_cli.rs`), opt-in:
//! without it the full allocation is the pass it was, and its plan for this kernel is pinned
//! here too. Every test of this file is written against the interfaces of `c507a7c` and is
//! red there.

use cubit::parser::parse_sass;
use cubit::pred_liveness::{pred_xfer, XferMode};
use cubit::ra::{run_file, RaMode};
use cubit::sass_file::parse_sass_file_str_strict;
use std::collections::{BTreeMap, BTreeSet};

const KERNEL: &str = include_str!("fixtures/ra_sm120/sparse_mla_prefill_v42.sass");
fn set(xs: &[u8]) -> BTreeSet<u8> {
    xs.iter().copied().collect()
}

fn rplan(run: &cubit::ra::RaRun) -> BTreeMap<u8, u8> {
    run.report.kernels[0].plan.as_ref().unwrap().r.iter().map(|(k, v)| (k.parse().unwrap(), *v)).collect()
}

fn kernel(body: &str) -> String {
    format!(".entry k\n    .reg R0-R253\n{body}    EXIT ;\n.endentry\n")
}

// ---------------------------------------------------------------- 1. the predicate families

#[test]
fn the_minmax_selector_is_a_predicate_use() {
    for (text, want) in [
        ("FMNMX.FTZ R2, R28, R29, P3 ;", vec![3u8]),
        ("FMNMX.FTZ R2, R28, R29, !P3 ;", vec![3]),
        ("VIMNMX.S32 R2, R2, R18, P1 ;", vec![1]),
        ("HMNMX2 R4, R5, R6, P2 ;", vec![2]),
        // PT / !PT (min / max chosen in the text): nothing to track, but the family is known
        ("FMNMX.FTZ R2, R28, R29, !PT ;", vec![]),
        ("VIMNMX.S32 R2, R2, R18, PT ;", vec![]),
    ] {
        let x = pred_xfer(&parse_sass(text, 0).unwrap(), XferMode::Strict);
        assert!(x.known, "{text}: the strict families must know the min/max selector");
        assert_eq!(x.uses, set(&want), "{text}");
        assert!(x.defs.is_empty(), "{text}: the selector is read, never written");
    }
    // a guard is one more use
    let x = pred_xfer(&parse_sass("@P0 VIMNMX.S32 R2, R2, R18, P4 ;", 0).unwrap(), XferMode::Strict);
    assert_eq!(x.uses, set(&[0, 4]));
    // Compat mirrors predcheck.py: its family list is unchanged
    let c = pred_xfer(&parse_sass("FMNMX.FTZ R2, R28, R29, P3 ;", 0).unwrap(), XferMode::Compat);
    assert!(!c.known, "Compat keeps the reference's families");
    // sm_103a's shape with predicates behind the destination has no measured roles: unknown
    let w = pred_xfer(&parse_sass("VIMNMX R7, P1, P2, R6, 0x1, !PT ;", 0).unwrap(), XferMode::Strict);
    assert!(!w.known, "two predicates behind the destination: no evidence, fail closed");
}

#[test]
fn fsetp_has_isetps_shape() {
    let x = pred_xfer(&parse_sass("FSETP.GT.FTZ.AND P1, P2, R26, RZ, P3 ;", 0).unwrap(), XferMode::Strict);
    assert!(x.known);
    assert_eq!(x.defs, set(&[1, 2]));
    assert_eq!(x.uses, set(&[3]));
    let x = pred_xfer(&parse_sass("FSETP.NEU.FTZ.AND P0, PT, R3, -1.00000001504746621988e+30, PT ;", 0).unwrap(), XferMode::Strict);
    assert!(x.known);
    assert_eq!(x.defs, set(&[0]));
    assert!(x.uses.is_empty());
    // ISETP itself is what it was, in both modes
    for mode in [XferMode::Strict, XferMode::Compat] {
        let i = pred_xfer(&parse_sass("ISETP.GT.AND P0, P1, R4, R5, P2 ;", 0).unwrap(), mode);
        assert_eq!((i.defs.clone(), i.uses.clone(), i.known), (set(&[0, 1]), set(&[2]), true));
    }
    let c = pred_xfer(&parse_sass("FSETP.GT.FTZ.AND P1, P2, R26, RZ, P3 ;", 0).unwrap(), XferMode::Compat);
    assert!(!c.known, "Compat keeps the reference's families");
}

#[test]
fn identity_reads_the_whole_kernel_and_changes_nothing() {
    let run = run_file(KERNEL, RaMode::Identity).expect("identity must accept the attention kernel");
    let k = &run.report.kernels[0];
    assert_eq!(k.n_ins, 1449);
    assert_eq!(k.changed, 0, "zero changed numerals");
    assert_eq!(k.r_used, (0..=125u8).collect::<Vec<_>>(), "R0..R125, no gaps");
    assert_eq!(k.ur_used, vec![4, 5]);
    assert_eq!(k.p_used, vec![0, 1, 2, 4, 5, 6]);
    assert_eq!(k.span_notes_total, 0);
    assert_eq!(run.out_text, KERNEL, "identity emits the input byte for byte");
}

// ---------------------------------------------------------------- 2. the selectors

const SELECTORS: &str = "\
.entry k
    .reg R0-R125
    F2FP.F16.E4M3.UNPACK_B R5, R88.H1 ;
    HADD2.F32 R29, -RZ, R4.H0_H0 ;
    HADD2.F32 R30, -RZ, R4.H1_H1 ;
    HMUL2.BF16_V2 R6, R6, R28.H0_H0 ;
    F2FP.BF16.E4M3.UNPACK_B R7, R89.H1, R86.B0 ;
    F2FP.BF16.E2M1.UNPACK_B R8, R74.B3, R72.B0 ;
    IMAD R9, R5.reuse, R6, RZ ;
    EXIT ;
.endentry
";

#[test]
fn the_renderer_keeps_register_operand_selectors() {
    // rendering a canonical text is the identity -- with its selectors
    let out = cubit::render::run_file(SELECTORS, true).unwrap();
    assert_eq!(out, SELECTORS);
    // and the proof would have caught the old output: the same text without one selector
    let src = parse_sass_file_str_strict(SELECTORS).unwrap();
    for (with, without) in [("R88.H1", "R88"), ("R4.H1_H1", "R4"), ("R86.B0", "R86"), ("R74.B3", "R74.B2")] {
        let lost = parse_sass_file_str_strict(&SELECTORS.replacen(with, without, 1)).unwrap();
        let e = cubit::render::structural_eq(&src, &lost).expect_err("a selector that is dropped or changed must fail the proof");
        assert!(format!("{e:#}").contains("selectors differ"), "{e:#}");
    }
}

#[test]
fn a_full_allocation_keeps_the_selectors_of_what_it_renames() {
    // target-neutral full mode on a kernel whose registers all move
    let src = kernel(
        "    S2R R40, SR_TID.X ;\n    F2FP.F16.E4M3.UNPACK_B R50, R40.H1 ;\n    HADD2.F32 R60, -RZ, R50.H1_H1 ;\n    \
         MOV R70, 0x7f ;\n    F2FP.BF16.E2M1.UNPACK_B R80, R60.B2, R70.B0 ;\n    HMUL2.BF16_V2 R90, R80, R50.H0_H0 ;\n    \
         STS [R40], R90 ;\n",
    );
    let run = run_file(&src, RaMode::Full).unwrap();
    let m = rplan(&run);
    let r = |n: u8| format!("R{}", m[&n]);
    for want in [
        format!("F2FP.F16.E4M3.UNPACK_B {}, {}.H1 ;", r(50), r(40)),
        format!("HADD2.F32 {}, -RZ, {}.H1_H1 ;", r(60), r(50)),
        format!("F2FP.BF16.E2M1.UNPACK_B {}, {}.B2, {}.B0 ;", r(80), r(60), r(70)),
        format!("HMUL2.BF16_V2 {}, {}, {}.H0_H0 ;", r(90), r(80), r(50)),
    ] {
        assert!(run.out_text.contains(&want), "missing `{want}` in\n{}", run.out_text);
    }
    assert!(m[&40] != 40 && m[&90] != 90, "the registers were renamed: {m:?}");
}

#[test]
fn the_kernels_selectors_survive_the_full_allocation() {
    let count = |text: &str, pat: &str| text.lines().filter(|l| !l.trim_start().starts_with("//")).map(|l| l.matches(pat).count()).sum::<usize>();
    let run = run_file(KERNEL, RaMode::Full).unwrap();
    for (sel, n) in [(".H1,", 64), (".H0_H0", 128), (".B0", 272), (".B1", 32), (".B2", 32), (".B3", 32)] {
        assert_eq!(count(KERNEL, sel), n, "the fixture has {n} x `{sel}`");
        assert_eq!(count(&run.out_text, sel), n, "`{sel}` after the allocation");
    }
}

// ---------------------------------------------------------------- 3. the grid

#[test]
fn the_target_neutral_plan_of_the_kernel_is_pinned() {
    let run = run_file(KERNEL, RaMode::Full).unwrap();
    let k = &run.report.kernels[0];
    let f = k.full.as_ref().unwrap();
    assert_eq!((f.r.symbols, f.r.groups, f.r.watermark, f.r.pinned), (126, 59, 125, 0));
    assert!(f.entry_pins.is_empty());
    assert_eq!(f.renamed, 3704);
    // the staging quad R88..R91 (an LDG.E.128 destination whose low pair is also an IMAD.WIDE
    // addend) lands on R15, a 64-bit address pair on R9: assembles, faults on sm_120
    // (the homes were R47 / R41 / R37 until BUG-491: the certified function now gives every 64-bit
    // `CS2R` its register pair, so the kernel's 48 `CS2R Rn, SRZ` words are spans of two and the
    // neutral plan orders its groups otherwise -- the same counts, still off the sm_120 grid)
    let m = rplan(&run);
    assert_eq!([m[&88], m[&89], m[&90], m[&91]], [15, 16, 17, 18]);
    assert_eq!((m[&2], m[&3]), (9, 10));
    assert_eq!((m[&14], m[&80]), (5, 5), "two values that never meet share a register");
    assert!(run.out_text.contains("    .reg R0-R125\n"), "`.reg` untouched");
    // the report of a run without a target carries no target fields
    let json = serde_json::to_value(&run.report).unwrap();
    let keys: Vec<&String> = json["kernels"][0].as_object().unwrap().keys().collect();
    assert!(!keys.iter().any(|k| *k == "target" || *k == "regcount"), "{keys:?}");
}
