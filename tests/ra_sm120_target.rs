//! `--target sm120` of the full register allocation (`src/ra_target.rs`, 2026-11-10): what the
//! allocator must know about the silicon it allocates for. Found on the production attention
//! kernel (`tests/ra_sm120_attention.rs`): the target-neutral plan is not sm_120 code.
//!
//! Pinned here, on that kernel and on small ones: the register grid (64-bit pairs on even
//! registers, quads on multiples of four -- an odd `IMAD.WIDE` addend pair faults the launch;
//! ptxas is never off the grid in 1.8 M census instructions); the footprints the role table does
//! not carry (the 64-bit address and descriptor of `desc[UR][R.64]`, the pair `CS2R` writes, the
//! two registers of `LDSM.2`); a value that stays alive across a guarded overwrite; the audit of
//! an applied plan against these footprints; `.reg` rewritten to the registers the plan uses.
//! The target-neutral pass is unchanged by all of it, and each test shows that side too.

use cubit::parser::parse_sass;
use cubit::ra::{run_file, run_file_opts, ApplyPlan, RaMode, RaOptions};
use cubit::ra_target::{target_xfer, RaTarget};
use cubit::reg_liveness::{reg_xfer, RegDom};
use cubit::sass_file::parse_sass_file_str_strict;
use std::collections::{BTreeMap, BTreeSet};

const KERNEL: &str = include_str!("fixtures/ra_sm120/sparse_mla_prefill_v42.sass");

fn set(xs: &[u8]) -> BTreeSet<u8> {
    xs.iter().copied().collect()
}

fn sm120() -> RaOptions {
    RaOptions { target: Some(RaTarget::Sm120), ..RaOptions::default() }
}

fn rplan(run: &cubit::ra::RaRun) -> BTreeMap<u8, u8> {
    run.report.kernels[0].plan.as_ref().unwrap().r.iter().map(|(k, v)| (k.parse().unwrap(), *v)).collect()
}

fn kernel(body: &str) -> String {
    format!(".entry k\n    .reg R0-R253\n{body}    EXIT ;\n.endentry\n")
}

#[test]
fn sm120_puts_every_multi_register_operand_on_its_grid() {
    let run = run_file_opts(KERNEL, RaMode::Full, &sm120()).unwrap();
    let k = &run.report.kernels[0];
    assert_eq!(k.target.as_deref(), Some("sm120"));
    let m = rplan(&run);
    let file = parse_sass_file_str_strict(KERNEL).unwrap();
    let (mut pairs, mut quads) = (0, 0);
    for ins in &file.kernels[0].instructions {
        for sp in target_xfer(RaTarget::Sm120, ins).spans.iter().filter(|s| s.dom == RegDom::R && !s.desc_ns && s.width > 1) {
            let home = m[&sp.base];
            for o in 0..sp.width as u8 {
                assert_eq!(m[&(sp.base + o)], home + o, "`{}`: R{}+{o} torn", ins.raw_text.trim(), sp.base);
            }
            let grid = if sp.width >= 4 { 4 } else { 2 };
            assert_eq!(home % grid, 0, "`{}`: R{} -> R{home} off the grid of {grid}", ins.raw_text.trim(), sp.base);
            if sp.width >= 4 { quads += 1 } else { pairs += 1 }
        }
    }
    assert_eq!((pairs, quads), (379, 319), "the kernel's pairs (IMAD.WIDE, addresses, LDC.64, CS2R, LDSM.2, HMMA B) and quads");
    // as many registers as by hand, and `.reg` says so: 126 symbols on R0..R124, register count 128
    let homes: BTreeSet<u8> = m.values().copied().collect();
    assert_eq!((m.len(), homes.len(), *homes.iter().max().unwrap()), (126, 125, 124));
    assert_eq!(k.regcount, Some(128));
    assert_eq!(k.peak_live_r, Some(113), "the kernel's lower bound: 113 registers hold a value at once");
    assert!(run.out_text.contains("    .reg R0-R124\n"), "`.reg` follows the allocation");
    // nothing else moved: the selectors are where they were
    let count = |text: &str, pat: &str| text.lines().filter(|l| !l.trim_start().starts_with("//")).map(|l| l.matches(pat).count()).sum::<usize>();
    for sel in [".H1,", ".H0_H0", ".B0", ".B1", ".B2", ".B3"] {
        assert_eq!(count(&run.out_text, sel), count(KERNEL, sel), "`{sel}`");
    }
    // uniform registers and predicates are compacted too
    let plan = k.plan.as_ref().unwrap();
    assert_eq!((plan.ur["4"], plan.ur["5"]), (0, 1));
    assert_eq!(plan.p.values().copied().collect::<Vec<u8>>(), vec![0, 1, 2, 3, 4, 5]);
}

#[test]
fn the_target_neutral_plan_is_refused_when_sm120_is_named() {
    let a = run_file(KERNEL, RaMode::Full).unwrap();
    let b = run_file_opts(KERNEL, RaMode::Full, &RaOptions::default()).unwrap();
    assert_eq!(a.out_text, b.out_text, "no option = the pass as it was");
    let k = &a.report.kernels[0];
    assert!(k.target.is_none() && k.regcount.is_none());
    let neutral = serde_json::json!({ "kernels": { "sparse_mla_prefill_v41": k.plan.as_ref().unwrap() } });
    let ap: ApplyPlan = serde_json::from_value(neutral).unwrap();
    let e = run_file_opts(KERNEL, RaMode::ApplyFile(ap), &sm120()).expect_err("off-grid plan");
    assert!(format!("{e:#}").contains("off its grid"), "{e:#}");
}

#[test]
fn a_guarded_write_keeps_the_old_value_alive() {
    // R1 holds a default, R2's whole life lies between the default and R1's guarded overwrite.
    let src = kernel(
        "    S2R R9, SR_TID.X ;\n    ISETP.NE.AND P0, PT, R9, RZ, PT ;\n    MOV R1, 0x5 ;\n    MOV R2, 0x7 ;\n    \
         IADD3 R3, PT, PT, R2, 0x1, RZ ;\n    @P0 MOV R1, R3 ;\n    STS [R9], R1 ;\n",
    );
    // the shared dataflow kills R1 at its guarded write: the target-neutral pass gives R1 and R2 one home
    let neutral = rplan(&run_file(&src, RaMode::Full).unwrap());
    assert_eq!(neutral[&1], neutral[&2], "the target-neutral pass (unchanged): {neutral:?}");
    // sm120: R1 stays live across the instruction that may not write it
    let m = rplan(&run_file_opts(&src, RaMode::Full, &sm120()).unwrap());
    assert_ne!(m[&1], m[&2], "{m:?}");
    // ... but a write under the SAME guard as every later read is a write: no register is live at the entry
    let src = kernel(
        "    S2R R9, SR_TID.X ;\n    ISETP.NE.AND P0, PT, R9, RZ, PT ;\n    @P0 LDS R2, [R9] ;\n    @P0 IADD3 R2, PT, PT, R2, 0x1, RZ ;\n    \
         @P0 STS [R9], R2 ;\n",
    );
    let run = run_file_opts(&src, RaMode::Full, &sm120()).unwrap();
    assert!(run.report.kernels[0].full.as_ref().unwrap().entry_pins.is_empty(), "{:?}", run.report.kernels[0].full);
    // a register read before anything wrote it is refused; the target-neutral pass does not see it (to its
    // dataflow the guarded write is a write on every path) and a register it does see live at the entry
    // it pins to its numeral
    let src = kernel("    S2R R9, SR_TID.X ;\n    ISETP.NE.AND P0, PT, R9, RZ, PT ;\n    @P0 MOV R200, 0x1 ;\n    STS [R9], R200 ;\n");
    let e = run_file_opts(&src, RaMode::Full, &sm120()).expect_err("R200 is read when P0 is false and never written then");
    assert!(format!("{e:#}").contains("reads 1 register(s) before any instruction wrote them") && format!("{e:#}").contains("R200"), "{e:#}");
    let neutral = run_file(&src, RaMode::Full).unwrap();
    assert!(neutral.report.kernels[0].full.as_ref().unwrap().entry_pins.is_empty(), "the target-neutral pass (unchanged)");
    let src = kernel("    S2R R9, SR_TID.X ;\n    STS [R9], R200 ;\n");
    let e = run_file_opts(&src, RaMode::Full, &sm120()).expect_err("R200 is never written");
    assert!(format!("{e:#}").contains("R200"), "{e:#}");
    assert_eq!(rplan(&run_file(&src, RaMode::Full).unwrap())[&200], 200, "the target-neutral pass (unchanged) pins it");
    // an instruction that rewrites its own guard does not close the facts that hang on the new value
    let src = kernel(
        "    S2R R9, SR_TID.X ;\n    ISETP.NE.AND P0, PT, R9, RZ, PT ;\n    MOV R1, 0x5 ;\n    MOV R2, 0x7 ;\n    STS [R9], R2 ;\n    \
         @P0 SHFL.BFLY P0, R1, R9, 0x1, 0x1f ;\n    @P0 STS [R9], R1 ;\n",
    );
    let m = rplan(&run_file_opts(&src, RaMode::Full, &sm120()).unwrap());
    assert_ne!(m[&1], m[&2], "{m:?}");
}

#[test]
fn sm120_footprints() {
    let x = |t: &str| target_xfer(RaTarget::Sm120, &parse_sass(t, 0).unwrap());
    let base = |t: &str| reg_xfer(&parse_sass(t, 0).unwrap());
    // the 64-bit address and the 64-bit descriptor of a global access
    let l = x("LDG.E R6, desc[UR4][R2.64+0x10] ;");
    assert_eq!((l.rdefs.clone(), l.ruses.clone(), l.uuses.clone()), (set(&[6]), set(&[2, 3]), set(&[4, 5])));
    assert_eq!(base("LDG.E R6, desc[UR4][R2.64+0x10] ;").ruses, set(&[2]), "the role table's reading is unchanged");
    let s = x("STG.E.128 desc[UR4][R6.64], R64 ;");
    assert_eq!(s.ruses, set(&[6, 7, 64, 65, 66, 67]));
    // CS2R writes the pair unless it is the 32-bit form
    assert_eq!(x("CS2R R88, SRZ ;").rdefs, set(&[88, 89]));
    assert_eq!(base("CS2R R88, SRZ ;").rdefs, set(&[88]));
    assert_eq!(x("CS2R.32 R5, SR_CLOCKHI ;").rdefs, set(&[5]));
    // LDSM: .2 two registers, .4 four
    assert_eq!(x("LDSM.16.MT88.2 R72, [R80+0x80] ;").rdefs, set(&[72, 73]));
    assert_eq!(base("LDSM.16.MT88.2 R72, [R80+0x80] ;").rdefs, set(&[72]));
    assert_eq!(x("LDSM.16.M88.4 R64, [R76] ;").rdefs, set(&[64, 65, 66, 67]));
    // the grid: every span of two registers on 2, of four on 4
    for (t, want) in [
        ("IMAD.WIDE.U32 R6, PT, R64, R73, R28 ;", vec![(6u8, 2usize, 2u8), (28, 2, 2)]),
        ("LDG.E.128 R88, desc[UR4][R6.64] ;", vec![(88, 4, 4), (6, 2, 2)]),
        ("STS.128 [R84+0x10], R8 ;", vec![(8, 4, 4)]),
        ("LDC.64 R4, c[0x0][0x3a8] ;", vec![(4, 2, 2)]),
        ("HMMA.16816.F32.BF16 R28, R64, R72, R28 ;", vec![(28, 4, 4), (64, 4, 4), (72, 2, 2), (28, 4, 4)]),
    ] {
        let got: Vec<(u8, usize, u8)> =
            x(t).spans.iter().filter(|s| s.dom == RegDom::R && !s.desc_ns && s.width > 1).map(|s| (s.base, s.width, s.align)).collect();
        assert_eq!(got, want, "{t}");
    }
}

#[test]
fn sm120_keeps_a_separately_written_address_pair_together() {
    // the two halves of a 64-bit address written by two instructions; only the access joins them
    let src = kernel(
        "    S2R R40, SR_TID.X ;\n    LDCU.64 UR8, c[0x0][0x358] ;\n    LDC R21, c[0x0][0x380] ;\n    LDC R51, c[0x0][0x384] ;\n    \
         MOV R30, R21 ;\n    MOV R31, R51 ;\n    LDG.E R60, desc[UR8][R30.64] ;\n    STS [R40], R60 ;\n",
    );
    // target-neutral: the high half is dead to the pass and goes anywhere
    let neutral = rplan(&run_file(&src, RaMode::Full).unwrap());
    assert_ne!(neutral[&31], neutral[&30] + 1, "the target-neutral pass (unchanged): {neutral:?}");
    let run = run_file_opts(&src, RaMode::Full, &sm120()).unwrap();
    let m = rplan(&run);
    assert_eq!((m[&31], m[&30] % 2), (m[&30] + 1, 0), "{m:?}");
    let ur = &run.report.kernels[0].plan.as_ref().unwrap().ur;
    assert_eq!((ur["8"], ur["9"]), (0, 1), "the descriptor pair");
    assert!(run.out_text.contains(&format!("LDG.E R{}, desc[UR0][R{}.64] ;", m[&60], m[&30])), "{}", run.out_text);
}

#[test]
fn an_applied_plan_is_audited_against_the_footprints() {
    let src = kernel(
        "    S2R R0, SR_TID.X ;\n    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n    IMAD.WIDE.U32 R2, PT, R0, 0x4, R2 ;\n    \
         LDG.E.128 R8, desc[UR4][R2.64] ;\n    STS.128 [R0], R8 ;\n",
    );
    // an applied plan names every register of the kernel (the apply contract): identity, with overrides
    let plan = |over: &[(u8, u8)]| -> ApplyPlan {
        let mut r: BTreeMap<String, u8> = [0u8, 2, 3, 8, 9, 10, 11].iter().map(|n| (n.to_string(), *n)).collect();
        for (from, to) in over {
            r.insert(from.to_string(), *to);
        }
        serde_json::from_value(serde_json::json!({ "kernels": { "k": { "r": r, "ur": {"4": 4, "5": 5} } } })).unwrap()
    };
    let err = |over: &[(u8, u8)]| format!("{:#}", run_file_opts(&src, RaMode::ApplyFile(plan(over)), &sm120()).expect_err("must be refused"));
    assert!(err(&[(3, 20)]).contains("tears the 2-register operand at R2"), "{}", err(&[(3, 20)]));
    assert!(err(&[(2, 5), (3, 6)]).contains("off its grid of 2"), "{}", err(&[(2, 5), (3, 6)]));
    assert!(err(&[(8, 13), (9, 14), (10, 15), (11, 16)]).contains("off its grid of 4"));
    // on the grid: accepted, `.reg` follows
    let ok = run_file_opts(&src, RaMode::ApplyFile(plan(&[(8, 12), (9, 13), (10, 14), (11, 15), (2, 4), (3, 5)])), &sm120()).unwrap();
    assert!(ok.out_text.contains("LDG.E.128 R12, desc[UR4][R4.64] ;") && ok.out_text.contains("    .reg R0-R15\n"), "{}", ok.out_text);
    assert_eq!(ok.report.kernels[0].regcount, Some(32));
    // the target-neutral apply mode takes the torn plan as before
    let torn = run_file(&src, RaMode::ApplyFile(plan(&[(3, 20)]))).expect("unchanged: no span audit without a target");
    assert!(torn.out_text.contains("LDC.64 R2, c[0x0][0x380] ;") && torn.out_text.contains("    .reg R0-R253\n"), "{}", torn.out_text);
}

#[test]
fn reg_follows_the_allocation_and_the_shadow_law() {
    // a generator may spread its registers over the whole file: one numeral per value
    let src = kernel("    S2R R200, SR_TID.X ;\n    MOV R150, 0x1 ;\n    IADD3 R250, PT, PT, R200, R150, RZ ;\n    STS [R200], R250 ;\n");
    let run = run_file_opts(&src, RaMode::Full, &sm120()).unwrap();
    assert!(run.out_text.contains("    .reg R0-R2\n"), "{}", run.out_text);
    assert_eq!(run.report.kernels[0].regcount, Some(32), "the smallest register count");
    // an explicit register count must leave the two shadow registers above the plan (KNOWN_ISSUES A1)
    let tight = src.replace("    .reg R0-R253\n", "    .reg R0-R253\n    .regcount 4\n");
    let e = run_file_opts(&tight, RaMode::Full, &sm120()).expect_err("regcount 4 cannot hold R2");
    assert!(format!("{e:#}").contains("`.regcount 4`"), "{e:#}");
    assert!(run_file_opts(&src.replace("    .reg R0-R253\n", "    .reg R0-R253\n    .regcount 5\n"), RaMode::Full, &sm120()).is_ok());
}

#[test]
fn no_share_keeps_a_register_per_numeral() {
    let opts = RaOptions { target: Some(RaTarget::Sm120), no_share: true };
    // the attention kernel: 126 numerals on 126 registers, the footprint of the hand numbering
    let run = run_file_opts(KERNEL, RaMode::Full, &opts).unwrap();
    let m = rplan(&run);
    let homes: BTreeSet<u8> = m.values().copied().collect();
    assert_eq!((m.len(), homes.len(), *homes.iter().max().unwrap()), (126, 126, 125));
    assert_eq!(run.report.kernels[0].regcount, Some(128));
    assert!(run.out_text.contains("    .reg R0-R125\n"));
    // a kernel written with one numeral per value: sharing packs 24 numerals on 11 registers ...
    let src = include_str!("fixtures/ra_sm120/sum16.sass");
    let shared = run_file_opts(src, RaMode::Full, &sm120()).unwrap();
    let ms = rplan(&shared);
    assert_eq!((ms.len(), ms.values().collect::<BTreeSet<_>>().len()), (24, 11));
    // ... and puts the factor on the register the first load's address pair has just left:
    // the second load must then wait for the first one's address latch
    assert_eq!(ms[&20], ms[&8], "{ms:?}");
    // with no_share nothing is merged
    let apart = run_file_opts(src, RaMode::Full, &opts).unwrap();
    let ma = rplan(&apart);
    assert_eq!((ma.len(), ma.values().collect::<BTreeSet<_>>().len()), (24, 24));
    assert_eq!(apart.report.kernels[0].regcount, Some(32));
    // the switch is the full allocation's
    let e = run_file_opts(src, RaMode::Identity, &RaOptions { target: None, no_share: true }).expect_err("identity");
    assert!(format!("{e:#}").contains("--no-share"), "{e:#}");
    // without a target it works on the target-neutral model (no grid): the plan stays injective
    let neutral = run_file_opts(src, RaMode::Full, &RaOptions { target: None, no_share: true }).unwrap();
    let mn = rplan(&neutral);
    assert_eq!(mn.values().collect::<BTreeSet<_>>().len(), mn.len());
}

#[test]
fn the_target_goes_with_an_allocation() {
    let e = run_file_opts(KERNEL, RaMode::Identity, &sm120()).expect_err("identity allocates nothing");
    assert!(format!("{e:#}").contains("--mode full or --mode apply"), "{e:#}");
    assert!(RaTarget::parse("sm103a").is_err());
    assert_eq!(RaTarget::parse("sm120").unwrap().name(), "sm120");
}

#[test]
fn selector_chains_of_a_source_line() {
    let ins = |t: &str| parse_sass(t, 0).unwrap();
    let sig = |t: &str| cubit::render::selector_signature(&ins(t));
    assert_eq!(sig("F2FP.BF16.E4M3.UNPACK_B R7, R89.H1, R86.B0 ;"), vec![(1, vec!["H1".to_string()]), (2, vec!["B0".to_string()])]);
    assert_eq!(sig("@P0 HADD2.F32 R29, -RZ, R4.H0_H0 ;"), vec![(2, vec!["H0_H0".to_string()])]);
    // `.reuse` is structured, brackets and immediates are not register tokens
    assert!(sig("IMAD R9, R5.reuse, R6, RZ ;").is_empty());
    assert!(sig("LDG.E.128 R8, desc[UR4][R6.64+0x10] ;").is_empty());
    assert!(sig("FMUL.FTZ R23, R0, 1.4426950216293334961 ;").is_empty());
    assert_eq!(cubit::render::reg_token_selectors("|R56|.F32x2.HI_LO"), Some(vec!["F32x2".to_string(), "HI_LO".to_string()]));
    assert_eq!(cubit::render::reg_token_selectors("R132.reuse.ROW"), Some(vec!["ROW".to_string()]));
    assert_eq!(cubit::render::reg_token_selectors("[R5+0x10]"), None);
    assert_eq!(cubit::render::raw_operand_tokens("@!P2 STS [R81+0x20], R3 !rsd[82:1]"), vec!["[R81+0x20]", "R3"]);
}
