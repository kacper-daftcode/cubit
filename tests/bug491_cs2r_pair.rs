//! BUG-491 — a 64-bit `CS2R` writes a register PAIR, and the scheduler's dependency model gave it one register
//! (2026-11-11; KNOWN_ISSUES A40).
//!
//! `CS2R Rd, <SR>` without `.32` writes `Rd:Rd+1` (`CS2R R8, SRZ` zeroes R8 and R9 — the control of the stall-floor
//! probes; the vendor's assembler zeroes accumulator pairs this way: 22 116 `CS2R Rn, SRZ` in the sm_120 census,
//! every one on an even register). The encoder's register grid and the register allocator's target have known the
//! pair since BUG-488. The scheduler's destination convention and the certified transfer function did not: for
//! them the word defined `Rd` only (the certified function named the pair for `SR_*LO` registers alone). So a
//! reader of `Rd+1` had no producer — the dependency legaliser left it at any distance behind the `CS2R`, and
//! `CUBIT_DEP_VERIFY` reported nothing — while on silicon the pair's floor is 6 issue cycles for either register
//! (`tools/stallfloor/probe_sm120_20261111_b33.json`: `CS2R` → `FMUL` for result register 0 and for result
//! register 1, one cycle closer wrong in almost every thread).
//!
//! The dependency walk takes the pair now (`dep_stall::dest_regs`: the legaliser and `CUBIT_DEP_VERIFY`). The
//! barrier allocator, the liveness and the scoreboard verifier keep the scheduler's convention — with the pair
//! there cubit's schedules of the served MoE kernels re-derive their scoreboard, a change to measure on its own.
//!
//! Found by counting `CS2R` → reader distances with both registers: cubit's own `CUBIT_SYNC_CLASSES` schedules of
//! the vendor's census texts held 24 such pairs below 6 in 12 kernels (4 and 5 cycles; 1 and 2 under
//! `CUBIT_SCHED2_MEMSTALL=table`), where the vendor keeps 7 and 8. Nothing that serves has a reader of either
//! register within 9 cycles of a `CS2R`.
//!
//! The numbers of this file moved from 6 to 7 with the table's `producer_forms` entry (the pair form is priced at
//! the vendor's 7, one above its floor: `tests/cs2r_pair_form_cell.rs`); what the file pins is unchanged — BOTH
//! registers of the pair are held alike.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const S1: &[(&str, &str)] = &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120"), ("CUBIT_MMA_PTXAS", "1")];
const S2: &[(&str, &str)] = &[("CUBIT_SYNC_CLASSES", "1"), ("CUBIT_SCHED2", "1"), ("CUBIT_MMA_PTXAS", "1"), ("CUBIT_SCHED2_LAT", "sm120")];

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bug491_{}_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst), tag));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

/// A kernel whose only word behind `CS2R R32, SRZ` reads `reader` (R32 or R33).
fn source(reader: &str) -> String {
    format!(
        ".entry cs2r_pair\n    .reg R0-R63\n    .param ptr out\n    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n    LDC R6, c[0x0][0x390] ;\n    CS2R R32, SRZ ;\n    FMUL.FTZ R4, R6, {reader} ;\n    STG.E desc[UR4][R2.64], R4 ;\n    EXIT ;\n.endentry\n"
    )
}

/// Schedules `text` from source under `env`: (the frozen listing, the stall of the `CS2R` = the issue distance to
/// the word behind it).
fn schedule(dir: &std::path::Path, name: &str, text: &str, env: &[(&str, &str)]) -> (String, u32) {
    let src = dir.join(format!("{name}.sass"));
    let cub = dir.join(format!("{name}.cubin"));
    std::fs::write(&src, text).unwrap();
    let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", cub.to_str().unwrap()], env);
    assert!(ok, "{log}");
    let (ok, frozen) = cubit(&["disassemble", cub.to_str().unwrap(), "-t", TABLE, "--frozen"], &[]);
    assert!(ok, "{frozen}");
    let line = frozen.lines().find(|l| l.contains("CS2R R32, SRZ")).unwrap_or_else(|| panic!("no CS2R in {frozen}"));
    let stall: u32 = line.split(":S").nth(1).and_then(|s| s.get(..2)).and_then(|s| s.parse().ok()).unwrap_or_else(|| panic!("no stall in {line}"));
    (frozen, stall)
}

#[test]
fn a_reader_of_the_second_register_of_a_cs2r_pair_is_held_like_a_reader_of_the_first() {
    let dir = scratch("sched");
    for (set, env) in [("the dependency-aware schedule", S1), ("under CUBIT_SYNC_CLASSES", S2)] {
        let (lo_text, lo) = schedule(&dir, "lo", &source("R32"), env);
        let (hi_text, hi) = schedule(&dir, "hi", &source("R33"), env);
        assert_eq!(lo, 7, "{set}: a reader of the first register stands 7 behind the CS2R: {lo_text}");
        assert_eq!(hi, 7, "{set}: a reader of the SECOND register stands 7 behind it too: {hi_text}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_dependency_check_sees_a_reader_of_the_second_register_closer_than_the_pairs_floor() {
    let dir = scratch("verify");
    let frozen = |stall: u32, reader: &str| -> String {
        format!(
            ".entry cs2r_pair\n    .reg R0-R63\n    .regcount 72\n    .param u64 p0 offset=0x0\n    [B------:R-:W-:Y:S{stall:02}] CS2R R32, SRZ ;\n    [B------:R-:W-:Y:S01] FMUL.FTZ R4, R6, {reader} ;\n    [B------:R-:W-:Y:S05] EXIT ;\n.endentry\n"
        )
    };
    let check = |name: &str, text: &str| -> String {
        let src = dir.join(format!("{name}.sass"));
        std::fs::write(&src, text).unwrap();
        let (ok, log) = cubit(
            &["asm", "-t", TABLE, src.to_str().unwrap(), "-o", dir.join(format!("{name}.cubin")).to_str().unwrap()],
            &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120"), ("CUBIT_DEP_VERIFY", "1")],
        );
        assert!(ok, "{log}");
        log
    };
    for reader in ["R32", "R33"] {
        // four cycles behind the pair: below the floor for either register
        let log = check("close", &frozen(4, reader));
        assert!(log.contains(&format!("CS2R R32, SRZ -> [1] FMUL.FTZ R4, R6, {reader} (raw {reader}): distance 4 < 7")), "{reader}: {log}");
        assert!(log.contains("DEP_VERIFY 1 below a table cell"), "{reader}: {log}");
        // seven (the pair form's number since the table prices it apart: `tests/cs2r_pair_form_cell.rs`): clean
        let log = check("far", &frozen(7, reader));
        assert!(log.contains("DEP_VERIFY 0 below a table cell, 0 waits closer than the arming distance to their barrier's setter, 0 below a resource spacing, 0 below a default"), "{reader}: {log}");
    }
    // the 32-bit form writes one register: a reader of the next register is no reader of it
    let one = frozen(1, "R33").replace("CS2R R32, SRZ", "CS2R.32 R32, SRZ");
    let log = check("dot32", &one);
    assert!(log.contains("0 below a default") && !log.contains("DEP dflt"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}
