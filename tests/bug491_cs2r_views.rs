//! BUG-491, the other views — the second register of a 64-bit `CS2R` in the certified transfer function, the
//! barrier allocator and the scoreboard verifier (2026-11-11; KNOWN_ISSUES A40).
//!
//! `CS2R Rd, <SR>` without `.32` writes the pair `Rd:Rd+1`. The dependency walk has taken the pair since the first
//! half of BUG-491 (`tests/bug491_cs2r_pair.rs`). Three views still gave the word one register:
//!
//! * the certified transfer function (`reg_liveness::reg_xfer`) named the pair only for an `SR_*LO` register — the
//!   liveness of `Rd+1` ran through a `CS2R Rd, SRZ` as if nothing wrote it;
//! * the scheduler's destination convention (`scheduling_pass::dest_regs_plain`), by which the barrier allocator
//!   places read barriers, write barriers and waits: a store that reads `Rd+1` got no read barrier against the
//!   `CS2R` that rewrites it, and a `CS2R` that rewrites a pending result in `Rd+1` did not wait the producer's
//!   write barrier;
//! * the scoreboard verifier, which shares that convention: an overwrite of `Rd+1` in front of the wait on a
//!   memory word's read barrier was no finding (the path walks of `CUBIT_VERIFY` — store paths, write after write —
//!   take their definitions from the register allocator's footprints as well and reported the pair; the
//!   simulation's `broken WAR` count did not).
//!
//! All three give the pair now, for every special register; `CS2R.32` writes one register, as before. Nothing that
//! serves has such a site (the production sources assemble to the same bytes); cubit's `CUBIT_SYNC_CLASSES`
//! schedules of the served MoE kernels re-derive barriers and waits around their `CS2R` words.

use cubit::parser::parse_sass;
use cubit::reg_liveness::reg_xfer;
use std::collections::BTreeSet;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const DEFAULT: &[(&str, &str)] = &[];
const S1: &[(&str, &str)] = &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120"), ("CUBIT_MMA_PTXAS", "1")];
const S2: &[(&str, &str)] = &[("CUBIT_SYNC_CLASSES", "1"), ("CUBIT_SCHED2", "1"), ("CUBIT_MMA_PTXAS", "1"), ("CUBIT_SCHED2_LAT", "sm120")];
const SETS: [(&str, &[(&str, &str)]); 3] = [("the default path", DEFAULT), ("the dependency-aware schedule", S1), ("under CUBIT_SYNC_CLASSES", S2)];

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bug491v_{}_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst), tag));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

/// One scheduled word of a frozen listing: its wait mask, read barrier, write barrier and text.
struct Word {
    waits: String,
    rb: char,
    wb: char,
    text: String,
}

impl Word {
    fn waits(&self, barrier: char) -> bool {
        self.waits.contains(barrier)
    }
}

/// Schedules a kernel body from source under `env`, with `CUBIT_VERIFY`: (the words of the frozen listing, the log).
fn build(dir: &std::path::Path, body: &str, env: &[(&str, &str)]) -> (Vec<Word>, String) {
    let text = format!(
        ".entry cs2r_views\n    .reg R0-R63\n    .param ptr out\n    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n    LDC R6, c[0x0][0x390] ;\n{body}    EXIT ;\n.endentry\n"
    );
    let src = dir.join("k.sass");
    let cub = dir.join("k.cubin");
    std::fs::write(&src, text).unwrap();
    let mut e: Vec<(&str, &str)> = env.to_vec();
    e.push(("CUBIT_VERIFY", "1"));
    let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", cub.to_str().unwrap()], &e);
    assert!(ok, "{log}");
    let (ok, frozen) = cubit(&["disassemble", cub.to_str().unwrap(), "-t", TABLE, "--frozen"], &[]);
    assert!(ok, "{frozen}");
    let words = frozen
        .lines()
        .filter_map(|l| {
            let at = l.find("[B")?;
            let cc = l.get(at..at + 21)?; // [B------:R-:W-:Y:S04]
            let b = cc.as_bytes();
            Some(Word {
                waits: cc[2..8].chars().filter(|c| *c != '-').collect(),
                rb: b[10] as char,
                wb: b[13] as char,
                text: l[at + 21..].trim().trim_end_matches(';').trim().to_string(),
            })
        })
        .collect();
    (words, log)
}

fn word<'a>(words: &'a [Word], head: &str) -> &'a Word {
    words.iter().find(|w| w.text.starts_with(head)).unwrap_or_else(|| panic!("no `{head}` in the listing"))
}

#[test]
fn the_certified_transfer_function_gives_every_64_bit_cs2r_the_pair() {
    let defs = |t: &str| reg_xfer(&parse_sass(t, 0).unwrap()).rdefs;
    let set = |xs: &[u8]| xs.iter().copied().collect::<BTreeSet<u8>>();
    for sr in ["SRZ", "SR_GLOBALTIMERLO", "SR_CLOCKLO", "SR_TID"] {
        assert_eq!(defs(&format!("CS2R R8, {sr} ;")), set(&[8, 9]), "CS2R R8, {sr}");
    }
    assert_eq!(defs("CS2R.32 R8, SRZ ;"), set(&[8]));
    assert_eq!(defs("CS2R.32 R8, SR_CLOCKHI ;"), set(&[8]));
    let x = reg_xfer(&parse_sass("CS2R R8, SRZ ;", 0).unwrap());
    assert!(x.known && x.ruses.is_empty());
}

/// A store reads `R33`; the `CS2R R32, SRZ` behind it rewrites `R33`. The store carries a read barrier and the `CS2R`
/// waits it — on the default path too. The 32-bit form does not write `R33`: the store stays bare.
#[test]
fn a_store_that_reads_the_second_register_is_protected_against_the_cs2r_that_rewrites_it() {
    let dir = scratch("war");
    let body = |cs2r: &str| format!("    FMUL.FTZ R33, R6, R6 ;\n    STG.E desc[UR4][R2.64], R33 ;\n    {cs2r} ;\n    STG.E desc[UR4][R2.64+0x8], R32 ;\n");
    for (set, env) in SETS {
        let (words, log) = build(&dir, &body("CS2R R32, SRZ"), env);
        let (store, cs2r) = (word(&words, "STG.E desc[UR4][R2.64], R33"), word(&words, "CS2R"));
        assert_ne!(store.rb, '-', "{set}: the store that reads R33 carries a read barrier");
        assert!(cs2r.waits(store.rb), "{set}: the CS2R waits the store's read barrier {} (its wait mask: `{}`)", store.rb, cs2r.waits);
        assert!(log.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale") && !log.contains("STORE PATH:"), "{set}: {log}");
    }
    let (words, log) = build(&dir, &body("CS2R.32 R32, SRZ"), DEFAULT);
    let (store, cs2r) = (word(&words, "STG.E desc[UR4][R2.64], R33"), word(&words, "CS2R"));
    assert_eq!((store.rb, cs2r.waits.as_str()), ('-', ""), "CS2R.32 writes one register: {log}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A load's result is pending in `R33`; `CS2R R32, SRZ` writes `R33` again. The `CS2R` waits the load's write barrier
/// (write after write, BUG-489's rule), and the reader of `R33` behind it reads the `CS2R`'s value: it does not wait
/// the load.
#[test]
fn a_cs2r_that_rewrites_a_pending_result_in_its_second_register_waits_the_producer() {
    let dir = scratch("waw");
    let body = "    LDG.E R33, desc[UR4][R2.64] ;\n    CS2R R32, SRZ ;\n    FMUL.FTZ R4, R6, R33 ;\n    STG.E desc[UR4][R2.64+0x8], R4 ;\n";
    for (set, env) in SETS {
        let (words, log) = build(&dir, body, env);
        let (load, cs2r, reader) = (word(&words, "LDG.E R33"), word(&words, "CS2R"), word(&words, "FMUL.FTZ R4, R6, R33"));
        assert_ne!(load.wb, '-', "{set}: the load is scoreboarded");
        assert!(cs2r.waits(load.wb), "{set}: the CS2R waits the load's write barrier {} (its wait mask: `{}`)", load.wb, cs2r.waits);
        assert!(!reader.waits(load.wb), "{set}: the reader of R33 takes the CS2R's value, not the load's (its wait mask: `{}`)", reader.waits);
        assert!(!log.contains("WRITE AFTER WRITE:") && log.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale"), "{set}: {log}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The scoreboard verifier on a frozen text: a `CS2R` that rewrites the second register in front of the wait on the
/// read barrier of the store that reads it is a broken WAR.
#[test]
fn the_scoreboard_verifier_counts_an_overwrite_of_the_second_register_as_a_broken_war() {
    let dir = scratch("verify");
    let frozen = |cs2r: &str| {
        format!(
            ".entry cs2r_views\n    .reg R0-R63\n    .regcount 72\n    .param u64 p0 offset=0x0\n    [B------:R0:W-:Y:S04] STG.E desc[UR4][R2.64], R33 ;\n    {cs2r} ;\n    [B0-----:R-:W-:Y:S04] MOV R5, R6 ;\n    [B------:R-:W-:Y:S05] EXIT ;\n.endentry\n"
        )
    };
    let check = |name: &str, cs2r: &str| -> String {
        let src = dir.join(format!("{name}.sass"));
        std::fs::write(&src, frozen(cs2r)).unwrap();
        let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", dir.join(format!("{name}.cubin")).to_str().unwrap()], &[("CUBIT_VERIFY", "1")]);
        assert!(ok, "{log}");
        log
    };
    let log = check("bare", "[B------:R-:W-:Y:S04] CS2R R32, SRZ");
    assert!(log.contains("BROKEN WAR: insn[1] CS2R overwrites R33 before rb (barrier 0) of mem-op insn[0] STG.E is waited"), "{log}");
    assert!(log.contains("CUBIT_VERIFY: 0 unprotected RAW, 1 broken WAR, 0 recycle-stale"), "{log}");
    // the CS2R waits the store's read barrier: clean
    let log = check("waited", "[B0-----:R-:W-:Y:S04] CS2R R32, SRZ");
    assert!(log.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale") && !log.contains("BROKEN WAR"), "{log}");
    // the 32-bit form does not write R33
    let log = check("half", "[B------:R-:W-:Y:S04] CS2R.32 R32, SRZ");
    assert!(log.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale") && !log.contains("BROKEN WAR"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}
