//! `CS2UR` is a fixed-latency word: no write barrier, its reader at ptxas's distance (2026-11-12).
//!
//! `CS2UR UR4, SR_GLOBALTIMERLO` copies a special register into a uniform register — `CS2R` for the uniform
//! register file. ptxas schedules both as fixed-latency words: no write barrier, the reader a number of issue
//! cycles behind (the vendor's sm_120 kernels: every `CS2UR` word without a write barrier, its first reader 6
//! issue cycles behind it or later, never closer; no `CS2R` word with a write barrier either). cubit excluded
//! `CS2R` from the scoreboarded producers long ago and missed its uniform twin: the class tables call `CS2UR` a
//! special-register load, so the allocator gave it a write barrier and put the wait on its reader — in every
//! recipe, the default one included. A wait on a barrier nothing is pending on is no cover: in cubit's schedule of
//! a served kernel's text the reader of the timer stood 2 issue cycles behind the `CS2UR` (5 under the older
//! recipes), and every schedule of that form that reached silicon stopped in the kernel's own timeout check —
//! `now - start` with a stale `now`. The scoreboard simulation saw nothing: it takes every write barrier for a
//! pending result.
//!
//! Now: no write barrier on `CS2UR`; the reader stands `CS2UR_RESULT_LATENCY` = 6 issue cycles behind it or
//! later (the dependency table has the cell `CS2UR` -> `IADD`, the uniform operand, = 6: ptxas's distance and the
//! pair's silicon floor on one card model); and the verifier names a `CS2R` / `CS2UR` that carries a write barrier
//! in a text it is given (`CUBIT_VERIFY_FIXED`, beside the three counts). KNOWN_ISSUES A48.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const S1: &[(&str, &str)] = &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120"), ("CUBIT_MMA_PTXAS", "1")];

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

fn with<'a>(env: &[(&'a str, &'a str)], more: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut v = env.to_vec();
    v.extend_from_slice(more);
    v
}

/// One instruction line of a frozen listing: (wait mask, read barrier, write barrier, stall, text).
type Word = (String, String, String, u32, String);

fn words(frozen: &str) -> Vec<Word> {
    frozen
        .lines()
        .filter_map(|l| {
            let t = l.trim_start();
            let close = t.find(']')?;
            let f: Vec<&str> = t.strip_prefix('[')?[..close - 1].split(':').collect();
            (f.len() == 5 && f[4].starts_with('S')).then(|| {
                (f[0].to_string(), f[1].to_string(), f[2].to_string(), f[4][1..].parse().unwrap(), t[close + 1..].trim().trim_end_matches(';').trim().to_string())
            })
        })
        .collect()
}

/// The schedule `cubit asm` builds from `text` under `env` (its words) and the log of the build.
fn build(text: &str, env: &[(&str, &str)]) -> (Vec<Word>, String) {
    let dir = std::env::temp_dir().join(format!("cs2ur_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, text).unwrap();
    let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()], env);
    assert!(ok, "asm {env:?} failed:\n{log}");
    let (ok, frozen) = cubit(&["disassemble", "-t", TABLE, "--frozen", out.to_str().unwrap()], &[]);
    assert!(ok, "disassemble failed: {frozen}");
    let _ = std::fs::remove_dir_all(&dir);
    let w = words(&frozen);
    assert!(!w.is_empty(), "no instruction lines in:\n{frozen}");
    (w, log)
}

/// The timeout check of a spin-wait, alone: the start of the wait in a register pair, the time now in a uniform
/// register, their difference against the limit.
const KERNEL: &str = "\
.entry cs2ur_probe
    .reg R0-R31
    .param ptr out
    LDCU.64 UR8, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    CS2R R30, SR_GLOBALTIMERLO ;
    MOV R17, R2 ;
    IADD3 R21, PT, PT, R17, 0x64, RZ ;
    CS2UR UR4, SR_GLOBALTIMERLO ;
    LDCU.64 UR6, c[0x0][0x420] ;
    IADD.64 R14, -R30, UR4 ;
    ISETP.GT.U64.AND P0, PT, R14, UR6, PT ;
    @P0 EXIT ;
    STG.E desc[UR8][R2.64], R14 ;
    EXIT ;
.endentry
";

/// The schedule cubit built from `KERNEL` before the fix (`CUBIT_SYNC_CLASSES` + the dependency-aware scheduler +
/// `CUBIT_SCHED2_MEMSTALL=table`): a write barrier on the `CS2UR`, the reader two issue cycles behind it on a wait
/// on that barrier.
const BEFORE: &str = "\
.entry cs2ur_probe
    .reg R0-R30
    .regcount 40
    .param ptr p0 offset=0x0
    [B------:R-:W0:Y:S01] LDCU.64 UR8, c[0x0][0x358] ;
    [B------:R-:W1:Y:S01] LDC.64 R2, c[0x0][0x380] ;
    [B------:R-:W-:Y:S01] CS2R R30, SR_GLOBALTIMERLO ;
    [B-1----:R-:W-:-:S05] MOV R17, R2 ;
    [B------:R-:W-:Y:S01] IADD3 R21, PT, PT, R17, 0x64, RZ ;
    [B------:R-:W1:Y:S01] CS2UR UR4, SR_GLOBALTIMERLO ;
    [B------:R-:W2:Y:S01] LDCU.64 UR6, c[0x0][0x420] ;
    [B-1----:R-:W-:-:S06] IADD.64 R14, -R30, UR4 ;
    [B--2---:R-:W-:-:S13] ISETP.GT.U64.AND P0, PT, R14, UR6, PT ;
    [B------:R-:W-:Y:S05] @P0 EXIT ;
    [B0-----:R-:W-:Y:S01] STG.E desc[UR8][R2.64], R14 ;
    [B------:R-:W-:Y:S05] EXIT ;
.endentry
";

/// Every recipe a kernel is built with: the default scheduler, the dependency-aware one, the synchronisation
/// classes, the table's stalls behind memory words, the lowering pass and the wait-policy switches on top.
fn recipes() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    let sync = with(S1, &[("CUBIT_SYNC_CLASSES", "1")]);
    let table = with(&sync, &[("CUBIT_SCHED2_MEMSTALL", "table")]);
    let lower = with(&table, &[("CUBIT_SCHED2_LOWER", "1")]);
    let policy = with(&lower, &[("CUBIT_MMA_SRC_RB", "0"), ("CUBIT_GUARDED_READER_SETTLES", "1"), ("CUBIT_SB_SHARE", "1")]);
    vec![
        ("the default scheduler", vec![]),
        ("the dependency-aware scheduler", S1.to_vec()),
        ("the synchronisation classes", sync),
        ("the table's stalls behind memory words", table),
        ("the lowering pass", lower),
        ("the wait-policy switches", policy),
    ]
}

#[test]
fn a_cs2ur_carries_no_write_barrier_and_its_reader_stands_six_issue_cycles_behind_it() {
    for (name, env) in recipes() {
        let (w, log) = build(KERNEL, &with(&env, &[("CUBIT_VERIFY", "1")]));
        let at = w.iter().position(|x| x.4.starts_with("CS2UR")).unwrap_or_else(|| panic!("{name}: no CS2UR in {w:?}"));
        let reader = at + w[at..].iter().position(|x| x.4.starts_with("IADD.64")).unwrap_or_else(|| panic!("{name}: no reader in {w:?}"));
        assert_eq!(w[at].2, "W-", "{name}: the `CS2UR` carries a write barrier:\n{w:?}");
        let d: u32 = w[at..reader].iter().map(|x| x.3).sum();
        assert!(d >= 6, "{name}: the reader stands {d} issue cycles behind the `CS2UR`:\n{w:?}");
        // the limit's load is a load: it keeps its barrier, and its reader waits it
        let limit = w.iter().find(|x| x.4.starts_with("LDCU.64 UR6")).unwrap();
        let cmp = w.iter().find(|x| x.4.starts_with("ISETP.GT.U64")).unwrap();
        assert_ne!(limit.2, "W-", "{name}: {w:?}");
        assert!(cmp.0.contains(&limit.2[1..]), "{name}: the comparison does not wait the limit's load:\n{w:?}");
        // the start of the wait, `CS2R`, never had a barrier
        assert_eq!(w.iter().find(|x| x.4.starts_with("CS2R")).unwrap().2, "W-", "{name}: {w:?}");
        assert!(log.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale"), "{name}: {log}");
        assert!(!log.contains("CUBIT_VERIFY_FIXED"), "{name}: {log}");
    }
}

#[test]
fn under_the_dependency_table_the_reader_stands_at_the_cell_and_the_checks_are_clean() {
    // the cell `CS2UR` -> `IADD` (the uniform operand) = 6: the legaliser asks for exactly that, and the lowering pass
    // leaves nothing above it
    for (name, env) in recipes().into_iter().skip(1) {
        let (w, log) = build(KERNEL, &with(&env, &[("CUBIT_VERIFY", "1"), ("CUBIT_DEP_VERIFY", "1")]));
        let at = w.iter().position(|x| x.4.starts_with("CS2UR")).unwrap();
        let reader = at + w[at..].iter().position(|x| x.4.starts_with("IADD.64")).unwrap();
        let d: u32 = w[at..reader].iter().map(|x| x.3).sum();
        assert!(d >= 6, "{name}: {d}\n{w:?}");
        if env.iter().any(|e| e.0 == "CUBIT_SCHED2_LOWER") {
            assert_eq!(d, 6, "{name}: the lowered schedule keeps the reader above the cell:\n{w:?}");
        }
        assert!(
            log.contains("DEP_VERIFY 0 below a table cell, 0 waits closer than the arming distance to their barrier's setter, 0 below a resource spacing, 0 below a default"),
            "{name}: {log}"
        );
    }
}

#[test]
fn the_verifier_names_a_write_barrier_on_a_fixed_latency_special_register_read() {
    let dir = std::env::temp_dir().join(format!("cs2ur_v_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out) = (dir.join("before.sass"), dir.join("before.cubin"));
    std::fs::write(&src, BEFORE).unwrap();
    for env in [&[("CUBIT_VERIFY", "1"), ("CUBIT_DEP_VERIFY", "1")][..], &[("CUBIT_VERIFY", "1"), ("CUBIT_DEP_VERIFY", "1"), ("CUBIT_SYNC_CLASSES", "1")][..]] {
        let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()], env);
        assert!(ok, "{log}");
        // the table prices the pair whatever barrier the text gives the word: 2 issue cycles where the cell asks 6
        assert!(log.contains("DEP_VERIFY 1 below a table cell"), "{env:?}: {log}");
        assert!(log.contains("CS2UR UR4, SR_GLOBALTIMERLO -> [7] IADD.64 R14, -R30, UR4") && log.contains("distance 2 < 6"), "{env:?}: {log}");
        // the three counts do not see it: the reader waits the barrier the word "sets"
        assert!(log.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale"), "{env:?}: {log}");
        assert!(log.contains("FIXED-LATENCY BARRIER: insn[5] CS2UR carries write barrier 1"), "{env:?}: {log}");
        assert!(log.contains("its first reader insn[7] IADD.64 2 issue cycle(s) behind it"), "{env:?}: {log}");
        assert!(log.contains("CUBIT_VERIFY_FIXED: 1 fixed-latency special-register read(s) carry a write barrier"), "{env:?}: {log}");
    }
    // a frozen listing is assembled as it stands: the words of BEFORE are what comes out
    let (ok, frozen) = cubit(&["disassemble", "-t", TABLE, "--frozen", out.to_str().unwrap()], &[]);
    assert!(ok, "{frozen}");
    let w = words(&frozen);
    assert_eq!(w.iter().find(|x| x.4.starts_with("CS2UR")).unwrap().2, "W1", "{w:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
