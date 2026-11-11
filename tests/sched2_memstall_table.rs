//! `CUBIT_SCHED2_MEMSTALL=table` (2026-11-11): the stall behind a memory word is the dependency table's.
//!
//! Under `CUBIT_SCHED2` the first scheduling pass still writes stalls of its own on memory words — older than the
//! dependency table and than the allocator that runs behind the pass:
//!
//! * **4** on every load and every store (9 on a store in front of a back edge): the margin that covered an
//!   overwriter of a late operand before the read barriers were set by liveness;
//! * **10** on a load whose destination register number a predicate writer reads earlier in the text of the loop
//!   ("the next iteration's loop-guard compare reads it"): a test on register NUMBERS — a register the loop reuses
//!   for another value (an index early in the pass, a partial sum late in it) trips it;
//! * **8** on a load for which the pass's own text-order barrier allocation had no free barrier: the retirement
//!   stall of its recycle drain.
//!
//! ptxas writes none of them: behind a shared-memory load it stalls 4 where the next word is a memory word (27 718
//! of 32 718 sites in the 381 distinct kernels of the sm_120 census, never more than 7) and 1 where it is not (32 628
//! of 38 298). On the sparse-MLA attention kernel these stalls are time: the same words with 66 of them lowered by
//! hand run 1.0 % faster on two card models, legal by every check.
//!
//! With the variable — valid only where the latency legaliser follows (`CUBIT_SCHED2` + a table in
//! `CUBIT_SCHED2_LAT`), refused otherwise — the first two are not written: the table's rows (`mem` 4, `ldc` 8,
//! `bar` → `mem` 6, the arming distance) hold the memory words apart on every path, and the pass's own spacing of
//! two adjacent words of one memory pipe stays. Two distances that the margins kept by accident become
//! requirements by name, as under `CUBIT_SYNC_CLASSES`: what has to have landed in front of `EXIT` (and the other
//! settle words), and the operand hold of an MMA. **The third stall stays** — it is the margin of a barrier re-used
//! while its first group is in flight, which nobody has measured (KNOWN_ISSUES A32) — but has its name under the
//! variable: `CUBIT_RECYCLE_DRAIN=<n>` (an experiment, not a form for production). **Without the variable nothing
//! changes: the default path, and every switch set that exists, byte for byte.**

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");

/// The dependency-aware schedule with the table: the switch set the opt-in is valid in.
const S1: &[(&str, &str)] = &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120"), ("CUBIT_MMA_PTXAS", "1")];
const OPT: (&str, &str) = ("CUBIT_SCHED2_MEMSTALL", "table");

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("memstall_{}_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst), tag));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

fn with<'a>(env: &[(&'a str, &'a str)], more: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut v = env.to_vec();
    v.extend_from_slice(more);
    v
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Line {
    wait: u8,
    wb: Option<u8>,
    stall: u32,
    text: String,
}

fn parse_line(l: &str) -> Option<Line> {
    let t = l.trim_start();
    let rest = match t.find('[') {
        Some(0) => t,
        Some(p) if t[..p].trim_end().ends_with(':') => &t[p..],
        _ => return None,
    };
    let close = rest.find(']')?;
    let f: Vec<&str> = rest[1..close].split(':').collect();
    if f.len() != 5 || !f[0].starts_with('B') || !f[4].starts_with('S') {
        return None;
    }
    let wait = f[0][1..].chars().filter_map(|c| c.to_digit(10)).fold(0u8, |m, b| m | (1 << b));
    Some(Line { wait, wb: f[2][1..].parse::<u8>().ok(), stall: f[4][1..].parse().ok()?, text: rest[close + 1..].trim().trim_end_matches(';').trim().to_string() })
}

struct Built {
    lines: Vec<Line>,
    cubin: Vec<u8>,
    /// the frozen listing of what was built
    frozen: String,
    /// what `cubit asm` printed
    log: String,
}

/// `cubit asm` of `text` under `env`, then the schedule read back from the cubin.
fn build(text: &str, env: &[(&str, &str)]) -> Built {
    let dir = scratch("k");
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, text).unwrap();
    let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()], env);
    assert!(ok, "asm {env:?} failed:\n{log}");
    let cubin = std::fs::read(&out).unwrap();
    let (ok, frozen) = cubit(&["disassemble", "-t", TABLE, "--frozen", out.to_str().unwrap()], &[]);
    assert!(ok, "disassemble failed: {frozen}");
    let _ = std::fs::remove_dir_all(&dir);
    let lines: Vec<Line> = frozen.lines().filter_map(parse_line).collect();
    assert!(!lines.is_empty(), "no instruction lines in:\n{frozen}");
    Built { lines, cubin, frozen, log }
}

/// The read-only checks on a frozen listing under `env`: what `cubit asm` printed.
fn check(frozen: &str, env: &[(&str, &str)]) -> String {
    let dir = scratch("c");
    let src = dir.join("k.sass");
    std::fs::write(&src, frozen).unwrap();
    let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", dir.join("k.cubin").to_str().unwrap()], env);
    assert!(ok, "{env:?}: {log}");
    let _ = std::fs::remove_dir_all(&dir);
    log
}

/// Index of the `nth` instruction whose text starts with `head`.
fn idx(b: &Built, head: &str, nth: usize) -> usize {
    b.lines.iter().enumerate().filter(|(_, l)| l.text.starts_with(head)).map(|(i, _)| i).nth(nth).unwrap_or_else(|| panic!("no `{head}` #{nth} in {:?}", b.lines))
}

fn stall(b: &Built, head: &str, nth: usize) -> u32 {
    b.lines[idx(b, head, nth)].stall
}

/// Issue distance (the sum of the stalls) from instruction `from` to instruction `to`.
fn distance(b: &Built, from: usize, to: usize) -> u32 {
    b.lines[from..to].iter().map(|l| l.stall).sum()
}

const CLEAN_VERIFY: &str = "CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale";
const CLEAN_DEP: &str = "DEP_VERIFY 0 below a table cell, 0 waits closer than the arming distance to their barrier's setter, 0 below a resource spacing, 0 below a default";

/// A loop that uses R8 twice: an index it compares (`ISETP … R8`) and, later in the pass, the first of four
/// partial sums it reloads from shared memory — the softmax of the attention kernel in small. A shared store in
/// the middle, a global store in front of the back edge.
const LOOP: &str = "\
.entry memstall_probe
    .reg R0-R31
    .param ptr out
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    MOV R6, RZ ;
    MOV R20, 0x100 ;
L_top:
    LDS R8, [R20] ;
    ISETP.GE.AND P0, PT, R8, RZ, PT ;
    LDS R8, [R20+0x40] ;
    LDS R9, [R20+0x80] ;
    LDS R10, [R20+0xc0] ;
    LDS R11, [R20+0x100] ;
    FADD.FTZ R12, R8, R9 ;
    FADD.FTZ R13, R10, R11 ;
    STS [R20+0x200], R12 ;
    FADD.FTZ R14, R12, R13 ;
    @P0 STG.E desc[UR4][R2.64], R14 ;
    IADD3 R6, PT, PT, R6, 0x1, RZ ;
    ISETP.LT.AND P1, PT, R6, 0x10, PT ;
    @P1 BRA L_top ;
    EXIT ;
.endentry
";

#[test]
fn the_margins_of_the_first_pass_are_what_the_default_writes_and_the_table_is_what_the_opt_in_writes() {
    let dflt = build(LOOP, S1);
    // the 10: the reload of R8 counts as "read by the next iteration's compare" -- by its register number
    assert_eq!(stall(&dflt, "LDS R8, [R20+0x40]", 0), 10, "{}", dflt.frozen);
    // the 4 where no memory word follows: the last load of the run, the shared store
    assert_eq!(stall(&dflt, "LDS R11", 0), 4);
    assert_eq!(stall(&dflt, "STS", 0), 4);
    // the 9: a store within four words of a back edge
    assert_eq!(stall(&dflt, "@P0 STG.E", 0), 9);

    let opt = build(LOOP, &with(S1, &[OPT]));
    // a load in front of a load: 4, the table's row for two words of the memory pipe (and the vendor's number)
    for (head, n) in [("LDS R8, [R20+0x40]", 0), ("LDS R9", 0), ("LDS R10", 0)] {
        assert_eq!(stall(&opt, head, n), 4, "`{head}` in front of a load: {}", opt.frozen);
    }
    // no memory word behind it: 1 (the first reader of the run waits another barrier of it two words on)
    assert_eq!(stall(&opt, "LDS R11", 0), 1, "{}", opt.frozen);
    assert_eq!(stall(&opt, "STS", 0), 1);
    assert_eq!(stall(&opt, "@P0 STG.E", 0), 1);
    // the first load of the pass: its reader is the next word and waits its barrier -- the arming distance, 2
    assert_eq!(stall(&opt, "LDS R8, [R20]", 0), 2);
    // the same words, the same barriers and waits: only stalls (and the yield flags that follow them) differ
    assert_eq!(dflt.lines.len(), opt.lines.len());
    for (a, b) in dflt.lines.iter().zip(&opt.lines) {
        assert_eq!((&a.text, a.wait, a.wb), (&b.text, b.wait, b.wb), "{}\n{}", dflt.frozen, opt.frozen);
    }
    // one pass of the loop: 73 issue cycles by the default's margins, 52 by the table
    let pass = |b: &Built| distance(b, idx(b, "LDS R8, [R20]", 0), idx(b, "EXIT", 0));
    assert_eq!((pass(&dflt), pass(&opt)), (73, 52), "{}\n{}", dflt.frozen, opt.frozen);
}

#[test]
fn the_opt_in_schedule_is_legal_by_every_check_also_for_words_without_a_read_barrier() {
    let opt = build(LOOP, &with(S1, &[OPT, ("CUBIT_VERIFY", "1"), ("CUBIT_DEP_VERIFY", "1")]));
    assert!(opt.log.contains(CLEAN_VERIFY) && opt.log.contains(CLEAN_DEP), "{}", opt.log);
    for extra in [&[][..], &[("CUBIT_VERIFY_RBPROBE", "1")][..], &[("CUBIT_SYNC_CLASSES", "1")][..], &[("CUBIT_DEP_TABLE", "sm120-silicon")][..]] {
        // the frozen listing, as a gate reads it: the scoreboard, the walks, the table -- and the probe's view (a load
        // or store that carries NO read barrier is tracked too: the margins' own subject), and the landing rows
        let log = check(&opt.frozen, &with(&[("CUBIT_VERIFY", "1"), ("CUBIT_DEP_VERIFY", "1")], extra));
        assert!(log.contains(CLEAN_VERIFY) && log.contains(CLEAN_DEP), "{extra:?}: {log}");
        for class in ["BROKEN WAR", "STORE PATH", "WRITE AFTER WRITE", "SHUFFLE SOURCE", "UNPROTECTED RAW"] {
            assert!(!log.contains(class), "{extra:?}: {log}");
        }
    }
}

#[test]
fn without_the_variable_nothing_moves_and_the_older_switch_is_what_it_was() {
    let plain = build(LOOP, S1);
    // an empty value is "unset"
    assert_eq!(build(LOOP, &with(S1, &[("CUBIT_SCHED2_MEMSTALL", "")])).cubin, plain.cubin);
    // the knob of the drain's stall belongs to the opt-in in this branch: alone it changes no byte
    assert_eq!(build(LOOP, &with(S1, &[("CUBIT_RECYCLE_DRAIN", "0")])).cubin, plain.cubin);
    assert_eq!(build(DRAIN, &with(S1, &[("CUBIT_RECYCLE_DRAIN", "0")])).cubin, build(DRAIN, S1).cubin);
    // the default scheduler does not know the variable's subject at all
    let dflt = build(LOOP, &[]);
    assert_ne!(dflt.cubin, plain.cubin);
    // CUBIT_SCHED2_NOMEMSTALL (the older switch: the 4 / 9 / 10 off, nothing put in their place) is unchanged by the
    // opt-in's existence, and is not the opt-in: it keeps no landing row (the last test)
    let nomem = build(LOOP, &with(S1, &[("CUBIT_SCHED2_NOMEMSTALL", "1")]));
    assert_eq!(stall(&nomem, "LDS R8, [R20+0x40]", 0), 4);
    assert_eq!(stall(&nomem, "STS", 0), 1);
}

#[test]
fn the_variable_is_refused_without_the_legaliser_and_with_any_other_value() {
    let dir = scratch("refuse");
    let src = dir.join("k.sass");
    std::fs::write(&src, LOOP).unwrap();
    let asm = |env: &[(&str, &str)]| cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", dir.join("k.cubin").to_str().unwrap()], env);
    // no CUBIT_SCHED2 at all; CUBIT_SCHED2 without a table: nothing would hold the memory words to the table's rows
    for env in [&[OPT][..], &[OPT, ("CUBIT_SCHED2", "1")][..]] {
        let _ = std::fs::remove_file(dir.join("k.cubin"));
        let (ok, log) = asm(env);
        assert!(!ok && log.contains("CUBIT_SCHED2_MEMSTALL=table needs CUBIT_SCHED2=1 CUBIT_SCHED2_LAT=<table>"), "{env:?}: {log}");
        assert!(!dir.join("k.cubin").exists(), "{env:?}: a refused kernel is not written");
    }
    // a misspelt value must not build the default schedule silently
    for bad in ["1", "tabel", "TABLE", "off"] {
        let (ok, log) = asm(&with(S1, &[("CUBIT_SCHED2_MEMSTALL", bad)]));
        assert!(!ok && log.contains(&format!("CUBIT_SCHED2_MEMSTALL={bad}: the only value is `table`")), "{bad}: {log}");
    }
    let (ok, log) = asm(&with(S1, &[OPT]));
    assert!(ok, "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Seven groups of loads with no reader between them (shared and constant loads in turn: a class change opens
/// a barrier): the first pass's text-order allocation runs out of its six barriers at the fifth.
const DRAIN: &str = "\
.entry drain_probe
    .reg R0-R31
    .param ptr out
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    MOV R20, 0x100 ;
    LDS R8, [R20] ;
    LDC R9, c[0x0][0x390] ;
    LDS R10, [R20+0x40] ;
    LDC R11, c[0x0][0x394] ;
    LDS R12, [R20+0x80] ;
    LDC R13, c[0x0][0x398] ;
    LDS R14, [R20+0xc0] ;
    IADD3 R15, PT, PT, R8, R9, RZ ;
    IADD3 R16, PT, PT, R10, R11, RZ ;
    IADD3 R17, PT, PT, R12, R13, RZ ;
    IADD3 R18, PT, PT, R14, R15, RZ ;
    IADD3 R19, PT, PT, R16, R17, RZ ;
    IADD3 R19, PT, PT, R18, R19, RZ ;
    STG.E desc[UR4][R2.64], R19 ;
    EXIT ;
.endentry
";

#[test]
fn the_retirement_stall_of_a_recycled_barrier_stays_under_the_opt_in_and_has_a_name_there() {
    let drained = ["LDS R12", "LDC R13", "LDS R14"];
    let dflt = build(DRAIN, S1);
    let opt = build(DRAIN, &with(S1, &[OPT]));
    for b in [&dflt, &opt] {
        for head in drained {
            let l = &b.lines[idx(b, head, 0)];
            // the load waits the barrier it sets -- a barrier re-used in flight -- and keeps the 8 behind it
            assert!(l.wb.is_some_and(|w| l.wait & (1 << w) != 0), "`{head}` waits the barrier it sets: {}", b.frozen);
            assert_eq!(l.stall, 8, "`{head}`: {}", b.frozen);
        }
    }
    // the loads in front of them carry the margin 4 by default and the table's numbers under the opt-in
    assert_eq!(stall(&dflt, "LDS R8", 0), 4);
    assert_eq!(stall(&opt, "LDS R8", 0), 1, "{}", opt.frozen);
    // by its name the stall goes too (an experiment: the recycle of a barrier in flight is not measured)
    let exp = build(DRAIN, &with(S1, &[OPT, ("CUBIT_RECYCLE_DRAIN", "0")]));
    assert!(drained.iter().all(|h| stall(&exp, h, 0) < 8), "{}", exp.frozen);
    assert!(stall(&exp, "LDS R14", 0) == 1, "{}", exp.frozen);
    for b in [&opt, &exp] {
        let log = check(&b.frozen, &[("CUBIT_VERIFY", "1"), ("CUBIT_DEP_VERIFY", "1")]);
        assert!(log.contains(CLEAN_VERIFY) && log.contains(CLEAN_DEP), "{log}");
    }
}

/// A predicate result three words in front of `EXIT`, a store between them.
const LANDING: &str = "\
.entry landing_probe
    .reg R0-R31
    .param ptr out
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    MOV R3, 0x3f800000 ;
    FSETP.NEU.FTZ.AND P0, PT, R3, R3, PT ;
    MOV R5, R3 ;
    @P0 STG.E desc[UR4][R2.64], R5 ;
    FSETP.NEU.FTZ.AND P1, PT, R5, R3, PT ;
    MOV R6, R3 ;
    STG.E desc[UR4][R2.64+0x4], R6 ;
    EXIT ;
.endentry
";

/// A fixed-latency overwriter of an MMA's A fragment right behind the MMA; the MMA's result is read far behind.
const HOLD: &str = "\
.entry hold_probe
    .reg R0-R95
    .param ptr out
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    MOV R20, 0x100 ;
    LDSM.16.M88.4 R64, [R20] ;
    LDSM.16.M88.2 R72, [R20+0x40] ;
    HMMA.16816.F32.BF16 R28, R64, R72, RZ ;
    MOV R64, RZ ;
    IADD3 R4, PT, PT, R20, 0x1, RZ ;
    IADD3 R5, PT, PT, R4, 0x1, RZ ;
    IADD3 R6, PT, PT, R5, 0x1, RZ ;
    IADD3 R7, PT, PT, R6, 0x1, RZ ;
    IADD3 R8, PT, PT, R7, 0x1, RZ ;
    IADD3 R9, PT, PT, R8, 0x1, RZ ;
    STG.E.128 desc[UR4][R2.64], R28 ;
    STG.E desc[UR4][R2.64+0x10], R64 ;
    STG.E desc[UR4][R2.64+0x14], R9 ;
    EXIT ;
.endentry
";

#[test]
fn the_two_distances_the_margins_kept_by_accident_are_requirements_under_the_opt_in() {
    // (1) what has to have landed in front of EXIT: a predicate result 13 issue cycles (law (c)'s row)
    let landing = |b: &Built| distance(b, idx(b, "FSETP.NEU.FTZ.AND P1", 0), idx(b, "EXIT", 0));
    let opt = build(LANDING, &with(S1, &[OPT, ("CUBIT_DEP_VERIFY", "1")]));
    assert!(landing(&opt) >= 13, "{} issue cycles: {}", landing(&opt), opt.frozen);
    assert!(opt.log.contains(CLEAN_DEP), "the build's own check carries the rows: {}", opt.log);
    assert!(check(&opt.frozen, &[("CUBIT_SYNC_CLASSES", "1"), ("CUBIT_DEP_VERIFY", "1")]).contains(CLEAN_DEP));
    // the older switch takes the margins away and puts nothing in their place: the row is broken, and only the
    // check under CUBIT_SYNC_CLASSES names it
    let nomem = build(LANDING, &with(S1, &[("CUBIT_SCHED2_NOMEMSTALL", "1"), ("CUBIT_DEP_VERIFY", "1")]));
    assert!(landing(&nomem) < 13, "{}", nomem.frozen);
    assert!(nomem.log.contains(CLEAN_DEP), "without the switch the check does not know the row: {}", nomem.log);
    let named = check(&nomem.frozen, &[("CUBIT_SYNC_CLASSES", "1"), ("CUBIT_DEP_VERIFY", "1")]);
    assert!(named.contains("1 below a resource spacing") && named.contains("-> [9] EXIT (settle P1)"), "{named}");

    // (2) the operand hold of an MMA: a fixed-latency overwriter of a fragment register 8 issue cycles behind it
    let hold = |b: &Built| distance(b, idx(b, "HMMA", 0), idx(b, "MOV R64, RZ", 0));
    let dflt = build(HOLD, S1);
    assert_eq!(hold(&dflt), 2, "the default path does not keep the hold: {}", dflt.frozen);
    let opt = build(HOLD, &with(S1, &[OPT]));
    assert!(hold(&opt) >= 8, "{} issue cycles: {}", hold(&opt), opt.frozen);
    assert!(opt.log.contains("1 overwriters moved behind the operand hold of their reader"), "{}", opt.log);
}
