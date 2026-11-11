//! `CUBIT_SCHED2_LOWER=1` (2026-11-11): behind the legaliser, the stalls no requirement asks for are taken back.
//!
//! The passes that make a schedule legal only raise a stall, one requirement after another, and none looks back:
//! the latency legaliser puts 13 cycles on the word in front of the second of two tensor instructions for their
//! spacing of 16, the operand hold then puts six more on the first tensor instruction (a fixed-latency overwriter
//! of its fragment stands right behind it) — and the spacing is 22. Cubit's schedules of the vendor's own tensor
//! loops carried 54, 20 and 34 such cycles per pass of the loop (three kernels of a served module; static).
//!
//! With the variable — on top of `CUBIT_SCHED2_MEMSTALL=table`, refused without it — a pass behind the two takes a
//! raise back as far as every requirement that spans the word keeps its distance (`src/stall_lower.rs`): the
//! table's on every path, the operand holds for every register a tensor instruction reads, the one distance the
//! scoreboard simulation counts. It never goes below the stall a word had in front of the legaliser. **Without the
//! variable nothing changes.**

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");

/// The dependency-aware schedule with the table's stalls behind memory words: what the variable stacks on.
const S2: &[(&str, &str)] = &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120"), ("CUBIT_MMA_PTXAS", "1"), ("CUBIT_SCHED2_MEMSTALL", "table")];
const LOWER: (&str, &str) = ("CUBIT_SCHED2_LOWER", "1");
const CLEAN_VERIFY: &str = "CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale";
const CLEAN_DEP: &str = "DEP_VERIFY 0 below a table cell, 0 waits closer than the arming distance to their barrier's setter, 0 below a resource spacing, 0 below a default";

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("lower_{}_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst), tag));
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

/// (stall, yield flag, text) of an instruction line of a frozen listing.
fn parse_line(l: &str) -> Option<(u32, bool, String)> {
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
    Some((f[4][1..].parse().ok()?, f[3] == "Y", rest[close + 1..].trim().trim_end_matches(';').trim().to_string()))
}

struct Built {
    lines: Vec<(u32, bool, String)>,
    cubin: Vec<u8>,
    frozen: String,
    log: String,
}

/// `cubit asm` of `text` under `env` (`Err`: what it printed when it refused), the schedule read back from the cubin.
fn try_build(text: &str, env: &[(&str, &str)]) -> Result<Built, String> {
    let dir = scratch("k");
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, text).unwrap();
    let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()], env);
    if !ok {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(log);
    }
    let cubin = std::fs::read(&out).unwrap();
    let (ok, frozen) = cubit(&["disassemble", "-t", TABLE, "--frozen", out.to_str().unwrap()], &[]);
    assert!(ok, "disassemble failed: {frozen}");
    let _ = std::fs::remove_dir_all(&dir);
    let lines: Vec<(u32, bool, String)> = frozen.lines().filter_map(parse_line).collect();
    assert!(!lines.is_empty(), "no instruction lines in:\n{frozen}");
    Ok(Built { lines, cubin, frozen, log })
}

fn build(text: &str, env: &[(&str, &str)]) -> Built {
    try_build(text, env).unwrap_or_else(|log| panic!("asm {env:?} failed:\n{log}"))
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

fn idx(b: &Built, head: &str, nth: usize) -> usize {
    b.lines.iter().enumerate().filter(|(_, l)| l.2.starts_with(head)).map(|(i, _)| i).nth(nth).unwrap_or_else(|| panic!("no `{head}` #{nth} in {}", b.frozen))
}

fn stall(b: &Built, head: &str, nth: usize) -> u32 {
    b.lines[idx(b, head, nth)].0
}

/// Issue distance (the sum of the stalls) from instruction `from` to instruction `to`.
fn distance(b: &Built, from: usize, to: usize) -> u32 {
    b.lines[from..to].iter().map(|l| l.0).sum()
}

/// Two tensor instructions with two words between them: a fixed-latency overwriter of the first one's B fragment,
/// and a word that has nothing to do with either.
const TWO_TENSOR_WORDS: &str = "\
.entry lower_probe
    .reg R0-R95
    .param ptr out
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    MOV R20, 0x100 ;
    LDSM.16.M88.4 R64, [R20] ;
    LDSM.16.M88.2 R72, [R20+0x40] ;
    LDSM.16.M88.2 R76, [R20+0x80] ;
    HMMA.16816.F32.BF16 R28, R64, R72, RZ ;
    MOV R72, RZ ;
    MOV R80, R20 ;
    HMMA.16816.F32.BF16 R32, R64, R76, RZ ;
    IADD3 R4, PT, PT, R20, 0x1, RZ ;
    IADD3 R5, PT, PT, R4, 0x1, RZ ;
    IADD3 R6, PT, PT, R5, 0x1, RZ ;
    IADD3 R7, PT, PT, R6, 0x1, RZ ;
    IADD3 R8, PT, PT, R7, 0x1, RZ ;
    IADD3 R9, PT, PT, R8, 0x1, RZ ;
    STG.E.128 desc[UR4][R2.64], R28 ;
    STG.E.128 desc[UR4][R2.64+0x10], R32 ;
    STG.E desc[UR4][R2.64+0x20], R72 ;
    STG.E desc[UR4][R2.64+0x24], R80 ;
    STG.E desc[UR4][R2.64+0x28], R9 ;
    EXIT ;
.endentry
";

#[test]
fn a_raise_that_a_later_raise_made_redundant_is_taken_back() {
    let spacing = |b: &Built| distance(b, idx(b, "HMMA", 0), idx(b, "HMMA", 1));
    let hold = |b: &Built| distance(b, idx(b, "HMMA", 0), idx(b, "MOV R72, RZ", 0));
    // as raised: the legaliser gives the word in front of the second tensor instruction 13 cycles for the
    // spacing of 16 (2 + 1 + 13), then the operand hold raises the first tensor instruction to 8
    let opt = build(TWO_TENSOR_WORDS, &with(S2, &[("CUBIT_DEP_VERIFY", "1"), ("CUBIT_VERIFY", "1")]));
    assert_eq!((stall(&opt, "HMMA", 0), stall(&opt, "MOV R80", 0), spacing(&opt), hold(&opt)), (8, 13, 22, 8), "{}", opt.frozen);
    assert!(opt.log.contains("1 overwriters moved behind the operand hold of their reader (6 cycles)"), "{}", opt.log);
    assert!(!opt.log.contains("stall lowering"), "{}", opt.log);

    // with the variable the six cycles nobody needs go: the spacing is 16, the hold is 8, nothing else moves
    let low = build(TWO_TENSOR_WORDS, &with(S2, &[LOWER, ("CUBIT_DEP_VERIFY", "1"), ("CUBIT_VERIFY", "1")]));
    assert_eq!((stall(&low, "HMMA", 0), stall(&low, "MOV R80", 0), spacing(&low), hold(&low)), (8, 7, 16, 8), "{}", low.frozen);
    assert!(low.log.contains("stall lowering: 1 of 9 raised word(s) lowered by 6 cycles"), "{}", low.log);
    assert!(low.log.contains("behind it the legaliser raised 0 stall(s) by 0 cycle(s) and the operand hold moved 0 overwriter(s)"), "{}", low.log);
    assert!(!low.log.contains("WITHDRAWN"), "{}", low.log);
    let differ: Vec<usize> = (0..opt.lines.len()).filter(|&i| opt.lines[i] != low.lines[i]).collect();
    assert_eq!(differ, [idx(&opt, "MOV R80", 0)], "one word differs:\n{}\n{}", opt.frozen, low.frozen);
    // a stall that still carries a requirement keeps the legaliser's yield rule
    assert!(!low.lines[idx(&low, "MOV R80", 0)].1, "{}", low.frozen);

    // every check says of the lowered schedule what it says of the raised one: the build's own, and the
    // read-only checks of the frozen listing in each view
    for b in [&opt, &low] {
        assert!(b.log.contains(CLEAN_VERIFY) && b.log.contains(CLEAN_DEP), "{}", b.log);
    }
    for env in [&[][..], &[("CUBIT_SYNC_CLASSES", "1")][..], &[("CUBIT_VERIFY_RBPROBE", "1")][..]] {
        let e = with(env, &[("CUBIT_VERIFY", "1"), ("CUBIT_DEP_VERIFY", "1")]);
        let line = |log: &str, head: &str| log.lines().find(|l| l.contains(head)).unwrap_or_else(|| panic!("no `{head}` line in {log}")).to_string();
        let (a, b) = (check(&opt.frozen, &e), check(&low.frozen, &e));
        assert_eq!(line(&a, "CUBIT_VERIFY:"), line(&b, "CUBIT_VERIFY:"), "{env:?}");
        assert_eq!(line(&a, "DEP_VERIFY"), line(&b, "DEP_VERIFY"), "{env:?}");
        assert_eq!(a.matches("STORE PATH:").count() + a.matches("WRITE AFTER WRITE:").count(), b.matches("STORE PATH:").count() + b.matches("WRITE AFTER WRITE:").count());
    }
}

#[test]
fn without_the_variable_nothing_changes() {
    let opt = build(TWO_TENSOR_WORDS, S2);
    for off in [("CUBIT_SCHED2_LOWER", ""), ("CUBIT_SCHED2_LOWER", "0")] {
        let b = build(TWO_TENSOR_WORDS, &with(S2, &[off]));
        assert!(b.cubin == opt.cubin, "{off:?}:\n{}", b.frozen);
        assert!(!b.log.contains("stall lowering"), "{}", b.log);
    }
    // ... and where nothing was raised in vain the variable changes nothing either: the same text without the
    // overwriter has no operand hold to move, the legaliser's 13 cycles are the spacing
    let text = TWO_TENSOR_WORDS.replace("    MOV R72, RZ ;\n", "    MOV R81, RZ ;\n");
    let (opt, low) = (build(&text, S2), build(&text, &with(S2, &[LOWER])));
    assert!(low.cubin == opt.cubin, "{}\n{}", opt.frozen, low.frozen);
    assert!(low.log.contains("stall lowering: 0 of "), "{}", low.log);
}

#[test]
fn the_variable_is_refused_where_it_cannot_be_honoured() {
    // without the table's stalls behind memory words the distances of the schedule have no requirement by name
    let s1: Vec<(&str, &str)> = S2.iter().copied().filter(|(k, _)| *k != "CUBIT_SCHED2_MEMSTALL").collect();
    let log = try_build(TWO_TENSOR_WORDS, &with(&s1, &[LOWER])).err().expect("refused without CUBIT_SCHED2_MEMSTALL=table");
    assert!(log.contains("CUBIT_SCHED2_LOWER=1 needs CUBIT_SCHED2_MEMSTALL=table"), "{log}");
    let log = try_build(TWO_TENSOR_WORDS, &[LOWER]).err().expect("refused on the default path");
    assert!(log.contains("CUBIT_SCHED2_LOWER=1 needs CUBIT_SCHED2_MEMSTALL=table"), "{log}");
    // a misspelt opt-in does not build the raised schedule silently
    let log = try_build(TWO_TENSOR_WORDS, &with(S2, &[("CUBIT_SCHED2_LOWER", "yes")])).err().expect("refused: not `1`");
    assert!(log.contains("CUBIT_SCHED2_LOWER=yes: the only value is `1`"), "{log}");
}
