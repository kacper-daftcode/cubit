//! `CUBIT_DUMP_STALL=1` (a look, stderr; 2026-11-20): why every stall field has the value it has.
//!
//! The schedule of a kernel is written by a first pass (a stall of its own rules), a legaliser that raises a
//! stall until every requirement of the latency table holds on every path, an operand hold that raises a stall
//! in front of an overwriter, and — under `CUBIT_SCHED2_LOWER=1` — a pass that takes back what nothing asks
//! for. None of them says afterwards which of its rules a stall field stands on. The dump does, one `STALL`
//! line a word, read off the schedule as it is written with the lowering pass's own dataflows
//! (`stall_lower::reasons`):
//!
//! * `REQ` — a requirement is met exactly through the word (one cycle less breaks it), with its name: `cell` or
//!   `default` and the pair class of the table, `resource` and its name, `arm`, a landing row, `hold` (an
//!   operand hold), `sim` (the scoreboard simulation's distance); `+N` = so many more are met exactly too;
//! * `FIRST` — the stall is the first pass's and stands above every requirement;
//! * `LEFT` — the stall stands above the first pass's AND above every requirement: a raise nothing asks for any
//!   more (`floor` = how far the requirements would let it go);
//! * `HAND` — a hand-scheduled word.
//!
//! The dump changes no byte: with it and without it the cubin is the same.
//!
//! Five tests fail without the dump (the variable is then unknown and prints nothing); one is a control.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
/// the legaliser with the latency table and the memory rows
const S2: &[(&str, &str)] = &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120"), ("CUBIT_MMA_PTXAS", "1"), ("CUBIT_SCHED2_MEMSTALL", "table")];
const LOWER: (&str, &str) = ("CUBIT_SCHED2_LOWER", "1");
const DUMP: (&str, &str) = ("CUBIT_DUMP_STALL", "1");

fn with<'a>(env: &[(&'a str, &'a str)], more: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut v = env.to_vec();
    v.extend_from_slice(more);
    v
}

/// A build: the instruction lines of the frozen listing as (stall, text), the cubin's bytes, what `cubit asm`
/// printed, and the dump's lines in it.
struct Built {
    lines: Vec<(u32, String)>,
    cubin: Vec<u8>,
    frozen: String,
    log: String,
    dump: Vec<String>,
}

/// `[B------:R-:W-:Y:S04] <word> ;` behind an optional label: (stall, word).
fn parse_line(l: &str) -> Option<(u32, String)> {
    let at = l.find("[B")?;
    let end = at + l[at..].find(']')?;
    let fields: Vec<&str> = l[at + 1..end].split(':').collect();
    if fields.len() != 5 {
        return None;
    }
    let stall = fields[4].strip_prefix('S')?.parse().ok()?;
    Some((stall, l[end + 1..].trim().trim_end_matches(';').trim().to_string()))
}

/// `cubit asm` of `text` under `env`, the schedule read back from the cubin.
fn build(text: &str, env: &[(&str, &str)]) -> Built {
    let dir = std::env::temp_dir().join(format!("stallreason_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, text).unwrap();
    let run = |args: &[&str], env: &[(&str, &str)]| {
        let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
        let log = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert!(o.status.success(), "{args:?} under {env:?}: {log}");
        (String::from_utf8_lossy(&o.stdout).into_owned(), log)
    };
    let (_, log) = run(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()], env);
    let (frozen, _) = run(&["disassemble", "-t", TABLE, "--frozen", out.to_str().unwrap()], &[]);
    let cubin = std::fs::read(&out).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let lines: Vec<(u32, String)> = frozen.lines().filter_map(parse_line).collect();
    assert!(!lines.is_empty(), "no instruction lines in:\n{frozen}");
    let dump: Vec<String> = log.lines().filter(|l| l.starts_with("STALL ")).map(str::to_string).collect();
    Built { lines, cubin, frozen, log, dump }
}

/// The index of the `nth` word of the listing that begins with `head`.
fn idx(b: &Built, head: &str, nth: usize) -> usize {
    b.lines.iter().enumerate().filter(|(_, l)| l.1.starts_with(head)).map(|(i, _)| i).nth(nth).unwrap_or_else(|| panic!("no `{head}` #{nth} in {}", b.frozen))
}

/// The dump's line of word `i`.
fn line(b: &Built, i: usize) -> &str {
    let head = format!("STALL [{i}] ");
    b.dump.iter().find(|l| l.starts_with(&head)).unwrap_or_else(|| panic!("no dump line of word {i} in:\n{}", b.log))
}

/// Two tensor instructions with two words between them (the kernel of `tests/sched2_lower.rs`): a fixed-latency
/// overwriter of the first one's B fragment and a word that has nothing to do with either, then a chain of adds.
/// The legaliser gives `MOV R80` 13 cycles for the spacing of 16 between the two tensor instructions, the operand
/// hold then raises the first tensor instruction to 8, and six of the 13 cycles are asked for by nothing.
const TWO_TENSOR_WORDS: &str = "\
.entry stall_probe
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

/// One line a word, in the text's order, each with the stall the cubin carries; a head line with the counts.
#[test]
fn the_dump_prints_one_line_a_word_with_the_stall_as_written() {
    for env in [with(S2, &[DUMP]), with(S2, &[LOWER, DUMP])] {
        let b = build(TWO_TENSOR_WORDS, &env);
        let head: Vec<&String> = b.dump.iter().filter(|l| l.contains(" word(s) | REQ ")).collect();
        assert_eq!(head.len(), 1, "{}", b.log);
        assert!(head[0].starts_with(&format!("STALL stall_probe: {} word(s) | REQ ", b.lines.len())), "{}", head[0]);
        assert_eq!(b.dump.len(), b.lines.len() + 1, "one line a word and the head line:\n{}", b.log);
        for (i, (stall, _)) in b.lines.iter().enumerate() {
            assert!(line(&b, i).starts_with(&format!("STALL [{i}] S{stall:02} first ")), "{}\n{}", line(&b, i), b.frozen);
        }
    }
}

/// A stall a requirement holds says which: the word in front of the second tensor instruction stands on the
/// spacing of the two (a resource of the table, with its two words), the first tensor instruction on that
/// spacing AND on the operand hold of its overwriter, and the first add behind the second tensor instruction on
/// a cell of the table that is not its own: the 28 cycles between that tensor instruction and the store of its
/// result, seven words further on — the chain of adds between the two carries them.
#[test]
fn a_stall_a_requirement_holds_names_the_requirement() {
    let b = build(TWO_TENSOR_WORDS, &with(S2, &[LOWER, DUMP]));
    let (m0, m1) = (idx(&b, "HMMA", 0), idx(&b, "HMMA", 1));
    let gap = line(&b, idx(&b, "MOV R80", 0));
    assert!(gap.contains(" S07 ") && gap.contains(" floor 7 REQ resource "), "{gap}");
    assert!(gap.contains(&format!(" need 16 [{m0}] -> [{m1}]")), "{gap}");
    let first = line(&b, m0);
    assert!(first.contains(" S08 ") && first.contains(" floor 8 REQ resource ") && first.contains(&format!(" need 16 [{m0}] -> [{m1}] +1")), "{first}");
    let add = line(&b, idx(&b, "IADD3 R4", 0));
    assert!(add.contains(" REQ cell HMMA -> STG "), "{add}");
    assert!(add.contains(&format!(" need 28 [{m1}] -> [{}]", idx(&b, "STG.E.128", 1))), "{add}");
}

/// Without the lowering the raise that nothing asks for any more is named: 13 cycles where the requirements'
/// floor is 7, class `LEFT` — and the line still says which requirement sets that floor.
#[test]
fn a_raise_nothing_asks_for_is_named_with_the_floor_it_could_go_to() {
    let b = build(TWO_TENSOR_WORDS, &with(S2, &[DUMP]));
    let (m0, m1) = (idx(&b, "HMMA", 0), idx(&b, "HMMA", 1));
    let gap = line(&b, idx(&b, "MOV R80", 0));
    assert!(gap.contains(" S13 ") && gap.contains(" floor 7 LEFT resource "), "{gap}");
    assert!(gap.contains(&format!(" need 16 [{m0}] -> [{m1}]")), "{gap}");
    // under the lowering no word of this kernel is left over
    let low = build(TWO_TENSOR_WORDS, &with(S2, &[LOWER, DUMP]));
    assert!(low.dump[0].contains(" LEFT 0 "), "{}", low.dump[0]);
    assert!(!b.dump[0].contains(" LEFT 0 "), "{}", b.dump[0]);
}

/// A stall the first pass wrote and no requirement reaches is named so: the last word of the kernel.
#[test]
fn a_stall_of_the_first_pass_that_no_requirement_holds_is_named_first() {
    let b = build(TWO_TENSOR_WORDS, &with(S2, &[LOWER, DUMP]));
    let exit = line(&b, idx(&b, "EXIT", 0));
    assert!(exit.contains(" floor 0 FIRST - | "), "{exit}");
    // every line's class is one of the five, and a `FIRST` line's stall is the first pass's
    for l in &b.dump[1..] {
        let f: Vec<&str> = l.split_whitespace().collect();
        assert!(["REQ", "FIRST", "LEFT", "HAND", "BELOW"].contains(&f[7]), "{l}");
        if f[7] == "FIRST" {
            assert_eq!(f[2].trim_start_matches('S').parse::<u32>().unwrap(), f[4].parse::<u32>().unwrap(), "{l}");
        }
    }
}

/// Where no latency table is read there is no requirement to name: one line says so and the build is the build.
#[test]
fn without_the_latency_table_the_dump_says_what_it_needs() {
    let plain = build(TWO_TENSOR_WORDS, &[]);
    let b = build(TWO_TENSOR_WORDS, &[DUMP]);
    assert_eq!(b.dump.len(), 1, "{}", b.log);
    assert!(b.dump[0].starts_with("STALL stall_probe: CUBIT_DUMP_STALL needs CUBIT_SCHED2=1 CUBIT_SCHED2_LAT=<table>"), "{}", b.dump[0]);
    assert_eq!(plain.cubin, b.cubin);
}

/// CONTROL: the dump is a look — with it and without it the cubin is the same, in every view; without the
/// variable no `STALL` line is printed.
#[test]
fn the_dump_changes_no_byte() {
    for env in [with(S2, &[]), with(S2, &[LOWER]), with(S2, &[LOWER, ("CUBIT_SYNC_CLASSES", "1")])] {
        let off = build(TWO_TENSOR_WORDS, &env);
        let on = build(TWO_TENSOR_WORDS, &with(&env, &[DUMP]));
        assert!(off.dump.is_empty(), "{}", off.log);
        assert_eq!(off.cubin, on.cubin, "{env:?}");
        assert_eq!(off.frozen, on.frozen, "{env:?}");
    }
}
