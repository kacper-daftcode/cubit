//! `CUBIT_CONST_ALONE=1` (opt-in, 2026-11-18): a constant load shares no barrier with another constant load
//! while a scoreboard is free (`scheduling_pass::const_alone`).
//!
//! The allocator batches consecutive loads of one opcode, one width and one line of the constant bank onto ONE
//! write barrier; the first reader of any of them waits the scoreboard and with it every load of the batch. The
//! vendor's assembler gives each such load a scoreboard of its own — in the served fc2 kernel on every one of the
//! six batches cubit forms (three plain `LDC`, two `LDC.64` twice, two `LDCU`, two `LDC.64` under two different
//! guards twice). Under the switch a batch of constant loads is taken apart, and "while a scoreboard is free" is
//! decided by the colouring itself:
//!
//! * a load that finds no scoreboard free goes back onto the barrier of the nearest load of its batch that has
//!   one (three loads and two free scoreboards: one alone, two together);
//! * a batch stays whole when one of its loads finds no scoreboard and cannot go back, and when another use
//!   would lose the scoreboard it has without the switch.
//!
//! The exception — one first reader, one barrier: loads of a batch that the same words read first stay on one
//! barrier. It is the vendor's practice for two producers of one kind that ONE word reads first, whether
//! scoreboards are free or not.
//!
//! Six tests fail on the allocator without the switch (the variable is then unknown and changes nothing): the
//! first five and the one of three loads of which one word reads two first. The exception's own test and that
//! one failed on the rule before its exception; the last three are controls — texts the switch must leave
//! byte for byte.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const SYNC: (&str, &str) = ("CUBIT_SYNC_CLASSES", "1");
const POLICY: (&str, &str) = ("CUBIT_WAIT_POLICY", "1");
const COVER: (&str, &str) = ("CUBIT_LOAD_COVER", "1");
const ALONE: (&str, &str) = ("CUBIT_CONST_ALONE", "1");
const DUMP: (&str, &str) = ("CUBIT_DUMP_COLOUR", "1");

/// One instruction of the schedule cubit wrote: (wait bits, read barrier, write barrier, the word).
#[derive(Debug, Clone, PartialEq)]
struct Word {
    wait: Vec<u8>,
    rb: Option<u8>,
    wb: Option<u8>,
    text: String,
}

/// `cubit asm` of an unscheduled kernel under `env`, then `cubit disassemble --frozen`: the words with the
/// control fields the allocator gave them, the cubin's bytes, and what the assembler wrote to stderr.
fn build(body: &str, env: &[(&str, &str)]) -> (Vec<Word>, Vec<u8>, String) {
    let dir = std::env::temp_dir().join(format!("constalone_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, format!(".entry const_alone_probe\n    .reg R0-R63\n    .param ptr out\n{body}.endentry\n")).unwrap();
    let run = |args: &[&str]| {
        let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
        let (stdout, stderr) = (String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned());
        assert!(o.status.success(), "{args:?} under {env:?}: {stdout}{stderr}");
        (stdout, stderr)
    };
    let (_, asm_err) = run(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()]);
    let (listing, _) = run(&["disassemble", "--frozen", out.to_str().unwrap(), "-t", TABLE]);
    let cubin = std::fs::read(&out).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let mut words = Vec::new();
    for line in listing.lines() {
        // `[B01----:R2:W3:Y:S04] <word> ;` behind an optional label
        let Some(at) = line.find("[B") else { continue };
        let tag = &line[at + 2..];
        let Some(end) = tag.find(']') else { continue };
        let fields: Vec<&str> = tag[..end].split(':').collect();
        if fields.len() != 5 {
            continue;
        }
        let digit = |f: &str| f[1..].parse::<u8>().ok();
        words.push(Word {
            wait: fields[0].bytes().filter(u8::is_ascii_digit).map(|b| b - b'0').collect(),
            rb: digit(fields[1]),
            wb: digit(fields[2]),
            text: tag[end + 1..].trim().trim_end_matches(';').trim().to_string(),
        });
    }
    (words, cubin, asm_err)
}

fn word<'a>(k: &'a [Word], starts: &str) -> &'a Word {
    k.iter().find(|w| w.text.starts_with(starts)).unwrap_or_else(|| panic!("no word `{starts}` in {k:#?}"))
}

/// The write barrier of the load `starts` (it must carry one).
fn wb(k: &[Word], starts: &str) -> u8 {
    word(k, starts).wb.unwrap_or_else(|| panic!("`{starts}` carries no write barrier in {k:#?}"))
}

/// Two plain constant loads off one line of the bank, each with a reader of its own (kind (a) of the served
/// fc2 kernel: `LDC R11, c[0x0][0x3e8] ; LDC R73, c[0x0][0x3f8] ; LDC R78, c[0x0][0x3f8]`).
const TWO_PLAIN: &str = "    S2R R2, SR_TID.X ;
    LDC R4, c[0x0][0x160] ;
    LDC R5, c[0x0][0x164] ;
    IADD3 R6, PT, PT, R4, 0x1, RZ ;
    IADD3 R7, PT, PT, R5, 0x1, RZ ;
    IADD3 R8, PT, PT, R6, R7, RZ ;
    EXIT ;
";

/// Two wide constant loads under two different guards (kind (c): `@!P0 LDC.64 R18, c[0x0][0x398] ;
/// @!P1 LDC.64 R20, c[0x0][0x3a0]`).
const TWO_GUARDED: &str = "    S2R R2, SR_TID.X ;
    ISETP.NE.AND P0, PT, R2, RZ, PT ;
    ISETP.GE.AND P1, PT, R2, 0x3, PT ;
    @!P0 LDC.64 R18, c[0x0][0x398] ;
    @!P1 LDC.64 R20, c[0x0][0x3a0] ;
    @!P0 IADD3 R6, PT, PT, R18, 0x1, RZ ;
    @!P1 IADD3 R7, PT, PT, R20, 0x1, RZ ;
    EXIT ;
";

/// Two loads into uniform registers (kind (b4): `LDCU UR4, c[0x0][0x430] ; LDCU UR5, c[0x0][0x428]`).
const TWO_UNIFORM: &str = "    S2R R2, SR_TID.X ;
    LDCU UR4, c[0x0][0x430] ;
    LDCU UR5, c[0x0][0x428] ;
    UISETP.NE.AND UP0, UPT, UR4, URZ, UPT ;
    UISETP.NE.AND UP1, UPT, UR5, URZ, UPT ;
    EXIT ;
";

/// `count` shared loads off `count` different base registers, all read BEHIND the constant loads' readers: each
/// holds a scoreboard of its own across the constant loads (two shared loads off different bases are no batch).
fn pending(count: usize) -> (String, String) {
    let mut front = String::from("    S2R R2, SR_TID.X ;\n    SHF.L.U32 R30, R2, 0x4, RZ ;\n");
    let mut behind = String::new();
    for i in 0..count {
        front.push_str(&format!("    MOV R{}, R30 ;\n", 31 + i));
    }
    for i in 0..count {
        front.push_str(&format!("    LDS R{}, [R{}+{:#x}] ;\n", 40 + i, 31 + i, 0x100 + 0x1100 * i));
        behind.push_str(&format!("    IADD3 R{}, PT, PT, R{}, 0x1, RZ ;\n", 50 + i, 40 + i));
    }
    (front, behind)
}

/// Three constant loads of one batch behind `busy` pending shared loads.
fn three_behind(busy: usize) -> String {
    let (front, behind) = pending(busy);
    format!(
        "{front}    LDC R4, c[0x0][0x160] ;
    LDC R5, c[0x0][0x164] ;
    LDC R6, c[0x0][0x168] ;
    IADD3 R12, PT, PT, R4, 0x1, RZ ;
    IADD3 R13, PT, PT, R5, 0x1, RZ ;
    IADD3 R14, PT, PT, R6, 0x1, RZ ;
{behind}    EXIT ;
"
    )
}

/// Two constant loads behind four pending shared loads, and a FIFTH shared load behind them that is in flight
/// across their readers: without the switch the batch has one scoreboard and that load the last one.
fn two_and_a_late_load() -> String {
    let (front, behind) = pending(4);
    format!(
        "{front}    MOV R36, R30 ;
    LDC R4, c[0x0][0x160] ;
    LDC R5, c[0x0][0x164] ;
    LDS R46, [R36+0x5500] ;
    IADD3 R12, PT, PT, R4, 0x1, RZ ;
    IADD3 R13, PT, PT, R5, 0x1, RZ ;
    IADD3 R56, PT, PT, R46, 0x1, RZ ;
{behind}    EXIT ;
"
    )
}

#[test]
fn two_plain_constant_loads_stand_on_two_scoreboards() {
    for env in [&[ALONE][..], &[SYNC, POLICY, COVER, ALONE][..]] {
        let (k, _, _) = build(TWO_PLAIN, env);
        let (a, b) = (wb(&k, "LDC R4"), wb(&k, "LDC R5"));
        assert_ne!(a, b, "under {env:?} each load has a scoreboard of its own: {k:#?}");
        assert_eq!(word(&k, "IADD3 R6,").wait, vec![a], "the reader of R4 waits its producer alone ({env:?}): {k:#?}");
        assert_eq!(word(&k, "IADD3 R7,").wait, vec![b], "the reader of R5 waits its producer alone ({env:?}): {k:#?}");
    }
}

#[test]
fn two_guarded_constant_loads_stand_on_two_scoreboards() {
    let (k, _, _) = build(TWO_GUARDED, &[SYNC, POLICY, COVER, ALONE]);
    let (a, b) = (wb(&k, "@!P0 LDC.64 R18"), wb(&k, "@!P1 LDC.64 R20"));
    assert_ne!(a, b, "two guards, two scoreboards: {k:#?}");
    assert_eq!(word(&k, "@!P0 IADD3 R6").wait, vec![a], "the reader under the first guard waits the first load alone: {k:#?}");
    assert_eq!(word(&k, "@!P1 IADD3 R7").wait, vec![b], "the reader under the second guard waits the second load alone: {k:#?}");
}

#[test]
fn two_uniform_constant_loads_stand_on_two_scoreboards() {
    let (k, _, _) = build(TWO_UNIFORM, &[SYNC, POLICY, COVER, ALONE]);
    let (a, b) = (wb(&k, "LDCU UR4"), wb(&k, "LDCU UR5"));
    assert_ne!(a, b, "each uniform load has a scoreboard of its own: {k:#?}");
    assert_eq!(word(&k, "UISETP.NE.AND UP0").wait, vec![a], "{k:#?}");
    assert_eq!(word(&k, "UISETP.NE.AND UP1").wait, vec![b], "{k:#?}");
}

#[test]
fn three_loads_and_two_free_scoreboards_one_alone_two_together() {
    // four scoreboards are held across the batch: the first load takes the fifth, the second the sixth, the
    // third finds none and goes back onto the barrier of its nearest mate -- ONE wait for the two, at the
    // first reader of either
    let (k, _, _) = build(&three_behind(4), &[ALONE]);
    let (a, b, c) = (wb(&k, "LDC R4"), wb(&k, "LDC R5"), wb(&k, "LDC R6"));
    assert_ne!(a, b, "{k:#?}");
    assert_eq!(b, c, "the third load stands on the second's barrier: {k:#?}");
    assert_eq!(word(&k, "IADD3 R12,").wait, vec![a], "{k:#?}");
    assert_eq!(word(&k, "IADD3 R13,").wait, vec![b], "{k:#?}");
    assert!(word(&k, "IADD3 R14,").wait.is_empty(), "the set was waited by the reader in front: {k:#?}");
}

#[test]
fn the_colouring_dump_names_the_loads_taken_apart() {
    let (_, _, err) = build(TWO_PLAIN, &[ALONE, DUMP]);
    let cols: Vec<&str> = err.lines().filter(|l| l.starts_with("COL b=")).collect();
    assert_eq!(cols.iter().filter(|l| l.contains(" const[1]")).count(), 2, "one COL line a load of the batch at word 1: {err}");
    assert!(cols.iter().all(|l| l.contains(" busy=") || l.contains(" pin=")), "{err}");
    assert!(err.contains("CONST_ALONE batches kept whole (by their first load): []"), "{err}");
    // a batch that stays whole (no scoreboard is free) is named
    let (_, _, err) = build(&three_behind(6), &[ALONE, DUMP]);
    assert!(err.contains("CONST_ALONE batches kept whole (by their first load): [") && !err.contains("(by their first load): []"), "{err}");
    assert!(!err.contains(" const["), "{err}");
    // without the switch the dump has one line for the batch and no mark
    let (_, _, err) = build(TWO_PLAIN, &[DUMP]);
    assert_eq!(err.lines().filter(|l| l.starts_with("COL b=") && l.contains("setters=[1, 2]")).count(), 1, "{err}");
    assert!(!err.contains(" const["), "{err}");
}

/// Two constant loads that ONE word reads first (the vendor's practice: `[W0] LDCU.64 UR4, c[0x0][0x358] ;
/// [W0] LDC.64 R2, c[0x0][0x380] ;` and the word that reads both waits scoreboard 0 — with five scoreboards
/// free; ten of ten such sets in his schedules of the served kernels).
const ONE_READER: &str = "    S2R R2, SR_TID.X ;
    LDC R4, c[0x0][0x160] ;
    LDC R5, c[0x0][0x164] ;
    IADD3 R6, PT, PT, R4, R5, RZ ;
    IADD3 R8, PT, PT, R6, 0x1, RZ ;
    EXIT ;
";

/// Three loads of one batch: ONE word reads the first and the third first, another word the second.
const TWO_OF_THREE: &str = "    S2R R2, SR_TID.X ;
    LDC R4, c[0x0][0x160] ;
    LDC R5, c[0x0][0x164] ;
    LDC R6, c[0x0][0x168] ;
    IADD3 R7, PT, PT, R5, 0x1, RZ ;
    IADD3 R8, PT, PT, R4, R6, RZ ;
    EXIT ;
";

#[test]
fn loads_that_one_word_reads_first_stay_on_one_barrier() {
    // the exception of the rule: one first reader, one wait -- scoreboards free or not; the text is the one
    // without the switch, byte for byte
    for env in [&[ALONE][..], &[SYNC, POLICY, COVER, ALONE][..]] {
        let without: Vec<(&str, &str)> = env.iter().copied().filter(|e| *e != ALONE).collect();
        let (kb, base, _) = build(ONE_READER, &without);
        let (k, alone, _) = build(ONE_READER, env);
        assert_eq!(wb(&k, "LDC R4"), wb(&k, "LDC R5"), "one reader, one barrier ({env:?}): {k:#?}");
        assert_eq!(word(&k, "IADD3 R6,").wait, vec![wb(&k, "LDC R4")], "{k:#?}");
        assert_eq!(base, alone, "the text without the switch ({env:?}): {kb:#?}");
    }
}

#[test]
fn of_three_loads_the_two_one_word_reads_first_stay_together() {
    let (k, _, _) = build(TWO_OF_THREE, &[SYNC, POLICY, COVER, ALONE]);
    let (a, b, c) = (wb(&k, "LDC R4"), wb(&k, "LDC R5"), wb(&k, "LDC R6"));
    assert_eq!(a, c, "the first and the third are read first by one word: {k:#?}");
    assert_ne!(a, b, "the second has a reader of its own: {k:#?}");
    assert_eq!(word(&k, "IADD3 R7,").wait, vec![b], "{k:#?}");
    assert_eq!(word(&k, "IADD3 R8,").wait, vec![a], "{k:#?}");
}

#[test]
fn without_the_switch_the_batch_is_one_barrier() {
    for env in [&[][..], &[SYNC, POLICY, COVER][..]] {
        let (k, _, _) = build(TWO_PLAIN, env);
        assert_eq!(wb(&k, "LDC R4"), wb(&k, "LDC R5"), "the batch as it is without the switch ({env:?}): {k:#?}");
    }
}

#[test]
fn no_scoreboard_free_the_batch_stays_whole() {
    // six scoreboards are held across the batch: the text is the one without the switch, byte for byte
    let body = three_behind(6);
    let (_, base, _) = build(&body, &[]);
    let (k, alone, _) = build(&body, &[ALONE]);
    assert_eq!(base, alone, "{k:#?}");
}

#[test]
fn another_use_keeps_its_scoreboard() {
    // the batch could stand apart on the two free scoreboards -- and the shared load behind it would find
    // none: the batch stays whole and the text is the one without the switch, byte for byte
    let body = two_and_a_late_load();
    let (kb, base, _) = build(&body, &[]);
    assert_eq!(wb(&kb, "LDC R4"), wb(&kb, "LDC R5"), "{kb:#?}");
    assert_ne!(wb(&kb, "LDS R46"), wb(&kb, "LDC R4"), "without the switch the late load has a scoreboard to itself: {kb:#?}");
    let (k, alone, _) = build(&body, &[ALONE]);
    assert_eq!(base, alone, "{k:#?}");
}
