//! `CUBIT_WAIT_DRAINED=head | paths` (opt-in, 2026-11-18; with `CUBIT_WAIT_POLICY=1`): no wait on a scoreboard
//! another wait has drained (`wait_drained`, KNOWN_ISSUES A63).
//!
//! The barrier allocator writes waits use by use: the first readers of a use wait its scoreboard, and a wait that
//! another use wrote on the same scoreboard is never credited. Where scoreboards are shared — six of them, hundreds
//! of uses in a served kernel — a word waits for a result of the round before although the first wait of its own
//! round has drained the scoreboard (`head`), and a reader waits again behind the wait of another use (`paths`).
//! On an empty scoreboard the bit is nothing; where a younger result has armed the scoreboard since, the word blocks
//! behind a result it does not read.
//!
//! The kernels here pin all six scoreboards with hand-scheduled loads that fly across the whole text, so every use
//! the allocator colours shares scoreboard 0 — the state of a served kernel in a dozen words.
//!
//! The first seven tests fail on the allocator without the rule (the variable is then unknown and changes
//! nothing); the last five are controls that hold the rule in and pass on both.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const SYNC: (&str, &str) = ("CUBIT_SYNC_CLASSES", "1");
const POLICY: (&str, &str) = ("CUBIT_WAIT_POLICY", "1");
const HEAD: (&str, &str) = ("CUBIT_WAIT_DRAINED", "head");
const PATHS: (&str, &str) = ("CUBIT_WAIT_DRAINED", "paths");

/// One instruction of the schedule cubit wrote: (wait bits, write barrier, the word).
#[derive(Debug, Clone, PartialEq)]
struct Word {
    wait: Vec<u8>,
    wb: Option<u8>,
    text: String,
}

/// `cubit asm` of a kernel under `env`: did it succeed, and its log (both streams).
fn asm(body: &str, env: &[(&str, &str)], dir: &std::path::Path) -> (bool, String) {
    std::fs::create_dir_all(dir).unwrap();
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, format!(".entry wait_drained_probe\n    .reg R0-R63\n    .param ptr out\n{body}.endentry\n")).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .expect("run cubit");
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

/// `cubit asm` under `env`, then `cubit disassemble --frozen`: the words with the control fields the allocator
/// gave them, the cubin's bytes, and the log of the build.
fn build(body: &str, env: &[(&str, &str)]) -> (Vec<Word>, Vec<u8>, String) {
    let dir = std::env::temp_dir().join(format!("waitdrained_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    let (ok, log) = asm(body, env, &dir);
    assert!(ok, "asm under {env:?}: {log}");
    let out = dir.join("k.cubin");
    let o = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["disassemble", "--frozen", out.to_str().unwrap(), "-t", TABLE])
        .env_clear()
        .output()
        .expect("run cubit");
    assert!(o.status.success(), "disassemble: {}", String::from_utf8_lossy(&o.stderr));
    let listing = String::from_utf8_lossy(&o.stdout).into_owned();
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
        words.push(Word {
            wait: fields[0].bytes().filter(u8::is_ascii_digit).map(|b| b - b'0').collect(),
            wb: fields[2][1..].parse::<u8>().ok(),
            text: tag[end + 1..].trim().trim_end_matches(';').trim().to_string(),
        });
    }
    (words, cubin, log)
}

fn word<'a>(k: &'a [Word], starts: &str) -> &'a Word {
    k.iter().find(|w| w.text.starts_with(starts)).unwrap_or_else(|| panic!("no word `{starts}` in {k:#?}"))
}

/// The rule's count line of a build's log.
fn count_line(log: &str) -> &str {
    log.lines().find(|l| l.contains("wait rule")).unwrap_or_else(|| panic!("no count line of the rule in:\n{log}"))
}

/// Six hand-scheduled loads, one a scoreboard, read by the sum at the end of the kernel: every scoreboard is busy
/// across the text between, and a use the allocator colours there shares scoreboard 0.
const PINS: &str = "    S2R R2, SR_TID.X ;
    SHF.L.U32 R60, R2, 0x2, RZ ;
    SHF.L.U32 R61, R2, 0x3, RZ ;
    SHF.L.U32 R62, R2, 0x4, RZ ;
    SHF.L.U32 R63, R2, 0x5, RZ ;
    [B------:R-:W0:-:S02] LDS R40, [R60+0x1000] ;
    [B------:R-:W1:-:S02] LDS R41, [R60+0x1100] ;
    [B------:R-:W2:-:S02] LDS R42, [R60+0x1200] ;
    [B------:R-:W3:-:S02] LDS R43, [R60+0x1300] ;
    [B------:R-:W4:-:S02] LDS R44, [R60+0x1400] ;
    [B------:R-:W5:-:S02] LDS R45, [R60+0x1500] ;
    MOV R4, RZ ;
    MOV R5, RZ ;
    MOV R9, RZ ;
";
const SUM: &str = "    IADD3 R50, PT, PT, R40, R41, RZ ;
    IADD3 R50, PT, PT, R50, R42, RZ ;
    IADD3 R50, PT, PT, R50, R43, RZ ;
    IADD3 R50, PT, PT, R50, R44, RZ ;
    IADD3 R50, PT, PT, R50, R45, RZ ;
    EXIT ;
";
/// The tail of a round: two loads off two bases (two uses), the counter, the back edge — and behind the loop the
/// two registers are written again, so the two uses end in front of the sum (inside the flight of all six pins).
const TAIL: &str = "    LDS R4, [R61+0x300] ;
    LDS R5, [R62+0x400] ;
    IADD3 R9, PT, PT, R9, 0x1, RZ ;
    ISETP.NE.AND P0, PT, R9, 0x8, PT ;
    @P0 BRA L_top ;
    MOV R4, RZ ;
    MOV R5, RZ ;
";
const READ_R5: &str = "IADD3 R6, PT, PT, R5, R6, RZ";
const READ_R4: &str = "IADD3 R7, PT, PT, R4, R7, RZ";

/// A round whose first word reads the second load of the round before and whose second word reads the first.
fn round() -> String {
    format!("{PINS}L_top:\n    {READ_R5} ;\n    {READ_R4} ;\n{TAIL}{SUM}")
}

/// The same round with a younger load between the two readers, read behind them; `between` stands behind the
/// second reader.
fn round_with_a_younger_load(between: &str) -> String {
    format!(
        "{PINS}L_top:\n    {READ_R5} ;\n    LDS R10, [R63+0x500] ;\n    {READ_R4} ;\n{between}    IADD3 R11, PT, PT, R10, R11, RZ ;\n    IADD3 R13, PT, PT, R12, R13, RZ ;\n{TAIL}{SUM}"
    )
}

#[test]
fn a_wait_on_a_scoreboard_nothing_armed_since_its_last_wait_is_not_written() {
    let (plain, _, _) = build(&round(), &[SYNC, POLICY]);
    assert_eq!(word(&plain, "LDS R4").wb, Some(0), "the uses of the round share scoreboard 0");
    assert_eq!(word(&plain, "LDS R5").wb, Some(0));
    assert_eq!(word(&plain, READ_R5).wait, vec![0]);
    assert_eq!(word(&plain, READ_R4).wait, vec![0], "the allocator: one wait a use");
    let (k, _, log) = build(&round(), &[SYNC, POLICY, HEAD]);
    assert_eq!(word(&k, READ_R5).wait, vec![0], "the round's first wait stands");
    assert!(word(&k, READ_R4).wait.is_empty(), "behind it the scoreboard is empty: {:?}", word(&k, READ_R4));
    assert!(count_line(&log).contains("1 wait bit(s) not written: 1 on an empty scoreboard | 0 behind"), "{}", count_line(&log));
    // no barrier moved
    assert_eq!(k.iter().map(|w| w.wb).collect::<Vec<_>>(), plain.iter().map(|w| w.wb).collect::<Vec<_>>());
}

/// Two loads of two uses, then their readers: the second reader stands behind the wait of the first.
fn straight() -> String {
    format!("{PINS}    LDS R4, [R61+0x300] ;\n    LDS R5, [R62+0x400] ;\n    {READ_R5} ;\n    {READ_R4} ;\n{SUM}")
}

#[test]
fn a_reader_behind_another_uses_wait_does_not_wait_again() {
    let (plain, _, _) = build(&straight(), &[SYNC, POLICY]);
    assert_eq!(word(&plain, READ_R5).wait, vec![0]);
    assert_eq!(word(&plain, READ_R4).wait, vec![0]);
    let (k, _, _) = build(&straight(), &[SYNC, POLICY, PATHS]);
    assert_eq!(word(&k, READ_R5).wait, vec![0], "the first waiting word of the path");
    assert!(word(&k, READ_R4).wait.is_empty(), "{:?}", word(&k, READ_R4));
    // the repeat inside a round is not the kind `head` takes
    let (h, _, _) = build(&straight(), &[SYNC, POLICY, HEAD]);
    assert_eq!(word(&h, READ_R4).wait, vec![0]);
}

#[test]
fn a_wait_behind_a_younger_result_the_word_does_not_read_is_not_written() {
    let text = round_with_a_younger_load("");
    let (plain, _, _) = build(&text, &[SYNC, POLICY]);
    assert_eq!(word(&plain, "LDS R10").wb, Some(0));
    assert_eq!(word(&plain, READ_R4).wait, vec![0], "it waits behind the load of R10, which it does not read");
    let (k, _, log) = build(&text, &[SYNC, POLICY, HEAD]);
    assert!(word(&k, READ_R4).wait.is_empty(), "{:?}", word(&k, READ_R4));
    assert_eq!(word(&k, "IADD3 R11, PT, PT, R10").wait, vec![0], "the load's own reader takes the wait over");
    assert!(count_line(&log).contains("1 wait bit(s) not written: 0 on an empty scoreboard | 1 behind"), "{}", count_line(&log));
}

#[test]
fn a_wait_between_two_plain_shared_loads_goes_where_their_set_is_measured() {
    // two plain shared loads on one barrier in front of one wait: a measured set
    let text = round_with_a_younger_load("    LDS R12, [R60+0x600] ;\n");
    let (plain, _, _) = build(&text, &[SYNC, POLICY]);
    assert_eq!(word(&plain, "LDS R12").wb, Some(0));
    assert_eq!(word(&plain, READ_R4).wait, vec![0]);
    let (k, _, log) = build(&text, &[SYNC, POLICY, HEAD]);
    assert!(word(&k, READ_R4).wait.is_empty(), "{:?}", word(&k, READ_R4));
    assert!(count_line(&log).contains("0 kept for an unmeasured set"), "{}", count_line(&log));
}

/// A round whose first word carries the author's wait on scoreboard 0.
const AUTHORS_WAIT: &str = "    S2R R2, SR_TID.X ;
    SHF.L.U32 R60, R2, 0x2, RZ ;
    MOV R4, RZ ;
    MOV R9, RZ ;
L_top:
    [B0-----:R-:W-:-:S01] NOP ;
    IADD3 R7, PT, PT, R4, R7, RZ ;
    LDS R4, [R60+0x300] ;
    IADD3 R9, PT, PT, R9, 0x1, RZ ;
    ISETP.NE.AND P0, PT, R9, 0x8, PT ;
    @P0 BRA L_top ;
    EXIT ;
";

#[test]
fn a_hand_scheduled_wait_drains_for_the_words_behind_it() {
    let (plain, _, _) = build(AUTHORS_WAIT, &[SYNC, POLICY]);
    assert_eq!(word(&plain, "LDS R4").wb, Some(0));
    assert_eq!(word(&plain, READ_R4).wait, vec![0]);
    for value in [HEAD, PATHS] {
        let (k, _, _) = build(AUTHORS_WAIT, &[SYNC, POLICY, value]);
        assert_eq!(word(&k, "NOP").wait, vec![0], "the author's word is not touched");
        assert!(word(&k, READ_R4).wait.is_empty(), "under {value:?}: {:?}", word(&k, READ_R4));
    }
}

#[test]
fn a_value_that_is_neither_is_refused() {
    let dir = std::env::temp_dir().join(format!("waitdrained_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    let (ok, log) = asm(&straight(), &[SYNC, POLICY, ("CUBIT_WAIT_DRAINED", "all")], &dir);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!ok, "a misspelt opt-in must not build the allocator's schedule silently:\n{log}");
    assert!(log.contains("CUBIT_WAIT_DRAINED=all") && log.contains("`head`") && log.contains("`paths`"), "{log}");
}

#[test]
fn the_count_line_names_the_value_and_the_three_counts() {
    let (_, _, log) = build(&straight(), &[SYNC, POLICY, PATHS]);
    let line = count_line(&log);
    assert!(line.contains("wait rule (paths)") && line.contains("on an empty scoreboard") && line.contains("kept for an unmeasured set"), "{line}");
    let (_, _, plain) = build(&straight(), &[SYNC, POLICY]);
    assert!(!plain.contains("wait rule"), "without the variable no line:\n{plain}");
}

// ---- the controls: green with and without the rule ----

#[test]
fn a_path_that_misses_the_first_wait_keeps_the_second() {
    // the branch skips the round's first waiting word: on that path the second reader is the first wait
    let text = format!("{PINS}    ISETP.NE.AND P1, PT, R2, RZ, PT ;\nL_top:\n    @P1 BRA L_skip ;\n    {READ_R5} ;\nL_skip:\n    {READ_R4} ;\n{TAIL}{SUM}");
    for env in [vec![SYNC, POLICY], vec![SYNC, POLICY, HEAD], vec![SYNC, POLICY, PATHS]] {
        let (k, _, _) = build(&text, &env);
        assert_eq!(word(&k, READ_R4).wait, vec![0], "under {env:?}");
        assert_eq!(word(&k, READ_R5).wait, vec![0], "under {env:?}");
    }
}

#[test]
fn the_out_of_line_block_of_a_bra_div_keeps_its_wait() {
    let text = "    S2R R2, SR_TID.X ;
    SHF.L.U32 R60, R2, 0x2, RZ ;
    LDS R4, [R60+0x300] ;
    UMOV UR4, 0xffffffff ;
    BRA.DIV UR4, L_slow ;
    IADD3 R6, PT, PT, R4, R6, RZ ;
L_join:
    IADD3 R9, PT, PT, R6, R9, RZ ;
    EXIT ;
L_slow:
    IADD3 R10, PT, PT, R4, R10, RZ ;
    MOV R6, R10 ;
    BRA L_join ;
";
    for env in [vec![SYNC, POLICY], vec![SYNC, POLICY, HEAD], vec![SYNC, POLICY, PATHS]] {
        let (k, _, _) = build(text, &env);
        let sb = word(&k, "LDS R4").wb.expect("the load has a write barrier");
        assert_eq!(word(&k, "IADD3 R6, PT, PT, R4").wait, vec![sb], "the fast path, under {env:?}");
        assert_eq!(word(&k, "IADD3 R10, PT, PT, R4").wait, vec![sb], "the out-of-line block: no word waited on its path, under {env:?}");
    }
}

#[test]
fn a_block_only_a_brx_reaches_keeps_its_wait() {
    let text = "    S2R R2, SR_TID.X ;
    SHF.L.U32 R60, R2, 0x2, RZ ;
    LDS R4, [R60+0x300] ;
    [B------:R-:W1:-:S02] LDC R50, c[0x2][R20] ;
    BRX R50 -0x50 ;
    IADD3 R6, PT, PT, R4, R6, RZ ;
    BRA L_j ;
    IADD3 R7, PT, PT, R4, R7, RZ ;
    BRA L_j ;
L_j:
    EXIT ;
";
    for env in [vec![SYNC, POLICY], vec![SYNC, POLICY, HEAD], vec![SYNC, POLICY, PATHS]] {
        let (k, _, _) = build(text, &env);
        let sb = word(&k, "LDS R4").wb.expect("the load has a write barrier");
        assert_ne!(sb, 1, "the table's load is the author's, on scoreboard 1");
        assert_eq!(word(&k, "IADD3 R6, PT, PT, R4").wait, vec![sb], "the first case block, under {env:?}");
        assert_eq!(word(&k, READ_R4).wait, vec![sb], "the block no branch names: the wait of the first block is not on its path, under {env:?}");
    }
}

#[test]
fn the_wait_between_two_batches_of_one_scoreboard_stays_where_their_set_is_not_measured() {
    // a plain shared load and a 64-bit one on one barrier in front of one wait: no measured set
    let text = round_with_a_younger_load("    LDS.64 R12, [R60+0x600] ;\n");
    for env in [vec![SYNC, POLICY], vec![SYNC, POLICY, HEAD], vec![SYNC, POLICY, PATHS]] {
        let (k, _, _) = build(&text, &env);
        assert_eq!(word(&k, "LDS.64 R12").wb, Some(0), "under {env:?}");
        assert_eq!(word(&k, READ_R4).wait, vec![0], "the wait that keeps the two loads apart, under {env:?}");
    }
}

#[test]
fn without_the_switch_every_wait_stands_as_before() {
    for text in [round(), straight(), round_with_a_younger_load("")] {
        let (plain, bytes, _) = build(&text, &[SYNC, POLICY]);
        assert_eq!(word(&plain, READ_R4).wait, vec![0]);
        // unset, empty and `0` are one thing
        for off in ["", "0"] {
            let (_, b, _) = build(&text, &[SYNC, POLICY, ("CUBIT_WAIT_DRAINED", off)]);
            assert_eq!(b, bytes, "CUBIT_WAIT_DRAINED={off:?} is the allocator's schedule");
        }
        // honoured only with CUBIT_WAIT_POLICY=1
        let (_, alone, _) = build(&text, &[SYNC]);
        let (_, asked, _) = build(&text, &[SYNC, HEAD]);
        assert_eq!(asked, alone, "without the wait policy the variable changes nothing");
    }
}
