//! The scoreboard audit (`CUBIT_HAZ`) follows the paths of the kernel (2026-11-18,
//! `scheduling_pass::report_hazards_on_paths`).
//!
//! `report_hazards` walks the text in order and replays one loop body: the scoreboard state it holds at a word is
//! what the TEXT in front of the word leaves. A block that execution enters from somewhere else — the out-of-line
//! block of a `BRA.DIV` behind the last `EXIT`, the arm behind an unconditional `BRA`, the next round of any loop
//! but the first — was entered with waits its paths never issued, and a read there of a load that no word waited
//! was not named. The path-aware scan runs on the control-flow graph and names those reads (`NOT waited on a
//! path`); it prints under `CUBIT_HAZ` alone and adds to the text walk's list. One summary line says how the two
//! walks stand to each other — among it the reads the text walk names although a wait stands on every path.
//!
//! The first three tests and the two of the summary line fail on the audit without the scan; the other three are
//! controls that pass on both.
//! Every word of the kernels below carries its control word: nothing here is scheduled, the audit reads what
//! stands.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const ISA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");

/// `cubit asm` of `text` under `env`: the log (both streams).
fn log_of(text: &str, env: &[(&str, &str)]) -> String {
    let dir = std::env::temp_dir().join(format!("hazpaths_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, text).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", ISA, src.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .expect("run cubit");
    let log = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(o.status.success(), "asm failed:\n{log}\n{text}");
    log
}

/// The audit's RAW lines that name the word `word` as the reader.
fn raw_lines(log: &str, word: &str) -> Vec<String> {
    log.lines().filter(|l| l.contains("HAZ RAW") && l.contains(word)).map(str::to_string).collect()
}

const ASKED: &[(&str, &str)] = &[("CUBIT_HAZ", "1")];

/// A load on scoreboard 0; the fast path behind the `BRA.DIV` waits it, the out-of-line block (`slow`, the word
/// that reads the load there) stands behind the `EXIT`.
fn div_kernel(slow: &str) -> String {
    format!(
        "\
.entry haz_paths
    .reg R0-R31
    .param ptr out
    [B------:R-:W1:-:S01] LDCU.64 UR8, c[0x0][0x358] ;
    [B------:R-:W1:-:S01] LDC.64 R2, c[0x0][0x380] ;
    [B-1----:R-:W0:-:S02] LDG.E R4, desc[UR8][R2.64] ;
    [B------:R-:W-:-:S01] UMOV UR4, 0xffffffff ;
    [B------:R-:W-:-:S06] BRA.DIV UR4, L_slow ;
    [B0-----:R-:W-:-:S02] MOV R6, R4 ;
L_join:
    [B------:R-:W-:-:S01] MOV R9, R6 ;
    [B------:R-:W-:-:S05] EXIT ;
L_slow:
    {slow}
    [B------:R-:W-:-:S01] MOV R6, R10 ;
    [B------:R-:W-:-:S05] BRA L_join ;
"
    )
}

#[test]
fn a_read_in_the_out_of_line_block_of_a_bra_div_that_no_word_waited_is_named() {
    let log = log_of(&div_kernel("[B------:R-:W-:-:S02] MOV R10, R4 ;"), ASKED);
    let named = raw_lines(&log, "MOV R10, R4");
    assert_eq!(named.len(), 1, "the read of the load in the out-of-line block, one line:\n{log}");
    assert!(named[0].contains("reads R4") && named[0].contains("LDG") && named[0].contains("wb0") && named[0].contains("NOT waited"), "{}", named[0]);
    // the fast path waits the scoreboard: its read is not named
    assert!(raw_lines(&log, "MOV R6, R4").is_empty(), "the fast path waits:\n{log}");
}

/// A load on scoreboard 0, then two arms: the first waits it and leaves by an unconditional `BRA`; the text walk
/// carried that wait into the second arm, which execution enters from the branch in front of the first.
const ARMS: &str = "\
.entry haz_arms
    .reg R0-R31
    .param ptr out
    [B------:R-:W1:-:S01] LDCU.64 UR8, c[0x0][0x358] ;
    [B------:R-:W1:-:S01] LDC.64 R2, c[0x0][0x380] ;
    [B------:R-:W1:-:S01] LDC R5, c[0x0][0x388] ;
    [B-1----:R-:W0:-:S02] LDG.E R4, desc[UR8][R2.64] ;
    [B------:R-:W-:-:S13] ISETP.NE.AND P0, PT, R5, RZ, PT ;
    [B------:R-:W-:-:S05] @P0 BRA L_else ;
    [B0-----:R-:W-:-:S02] MOV R6, R4 ;
    [B------:R-:W-:-:S05] BRA L_join ;
L_else:
    [B------:R-:W-:-:S02] MOV R11, R4 ;
    [B------:R-:W-:-:S01] MOV R6, R11 ;
L_join:
    [B------:R-:W-:-:S01] MOV R9, R6 ;
    [B------:R-:W-:-:S05] EXIT ;
";

#[test]
fn the_arm_behind_an_unconditional_branch_does_not_inherit_the_wait_of_the_arm_in_front_of_it() {
    let log = log_of(ARMS, ASKED);
    let named = raw_lines(&log, "MOV R11, R4");
    assert_eq!(named.len(), 1, "the read in the second arm, one line:\n{log}");
    assert!(named[0].contains("reads R4") && named[0].contains("NOT waited"), "{}", named[0]);
    assert!(raw_lines(&log, "MOV R6, R4").is_empty(), "the first arm waits:\n{log}");
}

/// Two loops. The second reads at its head the load its own last round issued at its foot: no word waits between
/// the foot and the head. The text walk replays the first loop of a kernel only.
const LOOPS: &str = "\
.entry haz_loops
    .reg R0-R31
    .param ptr out
    [B------:R-:W1:-:S01] LDCU.64 UR8, c[0x0][0x358] ;
    [B------:R-:W1:-:S01] LDC.64 R2, c[0x0][0x380] ;
    [B-1----:R-:W0:-:S02] LDG.E R4, desc[UR8][R2.64] ;
    [B0-----:R-:W-:-:S01] MOV R6, R4 ;
    [B------:R-:W-:-:S01] MOV R20, RZ ;
L_one:
    [B------:R-:W-:-:S01] IADD3 R20, PT, PT, R20, 0x1, RZ ;
    [B------:R-:W-:-:S13] ISETP.NE.AND P1, PT, R20, 0x4, PT ;
    [B------:R-:W-:-:S05] @P1 BRA L_one ;
    [B------:R-:W-:-:S01] MOV R21, RZ ;
L_two:
    [B------:R-:W-:-:S02] MOV R12, R4 ;
    [B------:R-:W-:-:S01] IADD3 R21, PT, PT, R21, 0x1, RZ ;
    [B------:R-:W0:-:S02] LDG.E R4, desc[UR8][R2.64] ;
    [B------:R-:W-:-:S13] ISETP.NE.AND P2, PT, R21, 0x4, PT ;
    [B------:R-:W-:-:S05] @P2 BRA L_two ;
    [B0-----:R-:W-:-:S02] MOV R9, R4 ;
    [B------:R-:W-:-:S05] EXIT ;
";

#[test]
fn a_read_over_the_back_edge_of_a_loop_that_is_not_the_first_is_named() {
    let log = log_of(LOOPS, ASKED);
    let named = raw_lines(&log, "MOV R12, R4");
    assert_eq!(named.len(), 1, "the head's read of the load of the round before, one line:\n{log}");
    assert!(named[0].contains("reads R4") && named[0].contains("NOT waited"), "{}", named[0]);
    // behind the loop the load is waited
    assert!(raw_lines(&log, "MOV R9, R4").is_empty(), "the word behind the loop waits:\n{log}");
}

#[test]
fn a_wait_in_the_out_of_line_block_covers_its_read() {
    let log = log_of(&div_kernel("[B0-----:R-:W-:-:S02] MOV R10, R4 ;"), ASKED);
    assert!(raw_lines(&log, "MOV R10, R4").is_empty(), "the block waits scoreboard 0 itself:\n{log}");
    assert!(raw_lines(&log, "MOV R6, R4").is_empty(), "{log}");
}

/// A read the text walk names already (a straight line: the load, then its reader without a wait).
const STRAIGHT: &str = "\
.entry haz_straight
    .reg R0-R31
    .param ptr out
    [B------:R-:W1:-:S01] LDCU.64 UR8, c[0x0][0x358] ;
    [B------:R-:W1:-:S01] LDC.64 R2, c[0x0][0x380] ;
    [B-1----:R-:W0:-:S02] LDG.E R4, desc[UR8][R2.64] ;
    [B------:R-:W-:-:S02] MOV R13, R4 ;
    [B------:R-:W-:-:S05] EXIT ;
";

#[test]
fn a_read_the_text_walk_names_is_named_once() {
    let log = log_of(STRAIGHT, ASKED);
    let named = raw_lines(&log, "MOV R13, R4");
    assert_eq!(named.len(), 1, "one line, the text walk's:\n{log}");
    assert!(named[0].contains("NOT waited)"), "the text walk's own wording: {}", named[0]);
}

/// The summary line of the path-aware scan.
fn summary(log: &str) -> String {
    log.lines().find(|l| l.contains("HAZ paths:")).map(|l| l[l.find("HAZ paths:").unwrap()..].to_string()).unwrap_or_default()
}

#[test]
fn the_summary_line_says_how_the_two_walks_stand() {
    // the out-of-line block: one read on a path, not the text walk's
    let s = summary(&log_of(&div_kernel("[B------:R-:W-:-:S02] MOV R10, R4 ;"), ASKED));
    assert!(s.starts_with("HAZ paths: 1 read(s) of a result some path leaves unwaited (0 of them named by the text walk too); 0 read(s) the text walk names"), "{s:?}");
    // the straight line: one read, both walks name it
    let s = summary(&log_of(STRAIGHT, ASKED));
    assert!(s.starts_with("HAZ paths: 1 read(s) of a result some path leaves unwaited (1 of them named by the text walk too); 0 read(s) the text walk names"), "{s:?}");
    // nothing to say: no line
    assert!(summary(&log_of(&div_kernel("[B0-----:R-:W-:-:S02] MOV R10, R4 ;"), ASKED)).is_empty());
}

/// The wait stands in a block behind the `EXIT` that every path to the reader runs through; in the text the reader
/// stands in front of it.
const DETOUR: &str = "\
.entry haz_detour
    .reg R0-R31
    .param ptr out
    [B------:R-:W1:-:S01] LDCU.64 UR8, c[0x0][0x358] ;
    [B------:R-:W1:-:S01] LDC.64 R2, c[0x0][0x380] ;
    [B-1----:R-:W0:-:S02] LDG.E R4, desc[UR8][R2.64] ;
    [B------:R-:W-:-:S05] BRA L_wait ;
L_read:
    [B------:R-:W-:-:S02] MOV R14, R4 ;
    [B------:R-:W-:-:S05] EXIT ;
L_wait:
    [B0-----:R-:W-:-:S02] MOV R10, RZ ;
    [B------:R-:W-:-:S05] BRA L_read ;
";

#[test]
fn a_read_the_text_walk_names_behind_a_wait_on_every_path_is_counted_and_stays_named() {
    let log = log_of(DETOUR, ASKED);
    // the text walk's line stands as it did (the path-aware scan adds; it takes nothing away)
    let named = raw_lines(&log, "MOV R14, R4");
    assert_eq!(named.len(), 1, "{log}");
    assert!(named[0].contains("NOT waited)"), "{}", named[0]);
    let s = summary(&log);
    assert!(s.starts_with("HAZ paths: 0 read(s) of a result some path leaves unwaited (0 of them named by the text walk too); 1 read(s) the text walk names stand behind a wait on every path"), "{s:?}");
}

#[test]
fn without_the_variable_the_log_is_the_text_walks() {
    // the three kernels of the first three tests: nothing of the path-aware scan is printed
    for (text, word) in [(div_kernel("[B------:R-:W-:-:S02] MOV R10, R4 ;"), "MOV R10, R4"), (ARMS.to_string(), "MOV R11, R4"), (LOOPS.to_string(), "MOV R12, R4")] {
        let log = log_of(&text, &[]);
        assert!(raw_lines(&log, word).is_empty(), "{word}:\n{log}");
        assert!(!log.contains("on a path"), "{log}");
    }
}
