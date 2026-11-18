//! The scoreboard audit (`CUBIT_HAZ`) names a word that rewrites an operand of a word in flight (2026-11-18,
//! `scheduling_pass::report_war_on_paths`, KNOWN_ISSUES A64).
//!
//! A word that carries a read barrier reads its register operands after it issues; until a word waits that
//! scoreboard (or the scoreboard of the reader's own result) the operands are in flight, and a word that rewrites
//! one of them races the read. The audit's two RAW walks hold results, not operands: a schedule in which the
//! rewriter of a store's data lost its wait drew no line. The write-after-read half follows the paths of the
//! kernel like the path-aware RAW scan and names the rewriter (`NOT awaited on a path`), with the fewest static
//! cycles between the two words. Two kinds of rewrite are counted in its one summary line and not named: by a
//! producer of the reader's own completion class, and of a uniform register of a reader that is no
//! synchronisation word — both stand in the vendor's own schedules.
//!
//! Eight tests fail on the audit without the scan; three are controls that pass on both (a wait of the read
//! barrier ends the flight; a word that never executes; without the variable). Where a kernel below carries its
//! control words nothing is scheduled: the audit reads what stands. The last test builds a kernel, takes the wait
//! off the word that rewrites the store's data in the schedule cubit wrote, and assembles that text as written.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const ISA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const ASKED: &[(&str, &str)] = &[("CUBIT_HAZ", "1")];

fn scratch() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("hazwar_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `cubit asm` of `text` under `env` into `dir`: the log (both streams).
fn asm_in(dir: &std::path::Path, text: &str, env: &[(&str, &str)]) -> String {
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, text).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", ISA, src.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .expect("run cubit");
    let log = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success(), "asm failed:\n{log}\n{text}");
    log
}

/// `cubit asm` of `text` under `env`: the log.
fn log_of(text: &str, env: &[(&str, &str)]) -> String {
    let dir = scratch();
    let log = asm_in(&dir, text, env);
    let _ = std::fs::remove_dir_all(&dir);
    log
}

/// The audit's WAR lines.
fn war_lines(log: &str) -> Vec<String> {
    log.lines().filter(|l| l.contains("HAZ WAR")).map(str::to_string).collect()
}

/// The summary line of the write-after-read half, from `HAZ` on.
fn summary(log: &str) -> Option<String> {
    log.lines().find(|l| l.contains("HAZ paths:") && l.contains("rewrite(s)")).map(|l| l[l.find("HAZ paths:").unwrap()..].to_string())
}

fn kernel(body: &str) -> String {
    format!(
        "\
.entry haz_war
    .reg R0-R31
    .param ptr out
    [B------:R-:W1:-:S01] LDCU.64 UR8, c[0x0][0x358] ;
    [B------:R-:W1:-:S02] LDC.64 R2, c[0x0][0x380] ;
    [B-1----:R-:W-:-:S01] MOV R6, R9 ;
{body}    [B------:R-:W-:-:S05] EXIT ;
"
    )
}

/// A global store with a read barrier on scoreboard 0; `rewriter` is the word that writes the store's data again.
fn store_then(rewriter: &str) -> String {
    kernel(&format!("    [B------:R0:W-:-:S03] STG.E desc[UR8][R2.64], R6 ;\n    {rewriter}\n"))
}

#[test]
fn a_word_that_rewrites_the_data_of_a_store_in_flight_is_named() {
    let log = log_of(&store_then("[B------:R-:W-:-:S01] MOV R6, R10 ;"), ASKED);
    let lines = war_lines(&log);
    assert_eq!(lines.len(), 1, "{log}");
    let l = &lines[0];
    assert!(l.contains("MOV R6, R10") && l.contains("rewrites R6 <- 0x") && l.contains("STG (rb0, NOT awaited on a path"), "{l}");
    // the store stands at a stall count of 3: three cycles between the two issues
    assert!(l.contains("; 3 cycle(s) behind it on the shortest)"), "{l}");
}

#[test]
fn a_word_that_rewrites_the_address_of_a_store_in_flight_is_named() {
    let log = log_of(&store_then("[B------:R-:W-:-:S01] MOV R2, R10 ;"), ASKED);
    let lines = war_lines(&log);
    assert_eq!(lines.len(), 1, "{log}");
    assert!(lines[0].contains("rewrites R2 <- 0x"), "{}", lines[0]);
    // the registers are the scheduler's operand model in force: the high half of the 64-bit base is a source
    // under `CUBIT_SYNC_CLASSES`
    let high = store_then("[B------:R-:W-:-:S01] MOV R3, R10 ;");
    assert!(war_lines(&log_of(&high, ASKED)).is_empty());
    let lines = war_lines(&log_of(&high, &[("CUBIT_HAZ", "1"), ("CUBIT_SYNC_CLASSES", "1")]));
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("rewrites R3 <- 0x"), "{}", lines[0]);
}

#[test]
fn a_wait_of_the_read_barrier_ends_the_flight() {
    // the rewriter's own wait
    let log = log_of(&store_then("[B0-----:R-:W-:-:S01] MOV R6, R10 ;"), ASKED);
    assert!(war_lines(&log).is_empty(), "{log}");
    // a wait of any word in front of it
    let log = log_of(&store_then("[B0-----:R-:W-:-:S01] MOV R11, R10 ;\n    [B------:R-:W-:-:S01] MOV R6, R10 ;"), ASKED);
    assert!(war_lines(&log).is_empty(), "{log}");
    assert_eq!(summary(&log), None, "nothing to count: no summary line");
}

/// The store, then a branch: the arm that falls through waits scoreboard 0, the arm the branch takes does not; the
/// rewriter stands where the two meet.
const ARMS: &str = "\
    [B------:R0:W-:-:S03] STG.E desc[UR8][R2.64], R6 ;
    [B------:R-:W-:-:S13] ISETP.NE.AND P0, PT, R9, RZ, PT ;
    [B------:R-:W-:-:S05] @P0 BRA L_join ;
    [B0-----:R-:W-:-:S01] MOV R11, R10 ;
L_join:
    [B------:R-:W-:-:S01] MOV R6, R10 ;
";

#[test]
fn a_wait_on_one_arm_does_not_cover_the_path_through_the_other() {
    let log = log_of(&kernel(ARMS), ASKED);
    let lines = war_lines(&log);
    assert_eq!(lines.len(), 1, "{log}");
    // the path through the branch: the store 3, the compare 13, the branch 5
    assert!(lines[0].contains("MOV R6, R10") && lines[0].contains("; 21 cycle(s) behind it on the shortest)"), "{}", lines[0]);
    // with the wait in front of the branch every path holds it
    let both = ARMS.replace("[B------:R-:W-:-:S13] ISETP", "[B0-----:R-:W-:-:S13] ISETP");
    assert!(war_lines(&log_of(&kernel(&both), ASKED)).is_empty());
}

/// A round: the word that rewrites the store's data stands in FRONT of the store in the text and is reached over
/// the back edge.
fn round(first: &str) -> String {
    kernel(&format!(
        "L_top:\n    {first}\n    [B------:R0:W-:-:S03] STG.E desc[UR8][R2.64], R6 ;\n    [B------:R-:W-:-:S05] IADD3 R9, PT, PT, R9, 0x1, RZ ;\n    [B------:R-:W-:-:S13] ISETP.NE.AND P0, PT, R9, 0x8, PT ;\n    [B------:R-:W-:-:S05] @P0 BRA L_top ;\n"
    ))
}

#[test]
fn a_rewriter_over_the_back_edge_of_a_round_is_named() {
    let log = log_of(&round("[B------:R-:W-:-:S01] MOV R6, R10 ;"), ASKED);
    let lines = war_lines(&log);
    assert_eq!(lines.len(), 1, "{log}");
    assert!(lines[0].contains("MOV R6, R10") && lines[0].contains("; 26 cycle(s) behind it on the shortest)"), "{}", lines[0]);
    assert!(war_lines(&log_of(&round("[B0-----:R-:W-:-:S01] MOV R6, R10 ;"), ASKED)).is_empty());
}

#[test]
fn a_wait_of_the_readers_own_result_ends_the_flight() {
    // a load with a read barrier on 0 and its result on 2: the word that waits the result stands in front of the
    // word that rewrites the base
    let covered = kernel(
        "    [B------:R0:W2:-:S02] LDG.E R4, desc[UR8][R2.64] ;\n    [B--2---:R-:W-:-:S01] MOV R7, R4 ;\n    [B------:R-:W-:-:S01] MOV R2, R10 ;\n",
    );
    assert!(war_lines(&log_of(&covered, ASKED)).is_empty());
    // without that word between: named
    let bare = kernel("    [B------:R0:W2:-:S02] LDG.E R4, desc[UR8][R2.64] ;\n    [B------:R-:W-:-:S01] MOV R2, R10 ;\n    [B--2---:R-:W-:-:S01] MOV R7, R4 ;\n");
    let lines = war_lines(&log_of(&bare, ASKED));
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("rewrites R2 <- 0x") && lines[0].contains("LDG (rb0"), "{}", lines[0]);
}

#[test]
fn a_rewriter_under_a_guard_is_named_and_so_is_the_next() {
    let log = log_of(&store_then("[B------:R-:W-:-:S01] @P1 MOV R6, R10 ;\n    [B------:R-:W-:-:S01] MOV R6, R11 ;"), ASKED);
    assert_eq!(war_lines(&log).len(), 2, "the guarded word may be skipped: the store's data is still in flight behind it\n{log}");
    // behind a rewriter that always executes the next one is not named again
    let log = log_of(&store_then("[B------:R-:W-:-:S01] MOV R6, R10 ;\n    [B------:R-:W-:-:S01] MOV R6, R11 ;"), ASKED);
    assert_eq!(war_lines(&log).len(), 1, "{log}");
}

#[test]
fn a_word_that_never_executes_neither_reads_nor_rewrites() {
    // the reader under `@!PT`
    let log = log_of(&kernel("    [B------:R0:W-:-:S03] @!PT STG.E desc[UR8][R2.64], R6 ;\n    [B------:R-:W-:-:S01] MOV R6, R10 ;\n"), ASKED);
    assert!(war_lines(&log).is_empty(), "{log}");
    // the rewriter under `@!PT`
    let log = log_of(&store_then("[B------:R-:W-:-:S01] @!PT MOV R6, R10 ;"), ASKED);
    assert!(war_lines(&log).is_empty(), "{log}");
}

#[test]
fn the_summary_line_counts_what_is_named_and_what_is_not() {
    // one named rewrite (the store's data) and one of the store's descriptor register, which is counted alone
    let log = log_of(&store_then("[B------:R-:W-:-:S01] MOV R6, R10 ;\n    [B------:R-:W-:-:S01] UMOV UR8, 0x0 ;"), ASKED);
    assert_eq!(war_lines(&log).len(), 1, "{log}");
    let s = summary(&log).expect("the summary line");
    assert!(
        s.starts_with("HAZ paths: 1 rewrite(s) of an operand in flight -- the reader a global store 1, a shared or local store 0, a load 0, another word 0; counted and not named: 0 by a producer of the reader's own completion class, 1 of a uniform register of a reader that is no synchronisation word (1 read barrier(s) in the text)"),
        "{s:?}"
    );
    // a shuffle whose result register is the operand of the shuffle in front of it: its result returns behind
    let pair = kernel("    [B------:R0:W2:-:S04] SHFL.BFLY PT, R12, R6, 0x1, 0x1f ;\n    [B------:R0:W3:-:S02] SHFL.BFLY PT, R6, R10, 0x1, 0x1f ;\n    [B--23--:R-:W-:-:S01] MOV R13, R12 ;\n");
    let log = log_of(&pair, ASKED);
    assert!(war_lines(&log).is_empty(), "{log}");
    let s = summary(&log).expect("the summary line");
    assert!(s.starts_with("HAZ paths: 0 rewrite(s) of an operand in flight") && s.contains("counted and not named: 1 by a producer of the reader's own completion class, 0 of a uniform register"), "{s:?}");
}

#[test]
fn without_the_variable_the_log_holds_no_line_of_the_scan() {
    let log = log_of(&store_then("[B------:R-:W-:-:S01] MOV R6, R10 ;"), &[]);
    assert!(war_lines(&log).is_empty() && summary(&log).is_none(), "{log}");
}

/// What cubit schedules itself: a store, the word that writes the store's data again, a second store.
const BUILT: &str = "\
.entry haz_war
    .reg R0-R31
    .param ptr out
    LDCU.64 UR8, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    S2R R6, SR_TID.X ;
    STG.E desc[UR8][R2.64], R6 ;
    MOV R6, R10 ;
    STG.E desc[UR8][R2.64+0x4], R6 ;
    EXIT ;
";

#[test]
fn the_rewriter_of_a_built_schedule_that_loses_its_wait_is_named() {
    let dir = scratch();
    let env = [("CUBIT_SYNC_CLASSES", "1"), ("CUBIT_HAZ", "1")];
    let log = asm_in(&dir, BUILT, &env);
    assert!(war_lines(&log).is_empty(), "the schedule cubit writes: {log}");
    let o = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["disassemble", "--frozen", dir.join("k.cubin").to_str().unwrap(), "-t", ISA])
        .env_clear()
        .output()
        .expect("run cubit");
    assert!(o.status.success(), "disassemble: {}", String::from_utf8_lossy(&o.stderr));
    let listing = String::from_utf8_lossy(&o.stdout).into_owned();
    // the store carries a read barrier and the word that rewrites its data waits that scoreboard
    let store = listing.lines().find(|l| l.contains("STG.E desc[UR8][R2.64], R6")).expect("the store");
    let rb = store[store.find(":R").unwrap() + 2..].chars().next().unwrap();
    assert!(rb.is_ascii_digit(), "the store's read barrier: {store}");
    let mov = listing.lines().find(|l| l.contains("MOV R6, R10")).expect("the rewriter");
    let tag = &mov[mov.find("[B").unwrap()..mov.find(']').unwrap() + 1];
    assert!(tag[2..8].contains(rb), "the rewriter waits the store's read barrier: {mov}");
    // the same schedule as written: no line
    let asw = [("CUBIT_HAZ", "1")];
    assert!(war_lines(&asm_in(&dir, &listing, &asw)).is_empty());
    // ... and with that one wait bit taken off the rewriter: named
    let bare = format!("{}{}{}", &tag[..2], tag[2..8].replace(rb, "-"), &tag[8..]);
    let cut = listing.replace(mov, &mov.replace(tag, &bare));
    assert_ne!(cut, listing);
    let lines = war_lines(&asm_in(&dir, &cut, &asw));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("MOV R6, R10") && lines[0].contains("rewrites R6 <- 0x") && lines[0].contains(&format!("STG (rb{rb}, NOT awaited on a path")), "{}", lines[0]);
}
