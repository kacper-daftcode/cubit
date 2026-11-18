//! `CUBIT_LOAD_TOP=1` (opt-in, 2026-11-18; with `CUBIT_WAIT_POLICY=1`): the wait for the result of a global load
//! stands at the top of the loop that holds the load, not at the reader (KNOWN_ISSUES A68; `src/load_top.rs`).
//!
//! The allocator writes the wait for a load on the first word that reads or rewrites the pending register on
//! every path behind it. Where the NEXT pass of a loop reads the load, that word stands a few words behind the
//! loop's top, and every word that waits the load's scoreboard for something else on the way round holds for
//! the load too. Under the switch:
//!
//! 1. the walk for the first consumers of an `LDG` in a natural loop ends at the TOPS -- the `BRA` that ends the
//!    header's block of every natural loop that holds the load; a reader (or a rewriter of the register) loses
//!    its wait only where every path from the load to it passes a top, and a top is taken only if it takes a
//!    reader;
//! 2. behind the colouring the use moves to the scoreboard on which no word waits for another use while its
//!    loads are in flight.
//!
//! What the rule must not do has a test each: no wait comes off a word of an ordered event; the wait that
//! releases a read barrier stays on the rewriter of its source; a reader a path reaches without a top keeps
//! its wait; no top in a block that holds a load; a flight that crosses a dispatch is not covered; nothing for
//! a hand-scheduled load, in a text without a loop, or without `CUBIT_WAIT_POLICY=1`.
//!
//! Ten tests fail on the allocator without the switch (the variable is then unknown and changes nothing); five
//! are controls -- shapes the switch leaves byte for byte.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const SYNC: (&str, &str) = ("CUBIT_SYNC_CLASSES", "1");
const POLICY: (&str, &str) = ("CUBIT_WAIT_POLICY", "1");
const TOP: (&str, &str) = ("CUBIT_LOAD_TOP", "1");
const DUMP: (&str, &str) = ("CUBIT_DUMP_USES", "1");
const VERIFY: (&str, &str) = ("CUBIT_VERIFY", "1");

/// One instruction of the schedule cubit wrote: (wait bits, read barrier, write barrier, the word).
#[derive(Debug, Clone, PartialEq)]
struct Word {
    wait: Vec<u8>,
    rb: Option<u8>,
    wb: Option<u8>,
    text: String,
}

/// A build: the words with the control fields the allocator gave them, the cubin's bytes, what `cubit asm`
/// printed.
struct Build {
    words: Vec<Word>,
    cubin: Vec<u8>,
    log: String,
}

/// `cubit asm` of an unscheduled kernel under `env`, then `cubit disassemble --frozen`.
fn build(body: &str, env: &[(&str, &str)]) -> Build {
    let dir = std::env::temp_dir().join(format!("loadtop_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, format!(".entry load_top_probe\n    .reg R0-R63\n    .param ptr out\n{body}.endentry\n")).unwrap();
    let run = |args: &[&str], env: &[(&str, &str)]| {
        let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
        let log = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert!(o.status.success(), "{args:?} under {env:?}: {log}");
        (String::from_utf8_lossy(&o.stdout).into_owned(), log)
    };
    let (_, log) = run(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()], env);
    let (listing, _) = run(&["disassemble", "--frozen", out.to_str().unwrap(), "-t", TABLE], &[]);
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
    Build { words, cubin, log }
}

impl Build {
    fn at(&self, starts: &str) -> usize {
        self.words.iter().position(|w| w.text.starts_with(starts)).unwrap_or_else(|| panic!("no word `{starts}` in {:#?}", self.words))
    }
    fn word(&self, starts: &str) -> &Word {
        &self.words[self.at(starts)]
    }
    /// The write barrier of the first word that starts so.
    fn wb(&self, starts: &str) -> u8 {
        self.word(starts).wb.unwrap_or_else(|| panic!("`{starts}` carries no write barrier: {:#?}", self.words))
    }
    /// The lines of the build's log that start so.
    fn lines(&self, starts: &str) -> Vec<&str> {
        self.log.lines().map(str::trim).filter(|l| l.starts_with(starts)).collect()
    }
}

/// The policy alone | the policy and the switch.
fn both(body: &str) -> (Build, Build) {
    (build(body, &[SYNC, POLICY, DUMP, VERIFY]), build(body, &[SYNC, POLICY, TOP, DUMP, VERIFY]))
}

/// A loop whose load is read by the next pass: the reader stands behind the loop's top (the stage loop of the
/// producer warp in `fc2_kernel_ws<4,2,1,0>`: five such loads).
const ONE_LOOP: &str = "    S2R R2, SR_TID.X ;
    MOV R3, RZ ;
    MOV R20, RZ ;
    MOV R4, R2 ;
L_top:
    ISETP.GE.AND P0, PT, R20, 0x8, PT ;
    @P0 BRA L_out ;
    IADD3 R8, PT, PT, R4, R20, RZ ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    LDG.E R4, desc[UR8][R2.64] ;
    BRA L_top ;
L_out:
    EXIT ;
";

#[test]
fn the_wait_for_a_global_load_stands_at_the_loops_top_when_every_path_to_its_readers_passes_it() {
    let (policy, top) = both(ONE_LOOP);
    // the allocator's place: the reader, behind the top
    let b = policy.wb("LDG.E R4");
    assert_eq!(policy.word("IADD3 R8").wait, vec![b], "{:#?}", policy.words);
    assert!(policy.word("@P0 BRA").wait.is_empty(), "{:#?}", policy.words);
    // under the switch: the branch that ends the header's block, and no wait on the reader
    let b = top.wb("LDG.E R4");
    assert_eq!(top.word("@P0 BRA").wait, vec![b], "the top waits for the load: {:#?}", top.words);
    assert!(top.word("IADD3 R8").wait.is_empty(), "the reader behind the top does not wait: {:#?}", top.words);
    assert_eq!(top.lines("TOP ").len(), 1, "one use waits at a top: {}", top.log);
}

/// The same loop with a second way out, behind the load: a reader there is reached without the top.
const SIDE_EXIT: &str = "    S2R R2, SR_TID.X ;
    MOV R3, RZ ;
    MOV R20, RZ ;
    MOV R4, R2 ;
L_top:
    ISETP.GE.AND P0, PT, R20, 0x8, PT ;
    @P0 BRA L_out ;
    IADD3 R8, PT, PT, R4, R20, RZ ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    LDG.E R4, desc[UR8][R2.64] ;
    ISETP.GE.AND P1, PT, R20, 0x4, PT ;
    @P1 BRA L_side ;
    BRA L_top ;
L_side:
    IADD3 R9, PT, PT, R4, R20, RZ ;
L_out:
    EXIT ;
";

#[test]
fn a_reader_a_path_reaches_without_the_top_keeps_its_wait() {
    let (policy, top) = both(SIDE_EXIT);
    let b = policy.wb("LDG.E R4");
    assert_eq!(policy.word("IADD3 R9").wait, vec![b]);
    let b = top.wb("LDG.E R4");
    assert_eq!(top.word("@P0 BRA").wait, vec![b], "the top takes the reader of the next pass: {:#?}", top.words);
    assert!(top.word("IADD3 R8").wait.is_empty(), "{:#?}", top.words);
    assert_eq!(top.word("IADD3 R9").wait, vec![b], "the reader behind the side exit is reached without the top: {:#?}", top.words);
}

/// The first word of the next pass that names the load's register REWRITES it (`MOV R30, RZ` in front of
/// `@P0 LDG.E.CONSTANT R30` in that loop): the allocator makes it wait as it makes a reader wait.
const REWRITER: &str = "    S2R R2, SR_TID.X ;
    MOV R3, RZ ;
    MOV R20, RZ ;
    MOV R4, R2 ;
L_top:
    ISETP.GE.AND P0, PT, R20, 0x8, PT ;
    @P0 BRA L_out ;
    MOV R4, RZ ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    ISETP.NE.AND P1, PT, R20, 0x3, PT ;
    @P1 LDG.E R4, desc[UR8][R2.64] ;
    BRA L_top ;
L_out:
    IADD3 R8, PT, PT, R4, R20, RZ ;
    EXIT ;
";

#[test]
fn a_rewriter_of_the_pending_register_is_covered_like_a_reader() {
    let (policy, top) = both(REWRITER);
    let b = policy.wb("@P1 LDG.E R4");
    assert_eq!(policy.word("MOV R4, RZ").wait, vec![b], "{:#?}", policy.words);
    let b = top.wb("@P1 LDG.E R4");
    assert_eq!(top.word("@P0 BRA").wait, vec![b], "{:#?}", top.words);
    assert!(top.word("MOV R4, RZ").wait.is_empty(), "the rewriter stands behind the top on every path: {:#?}", top.words);
    assert!(top.word("IADD3 R8").wait.is_empty(), "and so does the reader behind the loop: {:#?}", top.words);
}

/// The first consumer of the next pass is the word of an ordered event (`R2P`: the predicate set as a whole); a
/// plain reader stands behind the loop.
const ORDERED: &str = "    S2R R2, SR_TID.X ;
    MOV R3, RZ ;
    MOV R20, RZ ;
    MOV R4, R2 ;
L_top:
    ISETP.GE.AND P0, PT, R20, 0x8, PT ;
    @P0 BRA L_out ;
    R2P PR, R4, 0x7e ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    LDG.E R4, desc[UR8][R2.64] ;
    BRA L_top ;
L_out:
    IADD3 R9, PT, PT, R4, R20, RZ ;
    EXIT ;
";

#[test]
fn a_reader_that_is_an_ordered_event_keeps_its_wait() {
    let (policy, top) = both(ORDERED);
    let b = policy.wb("LDG.E R4");
    assert_eq!(policy.word("R2P").wait, vec![b]);
    assert_eq!(policy.word("IADD3 R9").wait, vec![b]);
    let b = top.wb("LDG.E R4");
    assert_eq!(top.word("@P0 BRA").wait, vec![b], "the top takes the plain reader: {:#?}", top.words);
    assert!(top.word("IADD3 R9").wait.is_empty(), "{:#?}", top.words);
    assert_eq!(top.word("R2P").wait, vec![b], "no wait comes off the word of an ordered event: {:#?}", top.words);
}

/// A store reads the load of the pass before and latches it late; the word behind it rewrites that register --
/// it waits the store's READ barrier -- and on the path round the store it is the first word that rewrites the
/// load's register: the allocator writes it two waits.
const READ_BARRIER: &str = "    S2R R2, SR_TID.X ;
    MOV R3, RZ ;
    MOV R6, R2 ;
    MOV R7, RZ ;
    MOV R20, RZ ;
    MOV R4, R2 ;
L_top:
    ISETP.GE.AND P0, PT, R20, 0x8, PT ;
    @P0 BRA L_out ;
    ISETP.NE.AND P1, PT, R20, 0x3, PT ;
    @P1 BRA L_skip ;
    STG.E desc[UR8][R6.64], R4 ;
L_skip:
    MOV R4, RZ ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    LDG.E R4, desc[UR8][R2.64] ;
    BRA L_top ;
L_out:
    EXIT ;
";

/// The scoreboard of the read-barrier use whose setter is the word `setter`, off the dump (`USE b=1 rb
/// setters=[10] waiters=[11] ...`), and its waiters as printed.
fn read_barrier_use(b: &Build, setter: usize) -> (u8, String) {
    let line = b
        .lines("USE ")
        .into_iter()
        .find(|l| l.contains(" rb ") && l.contains(&format!("setters=[{setter}]")))
        .unwrap_or_else(|| panic!("no read-barrier use of word {setter}: {}", b.log));
    let sb = line["USE b=".len()..].split(' ').next().unwrap().parse::<u8>().unwrap();
    let waiters = line.split("waiters=").nth(1).unwrap().split(' ').next().unwrap().to_string();
    (sb, waiters)
}

#[test]
fn a_wait_for_a_read_barrier_stays_on_the_rewriter_of_its_source() {
    let (policy, top) = both(READ_BARRIER);
    let (stg, mov) = (policy.at("STG.E"), policy.at("MOV R4, RZ"));
    // the allocator: the store waits the load; the rewriter waits the load AND the store's read barrier
    let (b, r) = (policy.wb("LDG.E R4"), policy.words[stg].rb.expect("the store carries a read barrier"));
    assert_eq!(read_barrier_use(&policy, stg), (r, format!("[{mov}]")));
    assert_eq!(policy.words[stg].wait, vec![b]);
    let mut two = vec![b, r];
    two.sort_unstable();
    assert_eq!(policy.words[mov].wait, two, "{:#?}", policy.words);
    // under the switch the top waits for the load; the store and the rewriter lose THAT wait, and the wait of
    // the store's read barrier stays on the rewriter, on the scoreboard the read-barrier use names
    let (b, r) = (top.wb("LDG.E R4"), top.words[stg].rb.expect("the store carries a read barrier"));
    assert_eq!(top.word("@P0 BRA").wait, vec![b], "{:#?}", top.words);
    assert!(top.words[stg].wait.is_empty(), "{:#?}", top.words);
    assert_eq!(read_barrier_use(&top, stg), (r, format!("[{mov}]")), "the read-barrier use is the allocator's as before");
    assert_eq!(top.words[mov].wait, vec![r], "the rewriter keeps the wait of the store's read barrier: {:#?}", top.words);
    let line = top.lines("TOP ")[0];
    assert!(line.contains(&format!("off=[{stg}, {mov}]")), "the two words lost the wait they had for the load: {line}");
}

/// The word behind the top rewrites the BASE of the load of the pass before: it waits the load's read barrier.
/// The reader stands behind it.
const BASE_REWRITTEN: &str = "    MOV R2, RZ ;
    MOV R3, RZ ;
    MOV R20, RZ ;
    MOV R4, R2 ;
L_top:
    ISETP.GE.AND P0, PT, R20, 0x8, PT ;
    @P0 BRA L_out ;
    IADD3 R2, PT, PT, R2, 0x4, RZ ;
    IADD3 R8, PT, PT, R4, R20, RZ ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    LDG.E R4, desc[UR8][R2.64] ;
    BRA L_top ;
L_out:
    EXIT ;
";

#[test]
fn the_read_barrier_of_a_covered_load_is_waited_where_it_was() {
    let (policy, top) = both(BASE_REWRITTEN);
    let (b, r) = (policy.wb("LDG.E R4"), policy.word("LDG.E R4").rb.expect("the load carries a read barrier"));
    assert_eq!(policy.word("IADD3 R2").wait, vec![r], "{:#?}", policy.words);
    assert_eq!(policy.word("IADD3 R8").wait, vec![b], "{:#?}", policy.words);
    // under the switch the top waits the load's WRITE barrier; the word that rewrites the load's base still
    // waits its READ barrier -- a top is no cover of a read barrier, the load's own neither
    let (b, r) = (top.wb("LDG.E R4"), top.word("LDG.E R4").rb.expect("the load keeps its read barrier"));
    assert_eq!(top.word("@P0 BRA").wait, vec![b], "{:#?}", top.words);
    assert!(top.word("IADD3 R8").wait.is_empty(), "{:#?}", top.words);
    assert_eq!(top.word("IADD3 R2").wait, vec![r], "the rewriter of the base keeps its wait: {:#?}", top.words);
}

/// Six global loads of six address streams, read by the next pass: six long uses, one a scoreboard. The word
/// behind them (`S2UR`, read by the `BRA.DIV` behind it) finds no scoreboard free and shares one with a load
/// in flight -- and the branch waits there behind that load.
const SIX: &str = "    S2R R2, SR_TID.X ;
    MOV R3, RZ ;
    MOV R6, R2 ;
    MOV R7, RZ ;
    MOV R10, R2 ;
    MOV R11, RZ ;
    MOV R12, R2 ;
    MOV R13, RZ ;
    MOV R14, R2 ;
    MOV R15, RZ ;
    MOV R16, R2 ;
    MOV R17, RZ ;
    MOV R20, RZ ;
L_top:
    ISETP.GE.AND P0, PT, R20, 0x8, PT ;
    @P0 BRA L_out ;
    IADD3 R30, PT, PT, R40, R41, RZ ;
    IADD3 R31, PT, PT, R42, R43, RZ ;
    IADD3 R32, PT, PT, R44, R45, RZ ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    LDG.E R40, desc[UR8][R2.64] ;
    LDG.E R41, desc[UR8][R6.64] ;
    LDG.E R42, desc[UR8][R10.64] ;
    LDG.E R43, desc[UR8][R12.64] ;
    LDG.E R44, desc[UR8][R14.64] ;
    LDG.E R45, desc[UR8][R16.64] ;
    S2UR UR4, SR_CgaCtaId ;
    BRA.DIV UR4, L_slow ;
L_back:
    BRA L_top ;
L_out:
    EXIT ;
L_slow:
    BRA L_back ;
";

/// The write barriers of the six loads of [`SIX`], in text order.
fn six_loads(b: &Build) -> Vec<u8> {
    (40..46).map(|r| b.wb(&format!("LDG.E R{r},"))).collect()
}

#[test]
fn the_covered_loads_take_the_scoreboard_no_waiter_of_the_loop_shares() {
    let (policy, top) = both(SIX);
    // the allocator: six scoreboards for the six loads, and the seventh use on one of them
    let mut loads = six_loads(&policy);
    assert!(loads.contains(&policy.wb("S2UR")), "the word behind the loads shares a load's scoreboard: {:#?}", policy.words);
    loads.sort_unstable();
    assert_eq!(loads, vec![0, 1, 2, 3, 4, 5]);
    // under the switch the six wait at the top, on ONE scoreboard, and it is not the one the branch waits on
    let loads = six_loads(&top);
    let b = loads[0];
    assert!(loads.iter().all(|&x| x == b), "the loads that wait at one top take one scoreboard: {:#?}", top.words);
    assert_ne!(b, top.wb("S2UR"), "{:#?}", top.words);
    assert_eq!(top.word("@P0 BRA").wait, vec![b]);
    for reader in ["IADD3 R30", "IADD3 R31", "IADD3 R32"] {
        assert!(top.word(reader).wait.is_empty(), "{reader}: {:#?}", top.words);
    }
    assert_eq!(top.lines("TOP ").len(), 6, "{}", top.log);
}

#[test]
fn a_control_word_keeps_its_bit_and_no_longer_waits_for_the_load() {
    let (policy, top) = both(SIX);
    // the allocator: the branch waits the scoreboard of the word it reads -- and a load flies on it
    let b = policy.wb("S2UR");
    assert_eq!(policy.word("BRA.DIV").wait, vec![b]);
    assert!(six_loads(&policy).contains(&b));
    // under the switch the branch carries the same bit; what moved is the load
    assert_eq!(top.wb("S2UR"), b, "the scoreboard of the word the branch reads does not move: {:#?}", top.words);
    assert_eq!(top.word("BRA.DIV").wait, vec![b], "the control word keeps its bit: {:#?}", top.words);
    assert!(!six_loads(&top).contains(&b), "no load flies on the scoreboard the branch waits on: {:#?}", top.words);
}

/// Two loads of two address streams in one loop, both read by the next pass.
const TWO: &str = "    S2R R2, SR_TID.X ;
    MOV R3, RZ ;
    MOV R6, R2 ;
    MOV R7, RZ ;
    MOV R20, RZ ;
    MOV R4, R2 ;
    MOV R5, R2 ;
L_top:
    ISETP.GE.AND P0, PT, R20, 0x8, PT ;
    @P0 BRA L_out ;
    IADD3 R8, PT, PT, R4, R5, RZ ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    LDG.E R4, desc[UR8][R2.64] ;
    IADD3 R9, PT, PT, R8, R20, RZ ;
    LDG.E R5, desc[UR8][R6.64] ;
    BRA L_top ;
L_out:
    EXIT ;
";

#[test]
fn two_covered_loads_in_flight_on_one_barrier_are_named_by_the_reuse_view() {
    let (policy, top) = both(TWO);
    // the allocator keeps the two streams apart; the verifier names nothing
    assert_ne!(policy.wb("LDG.E R4"), policy.wb("LDG.E R5"));
    assert!(policy.lines("RECYCLE-STALE").is_empty(), "{}", policy.log);
    // under the switch they fly together on one write barrier in front of the one wait at the top -- the
    // vendor's practice at such words, no law -- and `CUBIT_VERIFY` names the pair: the older load, whose
    // barrier the younger sets again
    let b = top.wb("LDG.E R4");
    assert_eq!(top.wb("LDG.E R5"), b, "{:#?}", top.words);
    assert_eq!(top.word("@P0 BRA").wait, vec![b]);
    let named = top.lines("RECYCLE-STALE");
    assert_eq!(named.len(), 1, "{}", top.log);
    let older = top.at("LDG.E R4");
    assert!(named[0].contains(&format!("reads R4 <- var-producer insn[{older}] LDG.E")), "{}", named[0]);
    assert!(top.log.contains("0 unprotected RAW, 0 broken WAR, 1 recycle-stale"), "{}", top.log);
}

/// A loop in a loop; the inner loop has a way out behind the load that does not pass its own top -- a back edge
/// of the outer loop. The reader of the inner loop's next pass stands behind the inner top, the reader in the
/// outer loop's body behind the outer top alone.
const TWO_LOOPS: &str = "    S2R R2, SR_TID.X ;
    MOV R3, RZ ;
    MOV R21, RZ ;
    MOV R4, R2 ;
L_outer:
    ISETP.GE.AND P0, PT, R21, 0x4, PT ;
    @P0 BRA L_out ;
    IADD3 R9, PT, PT, R4, R21, RZ ;
    IADD3 R21, PT, PT, R21, 0x1, RZ ;
    MOV R20, RZ ;
L_inner:
    ISETP.GE.AND P1, PT, R20, 0x8, PT ;
    @P1 BRA L_next ;
    IADD3 R8, PT, PT, R4, R20, RZ ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    LDG.E R4, desc[UR8][R2.64] ;
    ISETP.GE.AND P2, PT, R20, 0x6, PT ;
    @P2 BRA L_outer ;
    BRA L_inner ;
L_next:
    BRA L_outer ;
L_out:
    EXIT ;
";

#[test]
fn a_load_in_two_loops_is_covered_at_both_tops() {
    let (policy, top) = both(TWO_LOOPS);
    let b = policy.wb("LDG.E R4");
    assert_eq!(policy.word("IADD3 R8").wait, vec![b]);
    assert_eq!(policy.word("IADD3 R9").wait, vec![b]);
    let b = top.wb("LDG.E R4");
    assert_eq!(top.word("@P1 BRA").wait, vec![b], "the inner top: {:#?}", top.words);
    assert_eq!(top.word("@P0 BRA").wait, vec![b], "the outer top: {:#?}", top.words);
    assert!(top.word("IADD3 R8").wait.is_empty() && top.word("IADD3 R9").wait.is_empty(), "{:#?}", top.words);
}

/// Straight-line text with a forward branch: two loads, two readers, no loop.
const NO_LOOP: &str = "    S2R R2, SR_TID.X ;
    MOV R3, RZ ;
    MOV R6, R2 ;
    MOV R7, RZ ;
    LDG.E R4, desc[UR8][R2.64] ;
    LDG.E R5, desc[UR8][R6.64] ;
    IADD3 R8, PT, PT, R4, R5, RZ ;
    ISETP.GE.AND P0, PT, R8, 0x8, PT ;
    @P0 BRA L_out ;
    IADD3 R9, PT, PT, R4, R8, RZ ;
L_out:
    EXIT ;
";

/// The switch leaves the text byte for byte, and it names no use.
fn does_not_move(body: &str) -> Build {
    let (policy, top) = both(body);
    assert!(top.lines("TOP ").is_empty(), "{}", top.log);
    assert_eq!(policy.words, top.words);
    assert!(policy.cubin == top.cubin, "the cubins differ");
    top
}

#[test]
fn a_text_without_a_loop_does_not_move() {
    let k = does_not_move(NO_LOOP);
    assert_eq!(k.word("IADD3 R8").wait.len(), 2, "the reader waits both loads: {:#?}", k.words);
}

/// The block of the loop's header holds a load in front of its branch: a wait on that branch would stand right
/// behind it.
const LOAD_IN_THE_HEAD: &str = "    S2R R2, SR_TID.X ;
    MOV R3, RZ ;
    MOV R6, R2 ;
    MOV R7, RZ ;
    MOV R20, RZ ;
    MOV R4, R2 ;
L_top:
    LDG.E R5, desc[UR8][R6.64] ;
    ISETP.GE.AND P0, PT, R20, 0x8, PT ;
    @P0 BRA L_out ;
    IADD3 R8, PT, PT, R4, R5, RZ ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    LDG.E R4, desc[UR8][R2.64] ;
    BRA L_top ;
L_out:
    EXIT ;
";

#[test]
fn a_top_whose_block_holds_a_load_is_no_cover() {
    let k = does_not_move(LOAD_IN_THE_HEAD);
    assert!(k.word("@P0 BRA").wait.is_empty(), "{:#?}", k.words);
    assert_eq!(k.word("IADD3 R8").wait.len(), 2, "the reader waits both loads: {:#?}", k.words);
}

/// A register-indirect branch behind the load: the flow graph reads no jump table, and "every path passes the
/// top" would be a statement about the graph alone.
const DISPATCH: &str = "    S2R R2, SR_TID.X ;
    MOV R3, RZ ;
    MOV R20, RZ ;
    MOV R4, R2 ;
    MOV R22, RZ ;
L_top:
    ISETP.GE.AND P0, PT, R20, 0x8, PT ;
    @P0 BRA L_out ;
    IADD3 R8, PT, PT, R4, R20, RZ ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    LDG.E R4, desc[UR8][R2.64] ;
    BRX R22 -0xb0 ;
    MOV R9, RZ ;
    BRA L_top ;
    MOV R9, R20 ;
    BRA L_top ;
L_out:
    EXIT ;
";

#[test]
fn a_flight_that_crosses_a_dispatch_is_not_covered() {
    let k = does_not_move(DISPATCH);
    assert_eq!(k.word("IADD3 R8").wait, vec![k.wb("LDG.E R4")], "{:#?}", k.words);
    // (the same loop without the dispatch is covered: the first test)
}

/// The load is the author's (a control field in the source): the allocator's pinned use, not the rule's.
const HAND_SCHEDULED: &str = "    MOV R2, RZ ;
    MOV R3, RZ ;
    MOV R20, RZ ;
    MOV R4, R2 ;
L_top:
    ISETP.GE.AND P0, PT, R20, 0x8, PT ;
    @P0 BRA L_out ;
    IADD3 R8, PT, PT, R4, R20, RZ ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    [B------:R-:W3:-:S04] LDG.E R4, desc[UR8][R2.64] ;
    BRA L_top ;
L_out:
    EXIT ;
";

#[test]
fn a_hand_scheduled_load_is_not_touched() {
    let k = does_not_move(HAND_SCHEDULED);
    assert_eq!(k.word("IADD3 R8").wait, vec![3], "{:#?}", k.words);
    assert!(k.word("@P0 BRA").wait.is_empty(), "{:#?}", k.words);
}

#[test]
fn the_switch_alone_changes_nothing() {
    // honoured only with CUBIT_WAIT_POLICY=1 (which is honoured only with CUBIT_SYNC_CLASSES=1)
    for with in [&[][..], &[SYNC][..], &[POLICY][..]] {
        let mut under: Vec<(&str, &str)> = with.to_vec();
        let plain = build(ONE_LOOP, &under);
        under.push(TOP);
        let switched = build(ONE_LOOP, &under);
        assert!(plain.cubin == switched.cubin, "the cubins differ under {under:?}");
        assert!(switched.word("@P0 BRA").wait.is_empty(), "{:#?}", switched.words);
    }
}
