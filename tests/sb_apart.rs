//! `CUBIT_SB_APART=1` (opt-in, 2026-11-20; with `CUBIT_WAIT_POLICY=1`): a write-barrier use shares no scoreboard
//! with a read barrier that is pending over its flight (KNOWN_ISSUES A69; `src/sb_apart.rs`).
//!
//! A scoreboard counts: a word that waits it stands until everything armed on it has come back -- the result it
//! reads and every operand read another word still has pending there. Under `CUBIT_SB_KIND=wide` a read barrier
//! joins the low scoreboards and keeps none of them busy; a short producer behind it (`S2R`, `POPC`, a constant
//! load) takes the same scoreboard and its reader waits behind the operand read. Under the switch:
//!
//! 1. a write-barrier use that has a read-barrier use on its scoreboard whose flight meets its own moves to the
//!    lowest scoreboard on which nothing is in flight over its flight; its setters and its waiters take the new
//!    number together;
//! 2. the clause of `CUBIT_LOAD_TOP` takes no scoreboard on which a read barrier is pending over the flight of the
//!    load.
//!
//! What the rule must not do has a test each: no wait comes off a word (the word of an ordered event among the
//! waiters keeps its wait), no read barrier and no wait of a read barrier moves, no use joins another result in
//! flight or takes the scoreboard of a load that waits at a top, a use stays where no scoreboard is free, a
//! producer under a guard does not move, and nothing moves without the switch, without `CUBIT_WAIT_POLICY=1`
//! or where no use shares.
//!
//! Of these twelve tests eight fail on the allocator without the switch (the variable is then unknown and
//! changes nothing); four are controls -- shapes the switch leaves byte for byte.
//!
//! One more test says the second half of the bits that stay: a reader that is no word of an ordered event keeps
//! its bit on the scoreboard its use leaves where a second use would be armed there beside the pending read
//! barrier of a copy word (it fails without that half; the copy word's test in front of it is its control).

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const SYNC: (&str, &str) = ("CUBIT_SYNC_CLASSES", "1");
const POLICY: (&str, &str) = ("CUBIT_WAIT_POLICY", "1");
const WIDE: (&str, &str) = ("CUBIT_SB_KIND", "wide");
const TOP: (&str, &str) = ("CUBIT_LOAD_TOP", "1");
const APART: (&str, &str) = ("CUBIT_SB_APART", "1");
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
    let dir = std::env::temp_dir().join(format!("sbapart_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, format!(".entry sb_apart_probe\n    .reg R0-R63\n    .param ptr out\n{body}.endentry\n")).unwrap();
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
    fn word(&self, starts: &str) -> &Word {
        self.words.iter().find(|w| w.text.starts_with(starts)).unwrap_or_else(|| panic!("no word `{starts}` in {:#?}", self.words))
    }
    /// The write barrier of the first word that starts so.
    fn wb(&self, starts: &str) -> u8 {
        self.word(starts).wb.unwrap_or_else(|| panic!("`{starts}` carries no write barrier: {:#?}", self.words))
    }
    /// The read barrier of the first word that starts so.
    fn rb(&self, starts: &str) -> u8 {
        self.word(starts).rb.unwrap_or_else(|| panic!("`{starts}` carries no read barrier: {:#?}", self.words))
    }
    /// The lines of the build's log that start so.
    fn lines(&self, starts: &str) -> Vec<&str> {
        self.log.lines().map(str::trim).filter(|l| l.starts_with(starts)).collect()
    }
}

/// The recipe's view of the colouring | the same and the switch.
fn both(body: &str) -> (Build, Build) {
    (build(body, &[SYNC, POLICY, WIDE, DUMP, VERIFY]), build(body, &[SYNC, POLICY, WIDE, APART, DUMP, VERIFY]))
}

/// A shared load whose base a word further on rewrites -- the load carries a read barrier, the rewriter waits
/// it -- and two short producers between them, each read by the word behind it.
const BEHIND_A_LOAD: &str = "    S2R R2, SR_TID.X ;
    MOV R6, R2 ;
    MOV R12, RZ ;
    LDS R5, [R6+0x100] ;
    S2R R8, SR_CTAID.X ;
    IADD3 R9, PT, PT, R8, 0x1, RZ ;
    POPC R11, R9 ;
    IADD3 R13, PT, PT, R11, R12, RZ ;
    IADD3 R6, PT, PT, R6, 0x4, RZ ;
    IADD3 R10, PT, PT, R5, R13, RZ ;
    STG.E desc[UR8][R6.64], R10 ;
    EXIT ;
";

#[test]
fn a_short_producer_leaves_the_scoreboard_on_which_a_read_barrier_is_pending() {
    let (wide, apart) = both(BEHIND_A_LOAD);
    // the colouring: the load's read barrier joined a low scoreboard and keeps it free -- both producers take
    // it, and their readers wait where the operand read is pending
    let r = wide.rb("LDS R5");
    assert_eq!((wide.wb("S2R R8"), wide.wb("POPC R11")), (r, r), "{:#?}", wide.words);
    assert_eq!(wide.word("IADD3 R9,").wait, vec![r]);
    assert_eq!(wide.word("IADD3 R13,").wait, vec![r]);
    // under the switch each takes a scoreboard on which nothing is in flight over its flight: not the read
    // barrier's, and not the one the load's own result flies on
    let (r, load) = (apart.rb("LDS R5"), apart.wb("LDS R5"));
    let (s, p) = (apart.wb("S2R R8"), apart.wb("POPC R11"));
    assert!(s != r && p != r, "no producer shares the scoreboard of the pending read barrier: {:#?}", apart.words);
    assert!(s != load && p != load, "no use joins another result in flight: {:#?}", apart.words);
    // the waiters went with their setters
    assert_eq!(apart.word("IADD3 R9,").wait, vec![s], "{:#?}", apart.words);
    assert_eq!(apart.word("IADD3 R13,").wait, vec![p], "{:#?}", apart.words);
    // the read barrier, its wait and the load's result are where they were
    assert_eq!((r, load), (wide.rb("LDS R5"), wide.wb("LDS R5")), "the load's two barriers do not move");
    assert_eq!(apart.word("IADD3 R6,").wait, vec![r], "the rewriter of the base keeps the wait of the read barrier: {:#?}", apart.words);
    assert_eq!(apart.word("IADD3 R10,").wait, vec![load], "{:#?}", apart.words);
}

/// The same with a constant load behind the shared load.
const CONSTANT: &str = "    S2R R2, SR_TID.X ;
    MOV R6, R2 ;
    LDS R5, [R6+0x100] ;
    LDC R8, c[0x0][0x28] ;
    IADD3 R9, PT, PT, R8, 0x1, RZ ;
    IADD3 R6, PT, PT, R6, 0x4, RZ ;
    IADD3 R10, PT, PT, R5, R9, RZ ;
    STG.E desc[UR8][R6.64], R10 ;
    EXIT ;
";

#[test]
fn a_constant_load_moves_like_any_other_short_producer() {
    let (wide, apart) = both(CONSTANT);
    assert_eq!(wide.wb("LDC R8"), wide.rb("LDS R5"), "{:#?}", wide.words);
    let c = apart.wb("LDC R8");
    assert!(c != apart.rb("LDS R5") && c != apart.wb("LDS R5"), "{:#?}", apart.words);
    assert_eq!(apart.word("IADD3 R9,").wait, vec![c], "{:#?}", apart.words);
    assert_eq!(apart.word("IADD3 R6,").wait, vec![apart.rb("LDS R5")], "{:#?}", apart.words);
}

/// A copy word (`LDGSTS`) whose address register a word further on rewrites: the copy word carries a read
/// barrier and the rewriter waits it. An `S2R` and its reader stand between them.
const BEHIND_A_COPY: &str = "    S2R R2, SR_TID.X ;
    MOV R6, R2 ;
    MOV R7, RZ ;
    MOV R12, RZ ;
    ISETP.NE.AND P3, PT, R2, RZ, PT ;
    LDGSTS.E [R12+0x2000], desc[UR8][R6.64], P3 ;
    S2R R8, SR_CTAID.X ;
    IADD3 R9, PT, PT, R8, 0x1, RZ ;
    IADD3 R6, PT, PT, R6, 0x4, RZ ;
    STG.E desc[UR8][R6.64], R9 ;
    EXIT ;
";

#[test]
fn the_read_barrier_of_a_copy_word_stays_and_the_producer_behind_it_moves() {
    let (wide, apart) = both(BEHIND_A_COPY);
    let r = wide.rb("LDGSTS.E");
    assert_eq!(wide.wb("S2R R8"), r, "{:#?}", wide.words);
    assert_eq!(wide.word("IADD3 R9,").wait, vec![r]);
    assert_eq!(wide.word("IADD3 R6,").wait, vec![r]);
    // under the switch the copy word's read barrier keeps its scoreboard and the rewriter of its address
    // register keeps the wait; the reader of the `S2R` no longer stands behind the copy word's operands
    assert_eq!(apart.rb("LDGSTS.E"), r, "no read barrier is touched: {:#?}", apart.words);
    assert_eq!(apart.word("IADD3 R6,").wait, vec![r], "{:#?}", apart.words);
    let s = apart.wb("S2R R8");
    assert_ne!(s, r, "{:#?}", apart.words);
    assert_eq!(apart.word("IADD3 R9,").wait, vec![s], "{:#?}", apart.words);
}

/// The same with a store behind the reader of the `S2R`: the store's read barrier joins the scoreboard on which
/// the copy word's is pending, in front of the word that waits it.
const A_STORE_BEHIND_THE_READER: &str = "    S2R R2, SR_TID.X ;
    MOV R6, R2 ;
    MOV R7, RZ ;
    MOV R12, RZ ;
    MOV R14, R2 ;
    MOV R15, RZ ;
    ISETP.NE.AND P3, PT, R2, RZ, PT ;
    LDGSTS.E [R12+0x2000], desc[UR8][R6.64], P3 ;
    S2R R8, SR_CTAID.X ;
    IADD3 R9, PT, PT, R8, 0x1, RZ ;
    STG.E desc[UR8][R14.64], R9 ;
    IADD3 R6, PT, PT, R6, 0x4, RZ ;
    IADD3 R9, PT, PT, R9, 0x1, RZ ;
    STG.E desc[UR8][R6.64], R9 ;
    EXIT ;
";

#[test]
fn a_reader_keeps_its_bit_where_a_second_use_is_armed_beside_the_read_barrier_of_a_copy_word() {
    let (wide, apart) = both(A_STORE_BEHIND_THE_READER);
    let (store, reader) = ("STG.E desc[UR8][R14.64]", "IADD3 R9, PT, PT, R8");
    let r = wide.rb("LDGSTS.E");
    assert_eq!((wide.wb("S2R R8"), wide.rb(store)), (r, r), "{:#?}", wide.words);
    assert_eq!(wide.word(reader).wait, vec![r], "the reader releases the copy word's read barrier in front of the store: {:#?}", wide.words);
    // under the switch the `S2R` takes another scoreboard and its reader waits that one -- AND keeps the bit of
    // the scoreboard the use left: the copy word's read barrier is pending on the reader, and the store behind
    // it arms that scoreboard before any word waits it. Without the bit two uses would be in flight there
    // that the schedule without the switch keeps apart, beside a copy word
    let s = apart.wb("S2R R8");
    assert_ne!(s, r, "{:#?}", apart.words);
    assert_eq!((apart.rb("LDGSTS.E"), apart.rb(store)), (r, r), "no read barrier is touched: {:#?}", apart.words);
    assert_eq!(apart.word(reader).wait, if r < s { vec![r, s] } else { vec![s, r] }, "the reader keeps the wait behind the copy word's read barrier: {:#?}", apart.words);
    assert_eq!(apart.lines("BESIDE ").len(), 1, "the dump names the bit: {}", apart.log);
    // (where a word that waits the scoreboard stands in front of the next word that arms it, the reader goes
    // with its number: `the_read_barrier_of_a_copy_word_stays_and_the_producer_behind_it_moves`)
}

/// Six `S2R` in front of one reader -- ONE use, six setters -- and a store whose data register the reader's
/// successor rewrites: the store's read barrier is pending while the six are in flight.
const BATCH: &str = "    S2R R20, SR_TID.X ;
    S2R R21, SR_TID.Y ;
    S2R R22, SR_TID.Z ;
    S2R R23, SR_CTAID.X ;
    S2R R24, SR_CTAID.Y ;
    S2R R25, SR_CTAID.Z ;
    MOV R6, RZ ;
    MOV R7, RZ ;
    MOV R4, RZ ;
    STG.E desc[UR8][R6.64], R4 ;
    IADD3 R30, PT, PT, R20, R21, RZ ;
    IADD3 R31, PT, PT, R22, R23, RZ ;
    IADD3 R32, PT, PT, R24, R25, RZ ;
    IADD3 R4, PT, PT, R30, R31, RZ ;
    STG.E desc[UR8][R6.64+0x8], R32 ;
    EXIT ;
";

#[test]
fn a_use_of_several_setters_moves_as_one() {
    let (wide, apart) = both(BATCH);
    let six = |b: &Build| -> Vec<u8> { (20..26).map(|r| b.wb(&format!("S2R R{r},"))).collect() };
    let r = wide.rb("STG.E desc[UR8][R6.64], R4");
    assert_eq!(six(&wide), vec![r; 6], "{:#?}", wide.words);
    assert_eq!(wide.word("IADD3 R30,").wait, vec![r]);
    let moved = six(&apart);
    assert!(moved.iter().all(|&b| b == moved[0] && b != r), "the six setters take one new scoreboard: {:#?}", apart.words);
    assert_eq!(apart.word("IADD3 R30,").wait, vec![moved[0]], "{:#?}", apart.words);
    assert_eq!(apart.rb("STG.E desc[UR8][R6.64], R4"), r);
    assert_eq!(apart.word("IADD3 R4,").wait, vec![r], "the rewriter of the store's data register keeps its wait: {:#?}", apart.words);
}

/// The reader of the short producer is a word of an ordered event.
const ORDERED: &str = "    S2R R2, SR_TID.X ;
    MOV R6, R2 ;
    MOV R12, RZ ;
    LDS R5, [R6+0x100] ;
    S2R R8, SR_CTAID.X ;
    R2P PR, R8, 0x7e ;
    IADD3 R6, PT, PT, R6, 0x4, RZ ;
    IADD3 R10, PT, PT, R5, R12, RZ ;
    STG.E desc[UR8][R6.64], R10 ;
    EXIT ;
";

#[test]
fn a_waiter_that_is_an_ordered_event_keeps_its_bit_on_the_scoreboard_its_use_leaves() {
    let (wide, apart) = both(ORDERED);
    let r = wide.rb("LDS R5");
    assert_eq!(wide.wb("S2R R8"), r, "{:#?}", wide.words);
    assert_eq!(wide.word("R2P").wait, vec![r]);
    // the setter moves and the event word waits it under the new number -- AND keeps the bit of the scoreboard
    // the use left: the load's read barrier keeps that number and is pending on the word, the one bit was a
    // wait on it too, and a wait whose number changes while its setter does not is a wait taken off
    let s = apart.wb("S2R R8");
    assert_eq!(apart.rb("LDS R5"), r, "{:#?}", apart.words);
    assert_ne!(s, r, "{:#?}", apart.words);
    assert_eq!(apart.word("R2P").wait, if r < s { vec![r, s] } else { vec![s, r] }, "no wait comes off the word of an ordered event: {:#?}", apart.words);
    assert_eq!(apart.lines("KEPT ").len(), 1, "the dump names the bit that stays: {}", apart.log);
    // no word waits on fewer scoreboards than before
    let bits = |b: &Build| -> Vec<usize> { b.words.iter().map(|w| w.wait.len()).collect() };
    assert!(bits(&apart).iter().zip(bits(&wide)).all(|(a, w)| *a >= w), "{:#?}", apart.words);
}

/// Six results in flight over a store's pending read barrier, one a scoreboard.
const FULL: &str = "    POPC R20, R2 ;
    POPC R21, R3 ;
    POPC R22, R4 ;
    POPC R23, R5 ;
    POPC R24, R6 ;
    POPC R25, R7 ;
    STG.E desc[UR8][R8.64], R10 ;
    IADD3 R30, PT, PT, R20, R21, RZ ;
    IADD3 R31, PT, PT, R22, R23, RZ ;
    IADD3 R32, PT, PT, R24, R25, RZ ;
    IADD3 R10, PT, PT, R30, R31, RZ ;
    STG.E desc[UR8][R8.64+0x8], R32 ;
    EXIT ;
";

#[test]
fn a_use_stays_where_no_scoreboard_is_free() {
    // (a control: the shape builds byte for byte with and without the switch)
    let (wide, apart) = both(FULL);
    let r = wide.rb("STG.E desc[UR8][R8.64], R10");
    assert_eq!(wide.wb("POPC R20"), r, "one result shares the scoreboard of the store's read barrier: {:#?}", wide.words);
    let mut six: Vec<u8> = (20..26).map(|x| wide.wb(&format!("POPC R{x},"))).collect();
    six.sort_unstable();
    assert_eq!(six, vec![0, 1, 2, 3, 4, 5], "a result in flight on every scoreboard: {:#?}", wide.words);
    assert_eq!(apart.cubin, wide.cubin, "no scoreboard is free over the flight: the use stays, {:#?}", apart.words);
}

#[test]
fn the_dump_names_every_use_that_shares_and_where_it_goes() {
    let (wide, apart) = both(BEHIND_A_LOAD);
    assert!(wide.lines("APART ").is_empty(), "no line without the switch: {}", wide.log);
    let lines = apart.lines("APART ");
    assert_eq!(lines.len(), 2, "one line a use that shares: {}", apart.log);
    let (r, s) = (apart.rb("LDS R5"), apart.wb("S2R R8"));
    assert!(lines[0].starts_with(&format!("APART b={r}->{s} setters=[4] waiters=[5] beside=[3] ")), "{}", lines[0]);
    // a use that finds no scoreboard free is named too, with what bars each scoreboard
    let (_, full) = both(FULL);
    let lines = full.lines("APART ");
    assert_eq!(lines.len(), 1, "{}", full.log);
    assert!(lines[0].contains("(no scoreboard free) setters=[0] waiters=[7] beside=[6] bars=[= r0w1h0 r0w1h0 r0w1h0 r0w1h0 r0w1h0]"), "{}", lines[0]);
}

/// A loop whose load the next pass reads, and a store in the loop whose data register the word behind the
/// loop's top rewrites: the store's read barrier is pending over the load's flight. Under `CUBIT_LOAD_TOP` the
/// load waits at the top and takes the lowest scoreboard on which no word of the loop holds -- the one the read
/// barrier joined.
const TOPPED: &str = "    S2R R2, SR_TID.X ;
    MOV R3, RZ ;
    MOV R6, R2 ;
    MOV R7, RZ ;
    MOV R9, RZ ;
    MOV R20, RZ ;
    MOV R4, R2 ;
L_top:
    ISETP.GE.AND P0, PT, R20, 0x8, PT ;
    @P0 BRA L_out ;
    IADD3 R9, PT, PT, R4, R20, RZ ;
    STG.E desc[UR8][R6.64], R9 ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    LDG.E R4, desc[UR8][R2.64] ;
    BRA L_top ;
L_out:
    EXIT ;
";

#[test]
fn a_load_that_waits_at_a_top_takes_no_scoreboard_of_a_pending_read_barrier() {
    let top = build(TOPPED, &[SYNC, POLICY, WIDE, TOP, DUMP, VERIFY]);
    let apart = build(TOPPED, &[SYNC, POLICY, WIDE, TOP, APART, DUMP, VERIFY]);
    // the clause of the loads alone: the load arms the scoreboard on which the store's read barrier is pending
    let r = top.rb("STG.E");
    assert_eq!(top.wb("LDG.E R4"), r, "{:#?}", top.words);
    assert_eq!(top.word("@P0 BRA").wait, vec![r]);
    // under the switch that scoreboard is barred for the load; the top waits the load where it went AND keeps
    // the bit of the scoreboard the load no longer takes -- the store's read barrier is pending on the top, and
    // the top is the word of an ordered event --, and the rewriter of the store's data register keeps the wait
    // of the read barrier
    let b = apart.wb("LDG.E R4");
    assert_eq!(apart.rb("STG.E"), r, "{:#?}", apart.words);
    assert_ne!(b, r, "the load takes no scoreboard on which a read barrier is pending over its flight: {:#?}", apart.words);
    assert_eq!(apart.word("@P0 BRA").wait, if r < b { vec![r, b] } else { vec![b, r] }, "{:#?}", apart.words);
    assert_eq!(apart.lines("KEPT ").len(), 1, "the bit that stays: {}", apart.log);
    assert_eq!(apart.word("IADD3 R9,").wait, vec![r], "{:#?}", apart.words);
    assert_eq!(apart.lines("TOP ").len(), 1, "the load is the clause's: {}", apart.log);
    assert!(apart.lines("APART ").is_empty(), "and no use of the other clause: {}", apart.log);
}

/// [`TOPPED`] with a short producer and its reader in the loop, behind the store: the producer takes the
/// scoreboard the store's read barrier joined. The load's flight does not reach these two words.
const TOPPED_AND_A_PRODUCER: &str = "    S2R R2, SR_TID.X ;
    MOV R3, RZ ;
    MOV R6, R2 ;
    MOV R7, RZ ;
    MOV R9, RZ ;
    MOV R20, RZ ;
    MOV R4, R2 ;
L_top:
    ISETP.GE.AND P0, PT, R20, 0x8, PT ;
    @P0 BRA L_out ;
    IADD3 R9, PT, PT, R4, R20, RZ ;
    STG.E desc[UR8][R6.64], R9 ;
    S2R R30, SR_CTAID.X ;
    IADD3 R31, PT, PT, R30, 0x1, RZ ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    LDG.E R4, desc[UR8][R2.64] ;
    BRA L_top ;
L_out:
    EXIT ;
";

#[test]
fn no_use_takes_the_scoreboard_of_a_load_that_waits_at_a_top() {
    let top = build(TOPPED_AND_A_PRODUCER, &[SYNC, POLICY, WIDE, TOP, DUMP, VERIFY]);
    let apart = build(TOPPED_AND_A_PRODUCER, &[SYNC, POLICY, WIDE, TOP, APART, DUMP, VERIFY]);
    let r = top.rb("STG.E");
    assert_eq!(top.wb("S2R R30"), r, "{:#?}", top.words);
    // under the switch the load leaves the read barrier's scoreboard by its own clause, the producer by this
    // one -- and not onto the load's, though the load is not in flight where the producer is
    let (load, s) = (apart.wb("LDG.E R4"), apart.wb("S2R R30"));
    assert_eq!(apart.rb("STG.E"), r, "{:#?}", apart.words);
    assert!(load != r && s != r, "{:#?}", apart.words);
    assert_ne!(s, load, "the scoreboard of the load at the top is the tops' alone: {:#?}", apart.words);
    assert_eq!(apart.word("IADD3 R31,").wait, vec![s], "a reader that is no event word goes with its number: {:#?}", apart.words);
    assert_eq!(apart.word("@P0 BRA").wait, if r < load { vec![r, load] } else { vec![load, r] }, "the top keeps the bit of the read barrier's scoreboard: {:#?}", apart.words);
    let line = apart.lines("APART ");
    assert_eq!(line.len(), 1, "{}", apart.log);
    assert!(line[0].contains(" t "), "the load's scoreboard is named as barred: {}", line[0]);
}

/// [`CONSTANT`] with the constant load under a guard.
const GUARDED: &str = "    S2R R2, SR_TID.X ;
    MOV R6, R2 ;
    MOV R8, RZ ;
    ISETP.NE.AND P0, PT, R2, RZ, PT ;
    LDS R5, [R6+0x100] ;
    @P0 LDC R8, c[0x0][0x28] ;
    IADD3 R9, PT, PT, R8, 0x1, RZ ;
    IADD3 R6, PT, PT, R6, 0x4, RZ ;
    IADD3 R10, PT, PT, R5, R9, RZ ;
    STG.E desc[UR8][R6.64], R10 ;
    EXIT ;
";

#[test]
fn a_producer_under_a_guard_does_not_move() {
    // (a control) the wait of a guarded producer may be written on a later reader behind the colouring: its
    // flight is not all the colouring knows, and the rule leaves it where it is
    let (wide, apart) = both(GUARDED);
    assert_eq!(wide.wb("@P0 LDC R8"), wide.rb("LDS R5"), "the guarded producer shares the read barrier's scoreboard: {:#?}", wide.words);
    assert_eq!(apart.cubin, wide.cubin, "{:#?}", apart.words);
    assert!(apart.lines("APART ").is_empty(), "{}", apart.log);
}

#[test]
fn nothing_moves_where_no_use_shares() {
    // (a control) without `CUBIT_SB_KIND=wide` a read barrier keeps its scoreboard busy: no producer takes it
    for body in [BEHIND_A_LOAD, CONSTANT, BEHIND_A_COPY, ORDERED] {
        let plain = build(body, &[SYNC, POLICY, DUMP, VERIFY]);
        let apart = build(body, &[SYNC, POLICY, APART, DUMP, VERIFY]);
        assert_eq!(apart.cubin, plain.cubin, "{:#?}", apart.words);
        assert!(apart.lines("APART ").is_empty(), "{}", apart.log);
    }
}

#[test]
fn the_switch_alone_changes_nothing() {
    // (a control) the variable is honoured only together with `CUBIT_WAIT_POLICY=1`
    for body in [BEHIND_A_LOAD, BATCH, TOPPED] {
        assert_eq!(build(body, &[APART]).cubin, build(body, &[]).cubin);
        assert_eq!(build(body, &[SYNC, WIDE, APART]).cubin, build(body, &[SYNC, WIDE]).cubin);
        assert_eq!(build(body, &[SYNC, WIDE, TOP, APART]).cubin, build(body, &[SYNC, WIDE, TOP]).cubin);
    }
}
