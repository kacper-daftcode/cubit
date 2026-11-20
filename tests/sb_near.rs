//! `CUBIT_SB_NEAR=1` (opt-in, default off; honoured where `CUBIT_SB_APART` is: with `CUBIT_WAIT_POLICY=1` and
//! the flow graph of `CUBIT_SYNC_CLASSES`): in a loop that holds a copy word, no word waits for a use it does
//! not need when that use was armed a few words in front of it.
//!
//! The clause of these tests is the NEAR RESULT: the result of a constant load or of a register read (`LDC`,
//! `LDCU`, `S2R`, `S2UR`) whose scoreboard the next waiting word waits for ANOTHER use -- the rewriter of a
//! load's address register, the reader of another load of its batch -- at most eight words behind it. The
//! word blocks until the near result has landed although it reads nothing of it. Under the switch the result
//! takes the lowest scoreboard that is empty over its flight by the fields of the schedule (nothing pending
//! there on any path, nothing armed there, no word that waits it but the result's own readers), a load leaves
//! its batch as a use of its own, the wait of the new number goes on its first reader on every path, and no
//! wait bit of the schedule without the switch comes off.
//!
//! Every text is a kernel WITHOUT control codes; `cubit asm` schedules it and `cubit disassemble --frozen`
//! gives the words back with the fields the allocator wrote.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const SYNC: (&str, &str) = ("CUBIT_SYNC_CLASSES", "1");
const POLICY: (&str, &str) = ("CUBIT_WAIT_POLICY", "1");
const WIDE: (&str, &str) = ("CUBIT_SB_KIND", "wide");
const DRAINED: (&str, &str) = ("CUBIT_WAIT_DRAINED", "paths");
const NEAR: (&str, &str) = ("CUBIT_SB_NEAR", "1");

/// One instruction of the schedule cubit wrote: (wait bits, read barrier, write barrier, the word).
#[derive(Debug, Clone, PartialEq)]
struct Word {
    wait: Vec<u8>,
    rb: Option<u8>,
    wb: Option<u8>,
    text: String,
}

/// A build: the words with the control fields the allocator gave them, and the cubin's bytes.
struct Build {
    words: Vec<Word>,
    cubin: Vec<u8>,
}

/// `cubit asm` of an unscheduled kernel under `env`, then `cubit disassemble --frozen`.
fn build(body: &str, env: &[(&str, &str)]) -> Build {
    let dir = std::env::temp_dir().join(format!("sbnear_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, format!(".entry sb_near_probe\n    .reg R0-R63\n    .param ptr out\n{body}.endentry\n")).unwrap();
    let run = |args: &[&str], env: &[(&str, &str)]| {
        let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
        let log = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert!(o.status.success(), "{args:?} under {env:?}: {log}");
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    run(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()], env);
    let listing = run(&["disassemble", "--frozen", out.to_str().unwrap(), "-t", TABLE], &[]);
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
    Build { words, cubin }
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
}

/// The recipe without the switch | the same and the switch.
fn both(body: &str) -> (Build, Build) {
    (build(body, &[SYNC, POLICY, WIDE, DRAINED]), build(body, &[SYNC, POLICY, WIDE, DRAINED, NEAR]))
}

/// The words whose fields differ between two builds of one text, by their text.
fn moved<'a>(a: &'a Build, b: &Build) -> Vec<&'a str> {
    assert_eq!(a.words.len(), b.words.len());
    a.words.iter().zip(&b.words).filter(|(x, y)| x != y).map(|(x, _)| x.text.as_str()).collect()
}

/// A loop that holds a copy word. In it a shared load whose base the word behind the next rewrites -- the load
/// carries a read barrier and the rewriter waits it -- and, between the two, a register read: its result is
/// armed one word in front of the rewriter, on the scoreboard the rewriter waits, and its own reader stands
/// behind the rewriter.
const A_RESULT_IN_FRONT_OF_A_REWRITER: &str = "    S2R R2, SR_TID.X ;
    MOV R6, R2 ;
    MOV R7, RZ ;
    MOV R12, RZ ;
    MOV R16, R2 ;
    MOV R20, RZ ;
L_top:
    ISETP.GE.AND P0, PT, R20, 0x8, PT ;
    @P0 BRA L_out ;
    ISETP.NE.AND P3, PT, R2, RZ, PT ;
    LDGSTS.E [R12+0x2000], desc[UR8][R6.64], P3 ;
    LDS R5, [R16+0x100] ;
    S2R R8, SR_CTAID.X ;
    IADD3 R16, PT, PT, R16, 0x4, RZ ;
    IADD3 R9, PT, PT, R8, 0x1, RZ ;
    IADD3 R10, PT, PT, R5, R9, RZ ;
    IADD3 R6, PT, PT, R6, 0x4, RZ ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    BRA L_top ;
L_out:
    STG.E desc[UR8][R6.64], R10 ;
    EXIT ;
";

#[test]
fn a_near_result_leaves_the_scoreboard_on_which_the_next_word_waits_another_use() {
    let (base, near) = both(A_RESULT_IN_FRONT_OF_A_REWRITER);
    // without the switch: the register read stands on the scoreboard of the load's read barrier, the rewriter
    // of the load's base waits that scoreboard one word behind it, and the result's own reader carries no bit
    // (the rewriter's wait stands in front of it on every path)
    let r = base.rb("LDS R5");
    assert_eq!(base.wb("S2R R8"), r, "{:#?}", base.words);
    assert_eq!(base.word("IADD3 R16,").wait, vec![r], "{:#?}", base.words);
    assert!(base.word("IADD3 R9,").wait.is_empty(), "{:#?}", base.words);
    // under the switch the result takes a scoreboard on which nothing else stands over its flight ...
    let s = near.wb("S2R R8");
    assert!(s != r && s != near.wb("LDS R5") && s != near.rb("LDGSTS.E"), "the result stands alone: {:#?}", near.words);
    // ... its reader waits it, and the rewriter keeps the wait of the load's read barrier
    assert_eq!(near.word("IADD3 R9,").wait, vec![s], "{:#?}", near.words);
    assert_eq!(near.word("IADD3 R16,").wait, vec![r], "{:#?}", near.words);
    // nothing else moves: the load's two barriers, the copy word's read barrier, every other wait
    assert_eq!(moved(&base, &near), vec!["S2R R8, SR_CTAID.X", "IADD3 R9, PT, PT, R8, 0x1, RZ"], "{:#?}", near.words);
}

/// A loop that holds a copy word. In it two constant loads of one form -- ONE batch on one write barrier --,
/// the reader of the first three words behind the second, the reader of the second three words further on.
const A_BATCH_WITH_TWO_READERS: &str = "    S2R R2, SR_TID.X ;
    MOV R6, R2 ;
    MOV R7, RZ ;
    MOV R12, RZ ;
    MOV R20, RZ ;
    MOV R30, R2 ;
    MOV R31, RZ ;
    MOV R32, R2 ;
    MOV R33, RZ ;
L_top:
    ISETP.GE.AND P0, PT, R20, 0x8, PT ;
    @P0 BRA L_out ;
    ISETP.NE.AND P3, PT, R2, RZ, PT ;
    LDGSTS.E [R12+0x2000], desc[UR8][R6.64], P3 ;
    LDCU.64 UR4, c[0x0][0x380] ;
    MOV R40, R2 ;
    LDCU.64 UR6, c[0x0][0x388] ;
    MOV R41, R2 ;
    IADD.64 R30, R30, UR4 ;
    MOV R42, R2 ;
    MOV R43, R2 ;
    IADD.64 R32, R32, UR6 ;
    IADD3 R6, PT, PT, R6, 0x4, RZ ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    BRA L_top ;
L_out:
    STG.E desc[UR8][R6.64], R30 ;
    STG.E desc[UR8][R6.64+0x8], R32 ;
    EXIT ;
";

#[test]
fn a_constant_load_leaves_its_batch_where_the_first_reader_of_the_batch_reads_nothing_of_it() {
    let (base, near) = both(A_BATCH_WITH_TWO_READERS);
    // without the switch: both loads on one write barrier, the reader of the first waits it -- and with it the
    // second load, armed two words in front of it --, the reader of the second carries no bit
    let b = base.wb("LDCU.64 UR4");
    assert_eq!(base.wb("LDCU.64 UR6"), b, "{:#?}", base.words);
    assert_eq!(base.word("IADD.64 R30,").wait, vec![b], "{:#?}", base.words);
    assert!(base.word("IADD.64 R32,").wait.is_empty(), "{:#?}", base.words);
    // under the switch the second load is a use of its own on another scoreboard and ITS reader waits it; the
    // first load and its reader stay as they are
    let c = near.wb("LDCU.64 UR6");
    assert!(c != b && c != near.rb("LDGSTS.E"), "the second load stands alone: {:#?}", near.words);
    assert_eq!(near.wb("LDCU.64 UR4"), b, "{:#?}", near.words);
    assert_eq!(near.word("IADD.64 R30,").wait, vec![b], "{:#?}", near.words);
    assert_eq!(near.word("IADD.64 R32,").wait, vec![c], "{:#?}", near.words);
    assert_eq!(moved(&base, &near), vec!["LDCU.64 UR6, c[0x0][0x388]", "IADD.64 R32, R32, UR6"], "{:#?}", near.words);
}

#[test]
fn the_reader_waits_the_new_number_and_no_wait_bit_comes_off() {
    for body in [A_RESULT_IN_FRONT_OF_A_REWRITER, A_BATCH_WITH_TWO_READERS] {
        let (base, near) = both(body);
        let mut on = 0;
        for (x, y) in base.words.iter().zip(&near.words) {
            assert!(x.wait.iter().all(|b| y.wait.contains(b)), "a wait bit came off `{}`: {:?} -> {:?}", x.text, x.wait, y.wait);
            on += y.wait.len() - x.wait.len();
        }
        assert_eq!(on, 1, "one wait bit is put on -- the reader's: {:#?}", near.words);
        assert_ne!(base.cubin, near.cubin);
    }
}

/// The first text without its copy word: the loop holds none.
#[test]
fn outside_a_loop_that_holds_a_copy_word_nothing_moves() {
    let body = A_RESULT_IN_FRONT_OF_A_REWRITER.replace("    LDGSTS.E [R12+0x2000], desc[UR8][R6.64], P3 ;\n", "");
    let (base, near) = both(&body);
    assert_eq!(base.wb("S2R R8"), base.rb("LDS R5"), "the same pair stands in the text: {:#?}", base.words);
    assert_eq!(base.cubin, near.cubin, "{:#?}", near.words);
}

#[test]
fn the_switch_alone_changes_nothing() {
    // without `CUBIT_WAIT_POLICY=1` and the flow graph the switch is not honoured
    for body in [A_RESULT_IN_FRONT_OF_A_REWRITER, A_BATCH_WITH_TWO_READERS] {
        assert_eq!(build(body, &[]).cubin, build(body, &[NEAR]).cubin);
        assert_eq!(build(body, &[SYNC]).cubin, build(body, &[SYNC, NEAR]).cubin);
    }
}
