//! `CUBIT_YIELD_HOLD_FRAME=1` (opt-in, 2026-11-18; honoured only with `CUBIT_YIELD_HOLD=<n>n`): in the nests the
//! rule of `CUBIT_YIELD_HOLD` takes the yield flag also off a word that came in with its own control word — the
//! FRAME of a text that is scheduled in part (`scheduling_pass::yield_hold_frame`).
//!
//! The record text of the served FC2 is such a text: the vendor's control words on every word outside the stage
//! loop, cubit's schedule of that loop. Every word of its nest is the frame's, so the nests' clause alone finds
//! no word there (a hand-scheduled word is not touched). Under the pair of switches a framed word of the rule's
//! kind — the flag at a stall of 1 ..= n, no barrier set, no `.reuse` operand, an opcode of the list — gives the
//! flag up where it stands in a nest; no stall, wait or barrier moves, nothing outside the nests, and a text
//! that is all frame is not touched.
//!
//! The first two tests fail on the scheduler without the switch (the variable is then unknown and changes
//! nothing); the last two are their controls.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const ISA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
/// The recipe of the record text: the lowering pass on the dependency-aware scheduler with the sm_120 table,
/// the wait policy and the vendor's form of a shared load.
const RECIPE: &[(&str, &str)] = &[
    ("CUBIT_SYNC_CLASSES", "1"),
    ("CUBIT_SCHED2", "1"),
    ("CUBIT_MMA_PTXAS", "1"),
    ("CUBIT_SCHED2_LAT", "sm120"),
    ("CUBIT_SCHED2_MEMSTALL", "table"),
    ("CUBIT_SCHED2_LOWER", "1"),
    ("CUBIT_WAIT_POLICY", "1"),
    ("CUBIT_LOAD_COVER", "1"),
];
const CLAUSE: (&str, &str) = ("CUBIT_YIELD_HOLD", "2n");
const FRAME: (&str, &str) = ("CUBIT_YIELD_HOLD_FRAME", "1");
/// The opcodes of the rule (`scheduling_pass::HOLD_OPCODES`).
const HOLD: &[&str] = &[
    "CS2R", "ELECT", "F2FP", "FADD", "FFMA", "FMNMX", "FMUL", "FSEL", "FSETP", "HADD2", "HFMA2", "HMUL2", "IABS", "IADD", "IADD3", "IMAD", "ISETP", "LEA", "LOP3", "MOV",
    "NOP", "PLOP3", "PRMT", "R2UR", "SEL", "SGXT", "SHF", "UFLO", "UFMUL", "UIADD3", "UIMAD", "UISETP", "ULEA", "ULOP3", "UMOV", "UPLOP3", "USEL", "USHF", "UVIMNMX",
    "VIMNMX", "VOTEU",
];

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

fn recipe<'a>(more: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut v = RECIPE.to_vec();
    v.extend_from_slice(more);
    v
}

/// One instruction line of a frozen listing.
#[derive(Debug, Clone, PartialEq)]
struct Word {
    wait: String,
    rb: String,
    wb: String,
    flag: bool,
    stall: u32,
    text: String,
}

impl Word {
    fn opcode(&self) -> &str {
        let t = if self.text.starts_with('@') { self.text.split_once(' ').map_or("", |x| x.1) } else { self.text.as_str() };
        t.split([' ', '.']).next().unwrap_or("")
    }
    /// The rule's word apart from its place: the flag at a stall of 1 ..= n, no barrier, no `.reuse`, an opcode of the list.
    fn qualifies(&self, n: u32) -> bool {
        self.flag && (1..=n).contains(&self.stall) && self.rb == "-" && self.wb == "-" && !self.text.contains(".reuse") && HOLD.contains(&self.opcode())
    }
    fn code(&self) -> String {
        format!("[B{}:R{}:W{}:{}:S{:02}]", self.wait, self.rb, self.wb, if self.flag { "Y" } else { "-" }, self.stall)
    }
}

fn words(frozen: &str) -> Vec<Word> {
    frozen
        .lines()
        .filter_map(|l| {
            // a label stands in front of its word on the same line
            let t = &l[l.find("[B")?..];
            let close = t.find(']')?;
            let f: Vec<&str> = t[2..close].split(':').collect();
            (f.len() == 5 && f[4].starts_with('S')).then(|| Word {
                wait: f[0].to_string(),
                rb: f[1][1..].to_string(),
                wb: f[2][1..].to_string(),
                flag: f[3] == "Y",
                stall: f[4][1..].parse().unwrap(),
                text: t[close + 1..].trim().trim_end_matches(';').trim().to_string(),
            })
        })
        .collect()
}

/// The schedule `cubit asm` builds from `text` under `env` and the log of the build.
fn build(text: &str, env: &[(&str, &str)]) -> (Vec<Word>, String) {
    let dir = std::env::temp_dir().join(format!("yieldframe_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, text).unwrap();
    let (ok, log) = cubit(&["asm", "-t", ISA, src.to_str().unwrap(), "-o", out.to_str().unwrap()], env);
    assert!(ok, "asm {env:?} failed:\n{log}\n{text}");
    let (ok, frozen) = cubit(&["disassemble", "-t", ISA, "--frozen", out.to_str().unwrap()], &[]);
    assert!(ok, "disassemble failed: {frozen}");
    let _ = std::fs::remove_dir_all(&dir);
    let w = words(&frozen);
    assert!(!w.is_empty(), "no instruction lines in:\n{frozen}");
    (w, log)
}

/// A nest in front of a stage loop that holds a tensor loop, sums and a store behind them (the kernel of
/// `tests/yield_hold.rs`).
const KERNEL: &str = "\
.entry yield_hold_frame
    .reg R0-R31
    .param ptr out
    LDCU.64 UR8, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    LDC R4, c[0x0][0x388] ;
    LDC R5, c[0x0][0x38c] ;
    MOV R6, R4 ;
    IADD3 R7, PT, PT, R6, 0x40, RZ ;
    MOV R21, RZ ;
    MOV R18, RZ ;
    MOV R19, RZ ;
L_nest:
    IADD3 R18, PT, PT, R18, 0x3, RZ ;
    MOV R28, R5 ;
    MOV R29, R4 ;
    MOV R30, R5 ;
    MOV R23, R18 ;
    IADD3 R21, PT, PT, R21, 0x1, RZ ;
    ISETP.NE.AND P1, PT, R21, 0x4, PT ;
    @P1 BRA L_nest ;
    LOP3.LUT R8, R7, R23, RZ, 0x3c, !PT ;
    MOV R24, RZ ;
    MOV R25, RZ ;
    MOV R26, RZ ;
    MOV R27, RZ ;
    MOV R22, RZ ;
L_stage:
    MOV R9, R8 ;
    MOV R10, R5 ;
    MOV R20, RZ ;
L_top:
    MOV R12, R9 ;
    MOV R13, R9 ;
    MOV R14, R9 ;
    MOV R15, R9 ;
    MOV R16, R10 ;
    MOV R17, R10 ;
    HMMA.16816.F32 R24, R12, R16, R24 ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    ISETP.NE.AND P0, PT, R20, 0x4, PT ;
    @P0 BRA L_top ;
    IADD3 R22, PT, PT, R22, 0x1, RZ ;
    ISETP.NE.AND P2, PT, R22, 0x2, PT ;
    @P2 BRA L_stage ;
    FADD R9, R24, R25 ;
    FADD R10, R26, R27 ;
    FADD R9, R9, R10 ;
    STG.E desc[UR8][R2.64], R9 ;
    EXIT ;
.endentry
";

fn is_word(line: &str) -> bool {
    let t = line.trim();
    !t.is_empty() && !t.starts_with('.') && !t.ends_with(':')
}

/// The number of the instruction of `KERNEL` whose line is `line`.
fn at(line: &str) -> usize {
    KERNEL.lines().filter(|l| is_word(l)).position(|l| l.trim() == line).unwrap_or_else(|| panic!("no line `{line}`"))
}

/// `KERNEL` with the control word of `sched` in front of every word but the `free` ones — a frame around what
/// cubit is to schedule. A branch keeps its line (its label), every other framed word the text of the listing.
fn framed(sched: &[Word], free: &dyn Fn(usize) -> bool) -> String {
    let mut out = String::new();
    let mut i = 0;
    for line in KERNEL.lines() {
        if !is_word(line) {
            out.push_str(line);
        } else {
            let w = &sched[i];
            if free(i) {
                out.push_str(line);
            } else if w.opcode() == "BRA" {
                out.push_str(&format!("    {} {}", w.code(), line.trim()));
            } else {
                out.push_str(&format!("    {} {} ;", w.code(), w.text));
            }
            i += 1;
        }
        out.push('\n');
    }
    assert_eq!(i, sched.len(), "one control word a line");
    out
}

/// cubit's own schedule of the kernel (the frame's control words) and the three loops by their words.
#[allow(clippy::type_complexity)]
fn own() -> (Vec<Word>, std::ops::RangeInclusive<usize>, std::ops::RangeInclusive<usize>, std::ops::RangeInclusive<usize>) {
    let (sched, _) = build(KERNEL, &recipe(&[]));
    let nest = at("IADD3 R18, PT, PT, R18, 0x3, RZ ;")..=at("@P1 BRA L_nest ;");
    let stage = at("MOV R9, R8 ;")..=at("@P2 BRA L_stage ;");
    let tensor = at("MOV R12, R9 ;")..=at("@P0 BRA L_top ;");
    assert!(sched[*tensor.start()..=*tensor.end()].iter().any(|w| w.opcode() == "HMMA"), "{sched:?}");
    (sched, nest, stage, tensor)
}

/// `pair` is `base` with the flag off exactly the words of `nest` that are of the rule's kind.
fn only_the_nest_gave_the_flag_up(base: &[Word], pair: &[Word], nest: &std::ops::RangeInclusive<usize>) -> usize {
    assert_eq!(base.len(), pair.len());
    let mut gave = 0;
    for i in 0..base.len() {
        let mut want = base[i].clone();
        if nest.contains(&i) && base[i].qualifies(2) {
            want.flag = false;
            gave += 1;
        }
        assert_eq!(pair[i], want, "word {i}:\nbase {base:#?}\npair {pair:#?}");
    }
    gave
}

#[test]
fn a_framed_nest_word_gives_up_the_flag_under_the_pair_and_keeps_it_under_the_clause_alone() {
    // the frame is every word but the tensor loop's -- the shape of the record text
    let (sched, nest, _, tensor) = own();
    let text = framed(&sched, &|i| tensor.contains(&i));
    let (base, _) = build(&text, &recipe(&[]));
    for i in (0..base.len()).filter(|i| !tensor.contains(i)) {
        assert_eq!(base[i].code(), sched[i].code(), "a framed word keeps the control word it came with (word {i})");
    }
    let (clause, _) = build(&text, &recipe(&[CLAUSE]));
    assert_eq!(clause, base, "the clause alone finds no word in the frame");
    let (pair, log) = build(&text, &recipe(&[CLAUSE, FRAME]));
    let gave = only_the_nest_gave_the_flag_up(&base, &pair, &nest);
    assert!(gave >= 2, "the nest has no words of the form this test is about: {base:#?}");
    assert!(log.contains(&format!("{gave} word(s) give up the yield flag")) && log.contains("the frame's words too"), "{log}");
    // at a largest stall of 1 the words at stall 2 keep it
    let (one, _) = build(&text, &recipe(&[("CUBIT_YIELD_HOLD", "1n"), FRAME]));
    for i in 0..base.len() {
        assert_eq!(one[i].flag, base[i].flag && !(nest.contains(&i) && base[i].qualifies(1)), "word {i}: {one:#?}");
    }
}

#[test]
fn framed_words_of_a_tensor_loop_of_its_frame_and_of_no_loop_keep_the_flag() {
    // the frame is every word but ONE in no loop: the tensor loop and the loop around it are frame too
    let (sched, nest, stage, tensor) = own();
    let freed = at("MOV R24, RZ ;");
    let text = framed(&sched, &|i| i == freed);
    let (base, _) = build(&text, &recipe(&[]));
    assert!(tensor.clone().any(|i| base[i].qualifies(2)), "no word of the rule's kind in the tensor loop: {base:#?}");
    assert!(stage.clone().any(|i| !tensor.contains(&i) && base[i].qualifies(2)), "none in the loop around it: {base:#?}");
    assert!((0..base.len()).any(|i| !nest.contains(&i) && !stage.contains(&i) && base[i].qualifies(2)), "none in no loop: {base:#?}");
    let (pair, _) = build(&text, &recipe(&[CLAUSE, FRAME]));
    assert!(only_the_nest_gave_the_flag_up(&base, &pair, &nest) >= 2);
}

#[test]
fn the_frame_is_named_for_the_nests_clause_alone() {
    let (sched, _, _, tensor) = own();
    let text = framed(&sched, &|i| tensor.contains(&i));
    let (base, _) = build(&text, &recipe(&[]));
    assert_eq!(build(&text, &recipe(&[FRAME])).0, base, "without the clause the variable is not honoured");
    let (rule, _) = build(&text, &recipe(&[("CUBIT_YIELD_HOLD", "2")]));
    assert_eq!(build(&text, &recipe(&[("CUBIT_YIELD_HOLD", "2"), FRAME])).0, rule, "nor with the whole rule");
}

#[test]
fn a_text_that_is_all_frame_is_not_touched() {
    let (sched, _, _, _) = own();
    let text = framed(&sched, &|_| false);
    let (base, _) = build(&text, &recipe(&[]));
    for i in 0..base.len() {
        assert_eq!(base[i].code(), sched[i].code(), "word {i}");
    }
    assert_eq!(build(&text, &recipe(&[CLAUSE, FRAME])).0, base);
}
