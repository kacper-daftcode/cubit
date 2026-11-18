//! `CUBIT_TENSOR_YIELD=holds` (opt-in, 2026-11-18; honoured only with `CUBIT_SYNC_CLASSES=1`): in a tensor loop
//! every hold of the fixed-latency datapath yields (`tensor_yield`).
//!
//! In the text range of a tensor loop a HOLD — a word of the flag rule's datapath opcodes at a stall of 3 ..= 11
//! that carries no flag — takes the flag. Out of it: a word that sets a barrier, a word that waits, the first word
//! behind a wait that reads the result the wait is for, a word that came in with its own control word. No stall,
//! wait or barrier moves, no flag is taken off, and nothing moves outside the tensor loops.
//!
//! Every test but the last fails on the scheduler without the switch (the variable is then unknown and changes
//! nothing); the last is the control of the default path.

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
const HOLDS: (&str, &str) = ("CUBIT_TENSOR_YIELD", "holds");
/// The opcodes of the flag rule (`scheduling_pass::HOLD_OPCODES`).
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
    fn waits(&self) -> bool {
        !self.wait.chars().all(|c| c == '-')
    }
    /// A hold apart from its place: an opcode of the list at a stall of 3 ..= 11 without the flag, no barrier
    /// set, no wait.
    fn holds(&self) -> bool {
        !self.flag && (3..=11).contains(&self.stall) && self.rb == "-" && self.wb == "-" && !self.waits() && HOLD.contains(&self.opcode())
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

/// `cubit asm` of `text` under `env`: did it succeed, the schedule it built, its log.
fn try_build(text: &str, env: &[(&str, &str)]) -> (bool, Vec<Word>, String) {
    let dir = std::env::temp_dir().join(format!("tensoryield_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, text).unwrap();
    let (ok, log) = cubit(&["asm", "-t", ISA, src.to_str().unwrap(), "-o", out.to_str().unwrap()], env);
    let mut w = Vec::new();
    if ok {
        let (ok, frozen) = cubit(&["disassemble", "-t", ISA, "--frozen", out.to_str().unwrap()], &[]);
        assert!(ok, "disassemble failed: {frozen}");
        w = words(&frozen);
        assert!(!w.is_empty(), "no instruction lines in:\n{frozen}");
    }
    let _ = std::fs::remove_dir_all(&dir);
    (ok, w, log)
}

/// The schedule `cubit asm` builds from `text` under `env` and the log of the build.
fn build(text: &str, env: &[(&str, &str)]) -> (Vec<Word>, String) {
    let (ok, w, log) = try_build(text, env);
    assert!(ok, "asm {env:?} failed:\n{log}\n{text}");
    (w, log)
}

/// A nest, then a stage loop around a tensor loop that holds a load, the word that waits for it, a second reader
/// of its result right in front of a tensor word, and a second tensor word; sums and a store behind the loops.
const KERNEL: &str = "\
.entry tensor_yield
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
L_nest:
    IADD3 R18, PT, PT, R18, 0x3, RZ ;
    MOV R28, R5 ;
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
    LDG.E R11, desc[UR8][R2.64] ;
    MOV R12, R9 ;
    MOV R13, R9 ;
    IADD3 R14, PT, PT, R11, R9, RZ ;
    MOV R16, R10 ;
    MOV R17, R10 ;
    IADD3 R15, PT, PT, R11, 0x1, RZ ;
    HMMA.16816.F32 R24, R12, R16, R24 ;
    MOV R12, R10 ;
    MOV R13, R10 ;
    MOV R14, R10 ;
    MOV R15, R9 ;
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
/// The word that waits for the load of the tensor loop, and the first word behind it that reads the load's result.
const WAITER: &str = "IADD3 R14, PT, PT, R11, R9, RZ ;";
const FIRST_READER: &str = "IADD3 R15, PT, PT, R11, 0x1, RZ ;";

fn is_word(line: &str) -> bool {
    let t = line.trim();
    !t.is_empty() && !t.starts_with('.') && !t.ends_with(':')
}

/// The number of the instruction of `KERNEL` whose line is `line`.
fn at(line: &str) -> usize {
    KERNEL.lines().filter(|l| is_word(l)).position(|l| l.trim() == line).unwrap_or_else(|| panic!("no line `{line}`"))
}

/// The tensor loop of `KERNEL` by its words.
fn tensor() -> std::ops::RangeInclusive<usize> {
    at("LDG.E R11, desc[UR8][R2.64] ;")..=at("@P0 BRA L_top ;")
}

/// The holds of the base schedule as the clause names them — the kernel's one first reader behind a wait is named
/// here by its line.
fn holds(base: &[Word]) -> Vec<usize> {
    let first = at(FIRST_READER);
    tensor().filter(|&i| base[i].holds() && i != first).collect()
}

/// The words on which two schedules of the kernel differ.
fn moved(a: &[Word], b: &[Word]) -> Vec<usize> {
    assert_eq!(a.len(), b.len());
    (0..a.len()).filter(|&i| a[i] != b[i]).collect()
}

#[test]
fn a_hold_of_a_tensor_loop_takes_the_flag_and_nothing_else_moves() {
    let (base, _) = build(KERNEL, &recipe(&[]));
    assert!(base[tensor()].iter().any(|w| w.opcode() == "HMMA"), "{base:?}");
    let holds = holds(&base);
    assert!(!holds.is_empty(), "the kernel has holds in its tensor loop: {base:?}");
    // a word with the flag at a stall of 1 or 2 stands right in front of a hold: it is to keep its flag
    assert!(holds.iter().any(|&i| base[i - 1].flag && base[i - 1].stall <= 2 && HOLD.contains(&base[i - 1].opcode())), "{base:?}");
    let (under, log) = build(KERNEL, &recipe(&[HOLDS]));
    assert_eq!(moved(&base, &under), holds, "exactly the holds move\n{log}");
    for &i in &holds {
        assert_eq!(under[i], Word { flag: true, ..base[i].clone() }, "[{i}] takes the flag and nothing else of its control word moves");
    }
    let said = format!("tensor yield: {} hold(s) of the tensor loops take the yield flag (stall 3 ..= 11)", holds.len());
    assert!(log.contains(&said), "the log names the count ({said}):\n{log}");
}

#[test]
fn the_first_reader_behind_a_wait_a_long_stall_and_the_words_outside_the_loop_stay() {
    let (base, _) = build(KERNEL, &recipe(&[]));
    let (under, _) = build(KERNEL, &recipe(&[HOLDS]));
    assert_ne!(base, under, "the clause moves flags in this kernel");
    // the word that waits for the load, and the first reader behind it: a hold by its stall and its flag
    let (w, f) = (at(WAITER), at(FIRST_READER));
    assert!(base[w].waits(), "`{WAITER}` waits: {:?}", base[w]);
    assert!(base[f].holds(), "`{FIRST_READER}` holds without the flag: {:?}", base[f]);
    assert_eq!(under[f], base[f], "the first reader behind a wait keeps its control word");
    assert_eq!(under[w], base[w], "the waiting word keeps its control word");
    // a datapath word of the loop at a stall of 12 or more, a setter, the tensor words
    assert!(tensor().any(|i| !base[i].flag && base[i].stall >= 12 && HOLD.contains(&base[i].opcode())), "a datapath word at a stall of 12 or more: {base:?}");
    for i in tensor().filter(|&i| base[i].stall >= 12 || base[i].wb != "-" || base[i].rb != "-" || base[i].opcode() == "HMMA") {
        assert_eq!(under[i], base[i], "[{i}] stays as it is");
    }
    // outside the tensor loop: holds of the same kind exist, and no word moves
    let outside: Vec<usize> = (0..base.len()).filter(|i| !tensor().contains(i)).collect();
    assert!(outside.iter().any(|&i| base[i].holds()), "a hold outside the tensor loop: {base:?}");
    for &i in &outside {
        assert_eq!(under[i], base[i], "[{i}] stands outside the tensor loop");
    }
}

#[test]
fn a_word_that_came_in_with_its_control_word_is_not_touched() {
    let (base, _) = build(KERNEL, &recipe(&[]));
    let holds = holds(&base);
    assert!(holds.len() >= 2, "two holds: one is framed, one is left to the clause: {base:?}");
    let framed_at = holds[0];
    // the kernel with the first hold's own control word written in front of it
    let mut text = String::new();
    let mut i = 0;
    for line in KERNEL.lines() {
        if is_word(line) {
            if i == framed_at {
                text.push_str(&format!("    {} {} ;", base[i].code(), base[i].text));
            } else {
                text.push_str(line);
            }
            i += 1;
        } else {
            text.push_str(line);
        }
        text.push('\n');
    }
    let (under, log) = build(&text, &recipe(&[HOLDS]));
    assert_eq!(under[framed_at], base[framed_at], "the framed hold keeps the control word it came in with\n{log}");
    assert!(holds[1..].iter().any(|&i| under[i].flag), "a hold cubit scheduled takes the flag beside it\n{log}");
}

#[test]
fn another_value_is_refused_by_name() {
    for v in ["hold", "holds+fronts", "1"] {
        let (ok, _, log) = try_build(KERNEL, &recipe(&[("CUBIT_TENSOR_YIELD", v)]));
        assert!(!ok, "`CUBIT_TENSOR_YIELD={v}` is no value of the switch:\n{log}");
        assert!(log.contains(&format!("CUBIT_TENSOR_YIELD={v}")) && log.contains("the only value is `holds`"), "the refusal names the value:\n{log}");
    }
    // unset, empty and `0` are the schedule without the clause
    let (base, _) = build(KERNEL, &recipe(&[]));
    for v in ["", "0"] {
        let (same, _) = build(KERNEL, &recipe(&[("CUBIT_TENSOR_YIELD", v)]));
        assert_eq!(same, base, "CUBIT_TENSOR_YIELD={v:?}");
    }
}

#[test]
fn without_the_sync_classes_the_switch_changes_nothing() {
    // the control of the default path: the variable alone, on the default scheduler
    let (base, _) = build(KERNEL, &[]);
    let (same, log) = build(KERNEL, &[HOLDS]);
    assert_eq!(same, base, "{HOLDS:?} without CUBIT_SYNC_CLASSES=1");
    assert!(!log.contains("tensor yield"), "{log}");
}
