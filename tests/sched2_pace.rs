//! `CUBIT_SCHED2_PACE=tensor` (opt-in, 2026-11-18; needs the legaliser `CUBIT_SCHED2=1 CUBIT_SCHED2_LAT=<table>`):
//! in a tensor loop a word of the unit `IADD3` | `LEA` | `LOP3` | `PRMT` | `SHF` stands at a stall of 2 at least in
//! front of another word of the unit (`sched2_pace`).
//!
//! The floor is set in front of the legaliser, which then places every wait as without the switch: the hold in
//! front of a reader is shorter by the cycles the pacing put between its producer and it, and the reader keeps its
//! distance. A word of the unit in front of another opcode, every word outside the tensor loops and a word that
//! came in with its own control word stay as they are.
//!
//! Every test but the last fails on the scheduler without the switch (the variable is then unknown and changes
//! nothing); the last is the control of the schedule without it.

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
const PACE: (&str, &str) = ("CUBIT_SCHED2_PACE", "tensor");
/// The opcodes of the paced unit (`sched2_pace::PACED_OPCODES`).
const UNIT: &[&str] = &["IADD3", "LEA", "LOP3", "PRMT", "SHF"];

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
    fn unit(&self) -> bool {
        UNIT.contains(&self.opcode())
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
    let dir = std::env::temp_dir().join(format!("sched2pace_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
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

/// A nest that holds a pair of the unit, then a stage loop around a tensor loop: a word of the unit in front of a
/// `MOV`, the tensor word's operands, and three words of the unit between the last operand and the tensor word.
const KERNEL: &str = "\
.entry sched2_pace
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
    LOP3.LUT R19, R18, R5, RZ, 0x3c, !PT ;
    LOP3.LUT R11, R18, R5, RZ, 0xc0, !PT ;
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
    PRMT R31, R9, 0x5140, R10 ;
    MOV R12, R9 ;
    MOV R13, R9 ;
    MOV R14, R9 ;
    MOV R15, R9 ;
    MOV R16, R10 ;
    MOV R17, R10 ;
    LOP3.LUT R28, R9, R10, RZ, 0x3c, !PT ;
    LOP3.LUT R29, R9, R10, RZ, 0xc0, !PT ;
    SHF.R.U32.HI R30, RZ, 0x2, R9 ;
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
/// The last operand of the tensor word, the two words of the unit in front of a word of the unit, the word of the
/// unit in front of the tensor word, the tensor word.
const PRODUCER: &str = "MOV R17, R10 ;";
const FIRST: &str = "LOP3.LUT R28, R9, R10, RZ, 0x3c, !PT ;";
const SECOND: &str = "LOP3.LUT R29, R9, R10, RZ, 0xc0, !PT ;";
const LAST: &str = "SHF.R.U32.HI R30, RZ, 0x2, R9 ;";
const READER: &str = "HMMA.16816.F32 R24, R12, R16, R24 ;";

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
    at("PRMT R31, R9, 0x5140, R10 ;")..=at("@P0 BRA L_top ;")
}

#[test]
fn a_unit_word_in_front_of_a_unit_word_of_a_tensor_loop_stands_at_two() {
    let (base, _) = build(KERNEL, &recipe(&[]));
    let (under, log) = build(KERNEL, &recipe(&[PACE]));
    for line in [FIRST, SECOND] {
        let i = at(line);
        assert!(base[i].unit() && base[i + 1].unit() && base[i].stall == 1, "`{line}` stands at 1 in front of a word of the unit: {:?}", base[i]);
        assert_eq!(under[i], Word { stall: 2, ..base[i].clone() }, "`{line}` takes a stall of 2 and nothing else of its control word moves");
    }
    assert!(log.contains("unit pacing: 2 word(s) of the tensor loops take a stall of 2 in front of a word of their unit (2 cycles)"), "{log}");
}

#[test]
fn the_hold_in_front_of_the_reader_shrinks_and_the_reader_keeps_its_distance() {
    let (base, _) = build(KERNEL, &recipe(&[]));
    let (under, _) = build(KERNEL, &recipe(&[PACE]));
    let (p, l, r) = (at(PRODUCER), at(LAST), at(READER));
    assert_eq!(l + 1, r);
    let distance = |s: &[Word]| s[p..r].iter().map(|w| w.stall).sum::<u32>();
    // without the switch the wait for the last operand stands on the last word in front of the tensor word
    assert!(base[l].stall >= 3 && base[p..l].iter().all(|w| w.stall == 1), "{:?}", &base[p..r]);
    assert_eq!(distance(&under), distance(&base), "the tensor word keeps its distance from its last operand");
    assert_eq!(under[l].stall, base[l].stall - 2, "the hold is shorter by the two cycles the pacing put in front of it");
    assert_eq!(under[r], base[r], "the tensor word itself does not move");
}

#[test]
fn another_opcode_behind_it_and_the_words_outside_the_tensor_loops_stay() {
    let (base, _) = build(KERNEL, &recipe(&[]));
    let (under, _) = build(KERNEL, &recipe(&[PACE]));
    assert_ne!(base, under, "the pacing moves stalls in this kernel");
    // a word of the unit in front of a MOV, and the one in front of the tensor loop's branch
    for line in ["PRMT R31, R9, 0x5140, R10 ;", "IADD3 R20, PT, PT, R20, 0x1, RZ ;"] {
        let i = at(line);
        assert!(base[i].unit() && !base[i + 1].unit(), "{:?}", base[i]);
        assert_eq!(under[i], base[i], "`{line}` stands in front of another opcode");
    }
    // the nest holds a pair of the unit at a stall of 1: no word outside the tensor loop moves
    let n = at("LOP3.LUT R19, R18, R5, RZ, 0x3c, !PT ;");
    assert!(base[n].unit() && base[n + 1].unit() && base[n].stall == 1, "{:?}", base[n]);
    for i in (0..base.len()).filter(|i| !tensor().contains(i)) {
        assert_eq!(under[i], base[i], "[{i}] stands outside the tensor loop");
    }
}

#[test]
fn a_word_that_came_in_with_its_control_word_is_not_paced() {
    let (base, _) = build(KERNEL, &recipe(&[]));
    let framed_at = at(FIRST);
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
    let (under, log) = build(&text, &recipe(&[PACE]));
    assert_eq!(under[framed_at], base[framed_at], "the framed word keeps the control word it came in with\n{log}");
    assert_eq!(under[at(SECOND)].stall, 2, "the word cubit schedules beside it is paced\n{log}");
}

#[test]
fn the_switch_needs_the_legaliser_and_another_value_is_refused_by_name() {
    for v in ["1", "all", "tensors"] {
        let (ok, _, log) = try_build(KERNEL, &recipe(&[("CUBIT_SCHED2_PACE", v)]));
        assert!(!ok, "`CUBIT_SCHED2_PACE={v}` is no value of the switch:\n{log}");
        assert!(log.contains(&format!("CUBIT_SCHED2_PACE={v}")) && log.contains("the only value is `tensor`"), "the refusal names the value:\n{log}");
    }
    // without the legaliser nothing would place the waits behind the floor
    let (ok, _, log) = try_build(KERNEL, &[PACE]);
    assert!(!ok, "the switch alone, on the default scheduler:\n{log}");
    assert!(log.contains("CUBIT_SCHED2_PACE=tensor needs CUBIT_SCHED2=1 CUBIT_SCHED2_LAT=<table>"), "{log}");
}

#[test]
fn unset_empty_and_zero_are_the_schedule_without_the_switch() {
    let (base, _) = build(KERNEL, &recipe(&[]));
    for v in ["", "0"] {
        let (same, log) = build(KERNEL, &recipe(&[("CUBIT_SCHED2_PACE", v)]));
        assert_eq!(same, base, "CUBIT_SCHED2_PACE={v:?}");
        assert!(!log.contains("unit pacing"), "{log}");
    }
}
