//! `CUBIT_YIELD_HOLD=<n>` (n = 1 or 2; opt-in, with `CUBIT_SYNC_CLASSES=1`): a word of the fixed-latency
//! datapath that sets no barrier gives up the yield flag at a stall of 1 ..= n -- outside the tensor loops,
//! whose words keep theirs (2026-11-13).
//!
//! WHERE IT COMES FROM. Not from ptxas: in his sm_120 schedules a word that sets no barrier carries the flag
//! at stall 1 in every opcode but three (`NOP`, and a handful of `IADD3` and `LEA`); only at stall 2 is the
//! form without the flag his practice (43 opcodes). It comes from a card. The served FC1, as
//! `CUBIT_WAIT_POLICY=1` builds it, was read with the flag taken off sets of words and nothing else changed
//! (4 096 rows; one card model, free of its power limit; one block, one load order; every call's result
//! compared):
//!   - off the words outside the tensor loop that qualify at stall 1 (876): 2.19 µs a call faster; at stall 1
//!     and 2 (944): 2.47 µs; the same clause on the schedule of today's table (955 words): 2.57 µs faster than
//!     that schedule without it and 0.27 % below ptxas's own build of the kernel;
//!   - off the 223 qualifying words of the tensor loop as well: 11 µs a call SLOWER than without those.
//! So the rule has two halves, and both are measured on that one kernel: the frame's words give the flag up,
//! the tensor loop's keep it. Why a yield costs in the one place and pays in the other no instrument here
//! says; the kernel's r33 form has not been read under the rule.
//!
//! WHICH WORDS. A word that carries the flag at a stall of 1 ..= n, sets neither a write nor a read barrier,
//! carries no `.reuse` operand, whose opcode ptxas has without the flag at stall 2 on a word that sets no
//! barrier (41 opcodes, the tensor words left out) and that stands in no tensor loop -- the innermost
//! resolved loop around a `QMMA`, `HMMA`, `IMMA` or `DMMA`. Left alone: a barrier setter (a waiter one cycle
//! behind a setter WITH the flag does not see the barrier, so the flag there is part of the schedule's law), a
//! `.reuse` word (every one of ptxas's carries the flag), memory, shuffle, `MUFU`, synchronisation and
//! control-flow words, an author's word.
//!
//! What the switch has is pinned here: the flag off the frame's words; nothing else moved; the tensor loop and
//! the setters as they were; the variable alone, the default path and an author's schedule untouched.
//! KNOWN_ISSUES A55.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const ISA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
/// The lowering pass on the dependency-aware scheduler with the sm_120 table (the recipe the wait policy builds on).
const LOWER: &[(&str, &str)] = &[
    ("CUBIT_SYNC_CLASSES", "1"),
    ("CUBIT_SCHED2", "1"),
    ("CUBIT_MMA_PTXAS", "1"),
    ("CUBIT_SCHED2_LAT", "sm120"),
    ("CUBIT_SCHED2_MEMSTALL", "table"),
    ("CUBIT_SCHED2_LOWER", "1"),
];
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

fn with<'a>(env: &[(&'a str, &'a str)], more: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut v = env.to_vec();
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
    fn sets_a_barrier(&self) -> bool {
        self.rb != "-" || self.wb != "-"
    }
    fn opcode(&self) -> &str {
        let t = if self.text.starts_with('@') { self.text.split_once(' ').map_or("", |x| x.1) } else { self.text.as_str() };
        t.split([' ', '.']).next().unwrap_or("")
    }
    /// The rule's word apart from its place: the flag at a stall of 1 ..= n, no barrier, no `.reuse`, an opcode of the list.
    fn qualifies(&self, n: u32) -> bool {
        self.flag && (1..=n).contains(&self.stall) && !self.sets_a_barrier() && !self.text.contains(".reuse") && HOLD.contains(&self.opcode())
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
    let dir = std::env::temp_dir().join(format!("yieldhold_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, text).unwrap();
    let (ok, log) = cubit(&["asm", "-t", ISA, src.to_str().unwrap(), "-o", out.to_str().unwrap()], env);
    assert!(ok, "asm {env:?} failed:\n{log}");
    let (ok, frozen) = cubit(&["disassemble", "-t", ISA, "--frozen", out.to_str().unwrap()], &[]);
    assert!(ok, "disassemble failed: {frozen}");
    let _ = std::fs::remove_dir_all(&dir);
    let w = words(&frozen);
    assert!(!w.is_empty(), "no instruction lines in:\n{frozen}");
    (w, log)
}

/// A frame, a tensor loop, a frame: datapath words in front of the loop, the fragment registers filled and one
/// `HMMA` inside it, the sums and the store behind it.
const KERNEL: &str = "\
.entry yield_hold_probe
    .reg R0-R31
    .param ptr out
    LDCU.64 UR8, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    LDC R4, c[0x0][0x388] ;
    LDC R5, c[0x0][0x38c] ;
    MOV R6, R4 ;
    IADD3 R7, PT, PT, R6, 0x40, RZ ;
    LOP3.LUT R8, R7, R5, RZ, 0x3c, !PT ;
    MOV R24, RZ ;
    MOV R25, RZ ;
    MOV R26, RZ ;
    MOV R27, RZ ;
    MOV R20, RZ ;
L_top:
    MOV R12, R8 ;
    MOV R13, R8 ;
    MOV R14, R8 ;
    MOV R15, R8 ;
    MOV R16, R5 ;
    MOV R17, R5 ;
    HMMA.16816.F32 R24, R12, R16, R24 ;
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    ISETP.NE.AND P0, PT, R20, 0x4, PT ;
    @P0 BRA L_top ;
    FADD R9, R24, R25 ;
    FADD R10, R26, R27 ;
    FADD R9, R9, R10 ;
    STG.E desc[UR8][R2.64], R9 ;
    EXIT ;
.endentry
";

fn recipes() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    vec![("the lowering pass", LOWER.to_vec()), ("the wait policy", with(LOWER, &[("CUBIT_WAIT_POLICY", "1")]))]
}

/// The words of the tensor loop: from the first fragment `MOV` to the backward branch.
fn tensor_loop(w: &[Word]) -> std::ops::RangeInclusive<usize> {
    let top = w.iter().position(|x| x.text == "MOV R12, R8").expect("the loop's first word");
    let back = w.iter().position(|x| x.opcode() == "BRA").expect("the back edge");
    assert!(top < back && w[top..=back].iter().any(|x| x.opcode() == "HMMA"), "{w:?}");
    top..=back
}

#[test]
fn a_datapath_word_of_the_frame_gives_up_the_flag_at_stall_1() {
    for (name, env) in recipes() {
        // the schedule the switch works on: datapath words of the frame at stall 1 with the flag
        let (off, _) = build(KERNEL, &env);
        let lp = tensor_loop(&off);
        let frame: Vec<usize> = (0..off.len()).filter(|i| !lp.contains(i) && off[*i].qualifies(1)).collect();
        assert!(frame.len() >= 5, "{name}, without the switch: the form this test is about is gone: {off:?}");
        let (on, log) = build(KERNEL, &with(&env, &[("CUBIT_YIELD_HOLD", "1"), ("CUBIT_DEP_VERIFY", "1")]));
        for &i in &frame {
            assert!(!on[i].flag, "{name}: `{}` sets no barrier, stands in the frame at stall 1 and carries the yield flag under CUBIT_YIELD_HOLD=1: {}", on[i].text, on[i].code());
        }
        assert!(log.contains(&format!("yield hold: {} word(s) give up the yield flag (stall 1 ..= 1)", frame.len())), "{name}: the build does not name the words:\n{log}");
        assert!(log.contains("DEP_VERIFY 0 below a table cell, 0 waits closer than the arming distance to their barrier's setter, 0 below a resource spacing, 0 below a default"), "{name}: {log}");
    }
}

#[test]
fn the_switch_moves_those_flags_and_nothing_else() {
    for (name, env) in recipes() {
        let (off, _) = build(KERNEL, &env);
        let lp = tensor_loop(&off);
        for n in [1u32, 2] {
            let v = n.to_string();
            let (on, _) = build(KERNEL, &with(&env, &[("CUBIT_YIELD_HOLD", v.as_str())]));
            assert_eq!(off.len(), on.len());
            for (i, (a, b)) in off.iter().zip(&on).enumerate() {
                let want = a.qualifies(n) && !lp.contains(&i);
                assert_eq!(Word { flag: a.flag && !want, ..a.clone() }, *b, "{name}, CUBIT_YIELD_HOLD={n}, word {i}");
            }
        }
    }
}

#[test]
fn the_tensor_loop_and_the_barrier_setters_keep_their_flags() {
    for (name, env) in recipes() {
        let (off, _) = build(KERNEL, &env);
        let lp = tensor_loop(&off);
        // the loop holds words the rule would take outside it
        assert!(lp.clone().any(|i| off[i].qualifies(2)), "{name}: no qualifying word in the tensor loop: {off:?}");
        let setters = off.iter().filter(|x| x.sets_a_barrier() && x.flag).count();
        assert!(setters >= 3, "{name}: {off:?}");
        let (on, _) = build(KERNEL, &with(&env, &[("CUBIT_YIELD_HOLD", "2")]));
        // the switch acted on the frame around the loop ...
        assert!(off.iter().zip(&on).any(|(a, b)| a.flag && !b.flag), "{name}: no word gave up the flag under CUBIT_YIELD_HOLD=2");
        // ... and on no word of the loop
        assert_eq!(off[lp.clone()], on[lp.clone()], "{name}: a word of the tensor loop moved under CUBIT_YIELD_HOLD=2");
        for (a, b) in off.iter().zip(&on).filter(|(a, _)| a.sets_a_barrier()) {
            assert_eq!(a, b, "{name}: a barrier setter moved under CUBIT_YIELD_HOLD=2");
        }
    }
}

#[test]
fn the_variable_alone_the_default_path_and_an_authors_schedule_are_untouched() {
    // without CUBIT_SYNC_CLASSES the variable is not honoured: the default scheduler's schedule and the
    // dependency-aware one are what they are without it
    for env in [&[][..], &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120"), ("CUBIT_MMA_PTXAS", "1")][..]] {
        let (off, _) = build(KERNEL, env);
        let (on, log) = build(KERNEL, &with(env, &[("CUBIT_YIELD_HOLD", "2")]));
        assert_eq!(off, on, "{env:?}: the variable alone moved the schedule");
        assert!(!log.contains("yield hold"), "{env:?}: {log}");
    }
    // a value that is neither 1 nor 2 is no switch
    let (off, _) = build(KERNEL, LOWER);
    let (on, log) = build(KERNEL, &with(LOWER, &[("CUBIT_YIELD_HOLD", "3")]));
    assert_eq!(off, on, "CUBIT_YIELD_HOLD=3 moved the schedule");
    assert!(!log.contains("yield hold"), "{log}");
    // an author's schedule keeps its flags: the kernel as cubit writes it without the switch, frozen
    let top = *tensor_loop(&off).start();
    let mut frozen = String::from(".entry yield_hold_probe\n    .reg R0-R31\n    .regcount 40\n    .param ptr p0 offset=0x0\n");
    for (i, x) in off.iter().enumerate() {
        if i == top {
            frozen.push_str("L_top:\n");
        }
        let text = if x.opcode() == "BRA" { "@P0 BRA L_top".to_string() } else { x.text.clone() };
        frozen.push_str(&format!("    {} {} ;\n", x.code(), text));
    }
    frozen.push_str(".endentry\n");
    let (kept, log) = build(&frozen, &with(LOWER, &[("CUBIT_YIELD_HOLD", "2")]));
    assert_eq!(off.len(), kept.len());
    for (a, b) in off.iter().zip(&kept) {
        assert_eq!((a.code(), a.opcode()), (b.code(), b.opcode()), "an author's schedule moved under the switch");
    }
    assert!(!log.contains("yield hold"), "{log}");
}
