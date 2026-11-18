//! The two laws of a tensor instruction that no scoreboard carries (KNOWN_ISSUES A66; `sync_class::hold_need`,
//! `sync_class::settle_need`, `tensor_laws`; 2026-11-18).
//!
//! A tensor instruction reads its source registers over 8 issue cycles behind its own issue, and it stands 14
//! issue cycles in front of a branch. cubit's schedule of a kernel with m-tile loops broke both at six places:
//! `QMMA ..., R48, ... ; CS2R R50, SRZ ; CS2R R48, SRZ ; NOP ; BRA L_a160` stood at stalls 1 / 1 / 1 / 1 — the
//! accumulate re-zeroed one and two cycles behind the tensor instruction that reads it (the vendor: 8 and 9), the
//! branch four cycles behind it (14) — and a second `QMMA` stood 11 cycles in front of the same plain branch (14).
//! Two rows each left one form out: the operand hold took `CS2R` for a slow writer (the first pass's list of
//! long-latency opcodes names it, though the word is fixed-latency and never carries a write barrier), and the
//! landing row was written for a conditional branch only. No check of cubit read either distance.
//!
//! The tests: the two places of that kernel, word for word, scheduled by cubit under the scheduler's switches —
//! the six distances; the smallest kernel of each kind; the read-only check (`CUBIT_VERIFY`) on the same text as
//! it was written before, which names the six places, and on the text with the vendor's stalls, which names none.
//! Six fail on the tree without the fix — the three schedules, the two tests of the check and the rows of the
//! law taken one by one (22 of 23 had their number); two are their controls — a load may follow a tensor
//! instruction at once, and a guarded branch kept its 14 before.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
/// The switches of a schedule that every word of is cubit's.
const SET: [(&str, &str); 8] = [
    ("CUBIT_SYNC_CLASSES", "1"),
    ("CUBIT_SCHED2", "1"),
    ("CUBIT_MMA_PTXAS", "1"),
    ("CUBIT_SCHED2_LAT", "sm120"),
    ("CUBIT_SCHED2_MEMSTALL", "table"),
    ("CUBIT_SCHED2_LOWER", "1"),
    ("CUBIT_WAIT_POLICY", "1"),
    ("CUBIT_LOAD_COVER", "1"),
];

/// One word of the schedule: its stall and its text.
#[derive(Debug, Clone)]
struct Word {
    stall: u32,
    text: String,
}

/// `cubit asm` of a kernel body under `env`, then `cubit disassemble --frozen`: the words, the log of the
/// assembly and the cubin's bytes.
fn build(body: &str, env: &[(&str, &str)]) -> (Vec<Word>, String, Vec<u8>) {
    let dir = std::env::temp_dir().join(format!("tensorlaws_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, format!(".entry tensor_laws_probe\n    .reg R0-R95\n    .param ptr out\n{body}.endentry\n")).unwrap();
    let run = |args: &[&str], env: &[(&str, &str)]| {
        let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
        let log = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert!(o.status.success(), "{args:?} under {env:?}: {log}");
        log
    };
    let log = run(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()], env);
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
        words.push(Word { stall: fields[4][1..].parse().unwrap(), text: tag[end + 1..].trim().trim_end_matches(';').trim().to_string() });
    }
    (words, log, cubin)
}

/// The index of the `nth` word (from 0) whose text starts with `starts`.
fn at(k: &[Word], starts: &str, nth: usize) -> usize {
    k.iter().enumerate().filter(|(_, w)| w.text.starts_with(starts)).nth(nth).unwrap_or_else(|| panic!("no word `{starts}` #{nth} in {k:#?}")).0
}

/// Issue cycles from word `a` to word `b` on the straight-line text: the stalls of `a ..= b - 1`.
fn cycles(k: &[Word], a: usize, b: usize) -> u32 {
    k[a..b].iter().map(|w| w.stall).sum()
}

/// The lines of the check in a log: (the `TENSOR HOLD` / `TENSOR LANDING` lines, the count line).
fn check_lines(log: &str) -> (Vec<String>, Vec<String>) {
    let sites = log.lines().map(str::trim).filter(|l| l.starts_with("TENSOR HOLD:") || l.starts_with("TENSOR LANDING:")).map(String::from).collect();
    let count = log.lines().filter(|l| l.starts_with("CUBIT_VERIFY_TENSOR:")).map(String::from).collect();
    (sites, count)
}

/// The words behind the branch target: room for the distance the tensor instruction keeps in front of `EXIT`,
/// so that no stall in front of the branch is raised for it.
const TARGET: &str = "L_a160:
    MOV R4, R2 ;
    MOV R5, R2 ;
    MOV R6, R2 ;
    MOV R7, R2 ;
    EXIT ;
";

/// The two places of the kernel with m-tile loops, word for word: the tensor instruction whose accumulate two
/// `CS2R` re-zero, four words in front of a plain branch; and the tensor instruction eight words in front of
/// the same branch. `c` = the control word in front of each word (`{q1}` / `{n1}` / `{n2}`: the stall of the
/// first tensor instruction and of the two `NOP`), or nothing — then the schedule is cubit's.
fn six_places(frozen: Option<(u8, u8, u8)>) -> String {
    let c = |stall: u8, wb: char, yield_flag: bool| match frozen {
        Some(_) => format!("[B------:R-:W{wb}:{}:S{stall:02}] ", if yield_flag { 'Y' } else { '-' }),
        None => String::new(),
    };
    let (q1, n1, n2) = frozen.unwrap_or((1, 1, 1));
    let mut s = String::new();
    s += &format!("    {}S2R R2, SR_TID.X ;\n", c(2, '0', true));
    s += &format!("    {}ISETP.NE.AND P0, PT, R2, RZ, PT ;\n", if frozen.is_some() { "[B0-----:R-:W-:-:S13] " } else { "" });
    s += &format!("    {}@P0 BRA L_second ;\n", c(5, '-', true));
    s += &format!("    {}QMMA.SF.16832.F32.E4M3.E2M1.E8 R20, R20, R52, R48, R70, R66, UR4 ;\n", c(q1, '-', true));
    s += &format!("    {}CS2R R50, SRZ ;\n", c(1, '-', true));
    s += &format!("    {}CS2R R48, SRZ ;\n", c(1, '-', true));
    s += &format!("    {}NOP ;\n", c(n1, '-', n1 == 1));
    s += &format!("    {}BRA L_a160 ;\n", c(5, '-', true));
    s += "L_second:\n";
    s += &format!("    {}QMMA.SF.16832.F32.E4M3.E2M1.E8 R40, R16, R12, R40, R30, R31, UR4 ;\n", c(1, '-', true));
    s += &format!("    {}UMOV UR4, URZ ;\n", c(2, '-', true));
    s += &format!("    {}MOV R51, UR4 ;\n", c(1, '-', true));
    s += &format!("    {}MOV R23, UR4 ;\n", c(1, '-', true));
    s += &format!("    {}MOV R27, UR4 ;\n", c(3, '-', true));
    s += &format!("    {}MOV R31, UR4 ;\n", c(1, '-', true));
    s += &format!("    {}MOV R30, UR5 ;\n", c(1, '-', true));
    s += &format!("    {}NOP ;\n", c(n2, '-', n2 == 1));
    s += &format!("    {}BRA L_a160 ;\n", c(5, '-', true));
    s += "L_a160:\n";
    for (r, stall) in [(4, 1), (5, 1), (6, 1), (7, 15)] {
        s += &format!("    {}MOV R{r}, R2 ;\n", c(stall, '-', stall == 1));
    }
    s += &format!("    {}EXIT ;\n", c(5, '-', true));
    s
}

/// THE SIX PLACES: under the scheduler's switches the two `CS2R` stand 8 and 9 issue cycles behind the tensor
/// instruction whose accumulate they re-zero and both plain branches 14 behind theirs — the vendor's distances.
/// Without the fix: 1 and 2 (four registers of the accumulate inside the hold), 4 and 11.
#[test]
fn the_six_places_of_a_kernel_with_m_tile_loops_keep_both_laws() {
    let (k, _, _) = build(&six_places(None), &SET);
    let (q1, q2) = (at(&k, "QMMA", 0), at(&k, "QMMA", 1));
    let hold = (cycles(&k, q1, at(&k, "CS2R R50", 0)), cycles(&k, q1, at(&k, "CS2R R48", 0)));
    assert_eq!(hold, (8, 9), "the accumulate R48..R51 is re-zeroed inside the hold of the tensor instruction: {k:#?}");
    let landing = (cycles(&k, q1, at(&k, "BRA L_", 0)), cycles(&k, q2, at(&k, "BRA L_", 1)));
    assert_eq!(landing, (14, 14), "a plain branch inside the landing distance of a tensor instruction: {k:#?}");
    // the hold that was kept before: `MOV R31` rewrites a scale register of the second tensor instruction
    assert_eq!(cycles(&k, q2, at(&k, "MOV R31", 0)), 8, "{k:#?}");
}

/// The smallest kernel of the first kind: one `CS2R` of the accumulate behind a tensor instruction.
#[test]
fn a_cs2r_keeps_the_hold_behind_a_tensor_instruction() {
    let body = format!(
        "    S2R R2, SR_TID.X ;\n    QMMA.SF.16832.F32.E4M3.E2M1.E8 R20, R12, R16, R48, R70, R66, UR4 ;\n    CS2R R50, SRZ ;\n{}",
        TARGET.replace("L_a160:\n", "")
    );
    let (k, _, _) = build(&body, &SET);
    let d = cycles(&k, at(&k, "QMMA", 0), at(&k, "CS2R", 0));
    assert!(d >= 8, "`CS2R R50, SRZ` stands {d} issue cycle(s) behind the tensor instruction that reads R50: {k:#?}");
}

/// The smallest kernel of the second kind: a plain branch behind a tensor instruction.
#[test]
fn a_plain_branch_keeps_the_landing_distance_behind_a_tensor_instruction() {
    let body = format!(
        "    S2R R2, SR_TID.X ;\n    QMMA.SF.16832.F32.E4M3.E2M1.E8 R20, R12, R16, R48, R70, R66, UR4 ;\n    NOP ;\n    BRA L_a160 ;\n    MOV R3, R2 ;\n{TARGET}"
    );
    let (k, _, _) = build(&body, &SET);
    let d = cycles(&k, at(&k, "QMMA", 0), at(&k, "BRA L_", 0));
    assert_eq!(d, 14, "`BRA` stands {d} issue cycle(s) behind the tensor instruction: {k:#?}");
}

/// THE CHECK NAMES THE SIX PLACES in the text as it was written before — every word with the control word of
/// that schedule, nothing re-scheduled, no switch but `CUBIT_VERIFY` — and none in the same text with the
/// vendor's three stalls; it writes no field (the cubin is the one without the variable).
#[test]
fn the_check_names_the_six_places_of_a_schedule_as_written() {
    let text = six_places(Some((1, 1, 1)));
    let (k, log, cubin) = build(&text, &[("CUBIT_VERIFY", "1")]);
    assert_eq!((k[at(&k, "QMMA", 0)].stall, k[at(&k, "NOP", 0)].stall, k[at(&k, "NOP", 1)].stall), (1, 1, 1), "the text is assembled as written");
    let (sites, count) = check_lines(&log);
    let want = [
        "TENSOR HOLD: insn[4] CS2R R50, SRZ rewrites R50 1 issue cycle(s) behind insn[3] QMMA.SF.16832.F32.E4M3.E2M1.E8 that reads it (its accumulate)",
        "TENSOR HOLD: insn[4] CS2R R50, SRZ rewrites R51 1 issue cycle(s) behind insn[3] QMMA.SF.16832.F32.E4M3.E2M1.E8 that reads it (its accumulate)",
        "TENSOR HOLD: insn[5] CS2R R48, SRZ rewrites R48 2 issue cycle(s) behind insn[3] QMMA.SF.16832.F32.E4M3.E2M1.E8 that reads it (its accumulate)",
        "TENSOR HOLD: insn[5] CS2R R48, SRZ rewrites R49 2 issue cycle(s) behind insn[3] QMMA.SF.16832.F32.E4M3.E2M1.E8 that reads it (its accumulate)",
        "TENSOR LANDING: insn[7] BRA L_a160 stands 4 issue cycle(s) behind insn[3] QMMA.SF.16832.F32.E4M3.E2M1.E8",
        "TENSOR LANDING: insn[16] BRA L_a160 stands 11 issue cycle(s) behind insn[8] QMMA.SF.16832.F32.E4M3.E2M1.E8",
    ];
    assert_eq!(sites.len(), 6, "{log}");
    for (line, w) in sites.iter().zip(want) {
        assert!(line.starts_with(w), "{line}\n  wanted: {w}");
    }
    assert_eq!(count.len(), 1, "{log}");
    assert!(
        count[0].starts_with("CUBIT_VERIFY_TENSOR: 4 source register(s) of a tensor instruction rewritten by a fixed-latency word closer than 8 issue cycles behind it, 2 branch(es) closer than 14 behind a tensor instruction (2 tensor instructions walked;"),
        "{}",
        count[0]
    );
    // the check reads; without the variable the same bytes and no line
    let (_, quiet, plain) = build(&text, &[]);
    assert_eq!(cubin, plain, "CUBIT_VERIFY moved a byte");
    assert!(check_lines(&quiet).1.is_empty() && check_lines(&quiet).0.is_empty(), "{quiet}");
    // the vendor's stalls at the three words: 8 on the tensor instruction, 4 on the two `NOP`
    let (_, log, _) = build(&six_places(Some((8, 4, 4))), &[("CUBIT_VERIFY", "1")]);
    let (sites, count) = check_lines(&log);
    assert!(sites.is_empty(), "{log}");
    assert!(count.len() == 1 && count[0].starts_with("CUBIT_VERIFY_TENSOR: 0 source register(s)") && count[0].contains(", 0 branch(es) closer than 14"), "{log}");
    // a kernel without a tensor instruction prints no line of the check
    let (_, log, _) = build("    S2R R2, SR_TID.X ;\n    MOV R4, R2 ;\n    EXIT ;\n", &[("CUBIT_VERIFY", "1")]);
    assert!(check_lines(&log).1.is_empty(), "{log}");
}

/// A load that refills a register of the A fragment right behind a tensor instruction (the address of the load
/// is old enough: nothing but the hold could ask for a stall on the tensor instruction).
fn load_behind_a_tensor_instruction() -> String {
    let old: String = (32..44).map(|r| format!("    MOV R{r}, R2 ;\n")).collect();
    format!(
        "    S2R R2, SR_TID.X ;\n    SHF.L.U32 R8, R2, 0x4, RZ ;\n{old}    QMMA.SF.16832.F32.E4M3.E2M1.E8 R20, R12, R16, R48, R70, R66, UR4 ;\n    LDS R12, [R8+0x100] ;\n{}",
        TARGET.replace("L_a160:\n", "")
    )
}

/// Control: a load lands late and may follow a tensor instruction at once — the hold does not move it.
#[test]
fn a_load_may_follow_a_tensor_instruction_at_once() {
    let (k, _, _) = build(&load_behind_a_tensor_instruction(), &SET);
    assert_eq!(cycles(&k, at(&k, "QMMA", 0), at(&k, "LDS", 0)), 1, "{k:#?}");
}

/// ... and the check counts such a load beside the places, not among them.
#[test]
fn the_check_counts_a_late_landing_writer_apart() {
    let mut env = SET.to_vec();
    env.push(("CUBIT_VERIFY", "1"));
    let (_, log, _) = build(&load_behind_a_tensor_instruction(), &env);
    let (sites, count) = check_lines(&log);
    assert!(sites.is_empty() && count.len() == 1 && count[0].contains("inside the hold and no finding: 1 rewrite(s) by a word whose result lands late"), "{log}");
}

/// THE LANDING ROWS OF THE LAW, ONE BY ONE — word | what is in flight → issue cycles, the 23 rows as the law's
/// table lists them: `settle_need` has the number of each. The plain `BRA` was the one row left out.
#[test]
fn every_landing_row_of_the_law_has_its_number() {
    use cubit::sync_class::Landing::{Mma, Predicate, Register};
    let first = |body: &str| {
        let src = format!(".entry t\n    .param u64 io\n{body}    EXIT ;\n.endentry\n");
        cubit::sass_file::parse_sass_file_str_strict(&src).unwrap_or_else(|e| panic!("{body}: {e}")).kernels[0].instructions[0].clone()
    };
    let rows = [
        ("    BSYNC B0 ;\n", Register, 7),
        ("    BSYNC B0 ;\n", Predicate, 13),
        ("    BSYNC B0 ;\n", Mma, 29),
        ("    BSYNC.RECONVERGENT B0 ;\n", Register, 7),
        ("    BSYNC.RECONVERGENT B0 ;\n", Predicate, 13),
        ("    BSYNC.RECONVERGENT B0 ;\n", Mma, 29),
        ("    BSYNC.RELIABLE B1 ;\n", Register, 7),
        ("    BSYNC.RELIABLE B1 ;\n", Predicate, 13),
        ("    BSYNC.RELIABLE B1 ;\n", Mma, 29),
        ("    CALL.REL.NOINC L_x ;\nL_x:\n", Register, 7),
        ("    WARPSYNC.COLLECTIVE R12, L_x ;\nL_x:\n", Register, 7),
        ("    WARPSYNC.COLLECTIVE R12, L_x ;\nL_x:\n", Predicate, 13),
        ("    NANOSLEEP.SYNCS 0x989680 ;\n", Register, 7),
        ("    BREAK B0 ;\n", Register, 7),
        ("    BREAK B0 ;\n", Predicate, 13),
        ("    EXIT ;\n", Register, 6),
        ("    EXIT ;\n", Predicate, 13),
        ("    BRX R50 -0x1340 ;\n", Register, 4),
        ("    RET.REL.NODEC R18 0x0 ;\n", Register, 4),
        ("    @!P6 BRA L_x ;\nL_x:\n", Mma, 14),
        ("    BRA.U !UP0, L_x ;\nL_x:\n", Mma, 14),
        ("    BRA L_x ;\nL_x:\n", Mma, 14),
        ("    BRA.DIV UR4, L_x ;\nL_x:\n", Mma, 14),
    ];
    let out: Vec<String> = rows
        .iter()
        .filter(|(word, what, n)| cubit::sync_class::settle_need(&first(word), *what) != Some(*n))
        .map(|(word, what, n)| format!("{} <- {what:?} {n}", word.lines().next().unwrap().trim()))
        .collect();
    assert!(out.is_empty(), "{} of {} rows of the law without their number: {out:?}", out.len(), rows.len());
}

/// Control: the guarded branch had its row before the fix and keeps it.
#[test]
fn a_guarded_branch_kept_the_landing_distance_before() {
    let body = format!(
        "    S2R R2, SR_TID.X ;\n    ISETP.NE.AND P0, PT, R2, RZ, PT ;\n    QMMA.SF.16832.F32.E4M3.E2M1.E8 R20, R12, R16, R48, R70, R66, UR4 ;\n    NOP ;\n    @P0 BRA L_a160 ;\n    MOV R3, R2 ;\n{TARGET}"
    );
    let (k, _, _) = build(&body, &SET);
    let d = cycles(&k, at(&k, "QMMA", 0), at(&k, "@P0 BRA", 0));
    assert!(d >= 14, "{d}: {k:#?}");
}
