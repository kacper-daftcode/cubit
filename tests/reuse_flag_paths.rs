//! `CUBIT_VERIFY` checks the operand-reuse flags (`.reuse`) on every path of the flow graph
//! (`src/store_paths.rs`, 2026-11-11; KNOWN_ISSUES A39).
//!
//! A word that reads register r through an operand slot with the flag leaves the operand latched for the next
//! word that reads r through that slot. With r written between the two words that reader gets r's OLD content —
//! measured on two card models in two clock states (`tools/stallfloor/probe_sm120_20261111_b27.json` and its
//! `_ws_` files: every shape with a fixed-latency write, at every distance; the same text without the flag is
//! right). No scoreboard count sees it: the flag is not a barrier and no stall count repairs it.
//!
//! The walk: from every flagged read, along every path, to the next word that reads the register through the
//! same slot — with the flag or without; a write of the register on the way is a finding. A branch does not end
//! the window (that a taken branch ends the entry is a reading without a wait). The slot of an operand is the
//! flag bit its `.reuse` sets (122 / 123 / 124 = A / B / C), which the table gives per form — not the position
//! of the register field. A write that is reached only past a word of the slot that does not execute, or past a
//! word that takes the register as part of a wider operand, is counted apart: the vendor's own text has both.

use serde_json::Value;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("reuse_flag_{}_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst), tag));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

/// `cubit asm` of `text` under `env` in `dir`: (ok, stdout + stderr).
fn asm(dir: &std::path::Path, name: &str, text: &str, env: &[(&str, &str)]) -> (bool, String) {
    let src = dir.join(format!("{name}.sass"));
    std::fs::write(&src, text).unwrap();
    cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", dir.join(format!("{name}.cubin")).to_str().unwrap()], env)
}

/// A frozen kernel: every word carries its control field.
fn kernel(body: &[&str]) -> String {
    format!(".entry k\n    .reg R0-R95\n    .regcount 104\n    .param u64 p0 offset=0x0\n{}\n    [B------:R-:W-:Y:S05] EXIT ;\n.endentry\n", body.join("\n"))
}

/// The `REUSE FLAG:` lines of a log, trimmed.
fn lines(log: &str) -> Vec<&str> {
    log.lines().filter(|l| l.contains("REUSE FLAG:")).map(str::trim).collect()
}

/// `IADD3 R6 <- R5` with the flag on R5 (slot A), R5 written, `IADD3 R8 <- R5` through slot A.
const WRITTEN: [&str; 3] = [
    "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5.reuse, 0x1, RZ ;",
    "    [B------:R-:W-:Y:S03] MOV R5, R7 ;",
    "    [B------:R-:W-:Y:S02] IADD3 R8, PT, PT, R5, 0x2, RZ ;",
];

#[test]
fn a_register_written_inside_the_window_of_a_reuse_flag_is_reported_beside_the_three_counts() {
    let dir = scratch("cli");
    let text = kernel(&WRITTEN);
    // without CUBIT_VERIFY: not a word, and the same bytes
    let (ok, plain) = asm(&dir, "plain", &text, &[]);
    assert!(ok, "{plain}");
    assert!(!plain.contains("REUSE FLAG") && !plain.contains("CUBIT_VERIFY"), "{plain}");
    let (ok, log) = asm(&dir, "checked", &text, &[("CUBIT_VERIFY", "1")]);
    assert!(ok, "{log}");
    assert_eq!(
        lines(&log),
        ["REUSE FLAG: insn[0] IADD3 reads R5 through slot A with the flag; R5 <- written by insn[1] MOV before the next reader through that slot, insn[2] IADD3, 4 issue cycles behind the flagged word"],
        "{log}"
    );
    assert!(log.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale"), "{log}");
    assert!(
        log.lines().any(|l| l.starts_with(
            "CUBIT_VERIFY_REUSE: 1 register(s) read through a slot with the reuse flag and written before the next reader through that slot (1 flags on 1 words walked); not in the counts above"
        )),
        "{log}"
    );
    assert_eq!(std::fs::read(dir.join("plain.cubin")).unwrap(), std::fs::read(dir.join("checked.cubin")).unwrap(), "read-only");
    // the same text without the flag: nothing, not even a summary line
    let (ok, log) = asm(&dir, "cleared", &text.replace(".reuse", ""), &[("CUBIT_VERIFY", "1")]);
    assert!(ok, "{log}");
    assert!(!log.contains("REUSE"), "{log}");
    // the flag and no write: a clean window prints nothing
    let (ok, log) = asm(&dir, "clean", &kernel(&[WRITTEN[0], "    [B------:R-:W-:Y:S03] MOV R9, R7 ;", WRITTEN[2]]), &[("CUBIT_VERIFY", "1")]);
    assert!(ok, "{log}");
    assert!(!log.contains("REUSE"), "{log}");
    // the flagged word's own write counts: the next reader through the slot gets what the word read
    let own = kernel(&["    [B------:R-:W-:Y:S02] IADD3 R5, PT, PT, R5.reuse, 0x1, RZ ;", "    [B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R5, 0x3, RZ ;"]);
    let (ok, log) = asm(&dir, "own", &own, &[("CUBIT_VERIFY", "1")]);
    assert!(ok, "{log}");
    assert_eq!(
        lines(&log),
        ["REUSE FLAG: insn[0] IADD3 reads R5 through slot A with the flag; R5 <- written by insn[0] IADD3 (the flagged word itself) before the next reader through that slot, insn[1] IADD3, 2 issue cycles behind the flagged word"],
        "{log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_window_ends_at_the_next_reader_through_the_slot_flagged_or_not_and_not_at_a_branch() {
    let dir = scratch("window");
    let check = |name: &str, body: &[&str]| -> String {
        let (ok, log) = asm(&dir, name, &kernel(body), &[("CUBIT_VERIFY", "1")]);
        assert!(ok, "{log}");
        log
    };
    // an UNFLAGGED reader through the slot in front of the write ends the window: the write behind it is outside
    let log = check(
        "unflagged",
        &[
            "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5.reuse, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S01] IADD3 R8, PT, PT, R5, 0x2, RZ ;",
            "    [B------:R-:W-:Y:S01] MOV R5, R7 ;",
            "    [B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R5, 0x3, RZ ;",
        ],
    );
    assert!(!log.contains("REUSE"), "{log}");
    // ... a FLAGGED one ends it too, and starts its own, which holds the write
    let log = check(
        "flagged",
        &[
            "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5.reuse, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S01] IADD3 R8, PT, PT, R5.reuse, 0x2, RZ ;",
            "    [B------:R-:W-:Y:S01] MOV R5, R7 ;",
            "    [B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R5, 0x3, RZ ;",
        ],
    );
    assert_eq!(lines(&log).len(), 1, "{log}");
    assert!(lines(&log)[0].starts_with("REUSE FLAG: insn[1] IADD3 reads R5 through slot A with the flag; R5 <- written by insn[2] MOV"), "{log}");
    // another register through the slot does not end it, nor does a reader of the register through another slot
    let log = check(
        "other",
        &[
            "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5.reuse, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S01] IADD3 R8, PT, PT, R4, 0x2, RZ ;",
            "    [B------:R-:W-:Y:S01] IADD3 R10, PT, PT, R4, R5, RZ ;",
            "    [B------:R-:W-:Y:S01] MOV R5, R7 ;",
            "    [B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R5, 0x3, RZ ;",
        ],
    );
    assert_eq!(lines(&log).len(), 1, "{log}");
    assert!(lines(&log)[0].contains("R5 <- written by insn[3] MOV before the next reader through that slot, insn[4] IADD3, 4 issue cycles"), "{log}");
    // the write behind a TAKEN BRANCH: the window does not end at the branch
    let log = check(
        "branch",
        &[
            "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5.reuse, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S05] @P3 BRA L_w ;",
            "    [B------:R-:W-:Y:S01] IADD3 R8, PT, PT, R5, 0x2, RZ ;",
            "    [B------:R-:W-:Y:S05] EXIT ;",
            "L_w:",
            "    [B------:R-:W-:Y:S01] MOV R5, R7 ;",
            "    [B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R5, 0x3, RZ ;",
        ],
    );
    assert_eq!(
        lines(&log),
        ["REUSE FLAG: insn[0] IADD3 reads R5 through slot A with the flag; R5 <- written by insn[4] MOV before the next reader through that slot, insn[5] IADD3, 7 issue cycles behind the flagged word"],
        "{log}"
    );
    // a flag on a word without the yield flag is walked like any other
    let log = check(
        "noyield",
        &["    [B------:R-:W-:-:S01] IADD3 R6, PT, PT, R5.reuse, 0x1, RZ ;", "    [B------:R-:W-:Y:S03] MOV R5, R7 ;", "    [B------:R-:W-:Y:S02] IADD3 R8, PT, PT, R5, 0x2, RZ ;"],
    );
    assert_eq!(lines(&log).len(), 1, "{log}");
    assert!(log.lines().any(|l| l.starts_with("CUBIT_VERIFY_REUSE: 1 of the reuse flags on a word without the yield flag")), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_slot_of_an_operand_is_the_flag_bit_the_table_gives_it_not_the_position_of_its_field() {
    let dir = scratch("slot");
    let check = |name: &str, body: &[&str]| -> String {
        let (ok, log) = asm(&dir, name, &kernel(body), &[("CUBIT_VERIFY", "1")]);
        assert!(ok, "{log}");
        log
    };
    // the three slots by name: R78 through B, R13 through A and R58 through C, each written and read again
    // through its slot
    let log = check(
        "abc",
        &[
            "    [B------:R-:W-:Y:S01] IADD3 R58, PT, PT, R73, R78.reuse, RZ ;",
            "    [B------:R-:W-:Y:S01] PRMT R65, R13.reuse, 0x5140, R58.reuse ;",
            "    [B------:R-:W-:Y:S01] MOV R78, R7 ;",
            "    [B------:R-:W-:Y:S01] IADD3 R13, PT, PT, R14, 0x1, RZ ;",
            "    [B------:R-:W-:Y:S01] MOV R58, RZ ;",
            "    [B------:R-:W-:Y:S01] IADD3 R59, PT, PT, R73, R78, RZ ;",
            "    [B------:R-:W-:Y:S01] PRMT R66, R13, 0x5140, R58 ;",
        ],
    );
    let found: Vec<String> = lines(&log).iter().map(|l| l.split(" with the flag").next().unwrap().to_string()).collect();
    assert_eq!(
        found,
        [
            "REUSE FLAG: insn[0] IADD3 reads R78 through slot B",
            "REUSE FLAG: insn[1] PRMT reads R13 through slot A",
            "REUSE FLAG: insn[1] PRMT reads R58 through slot C",
        ],
        "{log}"
    );
    // `IMAD R, R, R, R` takes its third operand through slot B from the field at bit 32; `IMAD R, R, R, UR`
    // takes it through slot B from the field at bit 64 (the uniform register sits at bit 32): the second word is
    // the next reader through the slot of the first
    let log = check(
        "imad",
        &[
            "    [B------:R-:W-:Y:S01] IMAD R6, R4, R5.reuse, R9 ;",
            "    [B------:R-:W-:Y:S01] MOV R5, R7 ;",
            "    [B------:R-:W-:Y:S01] IMAD R8, R4, R5, UR2 ;",
        ],
    );
    assert_eq!(lines(&log).len(), 1, "{log}");
    assert!(lines(&log)[0].starts_with("REUSE FLAG: insn[0] IMAD reads R5 through slot B with the flag; R5 <- written by insn[1] MOV before the next reader through that slot, insn[2] IMAD"), "{log}");
    // ... and a word that takes the register from the field at bit 64 through slot C is not
    let log = check(
        "imad_c",
        &[
            "    [B------:R-:W-:Y:S01] IMAD R6, R4, R5.reuse, R9 ;",
            "    [B------:R-:W-:Y:S01] MOV R5, R7 ;",
            "    [B------:R-:W-:Y:S01] IMAD R8, R4, 0x3, R5 ;",
        ],
    );
    assert!(!log.contains("REUSE"), "{log}");
    // `FADD R, R, R`: the flag of the second source is bit 124 (slot C) on the field at bit 32
    let log = check(
        "fadd",
        &[
            "    [B------:R-:W-:Y:S01] FADD.FTZ R6, R4, R5.reuse ;",
            "    [B------:R-:W-:Y:S01] MOV R5, R7 ;",
            "    [B------:R-:W-:Y:S01] FADD.FTZ R8, R4, R5 ;",
        ],
    );
    assert_eq!(lines(&log).len(), 1, "{log}");
    assert!(lines(&log)[0].starts_with("REUSE FLAG: insn[0] FADD.FTZ reads R5 through slot C with the flag"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_write_behind_a_guarded_word_of_the_slot_is_counted_apart() {
    let dir = scratch("apart");
    // where `@P2 IADD3` executes it is the next reader (the window ends, nothing written yet); where it does not,
    // the write and the reader behind it are reached -- whether such a word takes the entry is not measured, and
    // the vendor's text has the shape: counted, no finding
    let text = kernel(&[
        "    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R5.reuse, 0x1, RZ ;",
        "    [B------:R-:W-:Y:S01] @P2 IADD3 R8, PT, PT, R5, 0x2, RZ ;",
        "    [B------:R-:W-:Y:S01] MOV R5, R7 ;",
        "    [B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R5, 0x3, RZ ;",
    ]);
    let file = dir.join("k.jsonl");
    let (ok, log) = asm(&dir, "k", &text, &[("CUBIT_VERIFY", "1"), ("CUBIT_VERIFY_JSON", file.to_str().unwrap())]);
    assert!(ok, "{log}");
    assert!(lines(&log).is_empty(), "{log}");
    assert!(
        log.lines().any(|l| l.starts_with("CUBIT_VERIFY_REUSE: counted apart, not findings") && l.ends_with("(0 of 1 flags clean on every path): guard 1")),
        "{log}"
    );
    let line: Value = serde_json::from_str(std::fs::read_to_string(&file).unwrap().lines().next().unwrap()).unwrap();
    let r = &line["reuse"];
    assert_eq!((&r["flags"], &r["rewritten"], &r["flags_rewritten"], &r["clean"]), (&1.into(), &0.into(), &0.into(), &0.into()), "{r}");
    assert_eq!((&r["apart"]["guard"], &r["flags_apart"]["guard"]), (&1.into(), &1.into()), "{r}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_json_line_carries_the_finding_and_legality_diff_refuses_a_candidate_with_a_write_inside_a_window() {
    let dir = scratch("json");
    let line = |name: &str, text: &str| -> (String, Value) {
        let file = dir.join(format!("{name}.jsonl"));
        let (ok, log) = asm(&dir, name, text, &[("CUBIT_VERIFY_JSON", file.to_str().unwrap())]);
        assert!(ok, "{log}");
        let text = std::fs::read_to_string(&file).unwrap();
        (file.to_str().unwrap().to_string(), serde_json::from_str(text.lines().next().unwrap()).unwrap())
    };
    // the seed: no flag -- the object is there and empty
    let (seed_file, seed) = line("seed", &kernel(&WRITTEN).replace(".reuse", ""));
    assert_eq!((&seed["reuse"]["flags"], &seed["reuse"]["rewritten"]), (&0.into(), &0.into()), "{seed}");
    assert!(seed["reuse"]["findings"].as_array().unwrap().is_empty(), "{seed}");
    // the candidate adds the flag in front of the write
    let (cand_file, cand) = line("cand", &kernel(&WRITTEN));
    let r = &cand["reuse"];
    assert_eq!((&r["flags"], &r["words"], &r["rewritten"], &r["flags_rewritten"], &r["clean"]), (&1.into(), &1.into(), &1.into(), &1.into(), &0.into()), "{r}");
    let f = r["findings"].as_array().unwrap();
    assert_eq!(f.len(), 1, "{cand}");
    assert_eq!(
        (f[0]["flagged"].as_u64(), f[0]["slot"].as_str(), f[0]["register"].as_str(), f[0]["writer"].as_u64(), f[0]["reader"].as_u64(), f[0]["distance"].as_u64(), f[0]["path"].as_str()),
        (Some(0), Some("A"), Some("R5"), Some(1), Some(2), Some(4), Some("straight"))
    );
    assert!(f[0]["flagged_text"].as_str().unwrap().contains("IADD3 R6, PT, PT, R5.reuse, 0x1, RZ"));
    assert!(f[0]["writer_text"].as_str().unwrap().contains("MOV R5, R7"));
    // the scoreboard counts do not know the class
    let sb = &cand["scoreboard"];
    assert_eq!((&sb["raw"], &sb["war"], &sb["recycle_stale"]), (&0.into(), &0.into(), &0.into()));
    let d = cubit::legality::compare(&seed, &cand);
    assert_eq!(d.new.iter().map(|x| (x.list, x.key.as_str())).collect::<Vec<_>>(), [("reuse", "reuse-flag straight [0] -> [2] R5 (slot A)")]);
    let (ok, log) = cubit(&["legality-diff", &seed_file, &cand_file], &[]);
    assert!(!ok && log.contains("new    reuse reuse-flag straight [0] -> [2] R5 (slot A):"), "{log}");
    let (ok, log) = cubit(&["legality-diff", &cand_file, &seed_file], &[]);
    assert!(ok, "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}
