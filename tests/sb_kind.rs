//! `CUBIT_SB_KIND=narrow | wide` (opt-in, 2026-11-18; with `CUBIT_WAIT_POLICY=1`): a use takes its scoreboard by
//! its kind (`scheduling_pass::SbKind`, KNOWN_ISSUES A65).
//!
//! The colouring gives every use the lowest scoreboard free over its flight, and a use that finds none shares the
//! busiest: read barriers end up where the results of global loads fly, and the read barrier of a load on the
//! scoreboard of the load's own result. Under the switch a read barrier never takes the scoreboard of its own
//! word's write barrier, the global loads take theirs from the top; `wide`: a read barrier joins the lowest
//! scoreboard on which no global load flies, free or not.
//!
//! The first five tests fail on the allocator without the clause (the variable is then unknown and changes
//! nothing); the last two are controls that pass on both.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const SYNC: (&str, &str) = ("CUBIT_SYNC_CLASSES", "1");
const POLICY: (&str, &str) = ("CUBIT_WAIT_POLICY", "1");
const NARROW: (&str, &str) = ("CUBIT_SB_KIND", "narrow");
const WIDE: (&str, &str) = ("CUBIT_SB_KIND", "wide");

/// One instruction of the schedule cubit wrote: (wait bits, read barrier, write barrier, the word).
#[derive(Debug, Clone, PartialEq)]
struct Word {
    wait: Vec<u8>,
    rb: Option<u8>,
    wb: Option<u8>,
    text: String,
}

/// `cubit asm` of a kernel under `env`: did it succeed, its log (both streams), the cubin's path.
fn asm(body: &str, env: &[(&str, &str)]) -> (bool, String, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("sbkind_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, format!(".entry sb_kind_probe\n    .reg R0-R63\n    .param ptr out\n{body}    EXIT ;\n.endentry\n")).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .expect("run cubit");
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)), dir)
}

/// `cubit asm` under `env`, then `cubit disassemble --frozen`: the words with their control fields, the cubin's
/// bytes, the log of the build.
fn build(body: &str, env: &[(&str, &str)]) -> (Vec<Word>, Vec<u8>, String) {
    let (ok, log, dir) = asm(body, env);
    assert!(ok, "asm under {env:?}: {log}");
    let out = dir.join("k.cubin");
    let o = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["disassemble", "--frozen", out.to_str().unwrap(), "-t", TABLE])
        .env_clear()
        .output()
        .expect("run cubit");
    assert!(o.status.success(), "disassemble: {}", String::from_utf8_lossy(&o.stderr));
    let listing = String::from_utf8_lossy(&o.stdout).into_owned();
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
        words.push(Word {
            wait: fields[0].bytes().filter(u8::is_ascii_digit).map(|b| b - b'0').collect(),
            rb: fields[1][1..].parse::<u8>().ok(),
            wb: fields[2][1..].parse::<u8>().ok(),
            text: tag[end + 1..].trim().trim_end_matches(';').trim().to_string(),
        });
    }
    (words, cubin, log)
}

fn word<'a>(k: &'a [Word], starts: &str) -> &'a Word {
    k.iter().find(|w| w.text.starts_with(starts)).unwrap_or_else(|| panic!("no word `{starts}` in {k:#?}"))
}

/// The clause's line of a build's log.
fn kind_line(log: &str) -> &str {
    log.lines().find(|l| l.contains("scoreboard by kind")).unwrap_or_else(|| panic!("no line of the clause in:\n{log}"))
}

const HEAD: &str = "    S2R R2, SR_TID.X ;
    SHF.L.U32 R60, R2, 0x2, RZ ;
    LDCU.64 UR8, c[0x0][0x358] ;
    LDC.64 R20, c[0x0][0x380] ;
    LDC.64 R22, c[0x0][0x388] ;
";

/// A global load and its reader.
fn load() -> String {
    format!("{HEAD}    LDG.E R4, desc[UR8][R20.64] ;\n    IADD3 R7, PT, PT, R4, R7, RZ ;\n")
}

#[test]
fn a_global_load_takes_the_highest_free_scoreboard() {
    let (plain, _, _) = build(&load(), &[SYNC, POLICY]);
    let low = word(&plain, "LDG.E R4").wb.expect("the load's write barrier");
    for mode in [NARROW, WIDE] {
        let (k, _, _) = build(&load(), &[SYNC, POLICY, mode]);
        assert_eq!(word(&k, "LDG.E R4").wb, Some(5), "under {mode:?} (without the switch: {low})");
        assert_eq!(word(&k, "IADD3 R7").wait, vec![5], "its reader waits there, under {mode:?}");
    }
    assert!(low < 5, "without the switch the lowest free: {low}");
}

/// A first store reads the descriptor and the base (their scoreboards are free behind it); then a shared load
/// whose result is read last, and in its flight a global store whose data is written again.
fn store_beside_a_shared_load() -> String {
    format!(
        "{HEAD}    STG.E desc[UR8][R22.64+0x8], R60 ;\n    LDS R10, [R60+0x100] ;\n    MOV R6, R60 ;\n    STG.E desc[UR8][R22.64], R6 ;\n    MOV R6, R11 ;\n    STG.E desc[UR8][R22.64+0x4], R6 ;\n    IADD3 R12, PT, PT, R10, R12, RZ ;\n"
    )
}

#[test]
fn under_wide_a_read_barrier_joins_the_lowest_scoreboard_without_a_global_load() {
    let text = store_beside_a_shared_load();
    let (plain, _, _) = build(&text, &[SYNC, POLICY]);
    let sb = word(&plain, "LDS R10").wb.expect("the shared load's write barrier");
    let rb = word(&plain, "STG.E desc[UR8][R22.64], R6").rb.expect("the store's read barrier");
    assert_eq!(sb, 0, "the shared load takes the lowest scoreboard");
    assert_ne!(rb, sb, "without the switch the read barrier takes a scoreboard that is free");
    let (k, _, _) = build(&text, &[SYNC, POLICY, WIDE]);
    assert_eq!(word(&k, "LDS R10").wb, Some(sb), "the shared load stays");
    assert_eq!(word(&k, "STG.E desc[UR8][R22.64], R6").rb, Some(sb), "the read barrier joins it: no global load flies there");
    assert_eq!(word(&k, "MOV R6, R11").wait, vec![sb], "the word that rewrites the store's data waits there");
    // `narrow` leaves the read barrier where a free scoreboard is
    let (n, _, _) = build(&text, &[SYNC, POLICY, NARROW]);
    assert_eq!(word(&n, "STG.E desc[UR8][R22.64], R6").rb, Some(rb));
}

/// A global load whose result is read last; in its flight a global store whose data is written again.
fn store_beside_a_global_load() -> String {
    format!(
        "{HEAD}    LDG.E R10, desc[UR8][R20.64] ;\n    MOV R6, R60 ;\n    STG.E desc[UR8][R22.64], R6 ;\n    MOV R6, R11 ;\n    STG.E desc[UR8][R22.64+0x4], R6 ;\n    IADD3 R12, PT, PT, R10, R12, RZ ;\n"
    )
}

#[test]
fn under_wide_no_read_barrier_stands_where_a_global_load_flies() {
    let text = store_beside_a_global_load();
    let (k, _, log) = build(&text, &[SYNC, POLICY, WIDE]);
    let g = word(&k, "LDG.E R10").wb.expect("the load's write barrier");
    let rb = word(&k, "STG.E desc[UR8][R22.64], R6").rb.expect("the store's read barrier");
    assert_eq!(g, 5, "the global load from the top");
    assert_eq!(rb, 0, "the read barrier from the bottom: {}", kind_line(&log));
    assert_eq!(word(&k, "MOV R6, R11").wait, vec![0]);
}

#[test]
fn the_line_of_the_clause_names_the_value_and_the_counts() {
    let (_, _, log) = build(&store_beside_a_global_load(), &[SYNC, POLICY, WIDE]);
    let l = kind_line(&log);
    assert!(l.contains("scoreboard by kind (wide): 1 read barrier(s) and 1 use(s) of global loads by the clause, ") && l.contains("; 0 went back for 0 use(s) of another kind that lost theirs"), "{l}");
    let (_, _, log) = build(&store_beside_a_global_load(), &[SYNC, POLICY, NARROW]);
    assert!(kind_line(&log).contains("scoreboard by kind (narrow): "), "{}", kind_line(&log));
}

#[test]
fn a_value_that_is_neither_is_refused() {
    let (ok, log, dir) = asm(&load(), &[SYNC, POLICY, ("CUBIT_SB_KIND", "both")]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!ok, "{log}");
    assert!(log.contains("CUBIT_SB_KIND=both: the values are `narrow`") && log.contains("`wide`"), "{log}");
}

#[test]
fn without_the_switch_every_scoreboard_stands_as_before() {
    for text in [load(), store_beside_a_shared_load(), store_beside_a_global_load()] {
        let (_, bytes, log) = build(&text, &[SYNC, POLICY]);
        assert!(!log.contains("scoreboard by kind"), "{log}");
        // unset, empty and `0` are one thing
        for off in ["", "0"] {
            let (_, b, _) = build(&text, &[SYNC, POLICY, ("CUBIT_SB_KIND", off)]);
            assert_eq!(b, bytes, "CUBIT_SB_KIND={off:?} is the allocator's schedule");
        }
        // honoured only with CUBIT_WAIT_POLICY=1
        let (_, alone, _) = build(&text, &[SYNC]);
        let (_, asked, _) = build(&text, &[SYNC, WIDE]);
        assert_eq!(asked, alone, "without the wait policy the variable changes nothing");
    }
}

#[test]
fn the_audit_names_no_rewrite_under_either_value() {
    for mode in [NARROW, WIDE] {
        for text in [store_beside_a_shared_load(), store_beside_a_global_load()] {
            let (_, _, log) = build(&text, &[SYNC, POLICY, mode, ("CUBIT_HAZ", "1")]);
            assert!(!log.contains("HAZ WAR") && !log.contains("HAZ RAW"), "under {mode:?}:\n{log}");
        }
    }
}
