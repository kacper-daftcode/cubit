//! `CUBIT_SB_KIND=narrow | wide` (opt-in, 2026-11-18; with `CUBIT_WAIT_POLICY=1`): a use takes its scoreboard by
//! its kind (`scheduling_pass::SbKind`, KNOWN_ISSUES A65).
//!
//! The colouring gives every use the lowest scoreboard free over its flight, and a use that finds none shares the
//! busiest: read barriers end up where the results of global loads fly, and the read barrier of a load on the
//! scoreboard of the load's own result. Under the switch a read barrier never takes the scoreboard of its own
//! word's write barrier, the global loads take theirs from the top; `wide`: a read barrier joins the lowest
//! scoreboard on which no global load flies, free or not.
//!
//! The first eleven tests fail on the allocator without the clause (the variable is then unknown and changes
//! nothing); the last two are controls that pass on both. Six of the eleven reach the trial and what stands
//! behind "nobody else pays": a word with both barriers, a load that finds no scoreboard free (the ladder), a use
//! that loses its scoreboard and has it again when the trial sends the taker back, the same beside
//! `CUBIT_CONST_ALONE`, and the two of the trial's limit -- a use goes back only for a use whose own scoreboard
//! the clause moved it onto: nothing goes back for a use the clause's uses did not push, and it is named and left.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const SYNC: (&str, &str) = ("CUBIT_SYNC_CLASSES", "1");
const POLICY: (&str, &str) = ("CUBIT_WAIT_POLICY", "1");
const NARROW: (&str, &str) = ("CUBIT_SB_KIND", "narrow");
const WIDE: (&str, &str) = ("CUBIT_SB_KIND", "wide");
const ALONE: (&str, &str) = ("CUBIT_CONST_ALONE", "1");

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
    assert!(l.contains("scoreboard by kind (wide): 1 read barrier(s) and 1 use(s) of global loads by the clause, ") && l.contains("; 0 went back for 0 use(s) of another kind that lost theirs; 0 still without a scoreboard of their own"), "{l}");
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

/// Two stores that read the descriptor and both bases: the scoreboards of the head's constants are free behind them.
const USED: &str = "    STG.E desc[UR8][R20.64+0x8], R60 ;\n    STG.E desc[UR8][R22.64+0x8], R60 ;\n";

/// `n` shared loads off lines that make no batch (`LDS R30` ...): each is a use of its own.
fn shared_loads(n: usize) -> String {
    (0..n).map(|i| format!("    LDS R{}, [R60+0x{:x}] ;\n", 30 + i, 0x100 * (i + 1))).collect()
}

/// One reader a register of `regs`, in that order: `IADD3 R<r - 22>, PT, PT, R<r>, R<r - 22>, RZ`.
fn readers(regs: &[u8]) -> String {
    regs.iter().map(|r| format!("    IADD3 R{0}, PT, PT, R{r}, R{0}, RZ ;\n", r - 22)).collect()
}

/// Three shared loads and the head's two constant uses are in flight when a global load is issued: its result
/// takes the sixth scoreboard and is read last; its address is written again inside that flight, behind the
/// readers of the shared loads -- the load's read barrier finds no scoreboard free at its turn.
fn load_with_both_barriers() -> String {
    format!("{HEAD}{}    LDG.E R36, desc[UR8][R22.64] ;\n{}    MOV R22, R60 ;\n{}", shared_loads(3), readers(&[30, 31, 32]), readers(&[36]))
}

#[test]
fn a_read_barrier_never_takes_the_scoreboard_of_its_own_words_write_barrier() {
    let text = load_with_both_barriers();
    let (plain, _, _) = build(&text, &[SYNC, POLICY]);
    let w = word(&plain, "LDG.E R36");
    assert_eq!((w.rb, w.wb), (Some(5), Some(5)), "without the switch the read barrier shares the busiest scoreboard: the one of the load's own result");
    // `narrow`: the busiest of the others; `wide`: the lowest without a global load in flight
    for (mode, rb) in [(NARROW, 4), (WIDE, 0)] {
        let (k, _, log) = build(&text, &[SYNC, POLICY, mode]);
        let w = word(&k, "LDG.E R36");
        assert_eq!(w.wb, Some(5), "under {mode:?}");
        assert_eq!(w.rb, Some(rb), "under {mode:?}: {}", kind_line(&log));
        assert_eq!(word(&k, "MOV R22").wait, vec![rb], "the word that rewrites the address waits the read barrier, under {mode:?}");
        assert_eq!(word(&k, "IADD3 R14").wait, vec![5], "the reader waits the result, under {mode:?}");
    }
}

/// Four shared loads in flight, then four global loads of two forms, every result read behind the last load: the
/// third and the fourth global load find no scoreboard free.
fn loads_of_two_forms() -> String {
    format!(
        "{HEAD}{USED}{}    LDG.E.CONSTANT R36, desc[UR8][R20.64] ;\n    LDG.E R37, desc[UR8][R22.64] ;\n    LDG.E R38, desc[UR8][R22.64+0x100] ;\n    LDG.E.CONSTANT R39, desc[UR8][R20.64+0x100] ;\n{}",
        shared_loads(4),
        readers(&[30, 31, 32, 33, 36, 37, 38, 39])
    )
}

#[test]
fn a_global_load_that_finds_no_scoreboard_free_joins_the_loads_of_its_own_form() {
    let text = loads_of_two_forms();
    let wbs = |k: &[Word]| ["LDG.E.CONSTANT R36", "LDG.E R37", "LDG.E R38", "LDG.E.CONSTANT R39"].map(|w| word(k, w).wb.unwrap_or_else(|| panic!("no write barrier on `{w}`")));
    let (plain, _, _) = build(&text, &[SYNC, POLICY]);
    // without the switch: the lowest free, then the busiest -- three loads of two forms on one scoreboard
    assert_eq!(wbs(&plain), [4, 5, 5, 5]);
    for mode in [NARROW, WIDE] {
        let (k, _, log) = build(&text, &[SYNC, POLICY, mode]);
        let l = kind_line(&log);
        // from the top; a load that finds none free joins the load of its own form
        assert_eq!(wbs(&k), [5, 4, 4, 5], "under {mode:?}: {l}");
        assert!(l.contains("0 read barrier(s) and 4 use(s) of global loads by the clause, 3 of them on another scoreboard than without it; 0 went back for 0 use(s)"), "under {mode:?}: {l}");
        // no shared load moves, and the readers wait where their loads stand
        for r in 30..34 {
            assert_eq!(word(&k, &format!("LDS R{r}")).wb, word(&plain, &format!("LDS R{r}")).wb, "under {mode:?}");
        }
        assert_eq!((word(&k, "IADD3 R16").wait.clone(), word(&k, "IADD3 R17").wait.clone()), (vec![4], vec![5]), "under {mode:?}");
    }
}

/// Five shared loads in flight, then two global loads of one form; the first is read at once, and behind its
/// reader a sixth shared load is issued that is read last. Without the switch the second global load finds no
/// scoreboard free and shares the busiest; the sixth shared load takes the scoreboard the first global load left.
fn taker_and_loser() -> String {
    format!(
        "{HEAD}{USED}{}    LDG.E R36, desc[UR8][R20.64] ;\n    LDG.E R37, desc[UR8][R22.64] ;\n{}    LDS R35, [R60+0x600] ;\n{}",
        shared_loads(5),
        readers(&[36]),
        readers(&[30, 31, 32, 33, 34, 37, 35])
    )
}

#[test]
fn a_use_that_lost_its_scoreboard_has_it_again_when_the_trial_sends_the_taker_back() {
    let text = taker_and_loser();
    let (plain, _, _) = build(&text, &[SYNC, POLICY]);
    assert_eq!((word(&plain, "LDG.E R36").wb, word(&plain, "LDG.E R37").wb, word(&plain, "LDS R35").wb), (Some(5), Some(4), Some(5)));
    for mode in [NARROW, WIDE] {
        // by the clause the second global load joins the first on 5 (its own form) and flies there across the
        // flight of `LDS R35`, which finds none free: the trial sends the global load back
        let (k, _, log) = build(&text, &[SYNC, POLICY, mode]);
        let l = kind_line(&log);
        assert!(
            l.contains("0 read barrier(s) and 1 use(s) of global loads by the clause, 0 of them on another scoreboard than without it; 1 went back for 1 use(s) of another kind that lost theirs: wb[15]; 0 still without a scoreboard of their own"),
            "under {mode:?}: {l}"
        );
        assert_eq!(word(&k, "LDS R35").wb, Some(5), "the shared load has its scoreboard again, under {mode:?}");
        assert_eq!(word(&k, "LDG.E R37").wb, Some(4), "the global load that went back stands as without the switch, under {mode:?}");
        assert_eq!(k, plain, "under {mode:?} every control field is the allocator's");
    }
}

#[test]
fn beside_const_alone_the_trial_runs_on_the_batches_taken_apart() {
    let text = taker_and_loser();
    // the two constant loads of the head are one batch on one scoreboard; `CUBIT_CONST_ALONE` takes them apart
    let (batch, _, _) = build(&text, &[SYNC, POLICY]);
    assert_eq!(word(&batch, "LDC.64 R20").wb, word(&batch, "LDC.64 R22").wb);
    let (alone, _, _) = build(&text, &[SYNC, POLICY, ALONE]);
    assert_ne!(word(&alone, "LDC.64 R20").wb, word(&alone, "LDC.64 R22").wb);
    for mode in [NARROW, WIDE] {
        let (k, _, log) = build(&text, &[SYNC, POLICY, ALONE, mode]);
        let l = kind_line(&log);
        assert!(l.contains("1 went back for 1 use(s) of another kind that lost theirs: wb[15]; 0 still without a scoreboard of their own"), "under {mode:?}: {l}");
        assert_eq!(k, alone, "under {mode:?} beside CUBIT_CONST_ALONE every control field is the one of CUBIT_CONST_ALONE alone");
    }
}

/// A global store whose data is written again (its read barrier flies up to that word), five shared loads, a
/// global load that is read first, and behind the word that rewrites the store's data a sixth shared load.
/// Without the switch the read barrier holds a scoreboard, the global load finds none free and shares, and the
/// sixth shared load takes the scoreboard the read barrier left.
fn load_beside_a_joined_read_barrier() -> String {
    format!(
        "{HEAD}    STG.E desc[UR8][R20.64+0x8], R60 ;\n    MOV R6, R60 ;\n    STG.E desc[UR8][R22.64], R6 ;\n{}    LDG.E R36, desc[UR8][R20.64] ;\n    MOV R6, R2 ;\n    LDS R35, [R60+0x600] ;\n{}",
        shared_loads(5),
        readers(&[36, 30, 31, 32, 33, 34, 35])
    )
}

/// The trial's limit (KNOWN_ISSUES A65): a use goes back only for a use whose own scoreboard the clause moved it
/// onto. Here the global load takes the top scoreboard, not the one the shared load has without the switch:
/// nothing goes back, the shared load is named and left.
#[test]
fn under_wide_nothing_goes_back_for_a_use_whose_scoreboard_the_clause_gave_to_nobody() {
    let text = load_beside_a_joined_read_barrier();
    let (plain, _, _) = build(&text, &[SYNC, POLICY]);
    assert_eq!((word(&plain, "STG.E desc[UR8][R22.64], R6").rb, word(&plain, "LDG.E R36").wb, word(&plain, "LDS R35").wb), (Some(0), Some(1), Some(0)));
    // `wide`: the read barrier joins scoreboard 0 and keeps nothing busy, the five shared loads take 0 .. 4, the
    // global load takes 5 -- and `LDS R35` finds none free. Its own scoreboard, 0, carries a shared load now and no
    // use the clause moved: the trial sends nothing back (sent back, the global load would take 5 again -- the read
    // barrier that made it share holds nothing now), and the line names the shared load.
    let (k, _, log) = build(&text, &[SYNC, POLICY, WIDE]);
    let l = kind_line(&log);
    assert!(
        l.contains("1 read barrier(s) and 1 use(s) of global loads by the clause, 1 of them on another scoreboard than without it; 0 went back for 1 use(s) of another kind that lost theirs: wb[15]; 1 still without a scoreboard of their own: wb[15]"),
        "{l}"
    );
    assert_eq!(word(&k, "LDG.E R36").wb, Some(5));
    assert_eq!(word(&k, "LDS R35").wb, word(&k, "LDS R34").wb, "it shares the scoreboard of the shared load in front of it");
    assert_eq!(word(&k, "IADD3 R13").wait, word(&k, "IADD3 R12").wait, "and its reader waits there");
    // `narrow`: the read barrier holds its scoreboard as without the switch -- nothing is lost
    let (n, _, log) = build(&text, &[SYNC, POLICY, NARROW]);
    assert!(kind_line(&log).contains("0 went back for 0 use(s) of another kind that lost theirs; 0 still without a scoreboard of their own"), "{}", kind_line(&log));
    assert_eq!(n, plain, "under `narrow` every control field is the allocator's");
}

/// The head of a kernel in small: a store whose data is written again early (its read barrier holds 2 without the
/// switch and frees it for the last shared load), a shared load on 0, a second store whose data is written again
/// at the very end (its read barrier holds 1 across everything), four shared loads, a global load, and behind
/// the first rewriter one more shared load. Without the switch the fourth of the four shared loads and the global
/// load find no scoreboard free; the last shared load takes 2.
fn long_read_barrier_across_a_crowd() -> String {
    format!(
        "{HEAD}    MOV R6, R60 ;\n    STG.E desc[UR8][R20.64+0x8], R6 ;\n    LDS R34, [R60+0x700] ;\n    MOV R7, R60 ;\n    STG.E desc[UR8][R22.64], R7 ;\n{}    LDG.E R36, desc[UR8][R20.64] ;\n    MOV R6, R2 ;\n    LDS R35, [R60+0x600] ;\n{}    MOV R7, R2 ;\n",
        shared_loads(4),
        readers(&[36, 30, 31, 32, 33, 34, 35])
    )
}

#[test]
fn under_wide_no_read_barrier_goes_back_for_a_use_it_did_not_push() {
    let text = long_read_barrier_across_a_crowd();
    let (plain, _, _) = build(&text, &[SYNC, POLICY]);
    assert_eq!((word(&plain, "STG.E desc[UR8][R22.64], R7").rb, word(&plain, "LDS R35").wb), (Some(1), Some(2)));
    // `wide`: both read barriers join scoreboard 0 and keep nothing busy, the five shared loads in flight take
    // 0 .. 4, the global load takes 5, and `LDS R35` finds none free. Its own scoreboard, 2, carries a shared load.
    // Nothing goes back: the long read barrier stays on 0 -- sent back it would take scoreboard 1 and keep it busy
    // across the kernel, and the global load would lose the scoreboard the clause gave it.
    let (k, _, log) = build(&text, &[SYNC, POLICY, WIDE]);
    let l = kind_line(&log);
    assert!(l.contains("; 0 went back for 1 use(s) of another kind that lost theirs: wb[16]; 1 still without a scoreboard of their own: wb[16]"), "{l}");
    assert_eq!(word(&k, "STG.E desc[UR8][R22.64], R7").rb, Some(0), "the long read barrier stays where no global load flies");
    assert_eq!(word(&k, "LDG.E R36").wb, Some(5), "the global load keeps the top scoreboard");
    assert!(k.iter().all(|w| w.wb != Some(5) || w.text.starts_with("LDG.E R36")), "and keeps it to itself: {k:#?}");
    // `narrow`: both read barriers hold their scoreboards as without the switch -- nothing is lost
    let (n, _, log) = build(&text, &[SYNC, POLICY, NARROW]);
    assert!(kind_line(&log).contains("0 went back for 0 use(s) of another kind that lost theirs; 0 still without a scoreboard of their own"), "{}", kind_line(&log));
    assert_eq!(n, plain, "under `narrow` every control field is the allocator's");
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
        for text in [
            store_beside_a_shared_load(),
            store_beside_a_global_load(),
            load_with_both_barriers(),
            loads_of_two_forms(),
            taker_and_loser(),
            load_beside_a_joined_read_barrier(),
            long_read_barrier_across_a_crowd(),
        ] {
            let (_, _, log) = build(&text, &[SYNC, POLICY, mode, ("CUBIT_HAZ", "1")]);
            assert!(!log.contains("HAZ WAR") && !log.contains("HAZ RAW"), "under {mode:?}:\n{log}");
        }
    }
}
