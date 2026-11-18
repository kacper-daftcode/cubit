//! `CUBIT_DEP_CELLS_GUARD` — the cell kind `guard-settled` of the dump `CUBIT_DEP_CELLS` (2026-11-18).
//!
//! A load arms a write barrier and the readers of its register wait on it — but not every reader carries the
//! wait bit: the first readers of a path wait, the readers behind them rest on that wait. A read that has no bit
//! of its own and stands behind waiters that are all under a guard (`@P0 …`) is covered by the wait only if a
//! wait carried by a word whose guard is false is honoured; otherwise it rests on the plain distance to its
//! producer. The vendor writes such reads, and so does cubit: its default leaves the readers behind a guarded
//! overwriter that waited without a wait of their own, and `CUBIT_GUARDED_READER_SETTLES=1` lets a guarded first
//! reader settle the barrier. Until now no dump named them: `CUBIT_DEP_CELLS` prints a distance cell for a
//! producer of a fixed latency only, and a load's readers got none — a tool that wants to count the reads of this
//! kind whose distance is below the distance another schedule of the same text gives the pair had nothing to
//! count from.
//!
//! Now: `CUBIT_DEP_CELLS_GUARD=1` adds to the file `CUBIT_DEP_CELLS` names one line per such read — kind
//! `guard-settled`, role `guarded`: `prod` the word that arms the barrier, `cons` the reader, `via` the first
//! guarded word that waits the barrier between them, `have` the tightest issue distance producer → reader over the
//! paths on which only guarded words wait between them, `need` 0 (no row of the table asks for a distance here).
//! `CUBIT_DEP_CELLS_GUARD=all` adds the other covers as kind `barrier-read` — role `own` (the reader waits
//! itself), `unguarded` (a word under no guard waits between them), `none` (no word waits between them), and
//! `bare` (the producer is a word the scheduler would scoreboard and the text gives it no barrier: the vendor
//! leaves loads bare) — so that the distance of the same pair in another schedule is one lookup whatever its cover
//! is there. The switch is the dump's alone: it is read-only, works on a frozen listing as on a schedule cubit
//! builds, and without it the dump and every build are what they were.

use serde_json::Value;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

/// What one `cubit asm` of `text` under `env` gives: the build's success and log, the dump's text, the cubin.
struct Run {
    ok: bool,
    log: String,
    dump: String,
    cubin: Vec<u8>,
}

fn run(text: &str, env: &[(&str, &str)]) -> Run {
    let dir = std::env::temp_dir().join(format!("guard_cells_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out, cells) = (dir.join("k.sass"), dir.join("k.cubin"), dir.join("cells.jsonl"));
    std::fs::write(&src, text).unwrap();
    let mut e = env.to_vec();
    e.push(("CUBIT_DEP_CELLS", cells.to_str().unwrap()));
    let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()], &e);
    let r = Run {
        ok,
        log,
        dump: std::fs::read_to_string(&cells).unwrap_or_default(),
        cubin: std::fs::read(&out).unwrap_or_default(),
    };
    let _ = std::fs::remove_dir_all(&dir);
    r
}

/// The lines of the new kinds in a dump: (kind, role, prod, cons, via, have, need).
type Cell = (String, String, u64, u64, Option<u64>, u64, u64);

fn cells(text: &str, env: &[(&str, &str)]) -> Vec<Cell> {
    let r = run(text, env);
    assert!(r.ok, "asm {env:?} failed:\n{}", r.log);
    let mut out: Vec<Cell> = r
        .dump
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap_or_else(|e| panic!("a line of the dump is not JSON ({e}): {l}")))
        .filter(|v| matches!(v["kind"].as_str(), Some("guard-settled" | "barrier-read")))
        .map(|v| {
            assert_eq!(v["defaulted"], Value::Bool(false), "{v}");
            assert!(v["pc"].as_str().is_some_and(|s| !s.is_empty()) && v["cc"].as_str().is_some_and(|s| !s.is_empty()), "{v}");
            (
                v["kind"].as_str().unwrap().to_string(),
                v["role"].as_str().unwrap().to_string(),
                v["prod"].as_u64().unwrap(),
                v["cons"].as_u64().unwrap(),
                v["via"].as_u64(),
                v["have"].as_u64().unwrap(),
                v["need"].as_u64().unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

fn cell(kind: &str, role: &str, prod: u64, cons: u64, via: Option<u64>, have: u64) -> Cell {
    (kind.to_string(), role.to_string(), prod, cons, via, have, 0)
}

const ONE: &[(&str, &str)] = &[("CUBIT_DEP_CELLS_GUARD", "1")];
const ALL: &[(&str, &str)] = &[("CUBIT_DEP_CELLS_GUARD", "all")];

/// A frozen listing: the load `[4]` arms scoreboard 2, the guarded `[5]` waits it, `[6]` reads the register
/// with no wait of its own.
const BEHIND_A_GUARDED_WAITER: &str = "\
.entry guard_probe
    .reg R0-R31
    .param u64 p0 offset=0x0
    [B------:R-:W0:Y:S01] LDCU.64 UR4, c[0x0][0x358] ;
    [B------:R-:W1:Y:S01] LDC.64 R0, c[0x0][0x380] ;
    [B------:R-:W-:Y:S07] S2R R3, SR_TID.X ;
    [B------:R-:W-:-:S13] ISETP.NE.U32.AND P0, PT, R3, RZ, PT ;
    [B01----:R-:W2:Y:S02] LDG.E R2, desc[UR4][R0.64] ;
    [B--2---:R-:W-:-:S03] @P0 VIMNMX.S32 R18, R2, RZ, !PT ;
    [B------:R-:W-:-:S04] IADD3 R19, PT, PT, R2, 0x10, RZ ;
    [B------:R-:W-:Y:S01] STG.E desc[UR4][R0.64], R19 ;
    [B------:R-:W-:Y:S05] EXIT ;
.endentry
";

/// The same words with the unguarded reader in front: it waits, the guarded reader behind it does not.
const BEHIND_AN_UNGUARDED_WAITER: &str = "\
.entry guard_probe
    .reg R0-R31
    .param u64 p0 offset=0x0
    [B------:R-:W0:Y:S01] LDCU.64 UR4, c[0x0][0x358] ;
    [B------:R-:W1:Y:S01] LDC.64 R0, c[0x0][0x380] ;
    [B------:R-:W-:Y:S07] S2R R3, SR_TID.X ;
    [B------:R-:W-:-:S13] ISETP.NE.U32.AND P0, PT, R3, RZ, PT ;
    [B01----:R-:W2:Y:S02] LDG.E R2, desc[UR4][R0.64] ;
    [B--2---:R-:W-:-:S04] IADD3 R19, PT, PT, R2, 0x10, RZ ;
    [B------:R-:W-:-:S03] @P0 VIMNMX.S32 R18, R2, RZ, !PT ;
    [B------:R-:W-:Y:S01] STG.E desc[UR4][R0.64], R19 ;
    [B------:R-:W-:Y:S05] EXIT ;
.endentry
";

/// Two paths from the load `[4]` to the reader `[9]`: the fall-through with an unguarded waiter (`[6]`), the
/// taken arm with a guarded one (`[8]`).
const TWO_PATHS: &str = "\
.entry guard_probe
    .reg R0-R31
    .param u64 p0 offset=0x0
    [B------:R-:W0:Y:S01] LDCU.64 UR4, c[0x0][0x358] ;
    [B------:R-:W1:Y:S01] LDC.64 R0, c[0x0][0x380] ;
    [B------:R-:W-:Y:S07] S2R R3, SR_TID.X ;
    [B------:R-:W-:-:S13] ISETP.NE.U32.AND P0, PT, R3, RZ, PT ;
    [B01----:R-:W2:Y:S02] LDG.E R2, desc[UR4][R0.64] ;
    [B------:R-:W-:Y:S05] @P0 BRA L_arm ;
    [B--2---:R-:W-:-:S01] MOV R5, R2 ;
    [B------:R-:W-:Y:S06] BRA L_join ;
L_arm:
    [B--2---:R-:W-:-:S03] @P1 MOV R6, R2 ;
L_join:
    [B------:R-:W-:-:S04] IADD3 R19, PT, PT, R2, 0x10, RZ ;
    [B------:R-:W-:Y:S01] STG.E desc[UR4][R0.64], R19 ;
    [B------:R-:W-:Y:S05] EXIT ;
.endentry
";

/// No word waits scoreboard 2 between the load `[4]` and its reader `[5]`.
const NO_WAITER: &str = "\
.entry guard_probe
    .reg R0-R31
    .param u64 p0 offset=0x0
    [B------:R-:W0:Y:S01] LDCU.64 UR4, c[0x0][0x358] ;
    [B------:R-:W1:Y:S01] LDC.64 R0, c[0x0][0x380] ;
    [B------:R-:W-:Y:S07] S2R R3, SR_TID.X ;
    [B------:R-:W-:-:S13] ISETP.NE.U32.AND P0, PT, R3, RZ, PT ;
    [B01----:R-:W2:Y:S09] LDG.E R2, desc[UR4][R0.64] ;
    [B------:R-:W-:-:S04] IADD3 R19, PT, PT, R2, 0x10, RZ ;
    [B------:R-:W-:Y:S01] STG.E desc[UR4][R0.64], R19 ;
    [B------:R-:W-:Y:S05] EXIT ;
.endentry
";

/// The load `[4]` carries no write barrier (the vendor's practice where the readers stand far behind it).
const BARE_LOAD: &str = "\
.entry guard_probe
    .reg R0-R31
    .param u64 p0 offset=0x0
    [B------:R-:W0:Y:S01] LDCU.64 UR4, c[0x0][0x358] ;
    [B------:R-:W1:Y:S01] LDC.64 R0, c[0x0][0x380] ;
    [B------:R-:W-:Y:S07] S2R R3, SR_TID.X ;
    [B------:R-:W-:-:S13] ISETP.NE.U32.AND P0, PT, R3, RZ, PT ;
    [B01----:R-:W-:-:S15] LDG.E R2, desc[UR4][R0.64] ;
    [B------:R-:W-:-:S03] @P0 VIMNMX.S32 R18, R2, RZ, !PT ;
    [B------:R-:W-:-:S04] IADD3 R19, PT, PT, R2, 0x10, RZ ;
    [B------:R-:W-:Y:S01] STG.E desc[UR4][R0.64], R19 ;
    [B------:R-:W-:Y:S05] EXIT ;
.endentry
";

/// For cubit's own scheduler (the text of `tests/needs37_guarded_reader.rs`): a load whose first reader is
/// guarded, an unguarded reader behind it.
const GUARDED_FIRST_READER: &str = "\
.entry guarded_first_reader
    .reg R0-R31
    .param u64 p0 offset=0x0
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R0, c[0x0][0x380] ;
    S2R R3, SR_TID.X ;
    ISETP.NE.U32.AND P0, PT, R3, RZ, PT ;
    LDG.E R2, desc[UR4][R0.64] ;
    @P0 VIMNMX.S32 R18, R2, RZ, !PT ;
    IADD3 R19, PT, PT, R2, 0x10, RZ ;
    STG.E desc[UR4][R0.64], R19 ;
    EXIT ;
.endentry
";

/// For cubit's own scheduler: the register of the load `[4]` is rewritten under a guard (`[5]`), then read.
const GUARDED_OVERWRITER: &str = "\
.entry guarded_overwriter
    .reg R0-R31
    .param u64 p0 offset=0x0
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R0, c[0x0][0x380] ;
    S2R R3, SR_TID.X ;
    ISETP.NE.U32.AND P0, PT, R3, RZ, PT ;
    LDG.E R2, desc[UR4][R0.64] ;
    @P0 MOV R2, R3 ;
    IADD3 R19, PT, PT, R2, 0x10, RZ ;
    STG.E desc[UR4][R0.64], R19 ;
    EXIT ;
.endentry
";

#[test]
fn a_read_behind_a_guarded_waiter_alone_is_one_guard_settled_cell() {
    // the load [4] (stall 2), the guarded waiter [5] (stall 3), the reader [6]: 2 + 3 issue cycles behind the load
    assert_eq!(cells(BEHIND_A_GUARDED_WAITER, ONE), vec![cell("guard-settled", "guarded", 4, 6, Some(5), 5)]);
    // `all`: the same cell among the other covers -- the waiter itself, the readers of the two constant loads
    // ([0] UR4: 22 cycles to the load that waits it, 31 to the store behind that wait; [1] R0: 21 | 30), and the
    // reader of the special-register read [2], which this text leaves without a barrier
    assert_eq!(
        cells(BEHIND_A_GUARDED_WAITER, ALL),
        vec![
            cell("barrier-read", "bare", 2, 3, None, 7),
            cell("barrier-read", "own", 0, 4, Some(4), 22),
            cell("barrier-read", "own", 1, 4, Some(4), 21),
            cell("barrier-read", "own", 4, 5, Some(5), 2),
            cell("barrier-read", "unguarded", 0, 7, Some(4), 31),
            cell("barrier-read", "unguarded", 1, 7, Some(4), 30),
            cell("guard-settled", "guarded", 4, 6, Some(5), 5),
        ]
    );
}

#[test]
fn a_reader_behind_an_unguarded_waiter_is_no_guard_settled_cell() {
    assert_eq!(cells(BEHIND_AN_UNGUARDED_WAITER, ONE), vec![]);
    let all = cells(BEHIND_AN_UNGUARDED_WAITER, ALL);
    assert!(all.contains(&cell("barrier-read", "own", 4, 5, Some(5), 2)), "{all:?}");
    assert!(all.contains(&cell("barrier-read", "unguarded", 4, 6, Some(5), 6)), "{all:?}");
    assert!(all.iter().all(|c| c.0 == "barrier-read"), "{all:?}");
}

#[test]
fn a_reader_has_one_cell_a_cover_with_the_tightest_distance_of_its_paths() {
    // [4] -> [5] taken -> [8] (guarded waiter) -> [9]: 2 + 5 + 3 = 10; [4] -> [5] -> [6] (unguarded waiter) -> [7] -> [9]: 2 + 5 + 1 + 6 = 14
    assert_eq!(cells(TWO_PATHS, ONE), vec![cell("guard-settled", "guarded", 4, 9, Some(8), 10)]);
    let all = cells(TWO_PATHS, ALL);
    for c in [
        cell("barrier-read", "own", 4, 6, Some(6), 7),
        cell("barrier-read", "own", 4, 8, Some(8), 7),
        cell("barrier-read", "unguarded", 4, 9, Some(6), 14),
        cell("guard-settled", "guarded", 4, 9, Some(8), 10),
    ] {
        assert!(all.contains(&c), "{c:?} is not in {all:?}");
    }
    assert_eq!(all.iter().filter(|c| c.2 == 4).count(), 4, "four cells behind the load: {all:?}");
}

#[test]
fn a_reader_no_word_waits_for_is_the_cover_none_and_no_guard_settled_cell() {
    assert_eq!(cells(NO_WAITER, ONE), vec![]);
    let all = cells(NO_WAITER, ALL);
    assert!(all.contains(&cell("barrier-read", "none", 4, 5, None, 9)), "{all:?}");
}

#[test]
fn the_readers_of_a_load_the_text_leaves_bare_are_lines_of_all_alone() {
    // no barrier, no wait: nothing rests on a guard -- and `all` names both readers with their distance,
    // so that a schedule that arms this load finds the pair in this text's dump
    assert_eq!(cells(BARE_LOAD, ONE), vec![]);
    let all = cells(BARE_LOAD, ALL);
    assert!(all.contains(&cell("barrier-read", "bare", 4, 5, None, 15)), "{all:?}");
    assert!(all.contains(&cell("barrier-read", "bare", 4, 6, None, 18)), "{all:?}");
    assert!(all.iter().all(|c| c.0 == "barrier-read"), "{all:?}");
}

#[test]
fn cubits_schedule_has_the_cell_where_a_guarded_first_reader_settles_the_barrier() {
    // the default: both readers of the load wait its barrier -- no read rests on the guarded one
    assert_eq!(cells(GUARDED_FIRST_READER, ONE), vec![]);
    let all = cells(GUARDED_FIRST_READER, ALL);
    assert!(all.iter().any(|c| (c.1.as_str(), c.2, c.3) == ("own", 4, 5)) && all.iter().any(|c| (c.1.as_str(), c.2, c.3) == ("own", 4, 6)), "{all:?}");
    // CUBIT_GUARDED_READER_SETTLES=1: the guarded first reader settles it, the reader behind it rests on that wait
    let settles = [("CUBIT_GUARDED_READER_SETTLES", "1"), ("CUBIT_DEP_CELLS_GUARD", "1")];
    let got = cells(GUARDED_FIRST_READER, &settles);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!((got[0].0.as_str(), got[0].1.as_str(), got[0].2, got[0].3, got[0].4), ("guard-settled", "guarded", 4, 6, Some(5)), "{got:?}");
}

#[test]
fn cubits_default_schedule_has_the_cell_behind_a_guarded_overwriter() {
    // the guarded overwriter of the load's register waits its barrier, and the reader behind it carries no wait:
    // if the guard is false the reader reads the load's result on the overwriter's wait alone
    let got = cells(GUARDED_OVERWRITER, ONE);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!((got[0].0.as_str(), got[0].1.as_str(), got[0].2, got[0].3, got[0].4), ("guard-settled", "guarded", 4, 6, Some(5)), "{got:?}");
}

#[test]
fn the_switch_is_the_dumps_alone_and_without_it_the_dump_is_what_it_was() {
    for text in [BEHIND_A_GUARDED_WAITER, TWO_PATHS, GUARDED_FIRST_READER, GUARDED_OVERWRITER] {
        let plain = run(text, &[]);
        assert!(plain.ok && !plain.cubin.is_empty(), "{}", plain.log);
        assert!(!plain.dump.contains("guard-settled") && !plain.dump.contains("barrier-read"), "no such line without the switch:\n{}", plain.dump);
        for env in [ONE, ALL, &[("CUBIT_DEP_CELLS_GUARD", "0")][..], &[("CUBIT_DEP_CELLS_GUARD", "")][..]] {
            let with = run(text, env);
            assert!(with.ok, "{}", with.log);
            assert_eq!(with.cubin, plain.cubin, "{env:?}: the switch moves no word");
            assert!(with.dump.starts_with(&plain.dump), "{env:?}: the dump's other lines stand as they were, the new ones behind them");
            if env[0].1.is_empty() || env[0].1 == "0" {
                assert_eq!(with.dump, plain.dump, "{env:?} is no switch");
            }
        }
    }
}

#[test]
fn a_value_that_is_no_value_of_the_switch_is_refused() {
    let r = run(BEHIND_A_GUARDED_WAITER, &[("CUBIT_DEP_CELLS_GUARD", "yes")]);
    assert!(!r.ok, "the build went through:\n{}", r.log);
    assert!(r.log.contains("CUBIT_DEP_CELLS_GUARD=yes") && r.log.contains("`all`"), "{}", r.log);
}
