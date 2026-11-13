//! The sm_120 dependency table: a pair on a uniform register takes ptxas's census MINIMUM as its cell where a
//! probe measured the pair's floor at or below that minimum on both card models (2026-11-12).
//!
//! The table gives a pair a cell only where the census is dense at its minimum (50 pairs, 8 of them at the
//! minimum); every other pair on a uniform register is priced by the default `uniform` = 13. In the vendor's
//! schedules of the served MoE kernels 29 word pairs of that kind stand at 2 … 11 issue cycles, and cubit's own
//! schedule of the same text put 12 or 13 cycles of stall there — a stall of 12 … 15 cannot carry the yield flag
//! either. The first of those classes with a measured floor is `UMOV UR, imm` -> `MOV R, UR`: the census has
//! it 751 times, 4 of them at 2 issue cycles (not dense: the default), and the probe reads it right from 1 issue
//! cycle on six grids, on a Server Edition card and on a Workstation Edition card alone and at its power limit
//! (`tools/stallfloor/probe_sm120_20261111_b46.json` and its two `_ws_` files, request `pu_umov_mov_u1`).
//!
//! The rule of such a cell (`tools/stallfloor/gen_dep_latency.py`, `MEASURED_MIN_CELLS`): the number is ptxas's
//! minimum of the census — never the floor: cubit does not stand closer than ptxas ever does —, and the cell
//! exists only where the floor is measured at or below it on both card models. Pinned here: the cell against the
//! census row and the three result files; cubit's schedule of the pair (2 issue cycles where it had 13); the
//! verifier's reading of an author's schedule (the vendor's 2 is no finding, 1 is one); and the default path,
//! which does not read the table. KNOWN_ISSUES A52.
//!
//! The next pairs (2026-11-13): a batch of probes measured thirteen more pairs on a uniform register on a Server
//! Edition card and on a Workstation Edition card (`probe_sm120_20261113_b63.json` and its `_ws_` file) -- no
//! floor above ptxas's minimum. Most of them have a word the certified operand sets do not know (`ULEA`, `USHF`,
//! the uniform result of `VOTEU`), so the census pairs have no row: ptxas's minimum is read from the verifier's
//! census (`tools/stallfloor/census_pairs_uniform_sm120.json`), per SET of roles the register has in the
//! consumer. Sixteen cells of eleven pairs take it; the cells of a pair never put a role set of that census
//! below ptxas's own minimum for the set -- which keeps `UMOV` -> `USHF` and `UMOV` -> `ULOP3` (in place) at the
//! default: their cells would price a form that only shares a role (`USHF.L.U32`: ptxas never closer than 6;
//! `ULOP3.LUT` without the third source: 12) at 2.

use serde_json::Value;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const ISA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const TABLE: &str = include_str!("../tables/dep_latency_sm120.json");
const CENSUS: &str = include_str!("../tools/stallfloor/census_pairs_sm120.json");
const UNIFORM_CENSUS: &str = include_str!("../tools/stallfloor/census_pairs_uniform_sm120.json");
const B63: [(&str, &str); 2] = [
    ("a Server Edition card", include_str!("../tools/stallfloor/probe_sm120_20261113_b63.json")),
    ("a Workstation Edition card", include_str!("../tools/stallfloor/probe_sm120_20261113_b63_ws_2eabe5dcdba4_alone.json")),
];
/// The cells on the floors of that batch: (producer, consumer, role, the cell, the batch's requests).
const B63_CELLS: [(&str, &str, &str, u64, &[&str]); 16] = [
    ("UIADD3", "ULEA", "u0", 4, &["u01_uiadd3_ulea"]),
    ("UIADD3", "ULEA", "u2", 4, &["u01_uiadd3_ulea"]),
    ("UMOV", "ULEA", "u0", 2, &["u02_umov_ulea"]),
    ("UMOV", "ULEA", "u2", 2, &["u02_umov_ulea"]),
    ("ULEA", "ULEA", "u0", 4, &["u03_ulea_ulea"]),
    ("ULEA", "ULEA", "u2", 4, &["u03_ulea_ulea"]),
    ("ULEA", "LEA", "u2", 6, &["u04_ulea_lea"]),
    ("ULEA", "IADD3", "u2", 6, &["u05_ulea_iadd3"]),
    ("ULEA", "STS", "u0", 9, &["u06_ulea_sts", "u06_ulea_sts128"]),
    ("VOTEU", "FLO", "u1", 2, &["u11_voteu_flo"]),
    ("VOTEU", "POPC", "u1", 3, &["u12_voteu_popc"]),
    ("USHF", "ULOP3", "u3", 4, &["u14_ushf_ulop3"]),
    ("ULOP3", "USHF", "u0", 4, &["u16_ulop3_ushf"]),
    ("ULOP3", "USHF", "u1", 4, &["u16_ulop3_ushf"]),
    ("UMOV", "UIADD3", "u0", 2, &["ua_umov_uiadd3i"]),
    ("UMOV", "UIADD3", "u1", 2, &["ua_umov_uiadd3", "ua_umov_uiadd3i"]),
];
const PROBES: [(&str, &str); 3] = [
    ("a Server Edition card", include_str!("../tools/stallfloor/probe_sm120_20261111_b46.json")),
    ("a Workstation Edition card alone", include_str!("../tools/stallfloor/probe_sm120_20261111_b46_ws_2eabe5dcdba4_alone.json")),
    ("a Workstation Edition card at its power limit", include_str!("../tools/stallfloor/probe_sm120_20261111_b46_ws_2eabe5dcdba4_capped.json")),
];
/// The dependency-aware scheduler with the sm_120 table.
const S1: &[(&str, &str)] = &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120"), ("CUBIT_MMA_PTXAS", "1")];

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

fn with<'a>(env: &[(&'a str, &'a str)], more: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut v = env.to_vec();
    v.extend_from_slice(more);
    v
}

/// One instruction line of a frozen listing: (the control code, stall, text).
type Word = (String, u32, String);

fn words(frozen: &str) -> Vec<Word> {
    frozen
        .lines()
        .filter_map(|l| {
            let t = l.trim_start();
            let close = t.find(']')?;
            let f: Vec<&str> = t.strip_prefix('[')?[..close - 1].split(':').collect();
            (f.len() == 5 && f[4].starts_with('S'))
                .then(|| (t[..=close].to_string(), f[4][1..].parse().unwrap(), t[close + 1..].trim().trim_end_matches(';').trim().to_string()))
        })
        .collect()
}

/// The schedule `cubit asm` builds from `text` under `env` (its words) and the log of the build.
fn build(text: &str, env: &[(&str, &str)]) -> (Vec<Word>, String) {
    let dir = std::env::temp_dir().join(format!("unicell_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
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

/// Issue cycles from the first word that starts with `from` to the first one behind it that starts with `to`.
fn distance(w: &[Word], from: &str, to: &str) -> u32 {
    let a = w.iter().position(|x| x.2.starts_with(from)).unwrap_or_else(|| panic!("no `{from}` in {w:?}"));
    let b = a + w[a..].iter().position(|x| x.2.starts_with(to)).unwrap_or_else(|| panic!("no `{to}` behind `{from}` in {w:?}"));
    w[a..b].iter().map(|x| x.1).sum()
}

/// The pair as the served MoE kernels have it: a constant into a uniform register, copied into a general
/// register one word on (the mailbox's phase word).
const KERNEL: &str = "\
.entry uniform_cell_probe
    .reg R0-R31
    .param ptr out
    LDCU.64 UR8, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    UMOV UR4, 0x400 ;
    MOV R26, UR4 ;
    IADD3 R27, PT, PT, R26, 0x1, RZ ;
    STG.E desc[UR8][R2.64], R27 ;
    EXIT ;
.endentry
";

/// An author's schedule of `KERNEL` with the pair `stall` issue cycles apart (ptxas: 2) -- the schedule the
/// dependency-aware scheduler builds from it, with that one stall count.
fn frozen(stall: u32) -> String {
    format!(
        "\
.entry uniform_cell_probe
    .reg R0-R27
    .regcount 40
    .param ptr p0 offset=0x0
    [B------:R-:W0:Y:S04] LDCU.64 UR8, c[0x0][0x358] ;
    [B------:R-:W1:Y:S04] LDC.64 R2, c[0x0][0x380] ;
    [B------:R-:W-:Y:S{stall:02}] UMOV UR4, 0x400 ;
    [B------:R-:W-:-:S05] MOV R26, UR4 ;
    [B------:R-:W-:-:S05] IADD3 R27, PT, PT, R26, 0x1, RZ ;
    [B01----:R-:W-:Y:S04] STG.E desc[UR8][R2.64], R27 ;
    [B------:R-:W-:Y:S05] EXIT ;
.endentry
"
    )
}

/// The control codes of the DEFAULT scheduler's schedule of `KERNEL` (no switch): the table is not read there.
const DEFAULT_CODES: [&str; 7] = [
    "[B------:R-:W0:Y:S04]",
    "[B------:R-:W1:Y:S04]",
    "[B------:R-:W-:-:S05]",
    "[B------:R-:W-:-:S05]",
    "[B------:R-:W-:-:S05]",
    "[B01----:R-:W-:-:S04]",
    "[B------:R-:W-:-:S05]",
];

fn cell(producer: &str, consumer: &str, role: &str) -> Option<Value> {
    let t: Value = serde_json::from_str(TABLE).unwrap();
    t["cells"].as_array().unwrap().iter().find(|c| c["producer"] == producer && c["consumer"] == consumer && c["role"] == role).cloned()
}

#[test]
fn the_cell_is_ptxas_minimum_of_the_census_and_no_measured_floor_stands_above_it() {
    let c = cell("UMOV", "MOV", "u1").expect("the table has no cell UMOV -> MOV u1: the pair is priced by the default");
    let l = c["L"].as_u64().unwrap();
    // ptxas's minimum, read off the census the table is mined from
    let census: Value = serde_json::from_str(CENSUS).unwrap();
    let row = census.as_array().unwrap().iter().find(|r| r["prod"] == "UMOV" && r["cons"] == "MOV" && r["role"] == "u1").expect("no census row");
    assert_eq!(l, row["min"].as_u64().unwrap(), "the cell is not the census minimum: {row}");
    assert_eq!(l, 2);
    // the floor measured on both card models, never above the cell
    for (card, file) in PROBES {
        let p: Value = serde_json::from_str(file).unwrap();
        let req: Vec<&Value> = p["requests"].as_array().unwrap().iter().filter(|q| q["id"] == "pu_umov_mov_u1").collect();
        assert_eq!(req.len(), 1, "{card}");
        let floor = req[0]["floor"]["binding"].as_u64().unwrap_or_else(|| panic!("{card}: no floor in {}", req[0]["floor"]));
        assert!(floor <= l, "{card}: the measured floor {floor} stands above the cell {l}");
        assert!(req[0]["floor"]["oracle_failures"].as_array().unwrap().is_empty() && req[0]["errors"] == 0, "{card}: {}", req[0]["floor"]);
        // every grid of the request, not only the binding one
        for (grid, f) in req[0]["floor"]["per_condition"].as_object().unwrap() {
            assert!(f.as_u64().unwrap() <= l, "{card}, grid {grid}: floor {f}");
        }
    }
    // the default stays what it was for every pair on a uniform register without a cell
    let t: Value = serde_json::from_str(TABLE).unwrap();
    assert_eq!(t["defaults"]["uniform"], 13);
    assert!(cell("UMOV", "USHF", "u1").is_none() && cell("UISETP", "BRA", "gc").is_none(), "a pair without a cell of this kind has one");
}

#[test]
fn cubit_schedules_the_pair_at_ptxas_distance_and_no_longer_at_the_default() {
    let sync = with(S1, &[("CUBIT_SYNC_CLASSES", "1")]);
    let table = with(&sync, &[("CUBIT_SCHED2_MEMSTALL", "table")]);
    let lower = with(&table, &[("CUBIT_SCHED2_LOWER", "1")]);
    for (name, env) in [("the dependency-aware scheduler", S1.to_vec()), ("the synchronisation classes", sync), ("the table's stalls behind memory words", table), ("the lowering pass", lower)] {
        let (w, log) = build(KERNEL, &with(&env, &[("CUBIT_DEP_VERIFY", "1")]));
        let d = distance(&w, "UMOV", "MOV R26");
        assert_eq!(d, 2, "{name}: `UMOV` -> `MOV R, UR` stands at {d} issue cycles (the cell is 2, the default was 13):\n{w:?}");
        assert!(log.contains("DEP_VERIFY 0 below a table cell, 0 waits closer than the arming distance to their barrier's setter, 0 below a resource spacing, 0 below a default"), "{name}: {log}");
        // a stall of 12 .. 15 has no encoding with the yield flag: at the cell's distance the producer keeps the flag
        let umov = w.iter().find(|x| x.2.starts_with("UMOV")).unwrap();
        assert_eq!(umov.0, "[B------:R-:W-:Y:S02]", "{name}: {umov:?}");
    }
}

#[test]
fn the_verifier_reads_an_authors_schedule_by_the_cell() {
    for sync in [&[][..], &[("CUBIT_SYNC_CLASSES", "1")][..]] {
        let env = with(sync, &[("CUBIT_VERIFY", "1"), ("CUBIT_DEP_VERIFY", "1")]);
        // ptxas's own distance is no finding any more
        let (_, log) = build(&frozen(2), &env);
        assert!(log.contains("DEP_VERIFY 0 below a table cell") && log.contains("0 below a default"), "{sync:?}: the pair at 2: {log}");
        // one cycle closer than ptxas ever stands is a finding against the cell, whatever the floor
        let (_, log) = build(&frozen(1), &env);
        assert!(log.contains("DEP_VERIFY 1 below a table cell"), "{sync:?}: the pair at 1: {log}");
        assert!(log.contains("UMOV UR4, 0x400 -> [3] MOV R26, UR4 (raw UR4): distance 1 < 2"), "{sync:?}: {log}");
    }
}

#[test]
fn the_default_path_does_not_read_the_table() {
    // without the opt-in the legaliser of the table does not run: the schedule is what it was before the cell
    let (w, _) = build(KERNEL, &[]);
    let codes: Vec<&str> = w.iter().map(|x| x.0.as_str()).collect();
    assert_eq!(codes, DEFAULT_CODES, "the default scheduler's schedule moved:\n{w:?}");
    assert_eq!(distance(&w, "UMOV", "MOV R26"), 5);
}

/// The uniform datapath of the served MoE kernels in small: a constant, `ULEA` on it in place, and the two
/// general consumers of the result.
const KERNEL_ULEA: &str = "\
.entry uniform_cells_probe
    .reg R0-R31
    .param ptr out
    LDCU.64 UR8, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    LDC R4, c[0x0][0x388] ;
    LDCU UR5, c[0x0][0x38c] ;
    UMOV UR4, 0x400 ;
    ULEA UR4, UR5, UR4, 0x18 ;
    LEA R6, R4, UR4, 0x3 ;
    IADD3 R7, PT, PT, R6, UR4, RZ ;
    STG.E desc[UR8][R2.64], R7 ;
    EXIT ;
.endentry
";

#[test]
fn the_cells_of_the_batch_are_ptxas_minima_and_no_floor_of_either_card_stands_above_them() {
    let table: Value = serde_json::from_str(TABLE).unwrap();
    let cells: std::collections::HashMap<(String, String, String), u64> = table["cells"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| ((c["producer"].as_str().unwrap().into(), c["consumer"].as_str().unwrap().into(), c["role"].as_str().unwrap().into()), c["L"].as_u64().unwrap()))
        .collect();
    let census: Value = serde_json::from_str(CENSUS).unwrap();
    let uniform: Value = serde_json::from_str(UNIFORM_CENSUS).unwrap();
    let sets = uniform["rows"].as_array().unwrap();
    let holds = |row: &Value, role: &str| row["roles"].as_str().unwrap().split('+').any(|x| x == role);
    for (p, c, role, l, requests) in B63_CELLS {
        assert_eq!(cell(p, c, role).unwrap_or_else(|| panic!("no cell {p} -> {c} {role}"))["L"].as_u64().unwrap(), l, "{p} -> {c} {role}");
        // ptxas's minimum: the census pairs where they have the row, else the verifier's census -- the smallest
        // minimum of the role sets that hold the role
        let row = census.as_array().unwrap().iter().find(|r| r["prod"] == p && r["cons"] == c && r["role"] == role);
        let min = match row {
            Some(r) => r["min"].as_u64().unwrap(),
            None => sets.iter().filter(|r| r["producer"] == p && r["consumer"] == c && holds(r, role)).map(|r| r["min"].as_u64().unwrap()).min().unwrap_or_else(|| panic!("no census row {p} -> {c} {role}")),
        };
        assert_eq!(l, min, "{p} -> {c} {role}: the cell is not ptxas's census minimum");
        // the floor on both card models, on every grid, never above the cell
        for (card, file) in B63 {
            let f: Value = serde_json::from_str(file).unwrap();
            for id in requests {
                let req: Vec<&Value> = f["requests"].as_array().unwrap().iter().filter(|q| q["id"] == *id).collect();
                assert_eq!(req.len(), 1, "{card}: {id}");
                let floor = req[0]["floor"]["binding"].as_u64().unwrap_or_else(|| panic!("{card}: no floor in {}", req[0]["floor"]));
                assert!(floor <= l, "{card}, {id}: the measured floor {floor} stands above the cell {l}");
                assert!(req[0]["floor"]["oracle_failures"].as_array().unwrap().is_empty() && req[0]["errors"] == 0, "{card}, {id}: {}", req[0]["floor"]);
                for (grid, g) in req[0]["floor"]["per_condition"].as_object().unwrap() {
                    assert!(g.as_u64().unwrap() <= l, "{card}, {id}, grid {grid}: floor {g}");
                }
            }
        }
    }
    // no role set of the verifier's census stands below ptxas's own minimum for the set: the table asks the
    // largest of the roles' cells; a set with a role that has no cell keeps a default
    let mut priced = 0;
    for r in sets {
        let (p, c) = (r["producer"].as_str().unwrap(), r["consumer"].as_str().unwrap());
        if !B63_CELLS.iter().any(|x| x.0 == p && x.1 == c) {
            continue;
        }
        let ls: Vec<Option<u64>> = r["roles"].as_str().unwrap().split('+').map(|x| cells.get(&(p.to_string(), c.to_string(), x.to_string())).copied()).collect();
        if ls.iter().all(|l| l.is_some()) {
            priced += 1;
            let need = ls.iter().map(|l| l.unwrap()).max().unwrap();
            assert!(need >= r["min"].as_u64().unwrap(), "{p} -> {c} {}: the table asks {need}, ptxas never stands closer than {}", r["roles"], r["min"]);
        }
    }
    assert!(priced >= 16, "{priced} role sets priced by cells alone");
    // the two pairs of the batch that stay at the default: a cell on their shared role would price a form
    // ptxas keeps farther apart
    for (p, c, role) in [("UMOV", "USHF", "u0"), ("UMOV", "USHF", "u1"), ("UMOV", "ULOP3", "u0"), ("UMOV", "ULOP3", "u1")] {
        assert!(cell(p, c, role).is_none(), "{p} -> {c} {role} has a cell");
    }
    let alone = |p: &str, c: &str, roles: &str| sets.iter().find(|r| r["producer"] == p && r["consumer"] == c && r["roles"] == roles).unwrap()["min"].as_u64().unwrap();
    assert_eq!((alone("UMOV", "USHF", "u0+u1"), alone("UMOV", "USHF", "u1")), (2, 6));
    assert_eq!((alone("UMOV", "ULOP3", "u0+u1"), alone("UMOV", "ULOP3", "u1")), (12, 7));
}

#[test]
fn cubit_schedules_the_uniform_datapath_at_ptxas_distances() {
    let (w, log) = build(KERNEL_ULEA, &with(S1, &[("CUBIT_DEP_VERIFY", "1")]));
    // the constant into `ULEA` in place: 2 (it was 13); `ULEA` into `LEA R, R, UR`: 6 (it was 13)
    assert_eq!(distance(&w, "UMOV UR4", "ULEA"), 2, "{w:?}");
    assert_eq!(distance(&w, "ULEA", "LEA R6"), 6, "{w:?}");
    assert!(distance(&w, "ULEA", "IADD3 R7") >= 6, "{w:?}");
    assert!(log.contains("DEP_VERIFY 0 below a table cell, 0 waits closer than the arming distance to their barrier's setter, 0 below a resource spacing, 0 below a default"), "{log}");
    // an author's schedule: the same words, `ULEA` one cycle closer to its reader than ptxas ever stands
    let frozen = |stall: u32| {
        let mut t = String::from(".entry uniform_cells_probe\n    .reg R0-R7\n    .regcount 40\n    .param ptr p0 offset=0x0\n");
        for x in &w {
            let code = if x.2.starts_with("ULEA") { format!("{}S{stall:02}]", &x.0[..x.0.len() - 4]) } else { x.0.clone() };
            t.push_str(&format!("    {code} {} ;\n", x.2));
        }
        t + ".endentry\n"
    };
    let env = [("CUBIT_SYNC_CLASSES", "1"), ("CUBIT_VERIFY", "1"), ("CUBIT_DEP_VERIFY", "1")];
    let (_, log) = build(&frozen(6), &env);
    assert!(log.contains("DEP_VERIFY 0 below a table cell") && log.contains("0 below a default"), "the pair at 6: {log}");
    let (_, log) = build(&frozen(5), &env);
    assert!(log.contains("DEP_VERIFY 1 below a table cell") && log.contains("LEA R6, R4, UR4, 0x3 (raw UR4): distance 5 < 6"), "the pair at 5: {log}");
}
