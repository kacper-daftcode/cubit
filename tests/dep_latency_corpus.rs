//! The sm_120 dependency-latency table (`tables/dep_latency_sm120.json`, `CUBIT_SCHED2_LAT`) against the evidence of
//! the kernels beyond the one it was built for (2026-11-10: the hand-written MoE GEMM kernels -- 2-bit / FP4 /
//! quintal planes, `QMMA.SF` -- and the state-prefill kernel; 92 auto-scheduled production sources).
//!
//! Two instruction forms those kernels are made of are invisible to the census the table was mined from: the
//! register-liveness model has no def / use rule for the 7-operand `QMMA.SF` form nor for `IADD.64` (`depdump` prints
//! `known: false` and empty sets), so `tools/stallfloor/census_pairs_sm120.json` has no row with either as producer or
//! consumer -- the MMA rows rest on HMMA and every pair through a 64-bit add is priced with a default.
//! `tools/stallfloor/slot_census.py` supplies their operands from the operand slots and runs the same walk;
//! `census_pairs_slots_sm120.json` holds its rows (142 rows, 146 962 pairs of the 166 frozen sm_120 listings).
//!
//! What is pinned here: whatever the table charges for such a pair -- an MMA row, a default, one day a cell -- is
//! never below ptxas's dense practice for it, and the MMA rows are ptxas's numbers for QMMA exactly.

use serde_json::Value;
use std::collections::HashMap;
use std::process::Command;

const TABLE: &str = include_str!("../tables/dep_latency_sm120.json");
const SLOTS: &str = include_str!("../tools/stallfloor/census_pairs_slots_sm120.json");
const FLOORS_E: &str = include_str!("../tools/stallfloor/stall_floors_sm120_20261110_pairs_e.json");

struct Table {
    cells: HashMap<(String, String, String), u64>,
    mma_classes: Vec<String>,
    to_acc: u64,
    to_data: u64,
    d_data: u64,
    d_mma_input: u64,
    d_guard: u64,
    d_pred: u64,
    d_uniform: u64,
}

fn table() -> Table {
    let j: Value = serde_json::from_str(TABLE).unwrap();
    let mut cells = HashMap::new();
    for c in j["cells"].as_array().unwrap() {
        cells.insert(
            (c["producer"].as_str().unwrap().to_string(), c["consumer"].as_str().unwrap().to_string(), c["role"].as_str().unwrap().to_string()),
            c["L"].as_u64().unwrap(),
        );
    }
    let d = &j["defaults"];
    Table {
        cells,
        mma_classes: j["mma"]["classes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect(),
        to_acc: j["mma"]["to_mma_accumulate"].as_u64().unwrap(),
        to_data: j["mma"]["to_data"].as_u64().unwrap(),
        d_data: d["data"].as_u64().unwrap(),
        d_mma_input: d["mma_input"].as_u64().unwrap(),
        d_guard: d["guard"].as_u64().unwrap(),
        d_pred: d["pred_operand"].as_u64().unwrap(),
        d_uniform: d["uniform"].as_u64().unwrap(),
    }
}

/// What `dep_stall` charges for (producer class, consumer class, operand role): the MMA rows for an MMA producer,
/// else the cell (the upper register of a multi-register operand falls back on its first), else the default of the
/// consumer's kind. Returns (latency, priced by a default).
fn price(t: &Table, p: &str, c: &str, role: &str) -> (u64, bool) {
    let is_mma = |x: &str| t.mma_classes.iter().any(|m| m == x);
    if is_mma(p) {
        return (if is_mma(c) && (role == "r3" || role == "r3h") { t.to_acc } else { t.to_data }, false);
    }
    let key = |r: &str| (p.to_string(), c.to_string(), r.to_string());
    if let Some(l) = t.cells.get(&key(role)) {
        return (*l, false);
    }
    if let Some(l) = role.strip_suffix('h').and_then(|r| t.cells.get(&key(r))) {
        return (*l, false);
    }
    let l = if is_mma(c) {
        t.d_mma_input
    } else if role == "g" || role == "gc" {
        t.d_guard
    } else if role == "p" {
        t.d_pred
    } else if role.starts_with('u') {
        t.d_uniform
    } else {
        t.d_data
    };
    (l, true)
}

fn slot_rows() -> Vec<Value> {
    serde_json::from_str::<Value>(SLOTS).unwrap().as_array().unwrap().clone()
}

/// ptxas's dense practice (the table's own definition of a dense cell: at least 50 pairs, at least 8 of them at the
/// minimum, minimum at most 7) for a pair through QMMA or IADD.64 is never above what the table charges for it.
#[test]
fn no_price_of_a_qmma_or_iadd64_pair_is_below_ptxas_dense_practice() {
    let t = table();
    let (mut dense, mut defaulted) = (0, 0);
    for r in slot_rows() {
        let (n, min, n_min) = (r["n"].as_u64().unwrap(), r["min"].as_u64().unwrap(), r["n_min"].as_u64().unwrap());
        if n < 50 || n_min < 8 || min > 7 {
            continue;
        }
        let (p, c, role) = (r["prod"].as_str().unwrap(), r["cons"].as_str().unwrap(), r["role"].as_str().unwrap());
        let (l, dflt) = price(&t, p, c, role);
        assert!(l >= min, "{p} -> {c} {role}: the table charges {l}, ptxas schedules it from {min} ({n_min} of {n} pairs)");
        dense += 1;
        defaulted += usize::from(dflt);
    }
    assert!(dense >= 40, "the slot census is read: {dense} dense rows");
    // today no cell names any of these pairs (the census could not see them): they are all defaults
    assert!(defaulted >= 40, "{defaulted} of {dense} dense rows are priced with a default");
}

/// The MMA rows are ptxas's numbers for QMMA: a reader of a QMMA result from 28, the accumulate operand of the next
/// QMMA from 29 -- every register of it --, an ALU result into a QMMA operand from 7.
#[test]
fn the_mma_rows_are_ptxas_practice_for_qmma() {
    let t = table();
    let rows = slot_rows();
    let min_of = |p: &str, c: &str, role: &str| -> (u64, u64, u64) {
        let r = rows
            .iter()
            .find(|r| r["prod"] == p && r["cons"] == c && r["role"] == role)
            .unwrap_or_else(|| panic!("no row {p} -> {c} {role}"));
        (r["min"].as_u64().unwrap(), r["n_min"].as_u64().unwrap(), r["n"].as_u64().unwrap())
    };
    for (c, role) in [("FFMA", "r1"), ("FFMA", "r2"), ("FMUL", "r1"), ("FADD", "r1"), ("MOV", "r1")] {
        let (min, n_min, n) = min_of("QMMA", c, role);
        assert_eq!(min, t.to_data, "QMMA -> {c} {role}: ptxas minimum ({n_min} of {n} pairs)");
        assert_eq!(price(&t, "QMMA", c, role).0, t.to_data);
    }
    for role in ["r3", "r3h"] {
        let (min, n_min, n) = min_of("QMMA", "QMMA", role);
        assert_eq!(min, t.to_acc, "QMMA -> QMMA {role}: ptxas minimum ({n_min} of {n} pairs)");
        assert!(n_min >= 1000, "a dense minimum: {n_min}");
        assert_eq!(price(&t, "QMMA", "QMMA", role).0, t.to_acc);
    }
    // an ALU result into a QMMA operand: ptxas's minimum over the dense rows is the fragment default
    let mut dense_min = u64::MAX;
    for r in rows.iter().filter(|r| r["cons"] == "QMMA" && r["prod"] != "QMMA") {
        let (n, min, n_min) = (r["n"].as_u64().unwrap(), r["min"].as_u64().unwrap(), r["n_min"].as_u64().unwrap());
        if n >= 50 && n_min >= 8 {
            dense_min = dense_min.min(min);
        }
    }
    assert_eq!(dense_min, t.d_mma_input, "the smallest dense ALU -> QMMA minimum is the MMA-fragment default");
}

/// The pair floors of one group of runs: no price of the table -- cell, MMA row or default -- is below the floor, and
/// in every run the sweep is wrong below the floor and clean from it up (consumer right behind the producer).
/// Returns the number of pairs and the pairs priced exactly at their floor.
fn floors_hold(t: &Table, group: &Value, runs: &[&str]) -> (usize, Vec<String>) {
    let (mut n, mut tight) = (0, Vec::new());
    for c in group["cells"].as_array().unwrap() {
        let (p, cc, role) = (c["producer"].as_str().unwrap(), c["consumer"].as_str().unwrap(), c["role"].as_str().unwrap());
        let floor = c["floor_d0"].as_u64().unwrap();
        let (l, _) = price(t, p, cc, role);
        assert!(l >= floor, "{p} -> {cc} {role}: the table charges {l}, the measured floor is {floor}");
        if l == floor {
            tight.push(format!("{p} -> {cc} {role}"));
        }
        for key in runs {
            let by = group[*key][format!("{}_d0", c["pair"].as_str().unwrap())].as_object().unwrap_or_else(|| panic!("{key}: no sweep of {p} -> {cc}"));
            for (stall, wrong) in by {
                let stall: u64 = stall.parse().unwrap();
                assert_eq!(wrong.as_i64().unwrap() != 0, stall < floor, "{p} -> {cc} {role} at S{stall:02} ({key})");
            }
        }
        n += 1;
    }
    tight.sort();
    (n, tight)
}

/// Silicon (harness v5e, `tools/stallfloor/pairfloor_gen_e.py`): two runs on a Server Edition card at a core clock of
/// at most 2 362 MHz and two on a Workstation Edition card at up to 2 752 MHz -- the same floors and the same clean /
/// dirty verdict of every kernel. No price of the table is below the measured floor of a pair the MoE / state kernels
/// bind on, and no kernel of a sweep is wrong at or above what the table charges.
#[test]
fn no_price_is_below_a_silicon_floor_of_the_corpus_pairs() {
    let t = table();
    let j: Value = serde_json::from_str(FLOORS_E).unwrap();
    let (n, tight) = floors_hold(&t, &j, &["mismatches", "mismatches_second_run", "mismatches_rtx_run_a", "mismatches_rtx_run_b"]);
    assert!(n >= 17, "{n} pair floors read");
    // three of them are priced exactly at their floor -- the guard of a branch / an exit behind its ISETP (13) and the
    // LUT selector behind a LOP3 (4): cells that must not be lowered
    assert_eq!(tight, ["ISETP -> BRA gc", "ISETP -> EXIT gc", "LOP3 -> PRMT r2"], "the pairs priced exactly at their floor");
    assert_eq!(j["floors_rtx"], j["floors"], "the floors do not move with the core clock");
    // the QMMA rows: a reader of the result needs 20 issue cycles (as HMMA -> FMUL), the accumulate operand of the
    // next QMMA and two QMMAs back to back are interlocked by the tensor pipe (clean from distance 1)
    let m = &j["mma_floors"];
    assert_eq!(m["qmma_data"].as_u64(), Some(20));
    assert_eq!(m["qmma_acc"].as_u64(), Some(1));
    assert_eq!(m["qmma_any"].as_u64(), Some(1));
    assert!(t.to_data >= 20 && t.to_acc >= 1);
    // every reference kernel was deterministic and its checksum depends on the inputs
    for (pair, state) in j["references"].as_object().unwrap() {
        let s = state.as_str().unwrap();
        assert!(s.starts_with("ok") && !s.contains("WEAK"), "{pair}: {s}");
    }
}

/// The eleven pairs added for the state-prefill kernel (second operands of `IADD.64`, store data, the uniform loop
/// counters, `LOP3` into the upper register of an HMMA B fragment): two runs on the first card, three on the second
/// (core clock up to 2 820 MHz), identical. Ten are priced above their floor; **`UIADD3 -> UISETP` is priced exactly
/// at it** (ptxas's census minimum 4 is the silicon floor) -- a cell that must not be lowered.
#[test]
fn the_state_kernel_pairs_are_priced_at_or_above_their_floors() {
    let t = table();
    let j: Value = serde_json::from_str(FLOORS_E).unwrap();
    let g = &j["new_pairs"];
    let runs = ["mismatches", "mismatches_second_run", "mismatches_rtx_run_a", "mismatches_rtx_run_b", "mismatches_rtx_run_c"];
    let (n, tight) = floors_hold(&t, g, &runs);
    assert_eq!(n, 11);
    assert_eq!(tight, ["UIADD3 -> UISETP u0"], "the pairs priced exactly at their floor");
    let floor = |pair: &str| g["floors"][pair].as_u64().unwrap();
    // a uniform register written through R2UR is the slowest path found on sm_120: 8 issue cycles (the default 13)
    assert_eq!((floor("r2ur_uiadd3_d0"), floor("r2ur_uiadd3_d1"), floor("r2ur_uiadd3_d2")), (8, 6, 4));
    assert!(t.d_uniform >= 8);
    assert_eq!(floor("uiadd3_uisetp_d0"), 4);
    // one weak probe, named: its reference checksum takes two values (a quarter of the threads discriminate)
    for (pair, state) in g["references"].as_object().unwrap() {
        let s = state.as_str().unwrap();
        assert!(s.starts_with("ok"), "{pair}: {s}");
        assert_eq!(s.contains("WEAK"), pair == "shf_sts_d", "{pair}: {s}");
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The shape of the MoE kernels under the switches: one k64 step (PRMT-LUT decode -> two QMMA.SF per k32 -> the FFMA
// fold -> the accumulators zeroed -> the next pair), fixture `tests/fixtures/dep_latency_corpus/moe_kstep.sass`.

const ISA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const KSTEP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/dep_latency_corpus/moe_kstep.sass");
const NEW: [(&str, &str); 5] = [
    ("CUBIT_SCHED2", "1"),
    ("CUBIT_SCHED2_LAT", "sm120"),
    ("CUBIT_MMA_PTXAS", "1"),
    ("CUBIT_VERIFY", "1"),
    ("CUBIT_DEP_VERIFY", "1"),
];

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

/// (stall, instruction text) of every instruction line of the frozen listing, and the assembler's log.
fn build(tag: &str, env: &[(&str, &str)]) -> (Vec<(u32, String)>, String) {
    let dir = std::env::temp_dir().join(format!("dep_corpus_{}_{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("k.cubin");
    let (ok, log) = cubit(&["asm", "-t", ISA, KSTEP, "-o", out.to_str().unwrap()], env);
    assert!(ok, "asm failed ({env:?}):\n{log}");
    let (ok, frozen) = cubit(&["disassemble", "-t", ISA, "--frozen", out.to_str().unwrap()], &[]);
    assert!(ok, "disassemble failed: {frozen}");
    let _ = std::fs::remove_dir_all(&dir);
    let mut lines = Vec::new();
    for l in frozen.lines() {
        let t = l.trim_start();
        let Some(open) = t.find("[B") else { continue };
        let Some(close) = t[open..].find(']') else { continue };
        let ctrl = &t[open + 1..open + close];
        let Some(s) = ctrl.rsplit(':').next().and_then(|f| f.strip_prefix('S')).and_then(|n| n.parse::<u32>().ok()) else { continue };
        lines.push((s, t[open + close + 1..].trim().trim_end_matches(';').trim().to_string()));
    }
    // the padding behind the last EXIT is not part of the kernel
    let end = lines.iter().rposition(|(_, t)| t == "EXIT").expect("an EXIT") + 1;
    lines.truncate(end);
    (lines, log)
}

fn is_drain(t: &str) -> bool {
    t.ends_with("UIADD3 URZ, UPT, UPT, URZ, URZ, URZ")
}

/// issue cycle of every instruction: the sum of the stalls in front of it
fn clock(lines: &[(u32, String)]) -> Vec<u32> {
    let mut c = Vec::with_capacity(lines.len());
    let mut t = 0;
    for (s, _) in lines {
        c.push(t);
        t += s;
    }
    c
}

#[test]
fn the_moe_k_step_under_the_switches_is_ptxas_qmma_discipline() {
    let (d, dlog) = build("default", &[("CUBIT_VERIFY", "1")]);
    let (n, nlog) = build("new", &NEW);
    // the same instructions in the same order: only pads differ
    let body = |ls: &[(u32, String)]| -> Vec<String> { ls.iter().map(|(_, t)| t.clone()).filter(|t| t != "NOP" && !is_drain(t)).collect() };
    assert_eq!(body(&d), body(&n), "a schedule changes control words and pads, never an instruction");
    // the default schedule: every QMMA between a pre-drain and four writeback drains; the new one: none, one NOP pad
    // between the two QMMAs of a pair
    let qmma = |ls: &[(u32, String)]| -> Vec<usize> { ls.iter().enumerate().filter(|(_, (_, t))| t.starts_with("QMMA")).map(|(i, _)| i).collect() };
    assert_eq!(qmma(&d).len(), 4);
    assert_eq!(d.iter().filter(|(_, t)| is_drain(t)).count(), 20, "default: 5 drains per QMMA");
    assert_eq!(n.iter().filter(|(_, t)| is_drain(t)).count(), 0, "CUBIT_MMA_PTXAS: no drain");
    assert_eq!(n.iter().filter(|(_, t)| t == "NOP").count(), 2, "one pad between the QMMAs of a pair");
    let (cd, cn) = (clock(&d), clock(&n));
    let (qd, qn) = (qmma(&d), qmma(&n));
    // issue distance between the two QMMAs of a pair: 72 cycles of drains by default, ptxas's 16 under the switches
    assert_eq!(cd[qd[1]] - cd[qd[0]], 72);
    assert_eq!(cn[qn[1]] - cn[qn[0]], 16);
    assert_eq!(cn[qn[3]] - cn[qn[2]], 16);
    // every reader of a QMMA result (the FFMA fold) sits at least 28 cycles behind its QMMA, the first one exactly
    for (qi, reg) in [(qn[0], "R40"), (qn[1], "R44"), (qn[2], "R40"), (qn[3], "R44")] {
        let readers: Vec<usize> = (qi + 1..n.len())
            .take_while(|&i| !(n[i].1.starts_with("MOV") && n[i].1.contains(&format!("{reg}, RZ"))))
            .filter(|&i| n[i].1.starts_with("FFMA") && n[i].1.contains(&format!(", {reg},")))
            .collect();
        assert_eq!(readers.len(), 1, "one fold reads {reg} of the QMMA at {qi}");
        assert_eq!(cn[readers[0]] - cn[qi], 28, "QMMA -> FFMA {reg}: {:?}", &n[qi..=readers[0]]);
    }
    // the accumulators are zeroed at least 7 cycles in front of the QMMA that accumulates on them
    let movs: Vec<usize> = (qn[1]..qn[2]).filter(|&i| n[i].1.starts_with("MOV R4")).collect();
    assert_eq!(movs.len(), 4);
    for &m in &movs {
        let q = if n[m].1.contains("R40") || n[m].1.contains("R41") { qn[2] } else { qn[3] };
        assert!(cn[q] - cn[m] >= 7, "{} -> QMMA at {} cycles", n[m].1, cn[q] - cn[m]);
    }
    // fewer stall cycles, and both schedules pass their verifiers
    let total = |ls: &[(u32, String)]| ls.iter().map(|(s, _)| *s).sum::<u32>();
    assert!(2 * total(&n) < total(&d) + total(&d) / 4, "stall cycles {} -> {}", total(&d), total(&n));
    assert!(dlog.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR"), "{dlog}");
    assert!(nlog.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR"), "{nlog}");
    assert!(
        nlog.contains("DEP_VERIFY 0 below a table cell, 0 waits closer than the arming distance to their barrier's setter, 0 below a resource spacing, 0 below a default"),
        "{nlog}"
    );
}

/// The switches are opt-in: without them the fixture's schedule carries the drains whatever the environment of the
/// other tests is, and the three switches are needed together for the QMMA discipline (the legaliser keeps the MMA
/// distances; `CUBIT_MMA_PTXAS` alone is refused).
#[test]
fn the_qmma_discipline_is_opt_in() {
    let (ok, log) = cubit(&["asm", "-t", ISA, KSTEP, "-o", "/dev/null"], &[("CUBIT_MMA_PTXAS", "1")]);
    assert!(!ok && log.contains("CUBIT_MMA_PTXAS=1 needs CUBIT_SCHED2=1 CUBIT_SCHED2_LAT"), "{log}");
    let (k1, _) = build("sched2", &[("CUBIT_SCHED2", "1")]);
    assert!(k1.iter().filter(|(_, t)| is_drain(t)).count() > 0, "plain CUBIT_SCHED2 keeps writeback drains");
}
