//! `CUBIT_SCHED2` on sm_120 (2026-11-10): the scoreboard arming rule and the dependency-latency
//! legaliser (`CUBIT_SCHED2_LAT`, `CUBIT_MMA_PTXAS`; `src/dep_stall.rs`,
//! `tables/dep_latency_sm120.json`).
//!
//! What failed: `CUBIT_SCHED2` built the production sparse-MLA prefill attention kernel with wrong
//! results on sm_120 silicon (softmax probabilities on every row, non-deterministic; the no-sink
//! `lse` deterministic). Bisecting the [yield, stall] fields by kernel region left ONE pattern in
//! both: RULE 2 puts the yield flag on a scoreboard producer whose waiter is the very next
//! instruction one cycle behind it -- `MUFU.EX2 [W:Y:S01]` / `FSEL [B]` in the softmax,
//! `MUFU.LG2 [W:Y:S01]` / `FADD [B]` in the epilogue -- and the waiter reads the register before
//! the barrier is armed. ptxas never schedules that: 0 of ~70 000 (setter, first waiter) pairs of
//! the sm_120 census are closer than 2 cycles.
//!
//! What the table adds: a fixed latency is a property of the (producer class, consumer class,
//! operand role) PAIR (same unit 4, cross unit 5, predicate into a guard 13 / into a select 5,
//! MMA 16 / 28 / 29), it holds on EVERY control-flow path (RULE 1 only walks the text), and some
//! pipes need issue spacing whatever the registers are (LDC 8, the multiplier 2 / 4, memory 4).
//!
//! Every test pins both sides: the schedule `e6bdbb2` produced (fixtures `*.sched2_e6bdbb2.txt`,
//! `*.default.txt`, `*.policy.txt`, written by that binary) and the property the fix restores.
//! The default path (no switch) must stay byte for byte.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The tests of this file run in parallel in one process: every scratch directory is its own.
static SCRATCH: AtomicUsize = AtomicUsize::new(0);

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sched2_dep_{}_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst), tag));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sched2_dep");
/// The production kernel's policy switches (the attention build of the serving stack).
const POLICY: [(&str, &str); 4] =
    [("CUBIT_SB_SHARE", "1"), ("CUBIT_RB_EARLY", "32"), ("CUBIT_MMA_WAIT", "1"), ("CUBIT_MMA_WB_DRAIN", "13")];

#[derive(Debug, Clone)]
struct Line {
    wait: u8,
    rb: Option<u8>,
    wb: Option<u8>,
    yld: bool,
    stall: u32,
    text: String,
    label: Option<String>,
}

struct Built {
    lines: Vec<Line>,
    /// the instruction lines as `disassemble --frozen` prints them, leading blanks removed
    listing: Vec<String>,
    frozen: String,
    log: String,
}

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

fn parse_line(l: &str) -> Option<Line> {
    let t = l.trim_start();
    let (label, rest) = match t.find('[') {
        Some(0) => (None, t),
        Some(p) if t[..p].trim_end().ends_with(':') => (Some(t[..p].trim_end().trim_end_matches(':').to_string()), &t[p..]),
        _ => return None,
    };
    let close = rest.find(']')?;
    let ctrl = &rest[1..close];
    let f: Vec<&str> = ctrl.split(':').collect();
    if f.len() != 5 || !f[0].starts_with('B') || !f[4].starts_with('S') {
        return None;
    }
    let wait = f[0][1..].chars().filter_map(|c| c.to_digit(10)).fold(0u8, |m, b| m | (1 << b));
    let bar = |s: &str| s[1..].parse::<u8>().ok();
    Some(Line {
        wait,
        rb: bar(f[1]),
        wb: bar(f[2]),
        yld: f[3] == "Y",
        stall: f[4][1..].parse().ok()?,
        text: rest[close + 1..].trim().trim_end_matches(';').trim().to_string(),
        label,
    })
}

fn build_src(tag: &str, src_path: &str, env: &[(&str, &str)]) -> Result<Built, String> {
    let dir = scratch(tag);
    let out = dir.join("k.cubin");
    let (ok, log) = cubit(&["asm", "-t", TABLE, src_path, "-o", out.to_str().unwrap()], env);
    if !ok {
        let _ = std::fs::remove_dir_all(&dir);
        return Err(log);
    }
    let (ok, frozen) = cubit(&["disassemble", "-t", TABLE, "--frozen", out.to_str().unwrap()], &[]);
    assert!(ok, "disassemble failed: {frozen}");
    let _ = std::fs::remove_dir_all(&dir);
    let lines: Vec<Line> = frozen.lines().filter_map(parse_line).collect();
    let listing: Vec<String> = frozen.lines().filter(|l| parse_line(l).is_some()).map(|l| l.trim_start().to_string()).collect();
    assert!(!lines.is_empty(), "no instruction lines in:\n{frozen}");
    Ok(Built { lines, listing, frozen, log })
}

fn build(name: &str, env: &[(&str, &str)]) -> Built {
    build_src(name, &format!("{FIX}/{name}.sass"), env).unwrap_or_else(|e| panic!("asm {name} {env:?} failed:\n{e}"))
}

fn with<'a>(base: &[(&'a str, &'a str)], more: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    base.iter().chain(more.iter()).copied().collect()
}

fn pinned(name: &str, what: &str) -> Vec<String> {
    std::fs::read_to_string(format!("{FIX}/{name}.{what}.txt")).unwrap().lines().map(|l| l.to_string()).collect()
}

/// (below a table cell, waiter too close to its barrier's setter, below a resource spacing,
/// below a default) of a built kernel: the read-only `CUBIT_DEP_VERIFY` on its frozen listing.
fn dep_verify(tag: &str, b: &Built) -> (usize, usize, usize, usize, String) {
    let dir = scratch(tag);
    let src = dir.join("k.frozen.sass");
    std::fs::write(&src, &b.frozen).unwrap();
    let out = dir.join("k.cubin");
    let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()], &[("CUBIT_DEP_VERIFY", "40")]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(ok, "re-assembling the frozen listing failed:\n{log}");
    let line = log.lines().find(|l| l.contains("DEP_VERIFY")).unwrap_or_else(|| panic!("no DEP_VERIFY line:\n{log}"));
    let nums: Vec<usize> = line.split("DEP_VERIFY").nth(1).unwrap().split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).map(|s| s.parse().unwrap()).collect();
    (nums[0], nums[1], nums[2], nums[3], log)
}

fn idx(b: &Built, starts: &str, nth: usize) -> usize {
    b.lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.text.starts_with(starts))
        .nth(nth)
        .unwrap_or_else(|| panic!("no instruction #{nth} starting `{starts}` in\n{}", b.listing.join("\n")))
        .0
}

/// Issue distance on the text: the stalls of `from .. to`.
fn dist(b: &Built, from: usize, to: usize) -> u32 {
    b.lines[from..to].iter().map(|l| l.stall).sum()
}

/// Every (barrier setter, first waiter on the text behind it) distance.
fn arming_distances(b: &Built) -> Vec<(usize, usize, u32)> {
    let mut out = Vec::new();
    for (i, l) in b.lines.iter().enumerate() {
        for bar in [l.wb, l.rb].into_iter().flatten() {
            let mut d = 0;
            for (j, w) in b.lines.iter().enumerate().skip(i) {
                if j > i && (w.wait >> bar) & 1 == 1 {
                    out.push((i, j, d));
                    break;
                }
                if j > i && (w.wb == Some(bar) || w.rb == Some(bar)) {
                    break; // re-set before anyone waited
                }
                d += w.stall;
            }
        }
    }
    out
}

// ───────────────────────── the SCHED2 failure: scoreboard arming ─────────────────────────

/// The schedule `e6bdbb2` built under `CUBIT_SCHED2=1`: both MUFUs carry the yield flag at S01
/// with their waiter right behind -- the pattern that reads a stale register on sm_120 silicon.
#[test]
fn e6bdbb2_sched2_put_yield_on_a_scoreboard_producer_one_cycle_before_its_waiter() {
    let old: Vec<Line> = pinned("arm", "sched2_e6bdbb2").iter().filter_map(|l| parse_line(l)).collect();
    for (mufu, waiter) in [("MUFU.EX2 R8", "FSEL R8"), ("MUFU.LG2 R9", "FADD.FTZ R9, R9, R6")] {
        let i = old.iter().position(|l| l.text.starts_with(mufu)).unwrap();
        assert!(old[i].wb.is_some() && old[i].yld && old[i].stall == 1, "{:?}", old[i]);
        assert!(old[i + 1].text.starts_with(waiter) && (old[i + 1].wait >> old[i].wb.unwrap()) & 1 == 1, "{:?}", old[i + 1]);
    }
    // CUBIT_SCHED2_NOARM=1 keeps that schedule for A/B runs on silicon
    let noarm = build("arm", &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_NOARM", "1")]);
    assert_eq!(noarm.listing, pinned("arm", "sched2_e6bdbb2"));
}

/// The fix: under `CUBIT_SCHED2` no waiter stands closer than 2 cycles behind the instruction that
/// set its barrier, whatever the yield policy; nothing else of the schedule moves.
#[test]
fn sched2_arms_the_scoreboard_before_the_waiter() {
    let old = pinned("arm", "sched2_e6bdbb2");
    let sets: [&[(&str, &str)]; 3] = [
        &[("CUBIT_SCHED2", "1")],
        &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_YIELD", "loads")],
        &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120")],
    ];
    for env in sets {
        let b = build("arm", env);
        let d = arming_distances(&b);
        assert!(d.len() >= 5, "{env:?}: expected the fixture's setters, got {d:?}");
        for (i, j, dd) in &d {
            assert!(*dd >= 2, "{env:?}: waiter `{}` {dd} cycle(s) behind its setter `{}`", b.lines[*j].text, b.lines[*i].text);
        }
        for mufu in ["MUFU.EX2 R8", "MUFU.LG2 R9"] {
            let l = &b.lines[idx(&b, mufu, 0)];
            assert_eq!(l.stall, 2, "{env:?}: {l:?}");
        }
        assert_eq!(dep_verify("arm", &b).1, 0, "{env:?}");
    }
    // plain SCHED2: exactly the two setters move, by one cycle each
    let b = build("arm", &[("CUBIT_SCHED2", "1")]);
    assert!(b.log.contains("scoreboard arming: 2 stalls raised by 2 cycles"), "{}", b.log);
    let changed: Vec<(&String, &String)> = old.iter().zip(b.listing.iter()).filter(|(a, c)| a != c).collect();
    assert_eq!(changed.len(), 2, "{changed:?}");
    for (a, c) in changed {
        assert!(a.contains("MUFU") && a.replace(":S01]", ":S02]") == *c, "{a} -> {c}");
    }
    // the default scheduler has the same adjacency WITHOUT the yield flag (it works on silicon: the
    // shipped kernel) and is not touched
    let dflt = build("arm", &[]);
    assert_eq!(dflt.listing, pinned("arm", "default"));
    let m = &dflt.lines[idx(&dflt, "MUFU.EX2 R8", 0)];
    assert!(m.wb.is_some() && !m.yld && m.stall == 1, "{m:?}");
}

// ───────────────────────── latency on every control-flow path ─────────────────────────

/// RULE 1 measures the distance on the text. The consumer at a branch target is 20 cycles behind
/// its predicate on the text and 6 behind it through the taken branch (13 needed).
#[test]
fn the_latency_holds_through_a_taken_branch() {
    let old = build("branch_target", &[("CUBIT_SCHED2", "1")]);
    assert_eq!(old.listing, pinned("branch_target", "sched2_e6bdbb2"), "plain SCHED2 has no such rule: unchanged");
    let (cells, _, _, _, log) = dep_verify("bt_old", &old);
    assert_eq!(cells, 1, "{log}");
    assert!(log.contains("ISETP.LT.U32.AND P0, PT, R0, 0x10, PT -> [34] @P0 IADD3") && log.contains("distance 6 < 13"), "{log}");

    let new = build("branch_target", &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120")]);
    let (setp, bra) = (idx(&new, "ISETP.LT.U32.AND P0", 0), idx(&new, "@P1 BRA", 0));
    assert_eq!(bra, setp + 1);
    assert!(new.lines[setp].stall + new.lines[bra].stall >= 13, "{:?} {:?}", new.lines[setp], new.lines[bra]);
    let v = dep_verify("bt_new", &new);
    assert_eq!((v.0, v.1, v.2, v.3), (0, 0, 0, 0), "{}", v.4);
}

/// Two definitions of one predicate reach the guard at a join: the far one on the text, the near
/// one through `BRA join` (6 cycles under plain SCHED2).
#[test]
fn the_latency_holds_at_a_join() {
    let old = build("join", &[("CUBIT_SCHED2", "1")]);
    assert_eq!(old.listing, pinned("join", "sched2_e6bdbb2"));
    let (cells, _, _, _, log) = dep_verify("join_old", &old);
    assert_eq!(cells, 1, "{log}");
    assert!(log.contains("ISETP.LT.U32.AND P0") && log.contains("distance 6 < 13"), "{log}");

    let new = build("join", &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120")]);
    let setp = idx(&new, "ISETP.LT.U32.AND P0", 0);
    assert!(new.lines[setp + 1].text.starts_with("BRA "), "{:?}", new.lines[setp + 1]);
    assert!(new.lines[setp].stall + new.lines[setp + 1].stall >= 13);
    // the other arm is far on the text already: its ISETP keeps its single cycle
    let other = idx(&new, "ISETP.GT.U32.AND P0", 0);
    assert_eq!(new.lines[other].stall, 1);
    let v = dep_verify("join_new", &new);
    assert_eq!((v.0, v.1, v.2, v.3), (0, 0, 0, 0), "{}", v.4);
}

/// A loop-carried predicate (set at the bottom, guarding the first instruction of the body) and
/// the loop condition: the fixpoint over the back edge terminates and leaves no violation.
#[test]
fn the_latency_holds_around_a_back_edge() {
    let new = build("loop", &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120")]);
    let v = dep_verify("loop_new", &new);
    assert_eq!((v.0, v.1, v.2, v.3), (0, 0, 0, 0), "{}", v.4);
    let head = new.lines.iter().position(|l| l.label.is_some()).expect("loop head label");
    assert!(new.lines[head].text.starts_with("@P0 IADD3 R4"));
    let (setp, bra) = (idx(&new, "ISETP.NE.U32.AND P0, PT, R6", 0), idx(&new, "@P1 BRA", 0));
    assert!(dist(&new, setp, bra + 1) >= 13, "P0 around the back edge: {}", dist(&new, setp, bra + 1));
    let cond = idx(&new, "ISETP.LT.U32.AND P1", 0);
    assert!(dist(&new, cond, bra) >= 13, "loop condition into its branch: {}", dist(&new, cond, bra));
}

// ───────────────────────── latency is a property of the pair ─────────────────────────

/// One straight chain, every producer directly in front of its only consumer: the stall on the
/// producer IS the pair's latency. Plain SCHED2 prices the producer alone (6 / 6 / 13).
#[test]
fn the_latency_is_a_property_of_the_pair() {
    let new = build("pairs", &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120")]);
    let want: [(&str, u32, &str); 12] = [
        ("IADD3 R4", 4, "IADD3 -> IADD3: same unit"),
        ("IADD3 R5", 5, "IADD3 -> IMAD: cross unit"),
        ("IMAD R6", 4, "IMAD -> IMAD: same unit"),
        ("IMAD R7", 5, "IMAD -> IADD3"),
        ("IADD3 R8", 5, "IADD3 -> ISETP"),
        ("ISETP.LT.U32.AND P0", 5, "predicate -> select operand"),
        ("FMUL.FTZ R11", 4, "FMUL -> FADD: same unit"),
        ("FADD.FTZ R12", 4, "FADD -> FADD"),
        ("FADD.FTZ R13", 5, "FADD -> FSETP"),
        ("FSETP.GT.FTZ.AND P1", 5, "predicate -> FSEL"),
        ("FSEL R14", 5, "FSEL -> FMNMX"),
        ("ISETP.GE.U32.AND P2", 13, "predicate -> guard"),
    ];
    for (start, stall, why) in want {
        assert_eq!(new.lines[idx(&new, start, 0)].stall, stall, "{why}: {:?}", new.lines[idx(&new, start, 0)]);
    }
    let v = dep_verify("pairs_new", &new);
    assert_eq!((v.0, v.1, v.2, v.3), (0, 0, 0, 0), "{}", v.4);
    // pairs the table has no cell for are priced with its default and named
    assert!(new.log.contains("priced with a default") && new.log.contains("I2FP -> FMUL"), "{}", new.log);

    let old = build("pairs", &[("CUBIT_SCHED2", "1")]);
    assert_eq!(old.listing, pinned("pairs", "sched2_e6bdbb2"));
    let cycles = |b: &Built| -> u32 { b.lines.iter().map(|l| l.stall).sum() };
    assert!(cycles(&new) + 10 <= cycles(&old), "table {} vs per-producer {}", cycles(&new), cycles(&old));
}

/// The scaled BF16 unpack (`F2FP.BF16.<fmt>.UNPACK_B Rd, Rs[.sel], Rscale.B0`: two codes of Rs times
/// 2^(a byte of Rscale - 127); the table row of `89564ac`) in the two arms of a dequant. It is of
/// the class F2FP.UNPACK: under the table it issues at S01 behind its loads' barriers, and every
/// pair holds its price -- MOV / SEL into it 6 (the default; sm_120 silicon floor 5), its result
/// into a store's data 6 (the default; floor 3) and into HMUL2 6 / 5 (floor 5 either operand).
/// Floors: `tools/stallfloor/stall_floors_sm120_20261110_pairs_d.json`.
#[test]
fn the_scaled_unpack_dequant_holds_the_table() {
    let b = build("dequant_unpackb", &with(&POLICY, &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120"), ("CUBIT_MMA_PTXAS", "1")]));
    // the first unpack waits for the load of its source and for the load of its scale byte
    let u0 = idx(&b, "F2FP.BF16.E4M3.UNPACK_B R4, R20, R24.B0", 0);
    for load in ["LDG.E.128 R20", "LDG.E.U8 R24"] {
        let wb = b.lines[idx(&b, load, 0)].wb.unwrap_or_else(|| panic!("{load} sets no write barrier"));
        assert!((b.lines[u0].wait >> wb) & 1 == 1, "the unpack does not wait for {load}: {:?}", b.lines[u0]);
    }
    // the unpacks of a task issue back to back
    for n in 0..7 {
        let i = idx(&b, "F2FP.BF16.E4M3.UNPACK_B R", n);
        assert_eq!(b.lines[i].stall, 1, "{:?}", b.lines[i]);
    }
    let at = |starts: &str| idx(&b, starts, 0);
    let d = |from: &str, to: &str| dist(&b, at(from), at(to));
    // its result -> the store that reads it
    assert!(d("F2FP.BF16.E4M3.UNPACK_B R11", "STS.128 [R1+0x10], R8") >= 6, "{}", b.listing.join("\n"));
    assert!(d("F2FP.BF16.E4M3.UNPACK_B R7", "STS.128 [R1], R4") >= 6, "{}", b.listing.join("\n"));
    // MOV -> its scale register, SEL -> its source
    assert!(d("MOV R12, 0x7f", "F2FP.BF16.E4M3.UNPACK_B R14") >= 6, "{}", b.listing.join("\n"));
    assert!(d("SEL R16", "F2FP.BF16.E2M1.UNPACK_B R4, R16") >= 6, "{}", b.listing.join("\n"));
    assert!(d("SEL R17", "F2FP.BF16.E2M1.UNPACK_B R8, R17") >= 6, "{}", b.listing.join("\n"));
    // its result -> HMUL2: the value (first operand) and the block scale (second operand, .H0_H0)
    assert!(d("F2FP.BF16.E2M1.UNPACK_B R11", "HMUL2.BF16_V2 R11") >= 6, "{}", b.listing.join("\n"));
    assert!(d("F2FP.BF16.E4M3.UNPACK_B R14", "HMUL2.BF16_V2 R4") >= 5, "{}", b.listing.join("\n"));
    let v = dep_verify("dequant_unpackb", &b);
    assert_eq!((v.0, v.1, v.2, v.3), (0, 0, 0, 0), "{}", v.4);
    for pair in ["F2FP.UNPACK -> STS", "F2FP.UNPACK -> HMUL2", "MOV -> F2FP.UNPACK", "SEL -> F2FP.UNPACK"] {
        assert!(b.log.contains(pair), "{pair} is priced with a default and named:\n{}", b.log);
    }
    // without the switches the kernel assembles as any other (the default scheduler: S05 per unpack)
    let dflt = build("dequant_unpackb", &[]);
    assert!(dflt.lines.iter().filter(|l| l.text.starts_with("F2FP.BF16.E")).all(|l| l.stall == 5), "{}", dflt.listing.join("\n"));
}

/// Issue spacing of the shared pipes, whatever the registers: LDC 8, IMAD.WIDE -> IMAD(.WIDE) 4,
/// IMAD -> IMAD 2, memory 4. Plain SCHED2 packs the multiplies and the constant loads tighter.
#[test]
fn the_shared_pipes_are_spaced() {
    let old = build("resources", &[("CUBIT_SCHED2", "1")]);
    assert_eq!(old.listing, pinned("resources", "sched2_e6bdbb2"));
    let v = dep_verify("res_old", &old);
    assert_eq!(v.2, 4, "{}", v.4);

    let new = build("resources", &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120")]);
    let (l0, l1, l2) = (idx(&new, "LDC.64 R2", 0), idx(&new, "LDC R4", 0), idx(&new, "LDC R5", 0));
    assert!(dist(&new, l0, l1) >= 8 && dist(&new, l1, l2) >= 8, "{:?}", &new.listing[l0..=l2]);
    let (w0, w1, m0, m1) = (idx(&new, "IMAD.WIDE.U32 R12", 0), idx(&new, "IMAD.WIDE.U32 R14", 0), idx(&new, "IMAD R16", 0), idx(&new, "IMAD R17", 0));
    assert!(dist(&new, w0, w1) >= 4 && dist(&new, w1, m0) >= 4 && dist(&new, m0, m1) >= 2, "{:?}", &new.listing[w0..=m1]);
    let (s0, s1, s2) = (idx(&new, "LDS R8", 0), idx(&new, "LDS R9", 0), idx(&new, "LDS R10", 0));
    assert!(dist(&new, s0, s1) >= 4 && dist(&new, s1, s2) >= 4);
    let v = dep_verify("res_new", &new);
    assert_eq!((v.0, v.1, v.2, v.3), (0, 0, 0, 0), "{}", v.4);
}

// ───────────────────────── the MMA chain ─────────────────────────

fn mma_rows_hold(b: &Built, what: &str) {
    let mmas: Vec<usize> = b.lines.iter().enumerate().filter(|(_, l)| l.text.starts_with("HMMA")).map(|(i, _)| i).collect();
    assert!(mmas.len() >= 4);
    for w in mmas.windows(2) {
        assert!(dist(b, w[0], w[1]) >= 16, "{what}: two MMAs {} apart\n{}", dist(b, w[0], w[1]), b.listing.join("\n"));
    }
    // the accumulate operand: the next MMA that reads R28 back
    let chain: Vec<usize> = mmas.iter().copied().filter(|&i| b.lines[i].text.starts_with("HMMA.16816.F32.BF16 R28")).collect();
    for w in chain.windows(2) {
        assert!(dist(b, w[0], w[1]) >= 29, "{what}: accumulate {} behind its producer\n{}", dist(b, w[0], w[1]), b.listing.join("\n"));
    }
    let reader = idx(b, "FADD.FTZ R4, R28, R32", 0);
    for &m in &mmas[mmas.len() - 2..] {
        assert!(dist(b, m, reader) >= 28, "{what}: reader {} behind `{}`", dist(b, m, reader), b.lines[m].text);
    }
}

/// `CUBIT_MMA_PTXAS=1`: no writeback drain, the MMA rows of the table by issue distance alone
/// (16 between any two, 29 into the accumulate operand, 28 into any other reader), one pad where
/// a single stall field cannot carry a row (two MMAs back to back, a reader right behind an MMA).
#[test]
fn mma_ptxas_keeps_the_mma_rows_without_drains() {
    let env = with(&POLICY, &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120"), ("CUBIT_MMA_PTXAS", "1")]);
    for name in ["mma_chain", "mma_adjacent"] {
        let b = build(name, &env);
        assert!(!b.listing.iter().any(|l| l.contains("UIADD3")), "{name}: a drain survived\n{}", b.listing.join("\n"));
        mma_rows_hold(&b, name);
        let v = dep_verify(name, &b);
        assert_eq!((v.0, v.1, v.2, v.3), (0, 0, 0, 0), "{name}: {}", v.4);
    }
    // pads: one between the two adjacent MMAs of the chain kernel; in the adjacent kernel also
    // behind the MMA whose reader follows it directly
    let nops = |n: &str| build(n, &env).lines.iter().filter(|l| l.text == "NOP").count();
    assert_eq!(nops("mma_chain"), 1);
    assert_eq!(nops("mma_adjacent"), 3);
}

/// With the drains kept (`CUBIT_SCHED2_LAT` alone) the same rows hold; the policy build without
/// the switches is the pinned one.
#[test]
fn the_table_holds_the_mma_rows_with_the_drains_kept() {
    for name in ["mma_chain", "mma_adjacent"] {
        let b = build(name, &with(&POLICY, &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120")]));
        assert!(b.listing.iter().any(|l| l.contains("UIADD3")), "{name}: the drains stay without CUBIT_MMA_PTXAS");
        mma_rows_hold(&b, name);
        let v = dep_verify(name, &b);
        assert_eq!((v.0, v.1, v.2, v.3), (0, 0, 0, 0), "{name}: {}", v.4);
        assert_eq!(build(name, &POLICY).listing, pinned(name, "policy"), "{name}: the policy build moved");
    }
}

// ───────────────────────── switches ─────────────────────────

#[test]
fn the_switches_fail_closed() {
    let src = format!("{FIX}/pairs.sass");
    let e = build_src("lat_alone", &src, &[("CUBIT_SCHED2_LAT", "sm120")]).err().expect("LAT without SCHED2 must fail");
    assert!(e.contains("CUBIT_SCHED2_LAT needs CUBIT_SCHED2=1"), "{e}");
    let e = build_src("mma_alone", &src, &[("CUBIT_SCHED2", "1"), ("CUBIT_MMA_PTXAS", "1")]).err().expect("MMA_PTXAS without a table must fail");
    assert!(e.contains("CUBIT_MMA_PTXAS=1 needs"), "{e}");
    let e = build_src("lat_nofile", &src, &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "/nonexistent/table.json")]).err().expect("a missing table must fail");
    assert!(e.contains("cannot read"), "{e}");
    // arch lock: the sm_120 table is refused against another architecture's ISA table (the same source
    // assembles there without the switch)
    let t103 = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm103a.json.gz");
    let dir = scratch("arch_lock");
    let out = dir.join("k.cubin");
    let (ok, log) = cubit(&["asm", "-t", t103, &src, "-o", out.to_str().unwrap()], &[("CUBIT_SCHED2", "1")]);
    assert!(ok, "the fixture assembles for sm_103a without the table:\n{log}");
    let (ok, log) = cubit(&["asm", "-t", t103, &src, "-o", out.to_str().unwrap()], &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120")]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(!ok && log.contains("is for sm_120 but the ISA table is SM103"), "{log}");
    // off values
    for off in ["", "0"] {
        let b = build_src("lat_off", &src, &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", off)]).unwrap();
        assert_eq!(b.listing, pinned("pairs", "sched2_e6bdbb2"), "CUBIT_SCHED2_LAT={off:?} is off");
    }
}

/// No switch: every fixture assembles to the listing `e6bdbb2` produced.
#[test]
fn the_default_path_is_unchanged() {
    for name in ["arm", "branch_target", "join", "loop", "pairs", "resources", "mma_chain", "mma_adjacent"] {
        assert_eq!(build(name, &[]).listing, pinned(name, "default"), "{name}");
    }
}
