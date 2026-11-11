//! BUG-489 (2026-11-11): write after write — a register whose scoreboarded result is pending, written again with
//! no wait on the producer's write barrier: the verifier's class for it, and the three shapes the barrier allocator
//! left without a wait.
//!
//! The allocator has made an overwriter of a pending result wait like a reader since BUG-485, except:
//!
//! * **two loads of one batch into one register** — consecutive loads of one opcode, width and address line share a
//!   write barrier, and the batch loop stops at an instruction that READS a result of the group, not at one that
//!   writes one again. Found in cubit's own schedule of a served kernel (the persistent MoE kernel under
//!   `CUBIT_SYNC_CLASSES`): `LDC.64 R28, c[0x0][0x388]` and, five instructions later, `@P0 LDC.64 R28,
//!   c[0x0][0x3b8]`, both on barrier 5 with no wait between — two results in flight for one register, with nothing
//!   between them but the order of the pipe. ptxas schedules the same two words `[W3]` … `[B---3--:W1]`: the second
//!   waits on the first's barrier;
//! * **a fixed-latency overwriter between two batch-mates** — the scan for a group's first consumers starts behind
//!   its last setter;
//! * **a producer issued again by its own loop** when nobody read or rewrote its last result on the way round — that
//!   scan ends back at the producer.
//!
//! In the vendor's own text (the sm_120 census: 166 listings, 752 kernels, every path of the flow graph) a pending
//! result is written again without a wait in exactly one shape — 3 sites of a `SHFL` without a write barrier behind
//! a shared-memory quad, which the verifier counts apart; writers under complementary guards (`@P2 LDG … R14` /
//! `@!P2 LDG … R14`, 1 070 on one barrier in the straight-line text) are no pair: one of the two executes.
//!
//! The verifier (`store_paths::unwaited_rewrites`, under `CUBIT_VERIFY`) reports every such pair of a scheduled
//! kernel on every path — it used to drop a pending result silently when its register was written again. The fix
//! (`scheduling_pass.rs::reallocate_barriers`, its last pass): under `CUBIT_SYNC_CLASSES` — the switch under which
//! the pair was found — the allocator closes its schedule under that walk: the second writer waits the producer's
//! write barrier. Only waits are added. **The default path is byte for byte what it was**; `CUBIT_WAW_WAIT=1` turns
//! the pass on there too, `CUBIT_WAW_WAIT=0` turns it off under the switch (the allocator as it was, for an A/B).

use serde_json::Value;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");

/// The switch sets under which the allocator closes its schedule: the synchronisation classes alone, the set of
/// the served MoE schedules, and the default path with the pass asked for by name.
const ON: [&[(&str, &str)]; 3] = [
    &[("CUBIT_SYNC_CLASSES", "1")],
    &[("CUBIT_SYNC_CLASSES", "1"), ("CUBIT_SCHED2", "1"), ("CUBIT_MMA_PTXAS", "1"), ("CUBIT_SCHED2_LAT", "sm120")],
    &[("CUBIT_WAW_WAIT", "1")],
];

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bug489_{}_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst), tag));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Line {
    wait: u8,
    rb: Option<u8>,
    wb: Option<u8>,
    stall: u32,
    text: String,
}

impl Line {
    fn waits(&self, b: u8) -> bool {
        self.wait & (1 << b) != 0
    }
}

fn parse_line(l: &str) -> Option<Line> {
    let t = l.trim_start();
    let rest = match t.find('[') {
        Some(0) => t,
        Some(p) if t[..p].trim_end().ends_with(':') => &t[p..],
        _ => return None,
    };
    let close = rest.find(']')?;
    let f: Vec<&str> = rest[1..close].split(':').collect();
    if f.len() != 5 || !f[0].starts_with('B') || !f[4].starts_with('S') {
        return None;
    }
    let wait = f[0][1..].chars().filter_map(|c| c.to_digit(10)).fold(0u8, |m, b| m | (1 << b));
    let bar = |s: &str| s[1..].parse::<u8>().ok();
    Some(Line { wait, rb: bar(f[1]), wb: bar(f[2]), stall: f[4][1..].parse().ok()?, text: rest[close + 1..].trim().trim_end_matches(';').trim().to_string() })
}

struct Built {
    lines: Vec<Line>,
    cubin: Vec<u8>,
    /// what `cubit asm` printed (the verifier's lines when `CUBIT_VERIFY` is in the environment)
    log: String,
}

/// `cubit asm` of `text` under `env`, then the schedule read back from the cubin.
fn build(text: &str, env: &[(&str, &str)]) -> Built {
    let dir = scratch("k");
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, text).unwrap();
    let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()], env);
    assert!(ok, "asm {env:?} failed:\n{log}");
    let cubin = std::fs::read(&out).unwrap();
    let (ok, frozen) = cubit(&["disassemble", "-t", TABLE, "--frozen", out.to_str().unwrap()], &[]);
    assert!(ok, "disassemble failed: {frozen}");
    let _ = std::fs::remove_dir_all(&dir);
    let lines: Vec<Line> = frozen.lines().filter_map(parse_line).collect();
    assert!(!lines.is_empty(), "no instruction lines in:\n{frozen}");
    Built { lines, cubin, log }
}

/// The `nth` instruction whose text starts with `head`.
fn at<'a>(b: &'a Built, head: &str, nth: usize) -> &'a Line {
    b.lines.iter().filter(|l| l.text.starts_with(head)).nth(nth).unwrap_or_else(|| panic!("no `{head}` #{nth} in {:?}", b.lines))
}

/// The producer carries a write barrier and the other instruction waits it.
fn assert_waits(prod: &Line, cons: &Line, what: &str, env: &[(&str, &str)]) {
    let wb = prod.wb.unwrap_or_else(|| panic!("{env:?} {what}: `{}` must carry a write barrier", prod.text));
    assert!(cons.waits(wb), "{env:?} {what}: `{}` must wait W{wb} of `{}` (wait mask {:#04x})", cons.text, prod.text, cons.wait);
}

fn with<'a>(env: &[(&'a str, &'a str)], more: (&'a str, &'a str)) -> Vec<(&'a str, &'a str)> {
    let mut v = env.to_vec();
    v.push(more);
    v
}

/// `R2` (an address) and `P0` are ready before the body: the predicate's reader of `R2` ends the prologue's own
/// batch, so the loads of the body start a batch of their own.
fn kernel(body: &str) -> String {
    format!(
        ".entry waw_probe\n    .reg R0-R31\n    .param ptr out\n    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n    ISETP.NE.AND P0, PT, R2, RZ, PT ;\n{body}    EXIT ;\n"
    )
}

/// The site: a default and its guarded override from the same constant line.
const SITE: &str = "    LDC.64 R28, c[0x0][0x388] ;\n    @P0 LDC.64 R28, c[0x0][0x3b8] ;\n    STG.E.64 desc[UR4][R2.64+0x8], R28 ;\n";

#[test]
fn a_second_load_into_a_register_of_the_batch_waits_the_first() {
    for env in ON {
        let b = build(&kernel(SITE), env);
        let (first, second) = (at(&b, "LDC.64 R28", 0), at(&b, "@P0 LDC.64 R28", 0));
        assert_waits(first, second, "the guarded override of a pending load", env);
        // the reader waits the barrier the override set behind its own wait
        assert_waits(second, at(&b, "STG.E.64", 0), "RAW of the override", env);
        // an unguarded second load (a dead first load: the second replaces it on every path) waits too
        let b = build(&kernel("    LDC.64 R28, c[0x0][0x388] ;\n    LDC.64 R28, c[0x0][0x390] ;\n    STG.E.64 desc[UR4][R2.64+0x8], R28 ;\n"), env);
        assert_waits(at(&b, "LDC.64 R28", 0), at(&b, "LDC.64 R28", 1), "a dead load replaced by its batch-mate", env);
    }
}

#[test]
fn loads_of_other_registers_and_writers_under_complementary_guards_stay_as_they_were() {
    for env in ON {
        // three loads of one line into three registers: one barrier, nobody waits inside the batch
        let b = build(
            &kernel("    LDC.64 R28, c[0x0][0x388] ;\n    LDC.64 R30, c[0x0][0x390] ;\n    LDC.64 R26, c[0x0][0x398] ;\n    IADD.64 R28, R28, R30 ;\n    STG.E.64 desc[UR4][R2.64+0x8], R26 ;\n"),
            env,
        );
        let (x, y, z) = (at(&b, "LDC.64 R28", 0), at(&b, "LDC.64 R30", 0), at(&b, "LDC.64 R26", 0));
        let wb = x.wb.unwrap();
        assert_eq!((y.wb, z.wb), (Some(wb), Some(wb)), "{env:?}: three loads of one line, three registers: one barrier");
        assert!(!y.waits(wb) && !z.waits(wb), "{env:?}: {:?}", b.lines);
        assert_waits(x, at(&b, "IADD.64", 0), "the batch's first reader", env);
        // `@P0` / `@!P0` into one register: one of the two executes — no pair, and ptxas keeps such loads on one barrier
        let b = build(&kernel("    @P0 LDC.64 R28, c[0x0][0x388] ;\n    @!P0 LDC.64 R28, c[0x0][0x3b8] ;\n    STG.E.64 desc[UR4][R2.64+0x8], R28 ;\n"), env);
        let (x, y) = (at(&b, "@P0 LDC.64 R28", 0), at(&b, "@!P0 LDC.64 R28", 0));
        let wb = x.wb.unwrap();
        assert_eq!(y.wb, Some(wb), "{env:?}: the two arms share the barrier");
        assert!(!y.waits(wb), "{env:?}: the second arm does not wait the first");
        // ... until the predicate is rewritten between them: then both may execute
        let b = build(
            &kernel("    @P0 LDC.64 R28, c[0x0][0x388] ;\n    ISETP.NE.AND P0, PT, R3, RZ, PT ;\n    @!P0 LDC.64 R28, c[0x0][0x3b8] ;\n    STG.E.64 desc[UR4][R2.64+0x8], R28 ;\n"),
            env,
        );
        assert_waits(at(&b, "@P0 LDC.64 R28", 0), at(&b, "@!P0 LDC.64 R28", 0), "both arms may execute once the predicate changed", env);
    }
}

#[test]
fn a_fixed_latency_overwriter_between_two_batch_mates_waits() {
    // the `MOV` stands inside the batch's span and was never scanned: the first load's result could land on top of it
    for env in ON {
        let b = build(
            &kernel("    LDC.64 R28, c[0x0][0x388] ;\n    MOV R28, 0x1 ;\n    LDC.64 R30, c[0x0][0x390] ;\n    IADD.64 R28, R28, R30 ;\n    STG.E.64 desc[UR4][R2.64+0x8], R28 ;\n"),
            env,
        );
        assert_waits(at(&b, "LDC.64 R28", 0), at(&b, "MOV R28", 0), "an overwriter inside the batch's span", env);
    }
}

/// A load that nobody reads inside its loop (its reader stands behind the loop): every iteration issues it again
/// while the last iteration's result is still pending.
const DEAD_IN_LOOP: &str = ".entry waw_loop\n    .reg R0-R31\n    .param ptr out\n    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n    MOV R6, RZ ;\nL_top:\n    LDG.E R20, desc[UR4][R2.64] ;\n    IADD3 R6, PT, PT, R6, 0x1, RZ ;\n    ISETP.LT.AND P0, PT, R6, 0x100, PT ;\n    @P0 BRA L_top ;\n    STG.E desc[UR4][R2.64+0x8], R20 ;\n    EXIT ;\n";

#[test]
fn a_producer_reached_again_by_its_own_loop_waits_its_own_barrier() {
    for env in ON {
        let b = build(DEAD_IN_LOOP, env);
        let ldg = at(&b, "LDG.E R20", 0);
        assert_waits(ldg, ldg, "the load issued again with its last result pending", env);
        assert_waits(ldg, at(&b, "STG.E", 0), "RAW behind the loop", env);
        // a load that IS read on every path around its loop needs no wait of its own
        let b = build(&DEAD_IN_LOOP.replace("IADD3 R6, PT, PT, R6, 0x1, RZ", "IADD3 R6, PT, PT, R6, R20, RZ"), env);
        let ldg = at(&b, "LDG.E R20", 0);
        assert!(!ldg.waits(ldg.wb.unwrap()), "{env:?}: the reader in the loop waited: the load does not wait itself");
    }
}

#[test]
fn only_waits_are_added_and_the_verifier_names_what_the_allocator_left() {
    let cases = [
        (kernel(SITE), "@P0 LDC.64 R28", "insn[3] LDC.64", "insn[4] LDC.64"),
        (DEAD_IN_LOOP.to_string(), "LDG.E R20", "insn[3] LDG.E", "insn[3] LDG.E"),
    ];
    for (text, second, producer, writer) in cases {
        for env in ON {
            let on = build(&text, &with(env, ("CUBIT_VERIFY", "1")));
            let off = build(&text, &with(&with(env, ("CUBIT_VERIFY", "1")), ("CUBIT_WAW_WAIT", "0")));
            // the allocator as it was: the pair, reported beside the three classic counts
            let pairs: Vec<&str> = off.log.lines().filter(|l| l.contains("WRITE AFTER WRITE:")).map(str::trim).collect();
            assert_eq!(pairs.len(), 1, "{env:?}: {}", off.log);
            assert!(
                pairs[0].starts_with(&format!("WRITE AFTER WRITE: {producer} (write barrier ")) && pairs[0].contains(&format!("<- written again by {writer} (write barrier ")),
                "{}",
                off.log
            );
            assert!(off.log.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale"), "{}", off.log);
            assert!(off.log.lines().any(|l| l.starts_with("CUBIT_VERIFY_WAW: 1 pending result(s) written again on a path with no wait on the producer's write barrier")), "{}", off.log);
            // closed: no pair, and one control word differs — the second writer's wait mask
            assert!(!on.log.contains("WRITE AFTER WRITE") && !on.log.contains("CUBIT_VERIFY_WAW"), "{env:?}: {}", on.log);
            assert_eq!(on.lines.len(), off.lines.len());
            let moved: Vec<(&Line, &Line)> = on.lines.iter().zip(&off.lines).filter(|(a, b)| a != b).collect();
            assert_eq!(moved.len(), 1, "{env:?}: {moved:?}");
            let (a, b) = moved[0];
            assert!(a.text.starts_with(second), "{a:?}");
            assert_eq!((&a.text, a.rb, a.wb, a.stall), (&b.text, b.rb, b.wb, b.stall), "only the wait mask moves");
            assert_eq!(a.wait & b.wait, b.wait, "no wait is taken away");
            assert_eq!((a.wait ^ b.wait).count_ones(), 1, "one wait is added: {a:?} / {b:?}");
        }
    }
}

#[test]
fn the_default_path_is_byte_for_byte_and_its_pair_is_reported() {
    for text in [kernel(SITE), DEAD_IN_LOOP.to_string()] {
        // without a switch the pass does not run: the same bytes as with it turned off by name ...
        let plain = build(&text, &[]);
        let off = build(&text, &[("CUBIT_WAW_WAIT", "0")]);
        assert_eq!(plain.cubin, off.cubin, "the default path moved");
        assert_eq!(plain.lines, off.lines);
        // ... and the verifier names the pair the default allocator leaves
        let checked = build(&text, &[("CUBIT_VERIFY", "1")]);
        assert_eq!(checked.cubin, plain.cubin, "CUBIT_VERIFY is read-only");
        assert_eq!(checked.log.lines().filter(|l| l.contains("WRITE AFTER WRITE:")).count(), 1, "{}", checked.log);
        // asked for by name, the default path is closed like the others
        let on = build(&text, &[("CUBIT_WAW_WAIT", "1"), ("CUBIT_VERIFY", "1")]);
        assert_ne!(on.cubin, plain.cubin);
        assert!(!on.log.contains("WRITE AFTER WRITE"), "{}", on.log);
    }
}

/// A frozen schedule with the pair (`second` = the control field of the second load).
fn frozen(second: &str) -> String {
    format!(
        concat!(
            ".entry k\n    .reg R0-R95\n    .regcount 104\n    .param u64 p0 offset=0x0\n",
            "    [B------:R-:W5:Y:S04] LDC.64 R28, c[0x0][0x388] ;\n",
            "    [B------:R-:W-:-:S06] ISETP.NE.AND P0, PT, R58, RZ, PT ;\n",
            "    [B------:R-:W5:Y:S08] @P0 LDC.64 R30, c[0x0][0x3b0] ;\n",
            "    [{}] @P0 LDC.64 R28, c[0x0][0x3b8] ;\n",
            "    [B01---5:R-:W-:-:S02] IADD.64 R80, R28, R30 ;\n",
            "    [B------:R-:W-:Y:S05] EXIT ;\n.endentry\n"
        ),
        second
    )
}

/// `cubit asm` of a frozen `text` under `env` in `dir`: (ok, stdout + stderr).
fn asm(dir: &std::path::Path, name: &str, text: &str, env: &[(&str, &str)]) -> (bool, String) {
    let src = dir.join(format!("{name}.sass"));
    std::fs::write(&src, text).unwrap();
    cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", dir.join(format!("{name}.cubin")).to_str().unwrap()], env)
}

#[test]
fn the_json_line_carries_the_pair_and_legality_diff_refuses_a_candidate_that_adds_it() {
    let dir = scratch("json");
    let line = |name: &str, second: &str| -> (String, Value) {
        let file = dir.join(format!("{name}.jsonl"));
        let (ok, log) = asm(&dir, name, &frozen(second), &[("CUBIT_VERIFY_JSON", file.to_str().unwrap())]);
        assert!(ok, "{log}");
        let text = std::fs::read_to_string(&file).unwrap();
        (file.to_str().unwrap().to_string(), serde_json::from_str(text.lines().next().unwrap()).unwrap())
    };
    // the seed: the second load waits on the first's barrier and takes its own (the vendor's form)
    let (seed_file, seed) = line("seed", "B-----5:R-:W1:Y:S04");
    assert_eq!(seed["scoreboard"]["waw"], 0);
    assert!(seed["scoreboard"]["findings"].as_array().unwrap().is_empty(), "{seed}");
    // the candidate: the wait dropped, both loads on one barrier
    let (cand_file, cand) = line("cand", "B------:R-:W5:Y:S04");
    let sb = &cand["scoreboard"];
    assert_eq!((&sb["raw"], &sb["war"], &sb["recycle_stale"], &sb["waw"], &sb["waw_shuffle_into_load"]), (&0.into(), &0.into(), &0.into(), &1.into(), &0.into()));
    let f = sb["findings"].as_array().unwrap();
    assert_eq!(f.len(), 1, "{cand}");
    assert_eq!((f[0]["kind"].as_str(), f[0]["other"].as_u64(), f[0]["at"].as_u64(), f[0]["register"].as_str()), (Some("waw"), Some(0), Some(3), Some("R28")));
    assert!(f[0]["other_text"].as_str().unwrap().contains("LDC.64 R28, c[0x0][0x388]"));
    assert!(f[0]["at_text"].as_str().unwrap().contains("@P0 LDC.64 R28, c[0x0][0x3b8]"));
    // the rule a gate holds a candidate to
    let d = cubit::legality::compare(&seed, &cand);
    assert_eq!(d.new.iter().map(|x| (x.list, x.key.as_str())).collect::<Vec<_>>(), [("scoreboard", "waw [0] -> [3] R28")]);
    let (ok, log) = cubit(&["legality-diff", &seed_file, &cand_file], &[]);
    assert!(!ok && log.contains("new    scoreboard waw [0] -> [3] R28:"), "{log}");
    // the other way round the pair is gone: clean
    let (ok, log) = cubit(&["legality-diff", &cand_file, &seed_file], &[]);
    assert!(ok, "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_class_is_read_only_and_silent_without_cubit_verify_and_a_frozen_schedule_is_not_repaired() {
    let dir = scratch("ro");
    let text = frozen("B------:R-:W5:Y:S04");
    let (ok, plain) = asm(&dir, "plain", &text, &[]);
    assert!(ok, "{plain}");
    assert!(!plain.contains("WRITE AFTER WRITE") && !plain.contains("CUBIT_VERIFY"), "{plain}");
    // a hand-scheduled kernel owns its control codes: the pair is reported, under every switch, and nothing moves
    for env in [&[("CUBIT_VERIFY", "1")][..], &[("CUBIT_VERIFY", "1"), ("CUBIT_SYNC_CLASSES", "1")][..], &[("CUBIT_VERIFY", "1"), ("CUBIT_WAW_WAIT", "1")][..]] {
        let (ok, checked) = asm(&dir, "checked", &text, env);
        assert!(ok, "{checked}");
        assert!(
            checked.contains("WRITE AFTER WRITE: insn[0] LDC.64 (write barrier 5) R28 <- written again by insn[3] LDC.64 (write barrier 5: two results in flight) 18 issue cycles later on a path with no wait on barrier 5"),
            "{env:?}: {checked}"
        );
        assert_eq!(std::fs::read(dir.join("plain.cubin")).unwrap(), std::fs::read(dir.join("checked.cubin")).unwrap(), "{env:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
