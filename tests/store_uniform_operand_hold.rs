//! The uniform register of a store's address is held against a fixed-latency rewrite (2026-11-11).
//!
//! A store reads its address when the memory pipe serves it, not at issue. Its general registers are covered by
//! the read barrier it carries: whoever rewrites one waits on it. The UNIFORM register of the address — the
//! descriptor of `STG.E desc[UR4][R22.64], R16`, the uniform base of `STS [UR4+0x10], R8` — is in nobody's list:
//! the barrier allocator's late operands are general registers, the dependency table has no write-after-read
//! row, and the operand hold knew two readers (a tensor instruction, a word of the uniform datapath). What kept a
//! `UMOV UR4, …` away from the store was the first scheduling pass's blanket stall of 4 behind every store — the
//! margin `CUBIT_SCHED2_MEMSTALL=table` takes away. cubit's schedule of a served kernel under that variable had
//! `@P0 STG.E.128 desc[UR4][R22.64], R16 [S01] ; BSYNC [S05] ; UMOV UR4, 0xffffffff`: 6 issue cycles, where the
//! vendor's own schedule of the same words has 7 — the distance the vendor's schedules keep (the flow view over the
//! ptxas census: 656 rewrites of a barred store's uniform operand with no wait on its barrier stand at 7 or more, 82
//! at exactly 7; 14 stand closer, one `ULOP3` at 3 behind an `STS.128` in 14 builds).
//!
//! The operand hold has the third reader now: a fixed-latency writer of the uniform register of a store's address
//! stands 7 issue cycles behind the store (`sync_class::STORE_UNIFORM_OPERAND_HOLD`) — the distance the vendor keeps but for that
//! one `ULOP3`; the rule is 7 for every fixed-latency writer (KNOWN_ISSUES A45). It acts where the operand hold runs: under `CUBIT_SYNC_CLASSES` and under
//! `CUBIT_SCHED2_MEMSTALL=table`. The default path is not touched.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
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

/// (stall, text) of every instruction line of the schedule `cubit asm` builds from `text` under `env`, and its log.
fn build(text: &str, env: &[(&str, &str)]) -> (Vec<(u32, String)>, String) {
    let dir = std::env::temp_dir().join(format!("uhold_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, text).unwrap();
    let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()], env);
    assert!(ok, "asm {env:?} failed:\n{log}");
    let (ok, frozen) = cubit(&["disassemble", "-t", TABLE, "--frozen", out.to_str().unwrap()], &[]);
    assert!(ok, "disassemble failed: {frozen}");
    let _ = std::fs::remove_dir_all(&dir);
    let lines: Vec<(u32, String)> = frozen
        .lines()
        .filter_map(|l| {
            let t = l.trim_start();
            let close = t.find(']')?;
            let f: Vec<&str> = t.strip_prefix('[')?[..close - 1].split(':').collect();
            (f.len() == 5 && f[4].starts_with('S')).then(|| (f[4][1..].parse().unwrap(), t[close + 1..].trim().trim_end_matches(';').trim().to_string()))
        })
        .collect();
    assert!(!lines.is_empty(), "no instruction lines in:\n{frozen}");
    (lines, log)
}

/// Issue distance from the first word that starts with `from` to the first word behind it that starts with `to`.
fn distance(lines: &[(u32, String)], from: &str, to: &str) -> u32 {
    let a = lines.iter().position(|l| l.1.starts_with(from)).unwrap_or_else(|| panic!("no `{from}` in {lines:?}"));
    let b = a + lines[a..].iter().position(|l| l.1.starts_with(to)).unwrap_or_else(|| panic!("no `{to}` behind `{from}` in {lines:?}"));
    lines[a..b].iter().map(|l| l.0).sum()
}

/// Three stores and a rewrite of the uniform register of each one's address right behind it: the descriptor of a
/// global store, the uniform base of a shared store without and with a general register; a fourth store whose
/// descriptor nobody rewrites.
const STORES: &str = "\
.entry uhold_probe
    .reg R0-R31
    .param ptr out
    LDCU.64 UR4, c[0x0][0x358] ;
    LDC.64 R2, c[0x0][0x380] ;
    MOV R5, 0x3f800000 ;
    MOV R20, 0x100 ;
    STG.E desc[UR4][R2.64], R5 ;
    UMOV UR4, 0x400 ;
    STS [UR4+0x10], R5 ;
    UMOV UR4, 0x800 ;
    MOV R6, UR4 ;
    STS [R20+UR4+0x20], R6 ;
    R2UR UR4, R20 ;
    MOV R7, UR4 ;
    STG.E desc[UR6][R2.64+0x8], R7 ;
    EXIT ;
.endentry
";

#[test]
fn a_fixed_latency_rewrite_of_the_uniform_register_of_a_stores_address_stands_seven_cycles_behind_it() {
    for (name, env) in [("the table's stalls behind memory words", with(S1, &[("CUBIT_SCHED2_MEMSTALL", "table")])), ("the synchronisation classes", with(S1, &[("CUBIT_SYNC_CLASSES", "1")]))] {
        let (lines, log) = build(STORES, &with(&env, &[("CUBIT_VERIFY", "1"), ("CUBIT_DEP_VERIFY", "1")]));
        for (store, writer) in [("STG.E desc[UR4]", "UMOV UR4, 0x400"), ("STS [UR4+0x10]", "UMOV UR4, 0x800"), ("STS [R20+UR4+0x20]", "R2UR UR4")] {
            let d = distance(&lines, store, writer);
            assert!(d >= 7, "{name}: `{writer}` {d} issue cycles behind `{store}`:\n{lines:?}");
        }
        assert!(log.contains("3 overwriters moved behind the operand hold of their reader"), "{name}: {log}");
        assert!(log.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale"), "{name}: {log}");
        assert!(log.contains("DEP_VERIFY 0 below a table cell, 0 waits closer than the arming distance to their barrier's setter, 0 below a resource spacing, 0 below a default"), "{name}: {log}");
    }
    // under the table's stalls the hold is all that stands behind the store: exactly seven, and a store whose
    // uniform register nobody rewrites keeps the one cycle
    let (lines, _) = build(STORES, &with(S1, &[("CUBIT_SCHED2_MEMSTALL", "table")]));
    assert_eq!(distance(&lines, "STG.E desc[UR4]", "UMOV UR4, 0x400"), 7, "{lines:?}");
    assert_eq!(lines.iter().find(|l| l.1.starts_with("STG.E desc[UR6]")).unwrap().0, 1, "{lines:?}");
}

#[test]
fn a_load_of_the_register_is_not_held_and_the_default_path_does_not_run_the_operand_hold() {
    // a scoreboarded writer of the uniform register lands late: no distance is asked of it
    let text = STORES.replace("    UMOV UR4, 0x400 ;\n", "    LDCU.64 UR4, c[0x0][0x360] ;\n").replace("    UMOV UR4, 0x800 ;\n", "    LDCU.64 UR4, c[0x0][0x368] ;\n").replace("    R2UR UR4, R20 ;\n", "    LDCU.64 UR4, c[0x0][0x370] ;\n");
    let (_, log) = build(&text, &with(S1, &[("CUBIT_SCHED2_MEMSTALL", "table")]));
    assert!(!log.contains("overwriters moved behind the operand hold"), "{log}");
    // the operand hold runs under the two variables only: the default path and the plain dependency-aware
    // schedule are what they were
    for env in [&[][..], S1] {
        let (_, log) = build(STORES, env);
        assert!(!log.contains("overwriters moved behind the operand hold"), "{env:?}: {log}");
    }
}
