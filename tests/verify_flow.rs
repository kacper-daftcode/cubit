//! `CUBIT_VERIFY_FLOW=1` (2026-11-11): the three kinds of the scoreboard simulation on the paths of the flow graph.
//!
//! `CUBIT_VERIFY` simulates the scoreboard along the TEXT: the state of one word is handed to the next, also
//! across a word that never falls through, and a loop is the text between a backward branch and its target. On a
//! kernel laid out as nvcc lays it out — out-of-line blocks behind the hot text, entered by a forward branch,
//! left by a backward one — that reports what no execution has (one store of a served kernel's schedule: 276
//! "broken WAR" lines, 0 of them on a path; the vendor's own schedules of the served kernels: every unprotected
//! RAW and every broken WAR of the simulation) and misses what one has (a forward branch carries nothing to its
//! target). With the variable the same three kinds are walked on the flow graph (`src/sb_flow.rs`) and printed as
//! a view of their own, `CUBIT_VERIFY_FLOW: …`, next to the three classic counts. **Without the variable nothing
//! is printed or written that was not before.**

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const FLOW: (&str, &str) = ("CUBIT_VERIFY_FLOW", "1");

/// `cubit asm` of a scheduled listing under `CUBIT_VERIFY=1` + `env`: (what it printed, the cubin, the JSON line).
fn verify(listing: &str, env: &[(&str, &str)]) -> (String, Vec<u8>, serde_json::Value) {
    let dir = std::env::temp_dir().join(format!("vflow_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out, js) = (dir.join("k.sass"), dir.join("k.cubin"), dir.join("k.jsonl"));
    std::fs::write(&src, listing).unwrap();
    let o = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .env_clear()
        .env("CUBIT_VERIFY", "1")
        .env("CUBIT_VERIFY_JSON", &js)
        .envs(env.iter().copied())
        .output()
        .expect("run cubit");
    let log = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success(), "{env:?}: {log}");
    let cubin = std::fs::read(&out).unwrap();
    let line: serde_json::Value = serde_json::from_str(std::fs::read_to_string(&js).unwrap().lines().next().unwrap()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    // the path of the scratch directory is the only thing that differs between two runs
    (log.replace(dir.to_str().unwrap(), "<dir>"), cubin, line)
}

fn kernel(body: &str) -> String {
    format!(".entry flow_probe\n    .reg R0-R31\n    .param ptr out\n{body}.endentry\n")
}

fn flow_line(log: &str) -> &str {
    log.lines().find(|l| l.starts_with("CUBIT_VERIFY_FLOW: ") && !l.starts_with("CUBIT_VERIFY_FLOW: +")).unwrap_or_else(|| panic!("no CUBIT_VERIFY_FLOW line in:\n{log}"))
}

/// A store in the last block of a loop; the first word at the loop top rewrites its address register and waits
/// its read barrier (`wait`). Behind the unconditional back branch stands an out-of-line block — entered from
/// the loop by a forward branch, left by a backward one — that rewrites the same register.
fn loop_with_an_out_of_line_block(wait: &str) -> String {
    kernel(&format!(
        "    [B------:R-:W-:Y:S01] MOV R6, 0x10 ;
L_top:
    [{wait}:R-:W-:Y:S01] IADD3 R4, PT, PT, R6, 0x4, RZ ;
    [B------:R-:W-:Y:S01] MOV R5, RZ ;
    [B------:R-:W-:-:S13] ISETP.NE.AND P0, PT, R6, RZ, PT ;
    [B------:R-:W-:Y:S05] @P0 BRA L_cold ;
L_back:
    [B------:R-:W-:Y:S01] IADD3 R6, PT, PT, R6, 0x1, RZ ;
    [B------:R3:W-:Y:S04] STG.E desc[UR4][R4.64], R7 ;
    [B------:R-:W-:Y:S05] BRA L_top ;
L_cold:
    [B------:R-:W-:Y:S01] MOV R4, 0x40 ;
    [B------:R-:W-:Y:S05] BRA L_back ;
    [B------:R-:W-:Y:S05] EXIT ;
"
    ))
}

#[test]
fn a_wait_on_the_path_is_protection_whatever_text_stands_behind_the_branch() {
    let listing = loop_with_an_out_of_line_block("B---3--");
    let (classic, cubin, json) = verify(&listing, &[]);
    // the simulation carries the store's read barrier across `BRA L_top` into the block behind it
    assert!(classic.contains("BROKEN WAR: insn[8] MOV overwrites R4 before rb (barrier 3) of mem-op insn[6] STG.E is waited"), "{classic}");
    assert!(classic.contains("CUBIT_VERIFY: 0 unprotected RAW, 1 broken WAR, 0 recycle-stale"), "{classic}");
    assert!(!classic.contains("FLOW") && json.get("flow").is_none(), "nothing of the view without the variable:\n{classic}\n{json}");

    let (flow, cubin2, json2) = verify(&listing, &[FLOW]);
    assert!(flow_line(&flow).starts_with("CUBIT_VERIFY_FLOW: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale on the paths of the flow graph"), "{flow}");
    // the view is added; nothing else is printed, counted or encoded differently
    let rest: String = flow.lines().filter(|l| !l.contains("FLOW")).map(|l| format!("{l}\n")).collect();
    assert_eq!(rest, classic.lines().map(|l| format!("{l}\n")).collect::<String>());
    assert!(cubin == cubin2);
    assert_eq!(json2["scoreboard"], json["scoreboard"]);
    assert_eq!((json2["flow"]["raw"].as_u64(), json2["flow"]["war"].as_u64(), json2["flow"]["recycle_stale"].as_u64()), (Some(0), Some(0), Some(0)), "{json2}");

    // without that wait the first overwriter of each register on the path is a finding of the view
    let (bare, _, bare_json) = verify(&loop_with_an_out_of_line_block("B------"), &[FLOW]);
    assert!(flow_line(&bare).starts_with("CUBIT_VERIFY_FLOW: 0 unprotected RAW, 2 broken WAR, 0 recycle-stale"), "{bare}");
    assert!(bare.contains("FLOW WAR: insn[1] IADD3 overwrites R4 of mem-op insn[6] STG.E 9 issue cycles later on a path with no wait on its read barrier 3"), "{bare}");
    assert!(bare.contains("FLOW WAR: insn[2] MOV overwrites R5 of mem-op insn[6] STG.E 10 issue cycles later"), "{bare}");
    let found = bare_json["flow"]["findings"].as_array().unwrap();
    assert_eq!(found.iter().map(|f| (f["kind"].as_str().unwrap(), f["at"].as_u64().unwrap(), f["other"].as_u64().unwrap(), f["register"].as_str().unwrap())).collect::<Vec<_>>(), [("war", 1, 6, "R4"), ("war", 2, 6, "R5")]);
}

#[test]
fn a_reader_the_producer_does_not_reach_is_no_finding_and_one_it_reaches_across_a_forward_branch_is() {
    // the load stands in one arm, a reader of its register in the other arm's block further down the text;
    // the first reader on the load's own path (behind the join) waits
    let arms = kernel(
        "    [B------:R-:W-:-:S13] ISETP.NE.AND P0, PT, R6, RZ, PT ;
    [B------:R-:W-:Y:S05] @P0 BRA L_other ;
    [B------:R-:W1:Y:S02] LDG.E R8, desc[UR4][R2.64] ;
    [B------:R-:W-:Y:S05] BRA L_join ;
L_other:
    [B------:R-:W-:Y:S01] IADD3 R9, PT, PT, R8, 0x1, RZ ;
L_join:
    [B-1----:R-:W-:Y:S01] IADD3 R10, PT, PT, R8, 0x1, RZ ;
    [B------:R-:W-:Y:S05] EXIT ;
",
    );
    let (log, _, _) = verify(&arms, &[FLOW]);
    assert!(log.contains("UNPROTECTED RAW: insn[4] IADD3 reads R8 <- var-producer insn[2] LDG.E (barrier 1 not waited)"), "the text order's line:\n{log}");
    assert!(log.contains("CUBIT_VERIFY: 1 unprotected RAW, 0 broken WAR, 0 recycle-stale"), "{log}");
    assert!(flow_line(&log).starts_with("CUBIT_VERIFY_FLOW: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale"), "{log}");

    // the wait on the fall-through only, the branch taken while the load is in flight: the text order arrives
    // at the target with nothing pending, the path does not
    let forward = kernel(
        "    [B------:R-:W-:-:S13] ISETP.NE.AND P0, PT, R6, RZ, PT ;
    [B------:R-:W1:Y:S02] LDG.E R8, desc[UR4][R2.64] ;
    [B------:R-:W-:Y:S05] @P0 BRA L_far ;
    [B-1----:R-:W-:Y:S01] IADD3 R9, PT, PT, R8, 0x1, RZ ;
    [B------:R-:W-:Y:S05] EXIT ;
L_far:
    [B------:R-:W-:Y:S01] IADD3 R10, PT, PT, R8, 0x1, RZ ;
    [B------:R-:W-:Y:S05] EXIT ;
",
    );
    let (log, _, json) = verify(&forward, &[FLOW]);
    assert!(log.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale"), "{log}");
    assert!(flow_line(&log).starts_with("CUBIT_VERIFY_FLOW: 1 unprotected RAW, 0 broken WAR, 0 recycle-stale"), "{log}");
    assert!(log.contains("FLOW RAW: insn[5] IADD3 reads R8 <- var-producer insn[1] LDG.E 7 issue cycles earlier on a path with no wait on barrier 1"), "{log}");
    assert_eq!((json["scoreboard"]["raw"].as_u64(), json["flow"]["raw"].as_u64()), (Some(0), Some(1)));
}

#[test]
fn the_uniform_register_of_a_stores_address_is_walked_by_the_view() {
    let store = |stall: u8| kernel(&format!("    [B------:R2:W-:Y:S0{stall}] STG.E desc[UR4][R2.64], R5 ;\n    [B------:R-:W-:Y:S01] UMOV UR4, 0x400 ;\n    [B------:R-:W-:Y:S05] EXIT ;\n"));
    // no check of the stores names the descriptor: the simulation and the walk of the stores' read barriers say nothing
    let (near, _, json) = verify(&store(6), &[FLOW]);
    assert!(near.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale") && !near.contains("STORE PATH"), "{near}");
    assert!(flow_line(&near).starts_with("CUBIT_VERIFY_FLOW: 0 unprotected RAW, 1 broken WAR, 0 recycle-stale"), "{near}");
    assert!(near.contains("FLOW WAR: insn[1] UMOV overwrites UR4 of mem-op insn[0] STG.E 6 issue cycles later on a path with no wait on its read barrier 2"), "{near}");
    assert_eq!(json["flow"]["store_uniform_apart"].as_u64(), Some(0));
    // from the operand hold on it is the vendor's practice: counted apart
    let (far, _, json) = verify(&store(7), &[FLOW]);
    assert!(flow_line(&far).starts_with("CUBIT_VERIFY_FLOW: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale"), "{far}");
    assert!(far.contains("CUBIT_VERIFY_FLOW: + 1 rewrite(s) of the uniform register of a store's address from 7 issue cycles on with no wait on the store's read barrier (the nearest at 7;"), "{far}");
    assert_eq!((json["flow"]["store_uniform_apart"].as_u64(), json["flow"]["store_uniform_nearest"].as_u64()), (Some(1), Some(7)));
}
