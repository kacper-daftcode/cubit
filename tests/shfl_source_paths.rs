//! `CUBIT_VERIFY` checks the source registers of a warp shuffle on every path of the flow graph
//! (`src/store_paths.rs`, 2026-11-11; KNOWN_ISSUES A34).
//!
//! A `SHFL` reads its register operands when its unit serves it, not at issue. The scoreboard simulation
//! registers under a read barrier only the address registers of a long-latency producer (and an atomic's data);
//! a shuffle has no address, so its sources were protected by nothing there: a schedule that dropped the wait of
//! an overwriter — `[R0:W1] SHFL.BFLY PT, R47, R18, …` … `SEL R18, …` — passed with every count at 0, while the
//! barrier allocator under `CUBIT_SYNC_CLASSES` did set the read barrier and make the overwriter wait. On silicon
//! an unwaited fixed-latency overwriter is wrong at every issue distance tried once an SM runs more than one warp
//! (`tools/stallfloor/probe_sm120_20261111_b19.json`).
//!
//! The walk: from every shuffle, along every path, to the first fixed-latency instruction that rewrites one of
//! its general-register sources. Three waits release the source, each measured right: on the shuffle's read
//! barrier, on its own write barrier, on the write barrier of a younger shuffle (the unit is served in order). A
//! shuffle that rewrites the register is no pair, and the walk goes on behind it. Two further covers are the
//! vendor's practice and are counted apart: a wait on a younger shuffle's READ barrier, and on the write barrier
//! of a younger shared-memory load — every one of the 188 pairs the vendor's own text (the sm_120 census: 166
//! listings, 752 kernels) leaves outside the three measured covers stands behind one of them.

use serde_json::Value;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("shfl_source_{}_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst), tag));
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

fn kernel(body: &[&str]) -> String {
    format!(".entry k\n    .reg R0-R63\n    .regcount 72\n    .param u64 p0 offset=0x0\n{}\n    [B------:R-:W-:Y:S05] EXIT ;\n.endentry\n", body.join("\n"))
}

/// A shuffle with a read and a write barrier, a reader of its result, and the overwriter of its source in front
/// of every wait (`overwriter` = its control field).
fn unwaited(overwriter: &str) -> String {
    let second = format!("    [{overwriter}] MOV R13, RZ ;");
    kernel(&[
        "    [B------:R2:W1:Y:S04] SHFL.BFLY PT, R23, R13, 0x1, 0x1f ;",
        &second,
        "    [B-1----:R-:W-:Y:S04] IADD3 R5, PT, PT, R23, 0x1, RZ ;",
    ])
}

#[test]
fn an_unwaited_overwriter_of_a_shuffles_source_is_reported_beside_the_three_counts() {
    let dir = scratch("cli");
    let text = unwaited("B------:R-:W-:Y:S06");
    // without CUBIT_VERIFY: not a word, and the same bytes
    let (ok, plain) = asm(&dir, "plain", &text, &[]);
    assert!(ok, "{plain}");
    assert!(!plain.contains("SHUFFLE SOURCE") && !plain.contains("CUBIT_VERIFY"), "{plain}");
    // under either operand model the pair is named
    for env in [&[("CUBIT_VERIFY", "1")][..], &[("CUBIT_VERIFY", "1"), ("CUBIT_SYNC_CLASSES", "1")][..]] {
        let (ok, log) = asm(&dir, "checked", &text, env);
        assert!(ok, "{log}");
        let lines: Vec<&str> = log.lines().filter(|l| l.contains("SHUFFLE SOURCE:")).map(str::trim).collect();
        assert_eq!(
            lines,
            ["SHUFFLE SOURCE: insn[0] SHFL.BFLY [R2:W1] source R13 <- rewritten by insn[1] MOV 4 issue cycles later on a path with none of the waits that release it (the shuffle's read barrier, its write barrier, a younger shuffle's write barrier)"],
            "{env:?}: {log}"
        );
        assert!(log.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR, 0 recycle-stale"), "{log}");
        assert!(log.lines().any(|l| l.starts_with("CUBIT_VERIFY_SHFL: 1 source register(s) of a shuffle rewritten on a path with none of the waits that release it")), "{log}");
        assert_eq!(std::fs::read(dir.join("plain.cubin")).unwrap(), std::fs::read(dir.join("checked.cubin")).unwrap(), "read-only");
    }
    // the overwriter waits on the read barrier: clean
    let (ok, log) = asm(&dir, "waited", &unwaited("B--2---:R-:W-:Y:S06"), &[("CUBIT_VERIFY", "1")]);
    assert!(ok, "{log}");
    assert!(!log.contains("SHUFFLE SOURCE") && !log.contains("CUBIT_VERIFY_SHFL"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_json_line_carries_the_pair_and_legality_diff_refuses_a_candidate_that_drops_the_wait() {
    let dir = scratch("json");
    let line = |name: &str, overwriter: &str| -> (String, Value) {
        let file = dir.join(format!("{name}.jsonl"));
        let (ok, log) = asm(&dir, name, &unwaited(overwriter), &[("CUBIT_VERIFY_JSON", file.to_str().unwrap())]);
        assert!(ok, "{log}");
        let text = std::fs::read_to_string(&file).unwrap();
        (file.to_str().unwrap().to_string(), serde_json::from_str(text.lines().next().unwrap()).unwrap())
    };
    let (seed_file, seed) = line("seed", "B--2---:R-:W-:Y:S06");
    assert_eq!((&seed["scoreboard"]["shfl_sources"], &seed["scoreboard"]["shfl_sources_practice"]), (&0.into(), &0.into()));
    assert!(seed["scoreboard"]["findings"].as_array().unwrap().is_empty(), "{seed}");
    let (cand_file, cand) = line("cand", "B------:R-:W-:Y:S06");
    let sb = &cand["scoreboard"];
    assert_eq!((&sb["raw"], &sb["war"], &sb["recycle_stale"], &sb["shfl_sources"]), (&0.into(), &0.into(), &0.into(), &1.into()));
    let f = sb["findings"].as_array().unwrap();
    assert_eq!(f.len(), 1, "{cand}");
    assert_eq!((f[0]["kind"].as_str(), f[0]["other"].as_u64(), f[0]["at"].as_u64(), f[0]["register"].as_str()), (Some("shfl-source"), Some(0), Some(1), Some("R13")));
    assert!(f[0]["other_text"].as_str().unwrap().contains("SHFL.BFLY PT, R23, R13"));
    assert!(f[0]["at_text"].as_str().unwrap().contains("MOV R13, RZ"));
    let d = cubit::legality::compare(&seed, &cand);
    assert_eq!(d.new.iter().map(|x| (x.list, x.key.as_str())).collect::<Vec<_>>(), [("scoreboard", "shfl-source [0] -> [1] R13")]);
    let (ok, log) = cubit(&["legality-diff", &seed_file, &cand_file], &[]);
    assert!(!ok && log.contains("new    scoreboard shfl-source [0] -> [1] R13:"), "{log}");
    let (ok, log) = cubit(&["legality-diff", &cand_file, &seed_file], &[]);
    assert!(ok, "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_vendors_two_further_covers_are_counted_apart_and_printed_as_no_pair() {
    let dir = scratch("practice");
    // three shuffles read R36; only the youngest carries a read barrier and the overwriter waits on it
    let text = kernel(&[
        "    [B------:R-:W1:Y:S01] SHFL.IDX PT, R7, R22, R36, 0x1f ;",
        "    [B------:R-:W2:Y:S01] SHFL.IDX PT, R3, R51, R36, 0x1f ;",
        "    [B------:R0:W4:Y:S01] SHFL.IDX PT, R5, R37, R36, 0x1f ;",
        "    [B0-----:R-:W-:Y:S01] FMUL.FTZ R36, R25, R34 ;",
        "    [B-12-4-:R-:W-:Y:S01] IADD3 R9, PT, PT, R7, R3, R5 ;",
    ]);
    let file = dir.join("k.jsonl");
    let (ok, log) = asm(&dir, "k", &text, &[("CUBIT_VERIFY", "1"), ("CUBIT_VERIFY_JSON", file.to_str().unwrap())]);
    assert!(ok, "{log}");
    assert!(!log.contains("SHUFFLE SOURCE:"), "{log}");
    assert!(
        log.lines().any(|l| l.starts_with("CUBIT_VERIFY_SHFL: + 2 such pair(s) behind a wait on a younger shuffle's read barrier or a younger shared-memory load's write barrier only (not counted:")),
        "{log}"
    );
    let line: Value = serde_json::from_str(std::fs::read_to_string(&file).unwrap().lines().next().unwrap()).unwrap();
    let sb = &line["scoreboard"];
    assert_eq!((&sb["shfl_sources"], &sb["shfl_sources_practice"]), (&0.into(), &2.into()));
    let kinds: Vec<(&str, u64, u64)> =
        sb["findings"].as_array().unwrap().iter().map(|f| (f["kind"].as_str().unwrap(), f["other"].as_u64().unwrap(), f["at"].as_u64().unwrap())).collect();
    assert_eq!(kinds, [("shfl-source-practice", 0, 3), ("shfl-source-practice", 1, 3)]);
    let _ = std::fs::remove_dir_all(&dir);
}
