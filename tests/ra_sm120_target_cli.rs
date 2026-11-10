//! `cubit ra --mode full --target sm120` through the command line, on the production attention
//! kernel (fixture `ra_sm120/sparse_mla_prefill_v42.sass`): the target-neutral allocation
//! assembles into a cubin the strict round trip refuses (55 `IMAD.WIDE` words with an odd addend
//! pair -- BUG-008, CUDA 715 at launch), the targeted one assembles with the kernel's own build
//! switches into a cubin that round-trips word for word, keeps the register count of the
//! hand-numbered build and its schedule in every control word. Written against the command
//! line of `c507a7c` (red there: the kernel is refused, `--target` does not exist).

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/ra_sm120");
/// The attention build of the serving stack: its policy switches and the `s1` schedule.
const BUILD_ENV: [(&str, &str); 7] = [
    ("CUBIT_SB_SHARE", "1"),
    ("CUBIT_RB_EARLY", "32"),
    ("CUBIT_MMA_WAIT", "1"),
    ("CUBIT_MMA_WB_DRAIN", "13"),
    ("CUBIT_SCHED2", "1"),
    ("CUBIT_SCHED2_LAT", "sm120"),
    ("CUBIT_MMA_PTXAS", "1"),
];

static SCRATCH: AtomicUsize = AtomicUsize::new(0);

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ra_sm120_{}_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst), tag));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

#[test]
fn the_allocated_kernel_assembles_and_round_trips_only_with_the_target() {
    let dir = scratch("asm");
    let src = format!("{FIX}/sparse_mla_prefill_v42.sass");
    let stub = format!("{FIX}/qmma_e4m3.merc.stub");
    let p = |n: &str| dir.join(n).to_str().unwrap().to_string();
    let build = |sass: &str, cubin: &str| -> String {
        let mut env = BUILD_ENV.to_vec();
        env.push(("CUBIT_VERIFY", "1"));
        env.push(("CUBIT_DEP_VERIFY", "1"));
        let (ok, log) = cubit(&["asm", sass, "-t", TABLE, "-o", cubin, "--kernel", "sparse_mla_prefill_v41", "--mercury-stub", &stub], &env);
        assert!(ok, "asm {sass}: {log}");
        assert!(log.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR"), "{log}");
        assert!(log.contains("DEP_VERIFY 0 below a table cell, 0 waits closer than the arming distance to their barrier's setter, 0 below a resource spacing, 0 below a default"), "{log}");
        assert!(log.contains("regcount=128"), "the register count of the hand-numbered build: {log}");
        log
    };
    // the hand-numbered source: the reference
    build(&src, &p("hand.cubin"));
    let (ok, log) = cubit(&["roundtrip-strict", &p("hand.cubin"), "-t", TABLE], &[]);
    assert!(ok && log.contains("1454/1454"), "{log}");
    // target-neutral allocation: assembles, and is not sm_120 code -- 55 IMAD.WIDE words with an odd addend pair
    let (ok, log) = cubit(&["ra", &src, "--mode", "full", "-o", &p("neutral.sass"), "--report", &p("neutral.json")], &[]);
    assert!(ok, "{log}");
    build(&p("neutral.sass"), &p("neutral.cubin"));
    let (ok, log) = cubit(&["roundtrip-strict", &p("neutral.cubin"), "-t", TABLE], &[]);
    assert!(!ok && log.contains("1399/1454"), "the target-neutral plan must still be refused by the strict round trip: {log}");
    // with the target: every word round-trips
    let (ok, log) = cubit(&["ra", &src, "--mode", "full", "--target", "sm120", "-o", &p("sm120.sass"), "--report", &p("sm120.json")], &[]);
    assert!(ok, "{log}");
    build(&p("sm120.sass"), &p("sm120.cubin"));
    let (ok, log) = cubit(&["roundtrip-strict", &p("sm120.cubin"), "-t", TABLE], &[]);
    assert!(ok && log.contains("1454/1454"), "{log}");
    // a renaming moves register and predicate fields only: the two cubins have the same size and the
    // same control words (bits 105..127 of every instruction)
    let text = |path: &str| -> Vec<u8> {
        let (ok, out) = cubit(&["disassemble", path, "-t", TABLE], &[]);
        assert!(ok);
        out.lines().filter_map(|l| l.split("@sched ").nth(1)).flat_map(|s| s.as_bytes()[..7].to_vec()).collect()
    };
    assert_eq!(text(&p("hand.cubin")), text(&p("sm120.cubin")), "the schedule does not depend on the numbering");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_target_on_the_command_line() {
    let dir = scratch("cli");
    let src = format!("{FIX}/sparse_mla_prefill_v42.sass");
    let (ok, log) = cubit(&["ra", &src, "--mode", "full", "--target", "sm999"], &[]);
    assert!(!ok && log.contains("unknown target"), "{log}");
    let (ok, log) = cubit(&["ra", &src, "--mode", "identity", "--target", "sm120"], &[]);
    assert!(!ok && log.contains("--mode full or --mode apply"), "{log}");
    let out = dir.join("o.sass");
    let (ok, log) = cubit(&["ra", &src, "--mode", "full", "--target", "sm120", "-o", out.to_str().unwrap(), "--report", dir.join("r.json").to_str().unwrap()], &[]);
    assert!(ok, "{log}");
    let rep: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join("r.json")).unwrap()).unwrap();
    assert_eq!(rep["kernels"][0]["target"], "sm120");
    assert_eq!(rep["kernels"][0]["regcount"], 128);
    assert_eq!(rep["kernels"][0]["full"]["r"]["watermark"], 125);
    assert!(std::fs::read_to_string(&out).unwrap().contains("    .reg R0-R124\n"));
    std::fs::remove_dir_all(&dir).ok();
}
