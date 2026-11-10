//! `CUBIT_VERIFY` checks the read barriers of stores on every path of the flow graph (`src/store_paths.rs`,
//! 2026-11-10). The scoreboard simulation behind "N broken WAR" follows the text of a loop and does not
//! track shared stores, so a wait that the last iteration branches around passed as protection: the
//! production attention kernel `sparse_mla_prefill_v43b` (fixture: `cubit disassemble --frozen` of the
//! committed cubin, sha256 a163aea6…) has three `STS.128` whose data quads the next chunk's `LDSM`
//! rewrites 58 / 67 issue cycles later with no wait on their read barriers, and `CUBIT_VERIFY` said
//! "0 broken WAR". Found by a path-sensitive walk of the listing written independently in Python by
//! the sm_120 scheduler session; this check reproduces its rows — store, overwriter, register, read
//! barrier, distance — on the six listings it was run on (shipped / `k2` / `k2b` 0, `v42` 4, `v43` 3,
//! `v43b` 3). The vendor's own schedules are clean under it: 0 pairs in the 166 listings of the sm_120
//! census on a data register or on the address pair of a global store.

use std::process::Command;

const FROZEN: &str = "tests/fixtures/store_paths/attention_v43b.frozen.sass";

fn asm(env: &[(&str, &str)], out: &std::path::Path) -> (bool, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", FROZEN, "-t", "tables/sm120.json.gz", "-o", out.to_str().unwrap()])
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .expect("run cubit");
    (o.status.success(), String::from_utf8_lossy(&o.stderr).into_owned())
}

fn tmp(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("cubit_store_paths_{}_{name}.cubin", std::process::id()))
}

#[test]
fn the_three_unwaited_store_pairs_of_the_attention_kernel_are_reported() {
    let out = tmp("verify");
    let (ok, err) = asm(&[("CUBIT_VERIFY", "1")], &out);
    assert!(ok, "{err}");
    // the simulation along the text still counts none
    assert!(err.contains("CUBIT_VERIFY: 0 unprotected RAW, 0 broken WAR,"), "{err}");
    let lines: Vec<&str> = err.lines().filter(|l| l.contains("STORE PATH:")).map(str::trim).collect();
    assert_eq!(
        lines,
        [
            "STORE PATH: insn[1177] STS.128 (read barrier 3) data R68 <- rewritten by insn[733] LDSM.16.M88.4 67 issue cycles later on a path with no wait on barrier 3",
            "STORE PATH: insn[1348] STS.128 (read barrier 5) data R64 <- rewritten by insn[730] LDSM.16.M88.4 58 issue cycles later on a path with no wait on barrier 5",
            "STORE PATH: insn[1349] STS.128 (read barrier 3) data R68 <- rewritten by insn[733] LDSM.16.M88.4 67 issue cycles later on a path with no wait on barrier 3",
        ],
        "{err}"
    );
    assert!(
        err.lines().any(|l| l.starts_with("CUBIT_VERIFY_PATHS: 3 store -> overwriter pair(s) reached on a path with no wait on the store's read barrier (0 of them on a store without one)")),
        "{err}"
    );
    let _ = std::fs::remove_file(&out);
}

#[test]
fn the_check_is_read_only() {
    // the same bytes with and without CUBIT_VERIFY, and without it not a word about paths
    let (a, b) = (tmp("plain"), tmp("checked"));
    let (ok, err) = asm(&[], &a);
    assert!(ok, "{err}");
    assert!(!err.contains("STORE PATH") && !err.contains("CUBIT_VERIFY"), "{err}");
    let (ok, err) = asm(&[("CUBIT_VERIFY", "1")], &b);
    assert!(ok, "{err}");
    assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);
}

#[test]
fn the_report_carries_the_counts() {
    let text = std::fs::read_to_string(FROZEN).unwrap();
    let sf = cubit::sass_file::parse_sass_file_str(&text).unwrap();
    let k = &sf.kernels[0].instructions;
    let rep = cubit::scheduling_pass::verify_scoreboard_report(k, None);
    assert_eq!((rep.war, rep.store_paths, rep.store_paths_bare, rep.store_paths_shared_addr), (0, 3, 0, 0));
    let f = cubit::store_paths::unwaited_store_overwrites(k, false);
    assert_eq!(
        f.iter().map(|x| (x.store, x.overwriter, x.reg, x.data, x.read_bar, x.distance)).collect::<Vec<_>>(),
        [(1177, 733, 68, true, Some(3), 67), (1348, 730, 64, true, Some(5), 58), (1349, 733, 68, true, Some(3), 67)]
    );
}
