//! `R2UR Pd, URd, Rs` -- the broadcast form of the register -> uniform move -- has TWO results: the
//! uniform register and a per-thread predicate (2026-11-11).
//!
//! What failed: the scheduler's operand convention takes operand 0 for the destination. Operand 0
//! of this form is a predicate, so the instruction had no destination at all and the uniform
//! register was listed as a source. Nothing waited for either result: cubit's schedule of a kernel
//! of nvcc with the idiom
//!
//! ```text
//! @P0 R2UR P1, UR4, R3 ; @P0 PLOP3.LUT P0, PT, P1, PT, PT, 0x80, 0x8 ; @!P1 ARRIVES.LDGSTSBAR.64.ARVCNT [UR4]
//! ```
//!
//! put the guarded word 4 / 9 / 9 / 12 issue cycles behind the `R2UR` and the `PLOP3` one, and
//! `CUBIT_DEP_VERIFY` called it clean. Found by an independent legality gate that prices a
//! predicate destination as a result. ptxas, on every site of the form in the sm_120 census, the
//! served MoE cubin and the persistent kernel (93 + 40 with a modifier): the guard 13 cycles behind
//! the `R2UR` at 53 of 53 sites, the predicate as an operand 8 at 133 of 133, the first reader of
//! the uniform register never closer than 13.
//!
//! Both sides are pinned: the schedule `6264d55` produced under the dependency table (fixture
//! `broadcast.sched2_6264d55.frozen.sass`, written by that binary) and the property the fix
//! restores. No production source carries the form; a kernel without it builds the same bytes.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);

const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/r2ur_pred/broadcast.sass");
const OLD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/r2ur_pred/broadcast.sched2_6264d55.frozen.sass");
const TABLE_PATH: [(&str, &str); 2] = [("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "1")];

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("r2ur_pred_{}_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst), tag));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// (stall, text) of every instruction line of a frozen listing.
fn lines(frozen: &str) -> Vec<(u32, String)> {
    frozen
        .lines()
        .filter_map(|l| {
            let t = l.trim_start();
            let t = if t.starts_with('[') { t } else { t.split_once(':').map(|(_, r)| r.trim_start()).filter(|r| r.starts_with('['))? };
            let close = t.find(']')?;
            let stall: u32 = t[1..close].rsplit(":S").next()?.parse().ok()?;
            Some((stall, t[close + 1..].trim().trim_end_matches(';').trim().to_string()))
        })
        .collect()
}

/// The frozen listing of the fixture built with `env`.
fn build(tag: &str, env: &[(&str, &str)]) -> String {
    let dir = scratch(tag);
    let out = dir.join("k.cubin");
    let (ok, log) = cubit(&["asm", "-t", TABLE, SRC, "-o", out.to_str().unwrap()], env);
    assert!(ok, "asm {env:?} failed:\n{log}");
    let (ok, frozen) = cubit(&["disassemble", "-t", TABLE, "--frozen", out.to_str().unwrap()], &[]);
    assert!(ok, "disassemble failed:\n{frozen}");
    let _ = std::fs::remove_dir_all(&dir);
    frozen
}

/// Issue distance from the `R2UR` to the first line that starts with `reader`.
fn distance(frozen: &str, reader: &str) -> u32 {
    let l = lines(frozen);
    let from = l.iter().position(|(_, t)| t.starts_with("R2UR P1, UR4, R3")).unwrap_or_else(|| panic!("no R2UR in:\n{frozen}"));
    let to = l.iter().position(|(_, t)| t.starts_with(reader)).unwrap_or_else(|| panic!("no {reader} in:\n{frozen}"));
    assert!(to > from);
    l[from..to].iter().map(|(s, _)| *s).sum()
}

/// The `DEP` lines of the read-only checker that name the `R2UR`, on a frozen listing.
fn dep_lines(tag: &str, frozen: &str) -> Vec<String> {
    let dir = scratch(tag);
    let src = dir.join("k.frozen.sass");
    std::fs::write(&src, frozen).unwrap();
    let out = dir.join("k.cubin");
    let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()], &[("CUBIT_DEP_VERIFY", "40")]);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(ok, "re-assembling the frozen listing failed:\n{log}");
    assert!(log.contains("DEP_VERIFY"), "no DEP_VERIFY line:\n{log}");
    log.lines().filter(|l| l.contains("DEP ") && l.contains("R2UR")).map(|l| l.trim().to_string()).collect()
}

#[test]
fn the_schedule_of_6264d55_read_both_results_before_they_landed() {
    let old = std::fs::read_to_string(OLD).unwrap();
    // the predicate one cycle behind the R2UR as an operand, three as a guard; the uniform register four
    assert_eq!(distance(&old, "PLOP3.LUT P2, PT, P1"), 1);
    assert_eq!(distance(&old, "@!P1 IADD3"), 3);
    assert_eq!(distance(&old, "UIADD3 UR5"), 4);
    // ... and the checker of that commit had nothing to say: now it names the three readers
    assert_eq!(
        dep_lines("old", &old),
        [
            "DEP dflt [7] R2UR P1, UR4, R3 -> [8] PLOP3.LUT P2, PT, P1, PT, PT, 0x80, 0x8 (raw P1): distance 1 < 6 (default: no cell for the pair)",
            "DEP dflt [7] R2UR P1, UR4, R3 -> [9] @!P1 IADD3 R5, PT, PT, R5, 0x1, RZ (raw P1): distance 3 < 13 (default: no cell for the pair)",
            "DEP dflt [7] R2UR P1, UR4, R3 -> [10] UIADD3 UR5, UPT, UPT, UR4, 0x8, URZ (raw UR4): distance 4 < 13 (default: no cell for the pair)",
        ]
    );
}

#[test]
fn the_table_path_waits_for_the_predicate_and_for_the_uniform_register() {
    let new = build("table", &TABLE_PATH);
    // the table has no cell for the form: its defaults -- a predicate into a guard 13 (ptxas: 13 at
    // every site), into an operand 6 (ptxas: 8), a uniform register 13 (ptxas: never closer)
    assert!(distance(&new, "@!P1 IADD3") >= 13, "{new}");
    assert!(distance(&new, "PLOP3.LUT P2, PT, P1") >= 6, "{new}");
    assert!(distance(&new, "UIADD3 UR5") >= 13, "{new}");
    assert_eq!(dep_lines("new", &new), Vec::<String>::new(), "{new}");
}

#[test]
fn the_default_path_waits_for_them_too() {
    // the default scheduler prices the producer, not the pair: R2UR is 8 cycles to any reader
    let new = build("default", &[]);
    for reader in ["PLOP3.LUT P2, PT, P1", "@!P1 IADD3", "UIADD3 UR5"] {
        assert!(distance(&new, reader) >= 8, "{reader}:\n{new}");
    }
}

#[test]
fn the_plain_form_is_untouched() {
    // `R2UR URd, Rs` (one result, operand 0) schedules as before: the uniform register's reader
    // behind it at the table's uniform default
    let dir = scratch("plain");
    let src = dir.join("plain.sass");
    let text = std::fs::read_to_string(SRC).unwrap().replace("R2UR P1, UR4, R3 ;", "R2UR UR4, R3 ;\n    ISETP.NE.U32.AND P1, PT, R3, RZ, PT ;");
    std::fs::write(&src, text).unwrap();
    let out = dir.join("k.cubin");
    let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()], &TABLE_PATH);
    assert!(ok, "{log}");
    let (ok, frozen) = cubit(&["disassemble", "-t", TABLE, "--frozen", out.to_str().unwrap()], &[]);
    assert!(ok, "{frozen}");
    let _ = std::fs::remove_dir_all(&dir);
    let l = lines(&frozen);
    let from = l.iter().position(|(_, t)| t.starts_with("R2UR UR4, R3")).unwrap();
    let to = l.iter().position(|(_, t)| t.starts_with("UIADD3 UR5")).unwrap();
    assert!(l[from..to].iter().map(|(s, _)| *s).sum::<u32>() >= 13, "{frozen}");
}
