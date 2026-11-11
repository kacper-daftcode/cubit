//! The result of the 64-bit `CS2R` is priced apart from its class: 7 issue cycles, not the table's default 6
//! (2026-11-11; `tables/dep_latency_sm120.json`, section `producer_forms`).
//!
//! `CS2R Rd, <SR>` without `.32` writes the pair `Rd:Rd+1`. Silicon reads either register right from 6 issue
//! cycles and wrong one cycle closer in almost every thread-launch, on a Server Edition card and on a Workstation
//! Edition card alone and at its 400-W limit (`tools/stallfloor/probe_sm120_20261111_b33.json` and its two `_ws_`
//! files: `FMUL`, `FADD`, `LOP3`, `MOV`, `SHF`, `IADD` consumers; `probe_sm120_20261110_b3.json`: `IMAD`, `IADD3`,
//! `LOP3`). The table's default for a pair without a cell is that same 6: a floor with no margin, where every
//! other number of the table is the vendor's practice. ptxas never reads the form closer than 7 (22 116 words of
//! the form in the sm_120 census, 188 readers within 12 cycles, 26 at exactly 7, none at 6). The class `CS2R` of
//! the table does not tell the form from `CS2R.32` (whose census pairs stand at 5 into `IMAD`), so the number is
//! an entry of its own section: the class, the modifier the form does not carry, `L`, and the (consumer, role)
//! pairs that keep their cell or default — the data of a shared-memory store, whose measured floor is 3.
//!
//! Only schedules under `CUBIT_SCHED2_LAT` see the table: the default path does not move.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const DEP_TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/dep_latency_sm120.json");
const S1: &[(&str, &str)] = &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120"), ("CUBIT_MMA_PTXAS", "1")];
const S2: &[(&str, &str)] = &[("CUBIT_SYNC_CLASSES", "1"), ("CUBIT_SCHED2", "1"), ("CUBIT_MMA_PTXAS", "1"), ("CUBIT_SCHED2_LAT", "sm120")];
const CLEAN: &str = "DEP_VERIFY 0 below a table cell, 0 waits closer than the arming distance to their barrier's setter, 0 below a resource spacing, 0 below a default";

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("cs2r_form_{}_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst), tag));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

/// A kernel whose only word behind `producer` is `FMUL.FTZ R4, R6, <reader>`.
fn source(producer: &str, reader: &str) -> String {
    format!(
        ".entry cs2r_form\n    .reg R0-R63\n    .param ptr out\n    LDCU.64 UR4, c[0x0][0x358] ;\n    LDC.64 R2, c[0x0][0x380] ;\n    LDC R6, c[0x0][0x390] ;\n    {producer} ;\n    FMUL.FTZ R4, R6, {reader} ;\n    STG.E desc[UR4][R2.64], R4 ;\n    EXIT ;\n.endentry\n"
    )
}

/// Schedules `text` from source under `env`: the stall of the `CS2R` word = the issue distance to the word behind it.
fn stall_behind_cs2r(dir: &std::path::Path, name: &str, text: &str, env: &[(&str, &str)]) -> u32 {
    let src = dir.join(format!("{name}.sass"));
    let cub = dir.join(format!("{name}.cubin"));
    std::fs::write(&src, text).unwrap();
    let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", cub.to_str().unwrap()], env);
    assert!(ok, "{log}");
    let (ok, frozen) = cubit(&["disassemble", cub.to_str().unwrap(), "-t", TABLE, "--frozen"], &[]);
    assert!(ok, "{frozen}");
    let line = frozen.lines().find(|l| l.contains("CS2R")).unwrap_or_else(|| panic!("no CS2R in {frozen}"));
    line.split(":S").nth(1).and_then(|s| s.get(..2)).and_then(|s| s.parse().ok()).unwrap_or_else(|| panic!("no stall in {line}"))
}

/// `CUBIT_DEP_VERIFY` on a frozen two-word text: `producer` at stall `stall`, then `reader`.
fn verify(dir: &std::path::Path, name: &str, producer: &str, stall: u32, reader: &str, env: &[(&str, &str)]) -> String {
    let text = format!(
        ".entry cs2r_form\n    .reg R0-R63\n    .regcount 72\n    .param u64 p0 offset=0x0\n    [B------:R-:W-:Y:S{stall:02}] {producer} ;\n    [B------:R-:W-:Y:S01] {reader} ;\n    [B------:R-:W-:Y:S05] EXIT ;\n.endentry\n"
    );
    let src = dir.join(format!("{name}.sass"));
    std::fs::write(&src, text).unwrap();
    let mut e: Vec<(&str, &str)> = vec![("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120"), ("CUBIT_DEP_VERIFY", "1")];
    e.extend(env.iter().copied());
    let (ok, log) = cubit(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", dir.join(format!("{name}.cubin")).to_str().unwrap()], &e);
    assert!(ok, "{log}");
    log
}

#[test]
fn a_reader_of_the_pair_form_stands_seven_behind_it_and_a_reader_of_the_32_bit_form_six() {
    let dir = scratch("sched");
    for (set, env) in [("the dependency-aware schedule", S1), ("under CUBIT_SYNC_CLASSES", S2)] {
        for (producer, reader, want) in [
            ("CS2R R32, SRZ", "R32", 7),
            ("CS2R R32, SRZ", "R33", 7),
            ("CS2R R32, SR_GLOBALTIMERLO", "R33", 7),
            ("CS2R.32 R32, SRZ", "R32", 6),
        ] {
            let got = stall_behind_cs2r(&dir, "k", &source(producer, reader), env);
            assert_eq!(got, want, "{set}: `{producer}` -> a reader of {reader}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_dependency_check_names_a_reader_six_behind_the_pair_form_as_below_a_cell() {
    let dir = scratch("verify");
    for reader in ["FMUL.FTZ R4, R6, R32", "FMUL.FTZ R4, R6, R33", "IMAD R4, R32, R6, RZ", "MOV R4, R33"] {
        let log = verify(&dir, "six", "CS2R R32, SRZ", 6, reader, &[]);
        assert!(log.contains("DEP_VERIFY 1 below a table cell") && log.contains("0 below a default"), "{reader}: {log}");
        assert!(log.contains("distance 6 < 7") && !log.contains("no cell for the pair"), "{reader}: {log}");
        let log = verify(&dir, "seven", "CS2R R32, SRZ", 7, reader, &[]);
        assert!(log.contains(CLEAN), "{reader}: {log}");
    }
    // a 64-bit reader of the pair (the two shapes of a timer read): the data of a local store -- both registers are
    // named -- and a 64-bit add, of whose source the dependency walk reads the lower half (`DEP_VERIFY blind`; the
    // pair is held through its first register)
    for (reader, registers) in [("STL.64 [R1+0x10], R32", &["(raw R32)", "(raw R33)"][..]), ("IADD.64 R6, -R8, R32", &["(raw R32)"][..])] {
        let log = verify(&dir, "wide6", "CS2R R32, SR_GLOBALTIMERLO", 6, reader, &[]);
        assert!(log.contains("distance 6 < 7") && !log.contains("DEP_VERIFY 0 below a table cell"), "{reader}: {log}");
        assert!(registers.iter().all(|r| log.contains(r)), "{reader}: {registers:?} named: {log}");
        let log = verify(&dir, "wide7", "CS2R R32, SR_GLOBALTIMERLO", 7, reader, &[]);
        assert!(log.contains(CLEAN), "{reader}: {log}");
    }
    // the same under the table's 'silicon' edition (no entry lowers a form) and as the check's table
    let log = verify(&dir, "ed6", "CS2R R32, SRZ", 6, "FMUL.FTZ R4, R6, R33", &[("CUBIT_DEP_TABLE", "sm120-silicon")]);
    assert!(log.contains("distance 6 < 7"), "{log}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_data_of_a_shared_store_and_the_32_bit_form_keep_the_default() {
    let dir = scratch("keep");
    // CS2R -> STS data: the measured floor is 3; the pair has no cell and keeps the default 6
    for reader in ["STS [R1+0x10], R32", "STS [R1+0x10], R33", "STS.64 [R1+0x10], R32"] {
        let log = verify(&dir, "sts6", "CS2R R32, SRZ", 6, reader, &[]);
        assert!(log.contains(CLEAN), "{reader}: {log}");
        let log = verify(&dir, "sts5", "CS2R R32, SRZ", 5, reader, &[]);
        assert!(log.contains("distance 5 < 6") && log.contains("no cell for the pair") && log.contains("DEP_VERIFY 0 below a table cell"), "{reader}: {log}");
    }
    // ... but the ADDRESS of that store is a register role like any other
    let log = verify(&dir, "addr6", "CS2R R32, SRZ", 6, "STS [R32+0x10], R6", &[]);
    assert!(log.contains("distance 6 < 7"), "{log}");
    // the 32-bit form: one register, the default 6 (and the class's cell into the multiplier, 6)
    for reader in ["FMUL.FTZ R4, R6, R32", "IMAD R4, R32, R6, RZ"] {
        let log = verify(&dir, "half6", "CS2R.32 R32, SRZ", 6, reader, &[]);
        assert!(log.contains(CLEAN), "{reader}: {log}");
        let log = verify(&dir, "half5", "CS2R.32 R32, SRZ", 5, reader, &[]);
        assert!(log.contains("distance 5 < 6"), "{reader}: {log}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A table file without the section (a deployment's own copy, every table written before 2026-11-11) loads and
/// prices the pair form as before: the reader stands 6 behind it.
#[test]
fn a_table_file_without_the_section_prices_the_pair_form_as_before() {
    let dir = scratch("old");
    let mut j: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(DEP_TABLE).unwrap()).unwrap();
    let section = j.as_object_mut().unwrap().remove("producer_forms").expect("the bundled table has the section");
    assert_eq!(section.as_array().map(|a| a.len()), Some(1));
    let old = dir.join("dep_latency_old.json");
    std::fs::write(&old, j.to_string()).unwrap();
    let env: Vec<(&str, &str)> = vec![("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", old.to_str().unwrap()), ("CUBIT_MMA_PTXAS", "1")];
    for reader in ["R32", "R33"] {
        assert_eq!(stall_behind_cs2r(&dir, "k", &source("CS2R R32, SRZ", reader), &env), 6, "the old table: a reader of {reader}");
        assert_eq!(stall_behind_cs2r(&dir, "k", &source("CS2R R32, SRZ", reader), S1), 7, "the bundled table: a reader of {reader}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
