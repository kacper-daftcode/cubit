//! `CUBIT_SCHED2` / `CUBIT_SCHED2_LAT` on the callers of the scheduling passes that are not
//! `cubit asm` (2026-11-10).
//!
//! `cubit asm` runs three things in a row: `schedule()`, `reallocate_barriers()` and the
//! legaliser `dep_stall::apply` - with the dependency-latency table under `CUBIT_SCHED2_LAT`,
//! with the scoreboard arming rule alone under plain `CUBIT_SCHED2`. The library's `assemble`
//! (and the Python module's verifier) ran the first two only, while `schedule()` read the
//! switch from the environment:
//!
//!  * with `CUBIT_SCHED2_LAT` set, `schedule()` left every fixed-latency dependency to a
//!    legaliser that never came - producer and consumer one cycle apart (`ISETP` -> its guard
//!    at S01; the measured floor of that pair on sm_120 is 13);
//!  * under plain `CUBIT_SCHED2` the arming rule was missing - a `MUFU` with the yield flag one
//!    cycle in front of the waiter of its barrier, the schedule that reads a stale register on
//!    sm_120 silicon.
//!
//! Now `schedule()` leaves the fixed latencies to the legaliser only for a caller that has
//! declared it runs one (`scheduling_pass::DEP_LEGALISER_FOLLOWS`; `cubit asm` does), and
//! `assemble` runs the arming rule (`dep_stall::apply_library_path`). The table itself stays a
//! `cubit asm` feature: it needs the pads and the MMA discipline built around it there.
//!
//! One test function: the phases change the process environment.

use cubit::scheduling::{decode_control_code, extract_sched_from_ctrl};
use cubit::table::IsaTable;

/// The instruction lines of a fixture kernel (no directives).
fn body(name: &str) -> String {
    let p = format!("{}/tests/fixtures/sched2_dep/{name}.sass", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("{p}: {e}"))
        .lines()
        .filter(|l| !l.trim_start().starts_with('.') && !l.trim().is_empty())
        .map(|l| format!("{l}\n"))
        .collect()
}

/// (stall, yield, write barrier, wait mask) of every instruction of an assembled stream.
fn controls(bytes: &[u8]) -> Vec<(u8, bool, u8, u8)> {
    bytes
        .chunks_exact(16)
        .map(|w| {
            let hi = u64::from_le_bytes(w[8..16].try_into().unwrap());
            let cc = decode_control_code(extract_sched_from_ctrl(hi));
            (cc.stall, cc.yield_flag, cc.write_bar, cc.wait_mask)
        })
        .collect()
}

fn asm(text: &str, table: &IsaTable) -> Vec<u8> {
    let (bytes, n) = cubit::assemble(text, 0, table).expect("assemble");
    assert_eq!(bytes.len(), n * 16);
    bytes
}

fn set(vars: &[(&str, Option<&str>)]) {
    for (k, v) in vars {
        match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
}

#[test]
fn the_library_path_is_legal_under_the_sched2_switches() {
    let table = IsaTable::load_default().expect("the sm_120 table");
    let arm = body("arm");
    let pairs = body("pairs");
    let lines: Vec<&str> = arm.lines().map(|l| l.trim()).collect();
    let mufu: Vec<usize> = lines.iter().enumerate().filter(|(_, l)| l.starts_with("MUFU.")).map(|(i, _)| i).collect();
    assert_eq!(mufu.len(), 2, "the fixture's two MUFUs");

    set(&[("CUBIT_SCHED2", None), ("CUBIT_SCHED2_LAT", None), ("CUBIT_SCHED2_NOARM", None)]);
    let arm_default = asm(&arm, &table);
    let pairs_default = asm(&pairs, &table);

    // ---- plain CUBIT_SCHED2: the arming rule holds on the library path
    set(&[("CUBIT_SCHED2", Some("1"))]);
    let arm_s2 = asm(&arm, &table);
    let pairs_s2 = asm(&pairs, &table);
    let cc = controls(&arm_s2);
    for &i in &mufu {
        let (stall, _, wb, _) = cc[i];
        assert_ne!(wb, 7, "`{}` sets a scoreboard", lines[i]);
        assert!((cc[i + 1].3 >> wb) & 1 == 1, "`{}` waits for it", lines[i + 1]);
        assert!(stall >= 2, "`{}` [S{stall:02}] has its waiter `{}` one cycle behind", lines[i], lines[i + 1]);
    }
    // CUBIT_SCHED2_NOARM=1 keeps the old schedule (for A/B runs), here as in `cubit asm`
    set(&[("CUBIT_SCHED2_NOARM", Some("1"))]);
    let cc = controls(&asm(&arm, &table));
    assert!(mufu.iter().all(|&i| cc[i].0 == 1 && cc[i].1), "NOARM: the MUFUs at S01 with the yield flag: {cc:?}");
    set(&[("CUBIT_SCHED2_NOARM", None)]);

    // ---- CUBIT_SCHED2_LAT in the environment: nobody runs the table's legaliser on this path,
    //      so the fixed latencies stay charged by schedule() - the stream is plain SCHED2's
    set(&[("CUBIT_SCHED2_LAT", Some("sm120"))]);
    let arm_lat = asm(&arm, &table);
    let pairs_lat = asm(&pairs, &table);
    set(&[("CUBIT_SCHED2", None), ("CUBIT_SCHED2_LAT", None)]);
    let lower: Vec<String> = controls(&pairs_lat)
        .iter()
        .zip(controls(&pairs_s2).iter())
        .zip(pairs.lines())
        .filter(|((a, b), _)| a.0 < b.0)
        .map(|((a, b), l)| format!("S{:02} < S{:02} `{}`", a.0, b.0, l.trim()))
        .collect();
    assert!(lower.is_empty(), "stalls dropped by the switch with no legaliser behind it: {lower:?}");
    assert_eq!(pairs_lat, pairs_s2, "CUBIT_SCHED2_LAT is not honoured on the library path");
    assert_eq!(arm_lat, arm_s2);

    // ---- and nothing of this touches the default path
    assert_eq!(asm(&arm, &table), arm_default);
    assert_eq!(asm(&pairs, &table), pairs_default);
    assert_ne!(pairs_s2, pairs_default, "the fixture is one that CUBIT_SCHED2 re-schedules");
}
