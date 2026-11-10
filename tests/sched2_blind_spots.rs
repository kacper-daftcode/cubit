//! `CUBIT_SCHED2`: the instructions the dependency model does not see are named, and
//! `CUBIT_SCHED2_STRICT=1` refuses a kernel that has one (2026-11-10).
//!
//! `CUBIT_SCHED2` charges a stall where a consumer needs it. That is only as complete as the
//! scheduler's operand model: a producer with no definition in it, or a read missing from it,
//! gets no stall - and the legaliser of `CUBIT_SCHED2_LAT` has nothing to raise, its verifier
//! nothing to report. Found on the ptxas-compiled MoE kernels of the serving stack: every
//! whole-kernel `CUBIT_SCHED2` build of them faulted on sm_120 silicon, on forms the hand-written
//! kernels do not use - the predicate-result `LOP3.LUT Pn, Rd, ...`, definitions of uniform
//! predicates, `BRA.DIV`, 64-bit operands whose halves have different producers.
//!
//! The model is not extended here (that belongs to the operand model, which the default
//! scheduler shares). What changes: `dep_stall::blind_spots` lists those instructions;
//! `cubit asm` prints the list under `CUBIT_SCHED2` and under `CUBIT_DEP_VERIFY`, and refuses to
//! write the kernel under `CUBIT_SCHED2_STRICT=1`. A kernel without such a form - the attention
//! kernel - builds byte for byte as before and prints nothing new.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const BLIND: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sched2_blind/pred_lop3.sass");
const ATTENTION: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sb_long_keep/attention_prefetch.sass");

struct Run {
    ok: bool,
    log: String,
    cubin: Option<Vec<u8>>,
    /// (stall, text) of every instruction of the frozen listing
    lines: Vec<(u8, String)>,
}

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

fn asm(src: &str, kernel: Option<&str>, env: &[(&str, &str)]) -> Run {
    let dir = std::env::temp_dir().join(format!("sched2_blind_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("k.cubin");
    let mut args = vec!["asm", "-t", TABLE, src, "-o", out.to_str().unwrap()];
    if let Some(k) = kernel {
        args.extend_from_slice(&["--kernel", k]);
    }
    let (ok, log) = cubit(&args, env);
    let cubin = std::fs::read(&out).ok();
    let mut lines = Vec::new();
    if cubin.is_some() {
        let (ok2, frozen) = cubit(&["disassemble", "-t", TABLE, "--frozen", out.to_str().unwrap()], &[]);
        assert!(ok2, "disassemble failed:\n{frozen}");
        for l in frozen.lines() {
            let t = l.trim_start();
            let Some(p) = t.find('[') else { continue };
            let Some(q) = t.find(']') else { continue };
            let f: Vec<&str> = t[p + 1..q].split(':').collect();
            if f.len() == 5 && f[0].starts_with('B') && f[4].starts_with('S') {
                lines.push((f[4][1..].parse().unwrap(), t[q + 1..].trim().trim_end_matches(';').trim().to_string()));
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    Run { ok, log, cubin, lines }
}

fn stall_of(r: &Run, prefix: &str) -> u8 {
    r.lines.iter().find(|(_, t)| t.starts_with(prefix)).unwrap_or_else(|| panic!("no `{prefix}` in {:?}", r.lines)).0
}

/// The hole, pinned: under `CUBIT_SCHED2` the predicate-result LOP3 and the instruction it guards
/// are one cycle apart (the default scheduler keeps the predicate's latency) - and `cubit asm`
/// says so. When the operand model learns the form, this test is to be re-pinned and the form
/// taken off `dep_stall::blind_spots`.
#[test]
fn a_form_outside_the_model_is_named_under_sched2() {
    let base = asm(BLIND, None, &[]);
    assert!(base.ok, "{}", base.log);
    assert!(!base.log.contains("does not see"), "the default path prints nothing about it:\n{}", base.log);
    let default_stall = stall_of(&base, "LOP3.LUT P5");
    assert!(default_stall >= 4, "the default scheduler charges the producer: S{default_stall:02}");

    for env in [vec![("CUBIT_SCHED2", "1")], vec![("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120")]] {
        let r = asm(BLIND, None, &env);
        assert!(r.ok, "{}", r.log);
        assert!(
            r.log.contains("CUBIT_SCHED2: 1 instruction(s) whose results or reads the dependency model does not see"),
            "{env:?}:\n{}",
            r.log
        );
        assert!(r.log.contains("LOP3.LUT P5, RZ, R5, 0x10, RZ, 0xc0, !PT -- a predicate-result LOP3"), "{}", r.log);
        assert_eq!(stall_of(&r, "LOP3.LUT P5"), 1, "{env:?}: the pair the model cannot see is one cycle apart");
    }
}

/// `CUBIT_SCHED2_STRICT=1` refuses the kernel: nothing is written.
#[test]
fn strict_refuses_a_kernel_with_a_blind_spot() {
    let r = asm(BLIND, None, &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120"), ("CUBIT_SCHED2_STRICT", "1")]);
    assert!(!r.ok, "{}", r.log);
    assert!(r.cubin.is_none(), "no cubin is written");
    assert!(r.log.contains("CUBIT_SCHED2_STRICT: 1 instruction(s) outside the dependency model"), "{}", r.log);
    // the switch belongs to CUBIT_SCHED2: alone, or with `0`, it changes nothing
    let alone = asm(BLIND, None, &[("CUBIT_SCHED2_STRICT", "1")]);
    assert!(alone.ok && alone.cubin == asm(BLIND, None, &[]).cubin, "{}", alone.log);
    let zero = asm(BLIND, None, &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_STRICT", "0")]);
    assert!(zero.ok && zero.cubin == asm(BLIND, None, &[("CUBIT_SCHED2", "1")]).cubin, "{}", zero.log);
}

/// The read-only verifier names it for any kernel, next to its counts (which cannot contain it).
#[test]
fn dep_verify_reports_the_blind_spot() {
    let r = asm(BLIND, None, &[("CUBIT_DEP_VERIFY", "1")]);
    assert!(r.ok, "{}", r.log);
    assert!(r.log.contains("DEP_VERIFY blind: 1 instruction(s)"), "{}", r.log);
    assert!(r.log.contains("DEP blind [5] LOP3.LUT P5"), "{}", r.log);
}

/// The attention kernel has no such form: nothing new is printed, the strict switch lets it
/// through, and its cubin is the same with and without it.
#[test]
fn the_attention_kernel_passes_strict_unchanged() {
    let env: Vec<(&str, &str)> = vec![
        ("CUBIT_SB_SHARE", "1"),
        ("CUBIT_RB_EARLY", "32"),
        ("CUBIT_MMA_WAIT", "1"),
        ("CUBIT_MMA_WB_DRAIN", "13"),
        ("CUBIT_SCHED2", "1"),
        ("CUBIT_SCHED2_LAT", "sm120"),
        ("CUBIT_MMA_PTXAS", "1"),
        ("CUBIT_DEP_VERIFY", "1"),
    ];
    let plain = asm(ATTENTION, Some("sparse_mla_prefill_v41"), &env);
    assert!(plain.ok, "{}", plain.log);
    assert!(!plain.log.contains("does not see"), "{}", plain.log);
    let mut strict_env = env.clone();
    strict_env.push(("CUBIT_SCHED2_STRICT", "1"));
    let strict = asm(ATTENTION, Some("sparse_mla_prefill_v41"), &strict_env);
    assert!(strict.ok, "{}", strict.log);
    assert_eq!(strict.cubin, plain.cubin);
}
