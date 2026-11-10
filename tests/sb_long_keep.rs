//! `CUBIT_SB_LONG_KEEP=1` (with `CUBIT_SB_SHARE=1`; opt-in, 2026-11-10): a prefetch keeps its
//! scoreboard to itself.
//!
//! sm_120 scoreboards are counters: a wait on a scoreboard waits for everything counted on it.
//! The production attention kernel issues the 16 gather loads of chunk c+1 into staging
//! registers behind the barrier that publishes chunk c's tile, so that they are in flight
//! during chunk c's QK / softmax / PV; under `CUBIT_SB_SHARE` they share one scoreboard and
//! their readers (the dequant, a chunk of compute later) wait once.
//!
//! What went wrong without the switch: other uses were coloured onto the same scoreboard and
//! their waits sat inside the compute - the READ barrier of the previous dequant's last
//! `STS.128` (its data registers are next written by the QK chain's fragment loads: a long use
//! too, so coloured from the top two), and short uses that overflowed onto "the busiest"
//! scoreboard. In `sparse_mla_prefill_v42` the fifth `LDSM` of QK carried `[B-1---5]`, the
//! gather's scoreboard: the gather was in flight for four k-steps, not for the chunk. With one
//! more load in the loop the gather moved to scoreboard 4, where the first instruction of QK
//! waited for it. Measured on RTX PRO 6000 (random gather indices, every gather a cache miss):
//! 658 / 724 / 1 613 / 682 µs -> 645 / 710 / 1 591 / 673 µs for v42's own text; on real prefill
//! inputs (cache-resident gathers) no difference - the switch buys robustness of the prefetch
//! against any change of the kernel's text, and 1.4-2.0 % where the gather misses.
//!
//! Under the switch long uses are coloured first, the long loads share the top scoreboard, the
//! long store latches the one below it, and a short use never shares with a long one.
//! Fixture: the kernel's text (`tests/fixtures/sb_long_keep/attention_prefetch.sass`).

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sb_long_keep/attention_prefetch.sass");
/// The kernel's build environment (policy + the dependency-aware schedule).
const ENV: [(&str, &str); 7] = [
    ("CUBIT_SB_SHARE", "1"),
    ("CUBIT_RB_EARLY", "32"),
    ("CUBIT_MMA_WAIT", "1"),
    ("CUBIT_MMA_WB_DRAIN", "13"),
    ("CUBIT_SCHED2", "1"),
    ("CUBIT_SCHED2_LAT", "sm120"),
    ("CUBIT_MMA_PTXAS", "1"),
];

struct Line {
    wait: u8,
    wb: Option<u8>,
    text: String,
}

struct Built {
    lines: Vec<Line>,
    cubin: Vec<u8>,
    log: String,
}

fn cubit(args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    (out.status.success(), format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
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
    Some(Line { wait, wb: f[2][1..].parse::<u8>().ok(), text: rest[close + 1..].trim().trim_end_matches(';').trim().to_string() })
}

fn build(extra: &[(&str, &str)]) -> Built {
    build_text(None, extra)
}

/// Assemble the fixture, or `text` in its place, under the kernel's environment plus `extra`.
fn build_text(text: Option<&str>, extra: &[(&str, &str)]) -> Built {
    let dir = std::env::temp_dir().join(format!("sb_long_keep_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("k.cubin");
    let src = match text {
        Some(t) => {
            let p = dir.join("k.sass");
            std::fs::write(&p, t).unwrap();
            p.to_str().unwrap().to_string()
        }
        None => SRC.to_string(),
    };
    let src = src.as_str();
    let mut env: Vec<(&str, &str)> = ENV.to_vec();
    env.extend_from_slice(extra);
    env.push(("CUBIT_VERIFY", "1"));
    env.push(("CUBIT_DEP_VERIFY", "1"));
    let (ok, log) = cubit(&["asm", "-t", TABLE, src, "-o", out.to_str().unwrap(), "--kernel", "sparse_mla_prefill_v41"], &env);
    assert!(ok, "asm failed:\n{log}");
    let cubin = std::fs::read(&out).unwrap();
    let (ok, frozen) = cubit(&["disassemble", "-t", TABLE, "--frozen", out.to_str().unwrap()], &[]);
    assert!(ok, "disassemble failed:\n{frozen}");
    let _ = std::fs::remove_dir_all(&dir);
    Built { lines: frozen.lines().filter_map(parse_line).collect(), cubin, log }
}

/// The loop body's gather: (index of its last load, the scoreboards its loads set, index of the
/// first reader of a staged register = the first scaled unpack behind it).
fn gather(b: &Built) -> (usize, u8, usize) {
    let bars: Vec<usize> = b.lines.iter().enumerate().filter(|(_, l)| l.text.starts_with("BAR.SYNC")).map(|(i, _)| i).collect();
    assert!(bars.len() >= 3, "the kernel's barriers");
    // the loop's gather block sits between its first barrier (the kernel's second) and the QK chain
    let qk = (bars[1]..b.lines.len()).find(|&i| b.lines[i].text.starts_with("HMMA")).expect("the QK chain");
    let loads: Vec<usize> = (bars[1]..qk).filter(|&i| b.lines[i].text.contains("LDG.E.128 R") || b.lines[i].text.contains("LDG.E.U8 R")).collect();
    assert_eq!(loads.len(), 16, "16 gather loads per chunk");
    let mask = loads.iter().fold(0u8, |m, &i| m | (1 << b.lines[i].wb.expect("a gather load sets a write barrier")));
    let last = *loads.last().unwrap();
    let reader = (last..b.lines.len()).find(|&i| b.lines[i].text.starts_with("F2FP.BF16.E")).expect("the dequant behind the compute");
    (last, mask, reader)
}

/// Lines strictly between the gather's last load and its first reader that wait on one of the
/// gather's scoreboards.
fn drains(b: &Built) -> Vec<String> {
    let (last, mask, reader) = gather(b);
    assert!(reader - last > 250, "a chunk of compute lies between the gather and its readers ({} instructions)", reader - last);
    (last + 1..reader).filter(|&i| b.lines[i].wait & mask != 0).map(|i| format!("[{:#04x}] {}", b.lines[i].wait, b.lines[i].text)).collect()
}

fn legal(b: &Built) {
    assert!(b.log.contains("0 unprotected RAW, 0 broken WAR"), "{}", b.log);
    let v = b.log.lines().find(|l| l.contains("DEP_VERIFY")).unwrap_or_else(|| panic!("no DEP_VERIFY line:\n{}", b.log));
    assert!(v.contains("DEP_VERIFY 0 below a table cell, 0 waits closer than the arming distance to their barrier's setter, 0 below a resource spacing, 0 below a default"), "{v}");
}

/// Today's colouring: a wait on the gather's scoreboard sits in the QK chain - the fifth `LDSM`
/// of the chunk's compute waits for all sixteen loads.
#[test]
fn without_the_switch_the_compute_waits_for_the_gather() {
    let b = build(&[]);
    legal(&b);
    let d = drains(&b);
    assert!(!d.is_empty(), "no drain: the default colouring changed - re-pin this test");
    assert!(d.iter().any(|l| l.contains("LDSM.16.M88.4") || l.contains("HMMA")), "the drain sits in the HMMA chain: {d:?}");
}

/// Under the switch nothing between the gather and its first reader waits on the gather's
/// scoreboard, all sixteen loads share ONE scoreboard, and the schedule stays legal.
#[test]
fn with_the_switch_the_gather_flies_until_its_first_reader() {
    let b = build(&[("CUBIT_SB_LONG_KEEP", "1")]);
    legal(&b);
    let (last, mask, reader) = gather(&b);
    assert_eq!(mask.count_ones(), 1, "the gather's loads share one scoreboard: mask {mask:#04x}");
    assert_eq!(mask, 1 << 5, "the top scoreboard");
    let d = drains(&b);
    assert!(d.is_empty(), "waits on the gather's scoreboard between its last load and its first reader: {d:?}");
    // the first reader does wait for it
    assert!(b.lines[reader].wait & mask != 0, "the first reader waits for the gather: {}", b.lines[reader].text);
    assert!(reader > last);
}

/// The fixture with the scoreboard of every gather load pinned by a control code (`W5`).
fn pinned_gather() -> String {
    let text = std::fs::read_to_string(SRC).unwrap();
    let mut pinned = 0;
    let text: String = text
        .lines()
        .map(|l| {
            let t = l.trim_start();
            if t.starts_with("@P0 LDG.E.128 R") || t.starts_with("@P0 LDG.E.U8 R") {
                pinned += 1;
                format!("{}[B------:R-:W5:Y:S04] {}\n", &l[..l.len() - t.len()], t)
            } else {
                format!("{l}\n")
            }
        })
        .collect();
    assert_eq!(pinned, 32, "the gather loads of the prologue and of the loop");
    text
}

/// Pinning the gather's scoreboard does not protect it: the pin reserves the colour, but the
/// long store latches are still coloured from the top two and the short uses still overflow
/// onto the busiest scoreboard - the compute waits for the gather as before. Under the switch
/// it does not.
#[test]
fn a_pinned_prefetch_is_drained_without_the_switch_and_kept_with_it() {
    let text = pinned_gather();
    let b = build_text(Some(&text), &[]);
    legal(&b);
    assert_eq!(gather(&b).1, 1 << 5, "the pinned scoreboard");
    assert!(!drains(&b).is_empty(), "no drain: the default colouring changed - re-pin this test");
    let b = build_text(Some(&text), &[("CUBIT_SB_LONG_KEEP", "1")]);
    legal(&b);
    let (_, mask, reader) = gather(&b);
    assert_eq!(mask, 1 << 5, "the pinned scoreboard");
    let d = drains(&b);
    assert!(d.is_empty(), "waits on the pinned gather's scoreboard between its last load and its first reader: {d:?}");
    assert!(b.lines[reader].wait & mask != 0, "the first reader waits for the gather: {}", b.lines[reader].text);
}

/// The switch is opt-in and belongs to the sharing policy: unset, `0`, or without
/// `CUBIT_SB_SHARE` the cubin is the one cubit builds today, byte for byte.
#[test]
fn the_switch_is_opt_in() {
    let base = build(&[]);
    assert_eq!(build(&[("CUBIT_SB_LONG_KEEP", "0")]).cubin, base.cubin, "CUBIT_SB_LONG_KEEP=0");
    // without the sharing policy the switch does nothing
    let no_share = |keep: Option<&str>| -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!("sb_long_keep_ns_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("k.cubin");
        let mut env: Vec<(&str, &str)> = ENV.iter().copied().filter(|(k, _)| *k != "CUBIT_SB_SHARE").collect();
        if let Some(v) = keep {
            env.push(("CUBIT_SB_LONG_KEEP", v));
        }
        let (ok, log) = cubit(&["asm", "-t", TABLE, SRC, "-o", out.to_str().unwrap(), "--kernel", "sparse_mla_prefill_v41"], &env);
        assert!(ok, "asm failed:\n{log}");
        let c = std::fs::read(&out).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        c
    };
    assert_eq!(no_share(Some("1")), no_share(None), "CUBIT_SB_LONG_KEEP=1 without CUBIT_SB_SHARE");
}

// ---------------------------------------------------------------------------------------------
// Minimal kernels: one innocent edit per file (session RA-1, 2026-11-10; the fixtures
// `tests/fixtures/sb_long_keep/edit_*.sass` are generated by `gen_edits.py` next to them).
//
// The shape: a prefetch of four global loads (`LDG.E R40..R43`, one address temp recomputed per
// load, as a gather does) issued first and read ~300 instructions later, and in between 32
// rounds of four shared-memory loads issued together and consumed together - four short
// scoreboard uses alive at a time. The rule of today's colouring that these files isolate:
//   * a use longer than `CUBIT_SB_LONG` takes scoreboard 4 if it is free, else 5 - the prefetch
//     is split, its first load alone on 4, the other three on 5;
//   * a short use takes the lowest free scoreboard and, when none is free, shares the one with
//     the most uses on it over its own segment - inside a prefetch window that is one of the
//     prefetch's two.
// So the base (four short uses + the two of the prefetch = six) has no wait on the prefetch
// before its readers, and any edit that makes a fifth short use overlap the other four puts one
// on scoreboard 4 - its waiter drains the prefetch's first load in the middle of the compute:
//   edit_no_quiet         the rounds start while the address latch of the prefetch's last load
//                         (the read barrier `CUBIT_RB_EARLY` gives every load) is still held
//   edit_one_more_load    a fifth load in the 21st round
//   edit_late_latch_load  a load through its own address register in the 21st round
//   edit_renumbered_temp  the same with a temp renumbered onto that address register (what a
//                         register allocation may do): the temp's write waits for the load's
//                         address latch - a second waiter on the prefetch's scoreboard
// None of these edits touches the prefetch. Under the switch the prefetch is alone on the top
// scoreboard in every file and nothing waits for it before its first reader.

/// The two switches the colouring of a prefetch depends on (no dependency-aware schedule: the
/// minimal kernels are legal under the default one).
const EDIT_ENV: [(&str, &str); 2] = [("CUBIT_SB_SHARE", "1"), ("CUBIT_RB_EARLY", "32")];

/// The minimal kernels and, for today's colouring, how many instructions behind the prefetch's
/// last load each wait on one of the prefetch's scoreboards sits (before its first reader).
const EDITS: [(&str, &[usize]); 5] = [
    ("edit_base", &[]),
    ("edit_no_quiet", &[33]),
    ("edit_one_more_load", &[211]),
    ("edit_late_latch_load", &[214]),
    ("edit_renumbered_temp", &[212, 214]),
];

struct Edit {
    /// the scoreboards the four prefetch loads set
    mask: u8,
    /// distance behind the last prefetch load of every wait on `mask` before the first reader
    drains: Vec<usize>,
    /// the first reader waits for the prefetch
    reader_waits: bool,
}

/// Assemble one minimal kernel under `EDIT_ENV` (+ the switch), check the verifiers, find the
/// prefetch (`LDG.E R40..R43`) and its first reader (`IMAD R30, R40, ...`).
fn edit(name: &str, keep: bool) -> Edit {
    let src = format!("{}/tests/fixtures/sb_long_keep/{name}.sass", env!("CARGO_MANIFEST_DIR"));
    let dir = std::env::temp_dir().join(format!("sb_long_keep_edit_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("k.cubin");
    let mut env: Vec<(&str, &str)> = EDIT_ENV.to_vec();
    if keep {
        env.push(("CUBIT_SB_LONG_KEEP", "1"));
    }
    env.push(("CUBIT_VERIFY", "1"));
    env.push(("CUBIT_DEP_VERIFY", "1"));
    let (ok, log) = cubit(&["asm", "-t", TABLE, &src, "-o", out.to_str().unwrap()], &env);
    assert!(ok, "{name}: asm failed:\n{log}");
    let cubin = std::fs::read(&out).unwrap();
    let (ok, frozen) = cubit(&["disassemble", "-t", TABLE, "--frozen", out.to_str().unwrap()], &[]);
    assert!(ok, "{name}: disassemble failed:\n{frozen}");
    let _ = std::fs::remove_dir_all(&dir);
    let b = Built { lines: frozen.lines().filter_map(parse_line).collect(), cubin, log };
    legal(&b);
    let loads: Vec<usize> = (0..b.lines.len()).filter(|&i| ["LDG.E R40,", "LDG.E R41,", "LDG.E R42,", "LDG.E R43,"].iter().any(|p| b.lines[i].text.starts_with(p))).collect();
    assert_eq!(loads.len(), 4, "{name}: the four prefetch loads");
    let mask = loads.iter().fold(0u8, |m, &i| m | (1 << b.lines[i].wb.expect("a prefetch load sets a write barrier")));
    let last = loads[3];
    let reader = (last..b.lines.len()).find(|&i| b.lines[i].text.starts_with("IMAD R30, R40,")).unwrap_or_else(|| panic!("{name}: the prefetch's first reader"));
    assert!(reader - last > 256, "{name}: the prefetch is a long use ({} instructions to its first reader)", reader - last);
    Edit { mask, drains: (last + 1..reader).filter(|&i| b.lines[i].wait & mask != 0).map(|i| i - last).collect(), reader_waits: b.lines[reader].wait & mask != 0 }
}

/// Today's colouring: the base is not drained, and each one-line edit of the compute puts a
/// waiter on the prefetch's scoreboard - `N` instructions behind its last load, ~90 to ~270
/// instructions before its first reader.
#[test]
fn one_innocent_edit_drains_a_minimal_prefetch_without_the_switch() {
    for (name, want) in EDITS {
        let e = edit(name, false);
        assert_eq!(e.mask, 0b11_0000, "{name}: the prefetch is split over the top two scoreboards");
        assert_eq!(e.drains, want, "{name}: waits on the prefetch's scoreboards behind its last load - the default colouring changed, re-pin this test");
        assert!(e.reader_waits, "{name}: the first reader waits for the prefetch");
    }
}

/// Under the switch the prefetch is alone on the top scoreboard in every file, nothing waits
/// for it between its last load and its first reader, and the schedules stay legal. Fails
/// without the source change (the prefetch stays split and the four edits drain it).
#[test]
fn with_the_switch_no_edit_drains_the_minimal_prefetch() {
    for (name, _) in EDITS {
        let e = edit(name, true);
        assert_eq!(e.mask, 1 << 5, "{name}: the prefetch's loads share the top scoreboard");
        assert!(e.drains.is_empty(), "{name}: waits on the prefetch's scoreboard {:?} instructions behind its last load", e.drains);
        assert!(e.reader_waits, "{name}: the first reader waits for the prefetch");
    }
}
