//! `CUBIT_SYNC_CLASSES=1` on sm_120 (2026-11-10): control classes of the synchronisation words
//! (`src/sync_class.rs`, `src/cfg_flow.rs`; docs/SM120_ASYNC_IDIOMS.md).
//!
//! What failed: a kernel that talks through mbarriers, bulk copies, the release / acquire chains
//! or `setmaxnreg` got those words from the scheduler without a barrier and at an ALU stall --
//! `SYNCS.PHASECHK.TRANS64.TRYWAIT P0, ... [W-]` followed by `@!P0 BRA [B------]`. On silicon the
//! branch reads the stale predicate at EVERY stall from 1 to 15 (327 680 of 327 680 consumer
//! threads of the probe wrong; `tools/stallfloor/sync_floors_sm120_20261110_*.json`): the
//! predicate is a scoreboard result, only its write barrier synchronises it. And a kernel of nvcc
//! could not be scheduled in place at all: the default path inserts drain instructions in front
//! of backward branches (the code moves under `BRX` tables and under the template's offset
//! records) and walks the text where the layout needs the control-flow graph.
//!
//! Every test pins the property the switch adds; `the_default_path_is_byte_for_byte` pins what
//! the binary of `c507a7c` (origin/main before this change) built from the same fixtures without
//! the switch (`*.default.txt`, `*.sched2.txt`, `default_path.sha256`, written by that binary).

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sync_classes_{}_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst), tag));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sync_classes");
const SWITCH: (&str, &str) = ("CUBIT_SYNC_CLASSES", "1");
/// The default stall model and the dependency-aware one (`CUBIT_SCHED2` + the sm_120 table).
const MODELS: [&[(&str, &str)]; 2] = [&[SWITCH], &[SWITCH, ("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120")]];
const FIXTURES: [&str; 11] = [
    "mbar_wait",
    "mbar_sleep",
    "mbar_init",
    "release_acquire",
    "bulk",
    "setmaxnreg",
    "collective",
    "loop_layout",
    "frozen_store",
    "dispatch",
    "sync_probes",
];

#[derive(Debug, Clone)]
struct Line {
    wait: u8,
    rb: Option<u8>,
    wb: Option<u8>,
    yld: bool,
    stall: u32,
    text: String,
}

impl Line {
    fn waits(&self, b: u8) -> bool {
        self.wait & (1 << b) != 0
    }
}

struct Built {
    lines: Vec<Line>,
    listing: String,
    sha256: String,
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
    let bar = |s: &str| s[1..].parse::<u8>().ok();
    Some(Line {
        wait,
        rb: bar(f[1]),
        wb: bar(f[2]),
        yld: f[3] == "Y",
        stall: f[4][1..].parse().ok()?,
        text: rest[close + 1..].trim().trim_end_matches(';').trim().to_string(),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn build(name: &str, env: &[(&str, &str)]) -> Built {
    let dir = scratch(name);
    let out = dir.join("k.cubin");
    let src = format!("{FIX}/{name}.sass");
    let (ok, log) = cubit(&["asm", "-t", TABLE, &src, "-o", out.to_str().unwrap()], env);
    assert!(ok, "asm {name} {env:?} failed:\n{log}");
    let sha256 = sha256_hex(&std::fs::read(&out).unwrap());
    let (ok, frozen) = cubit(&["disassemble", "-t", TABLE, "--frozen", out.to_str().unwrap()], &[]);
    assert!(ok, "disassemble failed: {frozen}");
    let _ = std::fs::remove_dir_all(&dir);
    let listing: Vec<String> = frozen.lines().filter(|l| parse_line(l).is_some()).map(|l| l.trim_start().to_string()).collect();
    let lines: Vec<Line> = listing.iter().filter_map(|l| parse_line(l)).collect();
    assert!(!lines.is_empty(), "no instruction lines in:\n{frozen}");
    Built { lines, listing: listing.join("\n") + "\n", sha256, log }
}

/// Index of the n-th instruction whose text starts with `pat`.
fn nth(b: &Built, pat: &str, n: usize) -> usize {
    b.lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.text.starts_with(pat))
        .map(|(i, _)| i)
        .nth(n)
        .unwrap_or_else(|| panic!("no instruction #{n} starting with `{pat}` in:\n{}", b.listing))
}

fn at<'a>(b: &'a Built, pat: &str) -> &'a Line {
    &b.lines[nth(b, pat, 0)]
}

/// Instructions of the source (the lines that are not directives, labels or comments).
fn source_instructions(name: &str) -> usize {
    std::fs::read_to_string(format!("{FIX}/{name}.sass"))
        .unwrap()
        .lines()
        .map(str::trim)
        .filter(|l| l.ends_with(';') && !l.starts_with("//") && !l.starts_with('.'))
        .count()
}

#[test]
fn a_phase_check_is_a_scoreboard_result() {
    for env in MODELS {
        let b = build("mbar_wait", env);
        let i = nth(&b, "SYNCS.PHASECHK.TRANS64.TRYWAIT", 0);
        let (chk, bra) = (&b.lines[i], &b.lines[i + 1]);
        let w = chk.wb.unwrap_or_else(|| panic!("{env:?}: the phase check sets no write barrier:\n{}", b.listing));
        assert!(chk.stall >= 2, "{env:?}: the waiter one cycle behind the setter passes before the barrier is armed (S{:02})\n{}", chk.stall, b.listing);
        assert!(bra.text.starts_with("@!P0 BRA") && bra.waits(w), "{env:?}: the branch on the predicate waits scoreboard {w}:\n{}", b.listing);
    }
    // the default path: the predicate is read behind a fixed stall and no barrier -- the probe
    // kernel's consumer threads are wrong at every stall on silicon
    let d = build("mbar_wait", &[]);
    assert_eq!(at(&d, "SYNCS.PHASECHK").wb, None, "the default path changed:\n{}", d.listing);
}

#[test]
fn an_arrive_reads_its_operands_late() {
    for env in MODELS {
        let b = build("mbar_wait", env);
        let arr = at(&b, "SYNCS.ARRIVE.TRANS64.A1T0");
        let r = arr.rb.unwrap_or_else(|| panic!("{env:?}: the arrive whose address is overwritten behind it sets no read barrier:\n{}", b.listing));
        assert!(at(&b, "IADD3 R4").waits(r), "{env:?}: the overwriter of the address waits scoreboard {r}:\n{}", b.listing);
        assert_eq!(arr.wb, None, "{env:?}: an arrive has no result");
    }
}

#[test]
fn the_suspend_form_waits_at_every_reader() {
    for env in MODELS {
        let b = build("mbar_sleep", env);
        let i = nth(&b, "SYNCS.PHASECHK.TRANS64.TRYWAIT", 0);
        let w1 = b.lines[i].wb.expect("write barrier of the try-wait");
        let sleep = &b.lines[i + 1];
        assert!(sleep.text.starts_with("@!P0 NANOSLEEP.SYNCS") && sleep.waits(w1), "{env:?}: the guarded sleep waits its guard's producer:\n{}", b.listing);
        assert_eq!((sleep.stall, sleep.yld), (5, true), "{env:?}: NANOSLEEP is issued at S05 with yield (ptxas: 200 of 200)");
        let chk = &b.lines[i + 2];
        let w2 = chk.wb.expect("write barrier of the second phase check");
        assert!(chk.text.starts_with("@!P0 SYNCS.PHASECHK.TRANS64 ") && chk.stall >= 2, "{}", b.listing);
        assert!(b.lines[i + 3].text.starts_with("@!P0 BRA") && b.lines[i + 3].waits(w2), "{env:?}: the loop branch waits the re-check:\n{}", b.listing);
    }
}

#[test]
fn fence_and_init_are_ordered_by_tokens() {
    for env in MODELS {
        let b = build("mbar_init", env);
        let fence = at(&b, "FENCE.VIEW.ASYNC.S");
        let f = fence.wb.unwrap_or_else(|| panic!("{env:?}: the fence sets no barrier:\n{}", b.listing));
        assert!(fence.stall >= 2, "{env:?}: {}", b.listing);
        let cctl = at(&b, "SYNCS.CCTL.IVALL");
        assert!(cctl.waits(f), "{env:?}: the first mbarrier word behind the fence waits it:\n{}", b.listing);
        let m1 = cctl.wb.expect("SYNCS.CCTL.IVALL sets a barrier");
        let init = at(&b, "SYNCS.EXCH.64");
        assert!(init.waits(m1), "{env:?}: the init waits the cache control:\n{}", b.listing);
        let m2 = init.wb.expect("the init sets a barrier");
        let r = init.rb.unwrap_or_else(|| panic!("{env:?}: the init whose value register is overwritten sets no read barrier:\n{}", b.listing));
        assert_ne!(r, m2, "{env:?}: read and write barrier of one word are two scoreboards");
        assert!(at(&b, "UMOV UR4, 0x2").waits(r), "{env:?}: the overwriter of the init's operand waits scoreboard {r}:\n{}", b.listing);
        assert!(at(&b, "BAR.SYNC").waits(m2), "{env:?}: the __syncthreads behind the init waits it:\n{}", b.listing);
    }
}

#[test]
fn the_release_chain_and_the_acquire() {
    for env in MODELS {
        let b = build("release_acquire", env);
        let s = |p: &str| (at(&b, p).stall, at(&b, p).yld);
        assert_eq!(s("MEMBAR.ALL.CTA"), (0, false), "{env:?}: the chain's first word carries no stall:\n{}", b.listing);
        assert_eq!(s("MEMBAR.ALL.GPU"), (6, true), "{env:?}:\n{}", b.listing);
        assert_eq!(s("ERRBAR"), (0, false), "{env:?}:\n{}", b.listing);
        assert_eq!(s("CGAERRBAR"), (6, true), "{env:?}:\n{}", b.listing);
        let w = at(&b, "LDG.E.STRONG.GPU").wb.expect("the acquire load sets a barrier");
        assert!(at(&b, "CCTL.IVALL").waits(w), "{env:?}: the invalidate is issued after the load returned:\n{}", b.listing);
    }
}

#[test]
fn a_bulk_copy_and_its_group() {
    for env in MODELS {
        let b = build("bulk", env);
        let f = at(&b, "FENCE.VIEW.ASYNC.S").wb.expect("the fence sets a barrier");
        let cp = at(&b, "UBLKCP.S.G");
        assert!(cp.waits(f), "{env:?}: the copy waits the fence:\n{}", b.listing);
        assert_eq!((cp.stall, cp.yld), (12, false), "{env:?}: the load form is issued at S12 without yield:\n{}", b.listing);
        let r = cp.rb.unwrap_or_else(|| panic!("{env:?}: the copy whose size register is overwritten sets no read barrier:\n{}", b.listing));
        assert!(at(&b, "UMOV UR6, 0x2000").waits(r), "{env:?}:\n{}", b.listing);
        assert_eq!(at(&b, "UTMACMDFLUSH").rb, Some(0), "{env:?}: the commit's read barrier is the group's scoreboard:\n{}", b.listing);
        assert_eq!(at(&b, "LDGDEPBAR").wb, Some(0), "{env:?}:\n{}", b.listing);
        let dep = at(&b, "DEPBAR.LE SB0");
        assert_eq!((dep.stall, dep.yld), (4, false), "{env:?}:\n{}", b.listing);
        for l in b.lines.iter().filter(|l| !l.text.starts_with("UTMACMDFLUSH") && !l.text.starts_with("LDGDEPBAR")) {
            assert!(l.wb != Some(0) && l.rb != Some(0), "{env:?}: scoreboard 0 belongs to the copy group, `{}` uses it:\n{}", l.text, b.listing);
        }
    }
}

#[test]
fn the_register_pool_allocation_is_a_scoreboard_result() {
    for env in MODELS {
        let b = build("setmaxnreg", env);
        assert_eq!(b.lines.len(), source_instructions("setmaxnreg"), "{env:?}: nothing is inserted:\n{}", b.listing);
        let i = nth(&b, "USETMAXREG.TRY_ALLOC.CTAPOOL", 0);
        let w = b.lines[i].wb.unwrap_or_else(|| panic!("{env:?}: TRY_ALLOC sets no write barrier:\n{}", b.listing));
        assert!(b.lines[i].stall >= 2, "{env:?}:\n{}", b.listing);
        assert!(b.lines[i + 1].text.starts_with("BRA.U !UP0") && b.lines[i + 1].waits(w), "{env:?}: the retry branch waits the allocation:\n{}", b.listing);
        assert_eq!(at(&b, "USETMAXREG.DEALLOC").stall, 0, "{env:?}: the release is a hardware interlock (ptxas: S00):\n{}", b.listing);
    }
}

#[test]
fn a_shuffle_behind_a_divergence_branch_and_its_collective_fallback() {
    for env in MODELS {
        let b = build("collective", env);
        assert_eq!(b.lines.len(), source_instructions("collective"), "{env:?}: nothing is inserted:\n{}", b.listing);
        // the fast path: the instruction behind `BRA.DIV` is live code
        let fast = nth(&b, "SHFL.IDX PT, R8", 0);
        let w = b.lines[fast].wb.expect("the shuffle sets a write barrier");
        assert!(b.lines[fast + 1].text.starts_with("IADD3 R9") && b.lines[fast + 1].waits(w), "{env:?}: the reader on the fast path waits the shuffle:\n{}", b.listing);
        // the collective region
        let entry = nth(&b, "WARPSYNC.COLLECTIVE", 0);
        assert_eq!((b.lines[entry - 1].stall, b.lines[entry - 1].yld), (7, false), "{env:?}: S07 without yield in front of the region:\n{}", b.listing);
        assert_eq!(b.lines[entry].stall, 5, "{env:?}:\n{}", b.listing);
        let sh = &b.lines[entry + 1];
        let (r, w) = (sh.rb.expect("read barrier of the region's shuffle"), sh.wb.expect("write barrier of the region's shuffle"));
        assert_ne!(r, w, "{env:?}:\n{}", b.listing);
        assert_eq!(sh.stall, 2, "{env:?}:\n{}", b.listing);
        let end = &b.lines[entry + 2];
        assert!(end.text.starts_with("ENDCOLLECTIVE") && end.waits(r) && end.waits(w) && end.stall == 5, "{env:?}: the region's end waits both:\n{}", b.listing);
    }
}

#[test]
fn nothing_is_inserted_and_the_layout_holds() {
    for name in ["loop_layout", "mbar_wait", "mbar_sleep", "bulk", "sync_probes"] {
        for env in MODELS {
            let b = build(name, env);
            assert_eq!(b.lines.len(), source_instructions(name), "{name} {env:?}: the instruction count moved:\n{}", b.log);
        }
    }
    // the load that is pending at the back-edge is waited by its reader, on every path
    for env in MODELS {
        let b = build("loop_layout", env);
        let w = at(&b, "LDG.E R4").wb.expect("the load sets a barrier");
        assert!(at(&b, "IADD3 R6").waits(w), "{env:?}:\n{}", b.listing);
        assert!(!b.listing.contains("UIADD3 URZ"), "{env:?}: no drain instruction:\n{}", b.listing);
    }
}

#[test]
fn a_frozen_instruction_keeps_its_control_code() {
    let b = build("frozen_store", &[SWITCH]);
    let st = at(&b, "@!P4 STG.E.64");
    assert_eq!(st.rb, Some(4), "the hand-scheduled store's read barrier is its author's (its frozen waiter waits scoreboard 4):\n{}", b.listing);
    assert!(at(&b, "@P4 BRA").waits(4));
    // every hand-scheduled line of the source is in the result as written
    let src = std::fs::read_to_string(format!("{FIX}/frozen_store.sass")).unwrap();
    for l in src.lines().map(str::trim).filter(|l| l.starts_with("[B")) {
        let tag = &l[..l.find(']').unwrap() + 1];
        let op = l[tag.len()..].split_whitespace().next().unwrap();
        assert!(b.listing.lines().any(|x| x.contains(tag) && x.contains(op)), "`{l}` is not in the result as written:\n{}", b.listing);
    }
}

/// The three laws of ptxas's schedules that the first cubit-scheduled kernels of nvcc broke on
/// silicon (the served MoE kernels, 2026-11-10: CUDA_ERROR_ILLEGAL_ADDRESS / LAUNCH_FAILED).
#[test]
fn a_register_indirect_branch_is_issued_like_a_branch() {
    for env in MODELS {
        let b = build("dispatch", env);
        let brx = at(&b, "BRX R50");
        assert!(brx.stall >= 5 && brx.yld, "{env:?}: ptxas issues every control transfer at S05 or more, with yield (BRX: 58 of 58):\n{}", b.listing);
    }
    // the dependency-aware model without the switch schedules the dispatch as an ALU instruction
    let d = build("dispatch", &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120")]);
    assert_eq!(at(&d, "BRX R50").stall, 1, "the default path changed:\n{}", d.listing);
}

#[test]
fn a_reuse_flag_stands_only_on_a_word_with_yield_and_stall_1_or_2() {
    for env in MODELS {
        let b = build("dispatch", env);
        assert!(!b.listing.contains("!rsd["), "{env:?}: a reuse bit without the yield bit is not a reuse flag (nvdisasm prints none):\n{}", b.listing);
        for l in b.lines.iter().filter(|l| l.text.contains(".reuse")) {
            assert!(l.yld && (1..=2).contains(&l.stall), "{env:?}: `{}` at S{:02} yield {}: ptxas sets the flag only with yield at S01 / S02", l.text, l.stall, l.yld);
        }
        assert!(b.log.contains("reuse flags dropped"), "{env:?}: the log names what was dropped:\n{}", b.log);
    }
    // under the dependency-aware model the first flagged word keeps its S01: the flag stays
    let b = build("dispatch", MODELS[1]);
    assert!(at(&b, "IADD3 R7").text.contains("R20.reuse"), "{}", b.listing);
}

#[test]
fn an_async_copy_never_waits() {
    for env in MODELS {
        let b = build("dispatch", env);
        let i = nth(&b, "LDGSTS.E.BYPASS.128", 0);
        assert_eq!(b.lines[i].wait, 0, "{env:?}: ptxas never puts a wait mask on LDGSTS (0 of 1 163):\n{}", b.listing);
        let w = at(&b, "LDS.64 R4").wb.expect("the load of the copy's address sets a barrier");
        assert!(b.lines[i - 1].waits(w), "{env:?}: the instruction in front of the copy waits for its address:\n{}", b.listing);
    }
}

/// The six probe kernels of nvcc: every scoreboard result of a synchronisation word is waited by
/// the reader behind it, and the classes agree with ptxas's own schedule of the same code.
#[test]
fn the_probe_kernels_agree_with_ptxas() {
    let ptxas: Vec<Line> = std::fs::read_to_string(format!("{FIX}/sync_probes.ptxas.sass")).unwrap().lines().filter_map(parse_line).collect();
    for env in MODELS {
        let b = build("sync_probes", env);
        assert_eq!(b.lines.len(), ptxas.len());
        let mut results = 0;
        for (i, (c, p)) in b.lines.iter().zip(&ptxas).enumerate() {
            assert_eq!(c.text.split_whitespace().next(), p.text.split_whitespace().next(), "instruction {i} is another one");
            // the opcode behind an optional guard (`@!P0 SYNCS.PHASECHK.TRANS64 P0, ...`)
            let word = c.text.split_whitespace().find(|t| !t.starts_with('@')).unwrap_or("");
            // a result: the predicate of a phase check / of the pool allocation
            if word.starts_with("SYNCS.PHASECHK") || word.starts_with("USETMAXREG.TRY_ALLOC") {
                results += 1;
                let w = c.wb.unwrap_or_else(|| panic!("{env:?}: `{}` sets no write barrier", c.text));
                assert!(c.stall >= 2, "{env:?}: `{}` at S{:02}", c.text, c.stall);
                assert!(b.lines[i + 1].waits(w), "{env:?}: `{}` behind `{}` does not wait scoreboard {w}", b.lines[i + 1].text, c.text);
                assert!(p.wb.is_some(), "ptxas sets a write barrier on `{}` too", p.text);
            }
            // the words whose stall is their class: ptxas's value
            if ["MEMBAR", "ERRBAR", "CGAERRBAR", "DEPBAR", "UBLKCP.S.G", "USETMAXREG.DEALLOC"].iter().any(|w| word.starts_with(w)) {
                let same_chain = !(word.starts_with("MEMBAR.ALL.CTA") && p.stall == 6); // in front of a FENCE ptxas settles first
                if same_chain {
                    assert_eq!(c.stall, p.stall, "{env:?}: `{}` stall {} (ptxas {})", c.text, c.stall, p.stall);
                }
            }
            // a token: ptxas sets a write barrier on the fence, the init, the group commit
            if word.starts_with("FENCE") || word.starts_with("SYNCS.EXCH") || word.starts_with("LDGDEPBAR") {
                assert_eq!(c.wb.is_some(), p.wb.is_some(), "{env:?}: `{}`", c.text);
            }
            if word.starts_with("UTMACMDFLUSH") {
                assert_eq!((c.rb, p.rb), (Some(0), Some(0)), "{env:?}: `{}`", c.text);
            }
        }
        assert_eq!(results, 8, "the fixture's scoreboard results of synchronisation words");
    }
}

#[test]
fn the_default_path_is_byte_for_byte() {
    let pins = std::fs::read_to_string(format!("{FIX}/default_path.sha256")).unwrap();
    let mut checked = 0;
    for name in FIXTURES {
        for (mode, env) in [("default", &[][..]), ("sched2", &[("CUBIT_SCHED2", "1"), ("CUBIT_SCHED2_LAT", "sm120")][..])] {
            let b = build(name, env);
            let want = std::fs::read_to_string(format!("{FIX}/{name}.{mode}.txt")).unwrap();
            assert_eq!(b.listing, want, "{name} [{mode}]: the schedule without the switch moved");
            let pin = pins
                .lines()
                .find_map(|l| {
                    let f: Vec<&str> = l.split_whitespace().collect();
                    (f.len() == 3 && f[0] == name && f[1] == mode).then(|| f[2].to_string())
                })
                .unwrap_or_else(|| panic!("no pin for {name} {mode}"));
            assert_eq!(b.sha256, pin, "{name} [{mode}]: the cubin without the switch is not the one origin/main built");
            checked += 1;
        }
    }
    assert_eq!(checked, 22);
}
