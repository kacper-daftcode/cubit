//! `CUBIT_WAIT_POLICY=1` (opt-in, 2026-11-12; with `CUBIT_SYNC_CLASSES=1`): where the waits of an nvcc-shaped
//! kernel stand (KNOWN_ISSUES A49; `scheduling_pass::wait_policy`).
//!
//! On the consumer loops of the served MoE kernels cubit's schedule of the vendor's text lost to ptxas's by the
//! waits that BLOCK: a word waiting behind a young result that it does not read. Three places made them, and
//! the switch has one clause for each (it also contains `CUBIT_SB_SHARE=1`, `CUBIT_GUARDED_READER_SETTLES=1`
//! and `CUBIT_MMA_SRC_RB=0`):
//!
//! 1. the last load off a base register rewrites the base and waited the read barriers of the loads in front
//!    of it — no read barrier there, the vendor's form (the younger load keeps 4 issue cycles);
//! 2. the first overwriter of a `SYNCS.ARRIVE`'s address register was a load and waited the read barrier — the
//!    branch in front waits it, the vendor's place;
//! 3. a scale load (a plain shared load whose first readers are tensor instructions) shared a scoreboard with
//!    a fragment load whose unpack waits a few words on, inside the run of scale loads — it joins the nearest
//!    scale load's scoreboard, one set in front of one wait.
//!
//! Each pin fails on the allocator without the switch (the variable is then unknown and changes nothing).

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const SYNC: (&str, &str) = ("CUBIT_SYNC_CLASSES", "1");
const POLICY: (&str, &str) = ("CUBIT_WAIT_POLICY", "1");
/// what the switch contains of the older switches
const OLD: [(&str, &str); 3] = [("CUBIT_SB_SHARE", "1"), ("CUBIT_GUARDED_READER_SETTLES", "1"), ("CUBIT_MMA_SRC_RB", "0")];

/// One instruction of the schedule cubit wrote: (wait bits, read barrier, write barrier, the word).
#[derive(Debug, Clone, PartialEq)]
struct Word {
    wait: Vec<u8>,
    rb: Option<u8>,
    wb: Option<u8>,
    text: String,
}

/// `cubit asm` of an unscheduled kernel under `env`, then `cubit disassemble --frozen`: the words with the
/// control fields the allocator gave them, and the cubin's bytes.
fn build(body: &str, env: &[(&str, &str)]) -> (Vec<Word>, Vec<u8>) {
    let dir = std::env::temp_dir().join(format!("waitpol_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, format!(".entry wait_policy_probe\n    .reg R0-R63\n    .param ptr out\n{body}.endentry\n")).unwrap();
    let run = |args: &[&str]| {
        let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
        let log = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
        assert!(o.status.success(), "{args:?} under {env:?}: {log}");
        String::from_utf8_lossy(&o.stdout).into_owned()
    };
    run(&["asm", "-t", TABLE, src.to_str().unwrap(), "-o", out.to_str().unwrap()]);
    let listing = run(&["disassemble", "--frozen", out.to_str().unwrap(), "-t", TABLE]);
    let cubin = std::fs::read(&out).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let mut words = Vec::new();
    for line in listing.lines() {
        // `[B01----:R2:W3:Y:S04] <word> ;` behind an optional label
        let Some(at) = line.find("[B") else { continue };
        let tag = &line[at + 2..];
        let Some(end) = tag.find(']') else { continue };
        let fields: Vec<&str> = tag[..end].split(':').collect();
        if fields.len() != 5 {
            continue;
        }
        let digit = |f: &str| f[1..].parse::<u8>().ok();
        words.push(Word {
            wait: fields[0].bytes().filter(u8::is_ascii_digit).map(|b| b - b'0').collect(),
            rb: digit(fields[1]),
            wb: digit(fields[2]),
            text: tag[end + 1..].trim().trim_end_matches(';').trim().to_string(),
        });
    }
    (words, cubin)
}

fn word<'a>(k: &'a [Word], starts: &str) -> &'a Word {
    k.iter().find(|w| w.text.starts_with(starts)).unwrap_or_else(|| panic!("no word `{starts}` in {k:#?}"))
}

/// The last load off a base register rewrites the base (`LDS R8, [R8+0x320]`).
const BASE: &str = "    S2R R2, SR_TID.X ;
    SHF.L.U32 R8, R2, 0x2, RZ ;
    LDS R4, [R8+0x100] ;
    LDS R5, [R8+0x300] ;
    LDS R8, [R8+0x320] ;
    IADD3 R6, PT, PT, R4, R5, RZ ;
    IADD3 R6, PT, PT, R6, R8, RZ ;
    EXIT ;
";

/// A `SYNCS.ARRIVE`, a conditional branch, then a load that rewrites the word's address register.
const ARRIVE: &str = "    S2R R2, SR_TID.X ;
    SHF.L.U32 R10, R2, 0x3, RZ ;
    SHF.L.U32 R9, R2, 0x2, RZ ;
    ISETP.NE.AND P0, PT, R2, RZ, PT ;
    SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R10+URZ], RZ ;
    @P0 BRA L_out ;
    LDS R10, [R9+0x40] ;
    IADD3 R6, PT, PT, R10, 0x1, RZ ;
L_out:
    EXIT ;
";

/// Four fragment loads and scale loads through two bases, as in the consumer loop of the served FC1: six
/// scoreboards for eight results, `LDS R32` finds none free. The unpack of the first fragment load stands
/// inside the run of scale loads; the last scale load's reader is far behind (a long use: coloured first).
fn scale_run() -> String {
    let mut s = String::from(
        "    S2R R2, SR_TID.X ;
    SHF.L.U32 R8, R2, 0x4, RZ ;
    MOV R9, R8 ;
    MOV R10, R8 ;
    LDS.64 R20, [R8] ;
    LDS.64 R22, [R8+0x1000] ;
    LDS.64 R24, [R8+0x2000] ;
    LDS.64 R26, [R8+0x3000] ;
    LDS R30, [R9+0x3100] ;
    LDS R31, [R10+0x3000] ;
    LDS R32, [R9+0x3300] ;
    IMAD.SHL.U32 R40, R20, 0x4, RZ ;
    LDS R33, [R10+0x30c0] ;
    IMAD.SHL.U32 R41, R22, 0x4, RZ ;
    IMAD.SHL.U32 R42, R24, 0x4, RZ ;
    IMAD.SHL.U32 R43, R26, 0x4, RZ ;
    QMMA.SF.16832.F32.E4M3.E2M1.E8 R44, R12, R16, R44, R30, R31, URZ ;
    QMMA.SF.16832.F32.E4M3.E2M1.E8 R48, R12, R16, R48, R30, R32, URZ ;
",
    );
    for _ in 0..70 {
        s.push_str("    IADD3 R52, PT, PT, R52, 0x1, RZ ;\n");
    }
    s.push_str("    QMMA.SF.16832.F32.E4M3.E2M1.E8 R56, R12, R16, R56, R30, R33, URZ ;\n    EXIT ;\n");
    s
}

#[test]
fn the_base_of_a_plain_shared_load_rewritten_by_a_younger_one_carries_no_read_barrier() {
    // without the switch: both loads in front carry a read barrier and the load that rewrites the base waits them
    let (k, _) = build(BASE, &[SYNC]);
    let (a, b, last) = (word(&k, "LDS R4,"), word(&k, "LDS R5,"), word(&k, "LDS R8,"));
    assert!(a.rb.is_some() && b.rb.is_some(), "{k:#?}");
    assert!(last.wait.contains(&a.rb.unwrap()) && last.wait.contains(&b.rb.unwrap()), "{k:#?}");
    // with it: no read barrier, the younger load waits nothing; every result is still waited by its reader
    let (k, _) = build(BASE, &[SYNC, POLICY]);
    let (a, b, last) = (word(&k, "LDS R4,"), word(&k, "LDS R5,"), word(&k, "LDS R8,"));
    assert_eq!((a.rb, b.rb), (None, None), "{k:#?}");
    assert!(last.wait.is_empty(), "{k:#?}");
    let reader = word(&k, "IADD3 R6, PT, PT, R4,");
    assert!([a, b, last].iter().all(|l| reader.wait.contains(&l.wb.unwrap())), "{k:#?}");
}

#[test]
fn the_read_barrier_of_an_arrive_is_waited_by_the_branch_in_front_of_a_load_that_rewrites_its_address() {
    let (k, _) = build(ARRIVE, &[SYNC]);
    let (arrive, branch, load) = (word(&k, "SYNCS.ARRIVE"), word(&k, "@P0 BRA"), word(&k, "LDS R10,"));
    let rb = arrive.rb.expect("the word reads its address register late");
    assert!(load.wait.contains(&rb) && !branch.wait.contains(&rb), "{k:#?}");
    let (k, _) = build(ARRIVE, &[SYNC, POLICY]);
    let (arrive, branch, load) = (word(&k, "SYNCS.ARRIVE"), word(&k, "@P0 BRA"), word(&k, "LDS R10,"));
    let rb = arrive.rb.expect("the read barrier stays");
    assert!(branch.wait.contains(&rb), "{k:#?}");
    assert!(load.wait.is_empty(), "{k:#?}");
}

#[test]
fn a_scale_load_shares_a_scoreboard_with_scale_loads_only_and_the_switch_contains_the_three_older_ones() {
    let text = scale_run();
    // the older switches alone: `LDS R32` shares the scoreboard of the first fragment load, whose unpack waits
    // it one word behind the scale load -- inside the run of scale loads
    let mut env = vec![SYNC];
    env.extend(OLD);
    let (k, old_cubin) = build(&text, &env);
    let (frag, scale, unpack) = (word(&k, "LDS.64 R20,"), word(&k, "LDS R32,"), word(&k, "IMAD.SHL.U32 R40,"));
    assert_eq!(scale.wb, frag.wb, "{k:#?}");
    assert!(unpack.wait.contains(&scale.wb.unwrap()), "{k:#?}");
    // the switch: it joins the nearest scale load's scoreboard; the unpack waits the fragment load alone;
    // ONE wait for the set, on its first reader
    let (k, cubin) = build(&text, &[SYNC, POLICY]);
    let (frag, mate, scale, unpack) = (word(&k, "LDS.64 R20,"), word(&k, "LDS R31,"), word(&k, "LDS R32,"), word(&k, "IMAD.SHL.U32 R40,"));
    assert_ne!(scale.wb, frag.wb, "{k:#?}");
    assert_eq!(scale.wb, mate.wb, "{k:#?}");
    assert_eq!(unpack.wait, vec![frag.wb.unwrap()], "{k:#?}");
    let tensor: Vec<&Word> = k.iter().filter(|w| w.text.starts_with("QMMA")).collect();
    assert!(tensor[0].wait.contains(&scale.wb.unwrap()), "{k:#?}");
    assert!(!tensor[1].wait.contains(&scale.wb.unwrap()), "{k:#?}");
    assert!(cubin != old_cubin);
    // the older switches beside the new one change nothing: it contains them
    let mut env = vec![SYNC, POLICY];
    env.extend(OLD);
    assert!(build(&text, &env).1 == cubin);
    // and without CUBIT_SYNC_CLASSES the variable is not honoured
    assert!(build(&text, &[POLICY]).1 == build(&text, &[]).1);
}
