//! `CUBIT_LOAD_COVER=1` (opt-in, 2026-11-13; with `CUBIT_WAIT_POLICY=1`): the vendor's form of a shared-memory
//! load (KNOWN_ISSUES A57; `scheduling_pass::load_cover`).
//!
//! The memory pipe of a thread delivers in issue order, and the vendor's assembler lets ONE wait on a younger
//! shared load stand for the older ones in front of it. cubit gives every load a scoreboard of its own; in the
//! stage loop of the served fc2 kernel that is 72 loads on six scoreboards, 34 of them in nine shared sets and
//! one load that waits four scoreboards before it rewrites a base register. The switch has three clauses, each
//! in front of the colouring (a use that is dropped takes no scoreboard):
//!
//! 1. a shared load carries no write barrier when the wait of a younger shared load stands at or in front of
//!    each of its own first readers — the load is BARE;
//! 2. no read barrier on the base of a shared load that a younger shared load rewrites — the clause of
//!    `CUBIT_WAIT_POLICY` for a plain `LDS`, here also for `LDS.64` and `LDS.U16`;
//! 3. of the shared loads off one base register that the same word rewrites, the youngest carries the read
//!    barrier.
//!
//! And the vendor's SHARING, at the colouring itself:
//!
//! 4. a word's read barrier takes its scoreboard in front of its write barrier, and a shared load that finds
//!    no scoreboard free joins the shared load in front of it that is still in flight — ONE set in front of
//!    ONE wait, the first reader of any of its loads; the readers behind that word do not wait again
//!    (`[W4] LDS R89 ; [R5:W4] LDS.U16 R14 ; [W4] LDS.64 R48 ; [W4] LDS.64 R10 ; [W4] LDS R87 ... [B4] QMMA`);
//! 5. the read barrier of a `SYNCS.ARRIVE` in front of a BACKWARD branch holds its scoreboard up to the
//!    overwriter behind the branch, which waits it; on the path through the branch the first word that arms
//!    that scoreboard again waits it first (`[R0] SYNCS.ARRIVE ... BRA L_49f0` and, behind `L_49f0`,
//!    `[B0:W0] S2R R75, SR_CgaCtaId`) — the branch itself carries no wait.
//!
//! Four of the first five tests fail on the allocator without the switch (the variable is then unknown and
//! changes nothing); the fifth is their control — a load that keeps its barrier under the switch too. The
//! two tests of the sharing fail on the switch as it stood with its three clauses alone.

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const SYNC: (&str, &str) = ("CUBIT_SYNC_CLASSES", "1");
const POLICY: (&str, &str) = ("CUBIT_WAIT_POLICY", "1");
const COVER: (&str, &str) = ("CUBIT_LOAD_COVER", "1");

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
    let dir = std::env::temp_dir().join(format!("loadcover_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let (src, out) = (dir.join("k.sass"), dir.join("k.cubin"));
    std::fs::write(&src, format!(".entry load_cover_probe\n    .reg R0-R63\n    .param ptr out\n{body}.endentry\n")).unwrap();
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

/// Two shared loads off two bases; ONE word reads both results (the scale loads of a tensor word in the served
/// kernel: `LDS R86, [R12+0x2100] ; LDS R91, [R90+0x2000] ... QMMA ... R91, R86`).
const ONE_READER: &str = "    S2R R2, SR_TID.X ;
    SHF.L.U32 R8, R2, 0x4, RZ ;
    MOV R9, R8 ;
    LDS R4, [R8+0x100] ;
    IADD3 R12, PT, PT, R2, 0x1, RZ ;
    LDS R5, [R9+0x1200] ;
    IADD3 R6, PT, PT, R4, R5, RZ ;
    IADD3 R6, PT, PT, R6, R12, RZ ;
    EXIT ;
";

/// The younger load's first reader stands IN FRONT of the older load's first reader.
const YOUNGER_FIRST: &str = "    S2R R2, SR_TID.X ;
    SHF.L.U32 R8, R2, 0x4, RZ ;
    MOV R9, R8 ;
    LDS R4, [R8+0x100] ;
    IADD3 R12, PT, PT, R2, 0x1, RZ ;
    LDS.64 R20, [R9+0x1200] ;
    MOV R16, R20 ;
    MOV R17, R21 ;
    IADD3 R6, PT, PT, R4, R16, RZ ;
    IADD3 R6, PT, PT, R6, R17, RZ ;
    EXIT ;
";

/// The older load is read first: no younger load's wait stands in front of its reader.
const OLDER_FIRST: &str = "    S2R R2, SR_TID.X ;
    SHF.L.U32 R8, R2, 0x4, RZ ;
    MOV R9, R8 ;
    LDS R4, [R8+0x100] ;
    IADD3 R12, PT, PT, R2, 0x1, RZ ;
    LDS.64 R20, [R9+0x1200] ;
    IADD3 R6, PT, PT, R4, R12, RZ ;
    MOV R16, R20 ;
    IADD3 R6, PT, PT, R6, R16, RZ ;
    EXIT ;
";

/// Two `LDS.64` off one base; a younger `LDS.64` rewrites the base (`LDS.64 R58, [R64+0x1e00] ... LDS.64 R64,
/// [R92]` in the served kernel).
const BASE_64: &str = "    S2R R2, SR_TID.X ;
    SHF.L.U32 R8, R2, 0x4, RZ ;
    MOV R10, R8 ;
    LDS.64 R20, [R8+0x1000] ;
    IADD3 R12, PT, PT, R2, 0x1, RZ ;
    LDS.64 R22, [R8+0x1200] ;
    IADD3 R13, PT, PT, R2, 0x2, RZ ;
    LDS.64 R8, [R10] ;
    MOV R16, R20 ;
    MOV R17, R22 ;
    IADD3 R6, PT, PT, R16, R17, RZ ;
    IADD3 R6, PT, PT, R6, R8, RZ ;
    EXIT ;
";

/// Two loads off one base that a fixed-latency word rewrites (`LDS R86, [R12+0x2100] ... LDS R81, [R12+0x2120]
/// ... LOP3.LUT R12, ...` in the served kernel).
const ONE_BASE: &str = "    S2R R2, SR_TID.X ;
    SHF.L.U32 R8, R2, 0x4, RZ ;
    LDS R4, [R8+0x2100] ;
    IADD3 R12, PT, PT, R2, 0x1, RZ ;
    LDS R5, [R8+0x2120] ;
    IADD3 R13, PT, PT, R2, 0x2, RZ ;
    LOP3.LUT R8, R12, 0x3c3c3c3c, RZ, 0xc0, !PT ;
    IADD3 R6, PT, PT, R4, R5, RZ ;
    IADD3 R6, PT, PT, R6, R8, RZ ;
    EXIT ;
";

#[test]
fn a_shared_load_under_the_wait_of_a_younger_one_is_bare() {
    // the policy alone: both loads carry a write barrier and the reader waits both
    let (k, policy_cubin) = build(ONE_READER, &[SYNC, POLICY]);
    let (older, younger, reader) = (word(&k, "LDS R4,"), word(&k, "LDS R5,"), word(&k, "IADD3 R6, PT, PT, R4,"));
    assert!(older.wb.is_some() && younger.wb.is_some(), "{k:#?}");
    assert!(reader.wait.contains(&older.wb.unwrap()) && reader.wait.contains(&younger.wb.unwrap()), "{k:#?}");
    // the switch: the older load is bare, the reader waits the younger one alone
    let (k, cubin) = build(ONE_READER, &[SYNC, POLICY, COVER]);
    let (older, younger, reader) = (word(&k, "LDS R4,"), word(&k, "LDS R5,"), word(&k, "IADD3 R6, PT, PT, R4,"));
    assert_eq!(older.wb, None, "{k:#?}");
    assert_eq!(reader.wait, vec![younger.wb.expect("the younger load keeps its barrier")], "{k:#?}");
    assert!(cubin != policy_cubin);
    // a younger load whose first reader stands in front of the older load's: bare as well, and the older
    // load's reader waits nothing
    let (k, _) = build(YOUNGER_FIRST, &[SYNC, POLICY, COVER]);
    let (older, younger) = (word(&k, "LDS R4,"), word(&k, "LDS.64 R20,"));
    assert_eq!(older.wb, None, "{k:#?}");
    assert_eq!(word(&k, "MOV R16,").wait, vec![younger.wb.unwrap()], "{k:#?}");
    assert!(word(&k, "IADD3 R6, PT, PT, R4,").wait.is_empty(), "{k:#?}");
}

#[test]
fn a_load_that_is_read_in_front_of_every_younger_load_keeps_its_barrier() {
    let (k, cubin) = build(OLDER_FIRST, &[SYNC, POLICY, COVER]);
    let (older, younger) = (word(&k, "LDS R4,"), word(&k, "LDS.64 R20,"));
    assert_eq!(word(&k, "IADD3 R6, PT, PT, R4,").wait, vec![older.wb.expect("no wait stands in front of its reader")], "{k:#?}");
    assert_eq!(word(&k, "MOV R16,").wait, vec![younger.wb.unwrap()], "{k:#?}");
    // nothing of the switch applies: the policy's bytes
    assert!(cubin == build(OLDER_FIRST, &[SYNC, POLICY]).1);
    // a guarded older load is not bare either (the cover is for plain loads)
    let guarded = ONE_READER.replacen("    LDS R4,", "    ISETP.NE.AND P0, PT, R2, RZ, PT ;\n    @P0 LDS R4,", 1);
    let (k, _) = build(&guarded, &[SYNC, POLICY, COVER]);
    assert!(word(&k, "@P0 LDS R4,").wb.is_some(), "{k:#?}");
}

#[test]
fn the_base_of_a_wide_shared_load_rewritten_by_a_younger_one_carries_no_read_barrier() {
    // the policy alone (its clause is for a plain `LDS`): the two loads carry a read barrier and the load that
    // rewrites the base waits them
    let (k, _) = build(BASE_64, &[SYNC, POLICY]);
    let (a, b, last) = (word(&k, "LDS.64 R20,"), word(&k, "LDS.64 R22,"), word(&k, "LDS.64 R8,"));
    assert!(a.rb.is_some() && b.rb.is_some(), "{k:#?}");
    assert!(last.wait.contains(&a.rb.unwrap()) && last.wait.contains(&b.rb.unwrap()), "{k:#?}");
    // the switch: no read barrier, the younger load waits nothing
    let (k, _) = build(BASE_64, &[SYNC, POLICY, COVER]);
    let (a, b, last) = (word(&k, "LDS.64 R20,"), word(&k, "LDS.64 R22,"), word(&k, "LDS.64 R8,"));
    assert_eq!((a.rb, b.rb), (None, None), "{k:#?}");
    assert!(last.wait.is_empty(), "{k:#?}");
}

#[test]
fn of_the_loads_off_one_base_the_youngest_carries_the_read_barrier() {
    // the policy alone: both loads carry a read barrier and the word that rewrites the base waits both
    let (k, _) = build(ONE_BASE, &[SYNC, POLICY]);
    let (older, younger, rewrite) = (word(&k, "LDS R4,"), word(&k, "LDS R5,"), word(&k, "LOP3.LUT R8,"));
    assert!(older.rb.is_some() && younger.rb.is_some(), "{k:#?}");
    assert!(rewrite.wait.contains(&older.rb.unwrap()) && rewrite.wait.contains(&younger.rb.unwrap()), "{k:#?}");
    // the switch: the younger load alone
    let (k, _) = build(ONE_BASE, &[SYNC, POLICY, COVER]);
    let (older, younger, rewrite) = (word(&k, "LDS R4,"), word(&k, "LDS R5,"), word(&k, "LOP3.LUT R8,"));
    assert_eq!(older.rb, None, "{k:#?}");
    assert_eq!(rewrite.wait, vec![younger.rb.expect("the youngest load off the base keeps the read barrier")], "{k:#?}");
}

/// Four wide loads read late, then four loads in a row: six scoreboards for nine uses. The second load of the
/// row carries a read barrier (a fixed-latency word rewrites its base); every load of the row is read behind
/// the load in front of it, so none of them is bare (the ninth stage of the served fc2 kernel:
/// `LDS R89 ; LDS.U16 R14 ; LDS.64 R48 ; LDS.64 R10 ; LDS R87`).
const ONE_SET: &str = "    S2R R2, SR_TID.X ;
    SHF.L.U32 R8, R2, 0x4, RZ ;
    MOV R9, R8 ;
    MOV R10, R8 ;
    LDS.64 R20, [R9+0x1000] ;
    IADD3 R30, PT, PT, R2, 0x1, RZ ;
    LDS.64 R22, [R9+0x1200] ;
    IADD3 R31, PT, PT, R2, 0x2, RZ ;
    LDS.64 R24, [R9+0x1400] ;
    IADD3 R32, PT, PT, R2, 0x3, RZ ;
    LDS.64 R26, [R9+0x1600] ;
    IADD3 R33, PT, PT, R2, 0x4, RZ ;
    LDS R4, [R10+0x2000] ;
    LDS.U16 R5, [R8+0x2110] ;
    LDS.64 R28, [R9+0x1800] ;
    LDS R6, [R10+0x2040] ;
    MOV R16, R20 ;
    MOV R17, R22 ;
    MOV R18, R24 ;
    MOV R19, R26 ;
    LOP3.LUT R8, R30, 0x3c3c3c3c, RZ, 0xc0, !PT ;
    IADD3 R12, PT, PT, R4, R16, RZ ;
    IADD3 R12, PT, PT, R12, R5, RZ ;
    IADD3 R13, PT, PT, R28, R17, RZ ;
    IADD3 R13, PT, PT, R13, R6, RZ ;
    IADD3 R12, PT, PT, R12, R18, RZ ;
    IADD3 R13, PT, PT, R13, R19, RZ ;
    IADD3 R12, PT, PT, R12, R13, RZ ;
    IADD3 R12, PT, PT, R12, R8, RZ ;
    EXIT ;
";

/// A loop whose last words are a `SYNCS.ARRIVE` and the backward branch; a wide load rewrites the arrive's
/// address register behind the branch and another one at the loop's top, behind a special-register word that
/// arms a scoreboard (the stage loop of the served fc2 kernel: `@!P5 SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R69+URZ],
/// RZ ; @!P6 BRA L_49f0 ... LDS.64 R68, [R88+0x1c00]` and, at `L_49f0`, `S2R R75, SR_CgaCtaId ... LDS.64 R68,
/// [R64+0x1c00]`).
const ARRIVE_LOOP: &str = "    S2R R2, SR_TID.X ;
    SHF.L.U32 R10, R2, 0x3, RZ ;
    MOV R20, RZ ;
    MOV R6, RZ ;
L_top:
    IADD3 R20, PT, PT, R20, 0x1, RZ ;
    S2R R14, SR_CgaCtaId ;
    ISETP.NE.AND P0, PT, R20, 0x4, PT ;
    LEA R15, R14, R10, 0x18 ;
    LDS.64 R8, [R10+0x1c00] ;
    MOV R16, R8 ;
    IADD3 R6, PT, PT, R6, R16, RZ ;
    IADD3 R6, PT, PT, R6, R15, RZ ;
    SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R9+URZ], RZ ;
    @P0 BRA L_top ;
    LDS.64 R8, [R10+0x1e00] ;
    MOV R17, R8 ;
    IADD3 R6, PT, PT, R6, R17, RZ ;
    EXIT ;
";

#[test]
fn a_shared_load_that_finds_no_scoreboard_free_joins_the_load_in_front_one_set_one_wait() {
    let (k, cubin) = build(ONE_SET, &[SYNC, POLICY, COVER]);
    let row: Vec<&Word> = ["LDS R4,", "LDS.U16 R5,", "LDS.64 R28,", "LDS R6,"].iter().map(|s| word(&k, s)).collect();
    // ONE scoreboard for the row; the read barrier of its second load took the last free one first
    let sb = row[0].wb.expect("the load in front keeps its scoreboard");
    assert!(row.iter().all(|w| w.wb == Some(sb)), "{k:#?}");
    let rb = row[1].rb.expect("the load whose base is rewritten carries the read barrier");
    assert_ne!(rb, sb, "{k:#?}");
    assert!(row.iter().all(|w| w.wait.is_empty()), "no load waits: {k:#?}");
    let mut all: Vec<u8> = ["LDS.64 R20,", "LDS.64 R22,", "LDS.64 R24,", "LDS.64 R26,"]
        .iter()
        .map(|s| word(&k, s).wb.expect("a wide load in front keeps a scoreboard of its own"))
        .collect();
    all.extend([sb, rb]);
    all.sort_unstable();
    all.dedup();
    assert_eq!(all, vec![0, 1, 2, 3, 4, 5], "six scoreboards, none shared but the row's: {k:#?}");
    // ONE wait: the first reader of any load of the row; the readers behind it do not wait again
    assert_eq!(word(&k, "IADD3 R12, PT, PT, R4,").wait, vec![sb], "{k:#?}");
    for reader in ["IADD3 R12, PT, PT, R12, R5,", "IADD3 R13, PT, PT, R28,", "IADD3 R13, PT, PT, R13, R6,"] {
        assert!(word(&k, reader).wait.is_empty(), "{reader} {k:#?}");
    }
    assert_eq!(word(&k, "LOP3.LUT R8,").wait, vec![rb], "{k:#?}");
    assert!(cubin != build(ONE_SET, &[SYNC, POLICY]).1);
    assert!(build(ONE_SET, &[SYNC, COVER]).1 == build(ONE_SET, &[SYNC]).1);
}

#[test]
fn the_read_barrier_of_an_arrive_in_front_of_a_backward_branch_is_waited_where_its_scoreboard_is_armed_again() {
    // the policy alone: the branch waits the read barrier
    let (k, policy_cubin) = build(ARRIVE_LOOP, &[SYNC, POLICY]);
    let rb = word(&k, "SYNCS.ARRIVE").rb.expect("the word reads its address register late");
    assert!(word(&k, "@P0 BRA").wait.contains(&rb), "{k:#?}");
    assert!(word(&k, "S2R R14,").wait.is_empty(), "{k:#?}");
    // the switch: the overwriter behind the branch waits it; on the path through the branch the word that
    // arms the scoreboard again waits it first; the branch and the overwriter at the loop's top do not
    let (k, cubin) = build(ARRIVE_LOOP, &[SYNC, POLICY, COVER]);
    let rb = word(&k, "SYNCS.ARRIVE").rb.expect("the read barrier stays");
    let top = word(&k, "S2R R14,");
    assert_eq!((top.wb, top.wait.clone()), (Some(rb), vec![rb]), "{k:#?}");
    assert!(word(&k, "@P0 BRA").wait.is_empty(), "{k:#?}");
    assert!(word(&k, "LDS.64 R8, [R10+0x1e00]").wait.contains(&rb), "{k:#?}");
    assert!(!word(&k, "LDS.64 R8, [R10+0x1c00]").wait.contains(&rb), "{k:#?}");
    assert!(cubin != policy_cubin);
    assert!(build(ARRIVE_LOOP, &[SYNC, COVER]).1 == build(ARRIVE_LOOP, &[SYNC]).1);
}

#[test]
fn the_switch_is_honoured_only_with_the_wait_policy() {
    for text in [ONE_READER, YOUNGER_FIRST, BASE_64, ONE_BASE] {
        assert!(build(text, &[SYNC, COVER]).1 == build(text, &[SYNC]).1);
        assert!(build(text, &[COVER]).1 == build(text, &[]).1);
        assert!(build(text, &[SYNC, POLICY, COVER]).1 != build(text, &[SYNC, POLICY]).1);
    }
}
