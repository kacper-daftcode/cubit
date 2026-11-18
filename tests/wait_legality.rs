//! The legality of the wait rule (`CUBIT_WAIT_DRAINED=head | paths`, with `CUBIT_WAIT_POLICY=1`) beyond the uses
//! (`wait_drained`, KNOWN_ISSUES A67).
//!
//! The rule judges a wait bit by the uses the allocator wrote it for, on the paths of the flow graph. Two things
//! stand outside that statement, and the rule as it was first written lost a wait to each:
//!
//! * **The fields.** A wait releases every barrier armed on its scoreboard, also the read barrier of a word no
//!   use of the bit names. `CUBIT_LOAD_COVER`'s sharing leaves the read barrier of a `SYNCS.ARRIVE` in front of a
//!   backward branch to the first wait of the loop's head -- a wait the allocator wrote for ANOTHER use -- and
//!   told the rule nothing: the bit went with the use it was written for, and the word behind it rewrote the
//!   arrive's address register while the arrive was in flight (the instance `fc2_kernel_ws<4,2,1,0>` built with
//!   every control word cubit's: one pair, `SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R10+URZ], RZ` and, at the top of its
//!   loop, `SHF.L.U32 R10, R62, 0x1f, RZ`). Two layers hold it, and each alone does: the sharing tells the rule
//!   (the bit is written for the arrive's use too), and a guard on the fields puts back whatever wait the path
//!   audit (`CUBIT_HAZ`, its write-after-read half) misses that the allocator's schedule had.
//! * **The jump tables.** The flow graph reads no table: a register-indirect branch gets the word behind it, every
//!   block no branch names and the join of its case blocks. An entry of its table may name a word that a branch
//!   names too -- a path the graph does not have (the instance `fc1_kernel_wg<4,1,1,0,0>`: two such edges). The
//!   closing check of the rule walks every entry of every table (the constant section of bank 2 of the template,
//!   `cubit asm -T`); a dispatch whose table cannot be read keeps every wait written for a barrier that can still
//!   be armed where it issues.
//!
//! The kernels pin all six scoreboards with hand-scheduled loads that fly across the whole text (as
//! `tests/wait_drained.rs` does), so every use the allocator colours shares scoreboard 0.
//!
//! Five tests fail on the rule as it was; `told_of_the_read_barrier_the_rule_keeps_the_wait_of_the_head` is a
//! control that passes on both (the rule always judged a bit by every use it was told of).

use cubit::cfg_flow::Cfg;
use cubit::ir::Instruction;
use cubit::wait_drained::{apply, Drained, Written};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);
const TABLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tables/sm120.json.gz");
const KERNEL: &str = "wait_legality_probe";
const SYNC: (&str, &str) = ("CUBIT_SYNC_CLASSES", "1");
const POLICY: (&str, &str) = ("CUBIT_WAIT_POLICY", "1");
const COVER: (&str, &str) = ("CUBIT_LOAD_COVER", "1");
const PATHS: (&str, &str) = ("CUBIT_WAIT_DRAINED", "paths");
const HAZ: (&str, &str) = ("CUBIT_HAZ", "1");
const USES: (&str, &str) = ("CUBIT_DUMP_USES", "1");

/// One instruction of the schedule cubit wrote: (wait bits, the word).
#[derive(Debug, Clone, PartialEq)]
struct Word {
    wait: Vec<u8>,
    text: String,
}

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("waitlegality_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `cubit asm` of the kernel under `env`, on a template or without one: the cubin and the log (both streams).
fn asm(dir: &Path, body: &str, env: &[(&str, &str)], template: Option<&Path>, name: &str) -> (PathBuf, String) {
    let (src, out) = (dir.join("k.sass"), dir.join(name));
    std::fs::write(&src, format!(".entry {KERNEL}\n    .reg R0-R63\n    .param ptr out\n{body}.endentry\n")).unwrap();
    let mut args: Vec<&str> = vec!["asm", "-t", TABLE];
    if let Some(t) = template {
        args.extend(["-T", t.to_str().unwrap()]);
    }
    args.extend([src.to_str().unwrap(), "-o", out.to_str().unwrap()]);
    let o = Command::new(env!("CARGO_BIN_EXE_cubit")).args(&args).env_clear().envs(env.iter().copied()).output().expect("run cubit");
    let log = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success(), "asm under {env:?}: {log}");
    (out, log)
}

/// `cubit disassemble --frozen`: the words with the wait bits the allocator gave them.
fn listing(cubin: &Path) -> Vec<Word> {
    let o = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["disassemble", "--frozen", cubin.to_str().unwrap(), "-t", TABLE])
        .env_clear()
        .output()
        .expect("run cubit");
    assert!(o.status.success(), "disassemble: {}", String::from_utf8_lossy(&o.stderr));
    let mut words = Vec::new();
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        // `[B01----:R2:W3:Y:S04] <word> ;` behind an optional label
        let Some(at) = line.find("[B") else { continue };
        let tag = &line[at + 2..];
        let Some(end) = tag.find(']') else { continue };
        let fields: Vec<&str> = tag[..end].split(':').collect();
        if fields.len() != 5 {
            continue;
        }
        words.push(Word {
            wait: fields[0].bytes().filter(u8::is_ascii_digit).map(|b| b - b'0').collect(),
            text: tag[end + 1..].trim().trim_end_matches(';').trim().to_string(),
        });
    }
    words
}

/// The kernel built under `env` without a template: its words and the log of the build.
fn build(body: &str, env: &[(&str, &str)]) -> (Vec<Word>, String) {
    let dir = scratch();
    let (cubin, log) = asm(&dir, body, env, None, "k.cubin");
    let words = listing(&cubin);
    let _ = std::fs::remove_dir_all(&dir);
    (words, log)
}

/// The kernel built under `env` on a template: the kernel's own build with -- `Some` -- the constant section of
/// bank 2 `constants` appended, as the cubin of a kernel with a dispatch holds its jump tables.
fn build_on_template(body: &str, env: &[(&str, &str)], constants: Option<&[u8]>) -> (Vec<Word>, String) {
    let dir = scratch();
    let (base, _) = asm(&dir, body, &[SYNC, POLICY], None, "base.cubin");
    let template = dir.join("template.cubin");
    let bytes = std::fs::read(&base).unwrap();
    std::fs::write(&template, constants.map_or(bytes.clone(), |c| with_section(&bytes, &format!(".nv.constant2.{KERNEL}"), c))).unwrap();
    let (cubin, log) = asm(&dir, body, env, Some(&template), "k.cubin");
    let words = listing(&cubin);
    let _ = std::fs::remove_dir_all(&dir);
    (words, log)
}

/// An ELF64 with one more section: its bytes, a name table that holds its name and a section header table that
/// holds its header, all three appended -- no other offset of the file moves.
fn with_section(elf: &[u8], name: &str, data: &[u8]) -> Vec<u8> {
    let half = |o: usize| u16::from_le_bytes(elf[o..o + 2].try_into().unwrap()) as usize;
    let wide = |b: &[u8], o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap()) as usize;
    assert_eq!(&elf[..5], b"\x7fELF\x02", "an ELF64");
    let (shoff, shentsize, shnum, shstrndx) = (wide(elf, 0x28), half(0x3a), half(0x3c), half(0x3e));
    assert_eq!(shentsize, 64);
    let mut heads: Vec<Vec<u8>> = (0..shnum).map(|i| elf[shoff + i * 64..shoff + (i + 1) * 64].to_vec()).collect();
    let (names_off, names_len) = (wide(&heads[shstrndx], 0x18), wide(&heads[shstrndx], 0x20));
    let mut names = elf[names_off..names_off + names_len].to_vec();
    names.extend_from_slice(name.as_bytes());
    names.push(0);
    let mut out = elf.to_vec();
    let pad = |b: &mut Vec<u8>| b.resize(b.len().div_ceil(16) * 16, 0);
    pad(&mut out);
    let names_at = out.len();
    out.extend_from_slice(&names);
    pad(&mut out);
    let data_at = out.len();
    out.extend_from_slice(data);
    pad(&mut out);
    heads[shstrndx][0x18..0x20].copy_from_slice(&(names_at as u64).to_le_bytes());
    heads[shstrndx][0x20..0x28].copy_from_slice(&(names.len() as u64).to_le_bytes());
    let mut head = Vec::with_capacity(64);
    head.extend_from_slice(&(names_len as u32).to_le_bytes()); // the name
    head.extend_from_slice(&1u32.to_le_bytes()); // PROGBITS
    head.extend_from_slice(&2u64.to_le_bytes()); // ALLOC
    head.extend_from_slice(&0u64.to_le_bytes());
    head.extend_from_slice(&(data_at as u64).to_le_bytes());
    head.extend_from_slice(&(data.len() as u64).to_le_bytes());
    head.extend_from_slice(&[0u8; 8]); // link, info
    head.extend_from_slice(&4u64.to_le_bytes()); // alignment
    head.extend_from_slice(&0u64.to_le_bytes());
    let table_at = out.len();
    for h in &heads {
        out.extend_from_slice(h);
    }
    out.extend_from_slice(&head);
    out[0x28..0x30].copy_from_slice(&(table_at as u64).to_le_bytes());
    out[0x3c..0x3e].copy_from_slice(&((shnum + 1) as u16).to_le_bytes());
    out
}

/// The entries of a jump table as the constant section holds them.
fn entries(addresses: &[u32]) -> Vec<u8> {
    addresses.iter().flat_map(|a| a.to_le_bytes()).collect()
}

fn word<'a>(k: &'a [Word], starts: &str) -> &'a Word {
    k.iter().find(|w| w.text.starts_with(starts)).unwrap_or_else(|| panic!("no word `{starts}` in {k:#?}"))
}

/// The rule's count line of a build's log.
fn count_line(log: &str) -> &str {
    log.lines().find(|l| l.contains("wait rule")).unwrap_or_else(|| panic!("no count line of the rule in:\n{log}"))
}

/// Six hand-scheduled loads, one a scoreboard, read by the sum at the end of the kernel (11 words).
const PINS: &str = "    S2R R2, SR_TID.X ;
    SHF.L.U32 R60, R2, 0x2, RZ ;
    SHF.L.U32 R61, R2, 0x3, RZ ;
    SHF.L.U32 R62, R2, 0x4, RZ ;
    SHF.L.U32 R63, R2, 0x5, RZ ;
    [B------:R-:W0:-:S02] LDS R40, [R60+0x1000] ;
    [B------:R-:W1:-:S02] LDS R41, [R60+0x1100] ;
    [B------:R-:W2:-:S02] LDS R42, [R60+0x1200] ;
    [B------:R-:W3:-:S02] LDS R43, [R60+0x1300] ;
    [B------:R-:W4:-:S02] LDS R44, [R60+0x1400] ;
    [B------:R-:W5:-:S02] LDS R45, [R60+0x1500] ;
";
const SUM: &str = "    IADD3 R50, PT, PT, R40, R41, RZ ;
    IADD3 R50, PT, PT, R50, R42, RZ ;
    IADD3 R50, PT, PT, R50, R43, RZ ;
    IADD3 R50, PT, PT, R50, R44, RZ ;
    IADD3 R50, PT, PT, R50, R45, RZ ;
    EXIT ;
";
/// The first word of the loop's head: it reads a result that was armed in front of the loop and that the reader
/// of a younger load has drained since -- a wait the rule takes off.
const HEAD_READ: &str = "IADD3 R7, PT, PT, R14, R7, RZ";
/// The word behind it: it rewrites the address register of the arrive at the loop's end.
const REWRITE: &str = "SHF.L.U32 R10, R2, 0x3, RZ";

/// A loop whose last words are a `SYNCS.ARRIVE` and the backward branch. `arrive` = the arrive, with or without
/// a control word of the author; `behind` = the words behind the loop.
fn arrive_loop(arrive: &str, behind: &str) -> String {
    format!(
        "{PINS}    MOV R9, RZ ;\n    MOV R6, RZ ;\n    MOV R7, RZ ;\n    S2R R14, SR_CgaCtaId ;\n    LDS R5, [R62+0x400] ;\n    IADD3 R6, PT, PT, R5, R6, RZ ;\nL_top:\n    {HEAD_READ} ;\n    {REWRITE} ;\n    IADD3 R9, PT, PT, R9, 0x1, RZ ;\n    ISETP.NE.AND P0, PT, R9, 0x8, PT ;\n    {arrive} ;\n    @P0 BRA L_top ;\n{behind}{SUM}"
    )
}

/// The pair as `CUBIT_LOAD_COVER`'s sharing leaves it: a load rewrites the arrive's address register behind the
/// branch and waits its read barrier; on the path through the branch the head's first word waits that scoreboard
/// already -- for a use of its own.
fn pair_by_the_sharing() -> String {
    arrive_loop("SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R10+URZ], RZ", "    LDS R10, [R61+0x500] ;\n    IADD3 R6, PT, PT, R6, R10, RZ ;\n")
}

/// The same pair with the arrive's read barrier written by the author: the allocator has no use for it, and the
/// wait in front of the rewrite is a wait it wrote for the head's own read. No clause shares anything here.
fn pair_without_a_use() -> String {
    arrive_loop("[B------:R0:W-:-:S04] SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R10+URZ], RZ", "    IADD3 R6, PT, PT, R6, R10, RZ ;\n")
}

// ---- the fields: the sharing tells the rule ----

#[test]
fn the_sharing_of_the_load_cover_tells_the_rule_and_the_wait_of_the_head_stays() {
    let text = pair_by_the_sharing();
    // the sharing: the arrive's read barrier shares scoreboard 0, the head's first word waits it for its own
    // use, the word that rewrites the arrive's register carries no wait
    let (plain, log) = build(&text, &[SYNC, POLICY, COVER, HAZ]);
    assert_eq!(word(&plain, HEAD_READ).wait, vec![0], "{plain:#?}");
    assert!(word(&plain, REWRITE).wait.is_empty(), "{plain:#?}");
    assert!(word(&plain, "LDS R10,").wait.contains(&0), "the overwriter behind the branch waits the read barrier: {plain:#?}");
    assert!(!log.contains("HAZ WAR"), "the allocator's schedule names no rewrite:\n{log}");
    // under the rule the head's wait stays: it is the wait of the arrive's read barrier too
    let (k, log) = build(&text, &[SYNC, POLICY, COVER, PATHS, HAZ, USES]);
    assert_eq!(word(&k, HEAD_READ).wait, vec![0], "the wait in front of the rewrite: {}", count_line(&log));
    assert!(!log.contains("HAZ WAR"), "no rewrite of an operand in flight:\n{log}");
    assert!(log.lines().any(|l| l.starts_with("SHARED b=0 rb")), "the allocator tells the rule of the shared wait:\n{log}");
    // ... by the hand-over alone: the guard on the fields had nothing to put back
    assert!(!count_line(&log).contains("rewrite of an operand in flight"), "{}", count_line(&log));
}

// ---- the fields: the guard, closed by the path audit ----

/// The words with the fields as written; no word is a hand-scheduled one (the rule leaves those alone).
fn kernel(body: &str) -> Vec<Instruction> {
    let src = format!(".entry t\n    .param u64 io\n{body}.endentry\n");
    let mut k = cubit::sass_file::parse_sass_file_str_strict(&src).unwrap().kernels[0].instructions.clone();
    for x in k.iter_mut() {
        x.hand_sched = false;
    }
    k
}

/// The lines of the path audit's write-after-read half: a rewrite of a late operand with no wait of its read
/// barrier on a path.
fn war_lines(k: &[Instruction]) -> Vec<String> {
    cubit::scheduling_pass::report_war_on_paths(k).found.iter().map(|h| h.msg.clone()).collect()
}

/// The head of a loop as the sharing leaves it, with its fields: the arrive's read barrier is waited behind the
/// backward branch by its own use, and on the path through the branch by the first word of the head.
const ARRIVE_HEAD: &str = "    [B------:R-:W0:-:S02] S2R R14, SR_CgaCtaId ;
    [B0-----:R-:W-:-:S01] MOV R15, R14 ;
L_top:
    [B0-----:R-:W-:-:S01] MOV R16, R14 ;
    [B------:R-:W-:-:S01] SHF.L.U32 R10, R2, 0x3, RZ ;
    [B------:R0:W-:-:S04] SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R10+URZ], RZ ;
    [B------:R-:W-:-:S05] @P0 BRA L_top ;
    [B0-----:R-:W-:-:S01] MOV R10, RZ ;
    [B------:R-:W-:-:S05] EXIT ;
";

fn sync_classes() {
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("CUBIT_SYNC_CLASSES", "1")
    };
}

#[test]
fn a_wait_that_releases_a_read_barrier_in_front_of_the_rewriter_of_its_source_stays() {
    sync_classes();
    let mut k = kernel(ARRIVE_HEAD);
    assert!(war_lines(&k).is_empty(), "the fields as emitted name no rewrite: {:?}", war_lines(&k));
    let c = Cfg::build(&k);
    // the written waits WITHOUT the hand-over of the sharing: the head's wait (word 2) is written for the result
    // of word 0 alone
    let written = vec![
        Written { word: 1, sb: 0, setters: vec![0] },
        Written { word: 2, sb: 0, setters: vec![0] },
        Written { word: 6, sb: 0, setters: vec![4] },
    ];
    let out = apply(&mut k, &c, &written, Drained::Paths);
    let lines = war_lines(&k);
    assert!(lines.is_empty(), "the rule took off {:?} and the audit names {lines:?}", out.off);
    assert_eq!(k[2].ctrl.wait_mask & 1, 1, "the head's wait of scoreboard 0 stands");
}

#[test]
fn told_of_the_read_barrier_the_rule_keeps_the_wait_of_the_head() {
    sync_classes();
    let mut k = kernel(ARRIVE_HEAD);
    let c = Cfg::build(&k);
    // the hand-over the sharing owes: the head's wait is written for the arrive's read barrier too
    let written = vec![
        Written { word: 1, sb: 0, setters: vec![0] },
        Written { word: 2, sb: 0, setters: vec![0] },
        Written { word: 2, sb: 0, setters: vec![4] },
        Written { word: 6, sb: 0, setters: vec![4] },
    ];
    let out = apply(&mut k, &c, &written, Drained::Paths);
    assert!(!out.off.iter().any(|&(w, sb, _)| (w, sb) == (2, 0)), "{:?}", out.off);
    assert!(war_lines(&k).is_empty(), "{:?}", war_lines(&k));
}

#[test]
fn the_guard_on_the_fields_holds_a_wait_that_no_use_names() {
    let text = pair_without_a_use();
    let (plain, log) = build(&text, &[SYNC, POLICY, HAZ]);
    assert_eq!(word(&plain, HEAD_READ).wait, vec![0], "{plain:#?}");
    assert!(!log.contains("HAZ WAR"), "the allocator's schedule names no rewrite:\n{log}");
    let (k, log) = build(&text, &[SYNC, POLICY, PATHS, HAZ]);
    assert_eq!(word(&k, HEAD_READ).wait, vec![0], "the wait in front of the rewrite: {}", count_line(&log));
    assert!(!log.contains("HAZ WAR"), "no rewrite of an operand in flight:\n{log}");
    assert!(count_line(&log).contains("1 kept in front of a rewrite of an operand in flight"), "the guard's count: {}", count_line(&log));
}

// ---- the jump tables ----

/// The reader behind the label: on the flow graph it stands behind the wait of the first case block; an entry
/// of the table that names its word is a path on which nothing has waited.
const READ_R4: &str = "IADD3 R7, PT, PT, R4, R7, RZ";
/// The address of the word behind the dispatch (its first case block) and of the word the branch names.
const CASE: u32 = 0x150;
const NAMED: u32 = 0x170;

/// Two loads on scoreboard 0, a dispatch of the form the vendor's compiler writes (the clamp, the scale, the
/// load of the entry -- the author's, on scoreboard 1 --, the branch), a case block that reads the younger load
/// and branches to a label, and behind the label the reader of the older load.
fn dispatch() -> String {
    format!(
        "{PINS}    MOV R6, RZ ;\n    MOV R7, RZ ;\n    LDS R4, [R61+0x300] ;\n    LDS R5, [R62+0x400] ;\n    MOV R20, R2 ;\n    VIMNMX.U32 R20, R20, 0x1, PT ;\n    IMAD.SHL.U32 R21, R20, 0x4, RZ ;\n    [B------:R-:W1:-:S02] LDC R22, c[0x2][R21] ;\n    [B-1----:R-:W-:-:S01] SHF.R.S32.HI R23, RZ, 0x1f, R22 ;\n    BRX R22 -{CASE:#x} ;\n    IADD3 R6, PT, PT, R5, R6, RZ ;\n    BRA L_x ;\nL_x:\n    {READ_R4} ;\n{SUM}"
    )
}

#[test]
fn a_table_entry_that_names_a_word_a_branch_names_is_a_path_and_the_wait_behind_it_stays() {
    let text = dispatch();
    // the allocator: the reader behind the label is the first reader of the older load
    let (plain, _) = build(&text, &[SYNC, POLICY]);
    assert_eq!(word(&plain, READ_R4).wait, vec![0], "{plain:#?}");
    assert_eq!(word(&plain, "IADD3 R6, PT, PT, R5,").wait, vec![0], "{plain:#?}");
    // the table's second entry names the label: the dispatch reaches the reader with nothing waited
    let (k, log) = build_on_template(&text, &[SYNC, POLICY, PATHS], Some(&entries(&[CASE, NAMED])));
    assert_eq!(word(&k, READ_R4).wait, vec![0], "the wait behind the entry: {}", count_line(&log));
    assert!(count_line(&log).contains("kept for a jump table"), "{}", count_line(&log));
    // the control -- the table is read: where both entries name the word behind the dispatch, every path to
    // the reader holds the wait of the case block, and the reader's own goes
    let (k, log) = build_on_template(&text, &[SYNC, POLICY, PATHS], Some(&entries(&[CASE, CASE])));
    assert!(word(&k, READ_R4).wait.is_empty(), "{}", count_line(&log));
    assert_eq!(word(&k, "IADD3 R6, PT, PT, R5,").wait, vec![0], "{k:#?}");
}

#[test]
fn a_dispatch_whose_table_cannot_be_read_keeps_the_waits_of_what_crosses_it() {
    let text = dispatch();
    let env = [SYNC, POLICY, PATHS];
    // no template
    let (k, log) = build(&text, &env);
    assert_eq!(word(&k, READ_R4).wait, vec![0], "without a template: {}", count_line(&log));
    assert!(count_line(&log).contains("kept for a jump table"), "{}", count_line(&log));
    // a template without the constant section; a table shorter than its clamp says; an entry that is no word of
    // the kernel (inside a word, behind the kernel's end)
    let tables: [(&str, Option<Vec<u8>>); 4] = [
        ("no constant section", None),
        ("one entry of two", Some(entries(&[CASE]))),
        ("an entry inside a word", Some(entries(&[CASE, NAMED + 4]))),
        ("an entry behind the kernel", Some(entries(&[CASE, 0x4000]))),
    ];
    for (what, table) in tables {
        let (k, log) = build_on_template(&text, &env, table.as_deref());
        assert_eq!(word(&k, READ_R4).wait, vec![0], "{what}: {}", count_line(&log));
    }
}
