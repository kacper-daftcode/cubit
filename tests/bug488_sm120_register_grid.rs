//! BUG-488 (2026-11-11): on sm_120 an operand that spans several registers starts on its own grid
//! -- a pair on an even register, a quad on a multiple of four -- and `cubit asm` refuses the
//! KERNEL that has one off it, instead of writing a file that faults at its first launch.
//!
//! Two kernels of probe generators trapped a card in one evening (2026-11-10) with texts the
//! assembler had taken without a word: a 64-bit pair of `IADD.64` on an odd register. The grid
//! itself was measured the same day (`tools/ra/gen_align_probes.py`,
//! `tools/ra/align_probes_sm120_20261110.json`: 38 kernels, one process each): **23 of 23
//! off-grid kernels end in CUDA_ERROR_ILLEGAL_INSTRUCTION 715, 15 of 15 on-grid controls store
//! the expected words** -- and only the two wide-`IMAD` shapes were refused (BUG-008). The
//! vendor's assembler emits none (0 of 407 551 multi-register operands of the sm_120 census).
//!
//! Pinned here against that result file: `cubit asm` refuses a kernel around every instruction
//! that faulted on silicon and writes one around every control; `IADD.64`; `RZ` and the narrow
//! forms are not touched; `CUBIT_ALLOW_OFF_GRID=1` (the escape of a probe generator) and
//! `CUBIT_DISABLE_ERRATA=1` write the kernel; the other architectures keep their own laws; and
//! the word-level encoder is NOT guarded -- it stays the inverse of the decoder for every
//! register number a field can hold (the measured table rows are re-assembled that way).

use cubit::encoder::{check_register_grid_sm120, encode_instruction};
use cubit::parser::parse_sass;
use cubit::table::IsaTable;
use serde_json::Value;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static SCRATCH: AtomicUsize = AtomicUsize::new(0);

fn table_path(arch: &str) -> String {
    format!("{}/tables/{arch}.json.gz", env!("CARGO_MANIFEST_DIR"))
}

fn table(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&table_path(arch))).unwrap()
}

fn t120() -> &'static IsaTable {
    static TABLE: std::sync::OnceLock<IsaTable> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| table("sm120"))
}

/// The guard on one instruction, as `cubit asm` asks it.
fn guard(text: &str, t: &IsaTable) -> anyhow::Result<()> {
    let insn = parse_sass(&format!("{text} ;"), 0).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    check_register_grid_sm120(&insn, t)
}

fn refused(text: &str) -> String {
    match guard(text, t120()) {
        Ok(()) => panic!("`{text}` passes the guard: it faults on silicon"),
        Err(e) => e.to_string(),
    }
}

/// `cubit asm` of a one-instruction kernel (hand-scheduled, so nothing but the assembler runs):
/// (a cubin was written, the command's output).
fn asm(insn: &str, arch: &str, env: &[(&str, &str)]) -> (bool, String) {
    let dir = std::env::temp_dir().join(format!("bug488_{}_{}", std::process::id(), SCRATCH.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("k.sass");
    std::fs::write(
        &src,
        format!(
            ".entry k\n    .reg R0-R31\n    .regcount 40\n    .param u64 p0 offset=0x0\n    [B------:R-:W-:-:S01] {insn} ;\n    [B------:R-:W-:Y:S05] EXIT ;\n.endentry\n"
        ),
    )
    .unwrap();
    let out = dir.join("k.cubin");
    let o = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", src.to_str().unwrap(), "-t", &table_path(arch), "-o", out.to_str().unwrap()])
        .env_clear()
        .envs(env.iter().copied())
        .output()
        .expect("run cubit");
    let log = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    let written = o.status.success() && out.exists();
    assert_eq!(o.status.success(), out.exists(), "a refused kernel leaves no file: {log}");
    let _ = std::fs::remove_dir_all(&dir);
    (written, log)
}

/// The instruction of a probe shape on base register `b` -- the one `tools/ra/gen_align_probes.py`
/// builds its kernel around.
fn shaped(shape: &str, b: u64) -> String {
    match shape {
        "ldg128_dst" => format!("LDG.E.128 R{b}, desc[UR4][R4.64]"),
        "sts128_data" => format!("STS.128 [R1], R{b}"),
        "lds128_dst" => format!("LDS.128 R{b}, [R1]"),
        "ldg64_dst" => format!("LDG.E.64 R{b}, desc[UR4][R4.64]"),
        "sts64_data" => format!("STS.64 [R1], R{b}"),
        "lds64_dst" => format!("LDS.64 R{b}, [R1]"),
        "ldc64_dst" => format!("LDC.64 R{b}, c[0x0][0x388]"),
        "ldg_addr" => format!("LDG.E R12, desc[UR4][R{b}.64]"),
        "stg_addr" => format!("STG.E desc[UR4][R{b}.64], R12"),
        "imadw_c" => format!("IMAD.WIDE.U32 R12, PT, R0, 0x10000, R{b}"),
        "imadw_d" => format!("IMAD.WIDE.U32 R{b}, PT, R0, 0x10000, R8"),
        "cs2r" => format!("CS2R R{b}, SRZ"),
        "ldsm2" => format!("LDSM.16.MT88.2 R{b}, [R1]"),
        "ldsm4" => format!("LDSM.16.M88.4 R{b}, [R1]"),
        "ldcu64_desc" => format!("LDCU.64 UR{b}, c[0x0][0x358]"),
        other => panic!("a probe shape this test does not know: {other}"),
    }
}

#[test]
fn a_kernel_around_every_word_that_faulted_on_silicon_is_refused_and_every_control_is_written() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tools/ra/align_probes_sm120_20261110.json")).unwrap();
    let probes: serde_json::Map<String, Value> = serde_json::from_str(&text).unwrap();
    let (mut faulted, mut controls) = (0, 0);
    let mut shapes = std::collections::BTreeSet::new();
    for (name, p) in &probes {
        let shape = p["shape"].as_str().unwrap();
        let insn = shaped(shape, p["base"].as_u64().unwrap());
        shapes.insert(shape.to_string());
        let on_grid = p["on_grid"].as_bool().unwrap();
        let verdict = p["verdict"].as_str().unwrap();
        // the file itself: off the grid = a fault with the driver's 715, on it = OK
        assert_eq!(on_grid, verdict.starts_with("OK"), "{name}: {verdict}");
        assert!(on_grid || verdict.contains("715"), "{name}: {verdict}");
        let (written, log) = asm(&insn, "sm120", &[]);
        if on_grid {
            assert!(written, "{name}: the control `{insn}` ran on silicon and is refused:\n{log}");
            controls += 1;
        } else {
            // the wide IMAD has its own, older guard (inside the encoder); everything else is this one
            let bug = if shape.starts_with("imadw") { "BUG-008" } else { "BUG-488" };
            assert!(!written && log.contains(bug), "{name}: `{insn}` faults on silicon; expected a refusal by {bug}:\n{log}");
            assert!(log.contains("refusing to write"), "{name}: {log}");
            faulted += 1;
        }
    }
    assert_eq!((faulted, controls, shapes.len()), (23, 15, 15), "the result file: 23 faults, 15 controls, 15 shapes");
}

#[test]
fn a_pair_of_iadd64_on_an_odd_register_is_refused() {
    // the text that trapped the card: the destination pair on R13
    let e = refused("IADD.64 R13, R6, 0x4");
    assert!(e.contains("BUG-488") && e.contains("a pair of IADD.64 on R13") && e.contains("an even register"), "{e}");
    assert!(e.contains("CUBIT_ALLOW_OFF_GRID=1"), "the message names the escape: {e}");
    let (written, log) = asm("IADD.64 R13, R6, 0x4", "sm120", &[]);
    assert!(!written && log.contains("BUG-488"), "{log}");
    // a source pair is a pair as well (the addend of a wide IMAD on an odd base faults: BUG-008)
    assert!(refused("IADD.64 R24, R7, 0x4").contains("on R7"));
    assert!(refused("IADD.64 R24, R6, R9").contains("on R9"));
    assert!(refused("IADD.64 R24, -R11, UR4").contains("on R11"));
    // on the grid: the forms the vendor's assembler emits
    for ok in ["IADD.64 R24, R6, 0x4", "IADD.64 R20, R20, R32", "IADD.64 R2, -R10, UR4"] {
        guard(ok, t120()).unwrap_or_else(|e| panic!("`{ok}`: {e}"));
        assert!(asm(ok, "sm120", &[]).0, "`{ok}`");
    }
}

#[test]
fn the_message_says_what_is_off_which_grid() {
    let e = refused("LDG.E.128 R10, desc[UR4][R4.64]");
    assert!(e.contains("the destination register R10") && e.contains("128-bit quad") && e.contains("a multiple of four"), "{e}");
    let e = refused("STS.64 [R1], R9");
    assert!(e.contains("the data register R9") && e.contains("64-bit pair") && e.contains("an even register"), "{e}");
    let e = refused("STG.E desc[UR4][R9.64], R12");
    assert!(e.contains("the address pair on R9"), "{e}");
    let e = refused("LDCU.64 UR5, c[0x0][0x358]");
    assert!(e.contains("the uniform destination pair on UR5"), "{e}");
    // a quad one register off is refused like one two or three off; an even register is not enough for a quad
    for b in [9, 10, 11, 13, 14, 15, 254] {
        assert!(refused(&format!("LDS.128 R{b}, [R1]")).contains("BUG-488"), "R{b}");
        assert!(refused(&format!("LDSM.16.M88.4 R{b}, [R1]")).contains("BUG-488"), "R{b}");
    }
    // a pair on an even register that is not a multiple of four is on its grid
    for ok in ["LDS.64 R18, [R1]", "LDG.E.64 R10, desc[UR4][R4.64]", "LDSM.16.MT88.2 R10, [R1]", "CS2R R14, SRZ", "LDC.64 R6, c[0x0][0x388]"] {
        guard(ok, t120()).unwrap_or_else(|e| panic!("`{ok}`: {e}"));
    }
}

#[test]
fn the_narrow_forms_and_the_zero_register_are_not_touched() {
    // one register: no grid
    for ok in [
        "LDG.E R9, desc[UR4][R4.64]",
        "LDS R17, [R1]",
        "STS [R1], R9",
        "LDC R9, c[0x0][0x388]",
        "CS2R.32 R9, SRZ",
        "IADD3 R13, PT, PT, R7, 0x4, RZ",
        // a quad's ADDRESS register is one register
        "STS.128 [R5], R8",
        "LDS.128 R8, [R7]",
        // RZ is not the base of a pair
        "LDS.64 RZ, [R1]",
        "STS.64 [R1], RZ",
        "STS.128 [R1], RZ",
    ] {
        guard(ok, t120()).unwrap_or_else(|e| panic!("`{ok}`: {e}"));
    }
    assert!(asm("CS2R.32 R9, SRZ", "sm120", &[]).0);
    assert!(asm("STS.128 [R5], R8", "sm120", &[]).0);
}

#[test]
fn the_escapes_write_the_kernel() {
    for insn in ["LDG.E.128 R9, desc[UR4][R4.64]", "STS.64 [R1], R9", "CS2R R9, SRZ", "IADD.64 R13, R6, 0x4", "LDCU.64 UR5, c[0x0][0x358]"] {
        let (written, log) = asm(insn, "sm120", &[]);
        assert!(!written, "`{insn}`: {log}");
        // the probe generator's escape lifts this guard; the table-research hatch lifts every guard
        for var in ["CUBIT_ALLOW_OFF_GRID", "CUBIT_DISABLE_ERRATA"] {
            let (written, log) = asm(insn, "sm120", &[(var, "1")]);
            assert!(written, "{var}=1 `{insn}`: {log}");
        }
    }
    // the escape of this guard is not the hatch of the others: the wide IMAD's odd pair stays refused under it
    let (written, log) = asm("IMAD.WIDE.U32 R12, PT, R0, 0x10000, R9", "sm120", &[("CUBIT_ALLOW_OFF_GRID", "1")]);
    assert!(!written && log.contains("BUG-008"), "{log}");
}

#[test]
fn the_word_level_encoder_is_not_guarded_and_the_other_architectures_keep_their_own_laws() {
    // a word is a word: the encoder assembles every register number the field holds and the decoder gives the
    // text back (the measured rows of the tables are re-assembled this way; `cubit encode` is table work)
    for text in ["LDC.64 R9, c[0x0][0x388]", "LDG.E.128 R17, desc[UR4][R4.64]", "CS2R R9, SRZ", "STS.64 [R1], R9"] {
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let w = encode_instruction(&insn, t120()).unwrap_or_else(|e| panic!("`{text}` is a word of the table: {e}"));
        let d = t120().decode_index().decode(w, 0, t120()).unwrap();
        assert_eq!(cubit::printer::to_sass(&d).trim_end_matches(';').trim(), text);
    }
    // sm_121a has no measurement of its own: the guard says nothing there
    let t121 = table("sm121a");
    for t in ["LDC.64 R9, c[0x0][0x388]", "CS2R R9, SRZ", "LDS.64 R17, [R1]"] {
        guard(t, &t121).unwrap_or_else(|e| panic!("sm121a `{t}`: {e}"));
    }
    // sm_103a refuses by its own, stricter law (BUG-088, inside the encoder), not by this one
    let t103 = table("sm103a");
    guard("LDC.64 R9, c[0x0][0x388]", &t103).unwrap();
    let (written, log) = asm("LDC.64 R9, c[0x0][0x388]", "sm103a", &[]);
    assert!(!written && log.contains("BUG-088") && !log.contains("BUG-488"), "{log}");
    // ... R204 is on sm_120's quad grid and off sm_103a's
    guard("STS.128 [R5], R204", t120()).unwrap();
    assert!(asm("STS.128 [R5], R204", "sm120", &[]).0);
    assert!(!asm("STS.128 [R5], R204", "sm103a", &[]).0);
}
