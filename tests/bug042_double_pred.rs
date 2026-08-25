//! BUG-042 (rejestr sm120: 042_double_pred_silent_drop.md, CONFIRMED i119):
//! an instruction with TWO predicates (`@P2 @P5 MOV T2, 0xF`) was SILENTLY
//! DROPPED from the code stream: RE_INS never matched the second `@`, the lenient
//! parse_multi_sass simply skipped the segment, and the asm counter reported
//! the parsed remainder as "N/N encoded (0 failed)" — the cubin looked
//! correct while silicon received a program missing an instruction (in hopb: the DP
//! index clamp vanished -> stores into slots 16..19 instead of 15).
//! Fix (fail-closed, at the source):
//!  - parse_sass rejects a multi-predicate with an explicit message,
//!  - cmd_asm (the .entry path) parses strict (any unparseable segment
//!    is an error, not a skip),
//!  - lib `cubit::assemble` likewise strict.
//! SASS has a single guard field — emitting a predicate composition correctly
//! means a PLOP3 on the author's side, not the assembler's.

use cubit::parser::parse_sass;
use cubit::sass_file::parse_sass_file_str_strict;
use cubit::table::IsaTable;
use std::process::Command;

/// Faithful condensation of repro r042 (internal repro archive).
const SASS_DOUBLE_PRED: &str = ".entry t\n    .param u64 m\n    ISETP.EQ.AND P2, PT, R1, RZ, PT ;\n    ISETP.GT.AND P5, PT, R2, RZ, PT ;\n    @P2 @P5 MOV R28, 0xF ;\n    @P2 MOV R29, 0x9 ;\n    EXIT ;\n.endentry\n";
const SASS_SINGLE_PRED: &str = ".entry t\n    .param u64 m\n    ISETP.EQ.AND P2, PT, R1, RZ, PT ;\n    @P2 MOV R28, 0xF ;\n    @P2 MOV R29, 0x9 ;\n    EXIT ;\n.endentry\n";

#[test]
fn bug042_parse_rejects_double_predicate_with_clear_message() {
    for line in [
        "@P2 @P5 MOV R28, 0xF",
        "@!P2 @P5 MOV R28, 0xF",
        "@UP2 @P5 MOV R28, 0xF",
        "@P2 @!UP5 MOV R28, 0xF",
    ] {
        let err = parse_sass(line, 0x20).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("multiple guard predicates"),
            "expected clear multi-predicate error for {line:?}, got: {msg}"
        );
    }
}

#[test]
fn bug042_single_predicate_unchanged() {
    for line in [
        "@P2 MOV R28, 0xF",
        "@!P2 MOV R28, 0xF",
        "@UP2 MOV R28, 0xF",
        "MOV R28, 0xF",
    ] {
        let ins = parse_sass(line, 0x20).unwrap();
        assert_eq!(ins.opcode, "MOV");
    }
}

#[test]
fn bug042_entry_asm_fails_closed_and_writes_nothing() {
    let dir = std::env::temp_dir().join(format!("bug042_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("r042.sass");
    let out = dir.join("r042.cubin");
    let _ = std::fs::remove_file(&out);
    std::fs::write(&src, SASS_DOUBLE_PRED).unwrap();
    let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args([
            "asm",
            "-t",
            "tables/sm120.json",
            src.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!res.status.success(), "asm must fail on double-predicate input");
    assert!(
        !out.exists(),
        "fail-closed: no output cubin may be written (BUG-043 trap class)"
    );
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(
        stderr.contains("multiple guard predicates"),
        "stderr should name the cause, got: {stderr}"
    );
}

#[test]
fn bug042_single_pred_control_builds_all_slots() {
    let dir = std::env::temp_dir().join(format!("bug042_neg_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("r042_neg.sass");
    let out = dir.join("r042_neg.cubin");
    let _ = std::fs::remove_file(&out);
    std::fs::write(&src, SASS_SINGLE_PRED).unwrap();
    let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args([
            "asm",
            "-t",
            "tables/sm120.json",
            src.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        res.status.success(),
        "control input must assemble: {}",
        String::from_utf8_lossy(&res.stderr)
    );
    let stdout = String::from_utf8_lossy(&res.stdout);
    // Counter must equal the source instruction count (4 in SASS_SINGLE_PRED):
    // the desync class from BUG-042 is closed by strict parsing.
    assert!(
        stdout.contains("4/4 encoded") || stdout.contains("Total:   4 encoded"),
        "unexpected summary: {stdout}"
    );
}

#[test]
fn bug042_lib_assemble_is_also_fail_closed() {
    let table = IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap();
    let err = cubit::assemble("@P2 @P5 MOV R28, 0xF ;", 0, &table).unwrap_err();
    assert!(format!("{err:#}").contains("multiple guard predicates"));
}

#[test]
fn bug042_strict_file_parser_names_the_segment() {
    let err = parse_sass_file_str_strict(SASS_DOUBLE_PRED).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("@P2 @P5 MOV R28, 0xF"), "got: {msg}");
}
