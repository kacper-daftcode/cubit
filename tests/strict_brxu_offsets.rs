//! SM120 BRXU's signed q56 encoding and the legacy absolute-address shorthand.
//! Complete words/text are independently checked by NVIDIA nvdisasm; the
//! acceptance path receives only ordinary editable source and explicit CC.

use cubit::roundtrip_audit::{audit_kernel, encode_semantic_source};
use cubit::IsaTable;
use serde_json::Value;
use std::sync::OnceLock;

const CC: &str = "[B------:R-:W-:Y:S01]";

fn table() -> &'static IsaTable {
    static TABLE: OnceLock<IsaTable> = OnceLock::new();
    TABLE.get_or_init(|| IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap())
}

fn source(line: &str) -> String {
    format!(".entry brxu\n{CC} {line} ;\n.endentry\n")
}

#[test]
fn native_q56_offsets_match_nvidia_complete_words_and_editable_source() {
    let table = table();
    let index = table.decode_index();
    let mut checked = 0;
    for line in include_str!("fixtures/sm120_brxu_native_nvdisasm.jsonl").lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        let sass = row["sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
        let bytes = encode_semantic_source(&source(sass), table).unwrap();
        assert_eq!(bytes, word.to_le_bytes(), "{sass}");
        let decoded = index.decode(word, 0, table).unwrap();
        assert_eq!(cubit::printer::to_sass_lossless(&decoded), sass);
        let mut failures = Vec::new();
        let (report, emitted) = audit_kernel(
            ".text.brxu", 0, &bytes, table, &index,
            &mut |failure| { failures.push(failure.clone()); Ok(()) },
        ).unwrap();
        assert!(report.passed && report.stream_verified, "{sass}: {failures:?}");
        assert!(!emitted.contains("!rsd[") && !emitted.contains("__raw__"));
        assert_eq!(encode_semantic_source(&emitted, table).unwrap(), bytes);
        checked += 1;
    }
    assert_eq!(checked, 8);
}

#[test]
fn absolute_lowering_preserves_guard_controls_and_resolved_labels() {
    let table = table();
    for guard in ["", "@P0 ", "@!P3 "] {
        let absolute = source(&format!("{guard}BRXU 0x5030"));
        let explicit = source(&format!("{guard}BRXU URZ, 0x5020"));
        assert_eq!(encode_semantic_source(&absolute, table).unwrap(),
                   encode_semantic_source(&explicit, table).unwrap());
    }
    // The absolute label names instruction 0x30. BRXU at 0x10 therefore
    // lowers to URZ + 0x10. Labels are resolved before the same lowering.
    let labeled = format!(".entry brxu\n{CC} NOP ;\n{CC} @P2 BRXU target ;\n{CC} NOP ;\ntarget:\n{CC} NOP ;\n.endentry\n");
    let explicit = labeled.replace("BRXU target", "BRXU URZ, 0x10");
    assert_eq!(encode_semantic_source(&labeled, table).unwrap(),
               encode_semantic_source(&explicit, table).unwrap());
}

#[test]
fn absolute_targets_refuse_negative_misaligned_and_unrepresentable_addresses() {
    let table = table();
    for (sass, diagnostic) in [
        ("BRXU -0x4", "nonnegative code address"),
        ("BRXU 0x11", "multiple of 4"),
        ("BRXU 0x200000000000010", "signed 58-bit"),
        // The signed source literal parser represents this bit pattern as -1.
        ("BRXU 0xffffffffffffffff", "nonnegative code address"),
        ("BRXU missing_label", "unresolved branch label"),
    ] {
        let error = encode_semantic_source(&source(sass), table).unwrap_err().to_string();
        assert!(error.contains(diagnostic), "{sass}: {error}");
    }
}

#[test]
fn native_offsets_refuse_discarded_low_bits_and_signed58_overflow() {
    let table = table();
    for (sass, diagnostic) in [
        ("BRXU UR4, 0x1", "multiple of 4"),
        ("BRXU UR4, -0x2", "multiple of 4"),
        ("BRXU UR4, 0x200000000000000", "signed 58-bit"),
        ("BRXU UR4, -0x200000000000004", "signed 58-bit"),
        ("BRXU UR4, 0xffffffffffffffff", "multiple of 4"),
    ] {
        let error = encode_semantic_source(&source(sass), table).unwrap_err().to_string();
        assert!(error.contains(diagnostic), "{sass}: {error}");
    }
    // Also exercise an explicitly unsigned IR value rather than relying on
    // the source parser's signed interpretation of the same literal.
    let mut native = cubit::parse_cuasm_line(&format!("{CC} BRXU UR4, 0x0 ;"), 0).unwrap();
    native.operands[1] = cubit::ir::Operand::Imm64(u64::MAX);
    assert!(cubit::encoder::encode_instruction(&native, table).is_err());
}

#[test]
fn strict_absolute_shorthand_rejects_wrong_bank_and_legacy_residue() {
    let table = table();
    for sass in ["@UP0 BRXU 0x5030", "@!UP3 BRXU 0x5030"] {
        let error = encode_semantic_source(&source(sass), table).unwrap_err().to_string();
        assert!(error.contains("predicate bank mismatch"), "{error}");
    }
    for sass in ["BRXU 0x5030 !rsd[18:1]", "BRXU URZ, 0x5020 !rsd[18:1]"] {
        assert!(encode_semantic_source(&source(sass), table).is_err(), "{sass}");
    }
}
