//! Native SM120 guard banks independently checked with NVIDIA nvdisasm.
//! The fixtures retain the newly authored source and the complete word; no
//! original-word bits are supplied to the code-only strict assembly API.

use cubit::roundtrip_audit::{audit_kernel, encode_semantic_source};
use cubit::IsaTable;
use serde_json::Value;
use std::sync::OnceLock;

fn table() -> &'static IsaTable {
    static TABLE: OnceLock<IsaTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        let path = std::env::var_os("CUBIT_TABLE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| "tables/sm120.json".into());
        IsaTable::load(&path).unwrap()
    })
}

fn fixtures() -> Vec<Value> {
    include_str!("fixtures/sm120_predicate_guard_nvdisasm.jsonl")
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn expected(row: &Value) -> u128 {
    u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap()
}

#[test]
fn native_predicate_banks_preserve_complete_words_and_editable_source() {
    let table = table();
    let index = table.decode_index();
    let rows = fixtures();
    assert_eq!(rows.len(), 40);
    let mut checked = 0;
    for row in rows.iter().filter(|row| row["bank_matches"] == true) {
        let source = row["source"].as_str().unwrap();
        let bytes = encode_semantic_source(source, table).unwrap();
        assert_eq!(bytes, expected(row).to_le_bytes(), "{source}");
        let decoded = index.decode(expected(row), 0, table).unwrap();
        let text = cubit::printer::to_sass_lossless(&decoded);
        assert_eq!(text.split_whitespace().next(), row["nvidia_guard"].as_str());
        let mut failures = Vec::new();
        let (report, emitted) = audit_kernel(
            ".text.guard_bank", 0, &bytes, table, &index,
            &mut |failure| { failures.push(failure.clone()); Ok(()) },
        ).unwrap();
        assert!(report.passed && report.stream_verified, "{source}: {failures:?}");
        assert_eq!(encode_semantic_source(&emitted, table).unwrap(), bytes);
        checked += 1;
    }
    assert_eq!(checked, 20);
}

#[test]
fn wrong_banks_fail_closed_while_legacy_encoder_aliases_stay_compatible() {
    let table = table();
    let mut checked = 0;
    for row in fixtures().iter().filter(|row| row["bank_matches"] == false) {
        let source = row["source"].as_str().unwrap();
        let error = encode_semantic_source(source, table).unwrap_err().to_string();
        assert!(error.contains("predicate bank mismatch"), "{source}: {error}");
        // The strict API owns this check. The historical general encoder's
        // accepted spelling aliases remain unchanged (including BUG-171).
        let line = source.lines().find(|line| line.starts_with('[')).unwrap();
        let parsed = cubit::parse_cuasm_line(line, 0).unwrap();
        let legacy = cubit::encoder::encode_instruction(&parsed, table).unwrap();
        assert_eq!(legacy, expected(row));
        checked += 1;
    }
    assert_eq!(checked, 20);
}

#[test]
fn true_and_false_predicate_constants_may_normalize_between_banks() {
    let table = table();
    let mut families = 0;
    for row in fixtures().iter().filter(|row| row["guard"] == "@P0") {
        let original = row["source"].as_str().unwrap();
        for (negated, guards) in [(false, ["@PT", "@UPT"]), (true, ["@!PT", "@!UPT"])] {
            let word = (expected(row) & !0xf000) | ((if negated { 15 } else { 7 }) << 12);
            for guard in guards {
                let source = original.replace("@P0", guard);
                assert_eq!(encode_semantic_source(&source, table).unwrap(), word.to_le_bytes(), "{source}");
            }
        }
        families += 1;
    }
    assert_eq!(families, 10);
}
