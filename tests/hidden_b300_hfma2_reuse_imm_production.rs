//! Production HFMA2 two-immediate Rb.reuse repair; CPU evidence, no GPU claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-hfma2-reuse-imm-production-2026-11-11";
const KEY: &str = "HFMA2_R_R_R_FI_FI";

fn arches() -> [(&'static str, &'static str); 2] {
    [
        ("sm103a", hb300_fixture("sm103a_hfma2_reuse_imm_production_nvdisasm.jsonl")),
        ("sm100a", hb300_fixture("sm100a_hfma2_reuse_imm_production_nvdisasm.jsonl")),
    ]
}

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLES: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLES.get_or_init(|| arches().iter().map(|(arch, _)| {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    }).collect())
}

fn rows(fixture: &str) -> impl Iterator<Item = Value> + '_ {
    fixture.lines().map(|line| serde_json::from_str(line).unwrap())
}

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn roundtrip(table: &IsaTable, index: &DecodeIndex, arch: &str, row: &Value) {
    let word = hex(&row["word"]);
    let expected = row["nvidia_sass"].as_str().unwrap();
    let decoded = index.decode(word, 0, table)
        .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
    assert_eq!(decoded.key, KEY, "{arch} {word:032x}");
    let group = if expected.starts_with("HFMA2.BF16_V2 ") { "BF16_V2" } else { "" };
    assert_eq!(decoded.mod_group, group, "{arch} {word:032x}");
    assert_eq!(cubit::printer::to_sass_lossless(&decoded), expected, "{arch} {word:032x}");
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {expected} ;"), 0).unwrap();
    let encoded = cubit::encoder::encode_instruction(&parsed, table)
        .unwrap_or_else(|error| panic!("{arch}: {word:032x} {expected}: {error}"));
    assert_eq!(encoded & ((1u128 << 96) - 1), word & ((1u128 << 96) - 1),
        "{arch}: opcode/immediate/operand bits differ {word:032x}");
    assert_eq!(encoded & (1u128 << 123), word & (1u128 << 123),
        "{arch}: Rb.reuse@123 lost {word:032x}");
}

#[test]
fn production_and_all_measured_register_reuse_domains_roundtrip() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let mut production = [0, 0];
        let mut adopted = 0;
        for row in rows(fixture) {
            if row["role"] != "adopt" { continue; }
            adopted += 1;
            if row["generation"] == "production" {
                let group = usize::from(row["nvidia_sass"].as_str().unwrap().starts_with("HFMA2 "));
                production[group] += 1;
                roundtrip(table, index, arch, &row);
            } else if ["base", "production_clear", "field"].contains(&row["generation"].as_str().unwrap()) {
                roundtrip(table, index, arch, &row);
            }
        }
        assert_eq!(production, [73, 26], "{arch}: BF16/plain production counts");
        assert_eq!(adopted, 3254, "{arch}: complete selected matrix");
    }
}

#[test]
fn exactly_two_repairs_and_only_token_three_reuse_fields() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 2);
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["scheduling"]["pipe_name"], "UNKNOWN");
        for group in entry["mod_groups"].as_object().unwrap() {
            let old_reuse_last = group.1["fields"].as_array().unwrap().iter()
                .filter(|field| field["extraction"] == "reuse").count();
            if ["", "BF16_V2"].contains(&group.0.as_str()) {
                assert_eq!(group.1["_src"], SOURCE, "{arch}: {}", group.0);
                assert_eq!(group.1["count"], Value::Null);
                assert_eq!(old_reuse_last, 1, "{arch}: {}", group.0);
                let field = group.1["fields"].as_array().unwrap().iter()
                    .find(|field| field["extraction"] == "reuse").unwrap();
                assert_eq!((field["shift"].as_u64(), field["bits"].as_u64(), field["token_idx"].as_u64()), (Some(123), Some(1), Some(3)));
                assert_eq!(hex(&group.1["variable_mask"]) & (1u128 << 123), 1u128 << 123);
                assert_eq!(hex(&group.1["and_base"]) & (1u128 << 123), 0);
            } else {
                assert_eq!(old_reuse_last, 0, "{arch}: unlicensed sibling {}", group.0);
            }
        }
        assert!(entry["mod_groups"]["FMZ"]["_src"] != SOURCE);
        assert!(entry["mod_groups"]["F32"]["_src"] != SOURCE);
        assert!(entry["mod_groups"]["BF16_V2,RELU"]["_src"] != SOURCE);
    }
}

#[test]
fn every_plain_bf16_production_has_a_measured_reuse_ab_pair() {
    let mut donors = std::collections::HashMap::new();
    for (_arch, fixture) in arches() {
        if !_arch.starts_with("sm103") { continue; }
        for row in rows(fixture) {
            if !["production", "production_clear"].contains(&row["generation"].as_str().unwrap()) { continue; }
            let word = hex(&row["word"]);
            assert!(donors.insert(word, row).is_none());
        }
    }
    let productions: Vec<u128> = donors.keys().copied()
        .filter(|word| (word >> 123) & 1 == 1).collect();
    assert_eq!(productions.len(), 99);
    for word in productions {
        let text = donors[&word]["nvidia_sass"].as_str().unwrap();
        assert!(text.contains(".reuse.H"), "{text}");
        let cleared = donors[&(word & !(1u128 << 123))]["nvidia_sass"].as_str().unwrap();
        assert_eq!(cleared, text.replacen(".reuse.H", ".H", 1), "{text}");
    }
}
