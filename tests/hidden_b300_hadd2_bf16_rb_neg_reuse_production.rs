//! Production HADD2.BF16_V2 Rb negation/reuse repair; CPU evidence only.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const SOURCE: &str = "rows-hadd2-bf16-rb-neg-reuse-production-2026-11-11";
const KEY: &str = "HADD2_R_R_R";

fn arches() -> [(&'static str, &'static str); 2] {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_hadd2_bf16_rb_neg_reuse_production_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_hadd2_bf16_rb_neg_reuse_production_nvdisasm.jsonl"),
        ),
    ]
}

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLES: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLES.get_or_init(|| {
        arches()
            .iter()
            .map(|(arch, _)| {
                let table =
                    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
                let index = DecodeIndex::build(&table);
                (table, index)
            })
            .collect()
    })
}

fn rows(fixture: &str) -> impl Iterator<Item = Value> + '_ {
    fixture
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
}

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn roundtrip(table: &IsaTable, index: &DecodeIndex, arch: &str, row: &Value) {
    let word = hex(&row["word"]);
    let expected = row["nvidia_sass"].as_str().unwrap();
    let decoded = index
        .decode(word, 0, table)
        .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
    assert_eq!(decoded.key, KEY, "{arch} {word:032x}");
    assert_eq!(decoded.mod_group, "BF16_V2", "{arch} {word:032x}");
    assert_eq!(
        cubit::printer::to_sass_lossless(&decoded),
        expected,
        "{arch} {word:032x}"
    );
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {expected} ;"), 0).unwrap();
    let encoded = cubit::encoder::encode_instruction(&parsed, table)
        .unwrap_or_else(|error| panic!("{arch}: {word:032x} {expected}: {error}"));
    assert_eq!(
        encoded & ((1u128 << 96) - 1),
        word & ((1u128 << 96) - 1),
        "{arch}: opcode/operand bits differ {word:032x}"
    );
    assert_eq!(
        encoded & (1u128 << 63),
        word & (1u128 << 63),
        "{arch}: Rb.neg@63 lost"
    );
    assert_eq!(
        encoded & (1u128 << 124),
        word & (1u128 << 124),
        "{arch}: Rb.reuse@124 lost"
    );
}

#[test]
fn production_and_measured_register_neg_reuse_domains_roundtrip() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let mut production = 0;
        let mut domains = BTreeMap::new();
        for row in rows(fixture) {
            if row["role"] != "adopt" {
                continue;
            }
            if row["generation"] == "production" {
                production += 1;
                roundtrip(table, index, arch, &row);
            } else if [
                "base",
                "production_toggle",
                "production_clear",
                "field",
                "guard",
                "cross",
            ]
            .contains(&row["generation"].as_str().unwrap())
            {
                roundtrip(table, index, arch, &row);
            }
            if ["production", "field", "base", "production_toggle", "production_clear"]
                .contains(&row["generation"].as_str().unwrap()) {
                let word = hex(&row["word"]);
                for (name, shift) in [("Rd", 16), ("Ra", 24), ("Rb", 32)] {
                    if row["generation"] == "field"
                        && row["label"].as_str().unwrap().split(':').nth(1) != Some(name)
                    {
                        continue;
                    }
                    let key = (name.to_owned(), (word >> 63) & 1, (word >> 124) & 1);
                    domains
                        .entry(key)
                        .or_insert_with(BTreeSet::new)
                        .insert((word >> shift) & 255);
                }
            }
        }
        assert_eq!(production, 10, "{arch}: exact production count");
        assert_eq!(
            domains.len(),
            12,
            "{arch}: three registers x neg/reuse states"
        );
        assert!(
            domains.values().all(|values| values.len() == 256),
            "{arch}: full byte domains"
        );
    }
}

#[test]
fn exactly_two_fields_are_repaired_on_one_existing_group() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["scheduling"]["pipe_name"], "UNKNOWN");
        let group = &entry["mod_groups"]["BF16_V2"];
        assert_eq!(group["_src"], SOURCE, "{arch}");
        assert_eq!(group["count"], Value::Null);
        for (shift, extraction) in [(63, "neg"), (124, "reuse")] {
            let field = group["fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|field| field["shift"] == shift && field["extraction"] == extraction)
                .unwrap_or_else(|| panic!("{arch}: missing {extraction}@{shift}"));
            assert_eq!(
                (field["bits"].as_u64(), field["token_idx"].as_u64()),
                (Some(1), Some(3)),
                "{arch}"
            );
            assert_ne!(hex(&group["variable_mask"]) & (1u128 << shift), 0, "{arch}");
            assert_eq!(hex(&group["and_base"]) & (1u128 << shift), 0, "{arch}");
        }
        assert!(entry["mod_groups"][""]["_src"] != SOURCE);
        assert!(entry["mod_groups"]["F32"]["_src"] != SOURCE);
    }
}

#[test]
fn every_production_word_has_independent_neg_and_reuse_ab() {
    let mut measured = BTreeMap::new();
    for (arch, fixture) in arches() {
        if arch != "sm103a" {
            continue;
        }
        for row in rows(fixture) {
            measured.entry(hex(&row["word"])).or_insert(row);
        }
    }
    let productions: Vec<u128> = measured
        .iter()
        .filter_map(|(word, row)| (row["generation"] == "production").then_some(*word))
        .collect();
    assert_eq!(productions.len(), 10);
    for word in productions {
        let text = measured[&word]["nvidia_sass"].as_str().unwrap();
        assert!(text.contains(", -R") && text.ends_with(".reuse"), "{text}");
        let no_neg = measured[&(word & !(1u128 << 63))]["nvidia_sass"]
            .as_str()
            .unwrap();
        let no_reuse = measured[&(word & !(1u128 << 124))]["nvidia_sass"]
            .as_str()
            .unwrap();
        let clear = measured[&(word & !(1u128 << 63) & !(1u128 << 124))]["nvidia_sass"]
            .as_str()
            .unwrap();
        assert!(
            no_neg.contains(", R") && no_neg.ends_with(".reuse"),
            "{no_neg}"
        );
        assert!(
            no_reuse.contains(", -R") && !no_reuse.ends_with(".reuse"),
            "{no_reuse}"
        );
        assert!(
            clear.contains(", R") && !clear.ends_with(".reuse"),
            "{clear}"
        );
    }
}
