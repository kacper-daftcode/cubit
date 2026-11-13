//! Production VHMNMX.BF16_V2 Rc.reuse repair; CPU evidence only.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const SOURCE: &str = "rows-vhmnmx-bf16-rc-reuse-production-2026-11-11";
const OLD_SOURCE: &str = "rows-vhmnmx-modifiers-production-2026-11-09";
const KEY: &str = "VHMNMX_R_R_R_R_P";

fn arches() -> [(&'static str, &'static str); 2] {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_vhmnmx_bf16_rc_reuse_production_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_vhmnmx_bf16_rc_reuse_production_nvdisasm.jsonl"),
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
        encoded & (1u128 << 124),
        word & (1u128 << 124),
        "{arch}: Rc.reuse@124 lost"
    );
}

#[test]
fn production_and_measured_register_predicate_reuse_domains_roundtrip() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let mut production = 0;
        let mut domains = BTreeMap::new();
        let mut guards = BTreeSet::new();
        let mut predicates = BTreeSet::new();
        for row in rows(fixture) {
            if row["generation"] == "legacy_schedule" {
                let word = hex(&row["word"]);
                let mask = (word >> 122) & 7;
                if mask >= 6 {
                    assert_ne!(row["rc"], 0, "{arch}: retained legacy schedule refusal");
                } else if (word >> 85) & 1 == 1 && (word >> 81) & 1 == 0 {
                    let expected = row["nvidia_sass"].as_str().unwrap();
                    let decoded = index.decode(word, 0, table)
                        .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
                    assert_eq!(decoded.mod_group, "BF16_V2");
                    assert_eq!(cubit::printer::to_sass(&decoded), expected);
                    let lossless = cubit::printer::to_sass_lossless(&decoded);
                    if mask != 0 {
                        assert!(lossless.contains(".reuse"), "{arch}: hidden yield=0 reuse lost");
                    }
                    let control = cubit::scheduling::format_control_code(
                        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
                    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {lossless} ;"), 0).unwrap();
                    let encoded = cubit::encoder::encode_instruction(&parsed, table).unwrap();
                    assert_eq!(encoded & ((1u128 << 96) - 1), word & ((1u128 << 96) - 1));
                    assert_eq!((encoded >> 122) & 7, mask, "{arch}: hidden reuse bits lost");
                }
                continue;
            }
            if row["generation"] == "source_neighbor" {
                let word = hex(&row["word"]);
                let invalid_hsel = [((word >> 74) & 3) == 1, ((word >> 60) & 3) == 1,
                                    ((word >> 76) & 3) == 1];
                if invalid_hsel.into_iter().any(|invalid| invalid) {
                    assert!(index.decode(word, 0, table).is_err(), "{arch}: INVALID1 overmatch");
                } else {
                    roundtrip(table, index, arch, &row);
                }
                continue;
            }
            if row["role"] != "adopt" {
                continue;
            }
            let generation = row["generation"].as_str().unwrap();
            if generation == "production" {
                production += 1;
            }
            roundtrip(table, index, arch, &row);
            let word = hex(&row["word"]);
            guards.insert((word >> 12) & 15);
            predicates.insert(((word >> 87) & 7, (word >> 90) & 1));
            for (name, shift) in [("Rd", 16), ("Ra", 24), ("Rb", 32), ("Rc", 64)] {
                if generation == "field"
                    && row["label"].as_str().unwrap().split(':').nth(1) != Some(name)
                {
                    continue;
                }
                domains
                    .entry((name.to_owned(), (word >> 122) & 7))
                    .or_insert_with(BTreeSet::new)
                    .insert((word >> shift) & 255);
            }
        }
        assert_eq!(production, 6, "{arch}: exact production count");
        assert_eq!(domains.len(), 32, "{arch}: four registers x eight reuse masks");
        assert!(domains.values().all(|values| values.len() == 256), "{arch}: full byte domains");
        assert_eq!(guards.len(), 16, "{arch}: all guards");
        assert_eq!(predicates.len(), 16, "{arch}: all predicates and inversions");
    }
}

#[test]
fn exactly_three_fields_and_three_forbids_are_repaired_on_one_existing_group() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        assert_eq!(raw["_meta"]["provenance"]["sources"][OLD_SOURCE]["rows"], 2);
        let entry = &raw["instructions"][KEY];
        let group = &entry["mod_groups"]["BF16_V2"];
        assert_eq!(group["_src"], SOURCE, "{arch}");
        assert_eq!(group["count"], Value::Null);
        for (shift, token) in [(122, 2), (123, 3), (124, 4)] {
            let field = group["fields"]
                .as_array()
                .unwrap()
                .iter()
                .find(|field| field["shift"] == shift && field["extraction"] == "reuse")
                .unwrap_or_else(|| panic!("{arch}: missing reuse@{shift}"));
            assert_eq!((field["bits"].as_u64(), field["token_idx"].as_u64()), (Some(1), Some(token)));
            assert_ne!(hex(&group["variable_mask"]) & (1u128 << shift), 0, "{arch}");
            assert_eq!(hex(&group["and_base"]) & (1u128 << shift), 0, "{arch}");
            assert!(group["claim_forbid"].as_array().unwrap().iter().all(|claim|
                !(claim["shift"] == shift && claim["bits"] == 1 && claim["values"] == serde_json::json!([1]))));
        }
        for sibling in ["", "NAN", "BF16_V2,NAN"] {
            assert_ne!(entry["mod_groups"][sibling]["_src"], SOURCE, "{arch}: sibling changed");
        }
    }
}

#[test]
fn every_production_word_has_independent_rc_reuse_ab() {
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
    assert_eq!(productions.len(), 6);
    for word in productions {
        let text = measured[&word]["nvidia_sass"].as_str().unwrap();
        assert!(text.starts_with("VHMNMX.BF16_V2 ") && text.ends_with(".reuse, !PT"), "{text}");
        let clear_word = word & !(1u128 << 124);
        let clear = measured[&clear_word]["nvidia_sass"].as_str().unwrap();
        assert!(clear.starts_with("VHMNMX.BF16_V2 ") && clear.ends_with(", !PT"), "{clear}");
        assert!(!clear.contains(".reuse"), "{clear}");
        for shift in [122, 123] {
            let other = measured[&(word | (1u128 << shift))].clone();
            assert_eq!(other["rc"], 0);
            assert!(other["nvidia_sass"].as_str().unwrap().contains(".reuse"));
        }
    }
}
