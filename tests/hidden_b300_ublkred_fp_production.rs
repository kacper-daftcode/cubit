//! Measured production UBLKRED FP text; no GPU execution or numeric claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

const SOURCE: &str = "rows-ublkred-fp-production-2026-11-09";
const KEY: &str = "UBLKRED_AURI_AURI_UR";
const GROUPS: [&str; 4] = [
    "ADD,BF16,G,RN,S",
    "ADD,F16,G,RN,S",
    "ADD,F32,G,RN,S",
    "ADD,F64,G,RN,S",
];
const EXPECTED: &str = include_str!("fixtures/ublkred_fp_production_measurement.json");
static ARCHES: std::sync::LazyLock<[(&str, &str, &str); 2]> = std::sync::LazyLock::new(|| [
    (
        "sm103a",
        "SM103",
        hb300_fixture("sm103a_ublkred_fp_production_nvdisasm.jsonl"),
    ),
    (
        "sm100a",
        "SM100",
        hb300_fixture("sm100a_ublkred_fp_production_nvdisasm.jsonl"),
    ),
]);

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLES: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLES.get_or_init(|| {
        ARCHES
            .iter()
            .map(|(arch, _, _)| {
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

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

#[test]
fn measured_production_and_field_words_roundtrip() {
    let expected: Value = serde_json::from_str(EXPECTED).unwrap();
    for (index, (arch, target, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let mut counts = BTreeMap::new();
        for row in rows(fixture) {
            if row["kind"] != "positive" {
                continue;
            }
            let group = row["scope_group"].as_str().unwrap();
            assert!(GROUPS.contains(&group));
            assert_eq!(row["decoded_group"], group);
            let census = counts.entry(group.to_string()).or_insert((0usize, 0usize));
            census.0 += 1;
            census.1 += usize::from(row["generation"] == "production");
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, KEY);
            assert_eq!(decoded.mod_group, group);
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                text,
                "{arch} {word:032x}"
            );
            assert_eq!(cubit::printer::to_sass(&decoded), text);
            assert_eq!(encode(table, word, text), word & !(7u128 << 125));
        }
        for group in GROUPS {
            let (positive, production) = counts[group];
            assert_eq!(production, 1, "{arch}: production census {group}");
            assert_eq!(
                positive as u64,
                expected["counts_by_group"][target][&format!("{group}:positive")]
                    .as_u64()
                    .unwrap(),
                "{arch}: full positive census {group}"
            );
        }
    }
}

#[test]
fn unlicensed_encodings_remain_fail_closed() {
    let expected: Value = serde_json::from_str(EXPECTED).unwrap();
    for (index, (arch, target, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let mut actual = BTreeMap::new();
        for row in rows(fixture) {
            let kind = row["kind"].as_str().unwrap().to_string();
            *actual.entry(kind.clone()).or_insert(0usize) += 1;
            if matches!(kind.as_str(), "positive" | "control_plane") {
                continue;
            }
            assert!(matches!(
                kind.as_str(),
                "negative" | "adjacent_modifier" | "other_family"
            ));
            let word = hex(&row["word"]);
            let group = row["scope_group"].as_str().unwrap();
            if let Ok(decoded) = index.decode(word, 0, table) {
                assert!(
                    !(decoded.key == KEY && decoded.mod_group == group),
                    "{arch}: {kind} {word:032x} entered {group}"
                );
            }
            if kind == "negative" {
                assert!(
                    index.decode(word, 0, table).is_err(),
                    "{arch}: invalid/text-inert word accepted {word:032x}"
                );
            }
        }
        for (kind, count) in actual {
            assert_eq!(
                count as u64,
                expected["counts_per_target"][target][&kind]
                    .as_u64()
                    .unwrap(),
                "{arch}: {kind} census"
            );
        }
    }
}

#[test]
fn only_four_measured_rows_have_fields_and_provenance() {
    for (arch, _, _) in *ARCHES {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 4);
        assert!(raw["_meta"]["provenance"]["sources"][SOURCE]["note"]
            .as_str()
            .unwrap()
            .contains("not silicon"));
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["operand_sig"], "AURI_AURI_UR");
        assert_eq!(entry["scheduling"]["pipe_name"], "UNKNOWN");
        assert_eq!(entry["scheduling"]["latency_source"], "synthetic");
        assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 4);
        for (name, group) in entry["mod_groups"].as_object().unwrap() {
            assert!(GROUPS.contains(&name.as_str()));
            assert_eq!(group["_src"], SOURCE);
            let base = hex(&group["and_base"]);
            assert_eq!(base >> 96, 0);
            let expected_type = match (base >> 81) & 0xf {
                4 => "F16",
                5 => "F32",
                7 => "F64",
                8 => "BF16",
                other => panic!("unexpected type selector {other}"),
            };
            assert_eq!(name.split(',').nth(1).unwrap(), expected_type);
            assert_eq!(hex(&group["variable_mask"]) & base, 0);
            assert!(!group["claim_forbid"].as_array().unwrap().is_empty());
            assert!(group["claim_forbid"]
                .as_array()
                .unwrap()
                .iter()
                .all(|claim| claim["values"].as_array().unwrap().len() == 1));
            let fields = group["fields"].as_array().unwrap();
            let expected = [
                (4, 12, 0, "guard"),
                (8, 32, 1, "sub_ur0"),
                (8, 24, 2, "sub_ur0"),
                (8, 64, 3, "ureg"),
            ];
            assert_eq!(fields.len(), expected.len());
            for (field, (bits, shift, token, extraction)) in fields.iter().zip(expected) {
                assert_eq!(field["bits"], bits);
                assert_eq!(field["shift"], shift);
                assert_eq!(field["token_idx"], token);
                assert_eq!(field["extraction"], extraction);
            }
        }
    }
}
