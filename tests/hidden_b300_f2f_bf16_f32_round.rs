//! F2F.BF16.F32 register/UR round/FTZ vendor text; no GPU execution.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

const SOURCE: &str = "rows-f2f-bf16-f32-ur-round-ftz-2026-11-09";
const KEY: &str = "F2F_R_UR";
const GROUPS: [&str; 8] = [
    "BF16,F32",
    "BF16,F32,FTZ",
    "BF16,F32,RM",
    "BF16,F32,FTZ,RM",
    "BF16,F32,RP",
    "BF16,F32,FTZ,RP",
    "BF16,F32,RZ",
    "BF16,F32,FTZ,RZ",
];
const EXPECTED: &str = include_str!("fixtures/f2f_bf16_f32_ur_round_measurement.json");
static ARCHES: std::sync::LazyLock<[(&str, &str, &str); 2]> = std::sync::LazyLock::new(|| [
    (
        "sm103a",
        "SM103",
        hb300_fixture("sm103a_f2f_bf16_f32_ur_round_nvdisasm.jsonl"),
    ),
    (
        "sm100a",
        "SM100",
        hb300_fixture("sm100a_f2f_bf16_f32_ur_round_nvdisasm.jsonl"),
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

fn number(value: &Value) -> usize {
    value.as_u64().unwrap() as usize
}

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

#[test]
fn licensed_words_decode_render_and_reencode() {
    let expected: Value = serde_json::from_str(EXPECTED).unwrap();
    for (arch_index, (arch, target, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[arch_index];
        let mut per_group = BTreeMap::new();
        let mut generations = BTreeMap::new();
        for row in rows(fixture) {
            if row["kind"] != "positive" {
                continue;
            }
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let group = row["scope_group"].as_str().unwrap().to_string();
            let generation = row["generation"].as_str().unwrap().to_string();
            assert!(
                GROUPS.contains(&group.as_str()),
                "{arch}: unexpected group {group}"
            );
            *per_group.entry(group.clone()).or_insert(0usize) += 1;
            *generations.entry(generation.clone()).or_insert(0usize) += 1;
            let decoded = index
                .decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, KEY, "{arch} {word:032x}");
            assert_eq!(decoded.mod_group, group, "{arch} {word:032x}");
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                text,
                "{arch} {word:032x}"
            );
            assert_eq!(
                cubit::printer::to_sass(&decoded),
                text,
                "{arch} {word:032x}"
            );
            assert_eq!(
                encode(table, word, text),
                word & !(7u128 << 125),
                "{arch} {word:032x} {text}"
            );
        }
        for (label, mode) in expected["per_mode"].as_object().unwrap() {
            let group = mode["scope_group"].as_str().unwrap();
            assert_eq!(
                per_group[group],
                number(&mode["counts"]["positive"]),
                "{arch}: positive census {label}"
            );
            for (generation, count) in generations.iter() {
                let expected_count: usize = expected["per_mode"]
                    .as_object()
                    .unwrap()
                    .values()
                    .filter_map(|mode| mode["generations"][generation.as_str()].as_u64())
                    .sum::<u64>() as usize;
                assert_eq!(*count, expected_count, "{arch}: generation {generation}");
            }
        }
        assert_eq!(
            per_group.values().sum::<usize>(),
            number(&expected["counts_per_target"][target]["positive"])
        );
    }
}

#[test]
fn unlicensed_words_stay_out_and_scoped_negatives_are_global_rejects() {
    let expected: Value = serde_json::from_str(EXPECTED).unwrap();
    for (arch_index, (arch, target, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[arch_index];
        let mut counts = BTreeMap::new();
        for row in rows(fixture) {
            let kind = row["kind"].as_str().unwrap().to_string();
            *counts.entry(kind.clone()).or_insert(0usize) += 1;
            if matches!(kind.as_str(), "positive" | "control_plane") {
                continue;
            }
            assert!(
                matches!(
                    kind.as_str(),
                    "negative" | "adjacent_modifier" | "other_family"
                ),
                "{arch}: unexpected kind {kind}"
            );
            let word = hex(&row["word"]);
            let scope = row["scope_group"].as_str().unwrap().to_string();
            let decoded = index.decode(word, 0, table);
            if kind == "negative" {
                assert!(
                    decoded.is_err(),
                    "{arch}: global negative accepted {word:032x}"
                );
            } else if let Ok(decoded) = decoded {
                assert!(
                    !(decoded.key == KEY && decoded.mod_group == scope),
                    "{arch}: {kind} {word:032x} entered {scope}"
                );
            }
        }
        for kind in [
            "positive",
            "negative",
            "adjacent_modifier",
            "other_family",
            "control_plane",
        ] {
            assert_eq!(
                counts.get(kind).copied().unwrap_or_default(),
                expected["counts_per_target"][target]
                    .get(kind)
                    .map(number)
                    .unwrap_or_default(),
                "{arch}: {kind} census"
            );
        }
    }
}

#[test]
fn exactly_eight_measured_rows_have_fields_and_provenance() {
    for (arch, _, _) in *ARCHES {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 8);
        assert!(raw["_meta"]["provenance"]["sources"][SOURCE]["note"]
            .as_str()
            .unwrap()
            .contains("not silicon"));
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["operand_sig"], "R_UR");
        assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 10);
        for sibling in ["F32,F64", "F64,F32"] {
            assert_ne!(
                entry["mod_groups"][sibling]["_src"], SOURCE,
                "{arch}: sibling {sibling}"
            );
        }
        for group_name in GROUPS {
            let group = &entry["mod_groups"][group_name];
            assert_eq!(group["_src"], SOURCE, "{arch}: {group_name}");
            let and_base = hex(&group["and_base"]);
            assert_eq!(and_base >> 96, 0);
            assert_eq!(group_name.contains("FTZ"), (and_base >> 80) & 1 == 1);
            if let Some(round) = group_name
                .split(',')
                .find(|part| matches!(*part, "RM" | "RP" | "RZ"))
            {
                assert_eq!(
                    (and_base >> 78) & 3,
                    match round {
                        "RM" => 1,
                        "RP" => 2,
                        "RZ" => 3,
                        _ => unreachable!(),
                    }
                );
            } else {
                assert_eq!((and_base >> 78) & 3, 0);
            }
            let expected = [
                (4, 12, "guard", 0),
                (8, 16, "reg", 1),
                (8, 32, "ureg", 2),
                (1, 63, "neg", 2),
                (1, 62, "abs", 2),
            ];
            let fields = group["fields"].as_array().unwrap();
            assert_eq!(fields.len(), expected.len());
            let mask = fields.iter().fold(0u128, |mask, field| {
                mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1)
                    << field["shift"].as_u64().unwrap())
            });
            for (field, (bits, shift, extraction, token)) in fields.iter().zip(expected) {
                assert_eq!(field["bits"], bits);
                assert_eq!(field["shift"], shift);
                assert_eq!(field["extraction"], extraction);
                assert_eq!(field["token_idx"], token);
            }
            assert_eq!(hex(&group["variable_mask"]), mask);
            assert_eq!(and_base & mask, 0);
            let claims = group["claim_forbid"].as_array().unwrap();
            for bit in [122u64, 123u64, 124u64] {
                assert!(claims.iter().any(|claim| claim["shift"] == bit
                    && claim["bits"] == 1
                    && claim["values"][0] == 1));
            }
        }
    }
}
