//! Measured production BMSK operand forms; vendor text is not an execution claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

const SOURCE: &str = "rows-bmsk-production-2026-11-08";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    (
        "sm103a",
        hb300_fixture("sm103a_bmsk_production_nvdisasm.jsonl"),
    ),
    (
        "sm100a",
        hb300_fixture("sm100a_bmsk_production_nvdisasm.jsonl"),
    ),
]);

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLE: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLE.get_or_init(|| {
        ARCHES
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

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn body(text: &str) -> &str {
    if text.starts_with('@') {
        text.split_once(' ').unwrap().1
    } else {
        text
    }
}

fn key_for(text: &str) -> &'static str {
    let last = body(text).rsplit(',').next().unwrap().trim();
    if last.starts_with("UR") {
        "BMSK_R_R_UR"
    } else {
        "BMSK_R_R_R"
    }
}

fn rows(fixture: &str) -> impl Iterator<Item = Value> + '_ {
    fixture
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
}

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

fn source_rows(arch: &str, key: &str, uniform: bool) {
    let raw: Value = serde_json::from_slice(
        &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 2);
    let entry = &raw["instructions"][key];
    assert_eq!(entry["_src"], SOURCE);
    assert_eq!(entry["base_op"], "BMSK");
    assert_eq!(
        entry["operand_sig"],
        if uniform { "R_R_UR" } else { "R_R_R" }
    );
    assert_eq!(entry["scheduling"]["latency_source"], "synthetic");
    let groups = entry["mod_groups"].as_object().unwrap();
    assert_eq!(groups.len(), 1);
    let group = &groups[""];
    assert_eq!(group["_src"], SOURCE);
    assert_eq!(group["count"], Value::Null);
    assert_eq!(
        hex(&group["and_base"]),
        if uniform {
            0x00000000080000000000000000000c1bu128
        } else {
            0x21b
        }
    );
    assert_eq!(hex(&group["variable_mask"]), 0xfffffff000u128);
    assert_eq!(hex(&group["and_base"]) >> 96, 0);
    let fields = group["fields"].as_array().unwrap();
    assert_eq!(fields.len(), 4);
    for (index, (shift, token, bits, extraction)) in [
        (12, 0, 4, "guard"),
        (16, 1, 8, "reg"),
        (24, 2, 8, "reg"),
        (32, 3, 8, if uniform { "ureg" } else { "reg" }),
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(fields[index]["shift"], shift);
        assert_eq!(fields[index]["token_idx"], token);
        assert_eq!(fields[index]["bits"], bits);
        assert_eq!(fields[index]["extraction"], extraction);
    }
}

fn positive_form(uniform: bool) {
    let expected_key = if uniform { "BMSK_R_R_UR" } else { "BMSK_R_R_R" };
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut production = 0;
        let mut generations = BTreeMap::new();
        let mut total = 0;
        for row in rows(fixture) {
            if row["kind"] != "positive"
                || key_for(row["nvidia_sass"].as_str().unwrap()) != expected_key
            {
                continue;
            }
            total += 1;
            *generations
                .entry(row["generation"].as_str().unwrap().to_string())
                .or_insert(0usize) += 1;
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = decoder
                .decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, expected_key, "{arch} {word:032x} {text}");
            assert_eq!(decoded.mod_group, "");
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
                "{arch} {word:032x}"
            );
            production += usize::from(row["generation"] == "production");
        }
        assert_eq!(
            total, 845,
            "{arch} {expected_key}: complete positive census"
        );
        assert_eq!(
            production, 64,
            "{arch} {expected_key}: stored production witnesses"
        );
        assert_eq!(generations["base"], 1);
        assert_eq!(generations["field"], 780);
        source_rows(arch, expected_key, uniform);
    }
}

#[test]
fn register_third_operand_matches_all_measured_words() {
    positive_form(false);
}

#[test]
fn uniform_third_operand_matches_all_measured_words() {
    positive_form(true);
}

#[test]
fn invalid_inert_and_unscoped_forms_do_not_enter_new_rows() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut counts = BTreeMap::new();
        for row in rows(fixture) {
            let kind = row["kind"].as_str().unwrap();
            if kind == "positive" {
                continue;
            }
            *counts.entry(kind.to_string()).or_insert(0usize) += 1;
            if kind == "control_negative" {
                continue; // Bounded upper-control vendor refusals, not general scheduling law.
            }
            let word = hex(&row["word"]);
            let decoded = decoder.decode(word, 0, table);
            if let Ok(ref value) = decoded {
                assert!(
                    !matches!(value.key.as_str(), "BMSK_R_R_R" | "BMSK_R_R_UR"),
                    "{arch} {kind} {word:032x} entered a new row"
                );
            }
            if kind == "negative" {
                assert!(decoded.is_err(), "{arch} negative {word:032x}: {decoded:?}");
            }
        }
        assert_eq!(counts["negative"], 124);
        assert_eq!(counts["other_family"], 10);
        assert_eq!(counts["adjacent_modifier"], 2);
        assert_eq!(counts["control_negative"], 6);
    }
}
