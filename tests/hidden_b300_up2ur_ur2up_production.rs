//! Measured UP2UR.B3 / UR2UP.B3 vendor-text tests; no execution claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const SOURCE: &str = "rows-up2ur-ur2up-production-2026-11-09";
const UPKEY: &str = "UP2UR_UR_II_UR_II";
const URKEY: &str = "UR2UP_II_UR";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    (
        "sm103a",
        hb300_fixture("sm103a_up2ur_ur2up_production_nvdisasm.jsonl"),
    ),
    (
        "sm100a",
        hb300_fixture("sm100a_up2ur_ur2up_production_nvdisasm.jsonl"),
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

fn family(text: &str) -> (&'static str, &'static str) {
    match body(text).split_whitespace().next().unwrap() {
        "UP2UR.B3" => (UPKEY, "B3"),
        "UR2UP" => (URKEY, ""),
        other => panic!("outside the measured byte-transfer family: {other}"),
    }
}

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

#[test]
fn production_and_measured_operands_roundtrip_exactly() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut groups = BTreeSet::new();
        let mut production = 0;
        let mut generations = BTreeMap::new();
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["kind"] != "positive" {
                continue;
            }
            *generations
                .entry(row["generation"].as_str().unwrap().to_string())
                .or_insert(0usize) += 1;
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = decoder
                .decode(word, 0, table)
                .unwrap_or_else(|e| panic!("{arch} {word:032x}: {e}"));
            let expected = family(text);
            assert_eq!(
                (decoded.key.as_str(), decoded.mod_group.as_str()),
                expected,
                "{arch} {word:032x} {text}"
            );
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                text,
                "{arch} {word:032x}"
            );
            assert_eq!(
                encode(table, word, text),
                word & !(7u128 << 125),
                "{arch} {word:032x} {text}"
            );
            groups.insert(expected);
            production += usize::from(row["generation"] == "production");
        }
        assert_eq!(
            groups,
            BTreeSet::from([(UPKEY, "B3"), (URKEY, "")]),
            "{arch}"
        );
        assert_eq!(
            production, 2,
            "{arch}: two distinct complete production words"
        );
        for generation in ["base", "guard", "byte", "production"] {
            assert!(
                generations[generation] > 0,
                "{arch}: absent positive {generation}"
            );
        }
    }
}

#[test]
fn provenance_bases_and_independently_measured_fields_are_scoped() {
    for (arch, _) in *ARCHES {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 2);
        for (key, group_name, required) in [
            (
                UPKEY,
                "B3",
                vec![
                    (12, 0, 4, "guard"),
                    (16, 1, 8, "ureg"),
                    (24, 3, 8, "ureg"),
                    (32, 4, 32, "imm"),
                ],
            ),
            (
                URKEY,
                "",
                vec![
                    (12, 0, 4, "guard"),
                    (24, 2, 8, "ureg"),
                    (76, 2, 2, "byte_sel"),
                ],
            ),
        ] {
            let entry = &raw["instructions"][key];
            if key == URKEY {
                assert_eq!(entry["_src"], SOURCE, "{arch} {key}");
            } else {
                assert_eq!(
                    entry["_src"],
                    Value::Null,
                    "{arch} {UPKEY}: legacy group must not inherit this probe"
                );
            }
            let group = &entry["mod_groups"][group_name];
            assert_eq!(group["_src"], SOURCE, "{arch} {key}");
            assert_eq!(
                hex(&group["and_base"]) >> 96,
                0,
                "{arch} {key}: baked control"
            );
            assert_eq!(group["count"], Value::Null);
            if key == URKEY {
                assert_eq!(
                    group["claim_forbid"],
                    serde_json::json!([
                        {"bits": 2, "shift": 76, "values": [0, 1, 2]}
                    ]),
                    "{arch} {URKEY}: only measured B3 is admitted"
                );
            } else {
                assert_eq!(group["claim_forbid"], Value::Null);
            }
            let fields = group["fields"].as_array().unwrap();
            assert_eq!(fields.len(), required.len(), "{arch} {key}");
            let mask = fields.iter().fold(0u128, |mask, field| {
                let bits = ((1u128 << field["bits"].as_u64().unwrap()) - 1)
                    << field["shift"].as_u64().unwrap();
                assert_eq!(mask & bits, 0, "{arch} {key}: overlapping fields");
                mask | bits
            });
            assert_eq!(hex(&group["variable_mask"]), mask, "{arch} {key}");
            assert_eq!(hex(&group["and_base"]) & mask, 0, "{arch} {key}");
            for (shift, token, bits, extraction) in required {
                assert!(
                    fields.iter().any(|field| field["shift"] == shift
                        && field["token_idx"] == token
                        && field["bits"] == bits
                        && field["extraction"] == extraction),
                    "{arch} {key}: field {shift}"
                );
            }
        }
    }
}

#[test]
fn invalid_inert_adjacent_and_other_byte_selectors_stay_outside_new_family() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut counts = BTreeMap::new();
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let kind = row["kind"].as_str().unwrap();
            if kind == "positive" {
                continue;
            }
            *counts.entry(kind.to_string()).or_insert(0usize) += 1;
            if kind == "control_plane" || kind == "control_negative" {
                continue;
            }
            assert_ne!(
                kind, "silicon_candidate",
                "{arch}: accepted unnamed word needs neutral review"
            );
            let word = hex(&row["word"]);
            let decoded = decoder.decode(word, 0, table);
            if let Ok(ref value) = decoded {
                assert!(
                    !((value.key == UPKEY && value.mod_group == "B3") || value.key == URKEY),
                    "{arch} {kind} {word:032x} entered new family"
                );
            }
            if kind == "negative" {
                assert!(decoded.is_err(), "{arch} negative {word:032x}: {decoded:?}");
            }
        }
        for kind in [
            "negative",
            "adjacent_modifier",
            "other_family",
            "control_plane",
            "control_negative",
        ] {
            assert!(counts[kind] > 0, "{arch}: no {kind} records: {counts:?}");
        }
    }
}
