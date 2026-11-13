//! Complete-word LDCU.S8 cAURI text; no constant-memory execution.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-ldcu-s8-cauri-production-2026-11-10";
const KEY: &str = "LDCU_UR_cAURI";
const GROUP: &str = "S8";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    (
        "sm103a",
        hb300_fixture("sm103a_ldcu_s8_cauri_production_nvdisasm.jsonl"),
    ),
    (
        "sm100a",
        hb300_fixture("sm100a_ldcu_s8_cauri_production_nvdisasm.jsonl"),
    ),
]);

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLES: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLES.get_or_init(|| {
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

fn rows(fixture: &str) -> impl Iterator<Item = Value> + '_ {
    fixture
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
}

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn encode(table: &IsaTable, word: u128, text: &str) -> Result<u128, anyhow::Error> {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table)
}

fn model() -> Value {
    serde_json::from_str(r#"{"and_base":"0x000000000800020000000000000007ac","claim_forbid":[{"bits":1,"shift":122,"values":[1]},{"bits":1,"shift":123,"values":[1]},{"bits":1,"shift":124,"values":[1]},{"bits":8,"shift":24,"values":[255]}],"fields":[{"bits":4,"extraction":"guard","shift":12,"token_idx":0},{"bits":8,"extraction":"ureg","shift":16,"token_idx":1},{"bits":8,"extraction":"sub_ur1","shift":24,"token_idx":2},{"bits":22,"extraction":"cm17_off","shift":37,"token_idx":2}],"kind_counts":{"adjacent_modifier":6177,"control_plane":37,"negative":626,"positive":1866},"positive":1866,"production":6,"reuse_decoded":0,"variable_mask":"0x000000000000000007ffffe0fffff000"}"#).unwrap()
}

#[test]
fn production_and_controlled_fields_roundtrip() {
    let expected = model();
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let (mut production, mut positive, mut reuse_decoded) = (0, 0, 0);
        for row in rows(fixture) {
            let accepted = row["kind"] == "positive";
            let reuse = row["generation"] == "reuse_control";
            if !accepted && !reuse {
                continue;
            }
            let word = hex(&row["word"]);
            let Ok(decoded) = decoder.decode(word, 0, table) else {
                continue;
            };
            if decoded.key != KEY || decoded.mod_group != GROUP {
                continue;
            }
            if reuse {
                reuse_decoded += 1;
            } else {
                positive += 1;
            }
            if row["generation"] == "production" {
                production += 1;
            }
            let text = row["nvidia_sass"].as_str().unwrap();
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
            let encoded = encode(table, word, text);
            assert_eq!(
                encoded.unwrap(),
                word & !(7u128 << 125),
                "{arch} {word:032x}"
            );
        }
        assert_eq!(
            production,
            usize::try_from(expected["production"].as_u64().unwrap()).unwrap()
        );
        assert_eq!(
            positive,
            usize::try_from(expected["positive"].as_u64().unwrap()).unwrap()
        );
        assert_eq!(
            reuse_decoded,
            usize::try_from(expected["reuse_decoded"].as_u64().unwrap()).unwrap()
        );
    }
}

#[test]
fn scoped_row_fields_and_provenance_match_measurement() {
    let expected = model();
    for (arch, _) in ARCHES.iter() {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["base_op"], "LDCU");
        assert_eq!(entry["operand_sig"], "UR_cAURI");
        let row = &entry["mod_groups"][GROUP];
        assert_eq!(row["_src"], SOURCE);
        assert_eq!(hex(&row["and_base"]) >> 96, 0);
        assert_eq!(row["and_base"], expected["and_base"]);
        assert_eq!(row["variable_mask"], expected["variable_mask"]);
        assert_eq!(row["fields"], expected["fields"]);
        assert_eq!(
            row.get("claim_forbid")
                .cloned()
                .unwrap_or(Value::Array(vec![])),
            expected["claim_forbid"]
        );
        let fields = row["fields"].as_array().unwrap();
        let mask = fields.iter().fold(0u128, |mask, field| {
            mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1)
                << field["shift"].as_u64().unwrap())
        });
        assert_eq!(hex(&row["variable_mask"]), mask);
        for (shift, bits, extraction) in [
            (12u64, 4u64, "guard"),
            (16, 8, "ureg"),
            (24, 8, "sub_ur1"),
            (37, 22, "cm17_off"),
        ] {
            assert!(fields.iter().any(|f| f["shift"] == shift
                && f["bits"] == bits
                && f["extraction"] == extraction));
        }
        assert!(raw["instructions"]["LDCU_UR_cAI"].is_object());
    }
}

#[test]
fn neighbours_inert_fields_and_refusals_fail_closed() {
    let expected = model();
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut counts = std::collections::BTreeMap::new();
        let mut reuse_refusals = 0;
        for row in rows(fixture) {
            let kind = row["kind"].as_str().unwrap();
            if matches!(kind, "positive" | "control_plane") {
                continue;
            }
            *counts.entry(kind.to_string()).or_insert(0usize) += 1;
            let word = hex(&row["word"]);
            let decoded = decoder.decode(word, 0, table);
            if let Ok(decoded) = decoded {
                assert!(
                    decoded.key != KEY || decoded.mod_group != GROUP,
                    "{arch} overmatch {kind} {word:032x}"
                );
            }
            if kind == "negative" {
                assert!(
                    decoder.decode(word, 0, table).is_err(),
                    "{arch}: invalid/text-inert word accepted {word:032x}"
                );
            }
        }
        for row in rows(fixture) {
            if row["generation"] != "reuse_control" {
                continue;
            }
            let word = hex(&row["word"]);
            assert!(
                decoder.decode(word, 0, table).is_err(),
                "{arch}: text-inert reuse mask accepted {word:032x}"
            );
            reuse_refusals += 1;
        }
        assert_eq!(reuse_refusals, 7);
        for (kind, count) in expected["kind_counts"].as_object().unwrap() {
            if matches!(kind.as_str(), "positive" | "control_plane") {
                continue;
            }
            assert_eq!(
                counts.get(kind).copied().unwrap_or(0),
                usize::try_from(count.as_u64().unwrap()).unwrap(),
                "{arch} {kind}"
            );
        }
    }
}
