//! Measured SHF R_R_R_UR vendor-text tests; no execution or numeric claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const SOURCE: &str = "rows-shf-rur-production-2026-11-09";
const KEY: &str = "SHF_R_R_R_UR";
const PRODUCTION: usize = 18;
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    (
        "sm103a",
        hb300_fixture("sm103a_shf_rur_production_nvdisasm.jsonl"),
    ),
    (
        "sm100a",
        hb300_fixture("sm100a_shf_rur_production_nvdisasm.jsonl"),
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

fn group(text: &str) -> &'static str {
    match body(text).split_whitespace().next().unwrap() {
        "SHF.R.U64" => "R,U64",
        "SHF.L.U64.HI" => "HI,L,U64",
        other => panic!("outside the measured SHF family: {other}"),
    }
}

fn reuse_operands(text: &str) -> BTreeSet<usize> {
    body(text)
        .split_once(' ')
        .unwrap()
        .1
        .split(", ")
        .enumerate()
        .filter_map(|(index, operand)| operand.contains(".reuse").then_some(index + 1))
        .collect()
}

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

fn measured_reuse_fields() -> BTreeMap<&'static str, BTreeMap<u32, usize>> {
    let mut expected: BTreeMap<&'static str, BTreeMap<u32, usize>> = BTreeMap::new();
    for line in ARCHES[0].1.lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        if row["generation"] != "reuse-scheduled" || row["kind"] != "positive" {
            continue;
        }
        let label = row["label"].as_str().unwrap();
        let mask = match label.rsplit(':').next().unwrap() {
            "001" => 122,
            "010" => 123,
            "100" => 124,
            _ => continue,
        };
        let tokens = reuse_operands(row["nvidia_sass"].as_str().unwrap());
        assert_eq!(tokens.len(), 1, "{label}");
        let token = *tokens.first().unwrap();
        let old = expected
            .entry(group(row["nvidia_sass"].as_str().unwrap()))
            .or_default()
            .insert(mask, token);
        assert!(old.is_none(), "duplicate independent reuse probe");
    }
    expected
}

#[test]
fn production_and_measured_operands_roundtrip_exactly() {
    let expected = BTreeSet::from(["R,U64".to_string(), "HI,L,U64".to_string()]);
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
            assert_eq!(decoded.key, KEY, "{arch} {word:032x}");
            let expected_group = group(text);
            assert_eq!(
                decoded.mod_group, expected_group,
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
            groups.insert(expected_group.to_string());
            production += usize::from(row["generation"] == "production");
        }
        assert_eq!(
            groups, expected,
            "{arch}: exactly two measured modifier groups"
        );
        assert_eq!(
            production, PRODUCTION,
            "{arch}: distinct complete production words"
        );
        for generation in ["base", "field", "production"] {
            assert!(
                generations[generation] > 0,
                "{arch}: absent positive {generation}"
            );
        }
    }
}

#[test]
fn provenance_group_bases_and_independently_measured_fields_are_scoped() {
    let required = [
        (12, 0, 4, "guard"),
        (16, 1, 8, "reg"),
        (24, 2, 8, "reg"),
        (64, 3, 8, "reg"),
        (32, 4, 8, "ureg"),
    ];
    let reuse = measured_reuse_fields();
    for (arch, _) in *ARCHES {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 2);
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["_src"], SOURCE);
        assert_eq!(entry["base_op"], "SHF");
        assert_eq!(entry["operand_sig"], "R_R_R_UR");
        let groups = entry["mod_groups"].as_object().unwrap();
        assert_eq!(
            groups.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from(["R,U64".to_string(), "HI,L,U64".to_string()])
        );
        for (name, group) in groups {
            assert_eq!(group["_src"], SOURCE, "{arch} {name}");
            assert_eq!(
                hex(&group["and_base"]) >> 96,
                0,
                "{arch} {name}: baked control"
            );
            assert_eq!(group["count"], Value::Null);
            let fields = group["fields"].as_array().unwrap();
            let mask = fields.iter().fold(0u128, |mask, field| {
                let bits = ((1u128 << field["bits"].as_u64().unwrap()) - 1)
                    << field["shift"].as_u64().unwrap();
                assert_eq!(mask & bits, 0, "{arch} {name}: overlapping fields");
                mask | bits
            });
            assert_eq!(hex(&group["variable_mask"]), mask, "{arch} {name}");
            assert_eq!(hex(&group["and_base"]) & mask, 0, "{arch} {name}");
            for (shift, token, bits, extraction) in required {
                assert!(
                    fields.iter().any(|field| field["shift"] == shift
                        && field["token_idx"] == token
                        && field["bits"] == bits
                        && field["extraction"] == extraction),
                    "{arch} {name}: field {shift}"
                );
            }
            let empty = BTreeMap::new();
            let group_reuse = reuse.get(name.as_str()).unwrap_or(&empty);
            for (shift, token) in group_reuse {
                assert!(
                    fields.iter().any(|field| field["shift"] == *shift
                        && field["token_idx"] == *token
                        && field["bits"] == 1
                        && field["extraction"] == "reuse"),
                    "{arch} {name}: reuse {shift}"
                );
            }
            assert_eq!(
                fields.len(),
                required.len() + group_reuse.len(),
                "{arch} {name}"
            );
        }
    }
}

#[test]
fn invalid_inert_adjacent_and_non_uniform_words_stay_outside_new_family() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut counts = BTreeMap::new();
        let mut controls = 0;
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let kind = row["kind"].as_str().unwrap();
            if kind == "positive" {
                continue;
            }
            *counts.entry(kind.to_string()).or_insert(0usize) += 1;
            if kind == "control_plane" || kind == "control_negative" {
                controls += 1;
                continue;
            }
            assert_ne!(
                kind, "silicon_candidate",
                "{arch}: accepted unnamed word needs neutral review"
            );
            let word = hex(&row["word"]);
            let decoded = decoder.decode(word, 0, table);
            if let Ok(ref value) = decoded {
                assert_ne!(
                    value.key, KEY,
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
            assert!(counts[kind] > 0, "{arch}: absent {kind}");
        }
        assert!(
            controls >= 58,
            "{arch}: upper control plane retained independently"
        );
    }
}
