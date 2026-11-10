//! Measured FSET.BF R_R_UR_P vendor-text tests; no execution or numeric claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const SOURCE: &str = "rows-fset-bf-ru-2026-11-09";
const KEY: &str = "FSET_R_R_UR_P";
const PRODUCTION: usize = 119;
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    ("sm103a", hb300_fixture("sm103a_fset_bf_ru_nvdisasm.jsonl")),
    ("sm100a", hb300_fixture("sm100a_fset_bf_ru_nvdisasm.jsonl")),
]);

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLE: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLE.get_or_init(|| {
        ARCHES.iter().map(|(arch, _)| {
            let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
            let index = DecodeIndex::build(&table);
            (table, index)
        }).collect()
    })
}

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn body(text: &str) -> &str {
    if text.starts_with('@') { text.split_once(' ').unwrap().1 } else { text }
}

fn group(text: &str) -> String {
    let mut modifiers: Vec<&str> = body(text).split_whitespace().next().unwrap()
        .split('.').skip(1).collect();
    modifiers.sort_unstable();
    modifiers.join(",")
}

fn expected_groups() -> BTreeSet<String> {
    const COMPARISONS: [&str; 16] = [
        "F", "LT", "EQ", "LE", "GT", "NE", "GE", "NUM",
        "NAN", "LTU", "EQU", "LEU", "GTU", "NEU", "GEU", "T",
    ];
    let mut result = BTreeSet::new();
    for comparison in COMPARISONS {
        for boolean in ["AND", "OR", "XOR"] {
            for ftz in [false, true] {
                let mut modifiers = vec!["BF", comparison, boolean];
                if ftz { modifiers.push("FTZ"); }
                modifiers.sort_unstable();
                result.insert(modifiers.join(","));
            }
        }
    }
    result
}

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

#[test]
fn vendor_groups_and_measured_operands_roundtrip_exactly() {
    let expected = expected_groups();
    assert_eq!(expected.len(), 96);
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut groups = BTreeSet::new();
        let mut production = 0;
        let mut generations = BTreeMap::new();
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["kind"] != "positive" { continue; }
            *generations.entry(row["generation"].as_str().unwrap().to_string()).or_insert(0usize) += 1;
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = decoder.decode(word, 0, table)
                .unwrap_or_else(|e| panic!("{arch} {word:032x}: {e}"));
            assert_eq!(decoded.key, KEY, "{arch} {word:032x}");
            let expected_group = group(text);
            assert_eq!(decoded.mod_group, expected_group, "{arch} {word:032x} {text}");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), text, "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass(&decoded), text, "{arch} {word:032x}");
            assert_eq!(encode(table, word, text), word & !(7u128 << 125),
                "{arch} {word:032x} {text}");
            groups.insert(expected_group);
            production += usize::from(row["generation"] == "production");
        }
        assert_eq!(groups, expected, "{arch}: measured 96-group coverage");
        assert_eq!(production, PRODUCTION, "{arch}: distinct stored production witnesses");
        for generation in ["base", "matrix", "field", "sign"] {
            assert!(generations[generation] > 0, "{arch}: absent positive {generation}");
        }
    }
}

#[test]
fn provenance_group_bases_and_independently_measured_fields_are_scoped() {
    let required = [
        (12, 0, 4, "guard"), (16, 1, 8, "reg"),
        (24, 2, 8, "reg"), (72, 2, 1, "neg"), (73, 2, 1, "abs"),
        (32, 3, 8, "ureg"), (62, 3, 1, "abs"), (63, 3, 1, "neg"),
        (87, 4, 3, "pred"), (90, 4, 1, "inv"),
    ];
    for (arch, _) in *ARCHES {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 96);
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["_src"], SOURCE);
        assert_eq!(entry["base_op"], "FSET");
        assert_eq!(entry["operand_sig"], "R_R_UR_P");
        let groups = entry["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), 96);
        assert_eq!(groups.keys().cloned().collect::<BTreeSet<_>>(), expected_groups());
        for (name, group) in groups {
            assert_eq!(group["_src"], SOURCE, "{arch} {name}");
            assert_eq!(hex(&group["and_base"]) >> 96, 0, "{arch} {name}: baked control");
            assert_eq!(group["count"], Value::Null);
            let fields = group["fields"].as_array().unwrap();
            let mask = fields.iter().fold(0u128, |mask, field| {
                mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1)
                    << field["shift"].as_u64().unwrap())
            });
            assert_eq!(hex(&group["variable_mask"]), mask, "{arch} {name}");
            assert_eq!(hex(&group["and_base"]) & mask, 0, "{arch} {name}");
            for (shift, token, bits, extraction) in required {
                assert!(fields.iter().any(|field| field["shift"] == shift
                    && field["token_idx"] == token && field["bits"] == bits
                    && field["extraction"] == extraction), "{arch} {name}: field {shift}");
            }
            assert_eq!(fields.len(), required.len(), "{arch} {name}");
            assert!(!fields.iter().any(|field| field["extraction"] == "reuse"),
                "{arch} {name}: refused reuse must stay outside");
        }
    }
}

#[test]
fn invalid_inert_and_non_uniform_operand_words_stay_outside_new_family() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut counts = BTreeMap::new();
        let mut invalid_boolean = 0;
        let mut separate_controls = 0;
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let kind = row["kind"].as_str().unwrap();
            if kind == "positive" { continue; }
            *counts.entry(kind.to_string()).or_insert(0usize) += 1;
            if kind == "control_negative" || kind == "control_plane" {
                separate_controls += 1;
                continue;
            }
            assert_ne!(kind, "silicon_candidate", "{arch}: accepted unnamed word needs neutral review");
            let word = hex(&row["word"]);
            let decoded = decoder.decode(word, 0, table);
            if let Ok(ref value) = decoded {
                assert_ne!(value.key, KEY, "{arch} {kind} {word:032x} entered new family");
            }
            if kind == "negative" {
                assert!(decoded.is_err(), "{arch} negative {word:032x}: {decoded:?}");
            }
            invalid_boolean += usize::from(row["generation"] == "matrix-invalid");
        }
        for kind in ["negative", "other_family", "control_negative", "control_plane"] {
            assert!(counts[kind] > 0, "{arch}: absent {kind}");
        }
        assert!(!counts.contains_key("adjacent_modifier"), "{arch}: unclassified adjacent modifier");
        assert_eq!(invalid_boolean, 32, "{arch}: all boolean INVALID3 controls");
        assert!(separate_controls >= 36, "{arch}: schedule and reuse measurements retained separately");
    }
}
