//! Measured FSET.BF R_R_FI_P vendor-text tests; no execution or numeric claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const SOURCE: &str = "rows-fset-bf-ri-2026-11-09";
const KEY: &str = "FSET_R_R_FI_P";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    ("sm103a", hb300_fixture("sm103a_fset_bf_ri_nvdisasm.jsonl")),
    ("sm100a", hb300_fixture("sm100a_fset_bf_ri_nvdisasm.jsonl")),
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

fn is_nan_immediate(word: u128) -> bool {
    let value = ((word >> 32) & 0xffff_ffff) as u32;
    value & 0x7f80_0000 == 0x7f80_0000 && value & 0x007f_ffff != 0
}

#[test]
fn all_96_vendor_text_groups_and_field_words_roundtrip_exactly() {
    let expected = expected_groups();
    assert_eq!(expected.len(), 96);
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut groups = BTreeSet::new();
        let mut production = 0;
        let mut nan_immediates = 0;
        let mut reuse = 0;
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
            let lossless = cubit::printer::to_sass_lossless(&decoded);
            if is_nan_immediate(word) {
                assert_eq!(cubit::printer::to_sass(&decoded), text, "{arch} {word:032x}");
                nan_immediates += 1;
            } else {
                assert_eq!(lossless, text, "{arch} {word:032x}");
            }
            assert_eq!(encode(table, word, &lossless), word & !(7u128 << 125),
                "{arch} {word:032x} {lossless}");
            groups.insert(expected_group);
            production += usize::from(row["generation"] == "production");
            reuse += usize::from(row["generation"] == "reuse");
        }
        assert_eq!(groups, expected, "{arch}: measured 96-group coverage");
        assert_eq!(production, 26, "{arch}: stored witness words");
        assert_eq!(nan_immediates, 6, "{arch}: signed QNAN/SNAN and two SNAN payloads");
        assert_eq!(reuse, 0, "{arch}: B300 immediate-form reuse was refused");
        for generation in ["base", "matrix", "field", "sign", "immediate"] {
            assert!(generations[generation] > 0, "{arch}: absent positive {generation}");
        }
    }
}

#[test]
fn provenance_group_bases_and_fields_are_measurement_scoped() {
    for (arch, _) in *ARCHES {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 96);
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["_src"], SOURCE);
        assert_eq!(entry["base_op"], "FSET");
        assert_eq!(entry["operand_sig"], "R_R_FI_P");
        let groups = entry["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), 96);
        assert_eq!(groups.keys().cloned().collect::<BTreeSet<_>>(), expected_groups());
        for (name, group) in groups {
            assert_eq!(group["_src"], SOURCE, "{arch} {name}");
            assert_eq!(hex(&group["and_base"]) >> 96, 0, "{arch} {name}: baked control");
            assert_eq!(group["count"], Value::Null);
            let fields = group["fields"].as_array().unwrap();
            assert_eq!(fields.len(), 8, "{arch} {name}");
            let mask = fields.iter().fold(0u128, |mask, field| {
                mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1)
                    << field["shift"].as_u64().unwrap())
            });
            assert_eq!(hex(&group["variable_mask"]), mask, "{arch} {name}");
            assert_eq!(hex(&group["and_base"]) & mask, 0, "{arch} {name}");
            for (shift, token, bits, extraction) in [
                (12, 0, 4, "guard"), (16, 1, 8, "reg"),
                (24, 2, 8, "reg"), (72, 2, 1, "neg"), (73, 2, 1, "abs"),
                (32, 3, 32, "f32"), (87, 4, 3, "pred"), (90, 4, 1, "inv"),
            ] {
                assert!(fields.iter().any(|field| field["shift"] == shift
                    && field["token_idx"] == token && field["bits"] == bits
                    && field["extraction"] == extraction), "{arch} {name}: field {shift}");
            }
        }
    }
}

#[test]
fn invalid_inert_and_non_immediate_words_stay_outside_new_family() {
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
        assert_eq!(invalid_boolean, 32, "{arch}: all boolean INVALID3 controls");
        assert!(separate_controls >= 36, "{arch}: schedule and reuse measurements retained separately");
    }
}
