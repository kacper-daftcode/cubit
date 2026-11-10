//! Measured production LDGMC R_ARURI vendor-text adoption; no GPU execution.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const KEY: &str = "LDGMC_R_ARURI";
const SOURCE: &str = "rows-ldgmc-production-2026-11-08";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    (
        "sm103a",
        hb300_fixture("sm103a_ldgmc_production_nvdisasm.jsonl"),
    ),
    (
        "sm100a",
        hb300_fixture("sm100a_ldgmc_production_nvdisasm.jsonl"),
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

fn word(row: &Value) -> u128 {
    let text = row
        .as_str()
        .or_else(|| row["word"].as_str())
        .unwrap_or_else(|| panic!("expected word object or hex string, got {row}"));
    u128::from_str_radix(text.trim_start_matches("0x"), 16)
        .unwrap_or_else(|error| panic!("invalid word {text}: {error}"))
}

fn encode(table: &IsaTable, raw: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (raw >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

#[test]
fn production_and_named_field_words_render_and_encode_exactly() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut forms = BTreeSet::new();
        let mut positive = 0;
        let mut production = 0;
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["kind"] != "positive" {
                continue;
            }
            let raw = word(&row);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = decoder
                .decode(raw, 0, table)
                .unwrap_or_else(|e| panic!("{arch} {raw:032x} {text}: {e}"));
            assert_eq!(decoded.key, KEY, "{arch} {raw:032x} {text}");
            let shape = row["shape"].as_str().unwrap();
            assert!(text.contains(shape), "{arch} wrong type: {text}");
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                text,
                "{arch} {raw:032x}"
            );
            assert_eq!(cubit::printer::to_sass(&decoded), text, "{arch} {raw:032x}");
            // Raw control formatting lacks [127:125]; all measured operands,
            // guards and expressible scheduling bits must roundtrip.
            assert_eq!(
                encode(table, raw, text),
                raw & !(7u128 << 125),
                "{arch} {raw:032x} {text}"
            );
            positive += 1;
            production += usize::from(row["label"].as_str().unwrap().starts_with("production:"));
            forms.insert(shape.to_owned());
        }
        assert!(positive > 160, "{arch}");
        assert_eq!(production, 160, "{arch}");
        assert_eq!(forms.len(), 8, "{arch}: {forms:?}");
    }
}

#[test]
fn only_eight_measured_rows_have_provenance_and_fields() {
    for (arch, _) in *ARCHES {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 8);
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["_src"], SOURCE);
        assert_eq!(entry["operand_sig"], "R_ARURI");
        let groups = entry["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), 8, "{arch}");
        for (name, group) in groups {
            let base = &group["and_base"];
            let variable = &group["variable_mask"];
            assert!(base.is_string(), "{arch} {name}: and_base={base}");
            assert!(
                variable.is_string(),
                "{arch} {name}: variable_mask={variable}"
            );
            assert_eq!(group["_src"], SOURCE);
            assert_eq!(word(&group["and_base"]) >> 96, 0, "{arch} {name}");
            let fields = group["fields"].as_array().unwrap();
            assert_eq!(fields.len(), 5);
            let mask = fields.iter().fold(0u128, |mask, field| {
                mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1)
                    << field["shift"].as_u64().unwrap())
            });
            assert_eq!(word(&group["variable_mask"]), mask);
            assert_eq!(word(&group["and_base"]) & mask, 0);
            assert_eq!(
                group["claim_forbid"],
                serde_json::json!([{
                    "bits": 8, "shift": 24, "values": [255],
                }])
            );
            for (bits, shift, token, extraction) in [
                (4, 12, 0, "guard"),
                (8, 16, 1, "reg"),
                (8, 24, 2, "sub_r0"),
                (24, 40, 2, "sub_imm2"),
                (8, 64, 2, "sub_ur1"),
            ] {
                assert!(
                    fields.iter().any(|field| field["bits"] == bits
                        && field["shift"] == shift
                        && field["token_idx"] == token
                        && field["extraction"] == extraction),
                    "{arch} {name} {extraction}"
                );
            }
        }
    }
}

#[test]
fn refused_unnamed_inert_and_unmeasured_forms_do_not_enter_new_rows() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut census = BTreeMap::new();
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let kind = row["kind"].as_str().unwrap().to_owned();
            if kind == "positive" {
                continue;
            }
            *census.entry(kind.clone()).or_insert(0usize) += 1;
            let raw = word(&row);
            let decoded = decoder.decode(raw, 0, table);
            if let Ok(value) = &decoded {
                assert_ne!(value.key, KEY, "{arch} {kind} {raw:032x}");
            }
            if kind != "other_family" {
                assert!(decoded.is_err(), "{arch} {kind} {raw:032x}: {decoded:?}");
            }
        }
        for kind in ["negative", "adjacent_modifier", "other_family"] {
            assert!(census.get(kind).unwrap_or(&0) > &0, "{arch} {kind}");
        }
    }
}
