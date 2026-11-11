//! K1 ExpertsKernel production forms measured with nvdisasm on SM103 and SM100.
//! No GPU execution is claimed by these encoding tests.

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::path::Path;

const SRC: &str = "rows-k1-experts-forms-2026-11-10";

fn fixtures(arch: &str) -> Vec<Value> {
    let text = match arch {
        "sm103a" => include_str!("fixtures/k1_experts_sm103a_nvdisasm.jsonl"),
        "sm100a" => include_str!("fixtures/k1_experts_sm100a_nvdisasm.jsonl"),
        _ => unreachable!(),
    };
    text.lines().map(|line| serde_json::from_str(line).unwrap()).collect()
}

fn table_path(arch: &str) -> String {
    std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz"))
}

fn table(arch: &str) -> IsaTable {
    IsaTable::load(Path::new(&table_path(arch))).unwrap()
}

fn reencode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32),
    );
    let source = format!("[{control}] {text} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    assert!(parsed.hand_sched && parsed.rsd.is_none(), "{source}");
    cubit::encoder::encode_instruction(&parsed, table)
        .unwrap_or_else(|error| panic!("{source}: {error}"))
}

#[test]
fn every_adopted_word_has_vendor_text_and_reencodes_all_128_bits() {
    for arch in ["sm103a", "sm100a"] {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let (mut adopted, mut production) = (0, 0);
        let mut production_names = std::collections::BTreeSet::new();
        for row in fixtures(arch) {
            if row["role"] != "adopt" {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, &table).unwrap_or_else(|error| {
                panic!("{arch} {} {vendor}: {error}", row["case"])
            });
            assert_eq!(decoded.key.as_str(), row["expected_key"].as_str().unwrap(),
                       "{arch} {} {vendor}", row["case"]);
            assert_eq!(decoded.mod_group.as_str(), row["expected_group"].as_str().unwrap(),
                       "{arch} {} {vendor}", row["case"]);
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor,
                       "{arch} {} {word:032x}", row["case"]);
            assert_eq!(reencode(&table, word, vendor), word,
                       "{arch} {} {vendor}", row["case"]);
            adopted += 1;
            if row["kind"] == "production" {
                production += 1;
                production_names.insert(row["family"].as_str().unwrap().to_string());
            }
        }
        assert!(adopted >= 200, "{arch}: incomplete positive fixture: {adopted}");
        assert_eq!(production, 8, "{arch}: all distinct K1 witnesses must be present");
        assert_eq!(production_names.len(), 4, "{arch}: production families");
    }
}

#[test]
fn every_neighbour_outside_the_measured_fields_fails_closed() {
    for arch in ["sm103a", "sm100a"] {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let mut rejected = 0;
        for row in fixtures(arch) {
            if row["role"] != "reject" {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            if let Ok(decoded) = index.decode(word, 0, &table) {
                let family = row["family"].as_str().unwrap();
                let new_key = match family {
                    "depbar" => "DEPBAR_II",
                    "cctl" => "CCTL_AURI",
                    "ublkcp" => "UBLKCP_AURI_AURI_UR_II",
                    "ublkpf" => "UBLKPF_AURI_UR",
                    _ => unreachable!(),
                };
                assert_ne!(decoded.key.as_str(), new_key,
                           "new row claimed {arch} {} {word:032x} ({})",
                           row["case"], row["nvidia_sass"]);
            }
            rejected += 1;
        }
        assert!(rejected >= 200, "{arch}: incomplete negative fixture: {rejected}");
    }
}

#[test]
fn the_change_is_exactly_four_measured_rows_per_architecture() {
    for arch in ["sm103a", "sm100a"] {
        let path = table_path(arch);
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(Path::new(&path)).unwrap(),
        ).unwrap();
        let mut new_rows = 0;
        for (key, entry) in raw["instructions"].as_object().unwrap() {
            for (name, group) in entry["mod_groups"].as_object().unwrap() {
                if group["_src"] != SRC {
                    continue;
                }
                new_rows += 1;
                assert_eq!(group["count"].is_null(), true, "{key}:{name}: harvested count");
                let number = |value: &Value| {
                    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16)
                        .unwrap()
                };
                let mut fields_mask = 0u128;
                for field in group["fields"].as_array().unwrap() {
                    let bits = ((1u128 << field["bits"].as_u64().unwrap()) - 1)
                        << field["shift"].as_u64().unwrap();
                    assert_eq!(fields_mask & bits, 0, "{key}:{name}: overlapping fields");
                    fields_mask |= bits;
                }
                assert_eq!(number(&group["variable_mask"]), fields_mask, "{key}:{name}");
                assert_eq!(number(&group["and_base"]) & fields_mask, 0, "{key}:{name}");
                assert_eq!(number(&group["and_base"]) >> 105, 0, "{key}:{name}: control bits");
            }
        }
        assert_eq!(new_rows, 4, "{arch}: measured scope");
        let depbar = &raw["instructions"]["DEPBAR_II"]["mod_groups"][""];
        assert_eq!(depbar["_src"], SRC);
        assert_eq!(depbar["claim_forbid"][0]["shift"], 32);
        assert_eq!(depbar["claim_forbid"][0]["bits"], 6);
        assert_eq!(depbar["claim_forbid"][0]["values"], serde_json::json!([0]));
    }
}
