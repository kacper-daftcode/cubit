//! SASS-only STAS width/address measurements; no GPU execution is claimed.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::path::Path;

const SRC: &str = "rows-hidden-b300-stas64-production-2026-11-08";

fn fixtures(arch: &str) -> Vec<Value> {
    let text = match arch {
        "sm103a" => hb300_fixture("sm103_stas64_nvdisasm.jsonl"),
        "sm100a" => hb300_fixture("sm100_stas64_nvdisasm.jsonl"),
        _ => unreachable!(),
    };
    text.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn reencode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let source = format!("[{control}] {text} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

#[test]
fn production_and_measured_operands_render_and_reencode_exactly() {
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(Path::new(
            &std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz")),
        ))
        .unwrap();
        let index = DecodeIndex::build(&table);
        for row in fixtures(arch) {
            if row["role"] != "adopt" {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(word, 0, &table)
                .unwrap_or_else(|e| panic!("{word:032x}: {e}"));
            assert_eq!(
                decoded.key.as_str(),
                row["expected_key"].as_str().unwrap(),
                "{word:032x}"
            );
            assert_eq!(
                decoded.mod_group.as_str(),
                row["expected_group"].as_str().unwrap()
            );
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded).replace(".reuse", ""),
                vendor,
                "{word:032x}"
            );
            assert_eq!(reencode(&table, word, vendor), word, "{vendor}");
        }
    }
}

#[test]
fn existing_plain_stas_word_remains_bit_exact() {
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(Path::new(&std::env::var("CUBIT_TABLE")
            .unwrap_or_else(|_| format!("tables/{arch}.json.gz")))).unwrap();
        let index = DecodeIndex::build(&table);
        let word = 0x000000000c0008ff0000000002007dbdu128;
        let decoded = index.decode(word, 0, &table).unwrap();
        assert_eq!(decoded.key.as_str(), "STAS_ARI_R");
        assert_eq!(decoded.mod_group.as_str(), "");
        assert_eq!(cubit::printer::to_sass_lossless(&decoded), "STAS [R2.64], R0");
        assert_eq!(reencode(&table, word, "STAS [R2.64], R0"), word);
    }
}

#[test]
fn invalid_type_reserved_operand_and_alternate_frame_stay_unclaimed() {
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(Path::new(
            &std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz")),
        ))
        .unwrap();
        let index = DecodeIndex::build(&table);
        for row in fixtures(arch) {
            if !matches!(row["role"].as_str(), Some("reject" | "reject-scoped")) {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            assert!(
                index.decode(word, 0, &table).is_err(),
                "claimed lattice word {word:032x}"
            );
        }
    }
}

#[test]
fn new_rows_have_provenance_and_disjoint_fail_closed_fields() {
    for arch in ["sm103a", "sm100a"] {
        let path =
            std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz"));
        let raw: Value =
            serde_json::from_slice(&cubit::table::read_table_bytes(Path::new(&path)).unwrap())
                .unwrap();
        for key in ["STAS_ARI_R", "STAS_ARURI_R"] {
            for (name, group) in raw["instructions"][key]["mod_groups"].as_object().unwrap() {
                assert_eq!(group["_src"], SRC, "{key}:{name}");
                assert!(group["count"].is_null() || (key == "STAS_ARI_R" && name.is_empty()));
                let number = |v: &Value| {
                    u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
                };
                let mut mask = 0u128;
                for field in group["fields"].as_array().unwrap() {
                    // (the canonical layout writes a tag once per level: a field's own `_src` is absent or equal)
                    assert!(field["_src"].is_null() || field["_src"] == SRC);
                    let bits = ((1u128 << field["bits"].as_u64().unwrap()) - 1)
                        << field["shift"].as_u64().unwrap();
                    assert_eq!(mask & bits, 0, "overlapping fields");
                    mask |= bits;
                }
                assert_eq!(number(&group["variable_mask"]), mask);
                assert_eq!(number(&group["and_base"]) & mask, 0);
                assert_eq!(number(&group["and_base"]) >> 105, 0);
            }
        }
    }
}
