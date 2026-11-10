//! Legacy SYNCS A0TR AURI strict-row repair; raw nvdisasm evidence only, no GPU claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::path::Path;

const SRC: &str = "rows-hidden-b300-syncs-a0tr-auri-repair-2026-11-08";
const KEY: &str = "SYNCS_R_AURI_R";
const GROUP: &str = "A0TR,ARRIVE,RED,TRANS64";

fn fixtures(arch: &str) -> Vec<Value> {
    let text = match arch {
        "sm103a" => hb300_fixture("sm103_syncs_a0tr_auri_nvdisasm.jsonl"),
        "sm100a" => hb300_fixture("sm100_syncs_a0tr_auri_nvdisasm.jsonl"),
        _ => unreachable!(),
    };
    text.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn arches() -> Vec<&'static str> {
    match std::env::var("CUBIT_ARCH").as_deref() {
        Ok("sm103a") => vec!["sm103a"],
        Ok("sm100a") => vec!["sm100a"],
        Ok(other) => panic!("unsupported CUBIT_ARCH={other}"),
        Err(_) => vec!["sm103a", "sm100a"],
    }
}

fn table_path(arch: &str) -> String {
    std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz"))
}

fn table(arch: &str) -> IsaTable {
    IsaTable::load(Path::new(&table_path(arch))).unwrap()
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
fn measured_a0tr_auri_words_render_and_reencode_exactly() {
    for arch in arches() {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let mut adopted = 0;
        for row in fixtures(arch) {
            if row["role"] != "adopt" {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(word, 0, &table)
                .unwrap_or_else(|e| panic!("{arch} {} {vendor}: {e}", row["case"]));
            assert_eq!(decoded.key, KEY, "{arch} {}", row["case"]);
            assert_eq!(decoded.mod_group, GROUP, "{arch} {}", row["case"]);
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                vendor,
                "{arch} {}",
                row["case"]
            );
            assert_eq!(
                reencode(&table, word, vendor),
                word,
                "{arch} {}",
                row["case"]
            );
            adopted += 1;
        }
        assert_eq!(adopted, 89, "{arch}: incomplete positive fixture");
    }
}

#[test]
fn inert_and_vendor_refused_neighbours_fail_closed() {
    for arch in arches() {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let mut rejected = 0;
        let mut failures = Vec::new();
        for row in fixtures(arch) {
            if row["role"] != "reject" {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            if let Ok(decoded) = index.decode(word, 0, &table) {
                failures.push(format!(
                    "{} {word:032x}: {}:{} {}",
                    row["case"],
                    decoded.key,
                    decoded.mod_group,
                    cubit::printer::to_sass_lossless(&decoded)
                ));
            }
            rejected += 1;
        }
        assert_eq!(rejected, 37, "{arch}: incomplete negative fixture");
        assert!(
            failures.is_empty(),
            "{arch}: claimed fail-closed neighbours:\n{}",
            failures.join("\n")
        );
    }
}

#[test]
fn foreign_text_and_production_aruri_never_use_legacy_a0tr_auri() {
    for arch in arches() {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let mut foreign = 0;
        let mut production = 0;
        for row in fixtures(arch) {
            if row["role"] != "foreign" {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            if let Ok(decoded) = index.decode(word, 0, &table) {
                assert!(
                    !(decoded.key == KEY && decoded.mod_group == GROUP),
                    "{arch} {} misclaimed as legacy A0TR AURI",
                    row["case"]
                );
            }
            foreign += 1;
            production += (row["kind"] == "production-other-shape") as usize;
        }
        assert_eq!(foreign, 72, "{arch}: incomplete boundary fixture");
        assert_eq!(production, 51, "{arch}: incomplete A0TR production census");
    }
}

#[test]
fn replacement_has_eight_bit_ur_disjoint_fields_and_strict_provenance() {
    for arch in arches() {
        let path = table_path(arch);
        let loaded = table(arch);
        let raw: Value =
            serde_json::from_slice(&cubit::table::read_table_bytes(Path::new(&path)).unwrap())
                .unwrap();
        let group = &raw["instructions"][KEY]["mod_groups"][GROUP];
        assert_eq!(
            group["_src"], SRC,
            "{arch}: legacy row was not replaced by measured data"
        );
        assert!(group["count"].is_null());
        assert!(
            loaded.get(KEY, GROUP).unwrap().row_probe,
            "{arch}: broad matching must be disabled"
        );
        let number = |value: &Value| {
            u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
        };
        let mut fields_mask = 0u128;
        let fields = group["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 5);
        for field in fields {
            assert!(field.get("_src").is_none() || field["_src"] == SRC);
            let bits = ((1u128 << field["bits"].as_u64().unwrap()) - 1)
                << field["shift"].as_u64().unwrap();
            assert_eq!(fields_mask & bits, 0, "overlapping fields");
            fields_mask |= bits;
        }
        let ur = fields
            .iter()
            .find(|field| field["extraction"] == "sub_ur0")
            .unwrap();
        assert_eq!(ur["shift"].as_u64(), Some(64));
        assert_eq!(ur["bits"].as_u64(), Some(8), "bit72 is not part of UR");
        assert_eq!(number(&group["variable_mask"]), fields_mask);
        assert_eq!(number(&group["and_base"]) & fields_mask, 0);
        assert_eq!(number(&group["and_base"]) >> 105, 0);
        assert_eq!(number(&group["and_base"]) & 0xFFF, 0x9A7);
        assert_eq!((number(&group["and_base"]) >> 72) & 1, 0);
    }
}
