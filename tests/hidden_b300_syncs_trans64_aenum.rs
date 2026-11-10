//! SYNCS.ARRIVE.TRANS64 A-selector forms measured on SM103/SM100; no GPU claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::path::Path;

const SRC: &str = "rows-hidden-b300-syncs-trans64-aenum-2026-11-08";

fn fixtures(arch: &str) -> Vec<Value> {
    let text = match arch {
        "sm103a" => hb300_fixture("sm103_syncs_trans64_aenum_nvdisasm.jsonl"),
        "sm100a" => hb300_fixture("sm100_syncs_trans64_aenum_nvdisasm.jsonl"),
        _ => unreachable!(),
    };
    text.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn table(arch: &str) -> IsaTable {
    IsaTable::load(Path::new(
        &std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz")),
    ))
    .unwrap()
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
fn production_and_selector_forms_render_and_reencode_exactly() {
    for arch in ["sm103a", "sm100a"] {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let mut production = 0;
        let mut adopted = 0;
        let mut existing = 0;
        for row in fixtures(arch) {
            if !matches!(row["role"].as_str(), Some("adopt" | "existing")) {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(word, 0, &table)
                .unwrap_or_else(|e| panic!("{arch} {} {vendor}: {e}", row["case"]));
            assert_eq!(
                decoded.key.as_str(),
                row["expected_key"].as_str().unwrap(),
                "{arch} {} {vendor}",
                row["case"]
            );
            assert_eq!(
                decoded.mod_group.as_str(),
                row["expected_group"].as_str().unwrap(),
                "{arch} {} {vendor}",
                row["case"]
            );
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                vendor,
                "{arch} {} {word:032x}",
                row["case"]
            );
            assert_eq!(
                reencode(&table, word, vendor),
                word,
                "{arch} {} {vendor}",
                row["case"]
            );
            production += (row["kind"] == "production") as usize;
            adopted += (row["role"] == "adopt") as usize;
            existing += (row["role"] == "existing") as usize;
        }
        assert_eq!(production, if arch == "sm103a" { 56 } else { 54 });
        assert!(
            adopted >= 348,
            "{arch}: incomplete adopted fixture: {adopted}"
        );
        assert_eq!(
            existing, 2,
            "{arch}: the old A0TR AURI anchor must stay intact"
        );
    }
}

#[test]
fn invalid_selectors_tmask_and_inert_neighbours_stay_unclaimed() {
    for arch in ["sm103a", "sm100a"] {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let mut rejects = 0;
        for row in fixtures(arch) {
            if row["role"] != "reject" {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            assert!(
                index.decode(word, 0, &table).is_err(),
                "claimed {arch} {} {word:032x} ({})",
                row["case"],
                row["nvidia_sass"]
            );
            rejects += 1;
        }
        assert_eq!(rejects, 114, "{arch}: incomplete negative fixture");
    }
}

#[test]
fn exactly_fifteen_new_rows_per_key_set_have_fail_closed_provenance() {
    for arch in ["sm103a", "sm100a"] {
        let path =
            std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz"));
        let loaded = table(arch);
        let raw: Value =
            serde_json::from_slice(&cubit::table::read_table_bytes(Path::new(&path)).unwrap())
                .unwrap();
        let mut new_rows = 0;
        for key in ["SYNCS_R_AURI_R", "SYNCS_R_ARURI_R"] {
            for (name, group) in raw["instructions"][key]["mod_groups"].as_object().unwrap() {
                if group["_src"] != SRC {
                    continue;
                }
                new_rows += 1;
                assert!(
                    name.contains("ARRIVE") && name.contains("RED") && name.contains("TRANS64")
                );
                assert!(["A0T1", "A0TR", "A0TX", "ART0"]
                    .iter()
                    .any(|a| name.contains(a)));
                assert_eq!(group["count"].is_null(), true);
                assert!(
                    loaded.get(key, name).unwrap().row_probe,
                    "{key}:{name}: broad matching must stay disabled"
                );
                let number = |v: &Value| {
                    u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
                };
                let mut fields_mask = 0u128;
                for field in group["fields"].as_array().unwrap() {
                    assert!(
                        field.get("_src").is_none() || field["_src"] == SRC,
                        "unexpected field-level provenance"
                    );
                    let bits = ((1u128 << field["bits"].as_u64().unwrap()) - 1)
                        << field["shift"].as_u64().unwrap();
                    assert_eq!(fields_mask & bits, 0, "overlapping fields");
                    fields_mask |= bits;
                }
                assert_eq!(number(&group["variable_mask"]), fields_mask);
                assert_eq!(number(&group["and_base"]) & fields_mask, 0);
                assert_eq!(number(&group["and_base"]) >> 105, 0);
            }
        }
        assert_eq!(
            new_rows, 15,
            "{arch}: changed provenance must be exactly the measured scope"
        );
        assert!(
            raw["instructions"]["SYNCS_R_AURI_R"]["mod_groups"]["A0TR,ARRIVE,RED,TRANS64"]["_src"]
                != SRC,
            "the existing A0TR AURI row is not part of this change"
        );
    }
}
