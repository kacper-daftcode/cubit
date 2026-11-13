//! Vendor-text STSM.8.MT168 forms on SM103a/SM100a; no GPU execution claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::path::Path;

const SRC: &str = "rows-hidden-b300-stsm8-mt168-2026-11-08";

fn fixtures(arch: &str) -> Vec<Value> {
    let text = match arch {
        "sm103a" => hb300_fixture("sm103_stsm8_mt168_nvdisasm.jsonl"),
        "sm100a" => hb300_fixture("sm100_stsm8_mt168_nvdisasm.jsonl"),
        _ => unreachable!(),
    };
    text.lines().map(|line| serde_json::from_str(line).unwrap()).collect()
}

fn table(arch: &str) -> IsaTable {
    IsaTable::load(Path::new(&std::env::var("CUBIT_TABLE")
        .unwrap_or_else(|_| format!("tables/{arch}.json.gz")))).unwrap()
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
fn production_and_operands_render_and_reencode_exactly() {
    for arch in ["sm103a", "sm100a"] {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let mut production = 0;
        for row in fixtures(arch) {
            if row["role"] != "adopt" { continue; }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, &table)
                .unwrap_or_else(|e| panic!("{arch} {word:032x}: {e}"));
            assert_eq!(decoded.key.as_str(), row["expected_key"].as_str().unwrap(), "{word:032x}");
            assert_eq!(decoded.mod_group.as_str(), row["expected_group"].as_str().unwrap());
            assert_eq!(cubit::printer::to_sass_lossless(&decoded).replace(".reuse", ""), vendor);
            assert_eq!(reencode(&table, word, vendor), word, "{vendor}");
            production += (row["kind"] == "production") as usize;
        }
        assert!(production > 300, "{arch}: incomplete production fixture: {production}");
    }
}

#[test]
fn existing_stsm16_anchor_is_unchanged() {
    for arch in ["sm103a", "sm100a"] {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let word = 0x844u128 | (1u128 << 73) | (8u128 << 24) | (4u128 << 32);
        let vendor = "@P0 STSM.16.M88.4 [R8], R4";
        let decoded = index.decode(word, 0, &table).unwrap();
        assert_eq!(decoded.key.as_str(), "STSM_ARI_R");
        assert_eq!(decoded.mod_group.as_str(), "16,4,M88");
        assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor);
        assert_eq!(reencode(&table, word, vendor), word);
    }
}

#[test]
fn invalid_and_unmeasured_neighbors_stay_unclaimed() {
    for arch in ["sm103a", "sm100a"] {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let mut migrated_16 = 0;
        for row in fixtures(arch) {
            if !matches!(row["role"].as_str(), Some("reject" | "reject-scoped")) { continue; }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            if row["kind"] == "existing-16-aruri" {
                // The independently measured .16.MT88.4 ARURI family owns
                // exactly these 24 prior scoped negatives on each target.
                let decoded = index.decode(word, 0, &table).unwrap();
                assert_eq!(decoded.key, "STSM_ARURI_R");
                assert_eq!(decoded.mod_group, "16,4,MT88");
                let vendor = row["nvidia_sass"].as_str().unwrap();
                assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor);
                assert_eq!(reencode(&table, word, vendor), word);
                migrated_16 += 1;
                continue;
            }
            assert!(index.decode(word, 0, &table).is_err(), "claimed {arch} {word:032x}");
        }
        assert_eq!(migrated_16, 24, "{arch}: unexpected .16 migration scope");
    }
}

#[test]
fn new_rows_have_provenance_and_disjoint_fail_closed_fields() {
    for arch in ["sm103a", "sm100a"] {
        let path = std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz"));
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(Path::new(&path)).unwrap()).unwrap();
        for key in ["STSM_ARI_R", "STSM_ARURI_R"] {
            for (name, group) in raw["instructions"][key]["mod_groups"].as_object().unwrap() {
                // The separately sourced .16 group is outside this .8 family.
                if key == "STSM_ARURI_R" && name == "16,4,MT88" { continue; }
                if key == "STSM_ARI_R" && !name.contains("8,MT168") { continue; }
                assert_eq!(group["_src"], SRC, "{key}:{name}");
                assert!(group["count"].is_null());
                assert_eq!(group["row_probe"], true, "{key}:{name}: broad fallback must stay closed");
                let number = |v: &Value| u128::from_str_radix(
                    v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
                let mut mask = 0u128;
                for field in group["fields"].as_array().unwrap() {
                    // the canonical layout writes a tag once per level (tools/tablefmt.py): a field carries `_src` only where it
                    // differs from its row's -- absent or equal (the candidate's file tagged every field)
                    assert!(field.get("_src").map_or(true, |s| s == SRC));
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
        assert!(!raw["instructions"]["STSM_ARI_R"]["mod_groups"]
            .as_object().unwrap().contains_key("16,ARURI"));
    }
}
