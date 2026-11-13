//! Production STSM.16.MT88.4 ARURI evidence; no GPU execution claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

const SRC: &str = "rows-hidden-b300-stsm16-mt88-x4-aruri-production-2026-11-11";
const OLD_SRC: &str = "rows-hidden-b300-stsm8-mt168-2026-11-08";
const KEY: &str = "STSM_ARURI_R";
const GROUP: &str = "16,4,MT88";

fn fixture(arch: &str) -> &'static str {
    match arch {
        "sm103a" => hb300_fixture("sm103a_stsm16_mt88_x4_aruri_production_nvdisasm.jsonl"),
        "sm100a" => hb300_fixture("sm100a_stsm16_mt88_x4_aruri_production_nvdisasm.jsonl"),
        _ => unreachable!(),
    }
}

fn rows(arch: &str) -> impl Iterator<Item = Value> {
    fixture(arch).lines().map(|line| serde_json::from_str(line).unwrap())
}

fn table(arch: &str) -> IsaTable {
    let path = std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz"));
    IsaTable::load(Path::new(&path)).unwrap()
}

fn raw_table(arch: &str) -> Value {
    let path = std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz"));
    serde_json::from_slice(&cubit::table::read_table_bytes(Path::new(&path)).unwrap()).unwrap()
}

fn word(row: &Value) -> u128 {
    u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap()
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

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

#[test]
fn production_and_full_operand_domains_render_and_reencode_exactly() {
    for arch in ["sm103a", "sm100a"] {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let mut production = 0;
        let mut guards = BTreeSet::new();
        let mut domains: [BTreeSet<u8>; 6] = Default::default();
        let mut adopted: Vec<Value> = rows(arch)
            .filter(|row| row["role"] == "adopt")
            .collect();
        adopted.sort_by_key(|row| (row["kind"] != "production", word(row)));
        for row in adopted {
            let word = word(&row);
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, &table)
                .unwrap_or_else(|e| panic!("{arch} {word:032x}: {e}"));
            assert_eq!(decoded.key, KEY, "{arch} {word:032x}");
            assert_eq!(decoded.mod_group, GROUP, "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{arch} {word:032x}");
            assert_eq!(reencode(&table, word, vendor), word, "{arch} {word:032x} {vendor}");
            production += usize::from(row["kind"] == "production");
            guards.insert(((word >> 12) & 15) as u8);
            for label in row["labels"].as_array().unwrap() {
                let label = label.as_str().unwrap();
                let prefixes = ["base=", "data=", "ur=", "imm-b0=", "imm-b1=", "imm-b2="];
                for (slot, prefix) in prefixes.iter().enumerate() {
                    if let Some(value) = label.strip_prefix(prefix) {
                        domains[slot].insert(value.parse::<u8>().unwrap());
                    }
                }
            }
        }
        assert_eq!(production, 24, "{arch}: exact production count");
        assert_eq!(guards.len(), 16, "{arch}: all guards");
        for (slot, domain) in domains.iter().enumerate() {
            assert_eq!(domain.len(), 256, "{arch}: domain {slot} is incomplete");
        }
    }
}

#[test]
fn invalid_and_unmeasured_aruri_neighbors_stay_fail_closed() {
    for arch in ["sm103a", "sm100a"] {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let mut checked = 0;
        for row in rows(arch) {
            if !matches!(row["role"].as_str(), Some("reject" | "scoped-reject")) { continue; }
            let word = word(&row);
            assert!(index.decode(word, 0, &table).is_err(),
                    "{arch}: overclaimed {word:032x} role={} sass={:?}",
                    row["role"], row["nvidia_sass"]);
            checked += 1;
        }
        assert!(checked > 0, "{arch}: no fail-closed witnesses");
    }
}

#[test]
fn exactly_one_sourced_group_and_existing_stsm8_siblings_are_preserved() {
    for arch in ["sm103a", "sm100a"] {
        let raw = raw_table(arch);
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 1);
        assert_eq!(raw["_meta"]["provenance"]["sources"][OLD_SRC]["rows"], 6);
        let entry = &raw["instructions"][KEY];
        let groups = entry["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), 4, "{arch}: sibling group set changed");
        for sibling in ["8,MT168", "2,8,MT168", "4,8,MT168"] {
            assert_eq!(groups[sibling]["_src"], OLD_SRC, "{arch}: {sibling} changed");
        }
        let group = &groups[GROUP];
        assert_eq!(group["_src"], SRC);
        assert_eq!(group["count"], Value::Null);
        assert_eq!(group["row_probe"], true);
        let expected = [
            (12, 4, "guard", 0), (24, 8, "sub_r0", 1), (40, 24, "sub_imm2", 1),
            (32, 8, "reg", 2), (64, 8, "sub_ur1", 1),
        ];
        let fields = group["fields"].as_array().unwrap();
        assert_eq!(fields.len(), expected.len());
        let mut mask = 0u128;
        for (field, &(shift, bits, extraction, token)) in fields.iter().zip(&expected) {
            assert_eq!(field["shift"], shift);
            assert_eq!(field["bits"], bits);
            assert_eq!(field["extraction"], extraction);
            assert_eq!(field["token_idx"], token);
            assert!(field.get("_src").is_none_or(|src| src == SRC));
            let part = ((1u128 << bits) - 1) << shift;
            assert_eq!(mask & part, 0);
            mask |= part;
        }
        assert_eq!(hex(&group["variable_mask"]), mask);
        let base = hex(&group["and_base"]);
        assert_eq!(base & mask, 0);
        assert_eq!(base >> 105, 0);
        assert_ne!(base & (1u128 << 91), 0);

        // This pre-existing .8 word was accepted before the new group.
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let old = 0x00000000080088000000000000000844u128;
        let decoded = index.decode(old, 0, &table).unwrap();
        assert_eq!(decoded.key, KEY);
        assert_eq!(decoded.mod_group, "8,MT168");
    }
}
