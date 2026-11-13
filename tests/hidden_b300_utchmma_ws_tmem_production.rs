//! Production UTCHMMA.WS leading-tmem descriptors; no GPU execution.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::{json, Value};
use std::sync::OnceLock;

const SOURCE: &str = "rows-utchmma-ws-tmem-production-2026-11-11";
const KEY: &str = "UTCHMMA_II_II_II_II_II_UP";

fn arches() -> [(&'static str, &'static str); 2] {
    [("sm103a", hb300_fixture("sm103a_utchmma_ws_tmem_production_nvdisasm.jsonl")),
     ("sm100a", hb300_fixture("sm100a_utchmma_ws_tmem_production_nvdisasm.jsonl"))]
}

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLES: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLES.get_or_init(|| arches().iter().map(|(arch, _)| {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    }).collect())
}

fn rows(fixture: &str) -> impl Iterator<Item = Value> + '_ {
    fixture.lines().map(|line| serde_json::from_str(line).unwrap())
}

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn encode_lossless(word: u128, text: &str, table: &IsaTable) -> u128 {
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

#[test]
fn production_and_measured_fields_decode_render_reencode() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let (mut production, mut adopt) = (0, 0);
        for row in rows(fixture) {
            if row["role"] != "adopt" { continue; }
            adopt += 1;
            production += usize::from(row["generation"] == "production");
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, KEY, "{arch} {word:032x}");
            assert_eq!(decoded.mod_group, "WS", "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass(&decoded), text, "{arch} {word:032x}");
            let lossless = cubit::printer::to_sass_lossless(&decoded);
            assert_eq!(encode_lossless(word, &lossless, table), word,
                       "{arch}: {word:032x} {text}");
        }
        assert_eq!(production, 78, "{arch}: all production pairs measured per target");
        assert_eq!(adopt, 1168, "{arch}: complete adopted matrix");
    }
}

#[test]
fn mixed_descriptor_row_has_exact_fields_exclusions_and_provenance() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["base_op"], "UTCHMMA");
        let group = &entry["mod_groups"]["WS"];
        assert_eq!(group["_src"], SOURCE, "{arch}");
        assert_eq!(group["_note"], raw["_meta"]["provenance"]["sources"][SOURCE]["note"]);
        assert_eq!(group["count"], Value::Null);
        assert_eq!(hex(&group["and_base"]), 0x000000000808000000ff0000000001eau128);
        assert_eq!(hex(&group["variable_mask"]), 0x00000000078000ff0000ffffff00fc00u128);
        assert_eq!(group["fields"], json!([
            {"bits":8,"extraction":"tdesc_ur","shift":24,"token_idx":1},
            {"bits":8,"extraction":"gdesc_ur","shift":32,"token_idx":2},
            {"bits":8,"extraction":"tmem_ur","shift":64,"token_idx":3},
            {"bits":8,"extraction":"tmem_ur","shift":40,"token_idx":4},
            {"bits":3,"extraction":"pred","shift":87,"token_idx":6},
            {"bits":1,"extraction":"neg","shift":90,"token_idx":6},
            {"bits":4,"extraction":"guard","shift":12,"token_idx":0},
            {"bits":2,"extraction":"dsel2","shift":10,"token_idx":1}
        ]));
        assert_eq!(group["claim_forbid"], json!([
            {"bits":2,"shift":10,"values":[0,3]}
        ]));
    }
}

#[test]
fn selector_exclusions_and_non_ws_tmem_are_distinct() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        for row in rows(fixture) {
            if row["role"] != "claim_forbidden" { continue; }
            let word = hex(&row["word"]);
            if let Ok(decoded) = index.decode(word, 0, table) {
                assert!(!(decoded.key == KEY && decoded.mod_group == "WS"),
                        "{arch}: unsupported WS descriptor selector {word:032x}");
            }
        }
        // The older BUG-104 non-WS form must not be affected by the WS repair.
        let word = 0x0001f2000f800006000804ff070099eau128;
        let decoded = index.decode(word, 0, table).unwrap();
        let text = cubit::printer::to_sass(&decoded);
        assert!(text.contains("UTCHMMA tmem[UR7], gdesc"), "{arch}: {text}");
        assert_eq!(encode_lossless(word, &cubit::printer::to_sass_lossless(&decoded), table), word);
        let mut exclusions = 0;
        for row in rows(fixture) {
            exclusions += usize::from(row["role"] == "claim_forbidden");
        }
        assert_eq!(exclusions, 2, "{arch}");
    }
}
