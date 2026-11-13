//! Production BAR opcode 0x091d; vendor text/CPU, not barrier execution.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-bar-arv-defer-production-2026-11-11";
const EXPECTED_ADOPT: usize = 683;
const EXPECTED_PRODUCTION: usize = 31;
const GROUPS: [(&str, &str, &str, &str, &str, usize, bool); 3] = [
    ("arv_reg", "BAR_II_R", "ARV",
     "0x0000000000002000000000000000091d",
     "0x000000000000000003c000ff0000f000", 3, true),
    ("sync_reg", "BAR_II_R", "DEFER_BLOCKING,SYNC",
     "0x0000000000010000000000000000091d",
     "0x000000000000000003c000ff0000f000", 3, true),
    ("sync_single", "BAR_II", "DEFER_BLOCKING,SYNC",
     "0x0000000000010000000000ff0000091d",
     "0x000000000000000003c000000000f000", 2, false),
];

fn arches() -> [(&'static str, &'static str); 2] {
    [
        ("sm103a", hb300_fixture("sm103a_bar_arv_defer_production_nvdisasm.jsonl")),
        ("sm100a", hb300_fixture("sm100a_bar_arv_defer_production_nvdisasm.jsonl")),
    ]
}

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLES: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLES.get_or_init(|| {
        arches().iter().map(|(arch, _)| {
            let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
            (DecodeIndex::build(&table), table)
        }).map(|(index, table)| (table, index)).collect()
    })
}

fn rows(fixture: &str) -> impl Iterator<Item = Value> + '_ {
    fixture.lines().map(|line| serde_json::from_str(line).unwrap())
}

fn word(row: &Value) -> u128 {
    u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap()
}

fn expected_group(text: &str) -> (&'static str, &'static str) {
    let body = if text.starts_with('@') {
        text.split_once(' ').unwrap().1
    } else {
        text
    };
    if body.starts_with("BAR.ARV ") {
        assert!(body.contains(", R"), "adopted ARV count is not a register: {text}");
        ("BAR_II_R", "ARV")
    } else if body.starts_with("BAR.SYNC.DEFER_BLOCKING ") && body.contains(", R") {
        ("BAR_II_R", "DEFER_BLOCKING,SYNC")
    } else if body.starts_with("BAR.SYNC.DEFER_BLOCKING ") {
        assert!(!body.contains(", RZ"), "unexpected explicit RZ: {text}");
        ("BAR_II", "DEFER_BLOCKING,SYNC")
    } else {
        panic!("adopted non-target text: {text}")
    }
}

#[test]
fn production_and_measured_fields_decode_render_reencode() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let mut production = 0;
        let mut adopted = 0;
        for row in rows(fixture) {
            if row["role"] != "adopt" { continue; }
            let text = row["nvidia_sass"].as_str().unwrap();
            let (key, group) = expected_group(text);
            let word = word(&row);
            let decoded = index.decode(word, 0, table)
                .unwrap_or_else(|e| panic!("{arch} {word:032x}: {e}"));
            assert_eq!(decoded.key, key);
            assert_eq!(decoded.mod_group, group);
            assert_eq!(cubit::printer::to_sass(&decoded), text, "{arch} {word:032x}");
            let lossless = cubit::printer::to_sass_lossless(&decoded);
            let control = cubit::scheduling::format_control_code(
                &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let parsed = cubit::parse_cuasm_line(&format!("[{control}] {lossless} ;"), 0).unwrap();
            assert_eq!(cubit::encoder::encode_instruction(&parsed, table).unwrap(),
                       word & !(7u128 << 125), "{arch}: {word:032x} {text}");
            adopted += 1;
            production += usize::from(row["generation"] == "production");
        }
        assert_eq!(production, EXPECTED_PRODUCTION, "{arch}");
        assert_eq!(adopted, EXPECTED_ADOPT, "{arch}");
    }
}

#[test]
fn exact_fields_provenance_and_scheduling() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 3);
        for (label, key, group, base, mask, field_count, forbid_rz) in GROUPS {
            let entry = &raw["instructions"][key];
            let row = &entry["mod_groups"][group];
            if key == "BAR_II" {
                assert_eq!(row["_src"], SOURCE, "{arch}: {label}");
            } else {
                assert_eq!(entry["_src"], SOURCE, "{arch}: {label}");
            }
            assert_eq!(entry["scheduling"]["pipe_name"], "UNKNOWN");
            assert_eq!(row["count"], Value::Null);
            assert_eq!(row["and_base"], json_string(base));
            assert_eq!(row["variable_mask"], json_string(mask));
            assert_eq!(row["fields"].as_array().unwrap().len(), field_count);
            assert!(row["fields"].as_array().unwrap().iter().any(|field|
                field["shift"] == 12 && field["bits"] == 4 &&
                field["extraction"] == "guard" && field["token_idx"] == 0));
            assert!(row["fields"].as_array().unwrap().iter().any(|field|
                field["shift"] == 54 && field["bits"] == 4 &&
                field["extraction"] == "imm" && field["token_idx"] == 1));
            let rz = row["claim_forbid"].as_array().unwrap().iter().any(|claim|
                claim["shift"] == 32 && claim["bits"] == 8 &&
                claim["values"].as_array().unwrap().contains(&Value::from(255)));
            assert_eq!(rz, forbid_rz, "{arch}: {label}: {}", row["claim_forbid"]);
            if field_count == 3 {
                assert!(row["fields"].as_array().unwrap().iter().any(|field|
                    field["shift"] == 32 && field["bits"] == 8 &&
                    field["extraction"] == "reg" && field["token_idx"] == 2));
            }
        }
    }
}

fn json_string(value: &str) -> Value { Value::String(value.to_string()) }

#[test]
fn adjacent_negative_and_unclaimed_text_fail_closed() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        for row in rows(fixture) {
            let role = row["role"].as_str().unwrap();
            if ["adopt", "other_family", "control"].contains(&role) { continue; }
            if let Ok(decoded) = index.decode(word(&row), 0, table) {
                assert!(decoded.key != "BAR_II_R" &&
                        !(decoded.key == "BAR_II" && decoded.mod_group == "DEFER_BLOCKING,SYNC"),
                        "{arch}: wrong new row {} {} {role} -> {} {}",
                        row["word"], row["label"], decoded.key, decoded.mod_group);
            }
        }
    }
}
