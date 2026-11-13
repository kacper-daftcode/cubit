//! Production LDL.LU.S16 local-load form; text/CPU, not execution semantics.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-ldl-lu-s16-production-2026-11-11";
const KEY: &str = "LDL_R_ARI";
const GROUP: &str = "LU,S16";
const EXPECTED_ADOPT: usize = 734;
const EXPECTED_AND_BASE: &str = "0x00000000003006000000000000000983";
const EXPECTED_MASK: &str = "0x0000000000000000ffffff00fffff000";

fn arches() -> [(&'static str, &'static str); 2] {
    [
        ("sm103a", hb300_fixture("sm103a_ldl_lu_s16_nvdisasm.jsonl")),
        ("sm100a", hb300_fixture("sm100a_ldl_lu_s16_nvdisasm.jsonl")),
    ]
}

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLES: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLES.get_or_init(|| {
        arches()
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

fn rows(fixture: &str) -> impl Iterator<Item = Value> + '_ {
    fixture
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
}

fn word(row: &Value) -> u128 {
    u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap()
}

fn roundtrip(table: &IsaTable, index: &DecodeIndex, arch: &str, row: &Value) {
    let word = word(row);
    let text = row["nvidia_sass"].as_str().unwrap();
    let decoded = index
        .decode(word, 0, table)
        .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
    assert_eq!(decoded.key, KEY);
    assert_eq!(decoded.mod_group, GROUP);
    assert_eq!(
        cubit::printer::to_sass(&decoded),
        text,
        "{arch} {word:032x}"
    );
    let lossless = cubit::printer::to_sass_lossless(&decoded);
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {lossless} ;"), 0).unwrap();
    assert_eq!(
        cubit::encoder::encode_instruction(&parsed, table).unwrap(),
        word & !(7u128 << 125),
        "{arch}: {word:032x} {text}"
    );
}

#[test]
fn production_and_measured_fields_decode_render_reencode() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let mut production = 0;
        let mut adopted = 0;
        for row in rows(fixture) {
            if row["role"] == "adopt" {
                adopted += 1;
                production += usize::from(row["generation"] == "production");
                roundtrip(table, index, arch, &row);
            }
        }
        assert_eq!(production, 88, "{arch}");
        assert_eq!(adopted, EXPECTED_ADOPT, "{arch}");
    }
}

#[test]
fn exact_fields_provenance_and_scheduling() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["scheduling"]["pipe_name"], "UNKNOWN");
        let group = &entry["mod_groups"][GROUP];
        assert_eq!(group["_src"], SOURCE);
        assert_eq!(group["count"], Value::Null);
        assert_eq!(group["and_base"], json_string(EXPECTED_AND_BASE));
        assert_eq!(group["variable_mask"], json_string(EXPECTED_MASK));
        for (shift, bits, extraction, token) in [
            (12, 4, "guard", 0),
            (16, 8, "reg", 1),
            (24, 8, "sub_r0", 2),
            (40, 24, "sub_imm1", 2),
        ] {
            assert!(
                group["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|field| field["shift"] == shift
                        && field["bits"] == bits
                        && field["extraction"] == extraction
                        && field["token_idx"] == token),
                "{arch}: {extraction}@{shift}/{bits}"
            );
        }
        assert_eq!(group["fields"].as_array().unwrap().len(), 4);
        assert!(raw["_meta"]["provenance"]["sources"][SOURCE]["note"]
            .as_str()
            .unwrap()
            .contains("89 observations and 88 distinct"));
        for rule in group["claim_forbid"].as_array().unwrap() {
            assert_eq!(rule["values"], serde_json::json!([1]));
            assert!([122, 123, 124].contains(&rule["shift"].as_u64().unwrap()));
        }
    }
}

fn json_string(value: &str) -> Value {
    Value::String(value.to_string())
}

#[test]
fn adjacent_negative_and_unclaimed_text_fail_closed() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        for row in rows(fixture) {
            if row["role"] == "adopt" || row["role"] == "other_family" || row["role"] == "control" {
                continue;
            }
            if let Ok(decoded) = index.decode(word(&row), 0, table) {
                assert_ne!(
                    decoded.mod_group,
                    GROUP,
                    "{arch}: wrong group {} {role}",
                    row["word"],
                    role = row["role"].as_str().unwrap()
                );
            }
        }
    }
}
