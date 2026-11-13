//! Measured production E8/F32 PACK_AB_MERGE_C RZ; no execution or numeric claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-f2fp-e8-pack-merge-rz-production-2026-11-11";
const KEY: &str = "F2FP_R_R_R_R";
const GROUP: &str = "E8,F32,PACK_AB_MERGE_C,RZ";

fn arches() -> [(&'static str, &'static str); 2] {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_f2fp_e8_pack_merge_rz_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_f2fp_e8_pack_merge_rz_nvdisasm.jsonl"),
        ),
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

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn roundtrip(table: &IsaTable, index: &DecodeIndex, arch: &str, row: &Value) {
    let word = hex(&row["word"]);
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
    let encoded = cubit::encoder::encode_instruction(&parsed, table)
        .unwrap_or_else(|error| panic!("{arch}: encode {word:032x} {text}: {error}"));
    assert_eq!(
        encoded,
        word & !(7u128 << 125),
        "{arch}: {word:032x} {text}"
    );
}

#[test]
fn production_and_all_measured_fields_decode_render_reencode() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let (mut production, mut adopt) = (0, 0);
        for row in rows(fixture) {
            if row["role"] == "adopt" {
                adopt += 1;
                production += usize::from(row["generation"] == "production");
                roundtrip(table, index, arch, &row);
            }
        }
        assert_eq!(production, 6, "{arch}: complete distinct production words");
        assert_eq!(adopt, 1073, "{arch}: adopted measured positives");
    }
}

#[test]
fn exact_row_fields_reuse_bindings_and_provenance() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let group = &raw["instructions"][KEY]["mod_groups"][GROUP];
        assert_eq!(group["_src"], SOURCE, "{arch}");
        assert!(raw["_meta"]["provenance"]["sources"][SOURCE]["note"]
            .as_str()
            .unwrap()
            .contains("7 observations and 6 distinct"));
        assert!(group["count"].is_null());
        assert_eq!(
            hex(&group["and_base"]),
            0x0000000004c1c000000000000000023eu128
        );
        assert_eq!(
            hex(&group["variable_mask"]),
            0x1c000000000000ff000000fffffff000u128
        );
        for (shift, bits, extraction, token) in [
            (12, 4, "guard", 0),
            (16, 8, "reg", 1),
            (24, 8, "reg", 2),
            (32, 8, "reg", 3),
            (64, 8, "reg", 4),
            (122, 1, "reuse", 2),
            (123, 1, "reuse", 3),
            (124, 1, "reuse", 4),
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
        assert_eq!(group["fields"].as_array().unwrap().len(), 8);
        assert!(group["claim_forbid"].as_array().unwrap().is_empty());
    }
}

#[test]
fn adjacent_text_inert_and_unlicensed_encodings_fail_closed() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let (mut negative, mut forbidden, mut adjacent, mut other, mut inert, mut control) =
            (0, 0, 0, 0, 0, 0);
        for row in rows(fixture) {
            let role = row["role"].as_str().unwrap();
            if role == "adopt" {
                continue;
            }
            let word = hex(&row["word"]);
            match role {
                "negative" | "claim_forbidden" | "unclaimed_text_inert" => {
                    match role {
                        "negative" => negative += 1,
                        "claim_forbidden" => forbidden += 1,
                        _ => inert += 1,
                    }
                    if let Ok(decoded) = index.decode(word, 0, table) {
                        assert_ne!(
                            decoded.mod_group, GROUP,
                            "{arch}: wrong-group overmatch {role} {word:032x}"
                        );
                    }
                }
                "adjacent_modifier" => {
                    adjacent += 1;
                    if let Ok(decoded) = index.decode(word, 0, table) {
                        assert_ne!(
                            decoded.mod_group, GROUP,
                            "{arch}: wrong adjacent group {word:032x}"
                        );
                    }
                }
                "other_family" => other += 1,
                "control" => control += 1,
                other => panic!("unexpected role {other}"),
            }
        }
        assert_eq!(
            (negative, forbidden, adjacent, other, inert),
            (46, 0, 9, 5, 30)
        );
        assert_eq!(control, 37, "{arch}: retained control-plane census");
    }
}
