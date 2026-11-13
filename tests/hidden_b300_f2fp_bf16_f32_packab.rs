//! Production BF16/F32 PACK_AB SATFINITE/RELU forms, without GPU execution.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-f2fp-bf16-f32-packab-production-2026-11-10";
const GROUPS: [&str; 3] = [
    "BF16,F32,PACK_AB,SATFINITE",
    "BF16,F32,PACK_AB,RELU",
    "BF16,F32,PACK_AB,RELU,SATFINITE",
];
const EXPECTED_POSITIVE: usize = 2808;
const EXPECTED_NEGATIVE: usize = 58;
const EXPECTED_ADJACENT: usize = 3;
const EXPECTED_OTHER: usize = 5;

fn arches() -> [(&'static str, &'static str); 2] {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_f2fp_bf16_f32_packab_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_f2fp_bf16_f32_packab_nvdisasm.jsonl"),
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

fn group_for_word(word: u128) -> &'static str {
    match ((word >> 77) & 1, (word >> 75) & 1) {
        (1, 0) => GROUPS[0],
        (0, 1) => GROUPS[1],
        (1, 1) => GROUPS[2],
        _ => panic!("positive word is outside adopted modifier groups"),
    }
}

fn roundtrip(table: &IsaTable, index: &DecodeIndex, arch: &str, row: &Value) {
    let word = hex(&row["word"]);
    let text = row["nvidia_sass"].as_str().unwrap();
    let decoded = index
        .decode(word, 0, table)
        .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
    assert_eq!(decoded.key, "F2FP_R_R_R");
    assert_eq!(decoded.mod_group, group_for_word(word));
    assert_eq!(cubit::printer::to_sass(&decoded), text);
    // Lossless output carries reuse hints hidden by vendor when yield=0;
    // use it for full-word encoding, but compare vendor text above.
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
        "{arch}: encode {word:032x} {text}"
    );
}

#[test]
fn production_and_measured_fields_roundtrip() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let (mut production, mut positive) = (0, 0);
        for row in rows(fixture) {
            if row["kind"] == "positive" {
                positive += 1;
                production += usize::from(row["generation"] == "production");
                roundtrip(table, index, arch, &row);
            }
        }
        assert_eq!(
            production, 453,
            "{arch}: complete unique-word production census"
        );
        assert_eq!(positive, EXPECTED_POSITIVE, "{arch}: positive census");
    }
}

#[test]
fn three_modifier_groups_fields_and_provenance() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 3);
        let entry = &raw["instructions"]["F2FP_R_R_R"];
        for group_name in GROUPS {
            let group = &entry["mod_groups"][group_name];
            assert_eq!(group["_src"], SOURCE, "{arch}: {group_name}");
            assert!(group["count"].is_null());
            let expected_mask =
                (0xfu128 << 12) | (0xffu128 << 16) | (0xffu128 << 24) | (0xffu128 << 32);
            assert_eq!(hex(&group["variable_mask"]), expected_mask);
            for (shift, bits, extraction, token) in [
                (12, 4, "guard", 0),
                (16, 8, "reg", 1),
                (24, 8, "reg", 2),
                (32, 8, "reg", 3),
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
                    "{arch}: {group_name}: {extraction}@{shift}/{bits}"
                );
            }
            assert!(group.get("claim_forbid").is_none());
        }
    }
}

#[test]
fn adjacent_and_unlicensed_encodings_do_not_enter_new_rows() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let (mut negative, mut adjacent, mut other, mut control, mut existing) = (0, 0, 0, 0, 0);
        for row in rows(fixture) {
            let kind = row["kind"].as_str().unwrap();
            if kind == "positive" {
                continue;
            }
            match kind {
                "negative" => negative += 1,
                "adjacent_modifier" => adjacent += 1,
                "other_family" => other += 1,
                "control_plane" => {
                    control += 1;
                    continue;
                }
                "existing_form" => existing += 1,
                other => panic!("unexpected kind {other}"),
            }
            let word = hex(&row["word"]);
            if let Ok(decoded) = index.decode(word, 0, table) {
                assert!(
                    !GROUPS.contains(&decoded.mod_group.as_str()),
                    "{arch} overmatch {kind} {word:032x}: {}",
                    decoded.mod_group
                );
            }
        }
        assert_eq!(
            (negative, adjacent, other),
            (EXPECTED_NEGATIVE, EXPECTED_ADJACENT, EXPECTED_OTHER)
        );
        assert!(
            control > 0 && existing > 0,
            "{arch}: retained control and existing-form census"
        );
    }
}
