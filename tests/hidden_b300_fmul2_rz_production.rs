//! Production FMUL2.RZ paired-register/scalar-source form, without GPU execution.
include!("hb300_fixture.inc");
include!("engine_l1_controls.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "engine-l1a-fmul2-shapes-2026-11-13";
const GROUPS: [&str; 1] = ["RZ"];
const EXPECTED_POSITIVE: usize = 847;
const EXPECTED_NEGATIVE: usize = 58;
const EXPECTED_ADJACENT: usize = 16;
const EXPECTED_OTHER: usize = 4;
const EXPECTED_CONTROL: usize = 36;

fn arches() -> [(&'static str, &'static str); 2] {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_fmul2_rz_production_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_fmul2_rz_production_nvdisasm.jsonl"),
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
    assert_eq!((word >> 78) & 0x3, 0x3);
    assert_eq!((word >> 88) & 1, 1);
    assert_eq!((word >> 82) & 1, 0);
    assert_eq!((word >> 122) & 1, 0);
    GROUPS[0]
}

fn roundtrip(table: &IsaTable, index: &DecodeIndex, arch: &str, row: &Value) {
    let word = hex(&row["word"]);
    let text = row["nvidia_sass"].as_str().unwrap();
    let decoded = index
        .decode(word, 0, table)
        .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
    assert_eq!(decoded.key, "FMUL2_R_R_R");
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
            production, 64,
            "{arch}: complete unique-word production census"
        );
        assert_eq!(positive, EXPECTED_POSITIVE, "{arch}: positive census");
    }
}

#[test]
fn one_modifier_group_fields_and_provenance() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 2);
        let entry = &raw["instructions"]["FMUL2_R_R_R"];
        for group_name in GROUPS {
            let group = &entry["mod_groups"][group_name];
            assert_eq!(group["_src"], SOURCE, "{arch}: {group_name}");
            assert!(group["count"].is_null());
            let expected_mask = (0xfu128 << 12)
                | (0xffu128 << 16)
                | (0xffu128 << 24)
                | (0xffu128 << 32)
                | (3u128 << 62)
                | (3u128 << 72)
                | (1u128 << 81)
                | (1u128 << 123);
            assert_eq!(hex(&group["variable_mask"]), expected_mask);
            for (shift, bits, extraction, token) in [
                (12, 4, "guard", 0),
                (16, 8, "reg", 1),
                (24, 8, "reg", 2),
                (72, 1, "neg", 2),
                (73, 1, "abs", 2),
                (81, 1, "opmod:LO_HI", 2),
                (32, 8, "reg", 3),
                (62, 1, "abs", 3),
                (63, 1, "neg", 3),
                (123, 1, "reuse", 3),
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
            assert_eq!(group["claim_forbid"].as_array().unwrap().len(), 5);
            for (shift, value) in [(83, 1), (122, 1), (124, 1)] {
                assert!(
                    group["claim_forbid"].as_array().unwrap().iter().any(|cf| {
                        cf["bits"] == 1 && cf["shift"] == shift && cf["values"][0] == value
                    }),
                    "{arch}: missing RZ prohibition at {shift}"
                );
            }
            assert_eq!(group["fields"].as_array().unwrap().len(), 10);
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
                "claim_forbidden" => {
                    negative += 1;
                    if row["label"].as_str().unwrap().starts_with("reuse:") {
                        assert!(index.decode(hex(&row["word"]), 0, table).is_err());
                    }
                    continue;
                }
                "adjacent_modifier" => adjacent += 1,
                "other_family" => other += 1,
                "silicon_candidate" => {
                    if let Ok(decoded) = index.decode(hex(&row["word"]), 0, table) {
                        assert_ne!(decoded.mod_group, GROUPS[0], "{arch}: unnamed overmatch");
                    }
                    continue;
                }
                "control_plane" => {
                    control += 1;
                    continue;
                }
                "existing_form" => existing += 1,
                "reuse_control" => {
                    let word = hex(&row["word"]);
                    if let Ok(decoded) = index.decode(word, 0, table) {
                        assert_ne!(decoded.mod_group, GROUPS[0], "{arch}: reuse overmatch");
                    }
                    continue;
                }
                other => panic!("unexpected kind {other}"),
            }
            let word = hex(&row["word"]);
            if let Ok(decoded) = index.decode(word, 0, table) {
                if e2_consolidated_control(&row, "FMUL2_R_R_R", &decoded.key) {
                    assert_eq!(
                        cubit::printer::to_sass(&decoded),
                        row["nvidia_sass"].as_str().unwrap(),
                        "{arch}: consolidated RZ control must preserve vendor text"
                    );
                    continue;
                }
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
            control == EXPECTED_CONTROL && existing == 1,
            "{arch}: retained control and existing-form census"
        );
    }
}
