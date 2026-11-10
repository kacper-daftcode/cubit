//! B300 VIMNMX packed16 register/UR vendor-text lattice; no execution claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-vimnmx-packed16-2026-11-08";
const PRODUCTION: [usize; 2] = [452, 452];
const POSITIVE: usize = 2084;
const NEGATIVE: usize = 114;
const GROUPS: [&str; 4] = ["U16x2", "RELU,U16x2", "S16x2", "RELU,S16x2"];
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    (
        "sm103a",
        hb300_fixture("sm103a_vimnmx_packed16_nvdisasm.jsonl"),
    ),
    (
        "sm100a",
        hb300_fixture("sm100a_vimnmx_packed16_nvdisasm.jsonl"),
    ),
]);

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLES: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLES.get_or_init(|| {
        ARCHES
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

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

fn key(row: &Value) -> &'static str {
    if row["ur"].as_u64().unwrap() == 0 {
        "VIMNMX_R_P_P_R_R_P"
    } else {
        "VIMNMX_R_P_P_R_UR_P"
    }
}

#[test]
fn all_licensed_packed16_forms_roundtrip() {
    for (arch_index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[arch_index];
        let (mut production, mut positive) = (0usize, 0usize);
        for row in rows(fixture) {
            if row["kind"] != "positive" {
                continue;
            }
            positive += 1;
            production += usize::from(row["generation"] == "production");
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, key(&row), "{arch} {word:032x}");
            assert!(
                GROUPS.contains(&decoded.mod_group.as_str()),
                "{arch} {word:032x}"
            );
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                text,
                "{arch} {word:032x}"
            );
            assert_eq!(
                cubit::printer::to_sass(&decoded),
                text,
                "{arch} {word:032x}"
            );
            assert_eq!(
                encode(table, word, text),
                word & !(7u128 << 125),
                "{arch} {word:032x}"
            );
        }
        assert_eq!(
            production, PRODUCTION[arch_index],
            "{arch}: included H production witnesses"
        );
        assert_eq!(
            positive, POSITIVE,
            "{arch}: controlled modifier/field probes"
        );
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 8);
        for name in ["VIMNMX_R_P_P_R_R_P", "VIMNMX_R_P_P_R_UR_P"] {
            let entry = &raw["instructions"][name];
            for group in GROUPS {
                let row = &entry["mod_groups"][group];
                assert_eq!(row["_src"], SOURCE, "{arch} {name} {group}");
                assert!(row["_note"].as_str().unwrap().contains("not execution"));
            }
        }
    }
}

#[test]
fn invalid_inert_and_unlicensed_words_fail_closed() {
    for (arch_index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[arch_index];
        let (mut negatives, mut control, mut other) = (0usize, 0usize, 0usize);
        for row in rows(fixture) {
            let word = hex(&row["word"]);
            match row["kind"].as_str().unwrap() {
                "negative" => {
                    negatives += 1;
                    if let Ok(decoded) = index.decode(word, 0, table) {
                        panic!("{arch}: invalid/text-inert/unlicensed word accepted {word:032x} as {} {}", decoded.key, decoded.mod_group);
                    }
                }
                "control_plane" => control += 1,
                "other_family" => other += 1,
                "positive" => {}
                other => panic!("unclassified fixture row {other}"),
            }
        }
        assert_eq!(
            (negatives, control, other),
            (NEGATIVE, 74, 12),
            "{arch}: incomplete boundary coverage"
        );
    }
}
