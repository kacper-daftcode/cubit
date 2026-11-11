//! B300 HSET2 register-result vendor-text lattice; no execution claim.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-hset2-rrr-production-2026-11-10";
const PRODUCTION: usize = 343;
const KEY: &str = "HSET2_R_R_R_P";
const ARCHES: [(&str, &str); 2] = [
    (
        "sm103a",
        include_str!("fixtures/sm103a_hset2_rrr_nvdisasm.jsonl"),
    ),
    (
        "sm100a",
        include_str!("fixtures/sm100a_hset2_rrr_nvdisasm.jsonl"),
    ),
];

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

#[test]
fn all_licensed_register_result_forms_roundtrip() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let (mut production, mut positive, mut selector_invalid) = (0usize, 0usize, 0usize);
        for row in rows(fixture) {
            let word = hex(&row["word"]);
            let kind = row["kind"].as_str().unwrap();
            if kind == "invalid_glyph" && row["label"].as_str().unwrap().contains("selector") {
                selector_invalid += 1;
                let text = row["nvidia_sass"].as_str().unwrap();
                let decoded = index
                    .decode(word, 0, table)
                    .unwrap_or_else(|error| panic!("{arch} selector glyph {word:032x}: {error}"));
                assert_eq!(decoded.key, KEY);
                assert_eq!(cubit::printer::to_sass_lossless(&decoded), text);
                assert!(cubit::encoder::encode_instruction(
                    &cubit::parse_cuasm_line(&format!("{text} ;"), 0).unwrap(),
                    table
                )
                .is_err());
                continue;
            }
            if kind != "positive" {
                continue;
            }
            positive += 1;
            production += usize::from(row["generation"] == "production");
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, KEY, "{arch} {word:032x}");
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
            production, PRODUCTION,
            "{arch}: every included H production witness"
        );
        assert!(
            positive >= PRODUCTION + 384,
            "{arch}: missing controlled modifier/field probes"
        );
        assert_eq!(selector_invalid, 2, "{arch}: both source selectors");
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 384);
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["_src"], SOURCE);
        assert_eq!(
            entry["mod_groups"].as_object().unwrap().len(),
            384,
            "{arch} {KEY}"
        );
        assert!(entry["mod_groups"]
            .as_object()
            .unwrap()
            .values()
            .all(|row| row["_src"] == SOURCE));
    }
}

#[test]
fn invalid_inert_and_unlicensed_words_fail_closed() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let (mut negatives, mut invalid_enum, mut control) = (0usize, 0usize, 0usize);
        for row in rows(fixture) {
            let word = hex(&row["word"]);
            match row["kind"].as_str().unwrap() {
                "negative" => {
                    negatives += 1;
                    assert!(
                        index.decode(word, 0, table).is_err(),
                        "{arch}: invalid/text-inert word accepted {word:032x}"
                    );
                }
                "invalid_glyph" if !row["label"].as_str().unwrap().contains("selector") => {
                    invalid_enum += 1;
                    assert!(
                        index.decode(word, 0, table).is_err(),
                        "{arch}: INVALID type/boolean accepted {word:032x}"
                    );
                }
                "control_plane" => control += 1,
                "positive" | "invalid_glyph" => {}
                "other_family" => {
                    if let Ok(decoded) = index.decode(word, 0, table) {
                        assert_ne!(decoded.key, KEY, "{arch}: wrong-family claim {word:032x}");
                    }
                }
                other => panic!("unclassified fixture row {other}"),
            }
        }
        assert!(
            negatives > 0 && invalid_enum == 3 && control > 0,
            "{arch}: incomplete negative coverage {negatives}/{invalid_enum}/{control}"
        );
    }
}
