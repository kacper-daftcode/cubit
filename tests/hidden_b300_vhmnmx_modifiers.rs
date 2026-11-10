//! Measured VHMNMX type/NAN/half-select rows, with retained semantic limits.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const KEY: &str = "VHMNMX_R_R_R_R_P";
const SOURCE: &str = "rows-vhmnmx-modifiers-production-2026-11-09";
const OLD_SOURCE: &str = "rows-vhmnmx-plain-production-2026-11-09";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    (
        "sm103a",
        hb300_fixture("sm103a_vhmnmx_modifiers_nvdisasm.jsonl"),
    ),
    (
        "sm100a",
        hb300_fixture("sm100a_vhmnmx_modifiers_nvdisasm.jsonl"),
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

fn expected_group(text: &str) -> &'static str {
    let mut words = text.split_whitespace();
    let opcode = if text.starts_with('@') {
        words.next();
        words.next().unwrap()
    } else {
        words.next().unwrap()
    };
    match opcode {
        "VHMNMX" => "",
        "VHMNMX.NAN" => "NAN",
        "VHMNMX.BF16_V2" => "BF16_V2",
        "VHMNMX.BF16_V2.NAN" => "BF16_V2,NAN",
        other => panic!("unexpected vendor opcode {other}"),
    }
}

#[test]
fn all_measured_modifier_words_decode_render_and_encode() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let mut positives = 0usize;
        assert_eq!(
            rows(fixture)
                .filter(|row| row["kind"] == "positive" && row["generation"] == "production")
                .count(),
            121
        );
        for prefix in ["", "nan:", "bf16:", "bf16_nan:"] {
            let count = |generation: &str| {
                rows(fixture)
                    .filter(|row| {
                        let label = row["label"].as_str().unwrap();
                        row["kind"] == "positive"
                            && row["generation"] == generation
                            && label.starts_with(prefix)
                            && (!prefix.is_empty()
                                || !label.starts_with("nan:")
                                    && !label.starts_with("bf16:")
                                    && !label.starts_with("bf16_nan:"))
                    })
                    .count()
            };
            if prefix.is_empty() {
                // Production/base/field/sign closures were retained verbatim by exact key.
                assert_eq!(count("production"), 121);
                assert_eq!(count("base"), 1);
                assert_eq!(count("field"), 1042);
                assert_eq!(count("sign"), 4);
                assert_eq!(count("absolute_modifier"), 6);
            } else {
                assert_eq!(count("base"), 1, "{prefix}: base");
                assert_eq!(
                    count("field"),
                    1042,
                    "{prefix}: all register/guard/predicate fields"
                );
                assert_eq!(count("sign"), 4, "{prefix}: inversion/negation");
                assert_eq!(count("absolute_modifier"), 6, "{prefix}: abs combinations");
            }
            // Legal products exclude value 1 in each of the three hsel windows.
            assert_eq!(
                count("selector"),
                26,
                "{prefix}: all independent legal selectors"
            );
            assert_eq!(
                count("operand_form"),
                18,
                "{prefix}: signs/abs compose with selectors"
            );
        }
        for row in rows(fixture) {
            if row["kind"] != "positive" {
                continue;
            }
            positives += 1;
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, KEY, "{arch} {word:032x}");
            assert_eq!(decoded.mod_group, expected_group(text), "{arch} {text}");
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                text,
                "{arch} {word:032x}"
            );
            assert_eq!(cubit::printer::to_sass(&decoded), text);
            assert_eq!(
                encode(table, word, text),
                word & !(7u128 << 125),
                "{arch} {word:032x}: full-word encode"
            );
        }
        assert_eq!(positives, 4696, "{arch}: full positive fixture census");
    }
}

#[test]
fn invalid_selectors_and_unmeasured_neighbors_stay_closed() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        for prefix in ["", "nan:", "bf16:", "bf16_nan:"] {
            for field in [60, 74, 76] {
                let label = format!("{prefix}single-reference-lower-bit:{field}");
                let row = rows(fixture).find(|row| row["label"] == label).unwrap();
                assert_eq!(row["kind"], "negative");
                assert!(row["nvidia_sass"].as_str().unwrap().contains(".INVALID1"));
                assert!(index.decode(hex(&row["word"]), 0, table).is_err());
            }
            let invalid_opcode = rows(fixture)
                .find(|row| row["label"] == format!("{prefix}single-reference-lower-bit:78"))
                .unwrap();
            assert_eq!(invalid_opcode["kind"], "negative");
            assert!(index
                .decode(hex(&invalid_opcode["word"]), 0, table)
                .is_err());
            for bit in [80, 82] {
                let label = format!("{prefix}single-reference-lower-bit:{bit}");
                let row = rows(fixture).find(|row| row["label"] == label).unwrap();
                assert_eq!(row["kind"], "adjacent_modifier");
                assert!(index.decode(hex(&row["word"]), 0, table).is_err());
            }
            for mask in 1..8 {
                let label = format!("{prefix}reuse-mask:{mask}");
                let row = rows(fixture).find(|row| row["label"] == label).unwrap();
                assert_eq!(row["kind"], "negative");
                assert!(index.decode(hex(&row["word"]), 0, table).is_err());
            }
        }
        for row in rows(fixture) {
            if row["kind"] == "negative" {
                assert!(
                    index.decode(hex(&row["word"]), 0, table).is_err(),
                    "{arch}: negative decoded: {:#032x}",
                    hex(&row["word"])
                );
            }
        }
    }
}

#[test]
fn table_provenance_and_field_geometry_are_measured() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 3);
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["_src"], OLD_SOURCE);
        assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 4);
        for (group, and_bits) in [
            ("", 0u128),
            ("NAN", 1u128 << 81),
            ("BF16_V2", 1u128 << 85),
            ("BF16_V2,NAN", (1u128 << 81) | (1u128 << 85)),
        ] {
            let row = &entry["mod_groups"][group];
            assert_eq!(
                row["_src"],
                if group.is_empty() { OLD_SOURCE } else { SOURCE }
            );
            assert_eq!(hex(&row["and_base"]) & and_bits, and_bits);
            let fields = row["fields"].as_array().unwrap();
            assert_eq!(fields.len(), 16);
            for (token, shift) in [(2, 74), (3, 60), (4, 76)] {
                let matches: Vec<_> = fields
                    .iter()
                    .filter(|field| field["extraction"] == "hsel" && field["token_idx"] == token)
                    .collect();
                assert_eq!(matches.len(), 1);
                assert_eq!(matches[0]["shift"], shift);
                assert_eq!(matches[0]["bits"], 2);
                let inherited = if matches[0]["_src"].is_null() {
                    &row["_src"]
                } else {
                    &matches[0]["_src"]
                };
                assert_eq!(inherited, SOURCE);
                let forbidden = row["claim_forbid"].as_array().unwrap().iter().any(|rule| {
                    rule["shift"] == shift
                        && rule["bits"] == 2
                        && rule["values"].as_array().unwrap() == &[Value::from(1)]
                });
                assert!(
                    forbidden,
                    "{arch} {group}: INVALID1 selector must fail closed"
                );
            }
        }
    }
}
