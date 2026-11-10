//! Measured plain directional F2F BF16/F16 conversions, CPU-only vendor-text tests.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

const SOURCE: &str = "rows-f2f-bf16-f16-2026-11-08";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    (
        "sm103a",
        hb300_fixture("sm103a_f2f_bf16_f16_nvdisasm.jsonl"),
    ),
    (
        "sm100a",
        hb300_fixture("sm100a_f2f_bf16_f16_nvdisasm.jsonl"),
    ),
]);

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLE: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLE.get_or_init(|| {
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

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn new_key(shape: &str) -> &'static str {
    match shape {
        "BF16_F16" => "F2F.BF16.F16_R_R",
        "F16_BF16" => "F2F.F16.BF16_R_R",
        _ => panic!("bad shape {shape}"),
    }
}

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

#[test]
fn plain_vendor_text_roundtrips_on_every_production_and_field_word() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut n = 0;
        let mut shapes = BTreeMap::new();
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["kind"] != "positive" {
                continue;
            }
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let shape = row["shape"].as_str().unwrap().to_string();
            let decoded = decoder
                .decode(word, 0, table)
                .unwrap_or_else(|e| panic!("{arch} {word:032x}: {e}"));
            assert_eq!(decoded.key, new_key(&shape), "{arch} {word:032x}");
            assert!(decoded.mod_group.is_empty());
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
            // Raw control text cannot name bits [127:125]. Every operand bit,
            // guard and visible scheduling field must roundtrip exactly.
            assert_eq!(
                encode(table, word, text),
                word & !(7u128 << 125),
                "{arch} {word:032x} {text}"
            );
            n += 1;
            *shapes.entry(shape.clone()).or_insert(0usize) += 1;
        }
        assert_eq!(n, 1138, "{arch}: positive count");
        assert_eq!(
            shapes,
            BTreeMap::from([("BF16_F16".into(), 569usize), ("F16_BF16".into(), 569usize)]),
            "{arch}"
        );
    }
}

#[test]
fn fields_provenance_and_unmodified_harvest_neighbour_are_exact() {
    for (arch, _) in *ARCHES {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 2);
        assert_eq!(
            raw["instructions"]["F2F_R_R"]["mod_groups"]
                .as_object()
                .unwrap()
                .len(),
            // the batch (T-26, 2026-11-10): the neighbour key carries ten groups once the F16 <- F32 sign / rounding / FTZ
            // candidates are in (five at this candidate's base); this candidate adds none of them
            10
        );
        for shape in ["BF16_F16", "F16_BF16"] {
            let key = new_key(shape);
            let entry = &raw["instructions"][key];
            assert_eq!(entry["_src"], SOURCE);
            assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 1);
            let group = &entry["mod_groups"][""];
            assert_eq!(group["_src"], SOURCE);
            assert_eq!(hex(&group["and_base"]) >> 96, 0);
            assert!(group["claim_forbid"].as_array().unwrap().is_empty());
            assert_eq!(group["fields"].as_array().unwrap().len(), 3);
            let mask = group["fields"]
                .as_array()
                .unwrap()
                .iter()
                .fold(0, |mask, field| {
                    mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1)
                        << field["shift"].as_u64().unwrap())
                });
            assert_eq!(hex(&group["variable_mask"]), mask);
            for (shift, token, bits) in [(12, 0, 4), (16, 1, 8), (32, 2, 8)] {
                assert!(
                    group["fields"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|field| field["shift"] == shift
                            && field["token_idx"] == token
                            && field["bits"] == bits
                            && field["extraction"] == if shift == 12 { "guard" } else { "reg" }),
                    "{arch} {shape}: missing field at {shift}"
                );
            }
        }
    }
}

#[test]
fn lower_unclaimed_bits_fail_closed_and_adjacent_forms_are_not_plain_claims() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut counts = BTreeMap::new();
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let kind = row["kind"].as_str().unwrap().to_string();
            if kind == "positive" {
                continue;
            }
            *counts.entry(kind.clone()).or_insert(0usize) += 1;
            let word = hex(&row["word"]);
            let decoded = decoder.decode(word, 0, table);
            if let Ok(ref value) = decoded {
                assert_ne!(
                    value.key,
                    new_key(row["shape"].as_str().unwrap()),
                    "{arch} {kind} {word:032x} entered the plain row"
                );
            }
            if kind == "negative" {
                assert!(decoded.is_err(), "{arch} negative {word:032x}: {decoded:?}");
            }
        }
        assert!(counts["negative"] > 0, "{arch}");
        assert!(counts["adjacent_modifier"] > 0, "{arch}");
        assert!(counts["other_family"] > 0, "{arch}");
    }
}
