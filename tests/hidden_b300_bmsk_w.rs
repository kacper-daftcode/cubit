//! Measured BMSK.W register form; vendor text is not an execution claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

const SOURCE: &str = "rows-bmsk-w-register-2026-11-08";
const KEY: &str = "BMSK.W_R_R_R";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    ("sm103a", hb300_fixture("sm103a_bmsk_w_nvdisasm.jsonl")),
    ("sm100a", hb300_fixture("sm100a_bmsk_w_nvdisasm.jsonl")),
]);

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLE: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLE.get_or_init(|| {
        ARCHES.iter().map(|(arch, _)| {
            let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
            let index = DecodeIndex::build(&table);
            (table, index)
        }).collect()
    })
}

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn rows(fixture: &str) -> impl Iterator<Item = Value> + '_ {
    fixture.lines().map(|line| serde_json::from_str(line).unwrap())
}

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

fn source_row(arch: &str) {
    let raw: Value = serde_json::from_slice(
        &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap(),
    ).unwrap();
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
    let entry = &raw["instructions"][KEY];
    assert_eq!(entry["_src"], SOURCE);
    assert_eq!(entry["base_op"], "BMSK.W");
    assert_eq!(entry["operand_sig"], "R_R_R");
    assert_eq!(entry["scheduling"]["latency_source"], "synthetic");
    let groups = entry["mod_groups"].as_object().unwrap();
    assert_eq!(groups.len(), 1);
    let group = &groups[""];
    assert_eq!(group["_src"], SOURCE);
    assert_eq!(group["count"], Value::Null);
    assert_eq!(hex(&group["and_base"]), 0x0000000000000800000000000000021bu128);
    assert_eq!(hex(&group["variable_mask"]), 0xfffffff000u128);
    assert_eq!(hex(&group["and_base"]) >> 96, 0);
    let fields = group["fields"].as_array().unwrap();
    assert_eq!(fields.len(), 4);
    for (index, (shift, token, bits, extraction)) in [
        (12, 0, 4, "guard"), (16, 1, 8, "reg"),
        (24, 2, 8, "reg"), (32, 3, 8, "reg"),
    ].into_iter().enumerate() {
        assert_eq!(fields[index]["shift"], shift);
        assert_eq!(fields[index]["token_idx"], token);
        assert_eq!(fields[index]["bits"], bits);
        assert_eq!(fields[index]["extraction"], extraction);
    }
}

#[test]
fn wide_register_form_matches_every_measured_word() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut total = 0;
        let mut generations = BTreeMap::new();
        for row in rows(fixture).filter(|row| row["kind"] == "positive") {
            total += 1;
            *generations.entry(row["generation"].as_str().unwrap().to_string()).or_insert(0usize) += 1;
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            assert_eq!(row["rc"], 0);
            assert!(!row["stdout"].as_str().unwrap().is_empty());
            let decoded = decoder.decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, KEY, "{arch} {word:032x} {text}");
            assert_eq!(decoded.mod_group, "");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), text, "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass(&decoded), text, "{arch} {word:032x}");
            assert_eq!(encode(table, word, text), word & !(7u128 << 125), "{arch} {word:032x}");
        }
        assert_eq!(total, 781, "{arch}: complete positive census");
        assert_eq!(generations["base"], 1);
        assert_eq!(generations["field"], 780);
        source_row(arch);
    }
}

#[test]
fn plain_inert_and_unscoped_forms_stay_out_of_the_wide_row() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut counts = BTreeMap::new();
        for row in rows(fixture).filter(|row| row["kind"] != "positive") {
            let kind = row["kind"].as_str().unwrap();
            *counts.entry(kind.to_string()).or_insert(0usize) += 1;
            if kind == "control_negative" {
                continue; // Only three zero-control reuse refusals; not a scheduling law.
            }
            let word = hex(&row["word"]);
            let decoded = decoder.decode(word, 0, table);
            if let Ok(ref value) = decoded {
                assert_ne!(value.key, KEY, "{arch} {kind} {word:032x} entered new row");
            }
            if kind == "negative" {
                assert!(decoded.is_err(), "{arch} negative {word:032x}: {decoded:?}");
            }
            if kind == "adjacent_plain" {
                // the batch (T-26, 2026-11-10): the plain form is a row of its own now -- BMSK_R_R_R, the sibling
                // candidate bmsk-production -- so the word decodes; it stays out of the wide row (above) and prints
                // the vendor text this record holds. At this candidate's own base it had no row at all.
                let value = decoded.as_ref().unwrap_or_else(|e| panic!("{arch} plain {word:032x}: {e}"));
                assert_eq!(value.key, "BMSK_R_R_R", "{arch} {word:032x}");
                assert_eq!(cubit::printer::to_sass(value), row["nvidia_sass"].as_str().unwrap(), "{arch} {word:032x}");
            }
        }
        assert_eq!(counts["negative"], 62);
        assert_eq!(counts["other_family"], 5);
        assert_eq!(counts["adjacent_plain"], 1);
        assert_eq!(counts["control_negative"], 3);
        assert_eq!(counts.values().sum::<usize>(), 71);
    }
}
