//! Schedule-safe decoding for measured FMNMX.IS_A, independently vendor-licensed.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

const SOURCE: &str = "hidden-b300-fmnmx-is-a-schedule-2026-11-08";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    ("sm103a", hb300_fixture("sm103a_fmnmx_is_a_schedule_nvdisasm.jsonl")),
    ("sm100a", hb300_fixture("sm100a_fmnmx_is_a_schedule_nvdisasm.jsonl")),
]);

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLE: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLE.get_or_init(|| ARCHES.iter().map(|(arch, _)| {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    }).collect())
}

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn encode(table: &IsaTable, word: u128, text: &str) -> anyhow::Result<u128> {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table)
}

#[test]
fn vendor_text_roundtrip_preserves_all_modelled_fields() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut shapes: BTreeMap<String, usize> = BTreeMap::new();
        let mut scheduled_uppers = BTreeSet::new();
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let kind = row["kind"].as_str().unwrap();
            *counts.entry(kind.to_string()).or_default() += 1;
            let word = hex(&row["word"]);
            match kind {
                "positive" | "scheduled" => {
                    let expected = row["nvidia_sass"].as_str().unwrap();
                    let decoded = decoder.decode(word, 0, table).unwrap_or_else(|e| panic!("{arch} {word:032x}: {e}"));
                    let shape = row["shape"].as_str().unwrap();
                    assert_eq!(decoded.key, format!("FMNMX_R_P_R_{shape}_P"), "{arch} {word:032x}");
                    assert!(decoded.mod_group.split(',').any(|m| m == "IS_A"));
                    assert_eq!(cubit::printer::to_sass_lossless(&decoded), expected);
                    let encoded = encode(table, word, expected).unwrap();
                    // The text ControlCode cannot name word[127:125].
                    // Decode/render must not discard those bits; encode must
                    // not invent a scheduling law in either fixture layer.
                    assert_eq!(encoded, word & !(7u128 << 125), "{arch} {word:032x}: {expected}");
                    if kind == "scheduled" {
                        *shapes.entry(shape.to_string()).or_default() += 1;
                        scheduled_uppers.insert(word >> 96);
                    }
                }
                "known_field_vendor_refusal" => {
                    // OPEX refusal in a complete control word doesn't license
                    // hardware execution; this only verifies my known fields
                    // roundtrip without losing the supplied schedule.
                    let decoded = decoder.decode(word, 0, table).unwrap_or_else(|e| panic!("{arch} {word:032x}: {e}"));
                    assert!(decoded.key.starts_with("FMNMX_R_P_R_"));
                    let rendered = cubit::printer::to_sass_lossless(&decoded);
                    // OPEX refusal is not a licensed instruction. Encode
                    // the measured fields. Unmodelled bit124, plus bit123 for
                    // non-R operand shapes, isn't held by text ControlCode.
                    // SM103a/SM100a has no SM120 Y+S00 legality claim here.
                    let encoded = encode(table, word, &rendered);
                    let mut unmodelled = 1u128 << 124;
                    if row["shape"] != "R" { unmodelled |= 1u128 << 123; }
                    assert_eq!(encoded.unwrap(), word & !unmodelled, "{arch} {word:032x}: {rendered}");
                }
                "negative" => {
                    if let Ok(decoded) = decoder.decode(word, 0, table) {
                        assert!(!decoded.key.starts_with("FMNMX_"), "{arch} negative {word:032x} became {decoded:?}");
                    }
                }
                "other_family" => {}
                _ => panic!("unknown fixture class {kind}"),
            }
        }
        assert_eq!(fixture.lines().count(), 2813, "{arch}: empty or partial fixture must not pass");
        assert_eq!(counts["positive"], 2484, "{arch}");
        assert_eq!(counts["scheduled"], 63, "{arch}");
        assert_eq!(counts["negative"], 185, "{arch}");
        assert_eq!(counts["known_field_vendor_refusal"], 59, "{arch}");
        assert_eq!(counts["other_family"], 22, "{arch}");
        assert_eq!(shapes, BTreeMap::from([("FI".into(), 20), ("R".into(), 23), ("UR".into(), 20)]), "{arch}");
        assert_eq!(scheduled_uppers.len(), 21, "{arch}");
    }
}

#[test]
fn fields_and_provenance_exclude_control_claims_not_unknown_bits() {
    for (arch, _) in *ARCHES {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 24);
        let mut groups = 0;
        for shape in ["R", "FI", "UR"] {
            let entry = &raw["instructions"][format!("FMNMX_R_P_R_{shape}_P").as_str()];
            assert_eq!(entry["_src"], SOURCE);
            for (mods, group) in entry["mod_groups"].as_object().unwrap() {
                assert!(mods.split(',').any(|m| m == "IS_A"));
                assert_eq!(group["_src"], SOURCE);
                assert!(group["claim_forbid"].as_array().unwrap().is_empty(),
                    "decode strips the control plane before claims; [96:128] is not instruction authority");
                assert_eq!(hex(&group["and_base"]) >> 96, 0);
                let mask = group["fields"].as_array().unwrap().iter().fold(0, |mask, field| {
                    mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1) << field["shift"].as_u64().unwrap())
                });
                assert_eq!(hex(&group["variable_mask"]), mask);
                assert_eq!(group["fields"].as_array().unwrap().iter().any(|field| field["shift"] == 123 && field["extraction"] == "reuse"), shape == "R");
                assert!(group["fields"].as_array().unwrap().iter().all(|field| !(69..=71).contains(&field["shift"].as_u64().unwrap())));
                for (shift, token, extraction) in [(12, 0, "guard"), (16, 1, "reg"), (66, 2, "pred"), (24, 3, "reg"), (32, 4, "reg"), (87, 5, "pred")] {
                    assert!(group["fields"].as_array().unwrap().iter().any(|field|
                        field["shift"] == shift && field["token_idx"] == token &&
                        (field["extraction"] == extraction || (shift == 32 && (field["extraction"] == "f32" || field["extraction"] == "ureg")))),
                        "{arch}: {mods} missing field {extraction}@{shift}/token{token}");
                }
                groups += 1;
            }
        }
        assert_eq!(groups, 24, "{arch}");
    }
}

#[test]
fn lower_unknown_bits_stay_fail_closed_on_a_real_schedule() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let base = fixture.lines().map(|line| serde_json::from_str::<Value>(line).unwrap())
            .find(|row| row["kind"] == "scheduled" && row["shape"] == "R" && row["control_label"] == "numeric-plain").unwrap();
        let word = hex(&base["word"]);
        let expected = base["nvidia_sass"].as_str().unwrap();
        assert_eq!(cubit::printer::to_sass_lossless(&decoder.decode(word, 0, table).unwrap()), expected);
        for bit in [0, 10, 11, 69, 70, 71, 91, 92, 93, 94, 95] {
            let mutant = word ^ (1u128 << bit);
            if let Ok(decoded) = decoder.decode(mutant, 0, table) {
                assert!(!decoded.key.starts_with("FMNMX_R_P_R_"), "{arch}: bit{bit} entered {decoded:?}");
            }
        }
    }
}
