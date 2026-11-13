//! Production FADD2 HI_LO/scalar-Rb reuse; complete-word CPU evidence only.
include!("engine_l1_controls.inc");
include!("hb300_fixture.inc");
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "engine-l1a-fadd2-shapes-2026-11-13";
const KEY: &str = "FADD2_R_R_R";
const DONOR: &str = "FADD2_R_R_R";
const BASE: u128 = 0x100fe2000020000000000005020a724bu128;
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_fadd2_hi_lo_rb_reuse_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_fadd2_hi_lo_rb_reuse_nvdisasm.jsonl"),
        ),
    ]
});

fn loaded() -> &'static Vec<(IsaTable, DecodeIndex)> {
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

fn model() -> Value {
    serde_json::from_str(include_str!(
        "fixtures/fadd2_hi_lo_rb_reuse_table_model.json"
    ))
    .unwrap()
}

fn word(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn roundtrip(table: &IsaTable, decoder: &DecodeIndex, arch: &str, row: &Value) {
    let raw = word(&row["word"]);
    let text = row["nvidia_sass"].as_str().unwrap();
    let decoded = decoder
        .decode(raw, 0, table)
        .unwrap_or_else(|error| panic!("{arch} {raw:032x}: {error}"));
    assert_eq!(decoded.key, KEY, "{arch} {raw:032x}");
    assert_eq!(decoded.mod_group, "", "{arch} {raw:032x}");
    assert_eq!(
        cubit::printer::to_sass_lossless(&decoded),
        text,
        "{arch} {raw:032x}"
    );
    assert_eq!(cubit::printer::to_sass(&decoded), text, "{arch} {raw:032x}");
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (raw >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    assert_eq!(
        cubit::encoder::encode_instruction(&parsed, table).unwrap(),
        raw & !(7u128 << 125),
        "{arch} {raw:032x} {text}"
    );
}

#[test]
fn source_inventory_and_clear_reuse_control_hold_on_parent() {
    let model = model();
    assert_eq!(model["production_observations"], 1296);
    assert_eq!(model["production_pairs"], 639);
    assert_eq!(model["production_words"], 589);
    assert_eq!(model["checks"]["closed_bit91_probes"], 0);
    for (position, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &loaded()[position];
        let mut production = 0;
        for row in rows(fixture) {
            assert!(
                row["generation"] != "single_lower_bit"
                    || !row["label"].as_str().unwrap().ends_with(":91"),
                "{arch}: closed bit91 repeated"
            );
            if row["generation"] == "production" {
                production += 1;
            }
        }
        assert_eq!(
            production, 589,
            "{arch}: all distinct H production words replayed"
        );
        let clear = BASE & !(1u128 << 124);
        let decoded = decoder.decode(clear, 0, table).unwrap();
        let text = cubit::printer::to_sass_lossless(&decoded);
        assert!(
            !text.contains(".reuse"),
            "{arch}: unexpected reuse in clear control"
        );
        let control = cubit::scheduling::format_control_code(
            &cubit::scheduling::decode_sched_upper32((clear >> 96) as u32),
        );
        let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
        let encoded = cubit::encoder::encode_instruction(&parsed, table).unwrap();
        assert_eq!(encoded & !(7u128 << 125), clear & !(7u128 << 125), "{arch}");
    }
}

#[test]
fn measured_hi_lo_scalar_rb_reuse_roundtrips() {
    for (position, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &loaded()[position];
        let mut counts = std::collections::BTreeMap::new();
        let mut registers = [
            std::collections::BTreeSet::new(),
            std::collections::BTreeSet::new(),
            std::collections::BTreeSet::new(),
        ];
        for row in rows(fixture) {
            if row["role"] != "adopt" {
                continue;
            }
            *counts
                .entry(row["generation"].as_str().unwrap().to_string())
                .or_insert(0usize) += 1;
            let raw = word(&row["word"]);
            for (slot, shift) in [16usize, 24, 32].into_iter().enumerate() {
                let mask = 0xffu128 << shift;
                if raw & !mask == BASE & !mask {
                    registers[slot].insert(((raw >> shift) & 0xff) as u16);
                }
            }
            roundtrip(table, decoder, arch, &row);
        }
        assert_eq!(counts["production"], 589, "{arch}");
        assert_eq!(counts["guard"], 15, "{arch}");
        assert_eq!(counts["register"], 765, "{arch}");
        assert_eq!(counts["base"], 1, "{arch}");
        assert_eq!(counts["reuse_ab"], 1, "{arch}");
        assert!(
            registers.iter().all(|values| values.len() == 256),
            "{arch}: incomplete byte domain {registers:?}"
        );
    }
}

#[test]
fn exactly_one_b300_field_and_provenance_are_added() {
    let model = model();
    for (position, (arch, _)) in ARCHES.iter().enumerate() {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1,
            "{arch}"
        );
        let group = &raw["instructions"][KEY]["mod_groups"][""];
        assert_eq!(group["_src"], SOURCE, "{arch}");
        assert_eq!(
            KEY, DONOR,
            "one measured FADD2 register row, no synthetic key"
        );
        let fields = group["fields"].as_array().unwrap();
        assert_eq!(
            fields.len(),
            15,
            "{arch}: guard, registers, sign/shape fields and independent reuse fields"
        );
        assert_eq!(
            &fields[0], &model["row"]["fields"][0],
            "{arch}: guard field"
        );
        let registers: Vec<_> = fields
            .iter()
            .filter(|field| field["extraction"] == "reg")
            .map(|field| field["shift"].as_u64().unwrap())
            .collect();
        assert_eq!(registers, [16, 24, 32], "{arch}: register fields");
        let reuse = fields
            .iter()
            .find(|field| field["extraction"] == "reuse" && field["shift"] == 124)
            .unwrap();
        assert_eq!(reuse, &model["added_field"], "{arch}");
        assert_eq!(
            model["added_field"],
            serde_json::json!({
            "bits": 1, "extraction": "reuse", "shift": 124, "token_idx": 3})
        );
        assert!(
            fields.iter().any(|field| field["extraction"] == "reuse"
                && field["shift"] == 122
                && field["token_idx"] == 2),
            "{arch}: first-source reuse has served-control witnesses"
        );
        assert!(
            model["old_row"]["fields"]
                .as_array()
                .unwrap()
                .iter()
                .all(|field| field["shift"] != 124),
            "{arch}"
        );
        let previous_mask = word(&model["row"]["variable_mask"]);
        let mask = word(&group["variable_mask"]);
        assert_eq!(
            previous_mask & !mask,
            0,
            "{arch}: previous fields retained in consolidated mask"
        );
        assert!(group["claim_forbid"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["shift"] == 123));
        assert!(group["claim_forbid"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["shift"] != 122));
        let parsed = cubit::parse_cuasm_line("FADD2 R10, R2.F32x2.LO_HI, R5.F32 ;", 0).unwrap();
        cubit::encoder::encode_instruction(&parsed, &loaded()[position].0)
            .expect("{arch}: measured Ra.LO_HI is inside the shared row");
    }
    for (position, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &loaded()[position];
        let mut boundaries = 0;
        for row in rows(fixture) {
            if row["role"] == "adopt" || row["generation"] == "control_plane" {
                continue;
            }
            boundaries += 1;
            if let Ok(decoded) = decoder.decode(word(&row["word"]), 0, table) {
                if e2_consolidated_control(&row, KEY, &decoded.key) {
                    assert_eq!(
                        cubit::printer::to_sass(&decoded),
                        row["nvidia_sass"].as_str().unwrap(),
                        "{arch}: consolidated FADD2 control must preserve vendor text"
                    );
                    continue;
                }
                assert_ne!(
                    decoded.key,
                    KEY,
                    "{arch}: new key overmatched {}: {:#034x}",
                    row["label"],
                    word(&row["word"])
                );
            }
        }
        // 107 other positives + 10 negative + 7 adjacent + 2 other-family
        // + 6 non-adopted reuse controls; the other 30 are control-plane.
        assert_eq!(
            boundaries, 132,
            "{arch}: all selected negative/adjacent/other boundaries"
        );
    }
}
