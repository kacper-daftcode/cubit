//! Production VIADDMNMX.U32 immediate Rb reuse; complete-word CPU only.
include!("hb300_fixture.inc");
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-viaddmnmx-u32-ii-reuse-production-2026-11-12";
const KEY: &str = "VIADDMNMX_R_R_R_II_P";
const POSITIVE: usize = 1049;
const BASE: u128 = 0x080fe200038000060000400005047446u128;

fn arches() -> [(&'static str, &'static str); 2] {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_viaddmnmx_u32_ii_reuse_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_viaddmnmx_u32_ii_reuse_nvdisasm.jsonl"),
        ),
    ]
}

fn loaded() -> &'static Vec<(IsaTable, DecodeIndex)> {
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

fn roundtrip(table: &IsaTable, decoder: &DecodeIndex, arch: &str, row: &Value) {
    let word = hex(&row["word"]);
    let text = row["nvidia_sass"].as_str().unwrap();
    let decoded = decoder.decode(word, 0, table).unwrap();
    assert_eq!(decoded.key, KEY, "{arch} {word:032x}");
    assert_eq!(decoded.mod_group, "U32", "{arch} {word:032x}");
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
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    assert_eq!(
        cubit::encoder::encode_instruction(&parsed, table).unwrap(),
        word & !(7u128 << 125),
        "{arch} {word:032x}"
    );
}

#[test]
fn production_and_measured_positive_fields_roundtrip() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, decoder) = &loaded()[position];
        let (mut production, mut positives) = (0, 0);
        let mut registers = [
            std::collections::BTreeSet::new(),
            std::collections::BTreeSet::new(),
            std::collections::BTreeSet::new(),
        ];
        for row in rows(fixture) {
            if row["role"] != "adopt" {
                continue;
            }
            positives += 1;
            production += usize::from(row["generation"] == "production");
            let word = hex(&row["word"]);
            for (slot, shift) in [16usize, 24, 64].into_iter().enumerate() {
                let mask = 0xffu128 << shift;
                if word & !mask == BASE & !mask {
                    registers[slot].insert(((word >> shift) & 0xff) as u16);
                }
            }
            roundtrip(table, decoder, arch, &row);
        }
        assert_eq!(
            production, 28,
            "{arch}: every production word, replayed on both targets"
        );
        assert_eq!(positives, POSITIVE, "{arch}");
        assert!(
            registers.iter().all(|values| values.len() == 256),
            "{arch}: all three complete byte domains: {:?}",
            registers
        );
    }
}

#[test]
fn exactly_one_reuse_field_and_provenance_are_added() {
    for (arch, _) in arches() {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let row = &raw["instructions"][KEY]["mod_groups"]["U32"];
        assert_eq!(row["_src"], SOURCE);
        assert_eq!(
            hex(&row["and_base"]),
            0x00000000000000000000000000000446u128
        );
        assert_eq!(
            hex(&row["variable_mask"]),
            // The canonical mask is the exact field union, including the two
            // independently measured reuse and negation flags, not control bits.
            0x08000000078008fffffffffffffff000u128
        );
        let fields = row["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 9);
        assert!(fields.iter().any(|f| f["shift"] == 123
            && f["bits"] == 1
            && f["extraction"] == "reuse"
            && f["token_idx"] == 3));
        assert!(fields
            .iter()
            .all(|f| f["shift"] != 122 && f["shift"] != 124));
        assert!(fields.iter().any(|f| {
            f["shift"] == 75 && f["bits"] == 1 && f["extraction"] == "neg" && f["token_idx"] == 3
        }));
        assert_eq!(
            row["claim_forbid"],
            serde_json::json!([{
                "bits": 1, "shift": 124, "values": [1]
            }])
        );
        let plain = &raw["instructions"][KEY]["mod_groups"][""];
        assert!(plain["_src"].as_str().unwrap() != SOURCE);
    }
}

#[test]
fn vendor_refused_bit124_fails_closed() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, decoder) = &loaded()[position];
        let mut rejected = 0;
        for row in rows(fixture) {
            if row["generation"] != "reuse" {
                continue;
            }
            let mask = row["label"]
                .as_str()
                .unwrap()
                .rsplit(':')
                .next()
                .unwrap()
                .parse::<u8>()
                .unwrap();
            if mask & 4 == 0 {
                continue;
            }
            let word = hex(&row["word"]);
            assert!(
                decoder.decode(word, 0, table).is_err(),
                "{arch}: vendor-refused mask {mask} accepted {word:032x}"
            );
            rejected += 1;
        }
        assert_eq!(rejected, 4, "{arch}");
    }
}

#[test]
fn known_negation_compatibility_four_states_roundtrip() {
    let fixture = hb300_fixture("viaddmnmx_u32_ii_negation_compatibility.jsonl");
    for (position, (arch, _)) in arches().iter().enumerate() {
        let (table, decoder) = &loaded()[position];
        let target = if *arch == "sm103a" { "SM103" } else { "SM100" };
        let mut states = std::collections::BTreeMap::new();
        for row in rows(fixture) {
            if row["target"] != target {
                continue;
            }
            let generation = row["generation"].as_str().unwrap().to_string();
            *states.entry(generation).or_insert(0usize) += 1;
            roundtrip(table, decoder, arch, &row);
        }
        assert_eq!(states.len(), 4, "{arch}");
        assert!(
            states.values().all(|count| *count == 4),
            "{arch}: {states:?}"
        );
    }
}
