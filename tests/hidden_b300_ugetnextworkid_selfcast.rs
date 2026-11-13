//! Production UGETNEXTWORKID.SELFCAST text evidence; no GPU execution.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-ugetnextworkid-selfcast-2026-11-10";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    ("sm103a", hb300_fixture("sm103a_ugetnextworkid_selfcast_nvdisasm.jsonl")),
    ("sm100a", hb300_fixture("sm100a_ugetnextworkid_selfcast_nvdisasm.jsonl")),
]);

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLES: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLES.get_or_init(|| ARCHES.iter().map(|(arch, _)| {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    }).collect())
}

fn rows(fixture: &str) -> impl Iterator<Item=Value> + '_ {
    fixture.lines().map(|line| serde_json::from_str(line).unwrap())
}

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

#[test]
fn measured_production_and_field_words_roundtrip() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let (mut production, mut guards, mut pairs, mut total) =
            (0usize, 0usize, 0usize, 0usize);
        for row in rows(fixture) {
            if row["kind"] != "positive" { continue; }
            total += 1;
            match row["generation"].as_str().unwrap() {
                "production" => production += 1,
                "guard" => guards += 1,
                "byte_field" => pairs += 1,
                "base" => {},
                other => panic!("unexpected positive generation {other}"),
            }
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, "UGETNEXTWORKID_AURI_AURI");
            assert_eq!(decoded.mod_group, "SELFCAST");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), text, "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass(&decoded), text);
            assert_eq!(encode(table, word, text), word & !(7u128 << 125));
        }
        assert_eq!((production, guards, pairs, total),
                   (22, 15, 232, 270), "{arch}: positive census");
        for value in 0u8..=253 {
            let text = format!("UGETNEXTWORKID.SELFCAST [UR{value}], [UR{}] ;", value + 1);
            let parsed = cubit::parse_sass(&text, 0).unwrap();
            assert!(cubit::encoder::encode_instruction(&parsed, table).is_ok(), "rejected {text}");
        }
        for text in [
            "UGETNEXTWORKID.SELFCAST [UR254], [URZ] ;",
            "UGETNEXTWORKID.SELFCAST [UR4], [UR7] ;",
            "UGETNEXTWORKID.SELFCAST [UR4+0x10], [UR5] ;",
            "UGETNEXTWORKID.SELFCAST [UR4], [UR5+0x10] ;",
            "UGETNEXTWORKID.SELFCAST [R4], [UR5] ;",
        ] {
            let parsed = cubit::parse_sass(text, 0).unwrap();
            assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "accepted {text}");
        }
    }
}

#[test]
fn unlicensed_encodings_do_not_enter_selfcast() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let (mut negative, mut adjacent, mut other, mut control) =
            (0usize, 0usize, 0usize, 0usize);
        for row in rows(fixture) {
            let kind = row["kind"].as_str().unwrap();
            if matches!(kind, "positive" | "control_plane") {
                control += usize::from(kind == "control_plane");
                continue;
            }
            match kind {
                "negative" => negative += 1,
                "adjacent_modifier" => adjacent += 1,
                "other_family" => other += 1,
                other => panic!("unexpected negative kind {other}"),
            }
            let word = hex(&row["word"]);
            if let Ok(decoded) = index.decode(word, 0, table) {
                assert_ne!(decoded.mod_group, "SELFCAST",
                           "{arch} overmatch {kind} {word:032x}");
            }
            if kind == "negative" {
                assert!(index.decode(word, 0, table).is_err(),
                        "{arch}: invalid/text-inert word accepted {word:032x}");
            }
        }
        assert_eq!((negative, adjacent, other, control),
                   (2179, 130, 2, 35),
                   "{arch}: complete raw negative/control census");
    }
}

#[test]
fn provenance_and_broadcast_remain_separate() {
    for (index, (arch, _fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let broadcast = index.decode(hex(&serde_json::json!(
            "000fec000800010000000000040073ca")), 0, table).unwrap();
        assert_eq!(broadcast.key, "UGETNEXTWORKID_AURI_AURI");
        assert_eq!(broadcast.mod_group, "BROADCAST");
        assert_eq!(cubit::printer::to_sass_lossless(&broadcast),
                   "UGETNEXTWORKID.BROADCAST [UR4], [UR5]");
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"]["UGETNEXTWORKID_AURI_AURI"];
        assert_eq!(entry["operand_sig"], "AURI_AURI");
        assert!(entry["mod_groups"].get("BROADCAST").is_some());
        let group = &entry["mod_groups"]["SELFCAST"];
        assert_eq!(group["_src"], SOURCE);
        assert_eq!(group["and_base"], "0x000000000800000000000000000003ca");
        assert_eq!(group["variable_mask"], "0x000000000000000000000000ff00f000");
        assert_eq!(hex(&group["and_base"]) >> 96, 0);
        assert_eq!(group["claim_forbid"].as_array().unwrap().len(), 84);
        let fields = group["fields"].as_array().unwrap();
        let expected = [(4, 12, 0, "guard"), (8, 24, 1, "sub_ur0"),
                        (8, 24, 2, "sub_ur0_m1")];
        assert_eq!(fields.len(), expected.len());
        for (field, (bits, shift, token, extraction)) in fields.iter().zip(expected) {
            assert_eq!(field["bits"], bits);
            assert_eq!(field["shift"], shift);
            assert_eq!(field["token_idx"], token);
            assert_eq!(field["extraction"], extraction);
        }
    }
}
