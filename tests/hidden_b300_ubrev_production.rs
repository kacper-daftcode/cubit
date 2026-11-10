//! Production UBREV UR,UR: vendor-text encoding evidence, not uniform semantics.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-ubrev-production-2026-11-08";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    ("sm103a", hb300_fixture("sm103a_ubrev_production_nvdisasm.jsonl")),
    ("sm100a", hb300_fixture("sm100a_ubrev_production_nvdisasm.jsonl")),
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
        let (mut production, mut register, mut guard, mut reuse, mut lower, mut total) =
            (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
        for row in rows(fixture) {
            if row["kind"] != "positive" { continue; }
            total += 1;
            let generation = row["generation"].as_str().unwrap();
            match generation {
                "production" => production += 1,
                "single_lower_bit" => lower += 1,
                "reuse_control" => reuse += 1,
                "field" if row["label"].as_str().unwrap().starts_with("register:") => register += 1,
                "field" => guard += 1,
                "base" => {},
                other => panic!("unexpected positive generation {other}"),
            }
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, "UBREV_UR_UR");
            assert_eq!(decoded.mod_group, "");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), text, "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass(&decoded), text);
            assert_eq!(encode(table, word, text), word & !(7u128 << 125));
        }
        assert_eq!(production, 10, "{arch}: stored production witness census");
        assert_eq!(register, 510, "{arch}: one URd and one URa word is shared with base");
        assert_eq!(guard, 15, "{arch}: the unguarded base is already present");
        assert_eq!(reuse, 0, "{arch}: every tested reuse encoding is refused");
        assert_eq!(lower, 0, "{arch}: text-inert lower bits fail closed");
        assert_eq!(total, 536, "{arch}: complete raw positive census");

        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"]["UBREV_UR_UR"];
        assert_eq!(entry["_src"], SOURCE);
        assert_eq!(entry["operand_sig"], "UR_UR");
        assert_eq!(entry["scheduling"]["latency_source"], "synthetic");
        let group = &entry["mod_groups"][""];
        assert_eq!(group["_src"], SOURCE);
        assert_eq!(group["and_base"], "0x000000000800000000000000000002be");
        assert_eq!(group["variable_mask"], "0x0000000000000000000000ff00fff000");
        assert_eq!(hex(&group["and_base"]) >> 96, 0);
        let fields = group["fields"].as_array().unwrap();
        let expected = [(4, 12, 0, "guard"), (8, 16, 1, "ureg_ff"),
                        (8, 32, 2, "ureg_ff")];
        assert_eq!(fields.len(), expected.len());
        assert_eq!(group["claim_forbid"].as_array().unwrap().len(), 3);
        for (index, bit) in [122u64, 123, 124].into_iter().enumerate() {
            assert_eq!(group["claim_forbid"][index]["shift"], bit);
            assert_eq!(group["claim_forbid"][index]["bits"], 1);
            assert_eq!(group["claim_forbid"][index]["values"][0], 1);
        }
        for (field, (bits, shift, token, extraction)) in fields.iter().zip(expected) {
            assert_eq!(field["bits"], bits);
            assert_eq!(field["shift"], shift);
            assert_eq!(field["token_idx"], token);
            assert_eq!(field["extraction"], extraction);
        }
    }
}

#[test]
fn unlicensed_encodings_do_not_enter_ubrev() {
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
                assert_ne!(decoded.key, "UBREV_UR_UR", "{arch} overmatch {kind} {word:032x}");
            }
            if kind == "negative" {
                assert!(index.decode(word, 0, table).is_err(),
                        "{arch}: invalid/text-inert word accepted {word:032x}");
            }
        }
        assert_eq!((negative, adjacent, other, control), (76, 0, 3, 29),
                   "{arch}: complete raw negative/control census");
    }
}
