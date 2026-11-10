//! Production USGXT: complete-word vendor-text evidence, not silicon semantics.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-usgxt-production-2026-11-09";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    ("sm103a", hb300_fixture("sm103a_usgxt_production_nvdisasm.jsonl")),
    ("sm100a", hb300_fixture("sm100a_usgxt_production_nvdisasm.jsonl")),
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
        let (mut production, mut register, mut guard, mut immediate, mut lower, mut total) =
            (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
        for row in rows(fixture) {
            if row["kind"] != "positive" { continue; }
            total += 1;
            let generation = row["generation"].as_str().unwrap();
            match generation {
                "production" => production += 1,
                "single_lower_bit" => lower += 1,
                "reuse_control" => panic!("reused bank accepted"),
                "field" if row["label"].as_str().unwrap().starts_with("register:") => register += 1,
                "field" => guard += 1,
                "immediate" => immediate += 1,
                "base" => {},
                other => panic!("unexpected positive generation {other}"),
            }
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, "USGXT_UR_UR_II");
            assert_eq!(decoded.mod_group, "");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), text, "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass(&decoded), text);
            assert_eq!(encode(table, word, text), word & !(7u128 << 125));
        }
        assert_eq!((production, register, guard, immediate, lower, total),
                   (2, 510, 15, 522, 20, 1070), "{arch}: positive census");
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"]["USGXT_UR_UR_II"];
        assert_eq!(entry["_src"], SOURCE);
        assert_eq!(entry["operand_sig"], "UR_UR_II");
        assert_eq!(entry["scheduling"]["latency_source"], "synthetic");
        let group = &entry["mod_groups"][""];
        assert_eq!(group["_src"], SOURCE);
        // (the candidate carried the native word's guard, 7, in and_base under the guard field: 0x...789a; cleared on
        // `main`, as on every measured row -- session T-26, 2026-11-10)
        assert_eq!(group["and_base"], "0x0000000008000200000000000000089a");
        assert_eq!(group["variable_mask"], "0x0000000000000000fffffffffffff000");
        assert_eq!(hex(&group["and_base"]) >> 96, 0);
        let fields = group["fields"].as_array().unwrap();
        let expected = [(4, 12, 0, "guard"), (8, 16, 1, "ureg_ff"),
                        (8, 24, 2, "ureg_ff"), (32, 32, 3, "imm")];
        assert_eq!(fields.len(), expected.len());
        assert_eq!(group["claim_forbid"].as_array().unwrap().len(), 44);
        for (field, (bits, shift, token, extraction)) in fields.iter().zip(expected) {
            assert_eq!(field["bits"], bits);
            assert_eq!(field["shift"], shift);
            assert_eq!(field["token_idx"], token);
            assert_eq!(field["extraction"], extraction);
        }
    }
}

#[test]
fn unlicensed_encodings_do_not_enter_usgxt() {
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
                assert_ne!(decoded.key, "USGXT_UR_UR_II",
                           "{arch} overmatch {kind} {word:032x}");
            }
            if kind == "negative" {
                assert!(index.decode(word, 0, table).is_err(),
                        "{arch}: invalid/text-inert word accepted {word:032x}");
            }
        }
        assert_eq!((negative, adjacent, other, control), (42, 2, 3, 29),
                   "{arch}: complete raw negative/control census");
    }
}
