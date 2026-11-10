//! Plain full-register VHMNMX: vendor-text encoding only, not execution semantics.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-vhmnmx-plain-production-2026-11-09";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    ("sm103a", hb300_fixture("sm103a_vhmnmx_plain_nvdisasm.jsonl")),
    ("sm100a", hb300_fixture("sm100a_vhmnmx_plain_nvdisasm.jsonl")),
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
        let mut total = 0usize;
        let mut census = std::collections::BTreeMap::<String, usize>::new();
        for row in rows(fixture) {
            if row["kind"] != "positive" { continue; }
            total += 1;
            *census.entry(row["generation"].as_str().unwrap().to_owned()).or_default() += 1;
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, "VHMNMX_R_R_R_R_P");
            assert_eq!(decoded.mod_group, "");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), text, "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass(&decoded), text);
            assert_eq!(encode(table, word, text), word & !(7u128 << 125));
        }
        assert_eq!(census["production"], 109, "{arch}: complete production census");
        assert_eq!(census["base"], 1);
        assert_eq!(census.get("reference").copied().unwrap_or(0), 0,
                   "{arch}: reference is already production");
        assert_eq!(census["absolute_modifier"], 6);
        assert_eq!(census["sign"], 4);
        assert_eq!(census["single_lower_bit"], 43);
        assert_eq!(census["field"], 1042);
        assert_eq!(total, 1205, "{arch}: full licensed-word census");
        let generation_field = |name: &str| rows(fixture).filter(|row|
            row["kind"] == "positive" && row["generation"] == "field" &&
            row["label"].as_str().unwrap().starts_with(name)).count();
        assert_eq!(generation_field("field:guard:"), 15);
        for reg in ["Rd", "Ra", "Rb", "Rc"] {
            assert_eq!(generation_field(&format!("field:{reg}:")), 255);
        }
        assert_eq!(generation_field("field:trailing-predicate:"), 7);

        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"]["VHMNMX_R_R_R_R_P"];
        assert_eq!(entry["_src"], SOURCE);
        assert_eq!(entry["operand_sig"], "R_R_R_R_P");
        assert_eq!(entry["scheduling"]["latency_source"], "synthetic");
        let group = &entry["mod_groups"][""];
        assert_eq!(group["_src"], SOURCE);
        assert_eq!(hex(&group["and_base"]) >> 96, 0);
        let fields = group["fields"].as_array().unwrap();
        let expected = [(4, 12, 0, "guard"), (8, 16, 1, "reg"), (8, 24, 2, "reg"),
                        (1, 72, 2, "neg"), (1, 73, 2, "abs"), (8, 32, 3, "reg"),
                        (1, 62, 3, "abs"), (1, 63, 3, "neg"), (8, 64, 4, "reg"),
                        (1, 83, 4, "abs"), (1, 84, 4, "neg"),
                        (3, 87, 5, "pred"), (1, 90, 5, "neg")];
        assert_eq!(fields.len(), expected.len());
        for (field, (bits, shift, token, extraction)) in fields.iter().zip(expected) {
            assert_eq!(field["bits"], bits);
            assert_eq!(field["shift"], shift);
            assert_eq!(field["token_idx"], token);
            assert_eq!(field["extraction"], extraction);
        }
    }
}

#[test]
fn unlicensed_and_text_inert_words_do_not_enter_vhmnmx() {
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
                assert_ne!(decoded.key, "VHMNMX_R_R_R_R_P", "{arch} overmatch {kind} {word:032x}");
            }
            if kind == "negative" {
                assert!(index.decode(word, 0, table).is_err(),
                        "{arch}: invalid/text-inert word accepted {word:032x}");
            }
        }
        assert_eq!((negative, adjacent, other, control), (42, 11, 4, 29),
                   "{arch}: complete raw negative/control census");
    }
}
