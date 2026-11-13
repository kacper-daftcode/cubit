//! Production ATOMS.MAX [R+UR+imm] text and encoding evidence; no GPU execution.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-atoms-max-production-2026-11-09";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    ("sm103a", hb300_fixture("sm103a_atoms_max_production_nvdisasm.jsonl")),
    ("sm100a", hb300_fixture("sm100a_atoms_max_production_nvdisasm.jsonl")),
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

#[test]
fn measured_production_and_field_words_roundtrip() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let (mut production, mut guards, mut bytes, mut cross, mut total) =
            (0usize, 0usize, 0usize, 0usize, 0usize);
        let mut guarded_encode_refusals = 0usize;
        for row in rows(fixture) {
            if row["kind"] != "positive" { continue; }
            total += 1;
            match row["generation"].as_str().unwrap() {
                "production" => production += 1,
                "guard" => guards += 1,
                "byte_field" => bytes += 1,
                "base" | "single_lower_bit" | "immediate" => {},
                "cross" => cross += 1,
                other => panic!("unexpected positive generation {other}"),
            }
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, "ATOMS_R_ARURI_R");
            assert_eq!(decoded.mod_group, "MAX");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), text, "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass(&decoded), text);
            let control = cubit::scheduling::format_control_code(
                &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
            let encoded = cubit::encoder::encode_instruction(&parsed, table);
            if *arch == "sm103a" && text.starts_with('@') {
                guarded_encode_refusals += 1;
                let error = match encoded {
                    Err(error) => error.to_string(),
                    Ok(value) => panic!(
                        "{arch} {word:032x}: guarded form unexpectedly assembled {value:032x}: {text}"
                    ),
                };
                assert!(error.contains("BUG-080"), "{arch} {word:032x}: {error}");
            } else {
                assert_eq!(encoded.unwrap(), word & !(7u128 << 125));
            }
        }
        assert_eq!((production, guards, bytes, cross, total),
                   (125, 15, 1784, 1620, 3564), "{arch}: positive census");
        assert_eq!(guarded_encode_refusals, if *arch == "sm103a" { 1095 } else { 0 },
                   "{arch}: BUG-080 guarded encode census");
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"]["ATOMS_R_ARURI_R"];
        assert_eq!(entry["_src"], SOURCE);
        assert_eq!(entry["operand_sig"], "R_ARURI_R");
        assert_eq!(entry["scheduling"]["latency_source"], "synthetic");
        let group = &entry["mod_groups"]["MAX"];
        assert_eq!(group["_src"], SOURCE);
        assert_eq!(group["and_base"], "0x0000000009000000000000000000098c");
        assert_eq!(group["variable_mask"], "0x00000000000000fffffffffffffff000"); // T-26: the canonical table writes masks with the 0x prefix (the candidate wrote this one bare)
        assert_eq!(hex(&group["and_base"]) >> 96, 0);
        assert_eq!(group["claim_forbid"].as_array().unwrap().len(), 1);
        assert_eq!(group["claim_forbid"][0]["bits"], 8);
        assert_eq!(group["claim_forbid"][0]["shift"], 24);
        assert_eq!(group["claim_forbid"][0]["values"][0], 255);
        let fields = group["fields"].as_array().unwrap();
        let expected = [(4, 12, 0, "guard"), (8, 16, 1, "reg"),
                        (8, 24, 2, "sub_r0"), (8, 32, 3, "reg"),
                        (24, 40, 2, "sub_imm1"), (8, 64, 2, "sub_ur1")];
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
fn unlicensed_encodings_do_not_enter_atoms_max() {
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
                assert!(decoded.key != "ATOMS_R_ARURI_R" || decoded.mod_group != "MAX",
                        "{arch} overmatch {kind} {word:032x}");
            }
            if kind == "negative" {
                assert!(index.decode(word, 0, table).is_err(),
                        "{arch}: invalid/text-inert word accepted {word:032x}");
            }
        }
        assert_eq!((negative, adjacent, other, control), (286, 496, 4, 37),
                   "{arch}: complete raw negative/control census");
    }
}
