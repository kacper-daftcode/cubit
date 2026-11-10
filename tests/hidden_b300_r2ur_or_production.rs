//! Production R2UR.OR: measured vendor text, not reduction or uniform semantics.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-r2ur-or-production-2026-11-09";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    ("sm103a", hb300_fixture("sm103a_r2ur_or_production_nvdisasm.jsonl")),
    ("sm100a", hb300_fixture("sm100a_r2ur_or_production_nvdisasm.jsonl")),
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
    for (arch_index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[arch_index];
        let (mut production, mut field, mut reuse, mut lower, mut total) =
            (0usize, 0usize, 0usize, 0usize, 0usize);
        for row in rows(fixture) {
            if row["kind"] != "positive" { continue; }
            total += 1;
            match row["generation"].as_str().unwrap() {
                "production" => production += 1,
                "field" => field += 1,
                "reuse_control" => reuse += 1,
                "single_lower_bit" => lower += 1,
                "base" => {},
                other => panic!("unexpected positive generation {other}"),
            }
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, "R2UR_P_UR_R");
            assert_eq!(decoded.mod_group, "OR");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), text, "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass(&decoded), text);
            assert_eq!(encode(table, word, text), word & !(7u128 << 125));
        }
        assert_eq!(production, 62, "{arch}: stored production census");
        assert_eq!(field, 532, "{arch}: complete guard/pred/UR/R field census");
        assert_eq!(reuse, 0, "{arch}: all seven B300 reuse masks are refused");
        assert_eq!(lower, 0, "{arch}: field one-bit words are shared with field probes");
        assert_eq!(total, 595, "{arch}: complete raw positive census");

        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"]["R2UR_P_UR_R"];
        assert_eq!(entry["operand_sig"], "P_UR_R");
        // the batch (T-26, 2026-11-10): the plain group beside the new row is a measured row on main since 2026-11-08
        // (rows-intalu-2026-11-07: guard and reuse as fields, no operand byte baked into the constant bits); the
        // candidate pinned the harvest row of its base (and_base ...00ff72ca), which it did not touch either
        assert_eq!(entry["mod_groups"][""]["and_base"],
                   "0x000000000000000000000000000002ca");
        assert_eq!(entry["mod_groups"][""]["_src"].as_str().or(entry["_src"].as_str()), Some("rows-intalu-2026-11-07"));
        let group = &entry["mod_groups"]["OR"];
        assert_eq!(group["_src"], SOURCE);
        assert_eq!(group["and_base"], "0x000000000010000000000000000002ca");
        assert_eq!(group["variable_mask"], "0x00000000000e000000000000fffff000");
        let fields = group["fields"].as_array().unwrap();
        let expected = [(4, 12, 0, "guard"), (3, 81, 1, "pred"),
                        (8, 16, 2, "ureg"), (8, 24, 3, "reg")];
        assert_eq!(fields.len(), expected.len());
        for (field, (bits, shift, token, extraction)) in fields.iter().zip(expected) {
            assert_eq!(field["bits"], bits);
            assert_eq!(field["shift"], shift);
            assert_eq!(field["token_idx"], token);
            assert_eq!(field["extraction"], extraction);
        }
        assert_eq!(group["claim_forbid"].as_array().unwrap().len(), 3);
        for (forbid_index, bit) in [122u64, 123, 124].into_iter().enumerate() {
            assert_eq!(group["claim_forbid"][forbid_index]["shift"], bit);
            assert_eq!(group["claim_forbid"][forbid_index]["bits"], 1);
            assert_eq!(group["claim_forbid"][forbid_index]["values"][0], 1);
        }
    }
}

#[test]
fn unlicensed_encodings_do_not_enter_r2ur_or() {
    for (arch_index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[arch_index];
        let (mut negative, mut adjacent, mut other, mut control, mut no_text) =
            (0usize, 0usize, 0usize, 0usize, 0usize);
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
                "no_text" => no_text += 1,
                other => panic!("unexpected negative kind {other}"),
            }
            let word = hex(&row["word"]);
            if let Ok(decoded) = index.decode(word, 0, table) {
                assert_ne!((decoded.key.as_str(), decoded.mod_group.as_str()),
                           ("R2UR_P_UR_R", "OR"), "{arch} overmatch {kind} {word:032x}");
            }
            if kind == "negative" {
                assert!(index.decode(word, 0, table).is_err(),
                        "{arch}: invalid/text-inert word accepted {word:032x}");
            }
        }
        assert_eq!((negative, adjacent, other, control, no_text), (76, 7, 1, 29, 0),
                   "{arch}: complete raw negative/control census");
    }
}
