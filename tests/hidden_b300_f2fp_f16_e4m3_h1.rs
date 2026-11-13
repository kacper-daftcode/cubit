//! F2FP.F16.E4M3.UNPACK_B source-H1 production text, without GPU execution.
include!("hb300_fixture.inc");
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-f2fp-f16-e4m3-h1-production-2026-11-09";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    ("sm103a", hb300_fixture("sm103a_f2fp_f16_e4m3_h1_nvdisasm.jsonl")),
    ("sm100a", hb300_fixture("sm100a_f2fp_f16_e4m3_h1_nvdisasm.jsonl")),
]);

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLES: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLES.get_or_init(|| ARCHES.iter().map(|(arch, _)| {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    }).collect())
}

fn rows(fixture: &str) -> impl Iterator<Item = Value> + '_ {
    fixture.lines().map(|line| serde_json::from_str(line).unwrap())
}

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn roundtrip(table: &IsaTable, index: &DecodeIndex, arch: &str, row: &Value) {
    let word = hex(&row["word"]);
    let text = row["nvidia_sass"].as_str().unwrap();
    let decoded = index.decode(word, 0, table).unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
    assert_eq!(decoded.key, "F2FP_R_R");
    assert_eq!(decoded.mod_group, "F16,E4M3,UNPACK_B");
    assert_eq!(cubit::printer::to_sass_lossless(&decoded), text, "{arch} {word:032x}");
    assert_eq!(cubit::printer::to_sass(&decoded), text);
    if row["kind"] == "positive" {
        assert!(decoded.fields.iter().any(|f| f.extraction == "opmod:H1" && f.shift == 88
            && f.token_idx == 2 && f.value == 1), "{arch}: missing H1 field {word:032x}");
    }
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    let encoded = cubit::encoder::encode_instruction(&parsed, table);
    assert_eq!(encoded.unwrap(), word & !(7u128 << 125), "{arch}: encode {word:032x} {text}");
}

#[test]
fn production_h1_and_h0_field_matrix_roundtrips() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let (mut production, mut positive, mut h0) = (0, 0, 0);
        for row in rows(fixture) {
            match row["kind"].as_str().unwrap() {
                "positive" => {
                    positive += 1;
                    production += usize::from(row["generation"] == "production");
                    roundtrip(table, index, arch, &row);
                }
                "h0_control" => {
                    h0 += 1;
                    assert!(hex(&row["word"]) & (1u128 << 88) == 0);
                    roundtrip(table, index, arch, &row);
                }
                _ => {}
            }
        }
        assert_eq!((production, positive, h0), (189, 752, 565), "{arch}: positive census");
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 2);
        let entry = &raw["instructions"]["F2FP_R_R"];
        let group = &entry["mod_groups"]["F16,E4M3,UNPACK_B"];
        assert_eq!(group["_src"], SOURCE);
        assert_eq!(group["and_base"], "0x00000000020006ff00000000ff00023e");
        let expected_mask = (0xfu128 << 12) | (0xffu128 << 16)
            | (0xffu128 << 32) | (1u128 << 88);
        assert_eq!(hex(&group["variable_mask"]), expected_mask);
        assert_eq!(group["claim_forbid"], serde_json::json!([{"bits": 1, "shift": 74, "values": [0]}]));
        let fields = group["fields"].as_array().unwrap();
        let expected = [(4, 12, 0, "guard"), (8, 16, 1, "reg"),
                        (8, 32, 2, "reg"), (1, 88, 2, "opmod:H1")];
        assert_eq!(fields.len(), 4);
        for (field, (bits, shift, token, extraction)) in fields.iter().zip(expected) {
            assert_eq!(field["bits"], bits);
            assert_eq!(field["shift"], shift);
            assert_eq!(field["token_idx"], token);
            assert_eq!(field["extraction"], extraction);
        }
        let alias = &entry["mod_groups"]["E4M3,F16,UNPACK_B"];
        assert_eq!(alias["variable_mask"], group["variable_mask"]);
        assert_eq!(alias["fields"], group["fields"]);
        assert_eq!(alias["encode_only"], true);
        assert_eq!(alias["_src"], SOURCE);
        assert_eq!(alias["claim_forbid"], group["claim_forbid"]);
    }
}

#[test]
fn adjacent_and_unlicensed_encodings_do_not_enter_h1_row() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let (mut negative, mut adjacent, mut other, mut control) = (0, 0, 0, 0);
        for row in rows(fixture) {
            let kind = row["kind"].as_str().unwrap();
            if matches!(kind, "positive" | "h0_control" | "control_plane") {
                control += usize::from(kind == "control_plane");
                continue;
            }
            match kind {
                "negative" => negative += 1,
                "adjacent_modifier" => adjacent += 1,
                "other_family" => other += 1,
                other => panic!("unexpected kind {other}"),
            }
            let word = hex(&row["word"]);
            if let Ok(decoded) = index.decode(word, 0, table) {
                let h1_claim = decoded.mod_group == "F16,E4M3,UNPACK_B"
                    && decoded.fields.iter().any(|f| f.extraction == "opmod:H1" && f.value == 1);
                assert!(!h1_claim, "{arch} overmatch {kind} {word:032x}");
            }
            if kind == "negative" && word & (1u128 << 88) != 0 {
                assert!(index.decode(word, 0, table).is_err(),
                        "{arch}: invalid/text-inert H1 word accepted {word:032x}");
            }
        }
        assert_eq!((negative, adjacent, other, control), (93, 7, 5, 36), "{arch}: negative census");
    }
}
