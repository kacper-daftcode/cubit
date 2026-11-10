//! Production F2F.BF16.F32 register/UR text evidence, without GPU execution.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

// T-26 (2026-11-10): this candidate (hidden-b300/f2f-bf16-f32-ur, the 110 production words) and
// hidden-b300/f2f-bf16-f32-round (the same row re-measured half an hour later with the fail-closed list over the
// text-inert bits, plus the seven rounding / FTZ rows) add the same row from the same base. The table carries the
// later, stricter row under its tag; this file keeps the production fixture and reads the row through that tag.
const SOURCE: &str = "rows-f2f-bf16-f32-ur-round-ftz-2026-11-09";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    (
        "sm103a",
        hb300_fixture("sm103a_f2f_bf16_f32_ur_nvdisasm.jsonl"),
    ),
    (
        "sm100a",
        hb300_fixture("sm100a_f2f_bf16_f32_ur_nvdisasm.jsonl"),
    ),
]);

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
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

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

#[test]
fn measured_production_and_field_words_roundtrip() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let (mut production, mut guards, mut bytes, mut signs, mut cross, mut total) =
            (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
        for row in rows(fixture) {
            if row["kind"] != "positive" {
                continue;
            }
            total += 1;
            match row["generation"].as_str().unwrap() {
                "production" => production += 1,
                "guard" => guards += 1,
                "byte_field" => bytes += 1,
                "base" | "single_lower_bit" => {}
                "sign" => signs += 1,
                "cross" => cross += 1,
                other => panic!("unexpected positive generation {other}"),
            }
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, "F2F_R_UR");
            assert_eq!(decoded.mod_group, "BF16,F32");
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                text,
                "{arch} {word:032x}"
            );
            assert_eq!(cubit::printer::to_sass(&decoded), text);
            let control = cubit::scheduling::format_control_code(
                &cubit::scheduling::decode_sched_upper32((word >> 96) as u32),
            );
            let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
            let encoded = cubit::encoder::encode_instruction(&parsed, table);
            assert_eq!(encoded.unwrap(), word & !(7u128 << 125));
        }
        assert_eq!(
            (production, guards, bytes, signs, cross, total),
            (110, 15, 503, 3, 144, 775),
            "{arch}: positive census"
        );
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 8); // the row + the seven rounding / FTZ rows
        let entry = &raw["instructions"]["F2F_R_UR"];
        assert_eq!(entry["operand_sig"], "R_UR");
        assert_eq!(entry["scheduling"]["pipe_name"], "UNKNOWN");
        assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 10); // two F32 / F64 rows + the eight BF16,F32 rows
        let group = &entry["mod_groups"]["BF16,F32"];
        assert_eq!(group["_src"], SOURCE);
        assert_eq!(group["and_base"], "0x00000000082020000000000000000d04");
        assert_eq!(group["variable_mask"], "0x0000000000000000c00000ff00fff000"); // T-26: the canonical table writes masks with the 0x prefix (the candidate wrote this one bare)
        assert_eq!(hex(&group["and_base"]) >> 96, 0);
        // the adopted row is the later candidate's: 55 single-bit exclusions over the text-inert bits
        assert_eq!(group["claim_forbid"].as_array().map(|a| a.len()), Some(55));
        let fields = group["fields"].as_array().unwrap();
        let expected = [
            (4, 12, 0, "guard"),
            (8, 16, 1, "reg"),
            (8, 32, 2, "ureg"),
            (1, 63, 2, "neg"),
            (1, 62, 2, "abs"),
        ];
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
fn unlicensed_encodings_do_not_enter_bf16_f32_ur() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let (mut negative, mut adjacent, mut other, mut control) = (0usize, 0usize, 0usize, 0usize);
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
                assert_ne!(
                    decoded.mod_group, "BF16,F32",
                    "{arch} overmatch {kind} {word:032x}"
                );
            }
            if kind == "negative" {
                assert!(
                    index.decode(word, 0, table).is_err(),
                    "{arch}: invalid/text-inert word accepted {word:032x}"
                );
            }
        }
        assert_eq!(
            (negative, adjacent, other, control),
            (88, 11, 5, 37),
            "{arch}: complete raw negative/control census"
        );
    }
}
