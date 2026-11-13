//! Production IMAD.U32.X R,R,IMM,R,P forms, without GPU execution.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-imad-u32x-production-2026-11-10";
const GROUP: &str = "U32,X";
const KEY: &str = "IMAD_R_R_II_R_P";

fn arches() -> [(&'static str, &'static str); 2] {
    [
        ("sm103a", hb300_fixture("sm103a_imad_u32x_nvdisasm.jsonl")),
        ("sm100a", hb300_fixture("sm100a_imad_u32x_nvdisasm.jsonl")),
    ]
}

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
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

fn roundtrip(table: &IsaTable, index: &DecodeIndex, arch: &str, row: &Value) {
    let word = hex(&row["word"]);
    let text = row["nvidia_sass"].as_str().unwrap();
    let decoded = index
        .decode(word, 0, table)
        .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
    assert_eq!(decoded.key, KEY, "{arch} {word:032x}");
    assert_eq!(decoded.mod_group, GROUP, "{arch} {word:032x}");
    let lossless = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(lossless, text, "{arch} {word:032x}");
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {lossless} ;"), 0).unwrap();
    let encoded = cubit::encoder::encode_instruction(&parsed, table)
        .unwrap_or_else(|error| panic!("{arch}: encode {word:032x} {text}: {error}"));
    assert_eq!(
        encoded,
        word & !(7u128 << 125),
        "{arch}: encode {word:032x} {text}"
    );
}

#[test]
fn production_and_measured_fields_roundtrip() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let (mut production, mut positive) = (0, 0);
        for row in rows(fixture) {
            if row["kind"] == "positive" {
                positive += 1;
                production += usize::from(row["generation"] == "production");
                roundtrip(table, index, arch, &row);
            }
        }
        assert_eq!((production, positive), (76, 911), "{arch}: positive census");
    }
}

#[test]
fn exact_row_fields_and_provenance() {
    let expected_fields = serde_json::json!([
        {"bits": 4, "extraction": "guard", "shift": 12, "token_idx": 0},
        {"bits": 8, "extraction": "reg", "shift": 16, "token_idx": 1},
        {"bits": 8, "extraction": "reg", "shift": 24, "token_idx": 2},
        {"bits": 1, "extraction": "reuse", "shift": 122, "token_idx": 2},
        {"bits": 8, "extraction": "reg", "shift": 64, "token_idx": 4},
        {"bits": 1, "extraction": "reuse", "shift": 124, "token_idx": 4},
        {"bits": 3, "extraction": "pred", "shift": 87, "token_idx": 5},
        {"bits": 32, "extraction": "imm", "shift": 32, "token_idx": 3},
        {"bits": 1, "extraction": "inv", "shift": 90, "token_idx": 5},
    ]);
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"][KEY];
        let group = &entry["mod_groups"][GROUP];
        assert_eq!(group["_src"], SOURCE);
        assert_eq!(group["and_base"], "0x00000000000e04000000000000000824");
        assert_eq!(group["variable_mask"], "0x14000000078000fffffffffffffff000");
        assert_eq!(group["fields"], expected_fields);
        assert!(group.get("claim_forbid").is_none());
        assert!(group["count"].is_null());
    }
}

#[test]
fn unlicensed_inert_and_adjacent_words_stay_out_of_u32x() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let (mut negative, mut adjacent, mut other, mut control) = (0, 0, 0, 0);
        for row in rows(fixture) {
            let kind = row["kind"].as_str().unwrap();
            if matches!(kind, "positive" | "control_plane") {
                control += usize::from(kind == "control_plane");
                continue;
            }
            match kind {
                "negative" => negative += 1,
                "adjacent_form" => adjacent += 1,
                "other_family" => other += 1,
                other => panic!("unexpected kind {other}"),
            }
            let word = hex(&row["word"]);
            if let Ok(decoded) = index.decode(word, 0, table) {
                assert_ne!(
                    decoded.mod_group, GROUP,
                    "{arch} overmatch {kind} {word:032x}"
                );
            }
        }
        assert_eq!(
            (negative, adjacent, other, control),
            (25, 4, 3, 32),
            "{arch}: negative census"
        );
    }
}
