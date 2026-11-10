//! B300 I2I.S8.S32.SAT measured vendor-text lattice; no execution claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-i2i-s8-s32-sat-2026-11-09";
const KEY: &str = "I2I.S8.S32.SAT_R_R";
const PRODUCTION: usize = 64;
const POSITIVE: usize = 592;
const FIELD: usize = 526;
const NEGATIVE: usize = 78;
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    ("sm103a", hb300_fixture("sm103a_i2i_s8_s32_sat_nvdisasm.jsonl")),
    ("sm100a", hb300_fixture("sm100a_i2i_s8_s32_sat_nvdisasm.jsonl")),
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

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

#[test]
fn all_licensed_production_and_field_words_roundtrip() {
    for (arch_index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[arch_index];
        let (mut production, mut positive, mut fields) = (0usize, 0usize, 0usize);
        for row in rows(fixture) {
            if row["kind"] != "positive" { continue; }
            positive += 1;
            production += usize::from(row["generation"] == "production");
            fields += usize::from(row["generation"] == "field");
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, KEY, "{arch} {word:032x}");
            assert_eq!(decoded.mod_group, "", "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), text,
                "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass(&decoded), text, "{arch} {word:032x}");
            assert_eq!(encode(table, word, text), word & !(7u128 << 125),
                "{arch} {word:032x}");
        }
        assert_eq!(production, PRODUCTION, "{arch}: every distinct H production word");
        assert_eq!(fields, FIELD, "{arch}: measured controlled fields");
        assert_eq!(positive, POSITIVE, "{arch}: complete positive census");
    }
}

#[test]
fn i2i_provenance_is_present_and_scoped() {
    for (arch, _) in *ARCHES {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["_src"], SOURCE);
        assert_eq!(entry["mod_groups"][""]["_src"], SOURCE);
        assert!(raw["_meta"]["provenance"]["sources"][SOURCE]["note"]
            .as_str().unwrap().contains("not execution"));
    }
}

#[test]
fn unlicensed_and_inert_words_fail_closed() {
    for (arch_index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[arch_index];
        let mut negatives = 0usize;
        for row in rows(fixture) {
            if row["kind"] != "negative" { continue; }
            negatives += 1;
            let word = hex(&row["word"]);
            if let Ok(decoded) = index.decode(word, 0, table) {
                panic!("{arch}: negative {word:032x} accepted as {} {}",
                    decoded.key, decoded.mod_group);
            }
        }
        assert_eq!(negatives, NEGATIVE, "{arch}: incomplete negative surface");
        for bad in [
            "I2I.U8.S32.SAT R1, R2",
            "I2I.S8.S32.SATRELU R1, R2",
            "I2I.S8.S32.SAT R1, -R2",
        ] {
            let parsed = cubit::parse_sass(&format!("{bad} ;"), 0).unwrap();
            assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(),
                "{arch}: {bad}");
        }
    }
}
