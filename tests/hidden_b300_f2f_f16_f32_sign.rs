//! Measured F2F.F16.F32 guard/NEG/ABS repair; CPU vendor text only.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

const SOURCE: &str = "rows-f2f-f16-f32-sign-2026-11-09";
const KEY: &str = "F2F_R_R";
const MOD_GROUP: &str = "F16,F32";
const PRODUCTION: usize = 44;
const POSITIVE: usize = 618;
const FIELD: usize = 525;
const NEGATIVE: usize = 74;
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    ("sm103a", hb300_fixture("sm103a_f2f_f16_f32_sign_nvdisasm.jsonl")),
    ("sm100a", hb300_fixture("sm100a_f2f_f16_f32_sign_nvdisasm.jsonl")),
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
fn every_licensed_plain_word_decodes_renders_and_reencodes() {
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
            assert_eq!(decoded.mod_group, MOD_GROUP, "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), text,
                "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass(&decoded), text,
                "{arch} {word:032x}");
            assert_eq!(encode(table, word, text), word & !(7u128 << 125),
                "{arch} {word:032x} {text}");
        }
        assert_eq!(production, PRODUCTION, "{arch}: all distinct production NEG words");
        assert_eq!(positive, POSITIVE, "{arch}: complete positive census");
        assert_eq!(fields, FIELD, "{arch}: guard/Rd/Ra controlled field census");
    }
}

#[test]
fn measured_negatives_stay_out_of_plain_and_neighbours_remain_separate() {
    for (arch_index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[arch_index];
        let mut counts = BTreeMap::new();
        for row in rows(fixture) {
            let kind = row["kind"].as_str().unwrap().to_string();
            if kind == "positive" { continue; }
            *counts.entry(kind.clone()).or_insert(0usize) += 1;
            // Scheduling alternatives intentionally retain the operation/operand form.
            if kind == "control_plane" { continue; }
            let word = hex(&row["word"]);
            let decoded = index.decode(word, 0, table);
            if let Ok(value) = decoded {
                assert!(!(value.key == KEY && value.mod_group == MOD_GROUP),
                    "{arch}: {kind} {word:032x} entered plain F16,F32; \
                     legacy alternate-family matches are outside this scoped repair");
            }
        }
        assert_eq!(counts["negative"], NEGATIVE, "{arch}: negative census");
        assert_eq!(counts["adjacent_modifier"], 13, "{arch}: RM/RP/RZ plus FTZ");
        assert_eq!(counts["other_family"], 4, "{arch}: distinct adjacent opcodes");
        assert_eq!(counts["control_plane"], 29, "{arch}: control separation");
    }
}

#[test]
fn only_the_measured_plain_group_and_its_provenance_changed() {
    for (arch, _) in *ARCHES {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        assert!(raw["_meta"]["provenance"]["sources"][SOURCE]["note"]
            .as_str().unwrap().contains("not silicon"));
        let entry = &raw["instructions"][KEY];
        assert!(entry.get("_src").is_none(), "{arch}: sibling groups inherit no new provenance");
        // the batch (T-26, 2026-11-10): F2F_R_R carries ten groups once the four F2F candidates meet -- the base's five,
        // `F16,F32,RZ` of the rounding ref and the four FTZ rows; each candidate pinned the count of its own base
        assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 10);
        let group = &entry["mod_groups"][MOD_GROUP];
        assert_eq!(group["_src"], SOURCE);
        assert_eq!(hex(&group["and_base"]) >> 96, 0);
        let expected = [
            (4, 12, "guard", 0), (8, 16, "reg", 1), (8, 32, "reg", 2),
            (1, 63, "neg", 2), (1, 62, "abs", 2),
        ];
        for (bits, shift, extraction, token) in expected {
            assert!(group["fields"].as_array().unwrap().iter().any(|field|
                field["bits"] == bits && field["shift"] == shift
                    && field["extraction"] == extraction && field["token_idx"] == token
                    && field.get("_src").is_none()),
                "{arch}: missing measured {extraction} field at {shift}");
        }
        let mask = group["fields"].as_array().unwrap().iter().fold(0, |mask, field| {
            mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1)
                << field["shift"].as_u64().unwrap())
        });
        assert_eq!(hex(&group["variable_mask"]), mask);
        assert_eq!(hex(&group["and_base"]) & mask, 0);
    }
}
