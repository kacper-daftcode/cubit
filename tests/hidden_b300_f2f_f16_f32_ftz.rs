//! Measured F2F.FTZ.F16.F32 default/RM/RP/RZ rows; CPU vendor text only.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::OnceLock;

const SOURCE: &str = "rows-f2f-f16-f32-ftz-2026-11-09";
const KEY: &str = "F2F_R_R";
const GROUPS: [&str; 4] = [
    "F16,F32,FTZ",
    "F16,F32,FTZ,RM",
    "F16,F32,FTZ,RP",
    "F16,F32,FTZ,RZ",
];
const EXPECTED: &str = include_str!("fixtures/f2f_f16_f32_ftz_measurement.json");
static ARCHES: std::sync::LazyLock<[(&str, &str, &str); 2]> = std::sync::LazyLock::new(|| [
    (
        "sm103a",
        "SM103",
        hb300_fixture("sm103a_f2f_f16_f32_ftz_nvdisasm.jsonl"),
    ),
    (
        "sm100a",
        "SM100",
        hb300_fixture("sm100a_f2f_f16_f32_ftz_nvdisasm.jsonl"),
    ),
]);

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLES: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLES.get_or_init(|| {
        ARCHES
            .iter()
            .map(|(arch, _, _)| {
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

fn number(value: &Value) -> usize {
    value.as_u64().unwrap() as usize
}

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

#[test]
fn every_licensed_ftz_word_decodes_renders_and_reencodes() {
    let expected: Value = serde_json::from_str(EXPECTED).unwrap();
    for (arch_index, (arch, target, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[arch_index];
        let (mut total, mut fields, mut bases) = (0usize, 0usize, 0usize);
        let (mut signs, mut sign_guards, mut sign_registers) = (0usize, 0usize, 0usize);
        let mut per_group = BTreeMap::new();
        for row in rows(fixture) {
            if row["kind"] != "positive" {
                continue;
            }
            total += 1;
            match row["generation"].as_str().unwrap() {
                "field" => fields += 1,
                "base" => bases += 1,
                "sign" => signs += 1,
                "sign_guard" => sign_guards += 1,
                "sign_registers" => sign_registers += 1,
                "single_lower_bit" => {}
                "reuse_control" => panic!("{arch}: a refused reuse mask became positive"),
                other => panic!("{arch}: unexpected positive generation {other}"),
            }
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let group = row["scope_group"].as_str().unwrap();
            assert!(GROUPS.contains(&group), "{arch}: unexpected group {group}");
            *per_group.entry(group.to_string()).or_insert(0usize) += 1;
            let decoded = index
                .decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, KEY, "{arch} {word:032x}");
            assert_eq!(decoded.mod_group, group, "{arch} {word:032x}");
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                text,
                "{arch} {word:032x}"
            );
            assert_eq!(
                cubit::printer::to_sass(&decoded),
                text,
                "{arch} {word:032x}"
            );
            assert_eq!(
                encode(table, word, text),
                word & !(7u128 << 125),
                "{arch} {word:032x} {text}"
            );
        }
        let counts = &expected["counts_per_target"][target];
        assert_eq!(
            total,
            number(&counts["positive"]),
            "{arch}: complete positive census"
        );
        assert_eq!(
            (fields, bases, signs, sign_guards, sign_registers),
            (2100, 4, 12, 180, 256),
            "{arch}: independent field/sign domains"
        );
        for name in ["DEFAULT", "RM", "RP", "RZ"] {
            let suffix = if name == "DEFAULT" {
                "".to_string()
            } else {
                format!(",{name}")
            };
            let group = format!("F16,F32,FTZ{suffix}");
            assert_eq!(
                per_group[&group],
                number(&expected["per_round"][name]["counts"]["positive"]),
                "{arch}: positive census for {group}"
            );
        }
    }
}

#[test]
fn scoped_negatives_and_neighbours_do_not_enter_their_measured_group() {
    let expected: Value = serde_json::from_str(EXPECTED).unwrap();
    for (arch_index, (arch, target, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[arch_index];
        let mut counts = BTreeMap::new();
        for row in rows(fixture) {
            let kind = row["kind"].as_str().unwrap().to_string();
            *counts.entry(kind.clone()).or_insert(0usize) += 1;
            if kind == "positive" || kind == "control_plane" {
                continue;
            }
            assert!(
                matches!(
                    kind.as_str(),
                    "negative" | "adjacent_modifier" | "other_family"
                ),
                "{arch}: unexpected unlicensed class {kind}"
            );
            let word = hex(&row["word"]);
            let scope = row["scope_group"].as_str().unwrap();
            if let Ok(decoded) = index.decode(word, 0, table) {
                assert!(
                    !(decoded.key == KEY && decoded.mod_group == scope),
                    "{arch}: {kind} {word:032x} entered {scope} as {}[{}]",
                    decoded.key,
                    decoded.mod_group
                );
            }
        }
        for kind in [
            "positive",
            "negative",
            "adjacent_modifier",
            "other_family",
            "control_plane",
        ] {
            assert_eq!(
                counts[kind],
                number(&expected["counts_per_target"][target][kind]),
                "{arch}: frozen {kind} census"
            );
        }
        assert!(number(&expected["accepted_unnamed"]) == 0);
    }
}

#[test]
fn exactly_four_measured_rows_carry_provenance_and_fail_closed_fields() {
    for (arch, _, _) in *ARCHES {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 4);
        assert!(raw["_meta"]["provenance"]["sources"][SOURCE]["note"]
            .as_str()
            .unwrap()
            .contains("not silicon"));
        let entry = &raw["instructions"][KEY];
        assert!(
            entry.get("_src").is_none(),
            "{arch}: siblings inherit no new provenance"
        );
        // the batch (T-26, 2026-11-10): F2F_R_R carries ten groups once the four F2F candidates meet -- the base's five,
        // `F16,F32,RZ` of the rounding ref and the four FTZ rows; each candidate pinned the count of its own base
        assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 10);
        for plain in ["BF16,F32", "F16,F32", "F32,F64"] {
            assert_ne!(
                entry["mod_groups"][plain]["_src"], SOURCE,
                "{arch}: sibling {plain} was re-tagged"
            );
        }
        for (index, name) in GROUPS.iter().enumerate() {
            let group = &entry["mod_groups"][name];
            assert_eq!(group["_src"], SOURCE, "{arch}: {name}");
            assert_eq!(group["count"], Value::Null);
            assert_eq!(hex(&group["and_base"]) >> 96, 0);
            assert_eq!((hex(&group["and_base"]) >> 80) & 1, 1);
            assert_eq!((hex(&group["and_base"]) >> 78) & 3, index as u128);
            let expected = [
                (4, 12, "guard", 0),
                (8, 16, "reg", 1),
                (8, 32, "reg", 2),
                (1, 63, "neg", 2),
                (1, 62, "abs", 2),
            ];
            let fields = group["fields"].as_array().unwrap();
            assert_eq!(fields.len(), expected.len(), "{arch}: {name} field count");
            for (field, (bits, shift, extraction, token)) in fields.iter().zip(expected) {
                assert_eq!(field["bits"], bits);
                assert_eq!(field["shift"], shift);
                assert_eq!(field["extraction"], extraction);
                assert_eq!(field["token_idx"], token);
                assert!(field.get("_src").is_none());
            }
            let mask = fields.iter().fold(0u128, |mask, field| {
                mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1)
                    << field["shift"].as_u64().unwrap())
            });
            assert_eq!(hex(&group["variable_mask"]), mask);
            assert_eq!(hex(&group["and_base"]) & mask, 0);
            let claims = group["claim_forbid"].as_array().unwrap();
            assert!(claims.len() >= 3);
            for bit in [122u64, 123, 124] {
                assert!(
                    claims.iter().any(|claim| claim["shift"] == bit
                        && claim["bits"] == 1
                        && claim["values"][0] == 1),
                    "{arch}: {name} reuse bit {bit} is not forbidden"
                );
            }
        }
    }
}
