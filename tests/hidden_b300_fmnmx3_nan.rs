//! Production FMNMX3.NAN vendor-text encodings; no numerical NaN claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-fmnmx3-nan-production-2026-11-08";
const POSITIVE: usize = 1209;
const NEGATIVE: usize = 55;
const ADJACENT: usize = 12;
const CONTROL: usize = 29;
const AND_BASE: &str = "0x00000000000200000000000000000276";
const VARIABLE_MASK: &str = "0x00000007800fffc00000fffffff000";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    (
        "sm103a",
        hb300_fixture("sm103a_fmnmx3_nan_nvdisasm.jsonl"),
    ),
    (
        "sm100a",
        hb300_fixture("sm100a_fmnmx3_nan_nvdisasm.jsonl"),
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

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

#[test]
fn production_and_measured_nan_fields_roundtrip_exactly() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let (mut production, mut register, mut guard, mut predicate, mut signs) =
            (0usize, 0usize, 0usize, 0usize, 0usize);
        let mut positive = 0usize;
        for row in rows(fixture) {
            if row["kind"] != "positive" {
                continue;
            }
            positive += 1;
            let generation = row["generation"].as_str().unwrap();
            let label = row["label"].as_str().unwrap();
            match generation {
                "production" => production += 1,
                "field" if label.starts_with("register:") => register += 1,
                "field" if label.starts_with("guard:") => guard += 1,
                "field" if label.starts_with("predicate:") => predicate += 1,
                "field" if label.starts_with("sign:") => signs += 1,
                "base" | "field" | "single_lower_bit" | "reuse_control" | "modifier" => {}
                other => panic!("unexpected positive generation {other}"),
            }
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, "FMNMX3_R_R_R_R_P");
            assert_eq!(decoded.mod_group, "NAN", "{arch} {word:032x}");
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                text,
                "{arch} {word:032x}"
            );
            assert_eq!(cubit::printer::to_sass(&decoded), text);
            assert_eq!(encode(table, word, text), word & !(7u128 << 125));
        }
        assert_eq!(production, 152, "{arch}: every stored production witness");
        assert_eq!(
            (register, guard, predicate),
            (1020, 15, 15),
            "{arch}: full field sweeps"
        );
        assert_eq!(signs, 6, "{arch}: independent sign placement");
        assert_eq!(positive, POSITIVE, "{arch}: exact complete positive census");

        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"]["FMNMX3_R_R_R_R_P"];
        assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 3);
        let group = &entry["mod_groups"]["NAN"];
        assert_eq!(group["_src"], SOURCE);
        assert_eq!(
            hex(&group["and_base"]),
            hex(&Value::String(AND_BASE.to_owned()))
        );
        assert_eq!(
            hex(&group["variable_mask"]),
            hex(&Value::String(VARIABLE_MASK.to_owned()))
        );
        assert_eq!(hex(&group["and_base"]) >> 96, 0);
        assert!(entry["mod_groups"][""]["_src508"].is_string());
        assert!(entry["mod_groups"]["FTZ"]["_src508"].is_string());
        let forbidden = group["claim_forbid"].as_array().unwrap();
        assert_eq!(forbidden.len(), 3);
        for (rule, bit) in forbidden.iter().zip([122u64, 123, 124]) {
            assert_eq!(
                rule,
                &serde_json::json!({"shift": bit, "bits": 1, "values": [1]})
            );
        }
    }
}

#[test]
fn adjacent_or_unlicensed_words_do_not_enter_nan() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let (mut negative, mut adjacent, mut control) = (0usize, 0usize, 0usize);
        for row in rows(fixture) {
            let kind = row["kind"].as_str().unwrap();
            if matches!(kind, "positive" | "control_plane") {
                control += usize::from(kind == "control_plane");
                continue;
            }
            let word = hex(&row["word"]);
            if let Ok(decoded) = index.decode(word, 0, table) {
                assert!(
                    decoded.key != "FMNMX3_R_R_R_R_P" || decoded.mod_group != "NAN",
                    "{arch}: overmatch {kind} {word:032x}"
                );
            }
            match kind {
                "negative" => {
                    negative += 1;
                    assert!(
                        index.decode(word, 0, table).is_err(),
                        "{arch}: invalid/text-inert word accepted {word:032x}"
                    );
                }
                "adjacent_modifier" => adjacent += 1,
                "other_family" => {}
                other => panic!("unclassified negative {other}"),
            }
        }
        assert_eq!((negative, adjacent, control), (NEGATIVE, ADJACENT, CONTROL));
    }
}
