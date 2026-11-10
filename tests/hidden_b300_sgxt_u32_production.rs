//! Production SGXT.U32 R,R,UR: measured text, not execution semantics.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-sgxt-u32-production-2026-11-09";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    (
        "sm103a",
        hb300_fixture("sm103a_sgxt_u32_production_nvdisasm.jsonl"),
    ),
    (
        "sm100a",
        hb300_fixture("sm100a_sgxt_u32_production_nvdisasm.jsonl"),
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

fn word(row: &Value) -> u128 {
    u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap()
}

fn encode(table: &IsaTable, raw_word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (raw_word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

#[test]
fn every_licensed_word_decodes_renders_and_reencodes() {
    for (number, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[number];
        let (mut positives, mut production, mut fields) = (0, 0, 0);
        let model: Value = serde_json::from_str(include_str!("fixtures/sgxt_u32_table_model.json")).unwrap();
        for row in rows(fixture) {
            if row["kind"] != "positive" {
                continue;
            }
            positives += 1;
            production += usize::from(row["generation"] == "production");
            fields += usize::from(row["generation"] == "field");
            let raw_word = word(&row);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(raw_word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {raw_word:032x}: {error}"));
            assert_eq!(decoded.key, "SGXT.U32_R_R_UR", "{arch} {raw_word:032x}");
            assert_eq!(decoded.mod_group, "", "{arch} {raw_word:032x}");
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                text,
                "{arch} {raw_word:032x}"
            );
            assert_eq!(
                cubit::printer::to_sass(&decoded),
                text,
                "{arch} {raw_word:032x}"
            );
            assert_eq!(encode(table, raw_word, text), raw_word & !(7u128 << 125));
        }
        assert_eq!(production, 2, "{arch}: two distinct production witnesses");
        assert_eq!(positives, model["counts"]["positive"]);
        assert_eq!(fields, model["counts"]["field"]);
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"]["SGXT.U32_R_R_UR"];
        assert_eq!(entry["_src"], SOURCE);
        assert_eq!(entry["operand_sig"], "R_R_UR");
        assert_eq!(entry["scheduling"]["latency_source"], "synthetic");
        assert_eq!(entry["mod_groups"][""]["_src"], SOURCE);
        assert_eq!(entry["mod_groups"][""]["and_base"], model["and_base"]);
        assert_eq!(
            entry["mod_groups"][""]["variable_mask"],
            model["variable_mask"]
        );
        assert_eq!(entry["mod_groups"][""]["fields"], model["fields"]);
        assert_eq!(
            entry["mod_groups"][""]["claim_forbid"],
            model["claim_forbid"]
        );
    }
}

#[test]
fn unlicensed_words_fail_closed_and_neighbours_are_not_merged() {
    for (number, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[number];
        let model: Value = serde_json::from_str(include_str!("fixtures/sgxt_u32_table_model.json")).unwrap();
        let (mut negative, mut adjacent, mut other, mut control) = (0, 0, 0, 0);
        for row in rows(fixture) {
            match row["kind"].as_str().unwrap() {
                "positive" => continue,
                "control_plane" => {
                    control += 1;
                    continue;
                }
                "negative" => negative += 1,
                "adjacent_modifier" => adjacent += 1,
                "other_family" => other += 1,
                kind => panic!("unexpected row kind {kind}"),
            }
            let raw_word = word(&row);
            let verdict = index.decode(raw_word, 0, table);
            if let Ok(decoded) = &verdict {
                assert_ne!(
                    decoded.key, "SGXT.U32_R_R_UR",
                    "{arch}: overmatch {raw_word:032x}"
                );
            }
            if row["kind"] == "negative" {
                assert!(
                    verdict.is_err(),
                    "{arch}: invalid/inert bit accepted {raw_word:032x}"
                );
            }
        }
        assert_eq!(negative, model["counts"]["negative"]);
        assert_eq!(adjacent, model["counts"]["adjacent_modifier"]);
        assert_eq!(other, model["counts"]["other_family"]);
        assert_eq!(control, model["counts"]["control_plane"]);
        for bad in [
            "SGXT R2, R2, UR6",
            "SGXT.U32 R2, UR6, R2",
            "SGXT.U32 R2, R2, -UR6",
        ] {
            let parsed = cubit::parse_sass(&format!("{bad} ;"), 0).unwrap();
            assert!(
                cubit::encoder::encode_instruction(&parsed, table).is_err(),
                "{arch}: {bad}"
            );
        }
        let neighbour = cubit::parse_sass("SGXT.U32 R2, R2, 0x6 ;", 0).unwrap();
        let encoded = cubit::encoder::encode_instruction(&neighbour, table).unwrap();
        assert_eq!(
            index.decode(encoded, 0, table).unwrap().key,
            "SGXT_R_R_II",
            "{arch}: pre-existing immediate neighbour changed ownership"
        );
    }
}
