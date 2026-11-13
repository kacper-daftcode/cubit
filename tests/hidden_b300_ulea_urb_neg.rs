//! Measured production ULEA URb negation; no execution or arithmetic claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-ulea-urb-neg-production-2026-11-11";
const KEY: &str = "ULEA_UR_UP_UR_UR_II";

fn arches() -> [(&'static str, &'static str); 2] {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_ulea_urb_neg_production_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_ulea_urb_neg_production_nvdisasm.jsonl"),
        ),
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
    assert_eq!(decoded.key, KEY);
    assert_eq!(decoded.mod_group, "");
    assert_eq!(
        cubit::printer::to_sass(&decoded),
        text,
        "{arch} {word:032x}"
    );
    let lossless = cubit::printer::to_sass_lossless(&decoded);
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {lossless} ;"), 0).unwrap();
    let encoded = cubit::encoder::encode_instruction(&parsed, table)
        .unwrap_or_else(|error| panic!("{arch}: encode {word:032x} {text}: {error}"));
    assert_eq!(
        encoded,
        word & !(7u128 << 125),
        "{arch}: {word:032x} {text}"
    );
}

#[test]
fn production_and_all_measured_fields_decode_render_reencode() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let (mut production, mut adopt, mut signs) = (0, 0, 0);
        for row in rows(fixture) {
            if row["role"] == "adopt" {
                adopt += 1;
                production += usize::from(row["generation"] == "production");
                signs += usize::from(
                    row["label"]
                        .as_str()
                        .unwrap()
                        .starts_with("source-neg-pred-cross:"),
                );
                roundtrip(table, index, arch, &row);
            }
        }
        assert_eq!(production, 1, "{arch}: complete production word");
        assert!(
            adopt > 700,
            "{arch}: incomplete adopted measured set: {adopt}"
        );
        assert!(
            signs >= 21,
            "{arch}: missing independent source-sign crosses: {signs}"
        );
    }
}

#[test]
fn exact_row_fields_and_provenance_preserve_parent_geometry() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let group = &raw["instructions"][KEY]["mod_groups"][""];
        assert_eq!(group["_src"], SOURCE, "{arch}");
        assert!(raw["_meta"]["provenance"]["sources"][SOURCE]["note"]
            .as_str()
            .unwrap()
            .contains("two duplicate source observations"));
        assert_eq!(
            hex(&group["and_base"]),
            0x000000000f8000ff0000000000000291u128
        );
        assert_eq!(
            hex(&group["variable_mask"]),
            0x00000000007ef900800000fffffff000u128
        );
        for (shift, bits, extraction, token) in [
            (12, 4, "guard", 0),
            (16, 8, "ureg_ff", 1),
            (81, 6, "pred", 2),
            (24, 8, "ureg", 3),
            (72, 1, "neg", 3),
            (32, 8, "ureg_ff", 4),
            (63, 1, "neg", 4),
            (75, 5, "imm", 5),
        ] {
            assert!(
                group["fields"].as_array().unwrap().iter().any(|field| {
                    field["shift"] == shift
                        && field["bits"] == bits
                        && field["extraction"] == extraction
                        && field["token_idx"] == token
                }),
                "{arch}: {extraction}@{shift}/{bits}"
            );
        }
        assert_eq!(group["fields"].as_array().unwrap().len(), 8);
        assert!(
            group.get("claim_forbid").is_none(),
            "{arch}: scope added no claim_forbid"
        );
    }
}

#[test]
fn negative_adjacent_and_control_roles_are_retained() {
    for (_arch, fixture) in arches() {
        let (mut negative, mut adjacent, mut inert, mut control, mut up7) = (0, 0, 0, 0, 0);
        for row in rows(fixture) {
            match row["role"].as_str().unwrap() {
                "adopt" => {}
                "negative" => negative += 1,
                "adjacent_modifier" => adjacent += 1,
                "unclaimed_text_inert" | "text_inert" => inert += 1,
                "control" => control += 1,
                "other_family" => control += 1,
                other => panic!("unexpected role {other}: {row}"),
            }
            if row["generation"] == "uniform_predicate" && row["label"] == "uniform_predicate:7" {
                up7 += 1;
                assert_eq!(row["role"], "adjacent_modifier");
            }
        }
        assert_eq!(up7, 1);
        assert!(
            negative + adjacent + inert + control > 20,
            "negative/adjacent/control evidence was dropped"
        );
    }
}
