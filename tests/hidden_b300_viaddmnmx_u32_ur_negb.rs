//! Measured VIADDMNMX.U32 Rb negation; no execution or arithmetic claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-viaddmnmx-u32-ur-negb-production-2026-11-11";
const KEY: &str = "VIADDMNMX_R_R_R_UR_P";

fn arches() -> [(&'static str, &'static str); 2] {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_viaddmnmx_u32_ur_negb_production_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_viaddmnmx_u32_ur_negb_production_nvdisasm.jsonl"),
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
    assert_eq!(decoded.mod_group, "U32");
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
        let (mut production, mut adopt, mut crosses) = (0, 0, 0);
        for row in rows(fixture) {
            if row["role"] == "adopt" {
                adopt += 1;
                production += usize::from(row["generation"] == "production");
                crosses += usize::from(row["generation"] == "operand_cross");
                roundtrip(table, index, arch, &row);
            }
        }
        assert_eq!(production, 3, "{arch}: complete production words");
        assert!(
            adopt > 1000,
            "{arch}: incomplete adopted measured set: {adopt}"
        );
        assert_eq!(crosses, 96, "{arch}: deterministic operand crosses");
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
        let group = &raw["instructions"][KEY]["mod_groups"]["U32"];
        assert_eq!(group["_src"], SOURCE, "{arch}");
        assert!(raw["_meta"]["provenance"]["sources"][SOURCE]["note"]
            .as_str()
            .unwrap()
            .contains("Five source observations"));
        assert_eq!(
            hex(&group["and_base"]),
            0x00000000080000000000000000000e46u128
        );
        assert_eq!(
            hex(&group["variable_mask"]),
            0x08000000078008ff000000fffffff000u128
        );
        for (shift, bits, extraction, token) in [
            (12, 4, "guard", 0),
            (16, 8, "reg", 1),
            (24, 8, "reg", 2),
            (64, 8, "reg", 3),
            (75, 1, "neg", 3),
            (32, 8, "ureg", 4),
            (123, 1, "reuse", 3),
            (90, 1, "neg", 5),
            (87, 3, "pred", 5),
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
        assert_eq!(group["fields"].as_array().unwrap().len(), 9);
        assert_eq!(group["claim_forbid"], serde_json::json!([
            {"bits": 1, "shift": 62, "values": [1]},
            {"bits": 1, "shift": 63, "values": [1]},
            {"bits": 1, "shift": 124, "values": [1]}
        ]));
    }
}

#[test]
fn guard_and_reuse_controls_roundtrip_and_inert_neighbours_fail_closed() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let (mut guards, mut valid_reuse, mut refused) = (0, 0, 0);
        for row in rows(fixture) {
            let word = hex(&row["word"]);
            match (row["generation"].as_str().unwrap(), (word >> 122) & 7) {
                ("guard", _) if row["role"] == "control" => {
                    roundtrip(table, index, arch, &row);
                    guards += 1;
                }
                ("reuse", 1..=3) => {
                    roundtrip(table, index, arch, &row);
                    valid_reuse += 1;
                }
                ("reuse", _) => {
                    assert!(index.decode(word, 0, table).is_err(), "{arch}: {word:032x}");
                    refused += 1;
                }
                _ => {}
            }
            if row["role"] == "unclaimed_text_inert" && word & (3u128 << 62) != 0 {
                assert!(index.decode(word, 0, table).is_err(), "{arch}: {word:032x}");
            }
        }
        assert_eq!((guards, valid_reuse, refused), (15, 3, 4), "{arch}");
    }
}

#[test]
fn negative_adjacent_and_control_roles_are_retained() {
    for (arch, fixture) in arches() {
        let (mut negative, mut adjacent, mut inert, mut control) = (0, 0, 0, 0);
        let (mut guards, mut reuses) = (0, 0);
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
            if row["generation"] == "guard" {
                guards += 1;
                assert_eq!(
                    row["role"], "control",
                    "{arch}: guard is out of scoped adoption"
                );
            }
            if row["generation"] == "reuse" {
                reuses += 1;
                assert_eq!(
                    row["role"], "control",
                    "{arch}: reuse is out of scoped adoption"
                );
            }
        }
        assert_eq!(
            (guards, reuses),
            (15, 7),
            "{arch}: base duplicates are not double-counted"
        );
        assert!(
            negative + adjacent + inert + control > 40,
            "{arch}: negative/adjacent/control evidence was dropped"
        );
    }
}
