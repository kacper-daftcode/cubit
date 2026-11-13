//! Production FFMA2 R,R,UR,R final-source negation; text evidence, no GPU claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-ffma2-rur-negd-production-2026-11-11";
const KEY: &str = "FFMA2_R_R_UR_R";
const LOWER96: u128 = (1u128 << 96) - 1;

fn arches() -> [(&'static str, &'static str); 2] {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_ffma2_rur_negd_production_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_ffma2_rur_negd_production_nvdisasm.jsonl"),
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

fn lossless_text(word: u128, vendor: &str) -> String {
    if (word >> 124) & 1 == 0 || vendor.contains(".reuse") {
        return vendor.to_string();
    }
    let position = vendor.rfind(".F32").unwrap();
    format!("{}.reuse{}", &vendor[..position], &vendor[position..])
}

#[test]
fn production_and_independent_ab_decode_render_reencode() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let (mut production, mut adopt) = (0, 0);
        for row in rows(fixture) {
            if row["role"] != "adopt" {
                continue;
            }
            adopt += 1;
            production += usize::from(row["generation"] == "production");
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, KEY, "{arch} {word:032x}");
            assert_eq!(decoded.mod_group, "", "{arch} {word:032x}");
            assert_eq!(
                cubit::printer::to_sass(&decoded),
                text,
                "{arch} {word:032x}"
            );
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                lossless_text(word, text),
                "{arch} {word:032x}"
            );
            let rendered = cubit::printer::to_sass_lossless(&decoded);
            let control = cubit::scheduling::format_control_code(
                &cubit::scheduling::decode_sched_upper32((word >> 96) as u32),
            );
            let parsed = cubit::parse_cuasm_line(&format!("[{control}] {rendered} ;"), 0).unwrap();
            let encoded = cubit::encoder::encode_instruction(&parsed, table)
                .unwrap_or_else(|error| panic!("{arch}: encode {word:032x} {rendered}: {error}"));
            // The textual control representation is not asserted to retain
            // unrelated upper sideband. Every operand byte, neg@75 and the
            // existing Rc.reuse@124 must be retained without __raw__.
            assert_eq!(
                encoded & LOWER96,
                word & LOWER96,
                "{arch}: operand bits changed for {word:032x} {rendered}"
            );
            assert_eq!(
                encoded & (1u128 << 124),
                word & (1u128 << 124),
                "{arch}: Rc.reuse changed for {word:032x} {rendered}"
            );
        }
        assert_eq!((production, adopt), (64, 1108), "{arch}");
    }
}

#[test]
fn only_neg75_is_added_to_the_existing_row_with_measured_provenance() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        let source = &raw["_meta"]["provenance"]["sources"][SOURCE];
        assert_eq!(source["rows"], 0);
        assert_eq!(source.as_object().unwrap().len(), 6);
        assert!(source["note"].as_str().unwrap().contains("neg [75]"));
        assert!(source["note"].as_str().unwrap().contains("_srcc68"));
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["base_op"], "FFMA2");
        assert_eq!(entry["operand_sig"], "R_R_UR_R");
        assert_eq!(entry["scheduling"]["pipe_name"], "UNKNOWN");
        let group = &entry["mod_groups"][""];
        assert!(group.get("_src").is_none(), "{arch}");
        assert!(entry.get("_src").is_none(), "{arch}");
        assert_eq!(group["count"], 256);
        assert_eq!(
            hex(&group["and_base"]),
            0x00000000092000000000000000007c49u128
        );
        let fields = group["fields"].as_array().unwrap();
        assert_eq!(
            hex(&group["variable_mask"]),
            0x10e02e00000008a300000015fefe0000u128,
            "{arch}"
        );
        assert_eq!(fields.len(), 6);
        for (bits, shift, extraction, token) in [
            (8, 16, "reg", 1),
            (8, 24, "reg", 2),
            (8, 32, "ureg", 3),
            (8, 64, "reg", 4),
            (1, 75, "neg", 4),
            (1, 124, "reuse", 4),
        ] {
            let field = fields
                .iter()
                .find(|field| {
                    field["bits"] == bits
                        && field["shift"] == shift
                        && field["extraction"] == extraction
                        && field["token_idx"] == token
                })
                .unwrap_or_else(|| panic!("{arch}: {extraction}@{shift}/{bits}"));
            assert_eq!(
                field["_src"],
                if extraction == "neg" {
                    Value::from(SOURCE)
                } else {
                    Value::from("2aE")
                },
                "{arch}: {extraction}@{shift} source"
            );
        }
        assert!(
            !fields.iter().any(|field| field["shift"] == 74),
            "abs74 is a separate boundary"
        );
        assert_eq!(
            group["claim_forbid"],
            serde_json::json!([{"bits": 1, "shift": 74, "values": [1]}]),
            "{arch}"
        );
        assert_eq!(group["_srcc68"], SOURCE, "{arch}");
        assert!(group["_notec68"]
            .as_str()
            .unwrap()
            .contains("4 records per target"));
    }
}

#[test]
fn negative_adjacent_and_control_records_are_not_silently_adopted() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let mut counts = std::collections::BTreeMap::new();
        let mut read: Vec<(String, String, bool)> = Vec::new();
        for row in rows(fixture) {
            let role = row["role"].as_str().unwrap().to_string();
            *counts.entry(role.clone()).or_insert(0usize) += 1;
            let word = hex(&row["word"]);
            match role.as_str() {
                "adopt" => continue,
                "control" => continue,
                "negative" => assert!(
                    index.decode(word, 0, table).is_err(),
                    "{arch}: static negative must stay rejected {word:032x}"
                ),
                "text_inert" | "vendor_invalid" | "adjacent_modifier" | "other_family" => {
                    // The existing row retains its standard modifier slots.
                    // Every neighbour it reads must re-assemble losslessly;
                    // the exact set and vendor-text relation is pinned below.
                    if let Ok(decoded) = index.decode(word, 0, table) {
                        let rendered = cubit::printer::to_sass_lossless(&decoded);
                        let control = cubit::scheduling::format_control_code(
                            &cubit::scheduling::decode_sched_upper32((word >> 96) as u32),
                        );
                        let parsed =
                            cubit::parse_cuasm_line(&format!("[{control}] {rendered} ;"), 0)
                                .unwrap();
                        let encoded = cubit::encoder::encode_instruction(&parsed, table)
                            .unwrap_or_else(|error| {
                                panic!("{arch}: encode {word:032x} {rendered}: {error}")
                            });
                        assert_eq!(
                            (encoded & LOWER96, encoded & (1u128 << 124)),
                            (word & LOWER96, word & (1u128 << 124)),
                            "{arch}: {role} read with loss {word:032x} {rendered}"
                        );
                        let vendor = format!("{} ;", row["nvidia_sass"].as_str().unwrap());
                        read.push((role, format!("{word:032x}"), decoded.to_string() == vendor));
                    }
                }
                other => panic!("unexpected role {other}"),
            }
        }
        let read: Vec<(&str, &str, bool)> = read
            .iter()
            .map(|(role, word, exact)| (role.as_str(), word.as_str(), *exact))
            .collect();
        assert_eq!(
            read,
            [
                (
                    "adjacent_modifier",
                    "000fc400092008474000000c04047c49",
                    false
                ),
                (
                    "adjacent_modifier",
                    "000fc400092008478000000c04047c49",
                    true
                ),
                (
                    "adjacent_modifier",
                    "000fc400092009470000000c04047c49",
                    true
                ),
                (
                    "adjacent_modifier",
                    "000fc40009200a470000000c04047c49",
                    true
                ),
            ],
            "{arch}"
        );
        assert_eq!(counts["negative"], 10, "{arch}");
        assert_eq!(counts["adopt"], 1108, "{arch}");
        assert_eq!(counts.values().sum::<usize>(), 1201, "{arch}");
    }
}
