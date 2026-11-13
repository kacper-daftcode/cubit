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
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["base_op"], "FFMA2");
        assert_eq!(entry["operand_sig"], "R_R_UR_R");
        assert_eq!(entry["scheduling"]["pipe_name"], "UNKNOWN");
        let group = &entry["mod_groups"][""];
        assert_eq!(group["_src"], SOURCE, "{arch}");
        assert_eq!(group["count"], Value::Null);
        assert_eq!(
            hex(&group["and_base"]),
            0x00000000092000000000000000007c49u128
        );
        let fields = group["fields"].as_array().unwrap();
        let expected_mask = fields.iter().fold(0u128, |mask, field| {
            mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1)
                << field["shift"].as_u64().unwrap())
        });
        assert_eq!(hex(&group["variable_mask"]), expected_mask, "{arch}");
        assert_eq!(fields.len(), 6);
        for (bits, shift, extraction, token) in [
            (8, 16, "reg", 1),
            (8, 24, "reg", 2),
            (8, 32, "ureg", 3),
            (8, 64, "reg", 4),
            (1, 75, "neg", 4),
            (1, 124, "reuse", 4),
        ] {
            assert!(
                fields.iter().any(|field| field["bits"] == bits
                    && field["shift"] == shift
                    && field["extraction"] == extraction
                    && field["token_idx"] == token),
                "{arch}: {extraction}@{shift}/{bits}"
            );
        }
        assert!(
            !fields.iter().any(|field| field["shift"] == 74),
            "abs74 is a separate boundary"
        );
    }
}

#[test]
fn negative_adjacent_and_control_records_are_not_silently_adopted() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let mut counts = std::collections::BTreeMap::new();
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
                    // Some neighbours may decode elsewhere. They must not
                    // masquerade as the vendor's measured operand signature.
                    if let Ok(decoded) = index.decode(word, 0, table) {
                        assert_ne!(
                            decoded.to_string(),
                            format!("{} ;", row["nvidia_sass"].as_str().unwrap()),
                            "{arch}: {role} rendered as the scoped signature {word:032x}"
                        );
                    }
                }
                other => panic!("unexpected role {other}"),
            }
        }
        assert_eq!(counts["negative"], 10, "{arch}");
        assert_eq!(counts["adopt"], 1108, "{arch}");
        assert_eq!(counts.values().sum::<usize>(), 1201, "{arch}");
    }
}
