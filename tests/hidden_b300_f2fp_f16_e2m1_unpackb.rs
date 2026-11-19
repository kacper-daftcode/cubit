//! Production F2FP.F16.E2M1.UNPACK_B source byte selectors, without GPU execution.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-f2fp-f16-e2m1-unpackb-production-2026-11-10";
const GROUP: &str = "E2M1,F16,UNPACK_B";
fn arches() -> [(&'static str, &'static str); 2] {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_f2fp_f16_e2m1_unpackb_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_f2fp_f16_e2m1_unpackb_nvdisasm.jsonl"),
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
    assert_eq!(decoded.key, "F2FP_R_R");
    assert_eq!(decoded.mod_group, GROUP);
    assert_eq!(
        cubit::printer::to_sass_lossless(&decoded),
        text,
        "{arch} {word:032x}"
    );
    assert_eq!(cubit::printer::to_sass(&decoded), text);
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    let encoded = cubit::encoder::encode_instruction(&parsed, table);
    assert_eq!(
        encoded.unwrap_or_else(|error| panic!("{arch}: encode {word:032x} {text}: {error}")),
        word & !(7u128 << 125),
        "{arch}: encode {word:032x} {text}"
    );
}

#[test]
fn production_and_byte_selector_matrix_roundtrips() {
    for (index, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[index];
        let (mut production, mut positive) = (0, 0);
        for row in rows(fixture) {
            if row["kind"] != "positive" {
                continue;
            }
            positive += 1;
            production += usize::from(row["generation"] == "production");
            roundtrip(table, index, arch, &row);
        }
        assert_eq!(
            (production, positive),
            (264, 2524),
            "{arch}: positive census"
        );
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"]["F2FP_R_R"];
        assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 8);
        let group = &entry["mod_groups"][GROUP];
        assert_eq!(group["_src"], SOURCE);
        assert_eq!(group["and_base"], "0x00000000020402ff00000000ff00023e");
        let expected_mask =
            (0xfu128 << 12) | (0xffu128 << 16) | (0xffu128 << 32) | (1u128 << 72) | (1u128 << 88);
        assert_eq!(hex(&group["variable_mask"]), expected_mask);
        assert_eq!(
            group["fields"],
            serde_json::json!([
                {"bits":4, "shift":12, "token_idx":0, "extraction":"guard"},
                {"bits":8, "shift":16, "token_idx":1, "extraction":"reg"},
                {"bits":8, "shift":32, "token_idx":2, "extraction":"reg"},
                {"bits":1, "shift":72, "token_idx":2, "extraction":"f2fp_ra_b1"},
                {"bits":1, "shift":88, "token_idx":2, "extraction":"f2fp_ra_b2"}
            ])
        );
        assert_eq!(group["variable_mask"], format!("{expected_mask:#034x}"));
        assert!(group.get("claim_forbid").is_none());
        assert!(group["count"].is_null());
    }
}

#[test]
fn repeated_and_unknown_byte_selector_suffixes_are_refused() {
    for (index, (arch, _)) in arches().iter().enumerate() {
        let (table, _) = &tables()[index];
        for suffix in [".B1.B2", ".reuse.reuse", ".B4", ".H1", ".B1.NP"] {
            let text = format!("F2FP.F16.E2M1.UNPACK_B R7, R6{suffix} ;");
            assert!(
                cubit::encoder::encode_instruction(
                    &cubit::parse_cuasm_line(&text, 0).unwrap(),
                    table,
                )
                .is_err(),
                "{arch}: {text}"
            );
        }
    }
}

#[test]
fn adjacent_and_unlicensed_encodings_do_not_enter_e2m1_row() {
    for (index, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[index];
        let (mut negative, mut adjacent, mut other, mut control) = (0, 0, 0, 0);
        for row in rows(fixture) {
            let kind = row["kind"].as_str().unwrap();
            if matches!(kind, "positive" | "control_plane") {
                control += usize::from(kind == "control_plane");
                continue;
            }
            match kind {
                "negative" => negative += 1,
                "adjacent_modifier" => adjacent += 1,
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
            (91, 8, 5, 36),
            "{arch}: negative census"
        );
    }
}

#[test]
fn explicit_selector_encoder_uses_noncontiguous_b88_b72() {
    for (index, (arch, _)) in arches().iter().enumerate() {
        let (table, _) = &tables()[index];
        for (selector, suffix) in [(0, ""), (0, ".reuse"), (1, ".B1"), (2, ".B2"), (3, ".B3")] {
            let text = format!("F2FP.F16.E2M1.UNPACK_B R7, R6{suffix} ;");
            let parsed = cubit::parse_cuasm_line(&text, 0).unwrap();
            let expected = 0x00000000020402ff00000006ff07723eu128
                | (((selector & 1) as u128) << 72)
                | (((selector >> 1) as u128) << 88);
            let encoded = cubit::encoder::encode_instruction(&parsed, table).unwrap();
            // With no authored schedule, encoding supplies the default control code.
            // The production roundtrip above checks every complete control word.
            assert_eq!(encoded & ((1u128 << 96) - 1), expected, "{arch}: {text}");
        }
    }
}

#[test]
fn selector_and_reuse_accept_either_vendor_order() {
    for (index, (arch, _)) in arches().iter().enumerate() {
        let (table, _) = &tables()[index];
        for (selector, suffix) in [
            (1u128, ".reuse.B1"),
            (1u128, ".B1.reuse"),
            (2u128, ".B2.reuse"),
            (3u128, ".reuse.B3"),
        ] {
            let text = format!("F2FP.F16.E2M1.UNPACK_B R8, R17{suffix} ;");
            let encoded = cubit::encoder::encode_instruction(
                &cubit::parse_cuasm_line(&text, 0).unwrap(),
                table,
            )
            .unwrap_or_else(|error| panic!("{arch}: {text}: {error}"));
            assert_eq!(
                encoded & ((1u128 << 72) | (1u128 << 88)),
                (selector & 1) << 72 | (selector >> 1) << 88,
                "{arch}: {text}"
            );
            assert_ne!(encoded & (1u128 << 123), 0, "{arch}: {text}");
        }
    }
}
