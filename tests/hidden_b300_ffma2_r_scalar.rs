//! Measured production scalar-B/C FFMA2 fixed-shape text; no GPU execution.
include!("engine_l1_controls.inc");
include!("hb300_fixture.inc");
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_ffma2_r_scalar_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_ffma2_r_scalar_nvdisasm.jsonl"),
        ),
    ]
});

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

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn check_word(word: u128, text: &str, arch: &str) {
    let (table, index) = &tables()[usize::from(arch == "sm100a")];
    let decoded = index
        .decode(word, 0, table)
        .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
    assert_eq!(
        (decoded.key.as_str(), decoded.mod_group.as_str()),
        ("FFMA2_R_R_R_R", ""),
        "{arch} {word:032x}"
    );
    assert_eq!(
        cubit::printer::to_sass(&decoded),
        text,
        "{arch} {word:032x}"
    );
    assert_eq!(
        cubit::printer::to_sass_lossless(&decoded),
        text,
        "{arch} {word:032x}"
    );
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    assert_eq!(
        cubit::encoder::encode_instruction(&parsed, table).unwrap(),
        word & !(7u128 << 125),
        "{arch} {word:032x}"
    );
}

#[test]
fn production_machine_words_decode_render_and_reencode() {
    for (arch, fixture) in ARCHES.iter() {
        let production = fixture
            .lines()
            .filter_map(|line| {
                let row: Value = serde_json::from_str(line).unwrap();
                (row["role"] == "adopt" && row["generation"] == "production").then(|| {
                    check_word(
                        hex(&row["word"]),
                        row["nvidia_sass"].as_str().unwrap(),
                        arch,
                    );
                })
            })
            .count();
        assert_eq!(production, 148, "{arch}: all unique plain production words");
    }
}

#[test]
fn measured_lattice_and_provenance() {
    const SOURCE: &str = "engine-l1a-ffma2-shapes-2026-11-13";
    for (arch, fixture) in ARCHES.iter() {
        let adopted = fixture
            .lines()
            .filter_map(|line| {
                let row: Value = serde_json::from_str(line).unwrap();
                (row["role"] == "adopt").then(|| {
                    check_word(
                        hex(&row["word"]),
                        row["nvidia_sass"].as_str().unwrap(),
                        arch,
                    );
                })
            })
            .count();
        assert_eq!(adopted, 1184, "{arch}: measured lattice");
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"]["FFMA2_R_R_R_R"];
        assert_eq!(
            (
                entry["operand_sig"].as_str(),
                entry["base_op"].as_str(),
                entry["_src"].as_str()
            ),
            (Some("R_R_R_R"), Some("FFMA2"), Some(SOURCE))
        );
        assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 1);
        let group = &entry["mod_groups"][""];
        assert_eq!(
            hex(&group["and_base"]),
            0x00000000000000000000000000000249u128
        );
        assert_eq!(group["claim_forbid"].as_array().unwrap().len(), 6);
        let mask = group["fields"]
            .as_array()
            .unwrap()
            .iter()
            .fold(0u128, |mask, field| {
                mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1)
                    << field["shift"].as_u64().unwrap())
            });
        assert_eq!(hex(&group["variable_mask"]), mask);
        assert_eq!(mask, 0x1c000000012e0fffc00000fffffff000u128);
    }
}

#[test]
fn alternate_shapes_modifiers_and_refused_words_do_not_claim_this_row() {
    for (arch, fixture) in ARCHES.iter() {
        let (table, index) = &tables()[usize::from(*arch == "sm100a")];
        let (mut adjacent, mut inert, mut negative) = (0, 0, 0);
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let role = row["role"].as_str().unwrap();
            if !matches!(role, "negative" | "adjacent" | "unclaimed_text_inert") {
                continue;
            }
            adjacent += usize::from(role == "adjacent");
            negative += usize::from(role == "negative");
            inert += usize::from(role == "unclaimed_text_inert");
            if let Ok(decoded) = index.decode(hex(&row["word"]), 0, table) {
                if e2_consolidated_control(&row, "FFMA2_R_R_R_R", &decoded.key) {
                    assert_eq!(
                        cubit::printer::to_sass(&decoded),
                        row["nvidia_sass"].as_str().unwrap(),
                        "{arch}: consolidated control must preserve vendor text"
                    );
                    continue;
                }
                if row["role"] == "adjacent"
                    && row["generation"] == "production"
                    && row["nvidia_sass"]
                        .as_str()
                        .is_some_and(|text| text.contains(".reuse"))
                {
                    // Consolidation admits this measured source family including its reuse field.
                    continue;
                }
                assert_ne!(
                    (decoded.key.as_str(), decoded.mod_group.as_str()),
                    ("FFMA2_R_R_R_R", ""),
                    "{arch}: unlicensed {}",
                    row["word"]
                );
            }
        }
        assert_eq!(
            (adjacent, negative, inert),
            (979, 529, 637),
            "{arch}: boundaries"
        );
        for text in [
            "FFMA2 R6, R6.F32, R3.F32, R0.F32 ;",
            "FFMA2 R6, R6.F32x2.HI_LO.NP, R3.F32, R0.F32 ;",
            "FFMA2 R6, R6.F32x2.HI_LO, R3.F32x2.HI_LO, R0.F32 ;",
            "FFMA2 R6, R6.F32x2.HI_LO, R3.F32, R0.F32x2.HI_LO ;",
            "FFMA2 R6, -R6.F32x2.HI_LO, R3.F32, R0.F32 ;",
            "FFMA2 R6, R6.F32x2.HI_LO, R3.F32, -R0.F32 ;",
            "FFMA2 R6, R6.F32x2.HI_LO, R3.reuse.F32, R0.reuse.F32 ;",
        ] {
            let parsed = cubit::parse_cuasm_line(text, 0).unwrap();
            if let Ok(word) = cubit::encoder::encode_instruction(&parsed, table) {
                let decoded = index
                    .decode(word, 0, table)
                    .unwrap_or_else(|error| panic!("{arch} authored form {text}: {error}"));
                assert_eq!(
                    decoded.key, "FFMA2_R_R_R_R",
                    "{arch}: wrong consolidated row: {text}"
                );
                assert_eq!(
                    cubit::printer::to_sass_lossless(&decoded),
                    text.trim_end_matches(" ;"),
                    "{arch}: alternate rendering must remain vendor text: {text}"
                );
            }
        }
    }
}
