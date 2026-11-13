//! Measured production FMUL2 paired-uniform fixed-shape text; no GPU execution.
include!("engine_l1_controls.inc");
include!("hb300_fixture.inc");
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_fmul2_paired_ur_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_fmul2_paired_ur_nvdisasm.jsonl"),
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
        ("FMUL2_R_R_UR", ""),
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
        assert_eq!(production, 97, "{arch}: all unique production words");
    }
}

#[test]
fn measured_lattice_and_provenance() {
    const SOURCE: &str = "engine-l1a-fmul2-resolved-ur-shape-2026-11-13";
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
        assert_eq!(adopted, ADOPT_PER_TARGET, "{arch}: measured lattice");
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"]["FMUL2_R_R_UR"];
        assert_eq!(
            (
                entry["operand_sig"].as_str(),
                entry["base_op"].as_str(),
                entry["_src"].as_str()
            ),
            (Some("R_R_UR"), Some("FMUL2"), Some(SOURCE))
        );
        assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 1);
        let group = &entry["mod_groups"][""];
        assert_eq!(
            hex(&group["and_base"]),
            0x00000000080000000000000000000c4au128
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
        assert_eq!(mask, 0x0000000001000300c00000fffffff000u128);
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
                if e2_consolidated_control(&row, "FMUL2_R_R_UR", &decoded.key) {
                    assert_eq!(
                        cubit::printer::to_sass(&decoded),
                        row["nvidia_sass"].as_str().unwrap(),
                        "{arch}: consolidated control must preserve vendor text"
                    );
                    continue;
                }
                assert_ne!(
                    (decoded.key.as_str(), decoded.mod_group.as_str()),
                    ("FMUL2_R_R_UR", ""),
                    "{arch}: unlicensed {}",
                    row["word"]
                );
            }
        }
        assert!(
            adjacent > 0 && negative > 0 && inert > 0,
            "{arch}: boundaries"
        );
        for text in [
            "FMUL2 R14, R14.F32x2.HI_LO.GARBAGE, UR8.F32x2.HI_LO ;",
            "FMUL2 R14, R14.INVALID3.NP, UR8.F32x2.HI_LO ;",
        ] {
            let parsed = cubit::parse_cuasm_line(text, 0).unwrap();
            assert!(
                cubit::encoder::encode_instruction(&parsed, table).is_err(),
                "{text}"
            );
        }
        let scalar = cubit::parse_cuasm_line("FMUL2 R14, R14.F32x2.HI_LO, UR8.F32 ;", 0).unwrap();
        let word = cubit::encoder::encode_instruction(&scalar, table).unwrap();
        assert!(
            (word >> 88) & 1 != 0,
            "{arch}: the resolved UR row owns scalar bit 88"
        );
        let decoded = index.decode(word, 0, table).unwrap();
        assert_eq!(decoded.key, "FMUL2_R_R_UR");
    }
}

const ADOPT_PER_TARGET: usize = 878;
