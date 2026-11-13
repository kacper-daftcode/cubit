//! Measured production register-multiplier/uniform-addend FFMA2; no GPU execution.
include!("engine_l1_controls.inc");
include!("hb300_fixture.inc");
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_ffma2_addend_ur_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_ffma2_addend_ur_nvdisasm.jsonl"),
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
        ("FFMA2_R_R_R_UR", ""),
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
        assert_eq!(production, 63, "{arch}: all unique plain production words");
    }
}

#[test]
fn measured_lattice_and_provenance() {
    const SOURCE: &str = "engine-l1a-ffma2-ur-shape-2026-11-13";
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
        assert_eq!(adopted, 1099, "{arch}: measured lattice");
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"]["FFMA2_R_R_R_UR"];
        assert_eq!(
            (
                entry["operand_sig"].as_str(),
                entry["base_op"].as_str(),
                entry["_src"].as_str()
            ),
            (Some("R_R_R_UR"), Some("FFMA2"), Some(SOURCE))
        );
        assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 1);
        let group = &entry["mod_groups"][""];
        assert_eq!(
            hex(&group["and_base"]),
            0x00000000092000000000000000000e49u128
        );
        assert_eq!(group["claim_forbid"].as_array().unwrap().len(), 8);
        let mask = group["fields"]
            .as_array()
            .unwrap()
            .iter()
            .fold(0u128, |mask, field| {
                mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1)
                    << field["shift"].as_u64().unwrap())
            });
        assert_eq!(hex(&group["variable_mask"]), mask);
        assert_eq!(mask, 0x0800000000000fffc00000fffffff000u128);
        for field in group["fields"].as_array().unwrap() {
            match (
                field["token_idx"].as_u64().unwrap(),
                field["shift"].as_u64().unwrap(),
            ) {
                (3, 64) => assert_eq!(field["extraction"].as_str(), Some("reg")),
                (4, 32) => assert_eq!(field["extraction"].as_str(), Some("ureg")),
                (3, 123) => assert_eq!(field["extraction"].as_str(), Some("reuse")),
                (3, 74 | 75) => assert_eq!(
                    field["extraction"].as_str(),
                    Some(match field["shift"].as_u64().unwrap() {
                        74 => "abs",
                        75 => "neg",
                        _ => unreachable!(),
                    })
                ),
                (4, 62 | 63) => assert_eq!(
                    field["extraction"].as_str(),
                    Some(match field["shift"].as_u64().unwrap() {
                        62 => "abs",
                        63 => "neg",
                        _ => unreachable!(),
                    })
                ),
                (3, _) | (4, _) => panic!("{arch}: incorrect multiplier/addend field assignment"),
                _ => {}
            }
        }
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
                if e2_consolidated_control(&row, "FFMA2_R_R_R_UR", &decoded.key) {
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
                    ("FFMA2_R_R_R_UR", ""),
                    "{arch}: unlicensed {}",
                    row["word"]
                );
            }
        }
        assert_eq!(
            (adjacent, negative, inert),
            (815, 584, 637),
            "{arch}: boundaries"
        );
        for text in [
            "FFMA2 R6, R6.F32x2.HI_LO, R3.F32, R0.F32 ;",
            "FFMA2 R6, R6.F32x2.HI_LO, UR3.F32, R0.F32 ;",
            "FFMA2 R6, R6.F32x2.HI_LO.NP, R3.F32, UR0.F32 ;",
            "FFMA2 R6, R6.F32x2.HI_LO, R3.F32x2.HI_LO, UR0.F32 ;",
            "FFMA2 R6, R6.F32x2.HI_LO, R3.F32, UR0.F32x2.HI_LO ;",
            "FFMA2 R6, -R6.F32x2.HI_LO, R3.F32, UR0.F32 ;",
            "FFMA2 R6, R6.F32x2.HI_LO, R3.F32, -UR0.F32 ;",
            "FFMA2 R6, R6.F32x2.HI_LO, R3.reuse.F32, UR0.reuse.F32 ;",
        ] {
            let parsed = cubit::parse_cuasm_line(text, 0).unwrap();
            if text
                .rsplit(", ")
                .next()
                .is_some_and(|token| token.starts_with("UR") && token.contains(".reuse"))
            {
                assert!(
                    cubit::encoder::encode_instruction(&parsed, table).is_err(),
                    "{arch}: UR.reuse without a measured field must be refused"
                );
                continue;
            }
            if let Ok(word) = cubit::encoder::encode_instruction(&parsed, table) {
                let decoded = index
                    .decode(word, 0, table)
                    .unwrap_or_else(|error| panic!("{arch} authored form {text}: {error}"));
                let tokens: Vec<_> = text.trim_end_matches(" ;").split(", ").collect();
                let is_ur = |token: &str| token.starts_with("UR") || token.starts_with("-UR");
                let expected = if is_ur(tokens[3]) {
                    "FFMA2_R_R_R_UR"
                } else if is_ur(tokens[2]) {
                    "FFMA2_R_R_UR_R"
                } else {
                    "FFMA2_R_R_R_R"
                };
                assert_eq!(
                    decoded.key, expected,
                    "{arch}: wrong consolidated row: {text}"
                );
                assert_eq!(
                    cubit::printer::to_sass_lossless(&decoded),
                    text.trim_end_matches(" ;"),
                    "{arch}: alternate rendering must remain vendor text: {text}"
                );
            }
        }
        let garbage =
            cubit::parse_cuasm_line("FFMA2 R6, R6.F32.GARBAGE, R18.F32, UR90.F32 ;", 0).unwrap();
        assert!(
            cubit::encoder::encode_instruction(&garbage, table).is_err(),
            "{arch}: unknown source suffix must fail closed"
        );
    }
}
