//! Measured production FADD2 register/uniform fixed-shape text; no GPU execution.
include!("engine_l1_controls.inc");
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| {
    [
        ("sm103a", hb300_fixture("sm103a_fadd2_rur_nvdisasm.jsonl")),
        ("sm100a", hb300_fixture("sm100a_fadd2_rur_nvdisasm.jsonl")),
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

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

fn assert_decoded(
    decoded: cubit::decoder::DecodedInst,
    word: u128,
    text: &str,
    table: &IsaTable,
    arch: &str,
) {
    assert_eq!(decoded.key, "FADD2_R_R_UR", "{arch} {word:032x}");
    assert_eq!(decoded.mod_group, "", "{arch} {word:032x}");
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
    assert_eq!(
        encode(table, word, text),
        word & !(7u128 << 125),
        "{arch} {word:032x}"
    );
}

#[test]
fn production_machine_words_decode_render_and_reencode() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let mut production = 0;
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["role"] != "adopt" || row["generation"] != "production" {
                continue;
            }
            let word = hex(&row["word"]);
            let decoded = index
                .decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_decoded(
                decoded,
                word,
                row["nvidia_sass"].as_str().unwrap(),
                table,
                arch,
            );
            production += 1;
        }
        assert_eq!(production, 88, "{arch}: all deduplicated production words");
    }
}

#[test]
fn measured_lattice_and_provenance() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let mut adopted = 0;
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["role"] != "adopt" {
                continue;
            }
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_decoded(decoded, word, text, table, arch);
            adopted += 1;
        }
        assert_eq!(
            adopted, ADOPT_PER_TARGET,
            "{arch}: full measured field lattice"
        );
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        let source = "engine-l1a-fadd2-ur-shape-2026-11-13";
        assert_eq!(raw["_meta"]["provenance"]["sources"][source]["rows"], 1);
        let entry = &raw["instructions"]["FADD2_R_R_UR"];
        assert_eq!(entry["operand_sig"], "R_R_UR");
        assert_eq!(entry["base_op"], "FADD2");
        assert_eq!(entry["_src"], source);
        assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 1);
        let group = &entry["mod_groups"][""];
        assert_eq!(group["_src"], source);
        assert_eq!(
            hex(&group["and_base"]),
            0x00000000082000000000000000000e4bu128
        );
        assert_eq!(group["claim_forbid"].as_array().unwrap().len(), 7);
        let mask = group["fields"]
            .as_array()
            .unwrap()
            .iter()
            .fold(0u128, |mask, field| {
                mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1)
                    << field["shift"].as_u64().unwrap())
            });
        assert_eq!(hex(&group["variable_mask"]), mask);
        assert_eq!(mask, 0x0000000000000300c00000fffffff000u128);
    }
}

#[test]
fn alternate_shapes_modifiers_and_refused_words_do_not_claim_this_row() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let (mut adjacent, mut inert, mut negative, mut reuse) = (0, 0, 0, 0);
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let word = hex(&row["word"]);
            let role = row["role"].as_str().unwrap();
            let label = row["label"].as_str().unwrap();
            if !matches!(role, "negative" | "adjacent" | "unclaimed_text_inert")
                && !label.starts_with("reuse-mask:")
            {
                continue;
            }
            adjacent += usize::from(role == "adjacent");
            negative += usize::from(role == "negative");
            inert += usize::from(role == "unclaimed_text_inert");
            reuse += usize::from(label.starts_with("reuse-mask:"));
            if let Ok(decoded) = index.decode(word, 0, table) {
                if e2_consolidated_control(&row, "FADD2_R_R_UR", &decoded.key) {
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
                    ("FADD2_R_R_UR", ""),
                    "{arch}: unlicensed {label} claimed {word:032x}"
                );
            }
        }
        assert_eq!(
            (adjacent, negative, inert, reuse),
            (671, 600, 1019, 7),
            "{arch}: negative census"
        );
        let parsed =
            cubit::parse_cuasm_line("FADD2 R14, R14.F32x2.HI_LO.GARBAGE, UR8.F32 ;", 0).unwrap();
        assert!(cubit::encoder::encode_instruction(&parsed, table).is_err());
        let parsed = cubit::parse_cuasm_line("FADD2 R14, R14.INVALID3.NP, UR8.F32 ;", 0).unwrap();
        assert!(cubit::encoder::encode_instruction(&parsed, table).is_err());
    }
}

const ADOPT_PER_TARGET: usize = 869;
