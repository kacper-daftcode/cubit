//! Measured production F2FP E4M3.F16 UNPACK_B_MERGE_C; no GPU execution.
include!("hb300_fixture.inc");
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-f2fp-e4m3-f16-unpack-merge-c-production-2026-11-10";
const GROUP: &str = "E4M3,F16,SATFINITE,UNPACK_B_MERGE_C";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| {
    [("sm103a", hb300_fixture("sm103a_f2fp_e4m3_f16_unpack_merge_c_nvdisasm.jsonl")),
     ("sm100a", hb300_fixture("sm100a_f2fp_e4m3_f16_unpack_merge_c_nvdisasm.jsonl"))]
});

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLES: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLES.get_or_init(|| ARCHES.iter().map(|(arch, _)| {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    }).collect())
}

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn check_word(word: u128, text: &str, arch: &str) {
    let (table, index) = &tables()[usize::from(arch == "sm100a")];
    let decoded = index.decode(word, 0, table)
        .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
    assert_eq!((decoded.key.as_str(), decoded.mod_group.as_str()), ("F2FP_R_R_R", GROUP));
    assert_eq!(cubit::printer::to_sass(&decoded), text, "{arch} {word:032x}");
    assert_eq!(cubit::printer::to_sass_lossless(&decoded), text, "{arch} {word:032x}");
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    assert_eq!(cubit::encoder::encode_instruction(&parsed, table).unwrap(),
        word & !(7u128 << 125), "{arch} {word:032x}");
}

#[test]
fn production_machine_words_decode_render_and_reencode() {
    for (arch, fixture) in ARCHES.iter() {
        let production = fixture.lines().filter_map(|line| {
            let row: Value = serde_json::from_str(line).unwrap();
            (row["role"] == "adopt" && row["generation"] == "production").then(|| {
                check_word(hex(&row["word"]), row["nvidia_sass"].as_str().unwrap(), arch);
            })
        }).count();
        assert_eq!(production, 189, "{arch}: all unique production words");
    }
}

#[test]
fn measured_lattice_and_provenance() {
    for (arch, fixture) in ARCHES.iter() {
        let adopted = fixture.lines().filter_map(|line| {
            let row: Value = serde_json::from_str(line).unwrap();
            (row["role"] == "adopt").then(|| {
                check_word(hex(&row["word"]), row["nvidia_sass"].as_str().unwrap(), arch);
            })
        }).count();
        assert_eq!(adopted, 988, "{arch}: measured lattice");
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"]["F2FP_R_R_R"];
        assert_eq!((entry["operand_sig"].as_str(), entry["base_op"].as_str()),
                   (Some("R_R_R"), Some("F2FP")));
        let group = &entry["mod_groups"][GROUP];
        assert_eq!(group["_src"], SOURCE);
        assert_eq!(hex(&group["and_base"]), 0x000000000480320000000000ff00023eu128);
        assert_eq!(group["claim_forbid"].as_array().unwrap().len(), 3);
        let mask = group["fields"].as_array().unwrap().iter().fold(0u128, |mask, field| {
            mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1)
                << field["shift"].as_u64().unwrap())
        });
        assert_eq!(hex(&group["variable_mask"]), mask);
        assert_eq!(mask, 0x00000000000001ff000000ff00fff000u128);
    }
}

#[test]
fn modifiers_text_inert_and_refused_words_do_not_claim_this_row() {
    for (arch, fixture) in ARCHES.iter() {
        let (table, index) = &tables()[usize::from(*arch == "sm100a")];
        let (mut adjacent, mut inert, mut negative, mut control) = (0, 0, 0, 0);
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let role = row["role"].as_str().unwrap();
            if role == "adopt" { continue; }
            if role == "control" {
                control += 1;
                continue;
            }
            if let Ok(decoded) = index.decode(hex(&row["word"]), 0, table) {
                assert_ne!((decoded.key.as_str(), decoded.mod_group.as_str()),
                    ("F2FP_R_R_R", GROUP), "{arch}: unlicensed {}", row["word"]);
            }
            adjacent += usize::from(role == "adjacent");
            negative += usize::from(role == "negative");
            inert += usize::from(role == "unclaimed_text_inert");
        }
        assert_eq!((adjacent, negative, inert, control), (148, 1083, 1052, 37));
        for text in [
            "F2FP.SATFINITE.E4M3.F16.UNPACK_B_MERGE_C R21, R21.reuse, R4 ;",
            "F2FP.SATFINITE.E4M3.F16.UNPACK_B_MERGE_C R21, R21, R4.reuse ;",
            "F2FP.SATFINITE.E5M2.F16.UNPACK_B_MERGE_C R21, R21, R4 ;",
            "F2FP.SATFINITE.RELU.E4M3.F16.UNPACK_B_MERGE_C R21, R21, R4 ;",
            "F2FP.SATFINITE.E4M3.BF16.UNPACK_B_MERGE_C R21, R21, R4 ;",
        ] {
            let parsed = cubit::parse_cuasm_line(text, 0).unwrap();
            assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(),
                    "{arch}: unmeasured authored form selected this row: {text}");
        }
    }
}
