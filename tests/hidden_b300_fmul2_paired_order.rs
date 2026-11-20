//! Measured production FMUL2 Ra.LO_HI paired-register forms; no GPU execution.
include!("engine_l1_controls.inc");
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_fmul2_paired_order_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_fmul2_paired_order_nvdisasm.jsonl"),
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
    assert_eq!(decoded.key, "FMUL2_R_R_R", "{arch} {word:032x}");
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
            if row["kind"] != "positive" || row["generation"] != "production" {
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
        assert_eq!(production, 2, "{arch}: both production machine words");
    }
}

#[test]
fn measured_lattice_and_provenance() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let mut adopted = 0;
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["kind"] != "positive" {
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
            "{arch}: complete measured field lattice"
        );
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        let source = "engine-l1a-fmul2-shapes-2026-11-13";
        assert_eq!(raw["_meta"]["provenance"]["sources"][source]["rows"], 2);
        let entry = &raw["instructions"]["FMUL2_R_R_R"];
        assert_eq!(entry["operand_sig"], "R_R_R");
        assert_eq!(entry["base_op"], "FMUL2");
        assert_eq!(entry["_src"], source);
        assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 2);
        let group = &entry["mod_groups"][""];
        assert_eq!(group["_src"], source);
        assert!(group["claim_forbid"].as_array().unwrap().len() >= 3);
        let mask = group["fields"]
            .as_array()
            .unwrap()
            .iter()
            .fold(0u128, |mask, field| {
                mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1)
                    << field["shift"].as_u64().unwrap())
            });
        assert_eq!(hex(&group["variable_mask"]), mask);
        assert_eq!(mask, 0x0c00000001860300c00000fffffff000u128);
        assert_eq!(
            raw["instructions"]["FMUL2_R_R_R"]["mod_groups"][""]["_src"],
            source
        );
        for text in [
            "FMUL2 R42, R36.F32x2.LO_HI, R42.F32x2.HI_LO ;",
            "FMUL2 R42, R36.F32x2.LO_HI, R42.F32x2.LO_HI ;",
        ] {
            let parsed = cubit::parse_cuasm_line(text, 0).unwrap();
            assert!(
                cubit::encoder::encode_instruction(&parsed, table).is_ok(),
                "{text}"
            );
        }
    }
}

#[test]
fn alternate_shapes_modifiers_and_reuse_do_not_claim_this_row() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let (mut adjacent, mut negative, mut reuse) = (0, 0, 0);
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let generation = row["generation"].as_str().unwrap();
            if matches!(
                generation,
                "production"
                    | "base"
                    | "guard"
                    | "register"
                    | "b_order"
                    | "cross"
                    | "control_plane"
            ) {
                continue;
            }
            let word = hex(&row["word"]);
            if generation == "reuse_control" && ((word >> 122) & 7) == 0 {
                reuse += 1;
                continue;
            }
            adjacent += usize::from(row["kind"] == "adjacent_modifier");
            negative += usize::from(row["kind"] == "negative");
            reuse += usize::from(generation == "reuse_control");
            if let Ok(decoded) = index.decode(word, 0, table) {
                if generation == "reuse_control"
                    && row["rc"] != 0
                    && ((word >> 96) & !(7u128 << 26)) == 0
                {
                    // The vendor rejects the all-zero control field here;
                    // served controls independently measure the operand bit.
                    continue;
                }
                if e2_consolidated_control(&row, "FMUL2_R_R_R", &decoded.key) {
                    assert_eq!(
                        cubit::printer::to_sass(&decoded),
                        row["nvidia_sass"].as_str().unwrap(),
                        "{arch}: consolidated control must preserve vendor text"
                    );
                    continue;
                }
                assert_ne!(
                    (decoded.key.as_str(), decoded.mod_group.as_str()),
                    ("FMUL2_R_R_R", ""),
                    "{arch}: unlicensed {} claimed {word:032x}",
                    row["label"]
                );
            }
        }
        assert!(
            adjacent > 0 && negative > 0,
            "{arch}: negative census retained"
        );
        assert_eq!(
            reuse, 30,
            "{arch}: deduplicated reuse controls plus two base aliases"
        );
        {
            let text = "FMUL2 R42, R36.F32x2.LO_HI.GARBAGE, R42.F32x2.HI_LO ;";
            let parsed = cubit::parse_cuasm_line(text, 0).unwrap();
            assert!(
                cubit::encoder::encode_instruction(&parsed, table).is_err(),
                "{text}"
            );
        }
    }
}

const ADOPT_PER_TARGET: usize = 1820;
