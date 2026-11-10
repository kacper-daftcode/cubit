//! Production-anchored HMNMX2 register and two-f16-immediate measurement.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const SRC: &str = "hidden-b300-hmnmx2-2026-11-08";
/// The text-inert bits of the measured lattice: 64, [71:66], 76, 77, 79, 83, 84, 86, [95:92] on both forms and [59:40]
/// on the register form. The candidate carried each as a one-bit field without an extraction, so a word with such a
/// bit set decoded to the text of the word without it. On `main` the rows fail closed on them, as every measured row
/// of these tables does (session T-26, 2026-11-10, blackwell-isa 3a30f62): the 180 fixture words the candidate
/// adopted with such a bit set (110 register-form, 70 immediate-form) are refused, and every other adopted word --
/// the 629 production words included -- re-assembles to itself.
const TEXT_INERT_IMM: u128 = 0xf058_b0fd_u128 << 64;
const TEXT_INERT_REG: u128 = TEXT_INERT_IMM | (0xf_ffff_u128 << 40);

fn text_inert(word: u128) -> u128 {
    word & if word & 0xfff == 0x240 { TEXT_INERT_REG } else { TEXT_INERT_IMM }
}

#[test]
fn fixture_render_encode_and_boundaries() {
    let mut adopted = 0;
    let mut production = 0;
    let mut exact = 0;
    let mut negatives = 0;
    let mut explicit_invalid = 0;
    let mut inert_refused = 0;
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in hb300_fixture("sm103_hmnmx2_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["auxiliary"].is_string() {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str();
            if row["adopt"] == true && text_inert(word) != 0 {
                assert_ne!(row["encode_exact"], true, "{arch}: {word:032x}");
                assert!(
                    index.decode(word, 0, &table).is_err(),
                    "{arch}: a word with a text-inert bit set must fail closed {word:032x}"
                );
                inert_refused += 1;
            } else if row["adopt"] == true {
                adopted += 1;
                let want_key = if row["form"] == "reg" {
                    "HMNMX2_R_R_R_P"
                } else {
                    "HMNMX2_R_R_FI_FI_P"
                };
                let decoded = index
                    .decode(word, 0, &table)
                    .unwrap_or_else(|error| panic!("{arch}: {word:032x}: {error}: {vendor:?}"));
                assert_eq!(decoded.key, want_key, "{arch}: {word:032x}");
                let rendered = cubit::printer::to_sass(&decoded);
                assert_eq!(
                    rendered.trim(),
                    vendor.unwrap().trim(),
                    "{arch}: render {word:032x}"
                );
                if row["kind"] == "H-production" {
                    production += 1;
                }
                {
                    let lossless = cubit::printer::to_sass_lossless(&decoded);
                    let ctrl = cubit::scheduling::format_control_code(
                        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32),
                    );
                    let source = format!("[{ctrl}] {lossless} ;");
                    let parsed = cubit::parse_cuasm_line(&source, 0)
                        .unwrap_or_else(|error| panic!("{arch}: parse {source}: {error}"));
                    let encoded = cubit::encoder::encode_instruction(&parsed, &table)
                        .unwrap_or_else(|error| panic!("{arch}: encode {source}: {error}"));
                    assert_eq!(encoded, word, "{arch}: exact encoding {word:032x}");
                    exact += 1;
                }
            } else if word & 0xfff == 0x240 || word & 0xfff == 0x840 {
                if let Some(text) = vendor {
                    assert!(text.contains("HMNMX2"));
                    match index.decode(word, 0, &table) {
                        Err(_) => negatives += 1,
                        Ok(decoded) => {
                            let rendered = cubit::printer::to_sass(&decoded);
                            assert!(
                                rendered.contains("INVALID") || rendered.contains("???"),
                                "{arch}: silently legalized {word:032x} as {rendered}"
                            );
                            assert!(cubit::encoder::encode_instruction(
                                &cubit::parse_cuasm_line(&format!("{rendered} ;"), 0).unwrap(),
                                &table
                            )
                            .is_err());
                            explicit_invalid += 1;
                        }
                    }
                } else {
                    assert!(
                        index.decode(word, 0, &table).is_err(),
                        "{arch}: unnamed word must stay unclaimed {word:032x}"
                    );
                    negatives += 1;
                }
            }
        }
        for invalid in [
            "HMNMX2 R1, R2.H0_H1, R3, PT ;",
            "HMNMX2 R1, R2, R3.H0_H1, PT ;",
            "HMNMX2 R1, R2.H0_H1, 1, 1, PT ;",
            "HMNMX2 R1, R2, UR3, PT ;",
            "HMNMX2.UNKNOWN R1, R2, R3, PT ;",
            "HMNMX2 R1, R2, R3 ;",
        ] {
            assert!(
                cubit::encoder::encode_instruction(
                    &cubit::parse_cuasm_line(invalid, 0).unwrap(),
                    &table
                )
                .is_err(),
                "{arch}: {invalid}"
            );
        }
    }
    assert_eq!(production, 1258);
    assert_eq!((adopted, exact, inert_refused), (3604, 3604, 360));
    assert!(negatives >= 100, "negatives={negatives}");
    assert!(
        explicit_invalid >= 20,
        "explicit_invalid={explicit_invalid}"
    );
}

#[test]
fn measured_fields_and_provenance() {
    let mut production = 0;
    for line in hb300_fixture("sm103_hmnmx2_nvdisasm.jsonl").lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        if row["auxiliary"].is_string() {
            continue;
        }
        production += usize::from(row["kind"] == "H-production");
    }
    assert_eq!(production, 629);
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 32);
        for (key, opcode, pred_token) in [
            ("HMNMX2_R_R_R_P", 0x240, 4),
            ("HMNMX2_R_R_FI_FI_P", 0x840, 5),
        ] {
            let entry = &raw["instructions"][key];
            assert_eq!(entry["base_op"], "HMNMX2");
            assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 16);
            for (name, row) in entry["mod_groups"].as_object().unwrap() {
                assert_eq!(row["_src"], SRC);
                let base = u128::from_str_radix(
                    row["and_base"].as_str().unwrap().trim_start_matches("0x"),
                    16,
                )
                .unwrap();
                assert_eq!(base & 0xfff, opcode);
                for modifier in name.split(',').filter(|m| !m.is_empty()) {
                    let bit = match modifier {
                        "FTZ" => 80,
                        "NAN" => 81,
                        "XORSIGN" => 82,
                        "BF16_V2" => 85,
                        other => panic!("unexpected modifier {other}"),
                    };
                    assert_ne!(base & (1u128 << bit), 0, "{arch}: {key}: {name}");
                }
                for (shift, bits, extraction, token) in [
                    (12, 4, "guard", 0),
                    (16, 8, "reg", 1),
                    (24, 8, "reg", 2),
                    (72, 1, "neg", 2),
                    (73, 1, "abs", 2),
                    (74, 2, "hsel", 2),
                    (122, 1, "reuse", 2),
                    (87, 3, "pred", pred_token),
                    (90, 1, "neg", pred_token),
                ] {
                    assert!(
                        row["fields"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|field| field["shift"] == shift
                                && field["bits"] == bits
                                && field["extraction"] == extraction
                                && field["token_idx"] == token),
                        "{arch}: {key}: missing {extraction}@{shift}"
                    );
                }
                if opcode == 0x240 {
                    for (shift, bits, extraction, token) in [
                        (32, 8, "reg", 3),
                        (62, 1, "abs", 3),
                        (63, 1, "neg", 3),
                        (60, 2, "hsel", 3),
                        (123, 1, "reuse", 3),
                    ] {
                        assert!(row["fields"].as_array().unwrap().iter().any(|field| field
                            ["shift"]
                            == shift
                            && field["bits"] == bits
                            && field["extraction"] == extraction
                            && field["token_idx"] == token));
                    }
                } else {
                    for (shift, token) in [(48, 3), (32, 4)] {
                        let extraction = if name.split(',').any(|m| m == "BF16_V2") {
                            "bf16"
                        } else {
                            "f16"
                        };
                        assert!(row["fields"].as_array().unwrap().iter().any(|field| field
                            ["shift"]
                            == shift
                            && field["bits"] == 16
                            && field["extraction"] == extraction
                            && field["token_idx"] == token));
                    }
                }
                // (the canonical layout writes a tag once per level: a field's own `_src` is absent or equal)
                assert!(row["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|field| field["_src"].is_null() || field["_src"] == SRC));
                // no field without an extraction, none on a text-inert bit
                assert!(row["fields"].as_array().unwrap().iter().all(|field| field["extraction"] != ""));
                let mask = u128::from_str_radix(
                    row["variable_mask"].as_str().unwrap().trim_start_matches("0x"),
                    16,
                )
                .unwrap();
                assert_eq!(mask & if opcode == 0x240 { TEXT_INERT_REG } else { TEXT_INERT_IMM }, 0);
                let forbidden = row["claim_forbid"].as_array().unwrap();
                if opcode == 0x240 {
                    assert!(forbidden.iter().any(|rule| rule["shift"] == 124));
                    assert_eq!(forbidden.len(), 1);
                } else {
                    assert!(forbidden.iter().any(|rule| rule["shift"] == 123));
                    assert!(forbidden.iter().any(|rule| rule["shift"] == 124));
                    assert_eq!(forbidden.len(), 2);
                }
            }
        }
    }
}
