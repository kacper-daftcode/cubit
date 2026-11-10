//! Production-anchored FHFMA.BF16 fields, render/encoding and boundary.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const KEY: &str = "FHFMA_R_R_R_R";
const SRC: &str = "hidden-b300-fhfma-bf16-2026-11-08";
/// The text-inert bits of the measured lattice: [61:40], 76, 80, [90:85], [95:92]. The candidate carried each as a
/// one-bit field without an extraction, so a word with such a bit set decoded to the text of the word without it. On
/// `main` the rows fail closed on them, as every measured row of these tables does (session T-26, 2026-11-10,
/// blackwell-isa 3a30f62): the 472 fixture words the candidate adopted with such a bit set are refused, and every
/// other adopted word -- the 389 production words included -- re-assembles to itself.
const TEXT_INERT: u128 = (0x3f_ffff_u128 << 40) | (1 << 76) | (1 << 80) | (0x3f_u128 << 85) | (0xf_u128 << 92);

#[test]
fn fixture_render_encode_and_negatives() {
    let mut adopted = 0;
    let mut production = 0;
    let mut exact = 0;
    let mut negatives = 0;
    let mut inert_refused = 0;
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in hb300_fixture("sm103_fhfma_bf16_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str();
            if row["adopt"] == true && word & TEXT_INERT != 0 {
                assert_ne!(row["encode_exact"], true, "{arch}: {word:032x}");
                assert!(index.decode(word, 0, &table).is_err(),
                    "{arch}: a word with a text-inert bit set must fail closed {word:032x}");
                inert_refused += 1;
            } else if row["adopt"] == true {
                adopted += 1;
                let decoded = index.decode(word, 0, &table)
                    .unwrap_or_else(|error| panic!("{arch}: {word:032x}: {error}: {vendor:?}"));
                assert_eq!(decoded.key, KEY, "{arch}: witness {word:032x}");
                let rendered = cubit::printer::to_sass_lossless(&decoded);
                assert_eq!(rendered.trim(), vendor.unwrap().trim(), "{arch}: render {word:032x}");
                if row["kind"] == "H-production" {
                    production += 1;
                }
                {
                    let ctrl = cubit::scheduling::format_control_code(
                        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
                    let source = format!("[{ctrl}] {rendered} ;");
                    let parsed = cubit::parse_cuasm_line(&source, 0)
                        .unwrap_or_else(|error| panic!("{arch}: parse {source}: {error}"));
                    let encoded = cubit::encoder::encode_instruction(&parsed, &table)
                        .unwrap_or_else(|error| panic!("{arch}: encode {source}: {error}"));
                    assert_eq!(encoded, word, "{arch}: exact encoding {word:032x}");
                    exact += 1;
                }
            } else if vendor.is_none() {
                assert!(index.decode(word, 0, &table).is_err(),
                    "{arch}: unnamed/illegal must stay unclaimed {word:032x}");
                negatives += 1;
            } else if vendor.unwrap().starts_with("FHFMA") {
                assert!(index.decode(word, 0, &table).is_err(),
                    "{arch}: other FHFMA form must stay unclaimed {word:032x}");
                negatives += 1;
            }
        }
        for invalid in [
            "FHFMA R1, R2, R3, R4 ;",
            "FHFMA.BF16.FTZ R1, R2, R3, R4 ;",
            "FHFMA.BF16.FMZ R1, R2, R3, R4 ;",
            "FHFMA.BF16 R1, R2.INVALID3, R3, R4 ;",
        ] {
            assert!(cubit::encoder::encode_instruction(
                &cubit::parse_cuasm_line(invalid, 0).unwrap(), &table).is_err(), "{arch}: {invalid}");
        }
    }
    assert_eq!(production, 778);
    assert_eq!((adopted, exact, inert_refused), (1418, 1418, 944));
    assert!(negatives >= 60, "negatives={negatives}");
}

#[test]
fn measured_fields_and_provenance() {
    let mut production = 0;
    for line in hb300_fixture("sm103_fhfma_bf16_nvdisasm.jsonl").lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        production += usize::from(row["kind"] == "H-production");
    }
    assert_eq!(production, 389);
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 8);
        let entry = &raw["instructions"][KEY];
        assert_eq!(entry["base_op"], "FHFMA");
        assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 8);
        for (modifiers, bit) in [("BF16", 0), ("BF16,SAT", 77), ("BF16,RM", 78),
            ("BF16,RP", 79), ("BF16,RM,SAT", 0), ("BF16,RP,SAT", 0),
            ("BF16,RZ", 0), ("BF16,RZ,SAT", 0)] {
            let row = &entry["mod_groups"][modifiers];
            assert_eq!(row["_src"], SRC);
            let base = u128::from_str_radix(row["and_base"].as_str().unwrap()
                .trim_start_matches("0x"), 16).unwrap();
            assert_eq!(base & 0xfff, 0x223);
            assert_eq!(base & (3u128 << 81), 3u128 << 81);
            if bit > 0 { assert_ne!(base & (1u128 << bit), 0); }
            for (shift, bits, extraction, token) in [
                (12, 4, "guard", 0), (24, 8, "reg", 2), (83, 1, "opmod:H1", 2),
                (62, 1, "abs", 3), (84, 1, "opmod:H1", 3), (74, 1, "abs", 4),
                (75, 1, "neg", 4), (122, 1, "reuse", 2), (124, 1, "reuse", 4),
                (76, 0, "", 2), (80, 0, "", 2), (91, 0, "", 2),
                (85, 0, "", 2), (90, 0, "", 2), (95, 0, "", 2),
            ] {
                if bits == 0 {
                    // no field on a text-inert bit (nor on 91), and none without an extraction
                    assert!(row["fields"].as_array().unwrap().iter()
                        .all(|field| field["shift"] != shift && field["extraction"] != ""));
                    let mask = u128::from_str_radix(row["variable_mask"].as_str().unwrap()
                        .trim_start_matches("0x"), 16).unwrap();
                    assert_eq!(mask & TEXT_INERT, 0);
                } else {
                    assert!(row["fields"].as_array().unwrap().iter().any(|field|
                        field["shift"] == shift && field["bits"] == bits
                        && field["extraction"] == extraction && field["token_idx"] == token));
                }
            }
        }
    }
}
