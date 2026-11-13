//! Measured F2FP.BF16.E2M1 reuse/byte-selector text; no GPU execution.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

struct Arch {
    table: IsaTable,
    index: DecodeIndex,
    rows: Vec<Value>,
}

fn arches() -> Vec<Arch> {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_f2fp_bf16_e2m1_reuse_selector_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_f2fp_bf16_e2m1_reuse_selector_nvdisasm.jsonl"),
        ),
    ]
    .into_iter()
    .map(|(name, fixture)| {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{name}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        let rows = fixture
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        Arch { table, index, rows }
    })
    .collect()
}

fn word(row: &Value) -> u128 {
    u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap()
}

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let ctrl = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{ctrl}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

#[test]
fn production_reuse_byte_selectors_roundtrip_all_188_words() {
    for arch in arches() {
        let mut count = 0;
        for row in arch
            .rows
            .iter()
            .filter(|row| row["generation"] == "production")
        {
            let word = word(row);
            let decoded = arch.index.decode(word, 0, &arch.table).unwrap();
            assert_eq!(
                (decoded.key.as_str(), decoded.mod_group.as_str()),
                ("F2FP_R_R_R", "BF16,E2M1,UNPACK_B")
            );
            let text = row["nvidia_sass"].as_str().unwrap();
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                text,
                "{word:032x}"
            );
            assert_eq!(cubit::printer::to_sass(&decoded), text, "{word:032x}");
            assert_eq!(
                encode(&arch.table, word, text),
                word & !(7u128 << 125),
                "{word:032x}"
            );
            count += 1;
        }
        assert_eq!(count, 188);
    }
}

#[test]
fn all_decodable_measured_selector_register_and_reuse_positives_roundtrip() {
    for arch in arches() {
        let mut count = 0;
        for row in arch
            .rows
            .iter()
            .filter(|row| row["test_role"] == "encoder_regression")
        {
            let word = word(row);
            let decoded = arch.index.decode(word, 0, &arch.table).unwrap();
            assert_eq!(
                (decoded.key.as_str(), decoded.mod_group.as_str()),
                ("F2FP_R_R_R", "BF16,E2M1,UNPACK_B"),
                "{word:032x}"
            );
            let text = row["nvidia_sass"].as_str().unwrap();
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                text,
                "{word:032x}"
            );
            assert_eq!(
                encode(&arch.table, word, text),
                word & !(7u128 << 125),
                "{} {word:032x}",
                row["label"]
            );
            count += 1;
        }
        assert_eq!(count, 4534);
    }
}

#[test]
fn invalid_reuse_selector_suffixes_and_scoped_negatives_stay_closed() {
    for arch in arches() {
        for text in [
            "F2FP.BF16.E2M1.UNPACK_B R8, R17.reuse.B4, R99.reuse.reuse.B0 ;",
            "F2FP.BF16.E2M1.UNPACK_B R8, R17.reuse.reuse, R99.reuse.B0 ;",
            "F2FP.BF16.E2M1.UNPACK_B R8, R17.reuse.B1.B2, R99.reuse.B0 ;",
            "F2FP.BF16.E2M1.UNPACK_B R8, R17.reuse.B1.reuse.B2, R99.reuse.B0 ;",
            "F2FP.BF16.E2M1.UNPACK_B R8, R17.reuse.B1.NP, R99.reuse.B0 ;",
            "F2FP.BF16.E2M1.UNPACK_B R8, R17.reuse.H1, R99.reuse.B0 ;",
            "F2FP.BF16.E2M1.UNPACK_B R8, R17.reuse.B1, R99.reuse ;",
            "F2FP.BF16.E2M1.UNPACK_B R8, R17.reuse.B4, R99.reuse.B0 ;",
            "F2FP.BF16.E2M1.UNPACK_B R8, R17.reuse.reuse, R99.reuse.B0 ;",
            "F2FP.BF16.E2M3.UNPACK_B R8, R17.reuse.B1, R99.reuse.B0 ;",
        ] {
            assert!(
                cubit::encoder::encode_instruction(
                    &cubit::parse_cuasm_line(text, 0).unwrap(),
                    &arch.table
                )
                .is_err(),
                "{text}"
            );
        }
        let mut negative = 0;
        for row in arch.rows.iter().filter(|row| row["kind"] == "negative") {
            assert!(
                arch.index.decode(word(row), 0, &arch.table).is_err(),
                "{} invalid overmatch {word:032x}",
                row["label"],
                word = word(row)
            );
            negative += 1;
        }
        assert_eq!(negative, 16);
    }
}

#[test]
fn existing_scaled_unpack_row_and_selector_fields_remain_unchanged() {
    for name in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{name}.json")))
                .unwrap(),
        )
        .unwrap();
        let key = &raw["instructions"]["F2FP_R_R_R"];
        assert_eq!(key["mod_groups"].as_object().unwrap().len(), 27);
        let fields = key["mod_groups"]["BF16,E2M1,UNPACK_B"]["fields"]
            .as_array()
            .unwrap();
        for (shift, token, extraction) in [
            (72, 2, "f2fp_ra_b1"),
            (88, 2, "f2fp_ra_b2"),
            (123, 2, "reuse"),
            (124, 3, "reuse"),
            (24, 3, "f2fp_scale_sel"),
        ] {
            assert!(
                fields.iter().any(|field| field["shift"] == shift
                    && field["token_idx"] == token
                    && field["extraction"] == extraction),
                "{shift}"
            );
        }
    }
}
