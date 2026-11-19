//! E2/L1a shared FP32x2 lane law; CPU/SASS witnesses only.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const ARCHES: [&str; 2] = ["sm103a", "sm100a"];
const FAMILIES: [&str; 13] = [
    "fadd2_lo_hi",
    "fadd2_hi_lo_rb_reuse",
    "fadd2_rur",
    "fmul2_rur",
    "fmul2_paired_ur",
    "fmul2_paired_order",
    "fmul2_rz_production",
    "ffma2_addend_ur",
    "ffma2_all_paired_b88",
    "ffma2_packed_b",
    "ffma2_r_scalar",
    "ffma2_scalar_a",
    "engine_l1_ffma2_legacy",
];

fn table(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}

fn hex(row: &Value) -> u128 {
    let text = row["word"]
        .as_str()
        .unwrap_or_else(|| row.as_str().unwrap());
    u128::from_str_radix(text.trim_start_matches("0x"), 16).unwrap()
}

fn expected_key(family: &str) -> &'static str {
    match family {
        "fadd2_lo_hi" | "fadd2_hi_lo_rb_reuse" => "FADD2_R_R_R",
        "fadd2_rur" => "FADD2_R_R_UR",
        "fmul2_rur" | "fmul2_paired_ur" => "FMUL2_R_R_UR",
        "fmul2_paired_order" | "fmul2_rz_production" => "FMUL2_R_R_R",
        "ffma2_addend_ur" => "FFMA2_R_R_R_UR",
        _ => "FFMA2_R_R_R_R",
    }
}

#[test]
fn retained_vendor_words_render_and_reencode_exactly() {
    let mut retained = 0;
    let mut invalid3 = 0;
    for arch in ARCHES {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        for family in FAMILIES {
            let fixture = hb300_fixture(&format!("{arch}_{family}_nvdisasm.jsonl"));
            let mut family_count = 0;
            for line in fixture.lines() {
                let row: Value = serde_json::from_str(line).unwrap();
                let adopted = row["role"] == "adopt"
                    || row["role"] == "legacy_bug234"
                    || row["generation"] == "production";
                if !adopted {
                    continue;
                }
                let word = hex(&row);
                let text = row["nvidia_sass"].as_str().unwrap();
                if text.contains(".INVALID3") {
                    assert!(
                        index.decode(word, 0, &table).is_err(),
                        "{arch}/{family}: INVALID3 must be refused"
                    );
                    invalid3 += 1;
                    continue;
                }
                let decoded = index.decode(word, 0, &table).unwrap_or_else(|error| {
                    panic!("{arch}/{family} {word:032x} {text}: decode failed: {error}")
                });
                assert_eq!(
                    decoded.key,
                    expected_key(family),
                    "{arch}/{family} {word:032x}"
                );
                assert_eq!(
                    cubit::printer::to_sass(&decoded),
                    text,
                    "{arch}/{family} {word:032x}"
                );
                assert_eq!(
                    cubit::printer::to_sass_lossless(&decoded),
                    text,
                    "{arch}/{family} {word:032x}"
                );
                let control = cubit::scheduling::format_control_code(
                    &cubit::scheduling::decode_sched_upper32((word >> 96) as u32),
                );
                let text = format!("[{control}] {text} ;");
                let parsed = cubit::parse_cuasm_line(&text, 0).expect("vendor text must parse");
                let encoded =
                    cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|error| {
                        panic!("{arch}/{family} {word:032x}: reencode failed: {error}")
                    });
                assert_eq!(
                    encoded,
                    word & !(7u128 << 125),
                    "{arch}/{family} {word:032x}"
                );
                retained += 1;
                family_count += 1;
            }
            assert!(
                family_count > 0,
                "{arch}/{family}: no retained vendor witness"
            );
        }
    }
    assert!(
        retained > 20_000,
        "law coverage must include both targets and every retained family"
    );
    assert_eq!(invalid3, 2, "one measured INVALID3 anchor per target");
}

#[test]
fn both_resolved_uniform_donors_share_one_row() {
    for arch in ARCHES {
        let t = table(arch);
        let t103 = t;
        for (text, scalar) in [
            ("FMUL2 R14, R14.F32x2.HI_LO, UR8.F32x2.HI_LO ;", false),
            ("FMUL2 R14, R14.F32x2.HI_LO, UR8.F32 ;", true),
        ] {
            let parsed = cubit::parse_cuasm_line(text, 0).unwrap();
            let word = cubit::encoder::encode_instruction(&parsed, &t103).unwrap();
            assert_eq!((word >> 88) & 1 != 0, scalar, "{arch}: {text}");
            let index = DecodeIndex::build(&t103);
            let decoded = index.decode(word, 0, &t103).unwrap();
            assert_eq!(decoded.key, "FMUL2_R_R_UR");
            assert_eq!(
                cubit::printer::to_sass(&decoded),
                text.trim_end_matches(" ;")
            );
        }
    }
}

#[test]
fn invalid_shapes_and_unowned_suffixes_are_refused() {
    for arch in ARCHES {
        let table = table(arch);
        for text in [
            "FMUL2 R14, R14.F32x2.LO_HI.INVALID3, UR8.F32 ;",
            "FMUL2 R14, R14.INVALID3.NP, UR8.F32 ;",
            "FMUL2 R14, R14.F32x2.HI_LO.HI_LO, UR8.F32 ;",
            "FMUL2 R14, R14.F32x2.HI_LO, UR8.F32.NP ;",
            "FADD2 R10, R2.F32x2.LO_HI, UR5.F32x2.HI_LO ;",
            "FFMA2 R6, R6.F32x2.HI_LO, R3.F32x2.LO_HI, R0.F32 ;",
            "FADD2 R10, R2.F32x2.LO_HI.GARBAGE, R5.F32 ;",
            "FFMA2 R6, R6.F32x2.HI_LO.NP, R3.F32, UR90.F32 ;",
        ] {
            let parsed = cubit::parse_cuasm_line(text, 0).unwrap();
            assert!(
                cubit::encoder::encode_instruction(&parsed, &table).is_err(),
                "{arch}: accepted {text}"
            );
        }
    }
}

#[test]
fn canonical_rows_have_clean_fields_and_provenance() {
    for arch in ARCHES {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        let instructions = raw["instructions"].as_object().unwrap();
        for key in [
            "FADD2_R_R_R_LO_HI",
            "FADD2_R_R_R_HI_LO",
            "FMUL2_R_R_R_LO_HI",
            "FFMA2_R_R_R_R_SCALAR_B_C",
            "FFMA2_R_R_R_R_PACKED_A_B_SCALAR_C",
            "FFMA2_R_R_R_R_SCALAR_A_PACKED_B",
        ] {
            assert!(
                !instructions.contains_key(key),
                "{arch}: synthetic key {key}"
            );
        }
        for (key, source) in [
            ("FADD2_R_R_R", "engine-l1a-fadd2-shapes-2026-11-13"),
            ("FADD2_R_R_UR", "engine-l1a-fadd2-ur-shape-2026-11-13"),
            ("FMUL2_R_R_R", "engine-l1a-fmul2-shapes-2026-11-13"),
            (
                "FMUL2_R_R_UR",
                "engine-l1a-fmul2-resolved-ur-shape-2026-11-13",
            ),
            ("FFMA2_R_R_R_R", "engine-l1a-ffma2-shapes-2026-11-13"),
            ("FFMA2_R_R_R_UR", "engine-l1a-ffma2-ur-shape-2026-11-13"),
        ] {
            let entry = &instructions[key];
            assert_eq!(entry["_src"], source, "{arch}/{key}");
            for (_, row) in entry["mod_groups"].as_object().unwrap() {
                let mask = row["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .fold(0u128, |mask, field| {
                        mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1)
                            << field["shift"].as_u64().unwrap())
                    });
                assert_eq!(hex(&row["variable_mask"]), mask, "{arch}/{key}");
                assert_eq!(
                    hex(&row["and_base"]) & mask,
                    0,
                    "{arch}/{key}: constant below a field"
                );
                assert!(row["count"].is_null(), "{arch}/{key}: stale row count");
            }
        }
        assert_eq!(
            instructions["FMUL2_R_R_R"]["mod_groups"]["RZ"]["count"],
            Value::Null
        );
        assert_eq!(
            raw["_meta"]["provenance"]["sources"]["engine-l1a-fmul2-shapes-2026-11-13"]["rows"],
            2
        );
        for key in ["FADD2_R_R_R", "FADD2_R_R_UR", "FMUL2_R_R_R", "FMUL2_R_R_UR"] {
            for (_, row) in instructions[key]["mod_groups"].as_object().unwrap() {
                assert!(row["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|field| field["shift"] != 74 && field["shift"] != 75));
                assert!(
                    row["claim_forbid"].as_array().unwrap().iter().any(|entry| {
                        entry["shift"] == 74
                            && entry["bits"] == 2
                            && entry["values"] == serde_json::json!([1, 2, 3])
                    }),
                    "{arch}/{key}: lossy [75:74] is not refused"
                );
            }
        }
        let rz = &instructions["FMUL2_R_R_R"]["mod_groups"]["RZ"];
        assert!(rz["fields"]
            .as_array()
            .unwrap()
            .iter()
            .all(|field| ![82, 87, 88].contains(&field["shift"].as_u64().unwrap())));
        assert_eq!(
            hex(&rz["and_base"]) & ((1u128 << 82) | (1u128 << 87) | (1u128 << 88)),
            1u128 << 88
        );
        let ffma_ur = &instructions["FFMA2_R_R_R_UR"]["mod_groups"][""];
        assert!(ffma_ur["fields"]
            .as_array()
            .unwrap()
            .iter()
            .all(|field| ![85, 88].contains(&field["shift"].as_u64().unwrap())));
        assert_eq!(
            hex(&ffma_ur["and_base"]) & ((1u128 << 85) | (1u128 << 88)),
            (1u128 << 85) | (1u128 << 88)
        );
    }
}
