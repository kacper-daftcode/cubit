//! Scalar packed-FP32 operands and FFMA2's fourth-operand lane selector.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const SRC: &str = "k31-packed-scalar-fp32-2026-11-07";

#[test]
fn every_scalar_witness_round_trips() {
    let mut counts = std::collections::BTreeMap::new();
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_fp32_scalar_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["arch"] != target {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(word, 0, &table)
                .unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor}"));
            let text = cubit::printer::to_sass_lossless(&decoded);
            assert_eq!(text, vendor, "{arch}: {word:032x}: {}", decoded.key);
            let ctrl = cubit::scheduling::format_control_code(
                &cubit::scheduling::decode_sched_upper32((word >> 96) as u32),
            );
            let source = format!("[{ctrl}] {vendor} ;");
            cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
            let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
            assert_eq!(
                cubit::encoder::encode_instruction(&parsed, &table)
                    .unwrap_or_else(|e| panic!("{source}: {e}")),
                word,
                "{source}"
            );
            if row["occurrences"] != 0 {
                *counts
                    .entry(row["op"].as_str().unwrap().to_owned())
                    .or_insert(0u64) += row["occurrences"].as_u64().unwrap();
            }
        }
    }
    assert_eq!(counts["FMUL2"], 1432);
    assert_eq!(counts["FFMA2"], 1856);
}

#[test]
fn scalar_rows_are_measured_and_preserve_original_fields() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 3);
        let ins = raw["instructions"].as_object().unwrap();
        for key in ["FMUL2_R_R_R", "FFMA2_R_R_R_R", "FFMA2_R_R_UR_R"] {
            assert_eq!(ins[key]["_src"], SRC);
            let fields = ins[key]["mod_groups"][""]["fields"].as_array().unwrap();
            assert!(fields.iter().all(|f| f["_src"] == SRC));
            assert!(
                fields.iter().any(|f| f["token_idx"] == 4
                    && f["shift"] == 85
                    && f["extraction"] == "opmod:F32")
                    || key == "FMUL2_R_R_R"
            );
        }
        let fmul = &ins["FMUL2_R_R_R"]["mod_groups"][""]["fields"];
        assert!(fmul
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["token_idx"] == 3 && f["shift"] == 32 && f["extraction"] == "reg"));
        assert!(fmul
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["token_idx"] == 3 && f["shift"] == 88 && f["extraction"] == "opmod:F32"));
        assert!(!fmul
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["token_idx"] == 3 && f["shift"] == 64 && f["extraction"] == "reg"));
        assert!(ins["FMUL2_R_R_FI"]["_src"] == "k31-packed-fp32-2026-11-07");
        assert!(ins["FMUL2_R_R_UR"]["_src"] == "k31-packed-fp32-2026-11-07");
        let ffma = ins["FFMA2_R_R_R_R"]["mod_groups"][""]["fields"]
            .as_array()
            .unwrap();
        assert!(ffma
            .iter()
            .any(|f| f["token_idx"] == 3 && f["shift"] == 88 && f["extraction"] == "opmod:F32"));
        assert!(!ffma.iter().any(|f| f["token_idx"] == 2 && f["shift"] == 88));
    }
}
