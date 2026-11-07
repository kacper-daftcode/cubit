//! FHFMA.BF16 production form and four-register sign/reuse geometry.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

#[test]
fn fhfma_witnesses_round_trip() {
    let mut census = std::collections::BTreeMap::new();
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_fhfma_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["arch"] != target { continue; }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor}"));
            assert!(matches!(decoded.key.as_str(), "FHFMA.BF16_R_R_R_R" | "FHFMA.BF16.H1_R_R_R_R"));
            assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{arch}: {word:032x}");
            let ctrl = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let source = format!("[{ctrl}] {} ;", cubit::printer::to_sass_lossless(&decoded));
            cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
            let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
            assert_eq!(cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|e| panic!("{source}: {e}")), word, "{source}");
            *census.entry(target).or_insert(0u64) += row["occurrences"].as_u64().unwrap();
        }
    }
    assert_eq!(census["SM100"], 2560);
    assert_eq!(census["SM103"], 0);
}

#[test]
fn fhfma_has_one_fully_measured_row() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"]["k31-fhfma-bf16-flashmla-2026-11-07"]["rows"], 2);
        let row = &raw["instructions"]["FHFMA.BF16_R_R_R_R"];
        assert_eq!(row["_src"], "k31-fhfma-bf16-flashmla-2026-11-07");
        assert_eq!(row["base_op"], "FHFMA.BF16");
        assert_eq!(row["operand_sig"], "R_R_R_R");
        let fields = row["mod_groups"][""]["fields"].as_array().unwrap();
        for (token, neg, abs, reuse) in [(2, 72, 73, 122), (3, 63, 62, 123), (4, 75, 74, 124)] {
            assert!(fields.iter().any(|f| f["token_idx"] == token && f["shift"] == neg && f["extraction"] == "neg"));
            assert!(fields.iter().any(|f| f["token_idx"] == token && f["shift"] == abs && f["extraction"] == "abs"));
            assert!(fields.iter().any(|f| f["token_idx"] == token && f["shift"] == reuse && f["extraction"] == "reuse"));
        }
        let h1 = &raw["instructions"]["FHFMA.BF16.H1_R_R_R_R"]["mod_groups"][""]["fields"];
        assert!(h1.as_array().unwrap().iter().any(|f| f["token_idx"] == 2 && f["shift"] == 83 && f["extraction"] == "opmod:H1"));
        assert!(h1.as_array().unwrap().iter().any(|f| f["token_idx"] == 3 && f["shift"] == 84 && f["extraction"] == "opmod:H1"));
    }
}
