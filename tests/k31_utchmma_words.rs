//! Full production UTCHMMA witnesses from FlashMLA.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

#[test]
fn all_utchmma_witnesses_round_trip() {
    let mut census = 0u64;
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_utchmma_words_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{word:032x}: {e}: {vendor}"));
            let text = cubit::printer::to_sass_lossless(&decoded);
            assert_eq!(text, vendor, "{word:032x}: {}", decoded.key);
            let ctrl = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let source = format!("[{ctrl}] {vendor} ;");
            cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
            let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
            assert_eq!(cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|e| panic!("{source}: {e}")), word, "{source}");
            if arch == "sm100a" { census += row["occurrences"].as_u64().unwrap(); }
        }
    }
    assert_eq!(census, 757);
}

#[test]
fn descriptor_and_predicate_measurement_are_registered() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"]["k31-utchmma-descriptor-kinds-2026-11-07"]["rows"], 2);
        let entry = &raw["instructions"]["UTCHMMA_II_II_II_II_II_UP"];
        assert!(entry["mod_groups"]["WS"]["fields"].as_array().unwrap().iter().any(|f| f["token_idx"] == 1 && f["shift"] == 24 && f["extraction"] == "tdesc_ur"));
        assert!(entry["mod_groups"]["WS"]["fields"].as_array().unwrap().iter().any(|f| f["shift"] == 10 && f["extraction"] == "dsel2"));
        let cta = entry["mod_groups"]["2CTA"]["fields"].as_array().unwrap();
        assert!(cta.iter().any(|f| f["token_idx"] == 6 && f["shift"] == 87 && f["bits"] == 3 && f["extraction"] == "pred"));
        assert!(cta.iter().any(|f| f["token_idx"] == 6 && f["shift"] == 90 && f["bits"] == 1 && f["extraction"] == "neg"));
        assert!(!cta.iter().any(|f| f["token_idx"] == 6 && f["bits"] == 4));
    }
}
