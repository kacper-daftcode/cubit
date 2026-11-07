//! Measurement-backed BRXU UR-relative offset form.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

#[test]
fn brxu_witnesses_round_trip() {
    let mut census = 0;
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_brxu_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["arch"] != target { continue; }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor}"));
            assert_eq!(decoded.key, "BRXU_UR_II");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{arch}: {word:032x}");
            let ctrl = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let source = format!("[{ctrl}] {vendor} ;");
            cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
            let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
            assert_eq!(cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|e| panic!("{source}: {e}")), word, "{source}");
            if arch == "sm100a" { census += row["occurrences"].as_u64().unwrap(); }
        }
    }
    assert_eq!(census, 13);
}

#[test]
fn dword_split_fields_are_measured() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"]["k31-brxu-register-offset-2026-11-07"]["rows"], 1);
        assert_eq!(raw["_meta"]["key_aliases"]["BRXU_L"], "BRXU_UR_II");
        assert!(raw["instructions"]["BRXU_L"].is_null());
        let entry = &raw["instructions"]["BRXU_UR_II"]["mod_groups"][""];
        assert!(entry["fields"].as_array().unwrap().iter().any(|f| f["shift"] == 16 && f["extraction"] == "imm_shr2"));
        assert!(entry["fields"].as_array().unwrap().iter().any(|f| f["shift"] == 34 && f["bits"] == 48 && f["extraction"] == "imm_shr10"));
        assert!(entry["fields"].as_array().unwrap().iter().any(|f| f["shift"] == 24 && f["extraction"] == "ureg"));
    }
}
