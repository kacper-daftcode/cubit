//! Small LDG.NA[.64].CONSTANT forms.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

#[test]
fn small_constants_round_trip() {
    let mut census = 0u64;
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_ldg_constants_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["arch"] != target { continue; }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor}"));
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{arch}: {word:032x}");
            let ctrl = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let source = format!("[{ctrl}] {vendor} ;");
            cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
            let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
            if arch == "sm103a" && ((word >> 24) & 1) == 1 {
                let error = cubit::encoder::encode_instruction(&parsed, &table).expect_err("BUG-077 odd true desc pair on sm_103a");
                assert!(error.to_string().contains("BUG-077"));
                continue;
            }
            assert_eq!(cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|e| panic!("{source}: {e}")), word, "{source}");
            if arch == "sm100a" { census += row["occurrences"].as_u64().unwrap(); }
            if arch == "sm103a" { census += row["occurrences"].as_u64().unwrap(); }
        }
    }
    assert_eq!(census, 30);
}

#[test]
fn one_destination_and_one_scaled_offset_are_registered() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"]["k31-ldg-small-constants-2026-11-07"]["rows"], 2);
        for key in ["LDG.E.NA.CONSTANT_R_dARI", "LDG.E.NA.64.CONSTANT_R_dARI"] {
            let fields = &raw["instructions"][key]["mod_groups"][""]["fields"].as_array().unwrap();
            assert!(fields.iter().any(|f| f["shift"] == 16 && f["token_idx"] == 1 && f["extraction"] == "reg"));
            assert!(fields.iter().any(|f| f["shift"] == 32 && f["token_idx"] == 2 && f["extraction"] == "sub_ur0"));
            assert!(!fields.iter().any(|f| f["token_idx"] == 1 && f["shift"] == 64));
            assert!(fields.iter().any(|f| f["shift"] == 40 && f["token_idx"] == 2 && f["bits"] == 17 && f["extraction"] == "sub_imm2_shr0u"));
        }
    }
}
