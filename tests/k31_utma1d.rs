//! FlashKDA UTMALDG.1D with its explicit descriptor operand.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

#[test]
fn utma1d_witnesses_round_trip() {
    let mut census = 0u64;
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_utma1d_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["arch"] != target { continue; }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor}"));
            assert_eq!(decoded.key, "UTMALDG_AURI_AURI_II");
            assert_eq!(decoded.mod_group, "1D");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{arch}: {word:032x}");
            let ctrl = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let source = format!("[{ctrl}] {vendor} ;");
            cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
            let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
            assert_eq!(cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|e| panic!("{source}: {e}")), word, "{source}");
            if arch == "sm100a" { census += row["occurrences"].as_u64().unwrap(); }
        }
    }
    assert_eq!(census, 388);
}

#[test]
fn utma1d_preserves_other_dimension_rows() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"]["k31-utma1d-flashkda-2026-11-07"]["rows"], 1);
        let groups = raw["instructions"]["UTMALDG_AURI_AURI_II"]["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), 11);
        let fields = groups["1D"]["fields"].as_array().unwrap();
        for (shift, token, extraction) in [(32, 1, "sub_ur0"), (24, 2, "sub_ur0"), (40, 3, "desc_ur")] {
            assert!(fields.iter().any(|f| f["shift"] == shift && f["token_idx"] == token && f["extraction"] == extraction));
        }
        for group in ["2D", "3D", "4D", "5D", "2D,GATHER4", "2CTA,2D,GATHER4", "2CTA,5D"] {
            assert!(groups.contains_key(group));
        }
    }
}
