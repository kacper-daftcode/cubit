//! FlashKDA FMUL.FTZ.D2 and predicated FFMA.FTZ tail forms.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

#[test]
fn alu_tail_round_trips() {
    let mut census = std::collections::BTreeMap::new();
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_alu_tail_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["arch"] != target { continue; }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let op = row["op"].as_str().unwrap().to_owned();
            let decoded = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor}"));
            let key = if op == "FMUL" { "FMUL_R_R_R" } else { "FFMA_R_R_R_R" };
            let group = if op == "FMUL" { "D2,FTZ" } else { "FTZ" };
            assert_eq!((decoded.key.as_str(), decoded.mod_group.as_str()), (key, group), "{vendor}");
            // NVIDIA suppresses reuse when scheduling yield is clear. The
            // lossless editable path below intentionally retains those bits.
            assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{arch}: {word:032x}");
            let ctrl = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let lossless = cubit::printer::to_sass_lossless(&decoded);
            let source = format!("[{ctrl}] {lossless} ;");
            cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
            let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
            assert_eq!(cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|e| panic!("{source}: {e}")), word, "{source}");
            if arch == "sm100a" { *census.entry(op.clone()).or_insert(0u64) += row["occurrences"].as_u64().unwrap(); }
        }
    }
    assert_eq!(census["FMUL"], 64);
    assert_eq!(census["FFMA"], 164);
}

#[test]
fn full_sign_and_guard_fields_are_registered() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"]["k31-flashkda-alu-tail-2026-11-07"]["rows"], 2);
        for (key, group) in [("FMUL_R_R_R", "D2,FTZ"), ("FFMA_R_R_R_R", "FTZ")] {
            let fields = raw["instructions"][key]["mod_groups"][group]["fields"].as_array().unwrap();
            assert!(fields.iter().any(|f| f["shift"] == 12 && f["extraction"] == "guard"));
            assert!(fields.iter().any(|f| f["shift"] == 63 && f["extraction"] == "neg"));
            assert!(fields.iter().any(|f| f["shift"] == 72 && f["extraction"] == "neg"));
            assert!(fields.iter().any(|f| f["shift"] == 123 && f["extraction"] == "reuse"));
        }
    }
}
