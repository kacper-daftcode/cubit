//! The five remaining FlashMLA forms after LDG and BRXU.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

#[test]
fn every_mla_tail_word_round_trips() {
    let mut census = std::collections::BTreeMap::new();
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_mla_tail_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["arch"] != target { continue; }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap().replace(" ,", ",");
            let op = row["op"].as_str().unwrap().to_owned();
            let decoded = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor}"));
            let (key, group) = match op.as_str() {
                "FADD" => ("FADD_R_R_FI", "FTZ"),
                "FMUL" => ("FMUL_R_R_UR", ""),
                "FMNMX" => ("FMNMX_R_R_FI_P", "FTZ"),
                "UPLOP3" => ("UPLOP3.LUT_UP_UP_UP_UP_UP_II_II", ""),
                "BREAK" if vendor.contains("RELIABLE P") || vendor.contains("RELIABLE !P") => ("BREAK_P_B", "RELIABLE"),
                "BREAK" => ("BREAK_B", "RELIABLE"),
                other => panic!("unexpected op {other}"),
            };
            assert_eq!((decoded.key.as_str(), decoded.mod_group.as_str()), (key, group), "{vendor}");
            assert_eq!(cubit::printer::to_sass(&decoded).replace(" ,", ","), vendor, "{arch}: {word:032x}");
            let ctrl = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let lossless = cubit::printer::to_sass_lossless(&decoded);
            let source = format!("[{ctrl}] {lossless} ;");
            cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
            let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
            assert_eq!(cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|e| panic!("{source}: {e}")), word, "{source}");
            if arch == "sm100a" { *census.entry(op.clone()).or_insert(0u64) += row["occurrences"].as_u64().unwrap(); }
        }
    }
    for (op, count) in [("FADD", 8), ("FMUL", 14), ("FMNMX", 1), ("UPLOP3", 16), ("BREAK", 1)] {
        assert_eq!(census[op], count, "{op}");
    }
}

#[test]
fn five_measured_rows_and_uplop_alias_are_registered() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"]["k31-flashmla-tail-2026-11-07"]["rows"], 5);
        assert_eq!(raw["_meta"]["key_aliases"]["UPLOP3_UP_UP_UP_UP_UP_II_II"], "UPLOP3.LUT_UP_UP_UP_UP_UP_II_II");
        assert!(raw["instructions"].get("UPLOP3_UP_UP_UP_UP_UP_II_II").is_none());
        let up = raw["instructions"]["UPLOP3.LUT_UP_UP_UP_UP_UP_II_II"]["mod_groups"][""]["fields"].as_array().unwrap();
        for (shift, extraction) in [(81, "upred"), (84, "upred"), (87, "upred"), (64, "imm"), (72, "imm_shr3")] {
            assert!(up.iter().any(|f| f["shift"] == shift && f["extraction"] == extraction));
        }
        let br = raw["instructions"]["BREAK_P_B"]["mod_groups"]["RELIABLE"]["fields"].as_array().unwrap();
        for (shift, extraction) in [(12, "guard"), (16, "barrier"), (87, "pred"), (90, "neg")] {
            assert!(br.iter().any(|f| f["shift"] == shift && f["extraction"] == extraction));
        }
        let fadd = raw["instructions"]["FADD_R_R_FI"]["mod_groups"]["FTZ"]["fields"].as_array().unwrap();
        assert!(fadd.iter().any(|f| f["shift"] == 32 && f["bits"] == 32 && f["extraction"] == "f32"));
        assert!(raw["instructions"]["FMUL_R_R_UR"]["mod_groups"][""]["fields"].as_array().unwrap().iter().any(|f| f["shift"] == 63 && f["extraction"] == "neg"));
    }
}
