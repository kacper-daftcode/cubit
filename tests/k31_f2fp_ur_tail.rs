//! FlashKDA F2FP BF16 PACK_AB retaining the inert RC=0xff byte.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

#[test]
fn f2fp_ur_and_rc_survive_reencoding() {
    let mut census = 0u64;
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_f2fp_ur_tail_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["arch"] != target { continue; }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor}"));
            assert_eq!(decoded.key, "F2FP_R_R_UR");
            assert_eq!(decoded.mod_group, "BF16,F32,PACK_AB");
            assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{arch}: {word:032x}");
            let ctrl = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let lossless = cubit::printer::to_sass_lossless(&decoded);
            let source = format!("[{ctrl}] {lossless} ;");
            cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
            let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
            assert_eq!(cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|e| panic!("{source}: {e}")), word, "{source}");
            if arch == "sm100a" { census += row["occurrences"].as_u64().unwrap(); }
        }
    }
    assert_eq!(census, 4);
}

#[test]
fn rc_ff_is_fixed_not_a_missing_field() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"]["k31-f2fp-pack-ur-inert-rc-2026-11-07"]["rows"], 1);
        let group = &raw["instructions"]["F2FP_R_R_UR"]["mod_groups"]["BF16,F32,PACK_AB"];
        let and_base = u128::from_str_radix(group["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        let mask = u128::from_str_radix(group["variable_mask"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        assert_eq!((and_base >> 64) & 0xff, 0xff);
        assert_eq!((mask >> 64) & 0xff, 0);
        assert!(!group["claim_forbid"].as_array().unwrap().is_empty());
        assert!(!group["fields"].as_array().unwrap().iter().any(|f| f["shift"] == 64));
    }
}
