//! FlashKDA MOVM.16.MT88 register form.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

#[test]
fn movm_witnesses_round_trip() {
    let mut census = 0u64;
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_movm_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["arch"] != target { continue; }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor}"));
            assert_eq!(decoded.key, "MOVM.16.MT88_R_R");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{arch}: {word:032x}");
            let ctrl = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let source = format!("[{ctrl}] {vendor} ;");
            cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
            let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
            assert_eq!(cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|e| panic!("{source}: {e}")), word, "{source}");
            if arch == "sm100a" { census += row["occurrences"].as_u64().unwrap(); }
        }
    }
    assert_eq!(census, 7712);
}

#[test]
fn movm_has_measured_guard_and_register_fields() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"]["k31-movm16-mt88-2026-11-07"]["rows"], 1);
        let form = &raw["instructions"]["MOVM.16.MT88_R_R"]["mod_groups"][""];
        // The returned six-form candidate left [95:32] open, adopting 534
        // vendor words whose text re-encoded differently. Keep this row closed.
        assert_eq!(form["and_base"], "0x0000000000000000000000000000023a");
        assert_eq!(form["variable_mask"], "0x000000000000000000000000fffff000");
        let fields = form["fields"].as_array().unwrap();
        for (shift, token) in [(12, 0), (16, 1), (24, 2)] {
            assert_eq!(fields.iter().filter(|f| f["shift"] == shift && f["token_idx"] == token).count(), 1);
        }
        assert_eq!(fields.len(), 3);
    }
}

#[test]
fn movm_reserved_band_is_not_claimed() {
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for shift in 32..=95 {
            let word = 0x23au128 | (1u128 << shift);
            let decoded = index.decode(word, 0, &table);
            assert!(decoded.map_or(true, |d| d.key != "MOVM.16.MT88_R_R"),
                "{arch}: reserved bit {shift} is claimed by MOVM.16.MT88_R_R");
        }
    }
}
