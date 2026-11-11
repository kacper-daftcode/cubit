//! Exact FlashKDA UTMALDG, UBLKCP and F2FP residue on current main.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

fn key(kind: &str) -> &'static str {
    match kind {
        "utmaldg" => "UTMALDG_AURI_AURI_II",
        "ublkcp" => "UBLKCP.G.S_AURI_AURI_UR",
        "f2fp" => "F2FP_R_R_UR",
        other => panic!("unknown kind {other}"),
    }
}

#[test]
fn vendor_witnesses_decode_and_reencode_exactly() {
    let mut occurrences = BTreeMap::new();
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_flashkda_residue_nvdisasm.jsonl").lines() {
            let record: Value = serde_json::from_str(line).unwrap();
            if record["arch"] != target { continue; }
            let kind = record["kind"].as_str().unwrap();
            let vendor = record["nvidia_sass"].as_str().unwrap();
            let word = u128::from_str_radix(record["word"].as_str().unwrap(), 16).unwrap();
            let decoded = index.decode(word, 0, &table)
                .unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor}"));
            assert_eq!(decoded.key, key(kind));
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{arch}: {word:032x}");
            let ctrl = cubit::scheduling::format_control_code(
                &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let source = format!("[{ctrl}] {vendor} ;");
            cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
            let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
            assert_eq!(cubit::encoder::encode_instruction(&parsed, &table)
                .unwrap_or_else(|e| panic!("{source}: {e}")), word, "{source}");
            if arch == "sm100a" {
                *occurrences.entry(kind.to_string()).or_insert(0u64) +=
                    record["occurrences"].as_u64().unwrap();
            }
        }
    }
    assert_eq!(occurrences["utmaldg"], 388);
    assert_eq!(occurrences["ublkcp"], 24);
    assert_eq!(occurrences["f2fp"], 4);
}

#[test]
fn new_rows_have_closed_fields_and_f2fp_keeps_its_refusals() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        let utma = &raw["instructions"]["UTMALDG_AURI_AURI_II"]["mod_groups"]["1D"];
        assert_eq!(utma["variable_mask"], "0x00000000000000000000ffffff00f000");
        assert_eq!(utma["fields"].as_array().unwrap().len(), 4);
        let ublkcp = &raw["instructions"]["UBLKCP.G.S_AURI_AURI_UR"]["mod_groups"][""];
        assert_eq!(ublkcp["and_base"], "0x000000000800040000000000000003ba");
        assert_eq!(ublkcp["variable_mask"], "0x00000000000000ff000000ffff00f000");
        assert_eq!(ublkcp["fields"].as_array().unwrap().len(), 4);
        let f2fp = &raw["instructions"]["F2FP_R_R_UR"]["mod_groups"]["BF16,F32,PACK_AB"];
        assert_eq!(u128::from_str_radix(&f2fp["and_base"].as_str().unwrap()[2..], 16).unwrap()
            & (0xffu128 << 64), 0xffu128 << 64);
        // The inert RC byte is baked in and_base and stays outside the mask (no constant bit under the mask).
        let mask = u128::from_str_radix(&f2fp["variable_mask"].as_str().unwrap()[2..], 16).unwrap();
        assert_eq!(mask, 0x00000000f11000003ffffffffffff000u128);
        assert_eq!(mask & (0xffu128 << 64), 0, "{arch}: the RC byte must not be under the mask");
        assert_eq!(f2fp["claim_forbid"].as_array().unwrap().len(), 5);
    }
}

#[test]
fn utmaldg_1d_does_not_claim_its_reserved_bits() {
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        let base = 0x5b4u128 | (1 << 76) | (1 << 91) | (6 << 40) | (32 << 32) | (52 << 24);
        for shift in (16..=23).chain(48..=63).chain(72..=75).chain(77..=78)
            .chain(82..=83).chain(86..=90) {
            let decoded = index.decode(base | (1u128 << shift), 0, &table);
            assert!(decoded.map_or(true, |d| d.key != "UTMALDG_AURI_AURI_II" || d.mod_group != "1D"),
                "{arch}: UTMALDG.1D descriptor unexpectedly claims bit {shift}");
        }
    }
}
