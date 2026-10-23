//! SM120 CS2UR operand fields measured with nvdisasm 13.1 (tools/re_sm120_cs2ur.py).
//! Every swept word (uniform guard, URd incl. URZ, all 256 system registers,
//! plain and .32) decodes to NVIDIA's text and that text reassembles all 128 bits.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

fn table() -> IsaTable {
    let path = std::env::var_os("CUBIT_TABLE").map(std::path::PathBuf::from)
        .unwrap_or_else(|| "tables/sm120.json".into());
    IsaTable::load(&path).unwrap()
}

fn check(table: &IsaTable, index: &DecodeIndex, word: u128, vendor: &str) {
    let decoded = index.decode(word, 0, table).unwrap();
    let own = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(own, vendor, "{word:032x}");
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let source = format!("[{control}] {vendor} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    assert!(parsed.hand_sched && parsed.rsd.is_none());
    assert_eq!(cubit::encoder::encode_instruction(&parsed, table).unwrap(), word, "{source}");
}

#[test]
fn every_probed_cs2ur_word_matches_nvidia_and_reassembles_all_128_bits() {
    let table = table();
    let index = DecodeIndex::build(&table);
    let mut plain = 0;
    let mut narrow = 0;
    for line in include_str!("fixtures/sm120_cs2ur_nvdisasm.jsonl").lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
        let vendor = row["nvidia_sass"].as_str().unwrap();
        check(&table, &index, word, vendor);
        if vendor.contains("CS2UR.32 ") { narrow += 1 } else { plain += 1 }
    }
    assert_eq!((plain, narrow), (340, 340));
}

#[test]
fn cs2ur_has_no_immediate_form_and_rejects_out_of_range_operands() {
    let table = table();
    assert!(table.entries.get("CS2UR_UR_II").is_none());
    for source in ["CS2UR UR4, 0x0 ;", "CS2UR UR256, SR_CLOCKLO ;", "CS2UR UR4, SR256 ;"] {
        let parsed = match cubit::parse_sass(source, 0) {
            Ok(parsed) => parsed,
            Err(_) => continue,
        };
        assert!(cubit::encoder::encode_instruction(&parsed, &table).is_err(), "{source}");
    }
    // The strict code-only API rejects a regular-bank guard on the uniform family.
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32(0));
    let source = |line: &str| format!(".entry cs2ur\n[{control}] {line} ;\n.endentry\n");
    let err = cubit::roundtrip_audit::encode_semantic_source(
        &source("@P0 CS2UR UR4, SR_CLOCKLO"), &table).unwrap_err();
    assert!(err.to_string().contains("predicate bank mismatch"), "{err}");
    let bytes = cubit::roundtrip_audit::encode_semantic_source(
        &source("@UP0 CS2UR UR4, SR_CLOCKLO"), &table).unwrap();
    assert_eq!(bytes, 0x000000000001500000000000000408cbu128.to_le_bytes().to_vec());
}
