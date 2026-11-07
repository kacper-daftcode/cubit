//! UTCHMMA structured tmem/gdesc/idesc address extraction, including UR64+ offsets.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const KEY: &str = "UTCHMMA_II_II_II_II_II_UP";
const SRC: &str = "k31-utchmma-tmem-addr-2026-11-07";

#[test]
fn all_structured_address_witnesses_round_trip() {
    let table = IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap();
    let index = DecodeIndex::build(&table);
    let (mut n, mut occurrences) = (0, 0);
    for line in include_str!("fixtures/k31_utchmma_nvdisasm.jsonl").lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let decoded = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
        assert!(decoded.key.starts_with("UTCHMMA_"), "{word:032x}: {}", decoded.key);
        assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor);
        let ctrl = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
        let source = format!("[{ctrl}] {vendor} ;");
        cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
        let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
        assert_eq!(cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|e| panic!("{source}: {e}")), word);
        n += 1;
        occurrences += row["occurrences"].as_u64().unwrap();
    }
    assert_eq!(n, 153);
    assert_eq!(occurrences, 528);
}

#[test]
fn address_row_keeps_all_measured_fields_and_provenance() {
    let table: Value = serde_json::from_slice(&cubit::table::read_table_bytes(std::path::Path::new("tables/sm103a.json")).unwrap()).unwrap();
    let group = &table["instructions"][KEY]["mod_groups"][""];
    assert_eq!(group["_src"], SRC);
    assert!(group["fields"].as_array().unwrap().iter().any(|f| f["shift"] == 70 && f["extraction"] == "tdesc_off"));
    assert!(group["fields"].as_array().unwrap().iter().any(|f| f["shift"] == 64 && f["extraction"] == "tmem_ur" && f["token_idx"] == 3));
    assert!(group["fields"].as_array().unwrap().iter().all(|f| f["_src"] == SRC));
    assert_eq!(table["_meta"]["provenance"]["sources"][SRC]["rows"], 1);
}
