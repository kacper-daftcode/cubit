//! K3.1 F2FP.SATFINITE.BF16.F32.PACK_AB (0x23e) on SM103a / SM100a.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const KEY: &str = "F2FP.SATFINITE.BF16.F32.PACK_AB_R_R_R";
const SRC: &str = "k31-f2fp-satfinite-bf16-pack-2026-11-07";

#[test]
fn every_production_witness_and_field_probe_round_trips() {
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        let (mut n, mut production, mut occurrences) = (0, 0, 0);
        for line in include_str!("fixtures/k31_f2fp_pack_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["arch"] != target && row.get("occurrences").is_none() || row["nvidia_sass"].is_null() { continue; }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor}"));
            assert_eq!(decoded.key, KEY);
            let text = cubit::printer::to_sass_lossless(&decoded);
            assert_eq!(text, vendor, "{arch}: {word:032x}");
            let ctrl = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let source = format!("[{ctrl}] {text} ;");
            let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
            assert_eq!(cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|e| panic!("{source}: {e}")), word);
            n += 1;
            if row.get("occurrences").is_some() { production += 1; occurrences += row["occurrences"].as_u64().unwrap(); }
        }
        assert_eq!(production, 383);
        assert_eq!(occurrences, 1184);
        assert_eq!(n, 383 + 35);
    }
}

#[test]
fn row_is_measured_and_claim_forbid_is_preserved() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        let g = &raw["instructions"][KEY]["mod_groups"][""];
        assert_eq!(g["_src"], SRC);
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 1);
        assert_eq!(g["claim_forbid"].as_array().unwrap().len(), 2);
        let fields = g["fields"].as_array().unwrap();
        assert_eq!(fields[0]["extraction"], "guard");
        assert_eq!(fields[0]["shift"], 12);
        assert_eq!(fields[0]["_src"], SRC);
        assert_eq!(fields.len(), 4);
        assert!(!g["fields"].as_array().unwrap().iter().any(|f| f.get("_src458d2").is_some()));
    }
}
