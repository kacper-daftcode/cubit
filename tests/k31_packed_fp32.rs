//! K3.1 FADD2/FMUL2 packed-FP32: exact H witnesses and local nvdisasm probes.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const SRC: &str = "k31-packed-fp32-2026-11-07";
const KEYS: [&str; 5] = ["FADD2_R_R_R", "FADD2_R_R_FI", "FADD2_R_R_UR", "FMUL2_R_R_FI", "FMUL2_R_R_UR"];

#[test]
fn all_witnesses_and_field_probes_round_trip() {
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        let (mut n, mut production, mut occurrences) = (0, 0, 0);
        for line in include_str!("fixtures/k31_packed_fp32_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["arch"] != target || row.get("synthetic_probe").and_then(Value::as_bool) == Some(true)
                || (row["evidence"] == "independent raw nvdisasm probe" && row["op"] == "FMUL2" && matches!(row["kind"].as_str(), Some("R" | "UR"))) { continue; }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor}"));
            assert!(KEYS.contains(&decoded.key.as_str()), "{arch}: {word:032x}: {}\n{vendor}", decoded.key);
            let lossless = cubit::printer::to_sass_lossless(&decoded);
            let own = if f32::from_bits(((word >> 32) & 0xffff_ffff) as u32).is_nan() && vendor.contains("NAN") { cubit::printer::to_sass(&decoded) } else { lossless.clone() };
            assert_eq!(&own, vendor, "{arch}: {word:032x}");
            let ctrl = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let source = format!("[{ctrl}] {lossless} ;");
            cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
            let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
            assert_eq!(cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|e| panic!("{source}: {e}")), word, "{source}");
            n += 1;
            if row.get("occurrences").is_some() {
                production += 1;
                occurrences += row["occurrences"].as_u64().unwrap();
            }
        }
        assert!(n > 500, "{arch}: only {n} witnesses/probes");
        if target == "SM103" {
            assert_eq!(production, 940);
            assert_eq!(occurrences, 2228);
        } else {
            assert_eq!(production, 548);
            assert_eq!(occurrences, 1012);
        }
    }
}

#[test]
fn measured_geometry_is_registered_not_only_printed() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 6);
        for key in KEYS {
            assert_eq!(raw["instructions"][key]["_src"], SRC);
            let g = &raw["instructions"][key]["mod_groups"][""];
            assert_eq!(g["_src"], SRC);
            for f in g["fields"].as_array().unwrap() { assert_eq!(f["_src"], SRC); }
            let third = g["fields"].as_array().unwrap().iter().find(|f| f["token_idx"] == 3 && matches!(f["extraction"].as_str(), Some("reg" | "ureg" | "f32"))).unwrap();
            assert_eq!(third["shift"], 32, "{arch}: {key}");
        }
    }
}
