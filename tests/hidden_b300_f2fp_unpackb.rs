//! Scaled F2FP UNPACK_B: the five measured source types and fail-closed lattice.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const SRC: &str = "f2fp-unpackb-mxfp6-mxfp8-silicon-2026-11-07";
const TYPES: [&str; 5] = ["E2M1", "E2M3", "E3M2", "E4M3", "E5M2"];

#[test]
fn scaled_unpack_b_fixture_decode_render_encode_and_neighbors() {
    let mut adopt = 0;
    let mut unclaimed = 0;
    let mut auxiliary = 0;
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in hb300_fixture("sm103_f2fp_unpackb_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str();
            if row["auxiliary_control_probe"] == true {
                auxiliary += 1;
            } else if row["adopt"] == true {
                adopt += 1;
                let decoded = index.decode(word, 0, &table)
                    .unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor:?}"));
                let text = cubit::printer::to_sass_lossless(&decoded);
                assert_eq!(text, vendor.unwrap(), "{arch}: {word:032x}: {}", decoded.key);
                let ctrl = cubit::scheduling::format_control_code(
                    &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
                let source = format!("[{ctrl}] {text} ;");
                cubit::roundtrip_audit::check_semantic_source(&source)
                    .unwrap_or_else(|e| panic!("{arch}: semantic {source}: {e}"));
                let parsed = cubit::parse_cuasm_line(&source, 0)
                    .unwrap_or_else(|e| panic!("{arch}: parse {source}: {e}"));
                assert_eq!(cubit::encoder::encode_instruction(&parsed, &table)
                    .unwrap_or_else(|e| panic!("{arch}: encode {source}: {e}")), word, "{source}");
            } else {
                unclaimed += 1;
                assert!(index.decode(word, 0, &table).is_err(),
                    "{arch}: unclaimed {word:032x}: {vendor:?}");
            }
        }
        for invalid in [
            "F2FP.BF16.E2M3.UNPACK_B R11, R2, R5 ;",
            "F2FP.BF16.E2M3.UNPACK_B R11, R2, R5.INVALID6 ;",
            "F2FP.BF16.E2M3.UNPACK_B R11, R2.B1, R5.B0 ;",
            "F2FP.BF16.E2M1.UNPACK_B R11, R2.H1, R5.B0 ;",
        ] {
            assert!(cubit::encoder::encode_instruction(
                &cubit::parse_cuasm_line(invalid, 0).unwrap(), &table).is_err(), "{invalid}");
        }
    }
    assert_eq!(adopt, 406);
    assert_eq!(unclaimed, 4322);
    assert_eq!(auxiliary, 64);
}

#[test]
fn scaled_unpack_b_twenty_measured_groups_and_provenance() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        let instructions = raw["instructions"].as_object().unwrap();
        let ins = &instructions["F2FP_R_R_R"];
        assert_eq!(ins["mod_groups"].as_object().unwrap().len(), 23);
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 20);
        for typ in TYPES {
            for prefix in ["", "RELU,", "SATFINITE,", "RELU,SATFINITE,"] {
                let name = format!("BF16,{typ},{prefix}UNPACK_B");
                let group = &ins["mod_groups"][&name];
                assert_eq!(group["_src"], SRC, "{name}");
                assert_eq!(group["claim_forbid"][0],
                    serde_json::json!({"shift":24,"bits":3,"values":[6,7]}));
                let fields = group["fields"].as_array().unwrap();
                // the canonical table layout writes a tag once per level (tools/tablefmt.py): a field carries `_src`
                // only where it differs from its row's -- none does here (the candidate's file tagged every field)
                assert!(fields.iter().all(|f| f.get("_src").map_or(true, |s| s == SRC)));
                assert!(fields.iter().any(|f| f["shift"] == 24
                    && f["bits"] == 3 && f["extraction"] == "f2fp_scale_sel"
                    && f["token_idx"] == 3));
                if typ == "E2M1" {
                    assert!(fields.iter().any(|f| f["extraction"] == "f2fp_ra_b1"));
                    assert!(fields.iter().any(|f| f["extraction"] == "f2fp_ra_b2"));
                } else {
                    assert!(fields.iter().any(|f| f["shift"] == 88
                        && f["extraction"] == "opmod:H1" && f["token_idx"] == 2));
                }
            }
        }
    }
}
