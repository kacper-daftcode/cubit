//! FlashMLA F16/E4M3, F16/E2M1 and BF16/E8 UNPACK_B production forms.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const SRC: &str = "k31-f2fp-unpack-flashmla-2026-11-07";

#[test]
fn unpack_witnesses_and_fields_round_trip() {
    let mut census = std::collections::BTreeMap::new();
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_f2fp_unpack_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["arch"] != target {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(word, 0, &table)
                .unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor}"));
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                vendor,
                "{arch}: {word:032x}: {}",
                decoded.key
            );
            let ctrl = cubit::scheduling::format_control_code(
                &cubit::scheduling::decode_sched_upper32((word >> 96) as u32),
            );
            let source = format!("[{ctrl}] {vendor} ;");
            cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
            let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
            assert_eq!(
                cubit::encoder::encode_instruction(&parsed, &table)
                    .unwrap_or_else(|e| panic!("{source}: {e}")),
                word,
                "{source}"
            );
            let occurrences = row["occurrences"].as_u64().unwrap();
            *census
                .entry(row["op"].as_str().unwrap().to_owned())
                .or_insert(0u64) += occurrences;
        }
    }
    assert_eq!(census["F2FP.F16.E4M3.UNPACK_B"], 1264);
    assert_eq!(census["F2FP.F16.E2M1.UNPACK_B"], 1280);
    assert_eq!(census["F2FP.BF16.E8.UNPACK_B"], 568);
    assert_eq!(census["F2FP.E8.F32.PACK_AB_MERGE_C.RZ"], 16);
}

#[test]
fn three_donor_rows_and_byte_selectors_are_registered() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 4);
        let ins = raw["instructions"].as_object().unwrap();
        for key in [
            "F2FP.F16.E4M3.UNPACK_B_R_R",
            "F2FP.F16.E2M1.UNPACK_B_R_R",
            "F2FP.BF16.E8.UNPACK_B_R_R",
            "F2FP.E8.F32.PACK_AB_MERGE_C.RZ_R_R_R_R",
        ] {
            assert_eq!(ins[key]["_src"], SRC);
            assert_eq!(ins[key]["mod_groups"][""]["_src"], SRC);
            assert!(ins[key]["mod_groups"][""]["fields"]
                .as_array()
                .unwrap()
                .iter()
                .all(|f| f["_src"] == SRC));
        }
        let fields = ins["F2FP.F16.E2M1.UNPACK_B_R_R"]["mod_groups"][""]["fields"]
            .as_array()
            .unwrap();
        assert!(fields
            .iter()
            .any(|f| f["shift"] == 72 && f["extraction"] == "e2m1_ra"));
        assert!(fields
            .iter()
            .any(|f| f["shift"] == 88 && f["extraction"] == "e2m1_ra"));
        let h1 = ins["F2FP.F16.E4M3.UNPACK_B_R_R"]["mod_groups"][""]["fields"]
            .as_array()
            .unwrap();
        assert!(h1
            .iter()
            .any(|f| f["shift"] == 88 && f["extraction"] == "opmod:H1"));
        assert!(ins["F2FP_R_R"]["mod_groups"]["F16,E4M3,UNPACK_B"].is_null());
        assert!(ins["F2FP_R_R"]["mod_groups"]["E4M3,F16,UNPACK_B"].is_null());
        assert!(ins["F2FP_R_R"]["mod_groups"]["TF32,F32,PACK_B"].is_object());
    }
}
