//! Tail of FlashMLA scalar ALU and synchronization production forms.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

#[test]
fn all_tail_forms_round_trip() {
    let mut census = std::collections::BTreeMap::new();
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_alu_rest_nvdisasm.jsonl").lines() {
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
                "{arch}: {word:032x}"
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
            *census
                .entry(row["op"].as_str().unwrap().to_owned())
                .or_insert(0u64) += row["occurrences"].as_u64().unwrap();
        }
    }
    let total: u64 = census.values().sum();
    assert_eq!(total, 230);
}

#[test]
fn all_six_forms_have_measured_metadata() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            raw["_meta"]["provenance"]["sources"]["k31-alu-tail-flashmla-2026-11-07"]["rows"],
            6
        );
        for (key, group) in [
            ("FADD_R_R_UR", "FTZ"),
            ("FFMA_R_R_UR_R", "FTZ"),
            ("FSETP_P_P_R_FI_P", "AND,EQ"),
            ("ARRIVES_ARURI", "64,ARVCNT,LDGSTSBAR"),
            ("SYNCS.ARRIVE.TRANS64.RED.A0TX_R_ARURI_R", ""),
            ("VIMNMX3_R_R_UR_R_P", ""),
        ] {
            assert_eq!(
                raw["instructions"][key]["mod_groups"][group]["_src"], "k31-alu-tail-flashmla-2026-11-07",
                "{key}"
            );
        }
        let vim = &raw["instructions"]["VIMNMX3_R_R_UR_R_P"]["mod_groups"][""]["fields"];
        assert!(vim
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["shift"] == 87 && f["extraction"] == "pred"));
        assert!(vim
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["shift"] == 90 && f["extraction"] == "neg"));
    }
}
