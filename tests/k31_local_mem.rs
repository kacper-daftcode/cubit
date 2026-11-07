//! LDL.U8 and UBLKCP.G.S memory helpers.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

#[test]
fn local_memory_witnesses_round_trip() {
    let mut census = std::collections::BTreeMap::new();
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_local_mem_nvdisasm.jsonl").lines() {
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
    assert_eq!(census["LDL.U8"], 192);
    assert_eq!(census["UBLKCP.G.S"], 82);
    assert_eq!(census["UBLKCP.S.G"], 2);
}

#[test]
fn local_memory_rows_have_real_fields() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            raw["_meta"]["provenance"]["sources"]["k31-local-memory-flashmla-2026-11-07"]["rows"],
            3
        );
        let ldl = &raw["instructions"]["LDL.U8_R_ARI"]["mod_groups"][""];
        assert!(ldl["fields"].as_array().unwrap().len() >= 3);
        let cp = &raw["instructions"]["UBLKCP.G.S_AURI_AURI_UR"]["mod_groups"][""];
        for (shift, token, extraction) in [(32, 1, "sub_ur0"), (24, 2, "sub_ur0"), (64, 3, "ureg")]
        {
            assert!(cp["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["shift"] == shift
                    && f["token_idx"] == token
                    && f["extraction"] == extraction
                    && f["_src"] == "k31-local-memory-flashmla-2026-11-07"));
        }
        let sg = &raw["instructions"]["UBLKCP.S.G_AURI_AURI_UR"]["mod_groups"][""];
        for (shift, token) in [(32, 1), (24, 2), (64, 3)] {
            assert!(sg["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["shift"] == shift
                    && f["token_idx"] == token
                    && f["extraction"] == "ureg"));
        }
    }
}
