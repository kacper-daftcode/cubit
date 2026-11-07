//! FlashMLA UIADD3.64 full-byte register and immediate forms.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const SRC: &str = "k31-uiadd64-flashmla-2026-11-07";

#[test]
fn all_uiadd64_witnesses_round_trip() {
    let mut census = std::collections::BTreeMap::new();
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_uiadd64_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["arch"] != target {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let kind = row["kind"].as_str().unwrap().to_owned();
            let expected = if kind == "R" {
                "UIADD3.64_UR_UP_UP_UR_UR_UR"
            } else {
                "UIADD3.64_UR_UP_UP_UR_II_UR"
            };
            let decoded = index
                .decode(word, 0, &table)
                .unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor}"));
            assert_eq!(decoded.key, expected, "{arch}: {word:032x}");
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
            *census.entry(kind).or_insert(0u64) += row["occurrences"].as_u64().unwrap();
        }
    }
    assert_eq!(census["R"], 247);
    assert_eq!(census["II"], 174);
}

#[test]
fn both_forms_are_measured_with_full_fields() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 2);
        for key in ["UIADD3.64_UR_UP_UP_UR_UR_UR", "UIADD3.64_UR_UP_UP_UR_II_UR"] {
            let entry = &raw["instructions"][key];
            assert_eq!(entry["_src"], SRC);
            let fields = entry["mod_groups"][""]["fields"].as_array().unwrap();
            assert!(fields.iter().all(|f| f["_src"] == SRC));
            for (token, shift) in [(2, 81), (3, 84)] {
                assert!(fields.iter().any(|f| f["token_idx"] == token
                    && f["shift"] == shift
                    && f["extraction"] == "upred"
                    && f["bits"] == 3));
            }
        }
        let fields = raw["instructions"]["UIADD3.64_UR_UP_UP_UR_II_UR"]["mod_groups"][""]["fields"]
            .as_array()
            .unwrap();
        assert!(fields.iter().any(|f| f["token_idx"] == 5
            && f["shift"] == 32
            && f["bits"] == 32
            && f["extraction"] == "imm"));
        assert!(raw["instructions"]["UIADD3_UR_UP_UP_UR_UR_UR"]["mod_groups"]["64"].is_null());
        assert!(raw["instructions"]["UIADD3_UR_UP_UP_UR_UR_UR"]["mod_groups"][""].is_object());
    }
}
