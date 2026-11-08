//! Measured dynamic selector repair; text evidence, not silicon semantics.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::path::Path;

const SRC: &str = "hidden-b300-viaddmnmx-dynamic-selector-2026-11-08";
const PLAIN: &str = "VIADDMNMX_R_R_R_UR_P";
const REVERSED: &str = "VIADDMNMX_R_R_UR_R_P";

fn table(arch: &str) -> IsaTable {
    IsaTable::load(Path::new(
        &std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz")),
    ))
    .unwrap()
}

fn fixture(target: &str) -> Vec<Value> {
    let text = match target {
        "sm103" => include_str!("fixtures/sm103_viaddmnmx_dynamic_selector_nvdisasm.jsonl"),
        "sm100" => include_str!("fixtures/sm100_viaddmnmx_dynamic_selector_nvdisasm.jsonl"),
        _ => unreachable!(),
    };
    text.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn word(value: &Value) -> u128 {
    u128::from_str_radix(
        value
            .as_str()
            .or_else(|| value["word"].as_str())
            .unwrap()
            .trim_start_matches("0x"),
        16,
    )
    .unwrap()
}

fn reencode(table: &IsaTable, raw: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (raw >> 96) as u32,
    ));
    let source = format!("[{control}] {text} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

#[test]
fn dynamic_selector_decode_render_and_reencode_exact() {
    for arch in ["sm103a", "sm100a"] {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let mut adopt = 0;
        let mut delegates = 0;
        for target in ["sm103", "sm100"] {
            for row in fixture(target) {
                let raw = word(&row);
                if row["role"] == "reject-scoped" {
                    assert!(
                        index.decode(raw, 0, &table).is_err(),
                        "old opcode-field predicate claimed {raw:032x}"
                    );
                    delegates += 1;
                    continue;
                }
                let vendor = row["nvidia_sass"].as_str().unwrap();
                let decoded = index
                    .decode(raw, 0, &table)
                    .unwrap_or_else(|e| panic!("{arch} {raw:032x} {vendor}: {e}"));
                assert_eq!(decoded.key, row["expected_key"].as_str().unwrap());
                assert_eq!(decoded.mod_group, "");
                assert_eq!(
                    cubit::printer::to_sass_lossless(&decoded).replace(".reuse", ""),
                    vendor.replace(".reuse", "")
                );
                assert_eq!(reencode(&table, raw, vendor), raw, "{vendor}");
                adopt += 1;
            }
        }
        assert_eq!(adopt, 64);
        assert_eq!(delegates, 2);
    }
}

#[test]
fn two_plain_rows_are_narrow_and_prior_relu_provenance_survives() {
    for arch in ["sm103a", "sm100a"] {
        let path =
            std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz"));
        let raw: Value =
            serde_json::from_slice(&cubit::table::read_table_bytes(Path::new(&path)).unwrap())
                .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 2);
        for key in [PLAIN, REVERSED] {
            let groups = &raw["instructions"][key]["mod_groups"];
            let group = &groups[""];
            assert_eq!(group["_src"], SRC);
            assert_eq!(group["row_probe"], true);
            assert!(group["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field["extraction"] == "pred"
                    && field["shift"] == 87
                    && field["bits"] == 3
                    && field["token_idx"] == 5));
            assert!(group["fields"]
                .as_array()
                .unwrap()
                .iter()
                .all(|field| field["extraction"] != "pred" || field["shift"] != 9));
            assert!(group["claim_forbid"]
                .as_array()
                .unwrap()
                .iter()
                .any(|block| block["shift"] == 76 && block["values"] == serde_json::json!([1])));
            assert_eq!((word(&group["and_base"]) >> 72) & 3, 1);
            assert_eq!((word(&group["and_base"]) >> 76) & 1, 0);
            assert_eq!(word(&group["and_base"]) >> 96, 0);
            let relu = &groups["RELU"];
            let expected = if key == PLAIN {
                "hidden-b300-viaddmnmx-relu-closure-2026-11-08"
            } else {
                "hidden-b300-viaddmnmx-reversed-ur-2026-11-08"
            };
            assert_eq!(relu["_src"], expected);
            assert!(relu["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field["extraction"] == "pred" && field["shift"] == 87));
        }
    }
}
