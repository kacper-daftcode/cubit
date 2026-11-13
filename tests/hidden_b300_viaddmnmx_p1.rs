//! Controlled P1/!P1 selector fixtures; text evidence, not silicon semantics.
include!("hb300_fixture.inc");
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::path::Path;

const SRC: &str = "hidden-b300-viaddmnmx-p1-2026-11-08";
const PLAIN: &str = "VIADDMNMX_R_R_R_UR_P";

fn table(arch: &str) -> IsaTable {
    let path = std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz"));
    IsaTable::load(Path::new(&path)).unwrap()
}

fn fixture(target: &str) -> Vec<Value> {
    let text = match target {
        "sm103" => hb300_fixture("sm103_viaddmnmx_p1_nvdisasm.jsonl"),
        "sm100" => hb300_fixture("sm100_viaddmnmx_p1_nvdisasm.jsonl"),
        _ => unreachable!(),
    };
    text.lines().map(|line| serde_json::from_str(line).unwrap()).collect()
}

fn word(value: &Value) -> u128 {
    let text = value.as_str().or_else(|| value["word"].as_str()).unwrap();
    u128::from_str_radix(text.trim_start_matches("0x"), 16).unwrap()
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

fn check(arch: &str) {
    let table = table(arch);
    let index = DecodeIndex::build(&table);
    let mut adopt = 0;
    let mut reject = 0;
    for target in ["sm103", "sm100"] {
        for row in fixture(target) {
            let raw = word(&row);
            let decoded = index.decode(raw, 0, &table);
            if row["role"] != "adopt" {
                assert!(decoded.is_err(), "legacy low discriminator accepted {raw:032x}");
                reject += 1;
                continue;
            }
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let instruction = decoded.unwrap_or_else(|e| panic!("{arch} {raw:032x} {vendor}: {e}"));
            assert_eq!(instruction.key, row["expected_key"].as_str().unwrap());
            assert_eq!(instruction.mod_group, "");
            assert_eq!(
                cubit::printer::to_sass_lossless(&instruction).replace(".reuse", ""),
                vendor.replace(".reuse", "")
            );
            assert_eq!(reencode(&table, raw, vendor), raw, "{vendor}");
            adopt += 1;
        }
    }
    assert_eq!((adopt, reject), (8, 8));

    let path = std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz"));
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(Path::new(&path)).unwrap()).unwrap();
    assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 1);
    let group = &raw["instructions"][PLAIN]["mod_groups"][""];
    assert_eq!(group["_src"], SRC);
    assert_eq!(group["row_probe"], true);
    assert_eq!((word(&group["and_base"]) >> 9) & 7, 7);
    let fields = group["fields"].as_array().unwrap();
    assert!(fields.iter().any(|field| field["extraction"] == "pred"
        && field["shift"] == 87 && field["bits"] == 3 && field["token_idx"] == 5));
    assert!(fields.iter().all(|field| field["extraction"] != "pred" || field["shift"] != 9));
    assert!(fields.iter().any(|field| field["extraction"] == "neg" && field["shift"] == 90));
    let forbidden = group["claim_forbid"].as_array().unwrap();
    for (shift, bits, values) in [
        (72, 2, serde_json::json!([0, 2, 3])),
        (62, 1, serde_json::json!([1])),
        (63, 1, serde_json::json!([1])),
        (74, 1, serde_json::json!([1])),
        (76, 1, serde_json::json!([1])),
    ] {
        assert!(forbidden.iter().any(|block| block["shift"] == shift
            && block["bits"] == bits && block["values"] == values));
    }
}

#[test]
fn p1_sm103a_decode_render_reencode_and_fail_closed() {
    check("sm103a");
}

#[test]
fn p1_sm100a_decode_render_reencode_and_fail_closed() {
    check("sm100a");
}
