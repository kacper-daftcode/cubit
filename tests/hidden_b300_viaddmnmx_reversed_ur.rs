//! Controlled reversed-UR/R plain VIADDMNMX.RELU; encoding evidence only.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::path::Path;

const SRC: &str = "hidden-b300-viaddmnmx-reversed-ur-2026-11-08";
const KEY: &str = "VIADDMNMX_R_R_UR_R_P";

fn table(arch: &str) -> IsaTable {
    IsaTable::load(Path::new(
        &std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz")),
    ))
    .unwrap()
}

fn fixture(target: &str) -> Vec<Value> {
    let text = match target {
        "sm103" => include_str!("fixtures/sm103_viaddmnmx_reversed_ur_nvdisasm.jsonl"),
        "sm100" => include_str!("fixtures/sm100_viaddmnmx_reversed_ur_nvdisasm.jsonl"),
        _ => unreachable!(),
    };
    text.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn number(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn reencode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let source = format!("[{control}] {text} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

#[test]
fn reversed_u_r_relu_decode_render_and_encode_exact() {
    for arch in ["sm103a", "sm100a"] {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let mut adopt = 0;
        let mut control = 0;
        for target in ["sm103", "sm100"] {
            for row in fixture(target) {
                let word = number(&row["word"]);
                if row["role"] == "auxiliary-control" {
                    let control_code = cubit::scheduling::format_control_code(
                        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32),
                    );
                    assert_ne!(
                        control_code, "",
                        "control-plane classification needs actual control"
                    );
                    control += 1;
                }
                if row["role"] != "adopt" {
                    continue;
                }
                let vendor = row["nvidia_sass"].as_str().unwrap();
                let decoded = index
                    .decode(word, 0, &table)
                    .unwrap_or_else(|e| panic!("{arch} {word:032x} {vendor}: {e}"));
                assert_eq!(decoded.key, KEY);
                assert_eq!(decoded.mod_group, "RELU");
                assert_eq!(
                    cubit::printer::to_sass_lossless(&decoded).replace(".reuse", ""),
                    vendor.replace(".reuse", "")
                );
                assert_eq!(reencode(&table, word, vendor), word, "{vendor}");
                adopt += 1;
            }
        }
        assert!(adopt > 2000, "{arch}: missing complete operand lattice");
        assert!(control > 0);
    }
}

#[test]
fn typed_inert_and_disordered_neighbours_fail_closed() {
    for arch in ["sm103a", "sm100a"] {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let mut rejects = 0;
        let mut reverse_source = 0;
        for target in ["sm103", "sm100"] {
            for row in fixture(target) {
                let word = number(&row["word"]);
                if row["role"] == "auxiliary-existing" {
                    if row["kind"] == "bit9" {
                        assert_eq!(
                            row["nvidia_sass"],
                            "VIADDMNMX.RELU R27, R15.reuse, R13, UR5, PT"
                        );
                        reverse_source += 1;
                        continue;
                    }
                    let decoded = index
                        .decode(word, 0, &table)
                        .unwrap_or_else(|e| panic!("{arch} old form {word:032x}: {e}"));
                    assert_eq!(decoded.key, KEY);
                    assert_eq!(decoded.mod_group, "");
                }
                if row["role"] != "reject-scoped" {
                    continue;
                }
                assert!(
                    index.decode(word, 0, &table).is_err(),
                    "claimed {arch} {word:032x}: {:?}",
                    row["nvidia_sass"]
                );
                rejects += 1;
            }
        }
        assert!(
            rejects >= 10,
            "{arch}: missing typed/inert negatives: {rejects}"
        );
        assert_eq!(reverse_source, 2);
    }
}

#[test]
fn row_is_disjoint_narrow_and_provenanced() {
    for arch in ["sm103a", "sm100a"] {
        let path =
            std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz"));
        let raw: Value =
            serde_json::from_slice(&cubit::table::read_table_bytes(Path::new(&path)).unwrap())
                .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 1);
        let group = &raw["instructions"][KEY]["mod_groups"]["RELU"];
        assert_eq!(group["_src"], SRC);
        assert_eq!(group["row_probe"], true);
        assert!(group["count"].is_null());
        let expected = [
            (16, "reg", 1),
            (24, "reg", 2),
            (32, "ureg", 3),
            (64, "reg", 4),
            (63, "neg", 3),
            (122, "reuse", 2),
            (124, "reuse", 4),
            (87, "pred", 5),
            (90, "neg", 5),
        ];
        let mut mask = 0u128;
        for field in group["fields"].as_array().unwrap() {
            assert!(field.get("_src").is_none_or(|src| src == SRC));
            if field["shift"] == 12 {
                continue;
            }
            assert!(
                expected.iter().any(|(shift, extraction, token)| {
                    field["shift"] == *shift
                        && field["extraction"] == *extraction
                        && field["token_idx"] == *token
                }),
                "unmeasured field: {field}"
            );
            let bits = ((1u128 << field["bits"].as_u64().unwrap()) - 1)
                << field["shift"].as_u64().unwrap();
            assert_eq!(mask & bits, 0);
            mask |= bits;
        }
        mask |= 0xF << 12;
        assert_eq!(number(&group["variable_mask"]), mask);
        assert_eq!(number(&group["and_base"]) & mask, 0);
        assert_eq!(number(&group["and_base"]) >> 96, 0);
        for group_name in ["", "U32"] {
            assert!(
                raw["instructions"][KEY]["mod_groups"][group_name]["claim_forbid"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|block| {
                        block["shift"] == 76
                            && block["bits"] == 1
                            && block["values"] == serde_json::json!([1])
                    })
            );
        }
    }
}
