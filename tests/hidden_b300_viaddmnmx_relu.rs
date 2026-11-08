//! Measured plain VIADDMNMX.RELU on SM103a/SM100a; no execution claim.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::path::Path;

const SRC: &str = "hidden-b300-viaddmnmx-relu-closure-2026-11-08";
const KEYS: [&str; 4] = [
    "VIADDMNMX_R_R_R_R_P",
    "VIADDMNMX_R_R_R_UR_P",
    "VIADDMNMX_R_R_R_II_P",
    "VIADDMNMX_R_R_II_R_P",
];

fn table(arch: &str) -> IsaTable {
    IsaTable::load(Path::new(
        &std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz")),
    ))
    .unwrap()
}

fn fixture(target: &str) -> Vec<Value> {
    let text = match target {
        "sm103" => include_str!("fixtures/sm103_viaddmnmx_relu_nvdisasm.jsonl"),
        "sm100" => include_str!("fixtures/sm100_viaddmnmx_relu_nvdisasm.jsonl"),
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
fn production_and_controlled_plain_relu_render_and_reencode() {
    for arch in ["sm103a", "sm100a"] {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let mut production = 0;
        let mut adopt = 0;
        for target in ["sm103", "sm100"] {
            for row in fixture(target) {
                if row["role"] != "adopt" {
                    continue;
                }
                let word = number(&row["word"]);
                let vendor = row["nvidia_sass"].as_str().unwrap();
                let decoded = index
                    .decode(word, 0, &table)
                    .unwrap_or_else(|e| panic!("{arch} {word:032x}: {e}"));
                assert_eq!(decoded.key.as_str(), row["expected_key"].as_str().unwrap());
                assert_eq!(decoded.mod_group.as_str(), "RELU");
                assert_eq!(
                    cubit::printer::to_sass_lossless(&decoded).replace(".reuse", ""),
                    vendor.replace(".reuse", "")
                );
                assert_eq!(reencode(&table, word, vendor), word, "{vendor}");
                adopt += 1;
                production += (row["kind"] == "production") as usize;
            }
        }
        assert!(
            production >= 884,
            "{arch}: incomplete H production coverage: {production}"
        );
        assert!(
            adopt > 3000,
            "{arch}: incomplete controlled positive coverage: {adopt}"
        );
    }
}

#[test]
fn typed_inert_and_invalid_neighbours_stay_unclaimed() {
    for arch in ["sm103a", "sm100a"] {
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let mut rejects = 0;
        let mut previously_unclaimed_operand_order = 0;
        for target in ["sm103", "sm100"] {
            for row in fixture(target) {
                if row["role"] != "reject-scoped" {
                    continue;
                }
                let word = number(&row["word"]);
                // This exact bit9 crossover is also the positive anchor in
                // fixtures/{target}_viaddmnmx_reversed_ur_nvdisasm.jsonl.
                // Combining the families must decode it as the other order,
                // rather than incorrectly retaining the old isolated-family rejection.
                if row["kind"] == "single-bit"
                    && row["labels"][0] == "R_R_R_UR_P"
                    && row["labels"][1] == "bit=9"
                {
                    let vendor = row["nvidia_sass"].as_str().unwrap();
                    let decoded = index
                        .decode(word, 0, &table)
                        .unwrap_or_else(|e| panic!("{arch} crossover {word:032x}: {e}"));
                    assert_eq!(decoded.key, "VIADDMNMX_R_R_UR_R_P");
                    assert_eq!(decoded.mod_group, "RELU");
                    assert_eq!(
                        cubit::printer::to_sass_lossless(&decoded).replace(".reuse", ""),
                        vendor.replace(".reuse", "")
                    );
                    assert_eq!(reencode(&table, word, vendor), word);
                    previously_unclaimed_operand_order += 1;
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
        assert!(rejects > 200, "{arch}: missing negative controls");
        assert_eq!(previously_unclaimed_operand_order, 2);
    }
}

#[test]
fn new_rows_have_narrow_disjoint_fields_and_provenance() {
    for arch in ["sm103a", "sm100a"] {
        let path =
            std::env::var("CUBIT_TABLE").unwrap_or_else(|_| format!("tables/{arch}.json.gz"));
        let raw: Value =
            serde_json::from_slice(&cubit::table::read_table_bytes(Path::new(&path)).unwrap())
                .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 4);
        for key in KEYS {
            let group = &raw["instructions"][key]["mod_groups"]["RELU"];
            assert_eq!(group["_src"], SRC, "{key}");
            assert_eq!(group["row_probe"], true);
            assert!(group["count"].is_null());
            let mut mask = 0u128;
            for field in group["fields"].as_array().unwrap() {
                assert!(
                    field.get("_src").is_none_or(|src| src == SRC),
                    "{key}: field provenance must be the row tag or an explicit equal override"
                );
                if field["extraction"] == "pred" {
                    assert_eq!(
                        field["shift"], 87,
                        "{key}: predicate is not an opcode field"
                    );
                }
                let bits = ((1u128 << field["bits"].as_u64().unwrap()) - 1)
                    << field["shift"].as_u64().unwrap();
                assert_eq!(mask & bits, 0, "{key}: overlapping fields");
                mask |= bits;
            }
            assert_eq!(number(&group["variable_mask"]), mask);
            assert_eq!(number(&group["and_base"]) & mask, 0);
            assert_eq!(number(&group["and_base"]) >> 96, 0);
            assert_eq!((number(&group["and_base"]) >> 72) & 3, 1);
            assert_eq!((number(&group["and_base"]) >> 74) & 1, 0);
            assert_eq!((number(&group["and_base"]) >> 76) & 1, 1);
            assert_eq!(group["claim_forbid"][0]["shift"], 72);
            assert_eq!(group["claim_forbid"][0]["bits"], 2);
            assert_eq!(
                group["claim_forbid"][0]["values"],
                serde_json::json!([0, 2, 3])
            );
            for bit in [62, 63, 74, 75] {
                let occupied = group["fields"].as_array().unwrap().iter().any(|field| {
                    let shift = field["shift"].as_u64().unwrap();
                    shift <= bit && bit < shift + field["bits"].as_u64().unwrap()
                });
                if !occupied {
                    assert!(
                        group["claim_forbid"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|block| {
                                block["shift"] == bit
                                    && block["bits"] == 1
                                    && block["values"] == serde_json::json!([1])
                            }),
                        "{key}: unmeasured sign-window bit {bit} must stay closed"
                    );
                }
            }
        }
    }
}
