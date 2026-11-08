//! Four FADD2 immediate rounding/FTZ groups with exact measured semantics.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const OLD_SRC: &str = "hidden-b300-fadd2-imm-2026-11-08";
const SRC: &str = "hidden-b300-fadd2-rounding-2026-11-08";
const MODES: [(&str, u128); 4] = [
    ("RZ", (1u128 << 78) | (1u128 << 79)),
    ("FTZ,RM", (1u128 << 78) | (1u128 << 80)),
    ("FTZ,RP", (1u128 << 79) | (1u128 << 80)),
    ("FTZ,RZ", (1u128 << 78) | (1u128 << 79) | (1u128 << 80)),
];

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

#[test]
fn fadd2_rounding_decode_render_encode_and_fail_closed() {
    let mut adopted = 0;
    let mut exact = 0;
    let mut negatives = 0;
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/sm103_fadd2_rounding_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let word = hex(&row["word"]);
            if row["adopt"] == true {
                adopted += 1;
                let decoded = index
                    .decode(word, 0, &table)
                    .unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}"));
                assert_eq!(decoded.key, "FADD2_R_R_FI");
                let text = cubit::printer::to_sass_lossless(&decoded);
                assert_eq!(
                    text,
                    row["nvidia_sass"].as_str().unwrap(),
                    "{arch}: {word:032x}"
                );
                assert!(text.starts_with("FADD2.RZ ") || text.starts_with("FADD2.FTZ.R"));
                if row["encode_exact"] == true {
                    exact += 1;
                    let ctrl = cubit::scheduling::format_control_code(
                        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32),
                    );
                    let source = format!("[{ctrl}] {text} ;");
                    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
                    let parsed = cubit::parse_cuasm_line(&source, 0)
                        .unwrap_or_else(|e| panic!("{arch}: parse {source}: {e}"));
                    assert_eq!(
                        cubit::encoder::encode_instruction(&parsed, &table).unwrap(),
                        word,
                        "{arch}: exact {source}"
                    );
                } else {
                    // H's bit85 is independently measured neutral in the base
                    // family; canonical encode clears it rather than inventing it.
                    assert_eq!(word & (1 << 85), 1 << 85);
                }
            } else {
                negatives += 1;
                assert_eq!(row["kind"], "mask-closure");
                assert_ne!(word & (1 << 91), 0);
                assert!(
                    index.decode(word, 0, &table).is_err(),
                    "{arch}: B91 {word:032x}"
                );
            }
        }
        for mode in ["RZ", "FTZ.RM", "FTZ.RP", "FTZ.RZ"] {
            assert!(
                cubit::encoder::encode_instruction(
                    &cubit::parse_cuasm_line(&format!("FADD2.{mode} R1, R2.F32.LO_HI, -1 ;"), 0)
                        .unwrap(),
                    &table
                )
                .is_err(),
                "{arch}: {mode} accepted the measured INVALID3 scalar LO_HI"
            );
        }
    }
    assert_eq!(adopted, 768);
    assert_eq!(exact, 384);
    assert_eq!(negatives, 384);
}

#[test]
fn fadd2_rounding_fields_and_provenance() {
    let mut vm = None;
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        let groups = &raw["instructions"]["FADD2_R_R_FI"]["mod_groups"];
        assert_eq!(groups.as_object().unwrap().len(), 8);
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 4);
        assert_eq!(raw["_meta"]["provenance"]["sources"][OLD_SRC]["rows"], 4);
        for modifier in ["", "RM", "RP", "FTZ"] {
            assert_eq!(groups[modifier]["_src"], OLD_SRC);
        }
        for (modifier, bits) in MODES {
            let group = &groups[modifier];
            assert_eq!(group["_src"], SRC);
            assert_eq!(hex(&group["and_base"]), 0x44b | bits);
            let mask = hex(&group["variable_mask"]);
            assert_eq!(mask & (1 << 91), 0);
            if let Some(previous) = vm {
                assert_eq!(mask, previous);
            } else {
                vm = Some(mask);
            }
            for (index, field) in group["fields"].as_array().unwrap().iter().enumerate() {
                assert_eq!(field["_src"], SRC);
                let mut inherited = groups[""]["fields"][index].clone();
                inherited["_src"] = Value::from(SRC);
                assert_eq!(field, &inherited);
            }
            assert!(group["_note"]
                .as_str()
                .unwrap()
                .contains("SILICON-SEMANTIC"));
        }
    }
}
