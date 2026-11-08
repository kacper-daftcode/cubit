//! Measured production FFMA2 R,R,F32-immediate,R rows on SM103a and SM100a.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const SRC: &str = "hidden-b300-ffma2-b-imm-2026-11-08";
const VM: u128 = (0xfu128 << 12)
    | (0xffu128 << 16)
    | (0xffu128 << 24)
    | (0xffff_ffffu128 << 32)
    | (0xffu128 << 64)
    | (0xfu128 << 72)
    | (1u128 << 77)
    | (0x3ffu128 << 81)
    | (0xfu128 << 92);

#[test]
fn ffma2_b_immediate_fixture_and_fail_closed() {
    let mut adopted = 0;
    let mut exact = 0;
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/sm103_ffma2_b_imm_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str();
            let nan_immediate = vendor.is_some_and(|text| {
                text.split(", ")
                    .nth(2)
                    .is_some_and(|operand| operand.contains("NAN"))
            });
            if row["auxiliary_control_probe"] == true {
                continue;
            }
            if row["adopt"] == true {
                adopted += 1;
                let decoded = index
                    .decode(word, 0, &table)
                    .unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor:?}"));
                assert_eq!(decoded.key, "FFMA2_R_R_FI_R");
                let text = cubit::printer::to_sass_lossless(&decoded);
                if nan_immediate {
                    let expected = format!(
                        "{}, 0x{:08x}F, {}",
                        vendor
                            .unwrap()
                            .rsplit_once(", ")
                            .unwrap()
                            .0
                            .rsplit_once(", ")
                            .unwrap()
                            .0,
                        ((word >> 32) as u32),
                        vendor.unwrap().rsplit_once(", ").unwrap().1,
                    );
                    assert_eq!(text, expected, "{arch}: exact NaN {word:032x}");
                } else {
                    assert_eq!(text, vendor.unwrap(), "{arch}: {word:032x}");
                }
                if row["encode_exact"] == true {
                    let ctrl = cubit::scheduling::format_control_code(
                        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32),
                    );
                    let source = format!("[{ctrl}] {text} ;");
                    cubit::roundtrip_audit::check_semantic_source(&source)
                        .unwrap_or_else(|e| panic!("{arch}: semantic {source}: {e}"));
                    let parsed = cubit::parse_cuasm_line(&source, 0)
                        .unwrap_or_else(|e| panic!("{arch}: parse {source}: {e}"));
                    assert_eq!(
                        cubit::encoder::encode_instruction(&parsed, &table)
                            .unwrap_or_else(|e| panic!("{arch}: encode {source}: {e}")),
                        word
                    );
                    exact += 1;
                }
            } else if word & 0xfff == 0x849 {
                assert!(
                    index.decode(word, 0, &table).is_err(),
                    "{arch}: unclaimed {word:032x}: {vendor:?}"
                );
            }
        }
        for invalid in [
            "FFMA2.INVALID3 R1, R2.F32x2.HI_LO, 2, R3.F32 ;",
            "FFMA2 R1, R2.INVALID3, 2, R3.F32 ;",
            "FFMA2 R1, R2.F32.LO_HI, 2, R3.F32 ;",
            "FFMA2 R1, R2.F32x2.HI_LO, 2, R3.F32.LO_HI ;",
            "FFMA2 R1, R2, 2, R3 ;",
        ] {
            assert!(
                cubit::encoder::encode_instruction(
                    &cubit::parse_cuasm_line(invalid, 0).unwrap(),
                    &table
                )
                .is_err(),
                "{invalid}"
            );
        }
    }
    assert!(adopted >= 2000, "adopt={adopted}");
    assert!(exact >= 500, "exact={exact}");
}

#[test]
fn ffma2_b_immediate_fields_and_provenance() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 5);
        for (modifier, bit) in [("", 0), ("FMZ", 76), ("RM", 78), ("RP", 79), ("FTZ", 80)] {
            let group = &raw["instructions"]["FFMA2_R_R_FI_R"]["mod_groups"][modifier];
            assert_eq!(group["_src"], SRC);
            assert_eq!(
                u128::from_str_radix(
                    group["and_base"].as_str().unwrap().trim_start_matches("0x"),
                    16
                )
                .unwrap(),
                0x849 | if bit > 0 { 1u128 << bit } else { 0 }
            );
            assert_eq!(
                u128::from_str_radix(
                    group["variable_mask"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                    16
                )
                .unwrap(),
                VM
            );
            let fields: Vec<_> = group["fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|field| {
                    assert_eq!(field["_src"], SRC);
                    (
                        field["shift"].as_u64().unwrap(),
                        field["bits"].as_u64().unwrap(),
                        field["extraction"].as_str().unwrap(),
                        field["token_idx"].as_u64().unwrap(),
                    )
                })
                .collect();
            assert_eq!(
                fields,
                [
                    (12, 4, "guard", 0),
                    (16, 8, "reg", 1),
                    (24, 8, "reg", 2),
                    (72, 1, "neg", 2),
                    (73, 1, "abs", 2),
                    (81, 1, "opmod:LO_HI", 2),
                    (82, 1, "opmod:F32", 2),
                    (83, 1, "opmod:NP", 2),
                    (64, 8, "reg", 4),
                    (74, 1, "abs", 4),
                    (75, 1, "neg", 4),
                    (84, 1, "opmod:LO_HI", 4),
                    (85, 1, "opmod:F32", 4),
                    (86, 1, "opmod:NP", 4),
                    (77, 1, "", 3),
                    (87, 4, "", 3),
                    (92, 4, "", 3),
                    (32, 32, "f32", 3),
                ]
            );
        }
        assert!(VM & (1u128 << 91) == 0);
        assert!(VM & (1u128 << 122) == 0);
    }
}
