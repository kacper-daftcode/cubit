//! HIDDEN-B300: compressed-matrix LDSM forms on SM103a and SM100a.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const SRC: &str = "hidden-b300-ldsm-unpack-2026-11-07";
const PAIRS: [(&str, &str); 8] = [
    ("2,M816,U4x16P64TO8", "ARI"),
    ("2,M816,U4x16P64TO8", "AURI"),
    ("2,M816,U4x16P64TO8", "ARURI"),
    ("MT1616,U4x16P64TO8", "ARI"),
    ("MT1616,U4x16P64TO8", "AURI"),
    ("MT1616,U4x16P64TO8", "ARURI"),
    ("2,M816,U6x16P32TO8", "AURI"),
    ("MT1616,U6x16P32TO8", "AURI"),
];

#[test]
fn ldsm_unpack_fixture_decode_render_encode_and_fail_closed() {
    let mut adopted = [0usize; 8];
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in hb300_fixture("sm103_ldsm_unpack_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            if row["auxiliary_control_probe"] == true {
                continue;
            }
            let vendor = row["nvidia_sass"].as_str();
            if row["adopt"] == true {
                let decoded = index
                    .decode(word, 0, &table)
                    .unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor:?}"));
                assert!(decoded.key.starts_with("LDSM_R_"), "{arch}: {word:032x}");
                let text = cubit::printer::to_sass_lossless(&decoded);
                assert_eq!(text, vendor.unwrap(), "{arch}: {word:032x}");
                let corpus_name = text.split('.').nth(1).unwrap();
                let addr = if text.contains("+UR") {
                    "ARURI"
                } else if text.contains("[UR") {
                    "AURI"
                } else {
                    "ARI"
                };
                let shape = match corpus_name {
                    "U4x16P64TO8" if text.contains(".M816.2 ") => "2,M816,U4x16P64TO8",
                    "U4x16P64TO8" if text.contains(".MT1616 ") => "MT1616,U4x16P64TO8",
                    "U6x16P32TO8" if text.contains(".M816.2 ") => "2,M816,U6x16P32TO8",
                    "U6x16P32TO8" if text.contains(".MT1616 ") => "MT1616,U6x16P32TO8",
                    other => panic!("unexpected shape {other}"),
                };
                adopted[PAIRS.iter().position(|p| *p == (shape, addr)).unwrap()] += 1;
                let ctrl = cubit::scheduling::format_control_code(
                    &cubit::scheduling::decode_sched_upper32((word >> 96) as u32),
                );
                let source = format!("[{ctrl}] {text} ;");
                cubit::roundtrip_audit::check_semantic_source(&source)
                    .unwrap_or_else(|e| panic!("{arch}: semantic {source}: {e}"));
                if row["encode_exact"] == true {
                    let parsed = cubit::parse_cuasm_line(&source, 0)
                        .unwrap_or_else(|e| panic!("{arch}: parse {source}: {e}"));
                    assert_eq!(
                        cubit::encoder::encode_instruction(&parsed, &table)
                            .unwrap_or_else(|e| panic!("{arch}: encode {source}: {e}")),
                        word,
                        "{source}"
                    );
                }
            } else if row["core_negative"] == true {
                assert!(
                    index.decode(word, 0, &table).is_err(),
                    "{arch}: unclaimed {word:032x}: {vendor:?}"
                );
            }
        }
        for invalid in [
            "LDSM.U4x16P64TO8.INVALID3 R1, [R2] ;",
            "LDSM.U4x16P64TO8.M832.2 R1, [R2] ;",
            "LDSM.U6x16P32TO8.MT1616 R1, [R2] ;",
            "LDSM.U4x16P64TO8.MT1616 R1, R2 ;",
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
    assert!(
        adopted.iter().all(|count| *count >= 20),
        "insufficient coverage: {adopted:?}"
    );
}

#[test]
fn ldsm_unpack_eight_measured_rows_and_provenance() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        let instructions = raw["instructions"].as_object().unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 8);
        for (shape, addr) in PAIRS {
            let key = format!("LDSM_R_{addr}");
            let group = &instructions[&key]["mod_groups"][shape];
            assert_eq!(group["_src"], SRC);
            let fields: Vec<_> = group["fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|field| {
                    // the canonical layout writes a tag once per level (tools/tablefmt.py): a field carries `_src` only where it
                    // differs from its row's -- absent or equal (the candidate's file tagged every field)
                    assert!(field.get("_src").map_or(true, |s| s == SRC));
                    (
                        field["shift"].as_u64().unwrap(),
                        field["bits"].as_u64().unwrap(),
                        field["extraction"].as_str().unwrap(),
                        field["token_idx"].as_u64().unwrap(),
                    )
                })
                .collect();
            let expected = match addr {
                "ARI" => vec![
                    (12, 4, "guard", 0),
                    (16, 8, "reg", 1),
                    (24, 8, "sub_r0", 2),
                    (40, 24, "sub_imm1", 2),
                ],
                "AURI" => vec![
                    (12, 4, "guard", 0),
                    (16, 8, "reg", 1),
                    (32, 8, "sub_ur0", 2),
                    (40, 24, "sub_imm1", 2),
                ],
                _ => vec![
                    (12, 4, "guard", 0),
                    (16, 8, "reg", 1),
                    (24, 8, "sub_r0", 2),
                    (32, 8, "sub_ur1", 2),
                    (40, 24, "sub_imm1", 2),
                ],
            };
            assert_eq!(fields, expected);
        }
    }
}
