//! HIDDEN-B300: measured MOVM namespace rows for SM103a and SM100a.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const SRC: &str = "hidden-b300-movm-2026-11-07";
const VM: u128 = 0xf7ff07fffffffffffffff000u128;
const LANES: [(&str, u32); 6] = [
    ("MOVM.16.MT88_R_R", 0),
    ("MOVM.U4TO8.MT88_R_R", 1),
    ("MOVM.16.M832_R_R", 8),
    ("MOVM.U4TO8.M832_R_R", 9),
    ("MOVM.16.M864_R_R", 16),
    ("MOVM.U4TO8.M864_R_R", 17),
];

#[test]
fn movm_fixture_decode_render_encode_and_fail_closed() {
    let mut adopted = [0usize; 6];
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/sm103_movm_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            if row["auxiliary_control_probe"] == true {
                continue;
            }
            let vendor = row["nvidia_sass"].as_str();
            if row["adopt"] == true {
                let lane = ((word >> 75) & 31) as usize;
                let position = LANES.iter().position(|(_, ns)| *ns as usize == lane).unwrap();
                adopted[position] += 1;
                let decoded = index.decode(word, 0, &table)
                    .unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor:?}"));
                assert_eq!(decoded.key, LANES[position].0, "{arch}: {word:032x}");
                let text = cubit::printer::to_sass_lossless(&decoded);
                assert_eq!(text, vendor.unwrap(), "{arch}: {word:032x}");
                let ctrl = cubit::scheduling::format_control_code(
                    &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
                let source = format!("[{ctrl}] {text} ;");
                cubit::roundtrip_audit::check_semantic_source(&source)
                    .unwrap_or_else(|e| panic!("{arch}: semantic {source}: {e}"));
                if row["encode_exact"] == true {
                    let parsed = cubit::parse_cuasm_line(&source, 0)
                        .unwrap_or_else(|e| panic!("{arch}: parse {source}: {e}"));
                    assert_eq!(cubit::encoder::encode_instruction(&parsed, &table)
                        .unwrap_or_else(|e| panic!("{arch}: encode {source}: {e}")), word, "{source}");
                }
            } else {
                assert!(index.decode(word, 0, &table).is_err(),
                    "{arch}: unclaimed {word:032x}: {vendor:?}");
            }
        }
        for invalid in [
            "MOVM.INVALID5.MT88 R1, R2 ;",
            "MOVM.16.INVALID3 R1, R2 ;",
            "MOVM.U4TO8.INVALID3 R1, R2 ;",
            "MOVM.16.M832 R1, -R2 ;",
        ] {
            assert!(cubit::encoder::encode_instruction(
                &cubit::parse_cuasm_line(invalid, 0).unwrap(), &table).is_err(), "{invalid}");
        }
    }
    assert!(adopted.iter().all(|count| *count >= 96), "coverage by lane: {adopted:?}");
}

#[test]
fn movm_six_measured_rows_and_provenance() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        let instructions = raw["instructions"].as_object().unwrap();
        assert_eq!(instructions.keys().filter(|key| key.starts_with("MOVM")).count(), 6);
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 6);
        for (key, ns) in LANES {
            let group = &instructions[key]["mod_groups"][""];
            assert_eq!(group["_src"], SRC);
            assert_eq!(u128::from_str_radix(group["and_base"].as_str().unwrap()
                .trim_start_matches("0x"), 16).unwrap(), 0x23au128 | ((ns as u128) << 75));
            assert_eq!(u128::from_str_radix(group["variable_mask"].as_str().unwrap()
                .trim_start_matches("0x"), 16).unwrap(), VM);
            let fields: Vec<_> = group["fields"].as_array().unwrap().iter().map(|field| {
                assert_eq!(field["_src"], SRC);
                (field["shift"].as_u64().unwrap(), field["bits"].as_u64().unwrap(),
                 field["extraction"].as_str().unwrap(), field["token_idx"].as_u64().unwrap())
            }).collect();
            assert_eq!(fields, [(12, 4, "guard", 0), (16, 8, "reg", 1), (24, 8, "reg", 2)]);
        }
    }
}
