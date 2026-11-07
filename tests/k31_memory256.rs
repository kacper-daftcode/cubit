//! Exact LDG/STG 256-bit descriptor forms in FlashMLA.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const SRC: &str = "k31-memory256-flashmla-2026-11-07";

#[test]
fn every_descriptor_witness_round_trips() {
    let mut census = 0u64;
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_memory256_nvdisasm.jsonl").lines() {
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
                decoded.key,
                row["form"].as_str().unwrap(),
                "{arch}: {word:032x}"
            );
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
            let is_efl2 = decoded.key == "LDG.E.NA.EFL2.LTC256B.256.CONSTANT_R_R_dARI";
            let even_base = ((word >> 24) & 1) == 0;
            let refusal = match (arch, is_efl2, even_base) {
                ("sm103a", true, true) => Some("BUG-060"),
                ("sm103a", false, false) if decoded.key.starts_with("LDG.E.") => Some("BUG-077"),
                _ => None,
            };
            if let Some(bug) = refusal {
                // BUG-060 is word-level and must remain fail-closed on sm_103a.
                // Decoding and odd-address encoding remain exact; sm_100 has no such guard.
                let error = cubit::encoder::encode_instruction(&parsed, &table)
                    .expect_err("sm_103a descriptor parity guard must fire");
                assert!(error.to_string().contains(bug), "{source}: {error}");
                continue;
            }
            assert_eq!(
                cubit::encoder::encode_instruction(&parsed, &table)
                    .unwrap_or_else(|e| panic!("{source}: {e}")),
                word,
                "{source}"
            );
            census += row["occurrences"].as_u64().unwrap();
        }
    }
    assert_eq!(census, 644);
}

#[test]
fn exact_forms_and_offsets_are_registered() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 6);
        for (key, opcode, count) in [
            ("LDG.E.NA.EFL2.LTC256B.256.CONSTANT_R_R_dARI", 0x97e, 17),
            ("LDG.E.NA.ENL2.LTC256B.256.CONSTANT_R_R_dARI", 0x97e, 17),
            ("LDG.E.NA.ENL2.LTC256B.256.CONSTANT_R_R_dARI_II", 0x97e, 17),
            ("LDG.E.EF.ENL2.LTC256B.256.CONSTANT_R_R_dARI", 0x97e, 17),
            ("LDG.E.ENL2.LTC256B.256.CONSTANT_R_R_dARI", 0x97e, 17),
            ("STG.E.NA.EFL2.256_dARI_R_R", 0x97f, 19),
        ] {
            let entry = &raw["instructions"][key];
            assert_eq!(entry["_src"], SRC, "{key}");
            assert!(!entry["base_op"].as_str().unwrap().is_empty());
            let fields = entry["mod_groups"][""]["fields"].as_array().unwrap();
            assert!(fields.iter().all(|f| f["_src"] == SRC));
            assert!(fields.iter().any(|f| f["shift"] == 40
                && f["bits"] == count
                && f["extraction"] == "sub_imm2_shr5"));
            assert!(
                raw["instructions"][key]["mod_groups"][""]["and_base"]
                    .as_str()
                    .unwrap()
                    .ends_with(&format!("{opcode:x}"))
            );
        }
        let trailer = raw["instructions"]["LDG.E.NA.ENL2.LTC256B.256.CONSTANT_R_R_dARI_II"]
            ["mod_groups"][""]["fields"]
            .as_array()
            .unwrap();
        assert!(trailer
            .iter()
            .any(|f| f["shift"] == 57 && f["bits"] == 7 && f["extraction"] == "imm"));
        assert!(trailer
            .iter()
            .any(|f| f["shift"] == 72 && f["bits"] == 1 && f["extraction"] == "imm_shr7"));
    }
}
