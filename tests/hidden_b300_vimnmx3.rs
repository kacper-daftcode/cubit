//! Measured VIMNMX3 UR form, including the newly observed U16x2 type.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const SRC: &str = "hidden-b300-vimnmx3-ur-2026-11-07";

#[test]
fn vimnmx3_ur_fixture_decode_render_encode_and_fail_closed() {
    let mut adopt = 0;
    let mut unclaimed = 0;
    let mut auxiliary = 0;
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in hb300_fixture("sm103_vimnmx3_ur_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str();
            if row["auxiliary_control_probe"] == true {
                auxiliary += 1;
            } else if row["adopt"] == true {
                adopt += 1;
                let decoded = index
                    .decode(word, 0, &table)
                    .unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor:?}"));
                assert_eq!(decoded.key, "VIMNMX3_R_R_UR_R_P", "{arch}: {word:032x}");
                let text = cubit::printer::to_sass_lossless(&decoded);
                assert_eq!(text, vendor.unwrap(), "{arch}: {word:032x}");
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
                    word,
                    "{source}"
                );
            } else {
                unclaimed += 1;
                assert!(
                    index.decode(word, 0, &table).is_err(),
                    "{arch}: unclaimed {word:032x}: {vendor:?}"
                );
            }
        }
        for invalid in [
            "VIMNMX3.U16x2 R36, R11, UR10.reuse, R36, !PT ;",
            "VIMNMX3.F32 R36, R11, UR10, R36, !PT ;",
            "VIMNMX3.U16x2 R36, R11, UR10, R36 ;",
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
    assert_eq!(adopt, 734);
    assert_eq!(unclaimed, 628);
    assert_eq!(auxiliary, 82);
}

#[test]
fn vimnmx3_ur_eight_measured_groups_and_provenance() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        let instructions = raw["instructions"].as_object().unwrap();
        let groups = instructions["VIMNMX3_R_R_UR_R_P"]["mod_groups"]
            .as_object()
            .unwrap();
        assert_eq!(groups.len(), 8);
        // 7 on `main`: the plain group is the row session T-23 measured since this candidate's base (the same
        // and_base, mask and fields; this candidate's claim_forbid on bit 123 added to it) and keeps that tag
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 7);
        for name in [
            "",
            "U32",
            "U16x2",
            "S16x2",
            "RELU",
            "RELU,U32",
            "RELU,U16x2",
            "RELU,S16x2",
        ] {
            let group = &groups[name];
            let want = if name.is_empty() { "rows-intalu-2026-11-07" } else { SRC };
            assert_eq!(group["_src"], want, "{name}");
            assert_eq!(
                group["claim_forbid"][0],
                serde_json::json!({"shift": 123, "bits": 1, "values": [1]})
            );
            let fields = group["fields"].as_array().unwrap();
            // the canonical layout writes a tag once per level (tools/tablefmt.py): a field carries `_src` only
            // where it differs from its row's; the plain group is main's row and keeps the tags of its own fields
            assert!(name.is_empty() || fields.iter().all(|f| f.get("_src").map_or(true, |s| s == want)));
            assert!(fields.iter().any(|f| f["shift"] == 87
                && f["bits"] == 3
                && f["extraction"] == "pred"
                && f["token_idx"] == 5));
            assert!(fields.iter().any(|f| f["shift"] == 90
                && f["bits"] == 1
                && f["extraction"] == "neg"
                && f["token_idx"] == 5));
            assert!(fields.iter().any(|f| f["shift"] == 124
                && f["bits"] == 1
                && f["extraction"] == "reuse"
                && f["token_idx"] == 4));
        }
    }
}
