//! Controlled E3M2 pack/merge forms and explicit non-adopted type neighbours.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const SRC: &str = "hidden-b300-f2fp-e3m2-pack-merge-2026-11-08";
static FIXTURE: std::sync::LazyLock<&str> = std::sync::LazyLock::new(|| hb300_fixture("hidden_b300_f2fp_e3m2_merge.jsonl"));

#[test]
fn controlled_decode_render_reencode_and_fail_closed() {
    let mut adopt = 0;
    let mut negative = 0;
    let mut sibling = 0;
    let mut auxiliary = 0;
    let mut preexisting = 0;
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for (line, source) in FIXTURE.lines().enumerate() {
            let row: Value = serde_json::from_str(source).unwrap_or_else(|e| panic!("line {line}: {e}"));
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            if row["auxiliary_control_probe"].as_bool().unwrap() {
                auxiliary += 1;
                continue;
            }
            if !row["adopt"].as_bool().unwrap() {
                let other_e4m3 = row["kind"] == "type-window"
                    && row["labels"][0].as_str().is_some_and(|label| label == "type[87:83]=16");
                if other_e4m3 {
                    let decoded = index.decode(word, 0, &table).unwrap_or_else(|e|
                        panic!("{arch}: pre-existing E4M3 regressed {word:032x}: {e}"));
                    assert_eq!(cubit::printer::to_sass_lossless(&decoded),
                        row["nvidia_sass"].as_str().unwrap());
                    preexisting += 1;
                    continue;
                }
                negative += 1;
                // Session T-26, batch 4: this candidate was written on a table that had it alone. With its two sibling
                // pack-merge candidates on the same key a neighbour of the type window can be a sibling's measured
                // word: it must then print the vendor text through the sibling's row -- never through a group of this
                // candidate.
                if let Ok(d) = index.decode(word, 0, &table) {
                    assert!(!d.mod_group.split(',').any(|m| m == "E3M2"),
                        "{arch}: {word:032x} decodes through this candidate's group {}", d.mod_group);
                    assert_eq!(cubit::printer::to_sass_lossless(&d), row["nvidia_sass"].as_str().unwrap(),
                        "{arch}: sibling word {word:032x}");
                    sibling += 1;
                }
                continue;
            }
            adopt += 1;
            let decoded = index.decode(word, 0, &table).unwrap_or_else(|e|
                panic!("{arch}: {word:032x}: {e}"));
            let text = cubit::printer::to_sass_lossless(&decoded);
            assert_eq!(text, row["nvidia_sass"].as_str().unwrap(), "{arch}: {word:032x}");
            let ctrl = cubit::scheduling::format_control_code(
                &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let sass = format!("[{ctrl}] {text} ;");
            cubit::roundtrip_audit::check_semantic_source(&sass).unwrap_or_else(|e| panic!("{arch}: {e}"));
            let parsed = cubit::parse_cuasm_line(&sass, 0).unwrap_or_else(|e| panic!("{arch}: {sass}: {e}"));
            let encoded = cubit::encoder::encode_instruction(&parsed, &table)
                .unwrap_or_else(|e| panic!("{arch}: {sass}: {e}"));
            assert_eq!(encoded, word, "{arch}: {sass}");
        }
    }
    assert_eq!(sibling, 8, "neighbours that are measured words of the sibling pack-merge candidates (both tables)");
    assert_eq!(adopt, 288, "two architecture tables, 144 named E3M2 witnesses each");
    assert_eq!(negative, 170, "E2M1/S2_6/other/neighbour candidates stay unclaimed");
    assert_eq!(auxiliary, 58, "control-plane-only probes are not semantic roundtrips");
    assert_eq!(preexisting, 2, "the already-known E4M3 type-window form stays correct");
}

#[test]
fn four_e3m2_modifier_groups_and_provenance() {
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
        ).unwrap();
        let provenance = &raw["_meta"]["provenance"];
        assert_eq!(provenance["sources"][SRC]["rows"], 8);
        let groups = raw["instructions"]["F2FP_R_R_R_R"]["mod_groups"].as_object().unwrap();
        for name in ["SATFINITE,E3M2,F32,PACK_AB_MERGE_C",
                     "SATFINITE,RELU,E3M2,F32,PACK_AB_MERGE_C",
                     "SATFINITE,E3M2,F32,PACK_AB_MERGE_C,RS",
                     "SATFINITE,RELU,E3M2,F32,PACK_AB_MERGE_C,RS"] {
            let group = &groups[name];
            assert_eq!(group["_src"], SRC, "{name}");
            for (shift, bits, extraction, token) in [
                (12, 4, "guard", 0), (16, 8, "reg", 1), (24, 8, "reg", 2),
                (122, 1, "reuse", 2), (32, 8, "reg", 3), (123, 1, "reuse", 3),
                (64, 8, "reg", 4), (124, 1, "reuse", 4)] {
                assert!(group["fields"].as_array().unwrap().iter().any(|f|
                    f["shift"] == shift && f["bits"] == bits
                    && f["extraction"] == extraction && f["token_idx"] == token
                    // the canonical layout writes a tag once per level (tools/tablefmt.py): a field carries `_src` only where it
                    // differs from its row's -- absent or equal (the candidate's file tagged every field)
                    && f.get("_src").map_or(true, |s| s == SRC)),
                    "{arch}: {name}: {extraction}@{shift}/{bits}");
            }
        }
        // Session T-26, batch 4: with the sibling candidates on the table their types assemble -- through their own
        // rows, not through a group of this candidate (the candidate alone pinned "does not assemble").
        let index = DecodeIndex::build(&table);
        for suffix in ["E2M1", "S2_6"] {
            let text = format!("F2FP.SATFINITE.{suffix}.F32.PACK_AB_MERGE_C R8, R9, R8, R10 ;");
            let word = cubit::encoder::encode_instruction(&cubit::parse_cuasm_line(&text, 0).unwrap(), &table)
                .unwrap_or_else(|e| panic!("{arch}: {text}: {e}"));
            let d = index.decode(word, 0, &table).unwrap();
            assert!(d.mod_group.split(',').any(|m| m == suffix) && !d.mod_group.split(',').any(|m| m == "E3M2"),
                "{arch}: {text} -> {}", d.mod_group);
        }
    }
}
