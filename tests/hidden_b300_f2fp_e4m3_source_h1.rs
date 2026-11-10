//! Measured plain scaled E4M3 UNPACK_B rows and scoped fail-closed neighbours.
//!
//! On `main` the row of this measurement is one of the twenty rows of `hidden-b300/f2fp-unpackb` (the lane measured
//! the plain E4M3 row twice, 2026-11-07 and 2026-11-08, to the same fields): the table carries it under the earlier
//! tag, and this file's fixture is a second witness of the row. Two pins follow from that and are not the
//! candidate's: the tag asserted on the row, and three of its seven "unclaimed" neighbours (the E3M2 type, RELU,
//! SATFINITE), which are words of measured sibling rows there and must print the vendor text through them.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

/// The tag the row carries on `main` (the lane's first measurement of it, `tests/hidden_b300_f2fp_unpackb.rs`);
/// this file's own tag `hidden-b300-f2fp-e4m3-source-h1-2026-11-08` is not a source of the table.
const SRC: &str = "f2fp-unpackb-mxfp6-mxfp8-silicon-2026-11-07";
const OWN_TAG: &str = "hidden-b300-f2fp-e4m3-source-h1-2026-11-08";

#[test]
fn sm103a_decode_render_encode_and_fail_closed() {
    check("sm103a");
}

#[test]
fn sm100a_decode_render_encode_and_fail_closed() {
    check("sm100a");
}

fn check(arch: &str) {
    let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
    let index = DecodeIndex::build(&table);
    let fixture = match arch {
        "sm103a" => hb300_fixture("sm103_f2fp_e4m3_source_h1_nvdisasm.jsonl"),
        _ => hb300_fixture("sm100_f2fp_e4m3_source_h1_nvdisasm.jsonl"),
    };
    let (mut adopt, mut unclaimed, mut sibling) = (0, 0, 0);
    for line in fixture.lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
        let decoded = index.decode(word, 0, &table);
        if row["role"] == "adopt" {
            adopt += 1;
            let decoded = decoded.unwrap_or_else(|e| panic!("{arch} {word:032x}: {e}"));
            assert_eq!(decoded.key, "F2FP_R_R_R");
            assert_eq!(decoded.mod_group, "BF16,E4M3,UNPACK_B");
            let text = cubit::printer::to_sass_lossless(&decoded);
            assert_eq!(text, row["nvidia_sass"].as_str().unwrap(), "{word:032x}");
            let ctrl = cubit::scheduling::format_control_code(
                &cubit::scheduling::decode_sched_upper32((word >> 96) as u32),
            );
            let source = format!("[{ctrl}] {text} ;");
            cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
            let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
            assert_eq!(
                cubit::encoder::encode_instruction(&parsed, &table).unwrap(),
                word
            );
        } else {
            unclaimed += 1;
            // never through this row; a measured sibling row of the family may claim the word and must then print
            // exactly what nvdisasm prints for it
            if let Ok(d) = decoded {
                assert_eq!(d.key, "F2FP_R_R_R", "{arch} {word:032x}");
                assert_ne!(d.mod_group, "BF16,E4M3,UNPACK_B", "{arch} unclaimed {word:032x} decodes through the row");
                assert_eq!(cubit::printer::to_sass_lossless(&d), row["nvidia_sass"].as_str().unwrap(), "{arch} {word:032x}");
                sibling += 1;
            }
        }
    }
    assert_eq!((adopt, unclaimed, sibling), (16, 7, 3));
    for invalid in [
        "F2FP.BF16.E4M3.UNPACK_B R11, R2, R5 ;",
        "F2FP.BF16.E4M3.UNPACK_B R11, R2, R5.INVALID6 ;",
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
    let raw: Value = serde_json::from_slice(
        &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 20);
    assert!(raw["_meta"]["provenance"]["sources"].get(OWN_TAG).is_none());
    assert_eq!(
        raw["instructions"]["F2FP_R_R_R"]["mod_groups"]["BF16,E4M3,UNPACK_B"]["_src"],
        SRC
    );
}
