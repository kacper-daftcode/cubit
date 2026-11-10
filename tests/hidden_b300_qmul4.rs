//! SM103a/SM100a QMUL4: production FP4 x FP8 forms and fail-closed lattice.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const SRC: &str = "hidden-b300-qmul4-sm103-sm100-2026-11-07";
const KEY: &str = "QMUL4.E4M3x4.E2M1x4.E4M3x4_R_R_R";

#[test]
fn qmul4_fixture_decode_render_encode_and_neighbors() {
    let mut adopt = 0;
    let mut unclaimed = 0;
    let mut auxiliary_control_probes = 0;
    for arch in ["sm103a", "sm100a"] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in hb300_fixture("sm103_qmul4_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str();
            if row["auxiliary_control_probe"] == true {
                auxiliary_control_probes += 1;
            } else if row["adopt"] == true {
                adopt += 1;
                let decoded = index
                    .decode(word, 0, &table)
                    .unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor:?}"));
                let text = cubit::printer::to_sass_lossless(&decoded);
                assert_eq!(
                    text,
                    vendor.unwrap(),
                    "{arch}: {word:032x}: {}",
                    decoded.key
                );
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
        // A selector is mandatory: zero is B3210, never an absent-suffix default.
        assert!(cubit::encoder::encode_instruction(
            &cubit::parse_cuasm_line("QMUL4.E4M3x4.E2M1x4.E4M3x4.SATFINITE R22, R11, R4 ;", 0)
                .unwrap(),
            &table
        )
        .is_err());
    }
    assert_eq!(
        adopt, 282,
        "unique measured words covering both selected arch tables"
    );
    assert_eq!(
        unclaimed, 1490,
        "all other named siblings and unnamed holes stay unclaimed"
    );
    assert_eq!(
        auxiliary_control_probes, 30,
        "control-plane experiments are neither semantic roundtrips nor core-mask negatives"
    );
}

#[test]
fn qmul4_two_measured_groups_and_provenance() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        let instructions = raw["instructions"].as_object().unwrap();
        let ins = &instructions[KEY];
        assert_eq!(ins["_src"], SRC);
        // 3 on `main`: the two groups of this key and the one row of the encode-only twin key
        // `<op>.SATFINITE_R_R_R`, which carries the same tag (a source counts every row that resolves to it)
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 3);
        let groups = ins["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), 2);
        for name in ["", "SATFINITE"] {
            let fields = groups[name]["fields"].as_array().unwrap();
            assert_eq!(groups[name]["_src"], SRC);
            // the canonical layout writes a tag once per level (tools/tablefmt.py): a field carries `_src` only
            // where it differs from its row's
            assert!(fields.iter().all(|f| f.get("_src").map_or(true, |s| s == SRC)));
        }
        let fields = groups[""]["fields"].as_array().unwrap();
        for (shift, bits, extraction, token) in [
            (12, 4, "guard", 0),
            (16, 8, "reg", 1),
            (24, 8, "reg", 2),
            (73, 1, "neg", 2),
            (72, 1, "abs", 2),
            (122, 1, "reuse", 2),
            (74, 3, "qmul4_sel", 2),
            (32, 8, "reg", 3),
            (63, 1, "neg", 3),
            (62, 1, "abs", 3),
            (123, 1, "reuse", 3),
            (59, 3, "qmul4_sel", 3),
        ] {
            assert!(
                fields.iter().any(|f| f["shift"] == shift
                    && f["bits"] == bits
                    && f["extraction"] == extraction
                    && f["token_idx"] == token),
                "{arch}: missing {extraction}@{shift}/{bits}, token {token}"
            );
        }
        assert_eq!(
            instructions
                .keys()
                .filter(|key| key.starts_with("QMUL4"))
                .count(),
            2,
            "only the base key and its SATFINITE encode-only spelling are present"
        );
        let sat = &instructions["QMUL4.E4M3x4.E2M1x4.E4M3x4.SATFINITE_R_R_R"];
        assert_eq!(sat["encode_only"], true);
        // the canonical layout writes a note once per level too: the twin key has one row, so its note sits on
        // the key -- the two rows are compared with the note resolved
        let mut twin = sat["mod_groups"][""].clone();
        if twin.get("_note").is_none() {
            twin["_note"] = sat["_note"].clone();
        }
        assert_eq!(twin, groups["SATFINITE"]);
    }
}
