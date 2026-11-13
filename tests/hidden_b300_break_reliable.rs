//! Measured production BREAK.RELIABLE P,B; CPU text/roundtrip, no execution.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-break-reliable-production-2026-11-12";

fn arches() -> [(&'static str, &'static str); 2] {
    [("sm103a", hb300_fixture("sm103a_break_reliable_nvdisasm.jsonl")),
     ("sm100a", hb300_fixture("sm100a_break_reliable_nvdisasm.jsonl"))]
}

fn model() -> &'static Value {
    static MODEL: OnceLock<Value> = OnceLock::new();
    MODEL.get_or_init(|| serde_json::from_str(include_str!("fixtures/break-reliable-model.json")).unwrap())
}

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLES: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLES.get_or_init(|| arches().iter().map(|(arch, _)| {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    }).collect())
}

fn word(row: &Value) -> u128 {
    u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap()
}

#[test]
fn production_and_complete_fields_decode_render_and_reencode() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let (mut production, mut adopt) = (0, 0);
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["role"] != "adopt" { continue; }
            adopt += 1;
            production += usize::from(row["generation"] == "production");
            let word = word(&row);
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index.decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!((decoded.key.as_str(), decoded.mod_group.as_str()), ("BREAK_P_B", "RELIABLE"));
            let rendered = cubit::printer::to_sass(&decoded);
            assert_eq!(rendered, vendor, "{arch} {word:032x}");
            let lossless = cubit::printer::to_sass_lossless(&decoded);
            let ctrl = cubit::scheduling::format_control_code(
                &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
            let parsed = cubit::parse_cuasm_line(&format!("[{ctrl}] {lossless} ;"), 0).unwrap();
            let encoded = cubit::encoder::encode_instruction(&parsed, table).unwrap();
            assert_eq!(encoded, word & !(7u128 << 125), "{arch} {word:032x} {vendor}");
        }
        assert_eq!(production, 2, "{arch}: both production witnesses");
        assert_eq!(adopt, model()["adopt_per_target"].as_u64().unwrap());
    }
}

#[test]
fn exact_fields_claims_and_provenance() {
    let truthful = model();
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let row = &raw["instructions"]["BREAK_P_B"]["mod_groups"]["RELIABLE"];
        assert_eq!(row["_src"], SOURCE);
        assert_eq!(row["count"], Value::Null);
        assert_eq!(raw["instructions"]["BREAK_P_B"]["scheduling"], truthful["scheduling"]);
        let mut mask = 0u128;
        for field in row["fields"].as_array().unwrap() {
            let lo = field["shift"].as_u64().unwrap() as u32;
            let size = field["bits"].as_u64().unwrap() as u32;
            mask |= ((1u128 << size) - 1) << lo;
            assert!(truthful["fields"].as_array().unwrap().contains(field), "{arch}: {field}");
        }
        assert_eq!(mask, u128::from_str_radix(row["variable_mask"].as_str().unwrap()
            .trim_start_matches("0x"), 16).unwrap());
        assert_eq!(row["variable_mask"], truthful["variable_mask"]);
        assert_eq!(row["and_base"], truthful["and_base"]);
        assert_eq!(row["claim_forbid"], truthful["claim_forbid"]);
        assert!(row["claim_forbid"].as_array().unwrap().iter().any(|claim|
            claim["shift"] == 87 && claim["bits"] == 4 && claim["values"][0] == 7));
        for bit in [122, 123, 124] {
            assert!(row["claim_forbid"].as_array().unwrap().iter().any(|claim|
                claim["shift"] == bit && claim["bits"] == 1 && claim["values"][0] == 1));
        }
    }
}

#[test]
fn omitted_pt_and_unclaimed_scope_fail_closed() {
    for (position, (arch, fixture)) in arches().iter().enumerate() {
        let (table, index) = &tables()[position];
        let (mut checked, mut controls, mut omitted) = (0, 0, 0);
        for line in fixture.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["role"] == "adopt" { continue; }
            if row["role"] == "control" { controls += 1; continue; }
            checked += 1;
            if row["role"] == "claim_forbidden"
                && row["generation"] == "output_predicate" && row["label"] == "output-predicate:7" {
                omitted += 1;
                let decoded = index.decode(word(&row), 0, table)
                    .unwrap_or_else(|error| panic!("{arch}: BREAK_B control: {error}"));
                assert_eq!((decoded.key.as_str(), decoded.mod_group.as_str()), ("BREAK_B", "RELIABLE"));
                assert_eq!(cubit::printer::to_sass(&decoded), row["nvidia_sass"]);
                continue;
            }
            if let Ok(decoded) = index.decode(word(&row), 0, table) {
                assert_ne!(decoded.key, "BREAK_P_B", "{arch}: wrong overmatch {row}");
            }
        }
        assert_eq!(omitted, 1, "{arch}: explicit PT omission control");
        assert_eq!(checked, model()["unique_words"].as_u64().unwrap()
            - model()["adopt_per_target"].as_u64().unwrap()
            - model()["role_counts"]["control"].as_u64().unwrap());
        assert_eq!(controls, model()["role_counts"]["control"].as_u64().unwrap());
    }
}
