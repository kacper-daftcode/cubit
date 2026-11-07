//! K3.1 trtllm-gen FSETP GT/GEU FTZ AND: the R_R and R_FI forms.
//! H supplies all production words; independent SM103/SM100 probes cover the
//! exact modifier axes.  Donor family: G's measured 96-group-per-form SM120 rows.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const SRC: &str = "k31-fsetp-trtllm-2026-11-07";
const ALU_REST_SRC: &str = "k31-alu-tail-flashmla-2026-11-07";
const KEYS: [&str; 2] = ["FSETP_P_P_R_R_P", "FSETP_P_P_R_FI_P"];

fn fixture() -> Vec<Value> {
    include_str!("fixtures/k31_fsetp_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn rtt(table: &IsaTable, index: &DecodeIndex, word: u128, vendor: &str) {
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}: {vendor}"));
    assert!(KEYS.contains(&decoded.key.as_str()), "{word:032x}: {}: {vendor}", decoded.key);
    let lossless = cubit::printer::to_sass_lossless(&decoded);
    // Vendor display may elide scheduling-cache .reuse; lossless print keeps
    // every physical bit for the full-word re-encode (the two APIs have distinct jobs).
    assert_eq!(&cubit::printer::to_sass(&decoded), vendor, "{word:032x}");
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let text = format!("[{control}] {lossless} ;");
    cubit::roundtrip_audit::check_semantic_source(&text).unwrap();
    let parsed = cubit::parse_cuasm_line(&text, 0).unwrap();
    assert_eq!(cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{text}: {e}")), word, "{text}");
}

#[test]
fn all_witnesses_and_field_probes_round_trip() {
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        let (mut production, mut occurrences, mut probes) = (0, 0, 0);
        for row in fixture() {
            if row["arch"] != target && row.get("occurrences").is_none() { continue; }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            rtt(&table, &index, word, row["nvidia_sass"].as_str().unwrap());
            if row.get("occurrences").is_some() {
                production += 1;
                occurrences += row["occurrences"].as_u64().unwrap();
            } else { probes += 1; }
        }
        assert_eq!(production, 2331, "{arch}");
        assert_eq!(occurrences, 4736, "{arch}");
        assert_eq!(probes, 78, "{arch}: deduplicated field probes");
    }
}

#[test]
fn measured_groups_and_aliases_are_complete() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        let pro = &raw["_meta"]["provenance"];
        assert_eq!(pro["sources"][SRC]["rows"], 192);
        for key in KEYS {
            let entry = &raw["instructions"][key];
            assert_eq!(entry["_src"], SRC);
            let groups = entry["mod_groups"].as_object().unwrap();
            assert_eq!(groups.len(), 96, "{arch}: {key}");
            for (name, g) in groups {
                let want_src = if key == "FSETP_P_P_R_FI_P" && name == "AND,EQ" { ALU_REST_SRC } else { SRC };
                assert_eq!(g["_src"], want_src, "{arch}: {key}::{name}");
                let actual = g["fields"].as_array().unwrap().iter().fold(0u128, |m, f| m | (((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap()));
                let declared = u128::from_str_radix(g["variable_mask"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
                assert_eq!(declared, actual, "{arch}: {key}");
            }
        }
        let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
        assert_eq!(aliases["FSETP_P_P_R_II_P"], KEYS[1]);
        assert_eq!(aliases["FSETP_P_P_II_II_P"], KEYS[1]);
        assert_eq!(aliases["FSETP_P_P_II_R_P"], KEYS[0]);
        assert!(raw["instructions"]["DSETP_P_P_R_R_P"]["mod_groups"]["AND,EQ"]["_src"].is_null());
    }
}
