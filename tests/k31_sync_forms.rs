//! K3.1 SYNCS/ARRIVES/UTMALDG/U? helper production forms.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::collections::BTreeMap;

const SRC: &str = "k31-synchronisation-forms-2026-11-07";
const EXPECTED: [(&str, u64, u64); 7] = [
    ("SYNCS", 103, 174),
    ("ARRIVES", 103, 174),
    ("USETMAXREG", 2, 30),
    ("UTMALDG", 9, 56),
    ("UGETNEXTWORKID", 26, 328),
    ("BAR.SYNC", 1, 48),
    ("UGETNEXTWORKID.BROADCAST", 2, 82),
];

#[test]
fn every_small_form_round_trips() {
    let mut census: BTreeMap<(String, String, String), u64> = BTreeMap::new();
    for (arch, target) in [("sm103a", "SM103"), ("sm100a", "SM100")] {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for line in include_str!("fixtures/k31_sync_forms_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["arch"] != target {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(word, 0, &table)
                .unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor}"));
            let text = cubit::printer::to_sass_lossless(&decoded);
            assert_eq!(text, vendor, "{arch}: {word:032x}: {}", decoded.key);
            let ctrl = cubit::scheduling::format_control_code(
                &cubit::scheduling::decode_sched_upper32((word >> 96) as u32),
            );
            let source = format!("[{ctrl}] {vendor} ;");
            cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
            let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
            assert_eq!(
                cubit::encoder::encode_instruction(&parsed, &table)
                    .unwrap_or_else(|e| panic!("{source}: {e}")),
                word,
                "{source}"
            );
            let op = row["op"].as_str().unwrap().to_owned();
            census.insert(
                (
                    target.to_owned(),
                    op,
                    row["word"].as_str().unwrap().to_owned(),
                ),
                row["occurrences"].as_u64().unwrap(),
            );
        }
    }
    for (op, n, occ) in EXPECTED {
        let total = census
            .iter()
            .filter(|((_, name, _), _)| *name == op)
            .count() as u64;
        let words: u64 = census
            .iter()
            .filter(|((_, name, _), _)| *name == op)
            .map(|(_, occ)| *occ)
            .sum();
        assert_eq!(total, n, "{op}");
        assert_eq!(words, occ, "{op}");
    }
}

#[test]
fn all_helper_rows_have_registered_measurements() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 6);
        let ins = raw["instructions"].as_object().unwrap();
        for key in [
            "ARRIVES_ARURI",
            "USETMAXREG_UP_II",
            "UGETNEXTWORKID_AURI_AURI",
            "BAR.SYNC.DEFER_BLOCKING_II",
            "UTMALDG.4D.MULTICAST.2CTA_AURI_AURI_UR",
            "SYNCS.ARRIVE.TRANS64.RED.A0T1_R_ARURI_R",
        ] {
            assert_eq!(ins[key]["_src"], SRC, "{arch}: {key}");
            for (name, g) in ins[key]["mod_groups"].as_object().unwrap() {
                if key == "UGETNEXTWORKID_AURI_AURI" && name == "BROADCAST" {
                    assert_eq!(g["_src"], Value::Null);
                } else if key == "ARRIVES_ARURI" && name == "64,ARVCNT,LDGSTSBAR" {
                    assert_eq!(g["_src"], "k31-alu-tail-flashmla-2026-11-07");
                } else {
                    assert_eq!(g["_src"], SRC, "{arch}: {key}");
                }
            }
        }
        assert_eq!(
            raw["_meta"]["key_aliases"]["USETMAXREG_U_UP_II"],
            "USETMAXREG_UP_II"
        );
        assert!(
            raw["instructions"]["BAR.SYNC.DEFER_BLOCKING_II"]["mod_groups"]["DEFER_BLOCKING,SYNC"]
                ["fields"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["shift"] == 32 && f["extraction"] == "reg" && f["token_idx"] == 2)
        );
        assert_eq!(
            ins["UTMALDG_AURI_AURI_II"]["mod_groups"]
                .as_object()
                .unwrap()
                .len(),
            11
        );
        assert_eq!(ins["UTMALDG_AURI_AURI_II"]["mod_groups"]["1D"]["_src"], "k31-utma1d-flashkda-2026-11-07");
        for group in ["2D,GATHER4", "2CTA,2D,GATHER4", "2CTA,5D"] {
            assert_eq!(ins["UTMALDG_AURI_AURI_II"]["mod_groups"][group]["_src"], "k31-utma-flashmla-2026-11-07");
        }
        assert_eq!(ins["SYNCS_R_ARURI_R"]["_src"], Value::Null);
    }
}
