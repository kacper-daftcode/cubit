//! SM120 CCTL register-address forms measured with nvdisasm 13.1 (tools/re_sm120_cctl.py).
//! Every swept `.E` word (guard, address register incl. RZ, signed offset, the eight operations
//! PF1 / PF2 / WB / IV / RS / PML2 / DML2 / RML2) decodes to NVIDIA's text and that text
//! reassembles all 128 bits. The E-less words are in the fixture for the record; their rows are
//! harvest leftovers (CCTL.E.PF1_AR / PF2_AR / PML2_AR) not asserted here.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

fn table() -> IsaTable {
    let path = std::env::var_os("CUBIT_TABLE").map(std::path::PathBuf::from)
        .unwrap_or_else(|| "tables/sm120.json".into());
    IsaTable::load(&path).unwrap()
}

fn check(table: &IsaTable, index: &DecodeIndex, word: u128, vendor: &str) {
    let decoded = index.decode(word, 0, table).unwrap();
    let own = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(own, vendor, "{word:032x}");
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let source = format!("[{control}] {vendor} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    assert!(parsed.hand_sched && parsed.rsd.is_none());
    assert_eq!(cubit::encoder::encode_instruction(&parsed, table).unwrap(), word, "{source}");
}

#[test]
fn every_probed_cctl_e_word_matches_nvidia_and_reassembles_all_128_bits() {
    let table = table();
    let index = DecodeIndex::build(&table);
    let mut n = 0;
    let mut ops = std::collections::BTreeSet::new();
    for line in include_str!("fixtures/sm120_cctl_nvdisasm.jsonl").lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        let vendor = row["nvidia_sass"].as_str().unwrap();
        if !vendor.contains("CCTL.E.") {
            continue;
        }
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
        check(&table, &index, word, vendor);
        ops.insert(vendor.split("CCTL.E.").nth(1).unwrap().split(' ').next().unwrap().to_string());
        n += 1;
    }
    assert_eq!(n, 216);
    assert_eq!(ops.into_iter().collect::<Vec<_>>(), ["DML2", "IV", "PF1", "PF2", "PML2", "RML2", "RS", "WB"]);
}

#[test]
fn the_discard_l2_word_of_the_shipped_moe_kernel_round_trips() {
    // vLLM-Moet moe_l2_discard_sm120.cu, PTX discard.global.L2 -> CCTL.E.RML2 [R2] (image r21, five words)
    let table = table();
    let index = DecodeIndex::build(&table);
    check(&table, &index, 0x0001e40005800100000000000200798fu128, "CCTL.E.RML2 [R2]");
    for source in ["CCTL.E.XYZ [R2] ;", "CCTL.E.RML2 [R256] ;"] {
        if let Ok(parsed) = cubit::parse_sass(source, 0) {
            assert!(cubit::encoder::encode_instruction(&parsed, &table).is_err(), "{source}");
        }
    }
}
