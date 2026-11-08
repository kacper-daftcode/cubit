//! SM120 UBLKCP.G.S / UBLKCP.S.S (the bulk copy's direction code [74:73]: 2 = shared -> global, the TMA bulk store
//! `cp.async.bulk.global.shared::cta.bulk_group`; 3 = shared -> shared), measured with nvdisasm 13.1
//! (tools/probes/re_sm120_ublkcp_dir.py, fixture tests/fixtures/sm120_ublkcp_dir_nvdisasm.jsonl). The two letters are an
//! ORDERED pair (destination, source); a mod-group name is the sorted modifier set, so these two directions live on
//! dotted keys next to the plain key's `G,G` / `G,S` (codes 0 / 1). Every probed form word decodes to its dotted key,
//! prints NVIDIA's text and reassembles all 128 bits; the lattice (the unclaimed `.MULTICAST` / `.LTC64B` / `.LTC128B`
//! / `.SEQUENCED` / `.DST_G_BYTE_MASK` groups, the text-inert bits, the illegal bits 77-80 and the cleared frame bit)
//! never renders as another text. The encoder serves `UBLKCP.G.S` from the store row only: before these rows the text
//! assembled to the load word (`UBLKCP.S.G`, code 1) through the plain key's sorted `G,S` group -- a silent
//! wrong-direction encode -- and a table without the store row must refuse the text, not mint the load.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "ublkcp-dir-sm120-2026-11-08";
const KEYS: [&str; 4] = ["UBLKCP.G.S_AURI_AURI_UR", "UBLKCP.G.S_AURI_AURI_UR_II", "UBLKCP.S.S_AURI_AURI_UR", "UBLKCP.S.S_AURI_AURI_UR_II"];
const PLAIN_KEY: &str = "UBLKCP_AURI_AURI_UR";
const CTRL: u128 = 0x0003_f000u128 << 96; // the probe's control code
const LOW: u128 = (1u128 << 105) - 1;
/// nvcc 13.0 (`-arch=sm_120a`) for `cp.async.bulk.global.shared::cta.bulk_group [UR4], [UR36], UR6`.
const NVCC_STORE: u128 = 0x0045e2000800040600000004240073ba;

fn table_path() -> PathBuf {
    std::env::var_os("CUBIT_TABLE").map(PathBuf::from).unwrap_or_else(|| "tables/sm120.json".into())
}

fn table_and_index() -> &'static (IsaTable, DecodeIndex) {
    static TABLE: OnceLock<(IsaTable, DecodeIndex)> = OnceLock::new();
    TABLE.get_or_init(|| {
        let table = IsaTable::load(&table_path()).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    })
}

fn fixture() -> Vec<Value> {
    include_str!("fixtures/sm120_ublkcp_dir_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn expected_key(vendor: &str) -> &'static str {
    let direction = if vendor.contains("UBLKCP.G.S") { "G.S" } else { "S.S" };
    let desc = vendor.contains("desc[");
    KEYS.iter().copied().find(|k| k.contains(direction) && k.ends_with("_II") == desc).unwrap()
}

fn reencode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let source = format!("[{control}] {text} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    assert!(parsed.hand_sched && parsed.rsd.is_none(), "{source}");
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

fn check(word: u128, vendor: &str) {
    let (table, index) = table_and_index();
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
    assert_eq!(decoded.key.as_str(), expected_key(vendor), "{word:032x}");
    assert_eq!(decoded.mod_group, "", "{word:032x}");
    assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{word:032x}");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
}

/// Encode one text with the scheduler's own control code; the 105 instruction bits.
fn mint(table: &IsaTable, text: &str) -> anyhow::Result<u128> {
    let parsed = cubit::parse_sass(text, 0)?;
    Ok(cubit::encoder::encode_instruction(&parsed, table)? & LOW)
}

#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    let mut n = 0;
    let mut keys = std::collections::BTreeSet::new();
    for row in fixture() {
        if row.get("lattice").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        check(word, vendor);
        keys.insert(expected_key(vendor));
        n += 1;
    }
    assert_eq!(n, 167, "form words in the fixture");
    assert_eq!(keys.len(), 4, "{keys:?}");
}

#[test]
fn nvcc_store_word_decodes_as_the_store_and_the_store_text_mints_it() {
    let (table, index) = table_and_index();
    let decoded = index.decode(NVCC_STORE, 0, table).unwrap();
    assert_eq!(decoded.key, "UBLKCP.G.S_AURI_AURI_UR");
    assert_eq!(cubit::printer::to_sass_lossless(&decoded), "UBLKCP.G.S [UR4], [UR36], UR6");
    // the store text mints the store word -- and not the load word it minted before these rows
    let store = mint(table, "UBLKCP.G.S [UR4], [UR36], UR6 ;").unwrap();
    let load = mint(table, "UBLKCP.S.G [UR4], [UR36], UR6 ;").unwrap();
    assert_eq!(store, NVCC_STORE & LOW);
    assert_eq!(load, 0x0800020600000004240073ba, "the load (code 1) is the plain key's `G,S` row as before");
    assert_eq!(store ^ load, 3u128 << 73, "the two words differ in the direction code only");
    assert_eq!(mint(table, "UBLKCP.S.S [UR4], [UR36], UR6 ;").unwrap(), 0x0800060600000004240073ba);
    assert_eq!(mint(table, "UBLKCP.G.G [UR4], [UR36], UR6 ;").unwrap(), 0x0800000600000004240073ba);
    assert_eq!(mint(table, "UBLKCP.G.S [UR4], [UR36], UR6, desc[UR8] ;").unwrap(), 0x0800140600000804240073ba);
    // the direction codes 0 and 1 stay with the plain key
    for (word, vendor) in [(0x0800000600000004240073bau128 | CTRL, "UBLKCP.G.G [UR4], [UR36], UR6"),
                           (0x0800020600000004240073bau128 | CTRL, "UBLKCP.S.G [UR4], [UR36], UR6")] {
        let d = index.decode(word, 0, table).unwrap();
        assert_eq!(d.key, PLAIN_KEY, "{word:032x}");
        assert_eq!(cubit::printer::to_sass_lossless(&d), vendor);
    }
}

#[test]
fn a_table_without_the_store_row_refuses_the_store_text_instead_of_minting_the_load() {
    let mut table = IsaTable::load(&table_path()).unwrap();
    for key in KEYS {
        assert!(table.entries.remove(key).is_some(), "{key}");
    }
    for text in ["UBLKCP.G.S [UR4], [UR36], UR6 ;", "UBLKCP.S.S [UR4], [UR36], UR6 ;", "UBLKCP.G.S [UR4], [UR36], UR6, desc[UR8] ;"] {
        let err = mint(&table, text).expect_err(text).to_string();
        assert!(err.contains("no measured row") && err.contains("refused"), "{text}: {err}");
    }
    // the load and the global -> global copy are untouched by the refusal
    assert_eq!(mint(&table, "UBLKCP.S.G [UR4], [UR36], UR6 ;").unwrap(), 0x0800020600000004240073ba);
    assert_eq!(mint(&table, "UBLKCP.G.G [UR4], [UR36], UR6 ;").unwrap(), 0x0800000600000004240073ba);
}

#[test]
fn the_measured_rows_carry_the_provenance_and_a_fail_closed_mask() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    for key in KEYS {
        let entry = &raw["instructions"][key];
        assert_eq!(entry["_src"], SOURCE, "{key}");
        assert_eq!(entry["base_op"].as_str().unwrap(), &key[..key.find('_').unwrap()], "{key}");
        let groups = entry["mod_groups"].as_object().unwrap();
        assert_eq!(groups.keys().collect::<Vec<_>>(), vec![""], "{key}");
        let g = &groups[""];
        assert_eq!(g.get("_src").unwrap_or(&entry["_src"]), SOURCE, "{key}");
        let mut field_mask = 0u128;
        for f in g["fields"].as_array().unwrap() {
            assert_eq!(f.get("_src").unwrap_or(&g["_src"]).as_str().or(entry["_src"].as_str()), Some(SOURCE), "{key}");
            let bits = ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
            assert_eq!(field_mask & bits, 0, "{key}: overlapping fields");
            field_mask |= bits;
        }
        assert_eq!(number(&g["variable_mask"]), field_mask, "{key}");
        assert_eq!(number(&g["and_base"]) >> 105, 0, "{key}");
        assert_eq!(number(&g["and_base"]) & field_mask, 0, "{key}");
        assert!(g["count"].is_null(), "{key}");
        // the direction code sits in the constant bits: 2 for .G.S, 3 for .S.S; the descriptor keys fix bit 76
        let code = (number(&g["and_base"]) >> 73) & 3;
        assert_eq!(code, if key.contains(".G.S") { 2 } else { 3 }, "{key}");
        assert_eq!((number(&g["and_base"]) >> 76) & 1, key.ends_with("_II") as u128, "{key}");
    }
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 4);
}

#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    let (table, index) = table_and_index();
    let (mut n, mut undecoded, mut control_word) = (0, 0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        n += 1;
        let probed = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
        let word = probed | CTRL;
        match (index.decode(word, 0, table), row["nvidia_sass"].as_str()) {
            (Err(_), _) => {
                assert_eq!(probed >> 96, 0, "{word:032x}: a control-word bit must not fail the decode");
                undecoded += 1;
            }
            (Ok(d), Some(vendor)) => {
                // bits 96-127 are the control word (scheduling, reuse): text-inert for nvdisasm and stripped by
                // the decoder by design -- the only neighbours a measured row renders, and with NVIDIA's text
                assert_ne!(probed >> 96, 0, "{word:032x}: an instruction-bit neighbour decoded");
                assert_eq!(cubit::printer::to_sass_lossless(&d).replace(".reuse", ""), vendor, "{word:032x}");
                control_word += 1;
            }
            (Ok(d), None) => panic!("{word:032x} is illegal for nvdisasm but decodes as {}", cubit::printer::to_sass_lossless(&d)),
        }
    }
    assert_eq!(n, 48, "lattice words in the fixture");
    assert_eq!((undecoded, control_word), (36, 12), "fail-closed instruction-bit neighbours / control-word bits");
    // the unclaimed modifier groups and the misspelt directions are refused by the encoder
    for source in [
        "UBLKCP.G.S.MULTICAST [UR4], [UR36], UR6 ;",
        "UBLKCP.G.S.LTC64B [UR4], [UR36], UR6 ;",
        "UBLKCP.G.S.LTC128B [UR4], [UR36], UR6 ;",
        "UBLKCP.G.S.SEQUENCED [UR4], [UR36], UR6 ;",
        "UBLKCP.G.S.DST_G_BYTE_MASK [UR4], [UR36], UR6 ;",
        "UBLKCP.G [UR4], [UR36], UR6 ;",
        "UBLKCP.G.S.G [UR4], [UR36], UR6 ;",
    ] {
        if let Ok(parsed) = cubit::parse_sass(source, 0) {
            assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "{source}");
        }
    }
}
