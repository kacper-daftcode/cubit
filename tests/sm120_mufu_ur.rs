//! SM120 `MUFU.<fn>[.F16|.BF16] Rd, [-|]URb[|]` (the uniform-source transcendental, opcode 0xd08),
//! measured with nvdisasm 13.1 (tools/probes/re_sm120_mufu_ur.py, fixture
//! tests/fixtures/sm120_mufu_ur_nvdisasm.jsonl). Found by the GB10-host census of 2026-11-04:
//! `MUFU.EX2 R4, UR7` of cuBLASLt sm_120 code decoded as `MUFU.LG2`, `MUFU.RSQ R2, UR6` as `RCP` /
//! `RCP64H` - the four harvest rows of `MUFU_R_UR` baked their sample's UR and function into
//! `and_base` with a few-bit mask. Every probed form word (10 functions x the half types the function
//! takes x guard / Rd / UR / abs / neg) decodes to the measured row, prints NVIDIA's text (function
//! before the half type) and reassembles all 128 bits; the INVALIDn function codes, the half types of
//! RCP64H / RSQ64H and the both-halves word stay unclaimed (MUFU is excluded from the decoder's
//! sign-window fallback, which used to absorb them).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "mufu-ur-sm120-2026-11-04";
const KEY: &str = "MUFU_R_UR";
const CTRL: u128 = 0x000e_2400u128 << 96; // control code of the census word

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
    include_str!("fixtures/sm120_mufu_ur_nvdisasm.jsonl").lines()
        .map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn reencode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let source = format!("[{control}] {text} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    assert!(parsed.hand_sched && parsed.rsd.is_none(), "{source}");
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

fn check(word: u128, vendor: &str) {
    let (table, index) = table_and_index();
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
    assert_eq!(decoded.key.as_str(), KEY, "{word:032x}");
    let own = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(own, vendor, "{word:032x}");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
}

#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    let mut n = 0;
    let mut groups = std::collections::BTreeSet::new();
    let (table, index) = table_and_index();
    for row in fixture() {
        if row.get("lattice").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        check(word, vendor);
        groups.insert(index.decode(word, 0, table).unwrap().mod_group.clone());
        n += 1;
    }
    assert_eq!(n, 494, "form words in the fixture");
    assert_eq!(groups.len(), 26, "{groups:?}");
}

#[test]
fn the_census_words_round_trip() {
    // the three cuBLASLt words (lib_120.jsonl, GB10 host, 2026-11-04) with their nvdisasm 13.0 text
    for (word, vendor) in [
        (0x000e2400080008000000000700047d08u128, "MUFU.EX2 R4, UR7"),
        (0x000e2600080014000000000600027d08u128, "MUFU.RSQ R2, UR6"),
        (0x000e6200080014000000000b00047d08u128, "MUFU.RSQ R4, UR11"),
    ] {
        check(word, vendor);
    }
}

#[test]
fn the_measured_rows_carry_the_provenance_and_a_fail_closed_mask() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let groups = raw["instructions"][KEY]["mod_groups"].as_object().unwrap();
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let mut measured = 0;
    let mut remeasured = 0;
    for (name, g) in groups {
        if g["_src"] != SOURCE {
            // 2026-11-07 (session G, tools/probes/re_sm120_conv.py): the 16 .F16 / .BF16 rows carry the half selector
            // `.H1` (bit 60, `MUFU.RCP.F16 R4, UR2.H1`) the 2026-11-04 measurement did not probe -- re-measured by G
            assert_eq!(g["_src"], "conv-family-2026-11-07", "{name}");
            assert!(name.contains("F16"), "{name}: only the half-typed rows were re-measured");
            assert!(g["fields"].as_array().unwrap().iter().any(|f| f["extraction"] == "opmod:H1" && f["shift"] == 60), "{name}: .H1 field");
            remeasured += 1;
            continue;
        }
        measured += 1;
        let mut field_mask = 0u128;
        for f in g["fields"].as_array().unwrap() {
            assert_eq!(f["_src"], SOURCE, "{name}");
            let bits = ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
            assert_eq!(field_mask & bits, 0, "{name}: overlapping fields");
            field_mask |= bits;
        }
        assert_eq!(number(&g["variable_mask"]), field_mask, "{name}");
        assert_eq!(number(&g["and_base"]) >> 105, 0, "{name}");
        assert_eq!(number(&g["and_base"]) & field_mask, 0, "{name}");
        assert!(g["count"].is_null(), "{name}");
    }
    assert_eq!((measured, remeasured), (10, 16));
}

#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    let (table, index) = table_and_index();
    let (mut n, mut undecoded, mut same_text) = (0, 0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        n += 1;
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        let vendor = row["nvidia_sass"].as_str();
        match (index.decode(word, 0, table), vendor) {
            (Err(_), _) => undecoded += 1,
            (Ok(d), Some(vendor)) => {
                assert_eq!(cubit::printer::to_sass_lossless(&d).replace(".reuse", ""), vendor, "{word:032x}");
                same_text += 1;
            }
            (Ok(d), None) => panic!("{word:032x} is illegal for nvdisasm but decodes as {}", cubit::printer::to_sass_lossless(&d)),
        }
    }
    assert_eq!(n, 37, "lattice words in the fixture");
    // the text-inert neighbours decode with the vendor's text; INVALIDn codes, the half types of
    // RCP64H / RSQ64H, the both-halves word and the frame-less word stay unclaimed
    assert_eq!(undecoded + same_text, 37);
    for source in ["MUFU.INVALID10 R4, UR7 ;", "MUFU.RCP64H.F16 R4, UR7 ;"] {
        if let Ok(parsed) = cubit::parse_sass(source, 0) {
            assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "{source}");
        }
    }
}
