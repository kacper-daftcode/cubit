//! SM120 LDSM.U4x16P64TO8 / LDSM.U6x16P32TO8 [R+imm] (FP4 / FP6 matrix loads with unpack to 8-bit lanes, PTX ldmatrix .b8x16.b4x16_p64 / .b6x16_p32), measured with nvdisasm 13.1 (tools/probes/re_sm120_ldsm_fp4.py, fixture
//! tests/fixtures/sm120_ldsm_fp4_nvdisasm.jsonl). Every probed form word decodes to the measured row,
//! prints NVIDIA's text - in NVIDIA's modifier order - and that text reassembles all 128 bits. The
//! lattice around the form (illegal, INVALIDn and text-inert neighbours) is never rendered as a
//! different text: a lattice word either fails to decode or prints exactly what nvdisasm prints.
//! Shipped words: DeepGEMM sm120_m_grouped_fp8_fp4_gemm_contiguous_1d1d (576 words over 20 census cubins).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "ldsm-fp4-fp6-sm120-2026-11-02";
const KEY: &str = "LDSM_R_ARI";
const CTRL: u128 = 0x0002_a200u128 << 96; // control code of the shipped words

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
    include_str!("fixtures/sm120_ldsm_fp4_nvdisasm.jsonl").lines()
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

/// Decode, compare the lossless print with NVIDIA's text and re-encode bit for bit.
fn check(word: u128, vendor: &str) {
    let (table, index) = table_and_index();
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
    assert_eq!(decoded.key.as_str(), KEY, "{word:032x}");
    if vendor.contains("QNAN") {
        // NVIDIA's NaN glyph drops the payload: the lossless print keeps it as an exact
        // hexadecimal literal, the display print follows the vendor; a NaN has no
        // text-visible bit pattern to re-encode (parser quirk, see parser.rs)
        let display = format!("{decoded}");
        assert_eq!(display.trim_end_matches(" ;").trim_end_matches(';').trim(), vendor, "{word:032x}");
        return;
    }
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
    assert_eq!(n, 136, "form words in the fixture");
    assert_eq!(groups.len(), 30, "{groups:?}");
}

#[test]
fn the_shipped_census_words_round_trip() {
    for (word, vendor) in [
        (0x000ea4000000a90000a000004842783bu128, "LDSM.U4x16P64TO8.M816.2 R66, [R72+0xa000]"),
        (0x000ee8000000a90000a80000484c783bu128, "LDSM.U4x16P64TO8.M816.2 R76, [R72+0xa800]"),
        (0x000e5e000000a90000c400003e38783bu128, "LDSM.U4x16P64TO8.M816.2 R56, [R62+0xc400]"),
    ] {
        check(word, vendor);
    }
}

#[test]
fn the_measured_rows_carry_the_provenance_and_a_fail_closed_mask() {
    let raw: Value = serde_json::from_slice(&std::fs::read(table_path()).unwrap()).unwrap();
    let groups = raw["instructions"][KEY]["mod_groups"].as_object().unwrap();
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let mut measured = 0;
    for (name, g) in groups {
        if g["_src"] != SOURCE {
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
        // fail-closed: the variable mask is exactly the measured fields, and no
        // control/reuse bit is baked into the template
        assert_eq!(number(&g["variable_mask"]), field_mask, "{name}");
        assert_eq!(number(&g["and_base"]) >> 105, 0, "{name}");
        assert_eq!(number(&g["and_base"]) & field_mask, 0, "{name}");
        assert!(g["count"].is_null(), "{name}");
    }
    assert_eq!(measured, 30);
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
                // a decoded neighbour must print NVIDIA's text (the lossless print may
                // add `.reuse` for the reuse window, which nvdisasm never shows)
                assert_eq!(cubit::printer::to_sass_lossless(&d).replace(".reuse", ""), vendor, "{word:032x}");
                same_text += 1;
            }
            (Ok(d), None) => panic!("{word:032x} is illegal for nvdisasm but decodes as {}", cubit::printer::to_sass_lossless(&d)),
        }
    }
    assert_eq!(n, 45, "lattice words in the fixture");
    assert_eq!((undecoded, same_text), (29, 16), "fail-closed / text-identical neighbours");
    for source in [
        "LDSM.U4x16P64TO8.M816.INVALID3 R6, [R4] ;",
        "LDSM.U4x16P64TO8.INVALID5.2 R6, [R4] ;",
        "LDSM.U4x16P64TO8.M816.2 R6, [R4+UR5] ;",
    ] {
        if let Ok(parsed) = cubit::parse_sass(source, 0) {
            assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "{source}");
        }
    }
}
