//! SM120 `LDL[.size][.LU] Rd, [Ra+URb+imm]` (local load with a register base, a uniform offset
//! register and a 24-bit signed immediate), measured with nvdisasm 13.1 (tools/probes/re_sm120_ldl_aruri.py,
//! fixture tests/fixtures/sm120_ldl_aruri_nvdisasm.jsonl). Found by the GB10-host census of
//! 2026-11-04: 95 words `LDL.64 R14, [R18+UR12+0x20]` of cuBLASLt sm_120 cubins had no row
//! (`sm120.json` had `[Ra+imm]` and `[URb+imm]`, not the three-term address). Every probed form word
//! decodes to the measured row `LDL_R_ARURI`, prints NVIDIA's text (the plain `[R+UR+imm]` sum, like
//! LDS/STS - not the `desc[UR][R.64+off]` form the printer used to fabricate for LDL/STL) and the text
//! reassembles all 128 bits. The lattice (size 7 = INVALID7, `.EF`, `.NA`, the desc form, bit 91
//! clear = the register form, the text-inert bits) is never rendered as a different text.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "ldl-aruri-sm120-2026-11-04";
const KEY: &str = "LDL_R_ARURI";
const CTRL: u128 = 0x0000_a200u128 << 96; // control code of the census word

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
    include_str!("fixtures/sm120_ldl_aruri_nvdisasm.jsonl").lines()
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
    assert_eq!(n, 351, "form words in the fixture");
    assert_eq!(groups.len(), 14, "{groups:?}");
}

#[test]
fn the_census_words_round_trip() {
    // three of the 95 cuBLASLt words (lib_120.jsonl, GB10 host, 2026-11-04) with their nvdisasm 13.0 text
    for (word, vendor) in [
        (0x0000a20008100a000000200c120e7983u128, "LDL.64 R14, [R18+UR12+0x20]"),
        (0x0000e80008100a000000c009200e7983u128, "LDL.64 R14, [R32+UR9+0xc0]"),
        (0x0000e80008100a000000c00a200e7983u128, "LDL.64 R14, [R32+UR10+0xc0]"),
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
        assert_eq!(number(&g["variable_mask"]), field_mask, "{name}");
        assert_eq!(number(&g["and_base"]) >> 105, 0, "{name}");
        assert_eq!(number(&g["and_base"]) & field_mask, 0, "{name}");
        assert!(g["count"].is_null(), "{name}");
    }
    assert_eq!(measured, 14);
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
    assert_eq!(n, 22, "lattice words in the fixture");
    // bit 91 clear (`LDL.64 R14, [R18+0x20]`, the LDL_R_ARI row) and the text-inert neighbours decode
    // with the vendor's text; INVALID7, .EF, .NA, the desc form and the [UR+imm] twin with this row's
    // frame stay unclaimed or print exactly the vendor
    assert_eq!(undecoded + same_text, 22);
    for source in ["LDL.INVALID7 R14, [R18+UR12+0x20] ;", "LDL.NA.64 R14, [R18+UR12+0x20] ;"] {
        if let Ok(parsed) = cubit::parse_sass(source, 0) {
            assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "{source}");
        }
    }
}
