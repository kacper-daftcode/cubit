//! SM120 `USETMAXREG.DEALLOC.CTAPOOL imm` / `USETMAXREG.TRY_ALLOC.CTAPOOL UPd, imm` (0x9c8; PTX setmaxnreg.{dec,inc}), measured
//! with nvdisasm 13.1 (tools/probes/re_sm120_usetmaxreg.py, fixture tests/fixtures/sm120_usetmaxreg_nvdisasm.jsonl): the
//! uniform guard [15:12], the ten-bit register count [41:32] (the count itself, in hex), the operation [73:72] (1 / 2; 0 and 3
//! illegal), the pool bit 74 (`.CTAPOOL`; clear = the unclaimed vendor glyph `.???0`), the predicate destination [83:81] of
//! TRY_ALLOC (text-inert on DEALLOC, baked at 7). Every probed word decodes to its key, prints NVIDIA's text and reassembles
//! all 128 bits; the lattice never renders as another text; a reuse bit on the word is illegal (nvdisasm refuses the opex
//! table value), which the scheduler must never set. Before these rows the DEALLOC key had no guard field and neither row
//! was measured per field (KNOWN_ISSUES T1 exception 9; megakernel item 1).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "usetmaxreg-sm120-2026-11-08";
const KEYS: [(&str, &str); 2] = [("USETMAXREG_II", "CTAPOOL,DEALLOC"), ("USETMAXREG_UP_II", "CTAPOOL,TRY_ALLOC")];
const CTRL: u128 = 0x000f_c000u128 << 96; // nvcc's control code on the DEALLOC word
const LOW: u128 = (1u128 << 105) - 1;

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
    include_str!("fixtures/sm120_usetmaxreg_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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
    let (key, group) = if vendor.contains("TRY_ALLOC") { KEYS[1] } else { KEYS[0] };
    assert_eq!((decoded.key.as_str(), decoded.mod_group.as_str()), (key, group), "{word:032x}");
    assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{word:032x}");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
}

fn mint(table: &IsaTable, text: &str) -> anyhow::Result<u128> {
    let parsed = cubit::parse_sass(text, 0)?;
    Ok(cubit::encoder::encode_instruction(&parsed, table)? & LOW)
}

#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    let mut n = 0;
    for row in fixture() {
        if row.get("lattice").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        check(word, vendor);
        n += 1;
    }
    assert_eq!(n, 73, "form words in the fixture");
}

#[test]
fn the_three_role_counts_assemble_and_the_scheduler_sets_no_reuse() {
    let (table, index) = table_and_index();
    // nvcc's and the CUTLASS MXFP8 GEMM's words, and the persistent kernel's three role sizes (dec 32 / dec 56 / inc 208)
    assert_eq!(mint(table, "USETMAXREG.DEALLOC.CTAPOOL 0x18 ;").unwrap(), 0x080e050000000018000079c8);
    assert_eq!(mint(table, "USETMAXREG.TRY_ALLOC.CTAPOOL UP0, 0xe0 ;").unwrap(), 0x08000600000000e0000079c8);
    assert_eq!(mint(table, "USETMAXREG.DEALLOC.CTAPOOL 0x28 ;").unwrap(), 0x080e050000000028000079c8);
    assert_eq!(mint(table, "USETMAXREG.TRY_ALLOC.CTAPOOL UP0, 0xe8 ;").unwrap(), 0x08000600000000e8000079c8);
    for text in ["USETMAXREG.DEALLOC.CTAPOOL 0x20 ;", "USETMAXREG.DEALLOC.CTAPOOL 0x38 ;", "USETMAXREG.TRY_ALLOC.CTAPOOL UP0, 0xd0 ;",
                 "@UP1 USETMAXREG.DEALLOC.CTAPOOL 0x38 ;", "@!UP0 USETMAXREG.TRY_ALLOC.CTAPOOL UP3, 0xd0 ;"] {
        let (bytes, count) = cubit::assemble(text, 0, table).unwrap_or_else(|e| panic!("{text}: {e}"));
        assert_eq!(count, 1);
        let word = u128::from_le_bytes(bytes[..16].try_into().unwrap());
        assert_eq!(word >> 122, 0, "{text}: a reuse bit on USETMAXREG (illegal for nvdisasm)");
        let decoded = index.decode(word, 0, table).unwrap();
        assert_eq!(cubit::printer::to_sass_lossless(&decoded), text.trim_end_matches(" ;"));
    }
    for refused in ["USETMAXREG.DEALLOC.???0 0x18 ;", "USETMAXREG.ALLOC.CTAPOOL UP0, 0xe0 ;", "USETMAXREG.TRY_ALLOC.CTAPOOL 0xe0 ;",
                    "USETMAXREG.DEALLOC.CTAPOOL UP0, 0x18 ;", "USETMAXREG.DEALLOC.CTAPOOL !UPT, 0x18 ;"] {
        if let Ok(parsed) = cubit::parse_sass(refused, 0) {
            assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "{refused}");
        }
    }
}

#[test]
fn the_measured_rows_carry_the_provenance_and_a_fail_closed_mask() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    for (key, group) in KEYS {
        let entry = &raw["instructions"][key];
        assert_eq!(entry["_src"], SOURCE, "{key}");
        let groups = entry["mod_groups"].as_object().unwrap();
        assert_eq!(groups.keys().cloned().collect::<Vec<_>>(), vec![group], "{key}");
        let g = &groups[group];
        let fields = g["fields"].as_array().unwrap();
        assert_eq!(fields.len(), if key.contains("_UP_") { 3 } else { 2 }, "{key}: guard, [UPd,] count");
        let mut field_mask = 0u128;
        for f in fields {
            let bits = ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
            assert_eq!(field_mask & bits, 0, "{key}: overlapping fields");
            field_mask |= bits;
        }
        assert_eq!(field_mask & (0x3ff << 32), 0x3ff << 32, "{key}: the ten-bit count");
        let base = number(&g["and_base"]);
        assert_eq!(number(&g["variable_mask"]), field_mask, "{key}");
        assert_eq!(base >> 105, 0, "{key}");
        assert_eq!(base & field_mask, 0, "{key}");
        assert_eq!((base >> 72) & 7, if key.contains("_UP_") { 0b110 } else { 0b101 }, "{key}: operation + pool bits");
        assert_eq!((base >> 91) & 1, 1, "{key}: the frame bit");
        assert!(g["count"].is_null(), "{key}");
    }
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 2);
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
                // bits 96-127 are the control word: stripped by the decoder by design
                assert_ne!(probed >> 96, 0, "{word:032x}: an instruction-bit neighbour decoded");
                assert_eq!(cubit::printer::to_sass_lossless(&d).replace(".reuse", ""), vendor, "{word:032x}");
                control_word += 1;
            }
            (Ok(d), None) => {
                // the reuse bits 122-124: nvdisasm refuses the word, the decoder (which strips the control word) names
                // the instruction -- the law is enforced on the way out (the scheduler test above)
                assert!(probed >> 122 != 0, "{word:032x} is illegal for nvdisasm but decodes as {}", cubit::printer::to_sass_lossless(&d));
                control_word += 1;
            }
        }
    }
    assert_eq!(n, 148, "lattice words in the fixture");
    assert_eq!((undecoded, control_word), (124, 24), "fail-closed instruction-bit neighbours / control-word bits");
}
