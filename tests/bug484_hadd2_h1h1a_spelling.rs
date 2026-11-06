//! BUG-484 (session K's finding of 2026-11-05, fixed 2026-11-06): `HADD2.H1H1A Rd, Ra, Rb` — cubit's
//! own mnemonic-suffix spelling of 2026-08-08 (blackwell-isa `8f773da`: a row `HADD2.H1H1A_R_R_R` with
//! "Ra = H1_H1" baked into the mnemonic, added because the plain row then silently dropped the
//! selector) was retired at the O2 canonical cut (`4340cdf`) without an alias. The production kernels
//! `vllm-moet kernels/sass/exl3-wave-m8/k1_m8{,g}.sass` were written with it (256 sites, built by cubit
//! `5912400`) and stopped assembling ("No table row expresses this modifier combination (missing:
//! [H1H1A])"). The form is the vendor's `HADD2 Rd, Ra.H1_H1, Rb`: measured with nvdisasm 13.1
//! (`tools/probes/re_sm120_hadd2_sel.py`, `tests/fixtures/sm120_hadd2_sel_nvdisasm.jsonl`) the Ra
//! selector sits at bits [75:74] and the Rb selector at [61:60] (0 = natural, 2 = `.H0_H0`, 3 = `.H1_H1`,
//! 1 = nvdisasm's `INVALID1`), bit 72 = `-Ra`, 73 = `|Ra|`, 63 = `-Rb`, 62 = `|Rb|`; the plain
//! `HADD2_R_R_R` row encodes and prints all of it today. The spelling is an INPUT alias in the parser
//! (rewritten to the vendor text before encoding, never printed); the shipped `k1_m8` words pin the bits
//! (`000fc20000000c000000001010107230` = `HADD2 R16, R16.H1_H1, R16`).

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const CTRL: u128 = 0x000f_c200u128 << 96;

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
    include_str!("fixtures/sm120_hadd2_sel_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn encode(text: &str) -> u128 {
    let (table, _) = table_and_index();
    let source = format!("[B------:R-:W-:-:S01] {text} ;");
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap_or_else(|e| panic!("{source}: {e}"));
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

fn decode_text(word: u128) -> String {
    let (table, index) = table_and_index();
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
    cubit::printer::to_sass_lossless(&decoded)
}

/// The legacy spelling mints exactly the vendor word of the shipped exl3 kernels, the same word as the
/// vendor spelling, and decodes back to the vendor text — `H1H1A` never appears in any print.
#[test]
fn t484_1_legacy_spelling_is_the_vendor_word() {
    const SHIPPED: u128 = 0x000fc20000000c000000001010107230; // k1_m8.cubin @0x560 (cubit 5912400)
    let legacy = encode("HADD2.H1H1A R16, R16, R16");
    let vendor = encode("HADD2 R16, R16.H1_H1, R16");
    assert_eq!(legacy, SHIPPED, "legacy spelling must mint the shipped word");
    assert_eq!(vendor, SHIPPED, "vendor spelling must mint the shipped word");
    let text = decode_text(SHIPPED);
    assert_eq!(text, "HADD2 R16, R16.H1_H1, R16");
    assert!(!text.contains("H1H1A"));
    // The parsed instruction carries the vendor shape (opcode_full without the suffix, Ra selected).
    let parsed = cubit::parse_cuasm_line("[B------:R-:W-:-:S01] HADD2.H1H1A R11, R11, R11 ;", 0).unwrap();
    assert_eq!(parsed.opcode_full, "HADD2");
    assert!(parsed.modifiers.is_empty(), "{:?}", parsed.modifiers);
    assert!(parsed.raw_text.contains("HADD2 R11, R11.H1_H1, R11"), "{}", parsed.raw_text);
    // Other modifiers survive the rewrite in place.
    let parsed = cubit::parse_cuasm_line("HADD2.H1H1A.SAT R11, R11, R11 ;", 0).unwrap();
    assert_eq!(parsed.opcode_full, "HADD2.SAT");
}

/// The legacy spelling needs a plain register as Ra (its selector is applied there); anything else is
/// refused with a message naming the vendor spelling — never silently encoded as something else.
#[test]
fn t484_2_legacy_spelling_refuses_a_non_register_ra() {
    for text in ["HADD2.H1H1A R9, 0x3c00, R5 ;", "HADD2.H1H1A R9, R2.H0_H0, R5 ;", "HADD2.H1H1A R9, -R2, R5 ;"] {
        let err = cubit::parse_cuasm_line(text, 0).err().unwrap_or_else(|| panic!("{text} must be refused"));
        assert!(err.to_string().contains("HADD2.H1H1A"), "{text}: {err}");
    }
}

/// Every measured word of the register form — 12 modifier groups (`[.F32|.BF16_V2][.FTZ][.SAT]`) × the
/// selector / sign lattice, the operand field edges and the shipped shape — decodes through the rebuilt
/// `HADD2_R_R_R` row to NVIDIA's text and re-encodes bit for bit. The lattice words (the `INVALID1`
/// selector codes, `.F32` + `.BF16_V2`, bit 91, the text-inert bits of [64:96)) stay outside the row: cubit
/// never prints a valid selector for an `INVALID1` code and never claims an inert bit as a modifier.
#[test]
fn t484_3_register_form_lattice_matches_nvidia_and_round_trips() {
    let (table, index) = table_and_index();
    let mut forms = 0;
    let mut lattice = 0;
    let mut groups = std::collections::BTreeSet::new();
    for row in fixture() {
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        let vendor = row["nvidia_sass"].as_str();
        if row.get("lattice").is_some() {
            let own = index.decode(word, 0, table).ok();
            if let Some(d) = &own {
                let t = cubit::printer::to_sass_lossless(d);
                let v = vendor.unwrap_or("");
                assert!(!v.contains("INVALID") || !t.contains("_H"), "{word:032x}: INVALID1 printed as a selector: {t}");
                assert!(d.key != "HADD2_R_R_R" || v.is_empty() || t == v, "{word:032x}: {t} vs {v}");
            }
            lattice += 1;
            continue;
        }
        let vendor = vendor.unwrap();
        let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
        assert_eq!(decoded.key, "HADD2_R_R_R", "{word:032x}");
        groups.insert(decoded.mod_group.clone());
        assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{word:032x}");
        assert_eq!(encode(vendor), word, "{vendor}");
        forms += 1;
    }
    assert_eq!((forms, lattice), (181, 36), "form / lattice words of the fixture");
    assert_eq!(groups.len(), 12, "12 measured modifier groups");
}

/// The seven retired harvest keys are gone and nothing aliases to them; the words they used to absorb
/// decode through the plain key.
#[test]
fn t484_4_retired_hadd2_keys() {
    let (table, _) = table_and_index();
    for key in ["HADD2.F32_R_R_R", "HADD2.BF16_V2_R_R_R", "HADD2_R_R_R_R", "HADD2_R_R_R_II_?",
                "HADD2_R_R_R_II_II_?", "HADD2_R_R_II", "HADD2_R_R_II_II_II_II_?"] {
        assert!(!table.entries.contains_key(key), "{key} must be retired");
    }
    assert_eq!(decode_text(0x000fc20000000d004000000502097230), "HADD2 R9, -R2.H1_H1, |R5|");
    let bf16_signed = CTRL | 0x230 | (7 << 12) | (9 << 16) | (2 << 24) | (5 << 32) | (0xf << 60) | (1 << 85);
    assert_eq!(decode_text(bf16_signed), "HADD2.BF16_V2 R9, R2, -|R5|.H1_H1");
}
