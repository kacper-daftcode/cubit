//! SM103a / SM100a FP32 ALU (FADD / FMUL / FFMA / FMNMX) -- the sm120 law of G's `tools/probes/re_sm120_fp32_alu.py`
//! (2026-11-07) measured on `-b SM103` / `SM100` (session T-21, 2026-11-08, `probe --arch SM103` / `SM100`, nvdisasm 13.1):
//! every one of the 1 636 form, 30 glyph, 492 lattice and 16 neighbour words obeys the law on both targets. `apply`: the
//! 14 plain keys carry the 696 measured rows (36 harvest rows rewritten, 660 groups added), the integer-spelling twin
//! `FMUL_R_R_II` retired as an alias of `FMUL_R_R_FI`. Closes the B300 publish-corpus hole `FMUL.RZ R5, R5, R6` (the harvest
//! had no rounding groups). The field-law checks of the rows are in G's `tests/sm120_fp32_alu.rs`.
const SOURCE_TAG: &str = "fp32-alu-family-2026-11-07";
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = SOURCE_TAG;
const CTRL: u128 = 0x000f_e200u128 << 96;
const PREFIXES: [&str; 4] = ["FADD_", "FMUL_", "FFMA_", "FMNMX_"];
/// (table, fixture, the family's retired keys that are `_meta.key_aliases` on that table)
const TABLES: [(&str, &str, usize); 2] = [
    ("tables/sm103a.json", include_str!("fixtures/sm103a_fp32_alu_nvdisasm.jsonl"), 1),
    ("tables/sm100a.json", include_str!("fixtures/sm100a_fp32_alu_nvdisasm.jsonl"), 1),
];
const FORM_WORDS: usize = 1636;
const GLYPH_WORDS: usize = 30;
const LATTICE_WORDS: usize = 492;
const NEIGHBOUR_WORDS: usize = 16;
const LEGEND_ROWS: u64 = 696;

fn is_family_key(k: &str) -> bool {
    PREFIXES.iter().any(|p| k == p.trim_end_matches('_') || k.starts_with(p)) && !k.contains('.')
}

fn table_and_index(i: usize) -> &'static (IsaTable, DecodeIndex) {
    static TABLE: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    &TABLE.get_or_init(|| {
        TABLES.iter().map(|(path, _, _)| {
            let table = IsaTable::load(std::path::Path::new(path)).unwrap();
            let index = DecodeIndex::build(&table);
            (table, index)
        }).collect()
    })[i]
}

fn fixture(i: usize) -> Vec<Value> {
    TABLES[i].1.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn word_of(row: &Value) -> u128 {
    u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL
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

fn check(i: usize, word: u128, vendor: &str) -> (String, String) {
    let (table, index) = table_and_index(i);
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{}: {word:032x}: {e}", TABLES[i].0));
    assert!(is_family_key(&decoded.key), "{}: {word:032x}: {}", TABLES[i].0, decoded.key);
    assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{}: {word:032x}", TABLES[i].0);
    assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{}: {word:032x} (display print)", TABLES[i].0);
    assert_eq!(reencode(table, word, vendor), word, "{}: {vendor}", TABLES[i].0);
    (decoded.key.clone(), decoded.mod_group.clone())
}

/// Every form word of the sweep decodes to a family key, prints NVIDIA's text (display and lossless) and re-encodes
/// bit for bit on each table.
#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    for i in 0..TABLES.len() {
        let mut n = 0;
        for row in fixture(i) {
            if row.get("lattice").is_some() || row.get("glyph").is_some() || row.get("witness").is_some() {
                continue;
            }
            check(i, word_of(&row), row["nvidia_sass"].as_str().unwrap());
            n += 1;
        }
        assert_eq!(n, FORM_WORDS, "{}: form words in the fixture", TABLES[i].0);
    }
}

/// The NaN immediates: nvdisasm prints the `+QNAN ` / `-QNAN ` / `+SNAN ` glyph and cubit's display print does the same
/// (KNOWN_ISSUES A8; the lossless print keeps the payload).
#[test]
fn the_nan_glyph_words_decode_to_the_vendor_glyph() {
    for i in 0..TABLES.len() {
        let (table, index) = table_and_index(i);
        let mut n = 0;
        for row in fixture(i) {
            if row.get("glyph").is_none() {
                continue;
            }
            n += 1;
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let word = word_of(&row);
            let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{}: {word:032x}: {e}", TABLES[i].0));
            assert!(is_family_key(&decoded.key), "{}: {word:032x}: {}", TABLES[i].0, decoded.key);
            assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{}: {word:032x}", TABLES[i].0);
            let lossless = cubit::printer::to_sass_lossless(&decoded);
            assert_eq!(reencode(table, word, &lossless), word, "{}: {lossless}", TABLES[i].0);
        }
        assert_eq!(n, GLYPH_WORDS, "{}", TABLES[i].0);
    }
}

/// The lattice words are never rendered as a family text; the probe's neighbour words (other opcodes next to the
/// family's) are never claimed by a family key.
#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    for i in 0..TABLES.len() {
        let (table, index) = table_and_index(i);
        let (mut n_lattice, mut n_neighbour) = (0, 0);
        for row in fixture(i) {
            if row.get("lattice").is_none() {
                continue;
            }
            let word = word_of(&row);
            match (row.get("neighbour").and_then(Value::as_str), index.decode(word, 0, table)) {
                (None, Err(_)) => n_lattice += 1,
                (None, Ok(d)) => panic!("{}: lattice word {word:032x} ({:?}) decodes as {}", TABLES[i].0, row["nvidia_sass"], cubit::printer::to_sass_lossless(&d)),
                (Some(_), Err(_)) => n_neighbour += 1,
                (Some(nb), Ok(d)) => {
                    assert!(!is_family_key(&d.key), "{}: neighbour word {word:032x} ({nb}) claimed by {}", TABLES[i].0, d.key);
                    n_neighbour += 1;
                }
            }
        }
        assert_eq!((n_lattice, n_neighbour), (LATTICE_WORDS, NEIGHBOUR_WORDS), "{}", TABLES[i].0);
    }
}

/// The legend counts the measured rows, every plain key of the family carries the tag on every row (rows of another
/// measurement that the lattice does not cover keep their own tag), and the family's retired keys are aliases of a
/// family key.
#[test]
fn the_rows_are_measured_and_the_retired_keys_are_aliases() {
    for i in 0..TABLES.len() {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(TABLES[i].0).unwrap()).unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], LEGEND_ROWS, "{}", TABLES[i].0);
        let mut tagged = 0u64;
        for (key, e) in ins {
            if !is_family_key(key) || e.get("mod_groups").is_none() {
                continue;
            }
            if e["_src"] != SOURCE {
                continue; // a plain key of the family outside this probe's forms (its own measurement or a harvest row)
            }
            for (name, g) in e["mod_groups"].as_object().unwrap() {
                assert!(g["_src"].is_string(), "{}: {key} {name}: a row without provenance on a measured key", TABLES[i].0);
                if g["_src"] == SOURCE {
                    tagged += 1;
                }
            }
        }
        assert_eq!(tagged, LEGEND_ROWS, "{}: rows with the tag", TABLES[i].0);
        let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
        let mut n_alias = 0;
        for (old, new) in aliases {
            let mn = old.split(['.', '_']).next().unwrap();
            if !PREFIXES.iter().any(|p| p.trim_end_matches('_') == mn) {
                continue;
            }
            let new = new.as_str().unwrap();
            assert!(ins.get(old).is_none(), "{}: {old} still a key", TABLES[i].0);
            assert!(is_family_key(new) && ins.get(new).is_some(), "{}: {old} -> {new}", TABLES[i].0);
            n_alias += 1;
        }
        assert_eq!(n_alias, TABLES[i].2, "{}: the family's aliases", TABLES[i].0);
    }
}
