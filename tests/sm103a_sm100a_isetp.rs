//! SM103a / SM100a ISETP / UISETP -- the sm120 law of G's batch 2 (2026-11-06) measured on `-b SM103` / `SM100`
//! (session T-21, 2026-11-08, `tools/probes/re_sm120_isetp.py probe --arch SM103` / `SM100`, nvdisasm 13.1): every form
//! word prints the SM120 text EXCEPT for bit 80 -- the 64-bit compare (`.S64` / `.U64`) is SM120 / SM121-only; on these
//! targets the bit is text-inert (NEEDS 46: every nvdisasm 13.x build agrees, no compiler word of 2 145 B300 cubins sets
//! it), so the sweep's 977 bit-80 words print the 32-bit text and are a lattice plane here: 967 form + 1 169 lattice
//! words per target. `apply` rewrote the ten plain keys to the 48 measured groups each (the harvest had 4..29 per key:
//! 185 rows rewritten, 295 groups added) and retired the four phantom `.S64` / `.U64` harvest groups of
//! `ISETP_P_P_R_UR_P` (`AND,GE,U64`, `AND,GT,U64`, `AND,NE,S64`, `NE,OR,S64` -- their canonical words print
//! `ISETP.GE.U32.AND` etc. here, two of them are illegal on every target: NEEDS 46, R's decision of 2026-11-08: fail closed
//! on bit 80). The measured rows leave bit 80 outside their masks, so a word with it set has no decode on these tables.
//! The sm120 test `tests/sm120_isetp.rs` is the template.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "isetp-family-2026-11-06";
const CTRL: u128 = 0x000f_e200u128 << 96;
const KEYS: [&str; 10] = ["ISETP_P_P_R_R_P", "ISETP_P_P_R_R_P_P", "ISETP_P_P_R_UR_P", "ISETP_P_P_R_UR_P_P", "ISETP_P_P_R_II_P",
                          "ISETP_P_P_R_II_P_P", "UISETP_UP_UP_UR_UR_UP", "UISETP_UP_UP_UR_UR_UP_UP", "UISETP_UP_UP_UR_II_UP",
                          "UISETP_UP_UP_UR_II_UP_UP"];
const TABLES: [(&str, &str, &str); 2] = [
    ("tables/sm103a.json", "SM103", include_str!("fixtures/sm103a_isetp_nvdisasm.jsonl")),
    ("tables/sm100a.json", "SM100", include_str!("fixtures/sm100a_isetp_nvdisasm.jsonl")),
];
const FORM_WORDS: usize = 967;
const LATTICE_WORDS: usize = 1169;
const BIT80_WORDS: usize = 977;

fn table_path(i: usize) -> PathBuf {
    TABLES[i].0.into()
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
    TABLES[i].2.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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
    assert!(KEYS.contains(&decoded.key.as_str()), "{word:032x}: {}", decoded.key);
    assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{word:032x}");
    assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{word:032x} (display print)");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
    (decoded.key.clone(), decoded.mod_group.clone())
}

/// Every 32-bit form word decodes to one of the ten keys, prints NVIDIA's text and re-encodes bit for bit; the 480
/// groups all have a form word.
#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    for i in 0..TABLES.len() {
        let mut n = 0;
        let mut groups = std::collections::BTreeSet::new();
        for row in fixture(i) {
            if row.get("lattice").is_some() {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
            groups.insert(check(i, word, row["nvidia_sass"].as_str().unwrap()));
            n += 1;
        }
        assert_eq!(n, FORM_WORDS, "{}: form words in the fixture", TABLES[i].0);
        assert_eq!(groups.len(), 480, "{}: every group of the ten keys has a form word", TABLES[i].0);
    }
}

/// The lattice -- the `INVALID3` boolean, the frame bit flipped, the text-inert bits, the carry-in window without
/// `.EX`, and on these targets every word with bit 80 set (nvdisasm names it with the 32-bit text; the measured rows
/// fail closed on the text-inert bit) -- is never rendered as any text. The vendor text of the bit-80 words, with the
/// bit cleared, is the text of the 32-bit word they shadow.
#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    for i in 0..TABLES.len() {
        let (table, index) = table_and_index(i);
        let (mut n, mut n80) = (0, 0);
        for row in fixture(i) {
            if row.get("lattice").is_none() {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
            if let Ok(d) = index.decode(word, 0, table) {
                panic!("{}: lattice word {word:032x} ({:?}) decodes as {}", TABLES[i].0, row["nvidia_sass"], cubit::printer::to_sass_lossless(&d));
            }
            if row.get("bit80_inert").is_some() {
                n80 += 1;
                let vendor = row["nvidia_sass"].as_str().unwrap();
                assert!(!vendor.contains("64"), "{word:032x}: no 64-bit compare on {}: {vendor}", TABLES[i].1);
                let narrow = word & !(1u128 << 80);
                let d = index.decode(narrow, 0, table).unwrap_or_else(|e| panic!("{narrow:032x}: {e}"));
                assert_eq!(cubit::printer::to_sass(&d), vendor, "{word:032x}: the 32-bit word it shadows");
            }
            n += 1;
        }
        assert_eq!((n, n80), (LATTICE_WORDS, BIT80_WORDS), "{}", TABLES[i].0);
    }
}

/// The ten keys carry exactly the 48 measured groups each (two types: the 32-bit signed and `U32`), the four NEEDS 46
/// phantom groups are gone, and the legend counts the 480 rows.
#[test]
fn the_rows_are_measured_and_the_phantom_64_bit_groups_are_gone() {
    for i in 0..TABLES.len() {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path(i)).unwrap()).unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 480, "{}", TABLES[i].0);
        let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        for key in KEYS {
            assert_eq!(ins[key]["_src"], SOURCE, "{key}");
            let groups = ins[key]["mod_groups"].as_object().unwrap();
            assert_eq!(groups.len(), 48, "{}: {key}", TABLES[i].0);
            for (name, g) in groups {
                assert_eq!(g["_src"], SOURCE, "{key} {name}");
                assert!(!name.contains("S64") && !name.contains("U64"), "{key} {name}: no 64-bit compare on {}", TABLES[i].1);
                let mut field_mask = 0u128;
                for f in g["fields"].as_array().unwrap() {
                    field_mask |= ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
                }
                assert_eq!(number(&g["variable_mask"]), field_mask, "{key} {name}");
                assert_eq!(field_mask >> 80 & 1, 0, "{key} {name}: bit 80 outside the mask (text-inert, fail closed)");
                assert_eq!(number(&g["and_base"]) >> 80 & 1, 0, "{key} {name}: bit 80 clear in the base");
            }
        }
        for phantom in ["AND,GE,U64", "AND,GT,U64", "AND,NE,S64", "NE,OR,S64"] {
            assert!(ins["ISETP_P_P_R_UR_P"]["mod_groups"].get(phantom).is_none(), "{}: NEEDS 46 phantom group {phantom}", TABLES[i].0);
        }
    }
}

/// The B300 publish corpus' ISETP / UISETP words (nvcc output, nvdisasm 13.3 texts via the strict round trip) keep
/// decoding: a sample of the shapes -- the PT carry-in window, `.reuse`, a negative immediate, the uniform forms.
#[test]
fn witness_words_round_trip() {
    for i in 0..TABLES.len() {
        for (word, vendor) in [
            (0x000fe20003f05070000000ff1600720cu128, "ISETP.NE.U32.AND P0, PT, R22, RZ, PT"),
            (0x040fe20000701270000000ff0400720cu128, "ISETP.LT.AND P0, PT, R4.reuse, RZ, P0"),
            (0x000fe20003f040700000007f0400780cu128, "ISETP.GT.U32.AND P0, PT, R4, 0x7f, PT"),
            (0x000fe2000bf04270000000050b00728cu128, "UISETP.GT.AND UP0, UPT, UR11, UR5, UPT"),
            (0x000fe2000bf05270000000014300788cu128, "UISETP.NE.AND UP0, UPT, UR67, 0x1, UPT"),
            (0x000fe20003f06100000001000300780cu128, "ISETP.GE.U32.AND.EX P0, PT, R3, 0x100, PT, P0"),
            (0x000fe20001743070000000070500780cu128, "ISETP.LE.U32.AND P2, PT, R5, 0x7, P2"),
        ] {
            check(i, word, vendor);
        }
        // the SM120 `.S64` word (bit 80) has no decode here: the bit is text-inert on this target (NEEDS 46)
        let (table, index) = table_and_index(i);
        assert!(index.decode(0x000fe2000bf1527000000006ff007c0cu128, 0, table).is_err(), "{}: bit 80 fails closed", TABLES[i].0);
    }
}
