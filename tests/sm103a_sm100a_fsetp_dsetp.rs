//! SM103a / SM100a `FSETP` / `DSETP` rebuilt from measurement on `-b SM103` / `SM100` (session T-21, 2026-11-08,
//! `tools/probes/re_sm120_fsetp_dsetp.py probe --arch SM103` / `SM100`, nvdisasm 13.1; `T/NEEDS_OWNER.md` 58): every one
//! of the 1 022 form, 12 glyph and 223 lattice words of G's sweep obeys the sm120 law of 2026-11-06 word for word on
//! both targets (G's sweep had recorded "the same text on `-b SM103` / `SM100`"; asserted now). The six plain keys
//! (`FSETP_P_P_R_{R,UR,FI}_P`, `DSETP_P_P_R_{R,UR,FI}_P`) carry the 432 measured rows: on these tables the harvest had
//! 110 rows (10..26 groups per key) with the boolean bit 75 read as `.OR` where the vendor prints `.XOR` and `|Rb|`
//! baked into `DSETP_P_P_R_R_P` `LTU,OR` (bug254's 2026-08 sentinel) -- both gone with the rewrite; 322 groups added.
//! The sm120 test `tests/sm120_fsetp_dsetp.rs` is the template (these tables had no dotted twins or junk keys of the
//! family, so there is nothing to alias). Gate: the B300 publish corpus strict round trip unchanged (85 704 / 85 792;
//! 0 corpus words changed text or key -- nvcc writes no XOR-boolean DSETP).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "fsetp-dsetp-family-2026-11-06";
const CTRL: u128 = 0x000f_e200u128 << 96;
const KEYS: [&str; 6] = ["FSETP_P_P_R_R_P", "FSETP_P_P_R_UR_P", "FSETP_P_P_R_FI_P", "DSETP_P_P_R_R_P", "DSETP_P_P_R_UR_P", "DSETP_P_P_R_FI_P"];
const TABLES: [(&str, &str, &str); 2] = [
    ("tables/sm103a.json", "SM103", include_str!("fixtures/sm103a_fsetp_dsetp_nvdisasm.jsonl")),
    ("tables/sm100a.json", "SM100", include_str!("fixtures/sm100a_fsetp_dsetp_nvdisasm.jsonl")),
];

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

/// Every form word decodes to one of the six keys, prints NVIDIA's text (display and lossless) and re-encodes bit for
/// bit; the 432 groups all have a form word.
#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    for i in 0..TABLES.len() {
        let mut n = 0;
        let mut groups = std::collections::BTreeSet::new();
        for row in fixture(i) {
            if row.get("lattice").is_some() || row.get("glyph").is_some() {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
            groups.insert(check(i, word, row["nvidia_sass"].as_str().unwrap()));
            n += 1;
        }
        assert_eq!(n, 1022, "{}: form words in the fixture", TABLES[i].0);
        assert_eq!(groups.len(), 432, "{}: every group of the six keys has a form word", TABLES[i].0);
    }
}

/// The NaN immediates: nvdisasm prints the `+QNAN ` / `-QNAN ` / `+SNAN ` glyph, cubit's display print does the same
/// and the FSETP lossless print keeps the payload as a hexadecimal that re-encodes (KNOWN_ISSUES A8).
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
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
            let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
            assert!(KEYS.contains(&decoded.key.as_str()), "{word:032x}: {}", decoded.key);
            assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{word:032x}");
            if decoded.key.starts_with("FSETP") {
                let lossless = cubit::printer::to_sass_lossless(&decoded);
                assert_eq!(reencode(table, word, &lossless), word, "{lossless}");
            }
        }
        assert_eq!(n, 12, "{}", TABLES[i].0);
    }
}

/// The lattice: the `INVALID3` boolean, the frame bit flipped (illegal), the text-inert bits -- never claimed; the
/// `INVALID3` and the DSETP `.FTZ` spellings refused by the encoder.
#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    for i in 0..TABLES.len() {
        let (table, index) = table_and_index(i);
        let mut n = 0;
        for row in fixture(i) {
            if row.get("lattice").is_none() {
                continue;
            }
            n += 1;
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
            if let Ok(d) = index.decode(word, 0, table) {
                panic!("{}: lattice word {word:032x} ({:?}) decodes as {}", TABLES[i].0, row["nvidia_sass"], cubit::printer::to_sass_lossless(&d));
            }
        }
        assert_eq!(n, 223, "{}", TABLES[i].0);
        for text in ["FSETP.GT.INVALID3 P0, PT, R2, R4, PT", "DSETP.GT.INVALID3 P0, PT, R2, R4, PT", "DSETP.GT.FTZ.AND P0, PT, R2, R4, PT"] {
            let parsed = cubit::parser::parse_sass(text, 0).unwrap();
            assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "{}: {text} must be refused", TABLES[i].0);
        }
    }
}

/// The six keys carry exactly the measured groups (`_src`, mask == the fields, nothing baked under a field, the modifier
/// bits of each group name and nothing else -- in particular the boolean `XOR` is bit 75 and no `|Rb|` is baked), no
/// other FSETP / DSETP key exists, and the legend counts the 432 rows.
#[test]
fn the_rows_are_measured_and_bit_75_is_the_vendors_xor() {
    for i in 0..TABLES.len() {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path(i)).unwrap()).unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        let left: Vec<&String> = ins.keys().filter(|k| k.starts_with("FSETP") || k.starts_with("DSETP")).filter(|k| !KEYS.contains(&k.as_str())).collect();
        assert!(left.is_empty(), "{}: {left:?}", TABLES[i].0);
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 432, "{}", TABLES[i].0);
        let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        let fcmp = ["F", "LT", "EQ", "LE", "GT", "NE", "GE", "NUM", "NAN", "LTU", "EQU", "LEU", "GTU", "NEU", "GEU", "T"];
        for key in KEYS {
            assert_eq!(ins[key]["_src"], SOURCE, "{key}");
            let double = key.starts_with("DSETP");
            let groups = ins[key]["mod_groups"].as_object().unwrap();
            assert_eq!(groups.len(), if double { 48 } else { 96 }, "{}: {key}", TABLES[i].0);
            for (name, g) in groups {
                assert_eq!(g["_src"], SOURCE, "{key} {name}");
                let mut field_mask = 0u128;
                for f in g["fields"].as_array().unwrap() {
                    let bits = ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
                    assert_eq!(field_mask & bits, 0, "{name}: overlapping fields");
                    field_mask |= bits;
                }
                assert_eq!(number(&g["variable_mask"]), field_mask, "{key} {name}");
                let base = number(&g["and_base"]);
                assert_eq!(base >> 105, 0, "{key} {name}");
                assert_eq!(base & field_mask, 0, "{key} {name}");
                let mut want = 0u128;
                for m in name.split(',') {
                    want |= match m {
                        "AND" => 0, "OR" => 1 << 74, "XOR" => 2 << 74, "FTZ" => 1 << 80,
                        "MIN" => 0, "MAX" => 15 << 76,
                        c => (fcmp.iter().position(|x| *x == c).unwrap() as u128) << 76,
                    };
                }
                assert_eq!(base & !0xfffu128 & !(1u128 << 91), want, "{key} {name}");
                // the operand signs are fields on every row (NEEDS 58: the donors baked |Rb| into DSETP LTU,OR)
                assert!(field_mask & (1u128 << 62) != 0 && field_mask & (1u128 << 73) != 0, "{key} {name}: |Rb| / |Ra| are fields");
            }
        }
    }
}

/// The donors' harvest reading (bug254's 2026-08 sentinel, pinned on these legs until this batch): the word with the
/// boolean code 2 at [75:74] printed `.OR`; it is the vendor's `.XOR` on `-b SM103` / `SM100` as on SM120 / SM121.
#[test]
fn bit_75_prints_xor_on_the_donor_tables() {
    for i in 0..TABLES.len() {
        let (table, index) = table_and_index(i);
        // DSETP.LTU.XOR P0, PT, R2, R4, PT (nvdisasm 13.1 on SM103 / SM100 / SM120: the comparison 9 = LTU at [79:76],
        // the boolean 2 = XOR at [75:74])
        let word = 0x000fe20003f09800000000040200722au128;
        let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
        let text = cubit::printer::to_sass(&decoded);
        assert!(text.starts_with("DSETP.LTU.XOR "), "{}: {text}", TABLES[i].0);
        assert!(!text.contains('|'), "{}: no baked |Rb|: {text}", TABLES[i].0);
        assert_eq!(reencode(table, word, &text), word);
    }
}

/// Production census words of the B300 corpus' shape (nvcc output: `|R|`, FTZ, the uniform form, a decimal immediate).
#[test]
fn witness_words_round_trip() {
    for i in 0..TABLES.len() {
        for (word, vendor) in [
            (0x000fe20003f24200000000615800720bu128, "FSETP.GT.AND P1, PT, |R88|, R97, PT"),
            (0x000fe20003f14000000000ff0900720bu128, "FSETP.GT.FTZ.AND P0, PT, R9, RZ, PT"),
            (0x000fe20003f34000efa18f082d00780bu128, "FSETP.GT.FTZ.AND P1, PT, R45, -1.00000001504746621988e+29, PT"),
            (0x000fe2000c7024000000000cff007c0bu128, "FSETP.EQ.OR P0, PT, RZ, UR12, !P0"),
            (0x000fe2000472e600008000000a00780bu128, "FSETP.GEU.OR P1, PT, |R10|, 1.175494350822287508e-38, !P0"),
            (0x000fe20003f04000000000040200722au128, "DSETP.GT.AND P0, PT, R2, R4, PT"),
            (0x000fe20003f000003ff000000200742au128, "DSETP.MIN.AND P0, PT, R2, 1, PT"),
        ] {
            check(i, word, vendor);
        }
    }
}
