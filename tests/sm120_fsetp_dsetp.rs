//! SM120 `FSETP` / `DSETP` rebuilt from measurement (session G, 2026-11-06; KNOWN_ISSUES T1): the six keys
//! (`FSETP_P_P_R_{R,UR,FI}_P` 0x20b / 0xc0b+91 / 0x80b, `DSETP_P_P_R_{R,UR,FI}_P` 0x22a / 0xe2a+91 / 0x42a) carry the
//! rows `tools/probes/re_sm120_fsetp_dsetp.py` measures with nvdisasm 13.1 (1 022 form + 12 glyph + 223 lattice
//! words, the same text on `-b SM120` / `SM103` / `SM100`). Law: guard [15:12]; Ra [31:24], `-Ra` 72, `|Ra|` 73;
//! Rb / URb [39:32], `|Rb|` 62, `-Rb` 63, or the immediate at [63:32] (f32; the high half of the f64); the boolean
//! [75:74] (3 = `INVALID3`); the comparison [79:76] (DSETP names 0 / 15 `MIN` / `MAX`); `.FTZ` 80 on FSETP
//! (text-inert on DSETP); Pd0 [83:81]; Pd1 [86:84]; Pc [89:87] + `!` 90; `.reuse` Ra 122 / Rb 123 on FSETP, text-inert
//! on DSETP; [23:16], the unused part of [71:40] and [95:92] text-inert. Retired: 100 dotted encode-only twins
//! (byte-identical copies of the plain groups) and the "label" key `FSETP_P_P_L_L_P` deleted, 10 mis-tokenised harvest
//! keys and the integer-spelling twin `FSETP_P_P_R_II_P` as `_meta.key_aliases` (the hexadecimal f32 literal still
//! encodes through the alias).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "fsetp-dsetp-family-2026-11-06";
const CTRL: u128 = 0x000f_e200u128 << 96;
const KEYS: [&str; 6] = ["FSETP_P_P_R_R_P", "FSETP_P_P_R_UR_P", "FSETP_P_P_R_FI_P", "DSETP_P_P_R_R_P", "DSETP_P_P_R_UR_P", "DSETP_P_P_R_FI_P"];
const ALIASES: [(&str, &str); 11] = [
    ("FSETP.GE.FTZ.AND_P_P_R_R_R", "FSETP_P_P_R_R_P"), ("FSETP.NAN.FTZ.AND_P_P_R_R_R", "FSETP_P_P_R_R_P"),
    ("FSETP.GEU.AND_P_P_R_UR_UR", "FSETP_P_P_R_UR_P"), ("FSETP.NEU.AND_P_P_R_UR_UR", "FSETP_P_P_R_UR_P"),
    ("FSETP.NEU.OR_P_P_R_UR_UR", "FSETP_P_P_R_UR_P"), ("FSETP.NE.FTZ.AND_P_P_R_R_?", "FSETP_P_P_R_FI_P"),
    ("FSETP.NEU.AND_P_P_R_R_P_?", "FSETP_P_P_R_R_P"), ("FSETP.NEU.OR_P_P_R_R_P_?", "FSETP_P_P_R_R_P"),
    ("FSETP_P_P_II_II_P", "FSETP_P_P_R_FI_P"), ("FSETP_P_P_II_R_P", "FSETP_P_P_R_R_P"),
    ("FSETP_P_P_R_II_P", "FSETP_P_P_R_FI_P"),
];

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
    include_str!("fixtures/sm120_fsetp_dsetp_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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

fn check(word: u128, vendor: &str) -> (String, String) {
    let (table, index) = table_and_index();
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
    assert!(KEYS.contains(&decoded.key.as_str()), "{word:032x}: {}", decoded.key);
    let own = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(own, vendor, "{word:032x}");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
    (decoded.key.clone(), decoded.mod_group.clone())
}

/// Every form word (the 432 groups on the canonical operands, the operand lattice of two groups per key -- guard,
/// the three predicates with `!Pc`, RZ / URZ, the signs, 14 f32 / 13 f64 immediates incl. `+INF `, `-INF `, `-0.0 `
/// and the denormals, `.reuse` -- and one word per key with every field away from its canonical value) decodes to
/// the six keys, prints NVIDIA's text and re-encodes bit for bit.
#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    let mut n = 0;
    let mut groups = std::collections::BTreeSet::new();
    for row in fixture() {
        if row.get("lattice").is_some() || row.get("glyph").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        groups.insert(check(word, vendor));
        n += 1;
    }
    assert_eq!(n, 1022, "form words in the fixture");
    assert_eq!(groups.len(), 432, "96 x 3 FSETP + 48 x 3 DSETP groups");
}

/// The NaN immediates: nvdisasm prints the `+QNAN ` / `-QNAN ` / `+SNAN ` glyph, cubit's display print does the same
/// and the lossless print keeps the payload (KNOWN_ISSUES A8: the f32 lane re-encodes from its hexadecimal literal,
/// the f64 lane has no literal yet -- the glyph words document the gap instead of hiding it).
#[test]
fn the_nan_glyph_words_decode_to_the_vendor_glyph() {
    let (table, index) = table_and_index();
    let mut n = 0;
    for row in fixture() {
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
    assert_eq!(n, 12);
}

/// The lattice: the `INVALID3` boolean, the frame bit flipped (illegal), the text-inert bits -- never claimed.
#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    let (table, index) = table_and_index();
    let (mut n, mut undecoded) = (0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        n += 1;
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        match index.decode(word, 0, table) {
            Err(_) => undecoded += 1,
            Ok(d) => panic!("lattice word {word:032x} ({:?}) decodes as {}", row["nvidia_sass"], cubit::printer::to_sass_lossless(&d)),
        }
    }
    assert_eq!(n, 223);
    assert_eq!(undecoded, 223);
    for text in ["FSETP.GT.INVALID3 P0, PT, R2, R4, PT", "DSETP.GT.INVALID3 P0, PT, R2, R4, PT", "DSETP.GT.FTZ.AND P0, PT, R2, R4, PT"] {
        let parsed = cubit::parser::parse_sass(text, 0).unwrap();
        assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "{text} must be refused");
    }
}

/// The six keys carry the measured groups (`_src`, mask == the fields, nothing baked under a field, the modifier
/// bits of each group name and nothing else), the 100 dotted twins and the label key are gone, the 11 junk keys are
/// aliases of the plain keys, the provenance legend names the tag.
#[test]
fn the_rows_are_measured_and_the_junk_keys_are_gone() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let left: Vec<&String> = ins.keys().filter(|k| k.starts_with("FSETP") || k.starts_with("DSETP")).filter(|k| !KEYS.contains(&k.as_str())).collect();
    assert!(left.is_empty(), "{left:?}");
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    for (old, new) in ALIASES {
        assert_eq!(aliases[old], new, "{old}");
    }
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 432);
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let fcmp = ["F", "LT", "EQ", "LE", "GT", "NE", "GE", "NUM", "NAN", "LTU", "EQU", "LEU", "GTU", "NEU", "GEU", "T"];
    for key in KEYS {
        assert_eq!(ins[key]["_src"], SOURCE, "{key}");
        let double = key.starts_with("DSETP");
        let groups = ins[key]["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), if double { 48 } else { 96 }, "{key}");
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
            assert_eq!(field_mask & (3u128 << 122) != 0, !double, "{key} {name}: .reuse fields on FSETP only");
        }
    }
}

/// Production census words (nvcc output, incl. `|R|` and the decimal immediates), the BUG-226 anchors and the
/// hexadecimal f32 literal that encodes through the `FSETP_P_P_R_II_P` alias.
#[test]
fn witness_words_round_trip() {
    for (word, vendor) in [
        (0x000fe20003f24200000000615800720bu128, "FSETP.GT.AND P1, PT, |R88|, R97, PT"),
        (0x000fe20003f14000000000ff0900720bu128, "FSETP.GT.FTZ.AND P0, PT, R9, RZ, PT"),
        (0x000fe20003f34000efa18f082d00780bu128, "FSETP.GT.FTZ.AND P1, PT, R45, -1.00000001504746621988e+29, PT"),
        (0x000fe2000c7024000000000cff007c0bu128, "FSETP.EQ.OR P0, PT, RZ, UR12, !P0"),
        (0x000fe2000472e600008000000a00780bu128, "FSETP.GEU.OR P1, PT, |R10|, 1.175494350822287508e-38, !P0"),
        (0x000fe20003f04000000000040200722au128, "DSETP.GT.AND P0, PT, R2, R4, PT"),
        (0x000fe20003f000003ff000000200742au128, "DSETP.MIN.AND P0, PT, R2, 1, PT"),
    ] {
        check(word, vendor);
    }
    let (table, _) = table_and_index();
    let hex = cubit::parser::parse_sass("FSETP.GT.AND P0, PT, R3, 0x3f800000, PT", 0).unwrap();
    assert_eq!(cubit::encoder::encode_instruction(&hex, table).unwrap() & ((1u128 << 96) - 1), 0x0000_0000_03f0_4000_3f80_0000_0300_780b,
               "the hexadecimal f32 literal encodes through the FSETP_P_P_R_II_P alias");
}
