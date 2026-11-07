//! SM120 `UFSETP` rebuilt from measurement (session G, 2026-11-06; KNOWN_ISSUES T1): the two keys
//! `UFSETP_UP_UP_UR_{UR,FI}_UP` (0x253 + 91 / 0x853 + 91) carry the rows `tools/probes/re_sm120_ufsetp.py` measures with
//! nvdisasm 13.1 (394 form + 6 glyph + 66 lattice words). The family is SM120-only: on `-b SM103` / `SM100` nvdisasm
//! rejects every word of the sweep. Law = the FSETP law in the uniform datapath: guard [15:12] (`@UPn`); URa [31:24],
//! `-URa` 72, `|URa|` 73; URb [39:32], `|URb|` 62, `-URb` 63, or the f32 immediate at [63:32]; the boolean [75:74]
//! (3 = `INVALID3`); the comparison [79:76]; `.FTZ` 80; UPd0 [83:81]; UPd1 [86:84]; UPc [89:87] + `!` 90; no `.reuse`;
//! [23:16], the unused part of [71:40] and [95:92] text-inert. Retired: the integer-spelling twin `UFSETP_UP_UP_UR_II_UP`
//! (the hexadecimal f32 literal still encodes through the alias) and five dotted junk keys as `_meta.key_aliases`.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "ufsetp-family-2026-11-06";
const CTRL: u128 = 0x000f_e200u128 << 96;
const KEYS: [&str; 2] = ["UFSETP_UP_UP_UR_UR_UP", "UFSETP_UP_UP_UR_FI_UP"];
const ALIASES: [(&str, &str); 6] = [
    ("UFSETP.GT.AND_UP_UP_UR_UR_UP", "UFSETP_UP_UP_UR_UR_UP"), ("UFSETP.NEU.AND_UP_UP_UR_UR_UP", "UFSETP_UP_UP_UR_UR_UP"),
    ("UFSETP.NEU.OR_UP_UP_UR_UR_UP", "UFSETP_UP_UP_UR_UR_UP"), ("UFSETP.NEU.AND_UP_UP_UR_FI_UP", "UFSETP_UP_UP_UR_FI_UP"),
    ("UFSETP.NEU.AND_UP_UP_UR_II_UP", "UFSETP_UP_UP_UR_FI_UP"), ("UFSETP_UP_UP_UR_II_UP", "UFSETP_UP_UP_UR_FI_UP"),
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
    include_str!("fixtures/sm120_ufsetp_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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

/// Every form word (the 192 groups on the canonical operands, the operand lattice of two groups per key -- guard,
/// the three uniform predicates with `!UPc`, URZ, the signs, 14 f32 immediates incl. `+INF `, `-INF `, `-0.0 ` and
/// the denormals -- and one word per key with every field away from its canonical value) decodes to the two keys,
/// prints NVIDIA's text and re-encodes bit for bit.
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
    assert_eq!(n, 394, "form words in the fixture");
    assert_eq!(groups.len(), 192, "96 x 2 UFSETP groups");
}

/// The NaN immediates: nvdisasm prints the `+QNAN ` / `-QNAN ` / `+SNAN ` glyph, cubit's display print does the same
/// and the lossless print keeps the payload as a hexadecimal that re-encodes (KNOWN_ISSUES A8, the f32 lane).
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
        let lossless = cubit::printer::to_sass_lossless(&decoded);
        assert_eq!(reencode(table, word, &lossless), word, "{lossless}");
    }
    assert_eq!(n, 6);
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
    assert_eq!(n, 66);
    assert_eq!(undecoded, 66);
    for text in ["UFSETP.GT.INVALID3 UP0, UPT, UR2, UR4, UPT", "UFSETP.GT.AND UP0, UPT, UR2.reuse, UR4, UPT"] {
        let parsed = cubit::parser::parse_sass(text, 0).unwrap();
        assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "{text} must be refused");
    }
}

/// The two keys carry 96 measured groups each (`_src`, mask == the fields, nothing baked under a field, the modifier
/// bits of each group name and nothing else, no `.reuse` field), the six junk keys are aliases of the plain keys, the
/// provenance legend names the tag.
#[test]
fn the_rows_are_measured_and_the_junk_keys_are_gone() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let left: Vec<&String> = ins.keys().filter(|k| k.starts_with("UFSETP")).filter(|k| !KEYS.contains(&k.as_str())).collect();
    assert!(left.is_empty(), "{left:?}");
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    for (old, new) in ALIASES {
        assert_eq!(aliases[old], new, "{old}");
    }
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 192);
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let fcmp = ["F", "LT", "EQ", "LE", "GT", "NE", "GE", "NUM", "NAN", "LTU", "EQU", "LEU", "GTU", "NEU", "GEU", "T"];
    for key in KEYS {
        assert_eq!(ins[key]["_src"], SOURCE, "{key}");
        let groups = ins[key]["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), 96, "{key}");
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
                    c => (fcmp.iter().position(|x| *x == c).unwrap() as u128) << 76,
                };
            }
            assert_eq!(base & !0xfffu128 & !(1u128 << 91), want, "{key} {name}");
            assert_eq!(field_mask & (3u128 << 122), 0, "{key} {name}: no .reuse field on the uniform form");
            assert_ne!(field_mask & (1u128 << 12), 0, "{key} {name}: the uniform guard is a field");
        }
    }
}

/// The canonical words of the harvest rows (the family has no production census witness) and the hexadecimal f32
/// literal that encodes through the `UFSETP_UP_UP_UR_II_UP` alias.
#[test]
fn witness_words_round_trip() {
    for (word, vendor) in [
        (0x000fe2000bf040000000000402007253u128, "UFSETP.GT.AND UP0, UPT, UR2, UR4, UPT"),
        (0x000fe2000bf1d8003f80000002007853u128, "UFSETP.NEU.FTZ.XOR UP0, UPT, UR2, 1, UPT"),
    ] {
        check(word, vendor);
    }
    let (table, _) = table_and_index();
    let hex = cubit::parser::parse_sass("UFSETP.GT.AND UP0, UPT, UR3, 0x3f800000, UPT", 0).unwrap();
    assert_eq!(cubit::encoder::encode_instruction(&hex, table).unwrap() & ((1u128 << 96) - 1), 0x0000_0000_0bf0_4000_3f80_0000_0300_7853,
               "the hexadecimal f32 literal encodes through the UFSETP_UP_UP_UR_II_UP alias");
}
