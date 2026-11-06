//! SM120 `HSETP2` rebuilt from measurement (session G, 2026-11-06; KNOWN_ISSUES T1): the 384 + 384
//! harvest "mode grid" rows of `HSETP2_P_P_R_R_P` / `HSETP2_P_P_R_UR_P` (no `_src`, flagged
//! `baked_operand_byte` for the modifier bits inside [71:64]) are replaced by the rows
//! `tools/probes/re_sm120_hsetp2.py` measures with nvdisasm 13.1 (1 002 form + 88 lattice words, the same text on
//! `-b SM120` / `SM103` / `SM100`): opcode 0x234 (register form, bit 91 illegal) / 0xe34 + bit 91 (uniform form);
//! guard [15:12]; Ra [31:24] with `-Ra` 72, `|Ra|` 73, selector [75:74]; Rb / URb [39:32] with selector [61:60],
//! `|Rb|` 62, `-Rb` 63; the type [65:64] (fp16 / `.BF16_V2`; 1, 3 = `INVALID1` / `INVALID3`), the boolean [70:69]
//! (AND / OR / XOR; 3 = `INVALID3`), `.H_AND` 71, the comparison [79:76], `.FTZ` 80, Pd0 [83:81], Pd1 [86:84],
//! Pc [89:87] + `!` 90. [23:16], [59:40], 66-68 and [95:92] are text-inert and stay outside the rows. The three
//! dotted harvest keys (`HSETP2.GEU.AND_P_P_R_R_P` / `_R_R_R` / `_R_UR_UR`) are `_meta.key_aliases` of the plain keys.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "hsetp2-family-2026-11-06";
const CTRL: u128 = 0x000f_e200u128 << 96;
const KEYS: [&str; 2] = ["HSETP2_P_P_R_R_P", "HSETP2_P_P_R_UR_P"];

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
    include_str!("fixtures/sm120_hsetp2_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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

/// Every form word of the fixture (the 768 modifier groups on the canonical operands, the operand lattice
/// of two groups per form -- guard, the three predicates with `!Pc`, RZ / URZ, the selectors and signs, `.reuse`
/// -- and one word with every field away from its canonical value) decodes to the measured rows, prints
/// NVIDIA's text and re-encodes bit for bit.
#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    let mut n = 0;
    let mut groups = std::collections::BTreeSet::new();
    for row in fixture() {
        if row.get("lattice").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        groups.insert(check(word, vendor));
        n += 1;
    }
    assert_eq!(n, 1002, "form words in the fixture");
    assert_eq!(groups.len(), 768, "2 forms x 384 modifier groups");
}

/// The lattice: the vendor's `INVALID1` / `INVALID3` type and boolean codes, the frame bit flipped, the
/// text-inert bits -- never claimed. The selector code 1 (`R3.INVALID1`, `UR3.INVALID1`) is the one lattice
/// value inside a field: cubit decodes it to the vendor's glyph, never to a valid selector, and the encoder
/// refuses the spelling (BUG-272).
#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    let (table, index) = table_and_index();
    let (mut n, mut undecoded, mut glyphs) = (0, 0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        n += 1;
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        let vendor = row["nvidia_sass"].as_str();
        match index.decode(word, 0, table) {
            Err(_) => undecoded += 1,
            Ok(d) => {
                let own = cubit::printer::to_sass_lossless(&d);
                let v = vendor.unwrap_or("");
                assert!(v.contains(".INVALID1") && !v.starts_with("HSETP2.INVALID"), "lattice word {word:032x} ({v:?}) decodes as {own}");
                assert_eq!(own, v, "{word:032x}");
                glyphs += 1;
            }
        }
    }
    assert_eq!(n, 88);
    assert_eq!((undecoded, glyphs), (82, 6), "inert bits, INVALID codes and the wrong frame bit stay unclaimed; the 6 selector glyphs print as the vendor does");
    for text in ["HSETP2.GEU.AND P0, PT, R2, R3.INVALID1, PT", "HSETP2.GEU.AND P0, PT, R2.INVALID1, UR3, PT",
                 "HSETP2.INVALID1.GEU.AND P0, PT, R2, R3, PT", "HSETP2.GEU.INVALID3 P0, PT, R2, R3, PT"] {
        let parsed = cubit::parser::parse_sass(text, 0).unwrap();
        assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "{text} must be refused");
    }
}

/// The two keys carry 384 measured groups each (`_src`, mask == the fields, nothing baked under a field, no
/// control bits), the dotted harvest keys are gone and aliased, the provenance legend names the tag.
#[test]
fn the_rows_are_measured_and_the_dotted_keys_are_aliases() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let dotted: Vec<&String> = ins.keys().filter(|k| k.starts_with("HSETP2.")).collect();
    assert!(dotted.is_empty(), "{dotted:?}");
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    assert_eq!(aliases["HSETP2.GEU.AND_P_P_R_R_P"], "HSETP2_P_P_R_R_P");
    assert_eq!(aliases["HSETP2.GEU.AND_P_P_R_R_R"], "HSETP2_P_P_R_R_P");
    assert_eq!(aliases["HSETP2.GEU.AND_P_P_R_UR_UR"], "HSETP2_P_P_R_UR_P");
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 768);
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    for key in KEYS {
        assert_eq!(ins[key]["_src"], SOURCE, "{key}");
        let groups = ins[key]["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), 384, "{key}");
        for (name, g) in groups {
            assert_eq!(g["_src"], SOURCE, "{key} {name}");
            assert!(g["count"].is_null(), "{key} {name}: a measured row carries no harvest count");
            let mut field_mask = 0u128;
            for f in g["fields"].as_array().unwrap() {
                let bits = ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
                assert_eq!(field_mask & bits, 0, "{name}: overlapping fields");
                field_mask |= bits;
            }
            assert_eq!(number(&g["variable_mask"]), field_mask, "{key} {name}");
            assert_eq!(number(&g["and_base"]) >> 105, 0, "{key} {name}");
            assert_eq!(number(&g["and_base"]) & field_mask, 0, "{key} {name}");
            // the modifier bits of the group name and nothing else above the opcode
            let base = number(&g["and_base"]) & !0xfffu128 & !(1u128 << 91);
            let mut want = 0u128;
            for m in name.split(',') {
                want |= match m {
                    "AND" => 0, "OR" => 1 << 69, "XOR" => 1 << 70, "H_AND" => 1 << 71, "FTZ" => 1 << 80, "BF16_V2" => 1 << 65,
                    cmp => (["F", "LT", "EQ", "LE", "GT", "NE", "GE", "NUM", "NAN", "LTU", "EQU", "LEU", "GTU", "NEU", "GEU", "T"]
                        .iter().position(|c| *c == cmp).unwrap() as u128) << 76,
                };
            }
            assert_eq!(base, want, "{key} {name}");
        }
    }
}

/// The audit's canonical words of the harvest rows and the shapes the production kernels use.
#[test]
fn witness_words_round_trip() {
    for (word, vendor) in [
        (0x000fe20003f0e0000000000302007234u128, "HSETP2.GEU.AND P0, PT, R2, R3, PT"),
        (0x000fe2000bf0e8002000000302007e34u128, "HSETP2.GEU.AND P0, PT, R2.H0_H0, UR3.H0_H0, PT"),
        (0x000fe20003f102c28000000302007234u128, "HSETP2.BF16_V2.F.H_AND.FTZ.XOR P0, PT, |R2|, -R3, PT"),
    ] {
        check(word, vendor);
    }
}
