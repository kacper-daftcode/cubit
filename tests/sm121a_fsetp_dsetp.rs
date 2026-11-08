//! SM121a `FSETP` / `DSETP` rebuilt from measurement (session T-20, 2026-11-08; KNOWN_ISSUES T1 -- the first batch of the
//! GB10 line): the six keys (`FSETP_P_P_R_{R,UR,FI}_P` 0x20b / 0xc0b+91 / 0x80b, `DSETP_P_P_R_{R,UR,FI}_P` 0x22a /
//! 0xe2a+91 / 0x42a) carry the rows `tools/probes/re_sm120_fsetp_dsetp.py --arch SM121` measures with nvdisasm 13.1
//! (1 022 form + 12 glyph + 223 lattice words -- the sm120 law of 2026-11-06 holds word for word on `-b SM121` -- plus
//! the 2 688 FSETP / DSETP words of the GB10 census corpus with their own control codes as witnesses). Law: guard
//! [15:12]; Ra [31:24], `-Ra` 72, `|Ra|` 73; Rb / URb [39:32], `|Rb|` 62, `-Rb` 63, or the immediate at [63:32] (f32; the
//! high half of the f64); the boolean [75:74] (3 = `INVALID3`); the comparison [79:76] (DSETP names 0 / 15 `MIN` / `MAX`);
//! `.FTZ` 80 on FSETP (text-inert on DSETP); Pd0 [83:81]; Pd1 [86:84]; Pc [89:87] + `!` 90; `.reuse` Ra 122 / Rb 123 on
//! FSETP, text-inert on DSETP; [23:16], the unused part of [71:40] and [95:92] text-inert.
//! On this table the harvest had a third of the groups on the plain keys (33 / 32 / 32 of 96, 25 / 16 / 14 of 48), no
//! `FSETP_P_P_R_UR_P` and 105 dotted one-group keys carrying the census words: the missing key created, 312 groups added,
//! the 105 dotted keys and the 7 junk keys of the sm120 batch (`_P_P_R_R_R`, `_P_P_R_R_?`, `_P_P_R_R_P_?`, `FSETP_P_P_II_R_P`,
//! the integer-spelling twin `FSETP_P_P_R_II_P`) retired as `_meta.key_aliases` of the plain key of their operand signature.
//! Closed with it: the GB10 census regression of 2026-11-06 -- the batch-3 decoder arm (FSETP off the sign-tolerant
//! match on every table) had left the sm121a harvest rows, which had no sign fields, without a route for the 564 signed
//! FSETP words of the corpus (`FSETP.GT.AND P0, PT, R9, -R4, PT`, `FSETP.GEU.AND P1, PT, |R5|, …`); 91 927 / 91 927
//! words decode again, 1 text mismatch (the `LEPC` residue of the isolated-word oracle, KNOWN_ISSUES V3).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "fsetp-dsetp-family-2026-11-06";
const CTRL: u128 = 0x000f_e200u128 << 96;
const KEYS: [&str; 6] = ["FSETP_P_P_R_R_P", "FSETP_P_P_R_UR_P", "FSETP_P_P_R_FI_P", "DSETP_P_P_R_R_P", "DSETP_P_P_R_UR_P", "DSETP_P_P_R_FI_P"];
/// The family's aliases on sm121a: the 105 dotted harvest keys (`FSETP.<cmp>[.FTZ].<bool>_P_P_R_{R,UR,FI,II}_P`) and the
/// seven junk keys below (the same lineage as the sm120 batch's REMOVED_JUNK).
const ALIASES: usize = 107;
const JUNK_ALIASES: [(&str, &str); 7] = [
    ("FSETP.GE.FTZ.AND_P_P_R_R_R", "FSETP_P_P_R_R_P"), ("FSETP.NAN.FTZ.AND_P_P_R_R_R", "FSETP_P_P_R_R_P"),
    ("FSETP.NE.FTZ.AND_P_P_R_R_?", "FSETP_P_P_R_FI_P"), ("FSETP.NEU.AND_P_P_R_R_P_?", "FSETP_P_P_R_R_P"),
    ("FSETP.NEU.OR_P_P_R_R_P_?", "FSETP_P_P_R_R_P"), ("FSETP_P_P_II_R_P", "FSETP_P_P_R_R_P"),
    ("FSETP_P_P_R_II_P", "FSETP_P_P_R_FI_P"),
];
const FORM_WORDS: usize = 1022;
const GROUPS: usize = 432;
const GLYPH_WORDS: usize = 12;
const LATTICE_WORDS: usize = 223;
const WITNESS_WORDS: usize = 2688;

fn table_path() -> PathBuf {
    std::env::var_os("CUBIT_TABLE_SM121A").map(PathBuf::from).unwrap_or_else(|| "tables/sm121a.json".into())
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
    include_str!("fixtures/sm121a_fsetp_dsetp_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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

/// Every form word of the sweep (the 432 groups on the canonical operands, the operand lattice of two groups per key,
/// one word per key with every field away from its canonical value) decodes to the six keys, prints NVIDIA's `-b SM121`
/// text and re-encodes bit for bit.
#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    let mut n = 0;
    let mut groups = std::collections::BTreeSet::new();
    for row in fixture() {
        if row.get("lattice").is_some() || row.get("glyph").is_some() || row.get("witness").is_some() {
            continue;
        }
        assert_eq!(row["arch"], "SM121", "{}", row["word"]);
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        groups.insert(check(word, vendor));
        n += 1;
    }
    assert_eq!(n, FORM_WORDS, "form words in the fixture");
    assert_eq!(groups.len(), GROUPS, "96 x 3 FSETP + 48 x 3 DSETP groups");
}

/// The 2 688 FSETP / DSETP words of the GB10 census corpus (`/root/sparklab/results/q1/corpus` on gx4; their own
/// control codes): every one decodes to a plain key, prints the vendor's text and re-encodes bit for bit -- the 564
/// signed words among them had no decode on the 2026-11-06..08 tables.
#[test]
fn the_gb10_census_words_of_the_family_round_trip() {
    let (mut n, mut signed) = (0, 0);
    for row in fixture() {
        if row.get("witness").is_none() || row.get("glyph").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
        check(word, vendor);
        if vendor.contains(", -R") || vendor.contains(", |R") || vendor.contains(", -UR") || vendor.contains(", |UR") {
            signed += 1;
        }
        n += 1;
    }
    assert_eq!(n, WITNESS_WORDS);
    assert!(signed >= 564, "{signed} signed census words (564 failed to decode before the batch)");
}

/// The NaN immediates: nvdisasm prints the `+QNAN ` / `-QNAN ` / `+SNAN ` glyph, cubit's display print does the same
/// and the FSETP lossless print keeps the payload as a hexadecimal that re-encodes (KNOWN_ISSUES A8).
#[test]
fn the_nan_glyph_words_decode_to_the_vendor_glyph() {
    let (table, index) = table_and_index();
    let mut n = 0;
    for row in fixture() {
        if row.get("glyph").is_none() || row.get("witness").is_some() {
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
    assert_eq!(n, GLYPH_WORDS);
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
    assert_eq!(n, LATTICE_WORDS);
    assert_eq!(undecoded, LATTICE_WORDS);
    for text in ["FSETP.GT.INVALID3 P0, PT, R2, R4, PT", "DSETP.GT.INVALID3 P0, PT, R2, R4, PT", "DSETP.GT.FTZ.AND P0, PT, R2, R4, PT"] {
        let parsed = cubit::parser::parse_sass(text, 0).unwrap();
        assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "{text} must be refused");
    }
}

/// The six keys carry the measured groups (`_src`, mask == the fields, nothing baked under a field, the modifier bits of
/// each group name and nothing else), no dotted FSETP / DSETP key is left, the 107 retired keys are aliases of the plain
/// key of their operand signature whose groups include the one they spelled, the provenance legend names the tag.
#[test]
fn the_rows_are_measured_and_the_dotted_keys_are_aliases() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let left: Vec<&String> = ins.keys().filter(|k| k.starts_with("FSETP") || k.starts_with("DSETP")).filter(|k| !KEYS.contains(&k.as_str())).collect();
    assert!(left.is_empty(), "{left:?}");
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    let family: Vec<(&String, &Value)> = aliases.iter().filter(|(k, _)| k.starts_with("FSETP") || k.starts_with("DSETP")).collect();
    assert_eq!(family.len(), ALIASES);
    for (old, new) in JUNK_ALIASES {
        assert_eq!(aliases[old], new, "{old}");
    }
    for (alias, target) in &family {
        let target = target.as_str().unwrap();
        assert!(KEYS.contains(&target), "{alias} -> {target}");
        if JUNK_ALIASES.iter().any(|(k, _)| k == alias) {
            continue;
        }
        // a dotted harvest key: its tokens, sorted, name a group of the plain key of its operand signature
        let (head, sig) = alias.split_once('_').unwrap();
        let mut toks: Vec<&str> = head.split('.').skip(1).collect();
        toks.sort_unstable();
        let plain_sig = if sig == "P_P_R_II_P" { "P_P_R_FI_P" } else { sig };
        assert_eq!(target.split_once('_').unwrap().1, plain_sig, "{alias}");
        assert!(ins[target]["mod_groups"].get(toks.join(",")).is_some(), "{alias}: no group {:?} on {target}", toks.join(","));
    }
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], GROUPS);
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let fcmp = ["F", "LT", "EQ", "LE", "GT", "NE", "GE", "NUM", "NAN", "LTU", "EQU", "LEU", "GTU", "NEU", "GEU", "T"];
    for key in KEYS {
        assert_eq!(ins[key]["_src"], SOURCE, "{key}");
        assert_eq!(ins[key]["base_op"], key.split_once('_').unwrap().0, "{key}");
        assert_eq!(ins[key]["operand_sig"], key.split_once('_').unwrap().1, "{key}");
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

/// The hexadecimal f32 literal still encodes through the `FSETP_P_P_R_II_P` alias on this table too.
#[test]
fn the_hexadecimal_f32_literal_encodes_through_the_alias() {
    let (table, _) = table_and_index();
    let hex = cubit::parser::parse_sass("FSETP.GT.AND P0, PT, R3, 0x3f800000, PT", 0).unwrap();
    assert_eq!(cubit::encoder::encode_instruction(&hex, table).unwrap() & ((1u128 << 96) - 1), 0x0000_0000_03f0_4000_3f80_0000_0300_780b);
}
