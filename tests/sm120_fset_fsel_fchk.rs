//! SM120 FSET / FSEL / FCHK rebuilt from measurement (session G, 2026-11-07; KNOWN_ISSUES T1): the nine plain keys
//! `FSET_R_R_{R,FI,UR}_P` (0x20a / 0x80a / 0xc0a+91), `FSEL_R_R_{R,FI,UR}_P` (0x208 / 0x808 / 0xc08+91), `FCHK_P_R_{R,FI,UR}`
//! (0x302 / 0x902 / 0xd02+91) carry the rows `tools/probes/re_sm120_fset_fsel_fchk.py` measures with nvdisasm 13.1 (885
//! form + 15 glyph + 375 lattice words; the same text on `-b SM103` / `SM100`). Law: guard [15:12]; Rd [23:16] or Pd
//! [83:81] (FCHK); Ra [31:24] (`-` 72, `|` 73, `.reuse` 122); the B operand [39:32] (`|` 62, `-` 63; Rb `.reuse` 123) or
//! the f32 immediate [63:32]; FSET = the FSETP law with a register destination -- boolean [75:74] (3 = `INVALID3`),
//! comparison [79:76], FTZ 80, Pc [89:87] + `!` 90, `.BF` on every word, printed `FSET.BF.<cmp>[.FTZ].<bool>`; FSEL =
//! `[.FTZ]` + Pc; FCHK = no modifier, no `.reuse`. Retired: `FSET.BF.F.AND_R_R_R_P`, six FSEL junk keys and the
//! integer-spelling `FCHK_P_R_II` as `_meta.key_aliases`; the BUG-178 / BUG-249 `+QNAN` lane `FSEL_R_R_II_P` stays.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "fset-fsel-fchk-family-2026-11-07";
const CTRL: u128 = 0x000f_e200u128 << 96;
const KEYS: [(&str, usize); 9] = [
    ("FSET_R_R_R_P", 96), ("FSET_R_R_FI_P", 96), ("FSET_R_R_UR_P", 96),
    ("FSEL_R_R_R_P", 2), ("FSEL_R_R_FI_P", 2), ("FSEL_R_R_UR_P", 2),
    ("FCHK_P_R_R", 1), ("FCHK_P_R_FI", 1), ("FCHK_P_R_UR", 1),
];
const ALIASES: [(&str, &str); 8] = [
    ("FSET.BF.F.AND_R_R_R_P", "FSET_R_R_R_P"),
    ("FSEL_R_R_?_P_P", "FSEL_R_R_FI_P"), ("FSEL_R_R_II_P_P", "FSEL_R_R_FI_P"),
    ("FSEL_R_R_R_P_II_?", "FSEL_R_R_R_P"), ("FSEL_R_R_R_P_II_II_?", "FSEL_R_R_R_P"), ("FSEL_R_R_R_P_II_II_II_?", "FSEL_R_R_R_P"),
    ("FSEL_R_R_R_P_P", "FSEL_R_R_R_P"), ("FCHK_P_R_II", "FCHK_P_R_FI"),
];
const FCMP: [&str; 16] = ["F", "LT", "EQ", "LE", "GT", "NE", "GE", "NUM", "NAN", "LTU", "EQU", "LEU", "GTU", "NEU", "GEU", "T"];

fn is_family_key(k: &str) -> bool {
    KEYS.iter().any(|(key, _)| *key == k)
}

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
    include_str!("fixtures/sm120_fset_fsel_fchk_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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

fn check(word: u128, vendor: &str) -> (String, String) {
    let (table, index) = table_and_index();
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
    assert!(is_family_key(&decoded.key), "{word:032x}: {}", decoded.key);
    let own = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(own, vendor, "{word:032x}");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
    (decoded.key.clone(), decoded.mod_group.clone())
}

/// Every form word (the 297 groups on the canonical operands, the operand lattice of two groups per key -- guard,
/// Rd / Pd / Ra / Rb / URb at 0, 1, 63 and 255, every sign and `|abs|` combination, the `.reuse` bits where the
/// mnemonic has them, 14 f32 immediates incl. `+INF`, `-INF`, `-0.0` and the denormals, the eight predicates with `!`
/// -- and one word per key with every field away from its canonical value) decodes to the nine keys, prints NVIDIA's
/// text and re-encodes bit for bit.
#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    let mut n = 0;
    let mut groups = std::collections::BTreeSet::new();
    for row in fixture() {
        if row.get("lattice").is_some() || row.get("glyph").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        groups.insert(check(word_of(&row), vendor));
        n += 1;
    }
    assert_eq!(n, 885, "form words in the fixture");
    assert_eq!(groups.len(), 297, "96 x 3 FSET + 2 x 3 FSEL + 1 x 3 FCHK groups");
}

/// The NaN immediates: nvdisasm prints the `+QNAN` / `-QNAN` / `+SNAN` glyph, cubit's display print does the same
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
        let word = word_of(&row);
        let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
        assert!(is_family_key(&decoded.key), "{word:032x}: {}", decoded.key);
        assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{word:032x}");
        let lossless = cubit::printer::to_sass_lossless(&decoded);
        assert_eq!(reencode(table, word, &lossless), word, "{lossless}");
    }
    assert_eq!(n, 15);
}

/// The lattice: the frame bit flipped (illegal), the text-inert bits, FSET's `INVALID3` boolean -- never claimed.
/// The encoder refuses the invalid states and `.reuse` where the mnemonic has none.
#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    let (table, index) = table_and_index();
    let (mut n, mut undecoded) = (0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        n += 1;
        let word = word_of(&row);
        match index.decode(word, 0, table) {
            Err(_) => undecoded += 1,
            Ok(d) => panic!("lattice word {word:032x} ({:?}) decodes as {}", row["nvidia_sass"], cubit::printer::to_sass_lossless(&d)),
        }
    }
    assert_eq!((n, undecoded), (375, 375));
    for text in ["FSET.BF.GT.INVALID3 R4, R2, R3, PT", "FSET.GT.AND R4, R2, R3, PT", "FSEL.SAT R4, R2, R3, PT",
                 "FSET.BF.GT.AND R4, R2, UR3.reuse, PT", "FCHK.FTZ P0, R2, R3"] {
        let refused = cubit::parser::parse_sass(text, 0).map_or(true, |p| cubit::encoder::encode_instruction(&p, table).is_err());
        assert!(refused, "{text} must be refused");
    }
}

/// The nine keys carry their full measured grid (`_src`, mask == the fields, nothing baked under a field, the
/// modifier bits of each group name and nothing else, no `.reuse` field on FCHK), the eight junk keys are aliases
/// and nothing else of the three mnemonics is left but the kept `+QNAN` lane, the provenance legend names the tag.
#[test]
fn the_rows_are_measured_and_the_junk_keys_are_gone() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let left: Vec<&String> = ins.keys()
        .filter(|k| ["FSET_", "FSET.", "FSEL_", "FSEL.", "FCHK_", "FCHK."].iter().any(|p| k.starts_with(p)))
        .filter(|k| !is_family_key(k) && *k != "FSEL_R_R_II_P").collect();
    assert!(left.is_empty(), "{left:?}");
    // the BUG-178 / BUG-249 canonical `+QNAN` lane stays (the quiet NaN 0x7fc00000 baked; `FSEL Rd, Ra, QNAN, Pc`
    // encodes the canonical payload on every table, `-QNAN` / `+SNAN` refuse) -- measured by that wave, not harvest
    assert_eq!(ins["FSEL_R_R_II_P"]["mod_groups"][""]["_src"], "bug249-2026-08-28");
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    for (old, new) in ALIASES {
        assert_eq!(aliases[old], new, "{old}");
        assert!(ins.get(old).is_none(), "{old} still a key");
    }
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 297);
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    for (key, count) in KEYS {
        assert_eq!(ins[key]["_src"], SOURCE, "{key}");
        let groups = ins[key]["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), count, "{key}");
        for (name, g) in groups {
            assert_eq!(g["_src"], SOURCE, "{key} {name}");
            assert!(g["count"].is_null(), "{key} {name}: measured rows carry no harvest count");
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
            for m in name.split(',').filter(|m| !m.is_empty()) {
                want |= match m {
                    "BF" => 0, "AND" => 0, "OR" => 1 << 74, "XOR" => 2 << 74, "FTZ" => 1 << 80,
                    c => (FCMP.iter().position(|x| *x == c).unwrap() as u128) << 76,
                };
            }
            assert_eq!(base & !0xfffu128 & !(1u128 << 91), want, "{key} {name}");
            assert_eq!((base >> 91) & 1 == 1, key.contains("UR"), "{key} {name}: the uniform frame bit");
            assert_ne!(field_mask & (1u128 << 12), 0, "{key} {name}: the guard is a field");
            if key.starts_with("FCHK") {
                assert_eq!(field_mask >> 105, 0, "{key} {name}: no .reuse field on FCHK");
                assert_eq!(field_mask & (7u128 << 81), 7u128 << 81, "{key} {name}: Pd is a field");
            } else {
                assert_ne!(field_mask & (1u128 << 122), 0, "{key} {name}: Ra.reuse is a field");
                assert_eq!(field_mask & (0xffu128 << 16), 0xffu128 << 16, "{key} {name}: Rd is a field");
                assert_eq!(field_mask & (0xfu128 << 87), 0xfu128 << 87, "{key} {name}: Pc and its ! are fields");
            }
        }
    }
}

/// Production census witnesses (FSEL 1 490 words, FCHK 20), the canonical `+QNAN` lane kept next to the measured f32 key
/// (the baked word decodes to the glyph and the glyph text encodes the canonical payload, BUG-178 / BUG-249) and the
/// hexadecimal f32 literal through the `FCHK_P_R_II` alias.
#[test]
fn witness_words_round_trip() {
    for (word, vendor) in [
        (0x000fc40000000000f149f2ca0a099808u128, "@!P1 FSEL R9, R10, -1.00000001504746621988e+30, P0"),
        (0x000fc400000002000000000413097208u128, "FSEL R9, |R19|, R4, P0"),
        (0x000fc60000000000000000ff44687208u128, "FSEL R104, R68, RZ, P0"),
        (0x000e22000000000040c0000008007902u128, "FCHK P0, R8, 6"),
        (0x000e6200000000000000000f00007302u128, "FCHK P0, R0, R15"),
    ] {
        check(word, vendor);
    }
    let (table, index) = table_and_index();
    let qnan = 0x000fc800008000007fc00000ff007808u128;
    let decoded = index.decode(qnan, 0, table).unwrap();
    assert_eq!(cubit::printer::to_sass(&decoded), "FSEL R0, RZ, +QNAN , P1");
    let glyph = cubit::parser::parse_sass("FSEL R0, RZ, +QNAN , P1", 0).unwrap();
    assert_eq!(cubit::encoder::encode_instruction(&glyph, table).unwrap() & ((1u128 << 96) - 1), qnan & ((1u128 << 96) - 1),
               "the +QNAN glyph still encodes the canonical payload through the kept FSEL_R_R_II_P lane");
    let hex = cubit::parser::parse_sass("FCHK P0, R8, 0x40c00000", 0).unwrap();
    assert_eq!(cubit::encoder::encode_instruction(&hex, table).unwrap() & ((1u128 << 96) - 1), 0x0000_0000_0000_0000_40c0_0000_0800_7902,
               "the hexadecimal f32 literal encodes through the FCHK_P_R_II alias");
}
