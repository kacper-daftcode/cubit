//! SM120 uniform FP32 ALU (UFADD / UFMUL / UFFMA / UFSEL) rebuilt from measurement (session G, 2026-11-07; KNOWN_ISSUES
//! T1): the nine plain keys carry the rows `tools/probes/re_sm120_ufp32_alu.py` measures with nvdisasm 13.1 (1 025 form +
//! 30 glyph + 278 lattice + 4 neighbour words). The family is SM120-only: on `-b SM103` / `SM100` nvdisasm rejects every
//! word of the sweep. Law = the FP32 ALU law in the uniform datapath: guard [15:12] (`@UPn`); URd [23:16]; URa [31:24]
//! (`-` 72, `|` 73); the B operand [39:32] (`|` 62, `-` 63) or the f32 immediate [63:32]; the C slot [71:64] (`|` 74,
//! `-` 75; UFADD's URb lives there); UFADD `[.FTZ][.RM|.RP|.RZ][.SAT]`, UFMUL `[.FTZ|.FMZ][.D8…M8][.RND][.SAT]` (scale
//! [86:84], 4 unspelled, 0 = `INVALID0`, FTZ + FMZ = `INVALID3`), UFFMA `[.FTZ|.FMZ][.RND][.SAT]`, UFSEL `[.FTZ]` with
//! UPc [89:87] + `!` 90; bit 91 set; no `.reuse`. Bit 81 on the register forms of UFADD / UFFMA is UFHADD / UFHFMA --
//! a neighbour, never claimed. Retired: nine junk keys (`*_II*`, `_L`, `_?` twins) as `_meta.key_aliases`; the three
//! dsv41 rows the measurement reproduces field for field keep their tag.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "ufp32-alu-family-2026-11-07";
const KEPT: &str = "dsv41-sm120-2026-10-22";
const CTRL: u128 = 0x000f_e200u128 << 96;
const KEYS: [(&str, usize); 9] = [
    ("UFADD_UR_UR_UR", 16), ("UFADD_UR_UR_FI", 16), ("UFMUL_UR_UR_UR", 168), ("UFMUL_UR_UR_FI", 168),
    ("UFFMA_UR_UR_UR_UR", 24), ("UFFMA_UR_UR_UR_FI", 24), ("UFFMA_UR_UR_FI_UR", 24),
    ("UFSEL_UR_UR_UR_UP", 2), ("UFSEL_UR_UR_FI_UP", 2),
];
const ALIASES: [(&str, &str); 9] = [
    ("UFADD_UR_UR_II", "UFADD_UR_UR_FI"), ("UFMUL_UR_UR_II", "UFMUL_UR_UR_FI"),
    ("UFFMA_UR_UR_UR_II", "UFFMA_UR_UR_UR_FI"), ("UFFMA_UR_UR_UR_L", "UFFMA_UR_UR_UR_FI"),
    ("UFSEL_UR_UR_?_?", "UFSEL_UR_UR_FI_UP"), ("UFSEL_UR_UR_?_UP", "UFSEL_UR_UR_FI_UP"), ("UFSEL_UR_UR_II_?", "UFSEL_UR_UR_FI_UP"),
    ("UFSEL_UR_UR_II_UP", "UFSEL_UR_UR_FI_UP"), ("UFSEL_UR_UR_L_UP", "UFSEL_UR_UR_FI_UP"),
];

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
    include_str!("fixtures/sm120_ufp32_alu_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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

/// Every form word (the 444 groups on the canonical operands, the operand lattice of two groups per key -- guard,
/// URd / URa / URb / URc at 0, 1, 63 and 255 (`URZ`), every sign and `|abs|` combination, 14 f32 immediates incl. `+INF`, `-INF`, `-0.0` and the denormals, the eight UFSEL predicates with `!` --
/// and one word per key with every field away from its canonical value) decodes to the nine keys, prints NVIDIA's
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
    assert_eq!(n, 1025, "form words in the fixture");
    assert_eq!(groups.len(), 444, "16 x 2 UFADD + 168 x 2 UFMUL + 24 x 3 UFFMA + 2 x 2 UFSEL groups");
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
    assert_eq!(n, 30);
}

/// The lattice: the frame bit cleared (illegal), the text-inert bits, UFMUL's `INVALID0` scale and the `INVALID3`
/// denormal mode -- never claimed; the neighbours (UFHADD / UFHFMA at bit 81) never decode to a key of this family. The
/// encoder refuses the invalid states, `.reuse` on the uniform operands and the modifiers a mnemonic does not have.
#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    let (table, index) = table_and_index();
    let (mut n_lattice, mut n_neighbour, mut undecoded) = (0, 0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        let word = word_of(&row);
        match (row.get("neighbour").and_then(Value::as_str), index.decode(word, 0, table)) {
            (None, Err(_)) => {
                n_lattice += 1;
                undecoded += 1;
            }
            (None, Ok(d)) => panic!("lattice word {word:032x} ({:?}) decodes as {}", row["nvidia_sass"], cubit::printer::to_sass_lossless(&d)),
            (Some(_), Err(_)) => n_neighbour += 1,
            (Some(nb), Ok(d)) => {
                assert!(!is_family_key(&d.key), "neighbour word {word:032x} ({nb}) claimed by {}", d.key);
                n_neighbour += 1;
            }
        }
    }
    assert_eq!((n_lattice, undecoded, n_neighbour), (278, 278, 4));
    for text in ["UFMUL.INVALID0 UR4, UR2, UR3", "UFMUL.FTZ.FMZ UR4, UR2, UR3", "UFFMA.FMZ.FTZ UR4, UR2, UR3, UR5",
                 "UFMUL UR4, UR2.reuse, UR3", "UFSEL UR4, UR2, UR3.reuse, UPT", "UFADD.FMZ UR4, UR2, UR5", "UFSEL.SAT UR4, UR2, UR3, UPT"] {
        let refused = cubit::parser::parse_sass(text, 0).map_or(true, |p| cubit::encoder::encode_instruction(&p, table).is_err());
        assert!(refused, "{text} must be refused");
    }
}

/// The nine keys carry their full measured grid (`_src`, mask == the fields, nothing baked under a field, the
/// modifier bits of each group name and nothing else), the nine junk keys are aliases of the plain keys and nothing
/// else of the four mnemonics is left, the provenance legend names the tag.
#[test]
fn the_rows_are_measured_and_the_junk_keys_are_gone() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let left: Vec<&String> = ins.keys()
        .filter(|k| ["UFADD", "UFMUL", "UFFMA", "UFSEL"].iter().any(|p| k.starts_with(p)))
        .filter(|k| !is_family_key(k)).collect();
    assert!(left.is_empty(), "{left:?}");
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    for (old, new) in ALIASES {
        assert_eq!(aliases[old], new, "{old}");
        assert!(ins.get(old).is_none(), "{old} still a key");
    }
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 441);
    let mut kept = 0;
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    for (key, count) in KEYS {
        assert_eq!(ins[key]["_src"], SOURCE, "{key}");
        let groups = ins[key]["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), count, "{key}");
        let fmul = key.starts_with("UFMUL");
        for (name, g) in groups {
            if g["_src"] == KEPT {
                kept += 1;  // the dsv41 rows the measurement reproduces field for field keep their tag
            } else {
                assert_eq!(g["_src"], SOURCE, "{key} {name}");
                assert!(g["count"].is_null(), "{key} {name}: measured rows carry no harvest count");
            }
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
            let mut scaled = false;
            for m in name.split(',').filter(|m| !m.is_empty()) {
                want |= match m {
                    "FTZ" => 1 << 80, "FMZ" => 1 << 76, "SAT" => 1 << 77,
                    "RM" => 1 << 78, "RP" => 2 << 78, "RZ" => 3 << 78,
                    "NAN" => 1 << 81, "XORSIGN" => 1 << 82,
                    "D8" => { scaled = true; 1 << 84 }, "D4" => { scaled = true; 2 << 84 }, "D2" => { scaled = true; 3 << 84 },
                    "M2" => { scaled = true; 5 << 84 }, "M4" => { scaled = true; 6 << 84 }, "M8" => { scaled = true; 7 << 84 },
                    other => panic!("{key} {name}: unexpected modifier {other}"),
                };
            }
            if fmul && !scaled {
                want |= 4 << 84;
            }
            assert_eq!(base & !0xfffu128 & !(1u128 << 91), want, "{key} {name}");
            assert_eq!((base >> 91) & 1, 1, "{key} {name}: the uniform frame bit");
            assert_eq!(field_mask >> 105, 0, "{key} {name}: no .reuse field on the uniform forms");
            assert_ne!(field_mask & (1u128 << 12), 0, "{key} {name}: the guard is a field");
            assert_eq!(field_mask & (0xffu128 << 16), 0xffu128 << 16, "{key} {name}: URd is a field");
        }
    }
    assert_eq!(kept, 3, "UFADD_UR_UR_FI '' / FTZ and UFFMA_UR_UR_UR_FI '' reproduced the dsv41 rows");
}

/// Production census witnesses of the four keys with witnesses (incl. `-URZ` and the padded `-INF ,`) and the
/// hexadecimal f32 literal that encodes through the `UFMUL_UR_UR_II` alias.
#[test]
fn witness_words_round_trip() {
    for (word, vendor) in [
        (0x000fe20008010100bfe00000ff067454u128, "UFADD.FTZ UR6, -URZ, -1.75"),
        (0x000fc600080000053f80000006047455u128, "UFFMA UR4, UR6, UR5, 1"),
        (0x000fc600084100003fb8aa3b12117856u128, "UFMUL.FTZ UR17, UR18, 1.4426950216293334961"),
        (0x000fcc000c000100ff80000006067851u128, "UFSEL UR6, -UR6, -INF , !UP0"),
    ] {
        check(word, vendor);
    }
    let (table, _) = table_and_index();
    let hex = cubit::parser::parse_sass("UFMUL.FTZ UR17, UR18, 0x3fb8aa3b", 0).unwrap();
    assert_eq!(cubit::encoder::encode_instruction(&hex, table).unwrap() & ((1u128 << 96) - 1), 0x0000_0000_0841_0000_3fb8_aa3b_1211_7856,
               "the hexadecimal f32 literal encodes through the UFMUL_UR_UR_II alias");
}
