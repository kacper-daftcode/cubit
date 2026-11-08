//! SM121a (GB10 / Spark) ISETP / UISETP -- the sm120 law of G's batch 2 (2026-11-06) measured on `-b SM121` (session
//! T-21, 2026-11-08, `tools/probes/re_sm120_isetp.py probe --arch SM121 --witnesses <the GB10 census corpus>`, nvdisasm
//! 13.1): every one of the 1 944 form words prints the SM120 text -- the 64-bit compare (`.S64` / `.U64`, bit 80)
//! included, unlike SM103 / SM100 (NEEDS 46) --, the 192 lattice words behave the same, and all 3 155 ISETP / UISETP
//! words of the GB10 census corpus (their own control codes) obey the law word for word. `apply` rewrote the ten plain
//! keys to the 96 measured groups each (the harvest had 24..128 groups per key: 777 rows rewritten, 183 groups added,
//! the 224 `INVALID3`-boolean harvest groups -- nvdisasm's own invalid glyph, a lattice plane -- retired) and retired the
//! 146 dotted one-group keys `[U]ISETP.<cmp>[.type].<bool>_<sig>` (census-bearing, mis-tokenised signatures included)
//! as `_meta.key_aliases` of the plain key of their form. The sm120 test `tests/sm120_isetp.rs` is the template.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "isetp-family-2026-11-06";
const CTRL: u128 = 0x000f_e200u128 << 96;
const KEYS: [&str; 10] = ["ISETP_P_P_R_R_P", "ISETP_P_P_R_R_P_P", "ISETP_P_P_R_UR_P", "ISETP_P_P_R_UR_P_P", "ISETP_P_P_R_II_P",
                          "ISETP_P_P_R_II_P_P", "UISETP_UP_UP_UR_UR_UP", "UISETP_UP_UP_UR_UR_UP_UP", "UISETP_UP_UP_UR_II_UP",
                          "UISETP_UP_UP_UR_II_UP_UP"];
const FORM_WORDS: usize = 1944;
const LATTICE_WORDS: usize = 192;
const WITNESS_WORDS: usize = 3155;
const RETIRED_DOTTED_KEYS: usize = 146;

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
    include_str!("fixtures/sm121a_isetp_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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
    assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{word:032x}");
    assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{word:032x} (display print)");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
    (decoded.key.clone(), decoded.mod_group.clone())
}

/// Every form word of the sweep decodes to one of the ten keys, prints NVIDIA's text (display and lossless) and
/// re-encodes bit for bit; the 960 groups all have a form word.
#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    let mut n = 0;
    let mut groups = std::collections::BTreeSet::new();
    for row in fixture() {
        if row.get("lattice").is_some() || row.get("witness").is_some() {
            continue;
        }
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        groups.insert(check(word, row["nvidia_sass"].as_str().unwrap()));
        n += 1;
    }
    assert_eq!(n, FORM_WORDS, "form words in the fixture");
    assert_eq!(groups.len(), 960, "every group of the ten keys has a form word");
}

/// The lattice (the `INVALID3` boolean, the frame bit flipped, the text-inert bits, the carry-in window without
/// `.EX`) is never rendered as another instruction's text.
#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    let (table, index) = table_and_index();
    let mut n = 0;
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        if let Ok(d) = index.decode(word, 0, table) {
            panic!("lattice word {word:032x} ({:?}) decodes as {}", row["nvidia_sass"], cubit::printer::to_sass_lossless(&d));
        }
        n += 1;
    }
    assert_eq!(n, LATTICE_WORDS);
}

/// The 3 155 ISETP / UISETP words of the GB10 census corpus (gx4, `/root/sparklab/results/q1/corpus`; their own control
/// codes): every one decodes to a plain key, prints the vendor's text and re-encodes bit for bit -- including the 579
/// 64-bit compares (`.S64` / `.U64`), which SM121 renders like SM120.
#[test]
fn the_gb10_census_words_of_the_family_round_trip() {
    let (mut n, mut wide) = (0, 0);
    for row in fixture() {
        if row.get("witness").is_none() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
        check(word, vendor);
        if vendor.contains(".S64.") || vendor.contains(".U64.") {
            wide += 1;
        }
        n += 1;
    }
    assert_eq!(n, WITNESS_WORDS);
    assert!(wide >= 500, "{wide} 64-bit compares among the census words (SM121 renders bit 80 like SM120)");
}

/// The ten keys carry exactly the 96 measured groups each (mask == the fields, nothing baked under a field, the
/// modifier bits of the group name and nothing else), the 224 `INVALID3` harvest groups are gone, the 146 dotted keys
/// are aliases whose tokens name a group of their target, and the legend counts the 960 rows.
#[test]
fn the_rows_are_measured_and_the_dotted_keys_are_aliases() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 960);
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let cmp = ["F", "LT", "EQ", "LE", "GT", "NE", "GE", "T"];
    for key in KEYS {
        assert_eq!(ins[key]["_src"], SOURCE, "{key}");
        let groups = ins[key]["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), 96, "{key}");
        for (name, g) in groups {
            assert_eq!(g["_src"], SOURCE, "{key} {name}");
            assert!(!name.contains("INVALID"), "{key} {name}: the INVALID3 plane is retired");
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
            let ex = name.split(',').any(|m| m == "EX");
            let mut want = if ex { 1u128 << 72 } else { 7u128 << 68 };
            let (mut signed, mut w64) = (true, false);
            for m in name.split(',') {
                match m {
                    "AND" | "EX" => {}
                    "OR" => want |= 1 << 74,
                    "XOR" => want |= 2 << 74,
                    "U32" => signed = false,
                    "S64" => w64 = true,
                    "U64" => { signed = false; w64 = true; }
                    c => want |= (cmp.iter().position(|x| *x == c).unwrap() as u128) << 76,
                }
            }
            want |= ((signed as u128) << 73) | ((w64 as u128) << 80);
            assert_eq!(base & !0xfffu128 & !(1u128 << 91), want, "{key} {name}");
        }
    }
    let mut dotted = 0;
    for (k, target) in raw["_meta"]["key_aliases"].as_object().unwrap() {
        if !(k.starts_with("ISETP.") || k.starts_with("UISETP.")) {
            continue;
        }
        let target = target.as_str().unwrap();
        assert!(KEYS.contains(&target), "{k} -> {target}");
        assert!(ins.get(k).is_none(), "{k} still a key");
        let mut toks: Vec<&str> = k.split('_').next().unwrap().split('.').skip(1).collect();
        toks.sort_unstable();
        assert!(ins[target]["mod_groups"].get(toks.join(",")).is_some(), "{k}: its spelling names no group of {target}");
        dotted += 1;
    }
    assert_eq!(dotted, RETIRED_DOTTED_KEYS, "the dotted one-group harvest keys of the family");
    assert!(ins.keys().all(|k| !(k.starts_with("ISETP.") || k.starts_with("UISETP."))), "no dotted ISETP key left");
}
