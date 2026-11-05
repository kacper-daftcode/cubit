//! SM120 funnel shift `SHF` rebuilt from measurement (session T-5, 2026-11-05; dynamic-audit family
//! of `docs/KNOWN_ISSUES.md` T1): 40 dotted harvest keys (`SHF.L.U32_R_R_II_R`, `SHF.R.S32.HI_R_R_II_R_II_II_?`,
//! ...) with one sample's modifiers baked and truncated fields, and five generic keys that mixed the
//! opcodes of different forms, are replaced by 5 keys x 32 measured groups (`tools/probes/re_sm120_shf.py`,
//! nvdisasm 13.1 one word per call): forms 0x219 `Rd, Ra, Rb, Rc` / 0x419 `Rd, Ra, Rc, imm32` / 0x819
//! `Rd, Ra, imm32, Rc` / 0xc19 `Rd, Ra, URb, Rc` / 0xe19 `Rd, Ra, Rc, URb` (the UR forms carry frame bit
//! 91), modifiers bit 73 unsigned / 74 32-bit / 75 `.W` / 76 `.R` / 80 `.HI`. Bits 72, 77-79, 81-90 are
//! text-inert and stay outside the rows; the decoder's sign-window fallback no longer absorbs the family.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "shf-sm120-2026-11-05";
const CTRL: u128 = 0x000f_ca00u128 << 96;
const KEYS: [&str; 5] = ["SHF_R_R_R_R", "SHF_R_R_R_II", "SHF_R_R_II_R", "SHF_R_R_UR_R", "SHF_R_R_R_UR"];

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
    include_str!("fixtures/sm120_shf_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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
    assert_eq!(n, 380, "form words in the fixture");
    assert_eq!(groups.len(), 160, "5 forms x 32 modifier groups");
}

/// Census words (nvcc output) and the two words the audit flagged on the dotted keys.
#[test]
fn census_and_audit_words_round_trip() {
    for (word, vendor) in [
        (0x000fca000001160300000005ff027819u128, "SHF.R.U32.HI R2, RZ, 0x5, R3"),
        (0x000fe200000000ff0000001006047819u128, "SHF.L.S64 R4, R6, 0x10, RZ"),
    ] {
        check(word, vendor);
    }
}

#[test]
fn the_dotted_keys_are_gone_and_the_alias_points_at_the_plain_key() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let dotted: Vec<&String> = ins.keys().filter(|k| k.starts_with("SHF.")).collect();
    assert!(dotted.is_empty(), "{dotted:?}");
    assert_eq!(raw["_meta"]["key_aliases"]["SHF.L.U32_P0_R_R_II_R"], "SHF_R_R_II_R");
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    for key in KEYS {
        let groups = ins[key]["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), 32, "{key}");
        for (name, g) in groups {
            assert_eq!(g["_src"], SOURCE, "{key} {name}");
            let mut field_mask = 0u128;
            for f in g["fields"].as_array().unwrap() {
                let bits = ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
                assert_eq!(field_mask & bits, 0, "{name}: overlapping fields");
                field_mask |= bits;
            }
            assert_eq!(number(&g["variable_mask"]), field_mask, "{key} {name}");
            assert_eq!(number(&g["and_base"]) >> 105, 0, "{key} {name}");
            assert_eq!(number(&g["and_base"]) & field_mask, 0, "{key} {name}");
        }
    }
}

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
    assert_eq!(n, 78);
    assert_eq!(undecoded, 78, "every lattice word stays unclaimed (inert bits, wrong frame, unused opcodes)");
}
