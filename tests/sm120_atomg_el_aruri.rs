//! The plain uniform-indexed `.EL` atomic `ATOMG.E.<ADD|OR>.EL.STRONG.GPU Pd, Rd, [Ra.U32+URb(+off)], Rb`
//! (opcode 0x9a8, frame bit 91, descriptor bit 76 clear) rebuilt from measurement on sm120 / sm103a /
//! sm100a (session T-6, 2026-11-05, `tools/probes/re_sm120_atomg_el_aruri.py`, nvdisasm 13.1 one word
//! per call; `-b SM120`, `-b SM103` and `-b SM100` print the same text for every probed word).
//!
//! Before: sm103a / sm100a keyed the form as `ATOMG.E.ADD.EL.STRONG.GPU_P_R_dARI_R` (rt98 era, 2026-08-21)
//! and printed the 64-bit descriptor glyph `desc[UR6][RZ.64]` for a word nvdisasm reads as `[RZ.U32+UR6]`
//! (`tests/b4fill2_rows.rs` pinned that text); the wave-11 tables carry the real `.EL` descriptor rows
//! (bits 76 + 63 set), so the mis-keyed text re-encoded to another word. The sm120 twins had the right
//! signature but a 24-bit offset field that swallowed the width bit 63, a 6-bit UR field and no Pd field.
//! Measured: Pd [83:81], Rd [23:16], Ra [31:24], Rb [39:32], URb [71:64] (8 bits, 255 = URZ), offset
//! [62:40] signed 23-bit; bit 63 (`.64` width) and bit 76 (descriptor form) stay outside the row.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::Path, sync::OnceLock};

const SOURCE: &str = "atomg-el-aruri-2026-11-05";
const CTRL: u128 = 0x000f_c400u128 << 96;
const KEYS: [&str; 2] = ["ATOMG.E.ADD.EL.STRONG.GPU_P_R_ARURI_R", "ATOMG.E.OR.EL.STRONG.GPU_P_R_ARURI_R"];
const TABLES: [(&str, &str); 3] = [
    ("tables/sm120.json", include_str!("fixtures/sm120_atomg_el_aruri_nvdisasm.jsonl")),
    ("tables/sm103a.json", include_str!("fixtures/sm103a_atomg_el_aruri_nvdisasm.jsonl")),
    ("tables/sm100a.json", include_str!("fixtures/sm100a_atomg_el_aruri_nvdisasm.jsonl")),
];

fn loaded() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static ALL: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    ALL.get_or_init(|| {
        TABLES
            .iter()
            .map(|(p, _)| {
                let table = IsaTable::load(Path::new(p)).unwrap();
                let index = DecodeIndex::build(&table);
                (table, index)
            })
            .collect()
    })
}

fn fixture(i: usize) -> Vec<Value> {
    TABLES[i].1.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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

fn check(i: usize, word: u128, vendor: &str) -> String {
    let (table, index) = &loaded()[i];
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{}: {word:032x}: {e}", TABLES[i].0));
    assert!(KEYS.contains(&decoded.key.as_str()), "{}: {word:032x}: {}", TABLES[i].0, decoded.key);
    let own = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(own, vendor, "{}: {word:032x}", TABLES[i].0);
    assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{}: {word:032x} (display print)", TABLES[i].0);
    assert_eq!(reencode(table, word, vendor), word, "{}: {vendor}", TABLES[i].0);
    decoded.key.clone()
}

#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits_on_the_three_tables() {
    for (i, (name, _)) in TABLES.iter().enumerate() {
        let mut n = 0;
        let mut keys = std::collections::BTreeSet::new();
        for row in fixture(i) {
            if row.get("lattice").is_some() {
                continue;
            }
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
            keys.insert(check(i, word, vendor));
            n += 1;
        }
        assert_eq!(n, 98, "{}: form words in the fixture", name);
        assert_eq!(keys.len(), 2, "{}: ADD and OR", name);
    }
}

/// The words the suite used to pin with the era text (`tests/b4fill2_rows.rs`, `bug078`, `bug080`,
/// `bug041`): same words, the vendor's text.
#[test]
fn the_era_words_print_the_vendor_text_and_round_trip() {
    for (word, vendor) in [
        (0x000f6400082ee10600000051ffda39a8u128, "@P3 ATOMG.E.ADD.EL.STRONG.GPU PT, R218, [RZ.U32+UR6], R81"),
        (0x000fc200082ee1260000004d52d639a8u128, "@P3 ATOMG.E.ADD.EL.STRONG.GPU PT, R214, [R82.U32+UR38], R77"),
        (0x000fc200082ee10400000028053a79a8u128, "ATOMG.E.ADD.EL.STRONG.GPU PT, R58, [R5.U32+UR4], R40"),
        (0x000fc2000b2ee10600010051ffda39a8u128, "@P3 ATOMG.E.OR.EL.STRONG.GPU PT, R218, [RZ.U32+UR6+0x100], R81"),
        (0x000fc200082ee10640000051ffda39a8u128, "@P3 ATOMG.E.ADD.EL.STRONG.GPU PT, R218, [RZ.U32+UR6+-0x400000], R81"),
    ] {
        for i in 0..TABLES.len() {
            check(i, word, vendor);
        }
    }
}

#[test]
fn the_rows_are_the_measured_ones_and_the_era_keys_are_gone() {
    for (path, _) in TABLES {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(Path::new(path)).unwrap()).unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        for era in ["ATOMG.E.ADD.EL.STRONG.GPU_P_R_dARI_R", "ATOMG.E.OR.EL.STRONG.GPU_P_R_dARI_R"] {
            assert!(!ins.contains_key(era), "{path}: {era} still present");
        }
        let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        for key in KEYS {
            let groups = ins[key]["mod_groups"].as_object().unwrap();
            assert_eq!(groups.len(), 1, "{path}: {key}");
            for (name, g) in groups {
                assert_eq!(g["_src"], SOURCE, "{path}: {key} {name}");
                let mut field_mask = 0u128;
                let mut widths = std::collections::BTreeMap::new();
                for f in g["fields"].as_array().unwrap() {
                    let (shift, bits) = (f["shift"].as_u64().unwrap(), f["bits"].as_u64().unwrap());
                    let mask = ((1u128 << bits) - 1) << shift;
                    assert_eq!(field_mask & mask, 0, "{path}: {name}: overlapping fields");
                    field_mask |= mask;
                    widths.insert(f["extraction"].as_str().unwrap().to_string() + &shift.to_string(), bits);
                }
                assert_eq!(widths["imm40"], 23, "{path}: the offset stops below the width bit 63");
                assert_eq!(widths["ureg64"], 8, "{path}: 8-bit UR field");
                assert_eq!(widths["pred81"], 3, "{path}: predicate destination field");
                assert_eq!(number(&g["variable_mask"]), field_mask, "{path}: {key} {name}");
                let and_base = number(&g["and_base"]);
                assert_eq!(and_base >> 105, 0, "{path}: {key} {name}");
                assert_eq!(and_base & field_mask, 0, "{path}: {key} {name}");
                assert_eq!((and_base >> 63) & 1, 0, "{path}: U32 width");
                assert_eq!((and_base >> 76) & 1, 0, "{path}: plain (non-descriptor) form");
            }
        }
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 2, "{path}: provenance entry");
    }
}

#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    for (i, (name, _)) in TABLES.iter().enumerate() {
        let (table, index) = &loaded()[i];
        let (mut n, mut undecoded) = (0, 0);
        for row in fixture(i) {
            if row.get("lattice").is_none() {
                continue;
            }
            n += 1;
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
            match index.decode(word, 0, table) {
                Err(_) => undecoded += 1,
                Ok(d) => {
                    let own = cubit::printer::to_sass_lossless(&d);
                    let vendor = row["nvidia_sass"].as_str();
                    assert_eq!(Some(own.as_str()), vendor, "{}: lattice word {word:032x}", name);
                    assert!(!KEYS.contains(&d.key.as_str()) || vendor.unwrap().contains(".U32+"),
                        "{}: lattice word {word:032x} claimed by {}", name, d.key);
                }
            }
        }
        assert_eq!(n, 25, "{}: lattice words in the fixture", name);
        assert!(undecoded >= 3, "{}: the illegal words (bit 76 alone, frame bit clear) fail closed", name);
    }
}
