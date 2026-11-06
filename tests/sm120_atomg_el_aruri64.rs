//! The 64-bit-base twin of the plain uniform-indexed `.EL` atomic (session T-7, 2026-11-06):
//! `ATOMG.E.<op>.EL.STRONG.GPU Pd, Rd, [Ra.64+URb(+off)], Rb` — opcode 0x9a8, frame bit 91, width bit 63
//! SET, descriptor bit 76 clear — rows `ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R` on sm120 / sm103a /
//! sm100a (`tools/probes/re_sm120_atomg_el_aruri64.py`, nvdisasm 13.1, text-identical on the three
//! targets). The 2026-11-05 rebuild of the U32 rows excludes bit 63 by `claim_forbid` (before, the harvest
//! offset field swallowed it and the words printed a bogus `+-0x800000`), so the four `[R8.64+UR7(+-0x1)]`
//! ADD / OR words of the dynamic audit (`T/audit/dyn10`) failed closed. Pins: every measured word decodes to
//! NVIDIA's text through the new keys and re-encodes bit for bit on the three tables; the `.64` glyph comes
//! from the frame (not bits 90/91), base 255 prints the REDG-style `???255` glyph (BUG-461, text-faithful
//! decode only); the U32 twin and the descriptor form stay on their own rows.

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::Path, sync::OnceLock};

const SOURCE: &str = "atomg-el-aruri64-2026-11-06";
const CTRL: u128 = 0x000f_c400u128 << 96;
const KEYS: [&str; 2] = ["ATOMG.E.ADD.EL.STRONG.GPU_P_R_ARURI64_R", "ATOMG.E.OR.EL.STRONG.GPU_P_R_ARURI64_R"];
const TABLES: [(&str, &str); 3] = [
    ("tables/sm120.json", include_str!("fixtures/sm120_atomg_el_aruri64_nvdisasm.jsonl")),
    ("tables/sm103a.json", include_str!("fixtures/sm103a_atomg_el_aruri64_nvdisasm.jsonl")),
    ("tables/sm100a.json", include_str!("fixtures/sm100a_atomg_el_aruri64_nvdisasm.jsonl")),
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
    if !vendor.contains("???255") {
        assert_eq!(reencode(table, word, vendor), word, "{}: {vendor}", TABLES[i].0);
    }
    decoded.key.clone()
}

#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits_on_the_three_tables() {
    for i in 0..TABLES.len() {
        let mut n = 0;
        let mut glyph255 = 0;
        let mut keys = std::collections::BTreeSet::new();
        for row in fixture(i) {
            if row.get("lattice").is_some() {
                continue;
            }
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
            keys.insert(check(i, word, vendor));
            glyph255 += usize::from(vendor.contains("???255"));
            n += 1;
        }
        assert_eq!(n, 74, "{}: form words in the fixture", TABLES[i].0);
        assert_eq!(glyph255, 2, "{}: the two base-255 words print the degenerate glyph", TABLES[i].0);
        assert_eq!(keys.len(), 2, "{}: ADD and OR", TABLES[i].0);
    }
}

/// The four audit words that failed closed before (`T/audit/dyn10`, class `decode_miss`).
#[test]
fn the_audit_words_decode_and_round_trip() {
    for (word, vendor) in [
        (0x000fe200082ee1078000000a080679a8u128, "ATOMG.E.ADD.EL.STRONG.GPU PT, R6, [R8.64+UR7], R10"),
        (0x000fe200082ee107ffffff0a080679a8u128, "ATOMG.E.ADD.EL.STRONG.GPU PT, R6, [R8.64+UR7+-0x1], R10"),
        (0x000fe2000b2ee1078000000a080679a8u128, "ATOMG.E.OR.EL.STRONG.GPU PT, R6, [R8.64+UR7], R10"),
        (0x000fe2000b2ee107ffffff0a080679a8u128, "ATOMG.E.OR.EL.STRONG.GPU PT, R6, [R8.64+UR7+-0x1], R10"),
    ] {
        for i in 0..TABLES.len() {
            check(i, word, vendor);
        }
    }
}

/// The neighbours keep their own rows: the U32 twin (bit 63 clear) prints `[R8.U32+UR6]` through the
/// `_P_R_ARURI_R` row, the descriptor form (bits 63 + 76) prints `desc[UR6][R8.64]` through the wave-11
/// `ATOMG_P_R_dARI_R` row, and the new row never claims either.
#[test]
fn the_neighbours_stay_on_their_rows() {
    let base = 0x00000000082ee1068000005108da79a8u128 | CTRL; // ADD, Ra = R8, URb = UR6, Rd = R218, Rb = R81
    for i in 0..TABLES.len() {
        let (table, index) = &loaded()[i];
        let u32_word = base & !(1u128 << 63);
        let d = index.decode(u32_word, 0, table).unwrap();
        assert_eq!(d.key, "ATOMG.E.ADD.EL.STRONG.GPU_P_R_ARURI_R", "{}", TABLES[i].0);
        assert_eq!(cubit::printer::to_sass(&d), "ATOMG.E.ADD.EL.STRONG.GPU PT, R218, [R8.U32+UR6], R81");
        let desc_word = base | (1u128 << 76);
        let d = index.decode(desc_word, 0, table).unwrap();
        assert!(!KEYS.contains(&d.key.as_str()), "{}: {}", TABLES[i].0, d.key);
        assert_eq!(cubit::printer::to_sass(&d), "ATOMG.E.ADD.EL.STRONG.GPU PT, R218, desc[UR6][R8.64], R81");
    }
}

#[test]
fn the_rows_are_the_measured_ones() {
    for (path, _) in TABLES {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(Path::new(path)).unwrap()).unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        for key in KEYS {
            let groups = ins[key]["mod_groups"].as_object().unwrap();
            assert_eq!(groups.len(), 1, "{path}: {key}");
            for (name, g) in groups {
                assert_eq!(g["_src"], SOURCE, "{path}: {key} {name}");
                let mut field_mask = 0u128;
                for f in g["fields"].as_array().unwrap() {
                    let (shift, bits) = (f["shift"].as_u64().unwrap(), f["bits"].as_u64().unwrap());
                    let mask = ((1u128 << bits) - 1) << shift;
                    assert_eq!(field_mask & mask, 0, "{path}: {name}: overlapping fields");
                    field_mask |= mask;
                }
                assert_eq!(number(&g["variable_mask"]), field_mask, "{path}: {key} {name}");
                let and_base = number(&g["and_base"]);
                assert_eq!((and_base >> 63) & 1, 1, "{path}: the 64-bit base width is part of the frame");
                assert_eq!((and_base >> 76) & 1, 0, "{path}: plain (non-descriptor) form");
                assert_eq!((and_base >> 91) & 1, 1, "{path}: frame bit");
                let forbid = g["claim_forbid"].as_array().unwrap();
                assert!(forbid.iter().any(|c| c["shift"] == 76), "{path}: bit 76 excluded (the descriptor rows)");
            }
        }
        let prov = &raw["_meta"]["provenance"]["sources"][SOURCE];
        assert_eq!(prov["rows"], 2, "{path}: provenance entry");
    }
}
