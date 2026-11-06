//! `BRA` on SM103a / SM100a: the SM120 measurement applied 1:1 (session T-10, 2026-11-06;
//! `tools/probes/re_sm120_bra.py probe --arch SM103` / `SM100`, nvdisasm 13.1). The 551 probe words of
//! the SM120 fixture render the SAME text on `-b SM103` and `-b SM100` -- the uniform-predicate form
//! 0x547 included (T-9 had noted it as sm_120-only; nvdisasm 13.1 prints `BRA.U UP0, 0x110` on the
//! three targets, and the sm103a harvest row `BRA_UP_II [U]` had counted 17 806 such words).
//! `apply --arch sm103a` / `sm100a` replaced the 5 harvest keys / 9 rows (`BRA_II` with a guard-only
//! field list, `BRA_P_UR_II [CONV]` / `[DIV]` with `imm@18:6` + `imm@34:5` junk target fields,
//! `BRA_UP_II [ANY,U]` with a `pred@24:4` field over the UP operand) with the six measured keys / 66 rows
//! per table. Pins: every form word decodes to the vendor text through the measured keys on both tables
//! and re-encodes bit for bit; the lattice stays unclaimed; the row structure is the SM120 one.

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{collections::BTreeSet, path::Path};

const SOURCE: &str = "bra-family-2026-11-06";
const CTRL: u128 = 0x000f_ea00u128 << 96;
const KEYS: [&str; 6] = ["BRA_II", "BRA_P_II", "BRA_UR_II", "BRA_P_UR_II", "BRA_UP_II", "BRA_P_UP_II"];
const FIXTURES: [(&str, &str, &str); 2] = [
    ("sm103a", "SM103", include_str!("fixtures/sm103a_bra_nvdisasm.jsonl")),
    ("sm100a", "SM100", include_str!("fixtures/sm100a_bra_nvdisasm.jsonl")),
];
const SM120_FIXTURE: &str = include_str!("fixtures/sm120_bra_nvdisasm.jsonl");

fn rows(fixture: &str) -> Vec<Value> {
    fixture.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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

#[test]
fn the_three_targets_print_the_same_text_for_every_probe_word() {
    let sm120: std::collections::BTreeMap<String, Value> =
        rows(SM120_FIXTURE).into_iter().map(|r| (r["word"].as_str().unwrap().to_string(), r)).collect();
    for (arch, nv_arch, fixture) in FIXTURES {
        let mut n = 0;
        for row in rows(fixture) {
            assert_eq!(row["arch"], nv_arch, "{arch}: fixture rows carry nvdisasm's -b target");
            let twin = &sm120[row["word"].as_str().unwrap()];
            assert_eq!(row["nvidia_sass"], twin["nvidia_sass"], "{arch} {}", row["word"]);
            assert_eq!(row.get("lattice"), twin.get("lattice"));
            n += 1;
        }
        assert_eq!(n, sm120.len(), "{arch}: the whole SM120 sweep (519 form + 32 lattice words)");
    }
}

#[test]
fn every_probed_word_decodes_to_the_vendor_text_and_reassembles_on_both_tables() {
    for (arch, _nv_arch, fixture) in FIXTURES {
        let table = IsaTable::load(Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        let (mut n_form, mut n_lattice, mut unclaimed) = (0, 0, 0);
        let mut groups = BTreeSet::new();
        for row in rows(fixture) {
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
            if row.get("lattice").is_some() {
                n_lattice += 1;
                match index.decode(word, 0, &table) {
                    Err(_) => unclaimed += 1,
                    Ok(d) => assert_eq!(Some(cubit::printer::to_sass_lossless(&d).as_str()), row["nvidia_sass"].as_str(),
                        "{arch}: lattice word {word:032x} decodes as another text"),
                }
                continue;
            }
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let d = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{arch} {word:032x}: {e}"));
            assert!(KEYS.contains(&d.key.as_str()), "{arch} {word:032x}: {}", d.key);
            groups.insert((d.key.clone(), d.mod_group.clone()));
            assert_eq!(cubit::printer::to_sass_lossless(&d), vendor, "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass(&d), vendor, "{arch} {word:032x} (display print)");
            assert_eq!(reencode(&table, word, vendor), word, "{arch}: {vendor}");
            n_form += 1;
        }
        assert_eq!((n_form, n_lattice), (519, 32), "{arch}");
        assert_eq!(unclaimed, 32, "{arch}: every lattice word stays unclaimed");
        assert_eq!(groups.len(), 66, "{arch}: every measured row has a witness");
    }
}

/// The sm103a harvest row `BRA_UP_II [U]` (count 17 806) and the publish-corpus shapes keep decoding:
/// the uniform-predicate branch, the converge form with the inverted UR, a guarded predicate branch.
#[test]
fn the_corpus_shapes_assemble_and_print_as_before() {
    for (arch, _nv_arch, _fixture) in FIXTURES {
        let table = IsaTable::load(Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        for (text, key) in [
            ("BRA.U UP0, 0x80", "BRA_UP_II"),
            ("BRA.U.ANY !UP3, -0x40", "BRA_UP_II"),
            ("BRA.CONV ~UR6, 0x110", "BRA_UR_II"),
            ("BRA.DIV !P2, UR6, 0x110", "BRA_P_UR_II"),
            ("@!P1 BRA P0, 0x110", "BRA_P_II"),
            ("BRA 0x110", "BRA_II"),
        ] {
            let parsed = cubit::parse_cuasm_line(&format!("{text} ;"), 0).unwrap();
            let word = cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|e| panic!("{arch} {text}: {e}"));
            let d = index.decode(word, 0, &table).unwrap();
            assert_eq!(d.key, key, "{arch} {text}");
            assert_eq!(cubit::printer::to_sass(&d), text, "{arch}");
        }
    }
}

#[test]
fn the_rows_are_the_measured_ones_on_both_tables() {
    for (arch, nv_arch, _fixture) in FIXTURES {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        let bra_keys: Vec<&String> = ins.keys().filter(|k| k.split('_').next().unwrap().split('.').next().unwrap() == "BRA").collect();
        assert_eq!(bra_keys.len(), 6, "{arch}: {bra_keys:?}");
        let mut total = 0;
        for key in KEYS {
            for (name, g) in ins[key]["mod_groups"].as_object().unwrap() {
                assert_eq!(g["_src"], SOURCE, "{arch} {key} [{name}]");
                let mut field_mask = 0u128;
                for f in g["fields"].as_array().unwrap() {
                    field_mask |= ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
                }
                assert_eq!(number(&g["variable_mask"]), field_mask, "{arch} {key} [{name}]");
                let ab = number(&g["and_base"]);
                assert_eq!(ab & field_mask, 0, "{arch} {key} [{name}]");
                assert_eq!(ab & 0xfff, if key.contains("_UP_") { 0x547 } else { 0x947 }, "{arch} {key} [{name}]");
                total += 1;
            }
        }
        assert_eq!(total, 66, "{arch}");
        let src = &raw["_meta"]["provenance"]["sources"][SOURCE];
        assert_eq!(src["rows"], 66, "{arch}");
        assert_eq!(src["kind"], format!("nvdisasm 13.1 field probe (-b {nv_arch})"), "{arch}");
        assert_eq!(src["test"], "tests/sm103a_sm100a_bra.rs", "{arch}");
    }
}
