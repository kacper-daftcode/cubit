//! The `IDP` family rebuilt from measurement on the four tables (session T-11, 2026-11-06; the review of
//! coldface's D2 rows for NEEDS 36; `tools/probes/re_sm120_idp.py`, nvdisasm 13.1 `-b SM120` = `SM103` =
//! `SM100` = `SM121` for every probe word: 128 form + 480 lattice words per table).
//!
//! Law: guard [15:12], Rd [23:16], Ra [31:24], Rb [39:32] (register form, opcode 0x7226) / URb [39:32]
//! (uniform form, opcode byte 0xc26 + bit 91), Rc [71:64]; the enum window [79:72]: [77:76] the mode
//! (00 `4A`, 01 `2A.LO`, 11 `2A.HI`, 10 illegal), 73 = the first type is signed (`S8` / `S16`), 74 = the
//! second type is signed (`S8`), 75 = `-Rc`; 72, 78, 79, [63:40] and [95:80] without 91 are text-inert.
//! Twelve legal forms per operand shape. The type pair is order-sensitive and a sorted mod-group name
//! cannot tell `S8.U8` from `U8.S8` (`U16.S8` would print as `S8.U16`), so the mixed-type forms carry
//! typed keys (D2, the owner's decision of 2026-11-06; coldface's `IDP.4A.{S8.U8,U8.S8}_R_R_R_R` rows,
//! blackwell-isa `42192f0`, are the first of them) and the symmetric forms stay mod-group rows of
//! `IDP_R_R_R_R` / `IDP_R_R_UR_R`; sm121a keeps typed keys for every register form.
//!
//! What the measurement closed: the uniform-register rows (the 2026-08 harvest donor and D2's three
//! typed copies of it) had no `-Rc` field and failed closed on the inert bit 72, so `IDP.4A.U8.U8 R15,
//! R15, UR6, -R7` was absorbed by the `S8.S8` row through the sign-tolerant fallback; the 2A half of the
//! family (the mixed `LO` types and every `HI` form, 6 register + 8 uniform forms) had no row, and a
//! `2A.LO.U16.U8` word with bit 72 set printed as `2A.LO.S16.S8`; the sm121a register rows lacked `-Rc`
//! and baked `Rc = RZ`. The decoder's sign-tolerant fallback is off for IDP (bits 73–75 are the law).

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{collections::BTreeSet, path::Path};

const SOURCE: &str = "idp-family-2026-11-06";
const D2_SOURCE: &str = "idp-mixed-d2-2026-11-06";
const LANE_SOURCE: &str = "idp-types-sm120-2026-11-04";
const CTRL: u128 = 0x000f_e200u128 << 96;
const TABLES: [(&str, &str, &str); 4] = [
    ("sm120", "SM120", include_str!("fixtures/sm120_idp_nvdisasm.jsonl")),
    ("sm103a", "SM103", include_str!("fixtures/sm103a_idp_nvdisasm.jsonl")),
    ("sm100a", "SM100", include_str!("fixtures/sm100a_idp_nvdisasm.jsonl")),
    ("sm121a", "SM121", include_str!("fixtures/sm121a_idp_nvdisasm.jsonl")),
];
const MODES: [(u128, &str); 3] = [(0, "4A"), (1, "2A.LO"), (3, "2A.HI")];

fn rows(fixture: &str) -> Vec<Value> {
    fixture.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn load(arch: &str) -> (IsaTable, DecodeIndex) {
    let table = IsaTable::load(Path::new(&format!("tables/{arch}.json"))).unwrap();
    let index = DecodeIndex::build(&table);
    (table, index)
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

/// The twelve legal (mode, type, type) texts of one operand shape.
fn forms() -> Vec<(u128, String)> {
    let mut out = Vec::new();
    for (mode, name) in MODES {
        for s1 in 0..2u128 {
            for s2 in 0..2u128 {
                let t1 = format!("{}{}", if s1 == 1 { "S" } else { "U" }, if mode == 0 { "8" } else { "16" });
                let t2 = format!("{}8", if s2 == 1 { "S" } else { "U" });
                out.push(((mode << 4) | (s1 << 1) | (s2 << 2), format!("IDP.{name}.{t1}.{t2}")));
            }
        }
    }
    out
}

#[test]
fn the_four_targets_print_the_same_text_for_every_probe_word() {
    let sm120: std::collections::BTreeMap<String, Value> =
        rows(TABLES[0].2).into_iter().map(|r| (r["word"].as_str().unwrap().to_string(), r)).collect();
    assert_eq!(sm120.len(), 608);
    for (arch, nv_arch, fixture) in &TABLES[1..] {
        let mut n = 0;
        for row in rows(fixture) {
            assert_eq!(row["arch"], *nv_arch, "{arch}: fixture rows carry nvdisasm's -b target");
            let twin = &sm120[row["word"].as_str().unwrap()];
            assert_eq!(row["nvidia_sass"], twin["nvidia_sass"], "{arch} {}", row["word"]);
            assert_eq!(row.get("lattice"), twin.get("lattice"));
            n += 1;
        }
        assert_eq!(n, sm120.len(), "{arch}: the whole SM120 sweep");
    }
}

#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits_on_every_table() {
    for (arch, _, fixture) in TABLES {
        let (table, index) = load(arch);
        let mut n = 0;
        let mut witnessed = BTreeSet::new();
        for row in rows(fixture) {
            if row.get("lattice").is_some() {
                continue;
            }
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
            let d = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{arch} {word:032x}: {e}"));
            assert!(d.key.starts_with("IDP"), "{arch} {word:032x}: {} [{}]", d.key, d.mod_group);
            witnessed.insert((d.key.clone(), d.mod_group.clone()));
            assert_eq!(cubit::printer::to_sass_lossless(&d), vendor, "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass(&d), vendor, "{arch} {word:032x} (display print)");
            assert_eq!(reencode(&table, word, vendor), word, "{arch} {vendor}");
            n += 1;
        }
        assert_eq!(n, 128, "{arch}");
        assert_eq!(witnessed.len(), 24, "{arch}: every row of the family has a witness: {witnessed:?}");
    }
}

#[test]
fn the_lattice_around_the_family_is_never_rendered_as_another_text() {
    for (arch, _, fixture) in TABLES {
        let (table, index) = load(arch);
        let (mut n, mut illegal, mut undecoded, mut same) = (0, 0, 0, 0);
        for row in rows(fixture) {
            if row.get("lattice").is_none() {
                continue;
            }
            n += 1;
            let vendor = row["nvidia_sass"].as_str();
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
            match (vendor, index.decode(word, 0, &table)) {
                (None, Ok(d)) => panic!("{arch} {word:032x}: nvdisasm rejects, cubit prints {}", cubit::printer::to_sass(&d)),
                (None, Err(_)) => illegal += 1,
                (Some(_), Err(_)) => undecoded += 1,
                (Some(v), Ok(d)) => {
                    assert_eq!(cubit::printer::to_sass_lossless(&d), v, "{arch}: lattice word {word:032x} decodes as another text");
                    same += 1;
                }
            }
        }
        assert_eq!(n, 480, "{arch}");
        // the 64 mode-10 enum values on both shapes + the two frame-bit flips
        assert_eq!(illegal, 130, "{arch}: every vendor-rejected word stays unclaimed");
        // the text-inert bits (72, 78, 79, [63:40], [95:80]): the measured rows fail closed on them;
        // the wave-11 lane's two 4A register rows (and D2's copies) tolerate 72 / 78 / 79 / 62 / 63
        assert_eq!(undecoded + same, 350, "{arch}");
        assert!(same == 0 || arch != "sm121a", "sm121a: every row is a measured, fail-closed one");
        println!("{arch}: lattice {n} = {illegal} illegal + {undecoded} fail-closed + {same} tolerated inert bits");
    }
}

/// The type pair is order-sensitive on both operand shapes (D2) and `-Rc` is a field of every row.
#[test]
fn the_type_pairs_are_order_sensitive_and_minus_rc_round_trips_on_both_shapes() {
    for (arch, _, _) in TABLES {
        let (table, index) = load(arch);
        let enc = |text: &str| cubit::encoder::encode_instruction(&cubit::parse_cuasm_line(&format!("{text} ;"), 0).unwrap(), &table)
            .unwrap_or_else(|e| panic!("{arch} {text}: {e}"));
        for (b, shape) in [("R6", "R"), ("UR6", "UR")] {
            let su = enc(&format!("IDP.4A.S8.U8 R15, R15, {b}, R7"));
            let us = enc(&format!("IDP.4A.U8.S8 R15, R15, {b}, R7"));
            assert_ne!(su, us, "{arch} {shape}");
            assert_eq!((su >> 73) & 1, 1, "{arch} {shape}: the first type S8 is bit 73");
            assert_eq!((su >> 74) & 1, 0);
            assert_eq!((us >> 73) & 1, 0);
            assert_eq!((us >> 74) & 1, 1, "{arch} {shape}: the second type S8 is bit 74");
            assert_eq!((su >> 91) & 1, u128::from(shape == "UR"), "{arch}: bit 91 is the uniform frame");
            assert_eq!(su & 0xfff, if shape == "UR" { 0xc26 } else { 0x226 });
            for (enum_, text) in forms() {
                for neg in ["", "-"] {
                    let text = format!("{text} R15, R15, {b}, {neg}R7");
                    let w = enc(&text);
                    assert_eq!((w >> 72) & 0xff, enum_ | if neg.is_empty() { 0 } else { 8 }, "{arch} {text}");
                    let d = index.decode(w, 0, &table).unwrap_or_else(|e| panic!("{arch} {text}: {e}"));
                    assert_eq!(cubit::printer::to_sass(&d), text, "{arch}");
                    let typed = d.key.starts_with("IDP.");
                    let mixed = !(text.contains(".S8.S8 ") || text.contains(".U8.U8 ") || text.contains(".S16.S8 ") || text.contains(".U16.U8 "));
                    assert_eq!(typed, mixed || (arch == "sm121a" && shape == "R"),
                        "{arch} {text}: typed keys for the mixed types (and every sm121a register form), mod groups otherwise -- got {} [{}]", d.key, d.mod_group);
                }
            }
        }
    }
}

#[test]
fn the_rows_are_the_measured_ones_and_the_harvest_keys_are_gone() {
    for (arch, _, _) in TABLES {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        let mut family: Vec<(String, String, &Value)> = Vec::new();
        for (key, entry) in ins.iter().filter(|(k, _)| k.starts_with("IDP")) {
            for (group, row) in entry["mod_groups"].as_object().unwrap() {
                family.push((key.clone(), group.clone(), row));
            }
        }
        assert_eq!(family.len(), 24, "{arch}: 12 forms x 2 operand shapes: {:?}", family.iter().map(|f| (&f.0, &f.1)).collect::<Vec<_>>());
        let (mut measured, mut d2, mut lane) = (0, 0, 0);
        for (key, group, row) in &family {
            let src = row["_src"].as_str().unwrap();
            let ur = key.ends_with("_R_R_UR_R");
            let ab = number(&row["and_base"]);
            let mut field_mask = 0u128;
            for f in row["fields"].as_array().unwrap() {
                field_mask |= ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
            }
            match src {
                SOURCE => {
                    measured += 1;
                    assert_eq!(number(&row["variable_mask"]), field_mask, "{arch} {key} [{group}]");
                    assert_eq!(ab & field_mask, 0, "{arch} {key} [{group}]");
                    assert_eq!(ab & 0xffff, if ur { 0xc26 } else { 0x226 }, "{arch} {key} [{group}]: the guard is a field");
                    assert_eq!(field_mask & (1 << 75), 1 << 75, "{arch} {key} [{group}]: -Rc is a field");
                    assert_eq!(field_mask & (0xff << 64), 0xff << 64, "{arch} {key} [{group}]: Rc is a field");
                }
                D2_SOURCE => {
                    d2 += 1;
                    assert!(arch != "sm121a" && !ur && key.starts_with("IDP.4A."), "{arch} {key}: coldface's two register-form rows");
                }
                LANE_SOURCE => {
                    lane += 1;
                    assert!(arch != "sm121a" && !ur && key == "IDP_R_R_R_R" && group.starts_with("4A,"), "{arch} {key} [{group}]");
                }
                other => panic!("{arch} {key} [{group}]: unexpected _src {other}"),
            }
            assert_eq!((ab >> 91) & 1, u128::from(ur), "{arch} {key} [{group}]: bit 91 is the uniform frame");
            // the key / group name states the mode and the two types; the and_base carries them
            let name = if key.starts_with("IDP.") { key.split('_').next().unwrap().to_string() }
                       else { format!("IDP.{}", group.replace(',', ".")) };
            let (mode, s1, s2) = forms().into_iter().find(|(e, t)| {
                let mut toks: Vec<&str> = t.split('.').skip(1).collect();
                let mut want: Vec<&str> = name.split('.').skip(1).collect();
                if !key.starts_with("IDP.") { toks.sort(); want.sort(); }
                let _ = e;
                toks == want
            }).map(|(e, _)| ((e >> 4) & 3, (e >> 1) & 1, (e >> 2) & 1)).unwrap_or_else(|| panic!("{arch} {key} [{group}]: {name}"));
            assert_eq!((ab >> 76) & 3, mode, "{arch} {key} [{group}]");
            assert_eq!((ab >> 73) & 1, s1, "{arch} {key} [{group}]");
            assert_eq!((ab >> 74) & 1, s2, "{arch} {key} [{group}]");
        }
        if arch == "sm121a" {
            assert_eq!((measured, d2, lane), (24, 0, 0), "{arch}");
            for junk in ["IDP.4A.S8.S8_R_R_R_R_?", "IDP.4A.S8.S8_R_R_R_R_II_?"] {
                assert!(!ins.contains_key(junk), "{junk} retired");
                assert_eq!(raw["_meta"]["key_aliases"][junk], "IDP.4A.S8.S8_R_R_R_R");
            }
        } else {
            assert_eq!((measured, d2, lane), (20, 2, 2), "{arch}");
        }
        assert!(!ins.contains_key("IDP.4A.U8.U8_R_R_UR_R"), "{arch}: the symmetric uniform form is a mod-group row like its register sibling");
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], measured, "{arch}");
        assert_eq!(raw["_meta"]["provenance"]["sources"][D2_SOURCE]["rows"].as_u64().unwrap_or(0), d2, "{arch}");
    }
}
