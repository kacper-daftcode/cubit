//! The SM120 dense `IMMA` family rebuilt from measurement (session T-10 / T2, 2026-11-06;
//! `tools/probes/re_sm120_imma.py`, nvdisasm 13.1 `-b SM120`, 240 form + 16 lattice words, every form text
//! predicted by the layout): opcode 0x237, Rd [23:16], Ra [31:24] `.ROW`, Rb [39:32] `.COL`, Rc [71:64]; bit 86
//! the dense frame, 75 the shape (`16816` / `16832`), 76 A = `S8` (else `U8`), 78 B = `S8` (else `U8`), 82 `.SAT`;
//! bits 73 / 74 the only legal layouts (ROW / COL, baked); the optional fifth operand `[!]UPn` as the 4-bit
//! `pred_inv4` window [90:87]. The type pair is order-sensitive and a sorted mod-group name cannot tell `S8.U8`
//! from `U8.S8`, so the family uses typed keys: `IMMA.<shape>.<A>.<B>[.SAT]_R_R_R_R[_UP]` — 32 keys × 1 row replace
//! the 14 dense harvest keys (2-bit-shifted register fields that printed `R4, R6.ROW` for the vendor's `R16,
//! R24.ROW`, `neg` fields on the layout bits whose canonical words rendered `R8.???0`, phantom `_P_` and `_?` twins).
//! The decoder's sign-tolerant fallback is off for IMMA (bits 72–79 carry the family's law).

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::Path, sync::OnceLock};

const SOURCE: &str = "imma-family-2026-11-06";
const CTRL: u128 = 0x000f_e200u128 << 96;
const FIXTURE: &str = include_str!("fixtures/sm120_imma_nvdisasm.jsonl");

fn loaded() -> &'static (IsaTable, DecodeIndex) {
    static T: OnceLock<(IsaTable, DecodeIndex)> = OnceLock::new();
    T.get_or_init(|| {
        let table = IsaTable::load(Path::new("tables/sm120.json")).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    })
}

fn fixture() -> Vec<Value> {
    FIXTURE.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    let (table, index) = loaded();
    let mut n = 0;
    let mut keys = std::collections::BTreeSet::new();
    for row in fixture() {
        if row.get("lattice").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        let d = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
        assert!(d.key.starts_with("IMMA.168") && d.mod_group.is_empty(), "{word:032x}: {} [{}]", d.key, d.mod_group);
        keys.insert(d.key.clone());
        assert_eq!(cubit::printer::to_sass_lossless(&d), vendor, "{word:032x}");
        assert_eq!(cubit::printer::to_sass(&d), vendor, "{word:032x} (display print)");
        assert_eq!(reencode(table, word, vendor), word, "{vendor}");
        n += 1;
    }
    assert_eq!(n, 240);
    assert_eq!(keys.len(), 32, "every measured key has a witness: {keys:?}");
}

#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    let (table, index) = loaded();
    let (mut n, mut undecoded) = (0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        n += 1;
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        match index.decode(word, 0, table) {
            Err(_) => undecoded += 1,
            Ok(d) => assert_eq!(Some(cubit::printer::to_sass_lossless(&d).as_str()), row["nvidia_sass"].as_str(),
                "lattice word {word:032x} decodes as another text"),
        }
    }
    assert_eq!(n, 16);
    assert_eq!(undecoded, 16, "the `???` layouts, the INVALID type / shape codes, the sparse bit and the inert bits stay unclaimed");
}

/// The mixed-type pairs are distinct words (the D2 convention: typed keys, not a sorted mod group).
#[test]
fn the_type_pairs_are_order_sensitive_and_the_up_operand_is_inverted() {
    let (table, index) = loaded();
    let enc = |text: &str| cubit::encoder::encode_instruction(&cubit::parse_cuasm_line(&format!("{text} ;"), 0).unwrap(), table)
        .unwrap_or_else(|e| panic!("{text}: {e}"));
    let su = enc("IMMA.16816.S8.U8 R16, R24.ROW, R8.COL, R40");
    let us = enc("IMMA.16816.U8.S8 R16, R24.ROW, R8.COL, R40");
    assert_ne!(su, us);
    assert_eq!((su >> 76) & 1, 1, "A = S8 is bit 76");
    assert_eq!((su >> 78) & 1, 0, "B = U8 clears bit 78");
    assert_eq!((us >> 76) & 1, 0);
    assert_eq!((us >> 78) & 1, 1);
    for (text, key) in [
        ("IMMA.16832.S8.S8.SAT R16, R24.ROW, R8.COL, R40", "IMMA.16832.S8.S8.SAT_R_R_R_R"),
        ("IMMA.16816.U8.U8 R16, R24.ROW, R8.COL, RZ", "IMMA.16816.U8.U8_R_R_R_R"),
        ("IMMA.16816.S8.S8 R16, R24.ROW, R8.COL, R40, UP6", "IMMA.16816.S8.S8_R_R_R_R_UP"),
        ("IMMA.16816.S8.S8 R16, R24.ROW, R8.COL, R40, !UPT", "IMMA.16816.S8.S8_R_R_R_R_UP"),
    ] {
        let w = enc(text);
        let d = index.decode(w, 0, table).unwrap();
        assert_eq!(d.key, key, "{text}");
        assert_eq!(cubit::printer::to_sass(&d), text);
    }
    // UP6 = field value 1 (7 - 6); !UPT = bit 90 alone
    assert_eq!((enc("IMMA.16816.S8.S8 R16, R24.ROW, R8.COL, R40, UP6") >> 87) & 0xf, 1);
    assert_eq!((enc("IMMA.16816.S8.S8 R16, R24.ROW, R8.COL, R40, !UPT") >> 87) & 0xf, 8);
}

#[test]
fn the_rows_are_the_measured_ones_and_the_harvest_keys_are_gone() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(Path::new("tables/sm120.json")).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let dense: Vec<&String> = ins.keys().filter(|k| k.starts_with("IMMA.168")).collect();
    assert_eq!(dense.len(), 32, "{dense:?}");
    for key in &dense {
        let groups = ins[*key]["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), 1, "{key}");
        let g = &groups[""];
        assert_eq!(g["_src"], SOURCE, "{key}");
        let mut field_mask = 0u128;
        for f in g["fields"].as_array().unwrap() {
            field_mask |= ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
        }
        assert_eq!(number(&g["variable_mask"]), field_mask, "{key}");
        let ab = number(&g["and_base"]);
        assert_eq!(ab & field_mask, 0, "{key}");
        assert_eq!(ab & 0xfff, 0x237, "{key}");
        assert_eq!((ab >> 86) & 1, 1, "{key}: the dense frame bit");
        assert_eq!((ab >> 74) & 1, 1, "{key}: the B layout is COL");
        assert_eq!((ab >> 73) & 1, 0, "{key}: the A layout is ROW");
        assert_eq!((ab >> 75) & 1, u128::from(key.contains(".16832.")), "{key}: shape");
        assert_eq!((ab >> 82) & 1, u128::from(key.contains(".SAT")), "{key}: SAT");
        assert_eq!(field_mask & (0xf << 87) != 0, key.ends_with("_UP"), "{key}: the UP window is a field on the _UP keys only");
    }
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 32);
    for junk in ["IMMA.16816.S8.U8_P_R_R_R_R", "IMMA.16816.S8.S8.SAT_R_R_R_R_?", "IMMA.16816.S8.S8.SAT_R_R_R_R_II_?", "IMMA.16816.U8.U8.SAT_P_R_R_R_R"] {
        assert!(!ins.contains_key(junk), "{junk} retired");
        assert_eq!(raw["_meta"]["key_aliases"][junk], junk.replace("_P_R_R_R_R", "_R_R_R_R").replace("_R_R_R_R_II_?", "_R_R_R_R").replace("_R_R_R_R_?", "_R_R_R_R"));
    }
    // the sparse / scale-factor keys are another family and stay
    assert!(ins.contains_key("IMMA.SP.16832.S8.U8_R_R_R_R_R_II"));
    assert!(ins.contains_key("IMMA.SF.16832.U8.U8_R_R_R_R_R_R_UR"));
}
