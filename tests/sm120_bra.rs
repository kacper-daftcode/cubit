//! The SM120 `BRA` family rebuilt from measurement (session T-9, 2026-11-06; `tools/probes/re_sm120_bra.py`,
//! nvdisasm 13.1 `-b SM120`, 519 form + 32 lattice words, every form text predicted by the layout):
//! opcode 0x947 (+ 0x547 for the uniform-predicate operand form), target = PC + 16 + a signed 56-bit dword
//! offset [23:16] + [81:34], guard [15:12], predicate operand [89:87] + `!` 90 (PT elided), mode [33:32]
//! plain / `.U` / `.DIV` / `.CONV`, 85 `.INC`, 86 `.DEC`, 84 `.ANY` and 83 `.NOT_TID0` with `.U`, the UR
//! operand [31:24] + `~` 82 behind the frame bit 91 (`.DIV` / `.CONV` only), `[!]UPn` [26:24] + 27 on 0x547.
//! Six keys `BRA[_P][_UR|_UP]_II` × one group per legal modifier set = 66 rows replace the 15 harvest keys /
//! 31 rows (`BRA_II_II_II_?` …, the triplicated `CONV` / `DIV` groups with junk fields, `BRA_UP_II [U]` that
//! claimed `BRA.INVALID1` words, `BRA_P_UR_II [CONV]` printing `PT, UR6` for `~UR6`).
//! Pins: every form word decodes to the vendor text and re-encodes bit for bit; the lattice (INVALIDn /
//! `???n` forms, text-inert bits) stays unclaimed; a negative target prints as nvdisasm prints it
//! (`BRA -0x14a0`, not the 32-bit wrap `BRA 0xffffeb60`); the retired dotted keys resolve as aliases.

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::Path, sync::OnceLock};

const SOURCE: &str = "bra-family-2026-11-06";
const CTRL: u128 = 0x000f_ea00u128 << 96;
const KEYS: [&str; 6] = ["BRA_II", "BRA_P_II", "BRA_UR_II", "BRA_P_UR_II", "BRA_UP_II", "BRA_P_UP_II"];
const FIXTURE: &str = include_str!("fixtures/sm120_bra_nvdisasm.jsonl");

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
    let mut groups = std::collections::BTreeSet::new();
    for row in fixture() {
        if row.get("lattice").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        let d = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
        assert!(KEYS.contains(&d.key.as_str()), "{word:032x}: {}", d.key);
        groups.insert((d.key.clone(), d.mod_group.clone()));
        assert_eq!(cubit::printer::to_sass_lossless(&d), vendor, "{word:032x}");
        assert_eq!(cubit::printer::to_sass(&d), vendor, "{word:032x} (display print)");
        assert_eq!(reencode(table, word, vendor), word, "{vendor}");
        n += 1;
    }
    assert_eq!(n, 519);
    assert_eq!(groups.len(), 66, "every measured row has a witness: {groups:?}");
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
    assert_eq!(n, 32);
    assert_eq!(undecoded, 32, "every lattice word stays unclaimed (INVALIDn / ???n forms, text-inert bits)");
}

/// The census word nvdisasm prints `BRA -0x14a0` at address 0 (a backward branch of the DeepGEMM kernels)
/// used to print as the 32-bit wrap `BRA 0xffffeb60`; in its kernel (address 0x14b0) it is `BRA 0x0`.
#[test]
fn a_negative_target_prints_as_nvdisasm_prints_it() {
    let (table, index) = loaded();
    let word = 0x000fea000383ffffffffffe800d47947u128;
    let d = index.decode(word, 0, table).unwrap();
    assert_eq!(d.key, "BRA_II");
    assert_eq!(cubit::printer::to_sass(&d), "BRA -0x14a0");
    assert_eq!(reencode(table, word, "BRA -0x14a0"), word);
    let in_kernel = index.decode(word, 0x14a0, table).unwrap();
    assert_eq!(cubit::printer::to_sass(&in_kernel), "BRA 0x0");
}

/// Operand glyphs the harvest rows got wrong: `~UR6` on the converge form, `!PT` as a predicate operand,
/// the uniform-predicate form with a leading vector predicate.
#[test]
fn the_operand_glyphs_follow_the_vendor() {
    let (table, _) = loaded();
    for (text, key) in [
        ("BRA.CONV ~UR6, 0x110", "BRA_UR_II"),
        ("BRA.DIV !P2, UR6, 0x110", "BRA_P_UR_II"),
        ("BRA !PT, 0x110", "BRA_P_II"),
        ("BRA.U.ANY !UP3, -0x40", "BRA_UP_II"),
        ("BRA.U P2, UP0, 0x110", "BRA_P_UP_II"),
        ("BRA.INC.U.ANY.NOT_TID0 0x110", "BRA_II"),
    ] {
        let parsed = cubit::parse_cuasm_line(&format!("{text} ;"), 0).unwrap();
        let word = cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{text}: {e}"));
        let d = DecodeIndex::build(table).decode(word, 0, table).unwrap();
        assert_eq!(d.key, key, "{text}");
        assert_eq!(cubit::printer::to_sass(&d), text);
    }
}

#[test]
fn the_rows_are_the_measured_ones_and_the_harvest_keys_are_gone() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(Path::new("tables/sm120.json")).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let bra_keys: Vec<&String> = ins.keys().filter(|k| k.split('_').next().unwrap().split('.').next().unwrap() == "BRA").collect();
    assert_eq!(bra_keys.len(), 6, "{bra_keys:?}");
    let mut total = 0;
    for key in KEYS {
        let groups = ins[key]["mod_groups"].as_object().unwrap();
        for (name, g) in groups {
            assert_eq!(g["_src"], SOURCE, "{key} [{name}]");
            let mut field_mask = 0u128;
            for f in g["fields"].as_array().unwrap() {
                let (shift, bits) = (f["shift"].as_u64().unwrap(), f["bits"].as_u64().unwrap());
                field_mask |= ((1u128 << bits) - 1) << shift;
            }
            assert_eq!(number(&g["variable_mask"]), field_mask, "{key} [{name}]");
            let ab = number(&g["and_base"]);
            assert_eq!(ab & field_mask, 0, "{key} [{name}]");
            assert_eq!(ab & 0xfff, if key.contains("_UP_") { 0x547 } else { 0x947 }, "{key} [{name}]");
            assert_eq!((ab >> 91) & 1, u128::from(key.contains("_UR_") || key.contains("_UP_")), "{key} [{name}]: frame bit");
            total += 1;
        }
    }
    assert_eq!(total, 66);
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 66);
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    assert_eq!(aliases["BRA.U_UP_II"], "BRA_UP_II");
    assert_eq!(aliases["BRA.DIV_UR_II"], "BRA_UR_II");
}
