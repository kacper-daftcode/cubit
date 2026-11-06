//! The uniform-indexed shared-memory atomic `ATOMS.<op>[.S32|.64|.128] Rd, [Ra+URb(+imm)], Rb` (opcode
//! 0x98c + frame bit 91) rebuilt over its whole operation × type lattice (session T-8, 2026-11-06;
//! `tools/probes/re_sm120_atoms_aruri_ops.py`, nvdisasm 13.1 `-b SM120`, 720 form + 27 lattice words).
//! The 2026-10-29 probe had measured one group (`MAX,S32`); the other groups of `ATOMS_R_ARURI_R` and the
//! 0x98c groups of `ATOMS_R_ARI_R_R` were harvest rows that read the UR byte [71:64] as a fourth register
//! (`ATOMS.AND R4, [R7+UR4], R8` printed `ATOMS.AND R4, [R7], R8, R4`, the vendor text did not re-encode).
//! Pins: every form word decodes to the vendor text and re-encodes bit for bit (through `ATOMS_R_ARURI_R`; an
//! RZ base may route through the harvest RZ-base key `ATOMS_R_AURI_R` with the same text and bits);
//! the lattice (INVALIDn operations and types, text-inert bits, the wrong frame) stays unclaimed; the 36
//! rows are the measured ones; the four 0x98c junk groups are gone.

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::Path, sync::OnceLock};

const SOURCE: &str = "atoms-aruri-ops-sm120-2026-11-06";
const CTRL: u128 = 0x0001_e200u128 << 96;
const KEY: &str = "ATOMS_R_ARURI_R";
const FIXTURE: &str = include_str!("fixtures/sm120_atoms_aruri_ops_nvdisasm.jsonl");

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
        // an RZ base (`[UR4]`) may route through the harvest RZ-base key `ATOMS_R_AURI_R` (the decoder's
        // shorter-key tiebreak; same text, same bits) -- every other word is the measured key's
        if (word >> 24) & 0xff == 255 {
            assert!(d.key == KEY || d.key == "ATOMS_R_AURI_R", "{word:032x}: {}", d.key);
        } else {
            assert_eq!(d.key, KEY, "{word:032x}");
            groups.insert(d.mod_group.clone());
        }
        assert_eq!(cubit::printer::to_sass_lossless(&d), vendor, "{word:032x}");
        assert_eq!(cubit::printer::to_sass(&d), vendor, "{word:032x} (display print)");
        assert_eq!(reencode(table, word, vendor), word, "{vendor}");
        n += 1;
    }
    assert_eq!(n, 720);
    assert_eq!(groups.len(), 36, "{groups:?}");
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
    assert_eq!(n, 27);
    assert_eq!(undecoded, 27, "every lattice word stays unclaimed (INVALIDn, inert bits, wrong frame)");
}

/// The audit words of the junk rows (`T/audit/dyn13`): the vendor text now, through the measured key.
#[test]
fn the_audit_words_print_the_vendor_text() {
    let (table, index) = loaded();
    for (word, vendor) in [
        (0x000fe2000a800004000000080704798cu128, "ATOMS.AND R4, [R7+UR4], R8"),
        (0x000fe2000c000004000000080704798cu128, "ATOMS.EXCH R4, [R7+UR4], R8"),
        (0x000fe2000b00000a000000080704798cu128, "ATOMS.OR R4, [R7+UR10], R8"),
        (0x000fe2000b80000a000000080704798cu128, "ATOMS.XOR R4, [R7+UR10], R8"),
    ] {
        let d = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
        assert_eq!(d.key, KEY);
        assert_eq!(cubit::printer::to_sass_lossless(&d), vendor);
        assert_eq!(reencode(table, word, vendor), word, "{vendor}");
    }
}

#[test]
fn the_rows_are_the_measured_ones_and_the_junk_groups_are_gone() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(Path::new("tables/sm120.json")).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let groups = ins[KEY]["mod_groups"].as_object().unwrap();
    assert_eq!(groups.len(), 36);
    for (name, g) in groups {
        assert_eq!(g["_src"], SOURCE, "{name}");
        let mut field_mask = 0u128;
        for f in g["fields"].as_array().unwrap() {
            let (shift, bits) = (f["shift"].as_u64().unwrap(), f["bits"].as_u64().unwrap());
            field_mask |= ((1u128 << bits) - 1) << shift;
        }
        assert_eq!(number(&g["variable_mask"]), field_mask, "{name}");
        let ab = number(&g["and_base"]);
        assert_eq!(ab & field_mask, 0, "{name}");
        assert_eq!(ab & 0xfff, 0x98c, "{name}");
        assert_eq!((ab >> 91) & 1, 1, "{name}: frame bit");
    }
    let sibling = ins["ATOMS_R_ARI_R_R"]["mod_groups"].as_object().unwrap();
    for (name, g) in sibling {
        assert_ne!(number(&g["and_base"]) & 0xfff, 0x98c, "ATOMS_R_ARI_R_R [{name}] still carries the uniform-indexed opcode");
    }
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 36);
}
