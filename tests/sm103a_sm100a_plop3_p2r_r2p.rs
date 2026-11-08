//! SM103a / SM100a PLOP3 / P2R / R2P -- the sm120 law of G's 2026-11-06 probe measured on `-b SM103` / `SM100` (session
//! T-21, 2026-11-08, `tools/probes/re_sm120_plop3_p2r_r2p.py probe --arch SM103` / `SM100`, nvdisasm 13.1): every one of
//! the 202 form and 158 lattice words obeys the law on both targets. `apply` rewrote the four keys to the 8 measured rows
//! (P2R had the `.B2` / `.B3` selectors missing) and created the encode-only `R2P_II_R` row. Found by the ISETP batch's
//! lattice test: the harvest `PLOP3_P_P_P_P_P_II_II` row of these tables carried a 4-bit "pred" field at bit 2 -- inside the
//! opcode nibble -- and claimed every word of opcodes 0x80c..0x83c that fit its remaining bits (the bit-80 ISETP immediate
//! words decoded as `PLOP3.LUT P0, P3, PT, !P0, PT, 0x10, 0x30200`); the measured row pins the whole opcode. The sm120
//! test `tests/sm120_plop3_p2r_r2p.rs` is the template.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "plop3-p2r-r2p-family-2026-11-06";
const CTRL: u128 = 0x000f_e200u128 << 96;
const KEYS: [&str; 4] = ["PLOP3_P_P_P_P_P_II_II", "PLOP3_P_P_P_P_UP_II_II", "P2R_R_II_R_II", "R2P_II_R_II"];
#[allow(dead_code)]
const ALIASES_SM120: [(&str, &str); 10] = [
    ("PLOP3.LUT_P_P_P_P_P_II_II", "PLOP3_P_P_P_P_P_II_II"), ("P2R.B1_R_R_R_II", "P2R_R_II_R_II"), ("P2R_R_L_R_II", "P2R_R_II_R_II"),
    ("P2R_R_R_R_II", "P2R_R_II_R_II"), ("P2R_R_R_R_II_II", "P2R_R_II_R_II"), ("P2R_R_R_R_II_II_?", "P2R_R_II_R_II"),
    ("P2R_R_R_R_II_II_II_?", "P2R_R_II_R_II"), ("P2R_R_R_R_II_II_II_II_?", "P2R_R_II_R_II"), ("R2P_?_R_II", "R2P_II_R_II"),
    ("R2P_L_R_II", "R2P_II_R_II"),
];

const TABLES: [(&str, &str, &str); 2] = [
    ("tables/sm103a.json", "SM103", include_str!("fixtures/sm103a_plop3_p2r_r2p_nvdisasm.jsonl")),
    ("tables/sm100a.json", "SM100", include_str!("fixtures/sm100a_plop3_p2r_r2p_nvdisasm.jsonl")),
];

fn table_path(i: usize) -> PathBuf {
    TABLES[i].0.into()
}

fn table_and_index(i: usize) -> &'static (IsaTable, DecodeIndex) {
    static TABLE: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    &TABLE.get_or_init(|| {
        TABLES.iter().map(|(path, _, _)| {
            let table = IsaTable::load(std::path::Path::new(path)).unwrap();
            let index = DecodeIndex::build(&table);
            (table, index)
        }).collect()
    })[i]
}

fn fixture(i: usize) -> Vec<Value> {
    TABLES[i].2.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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

fn check(i: usize, word: u128, vendor: &str) -> (String, String) {
    let (table, index) = table_and_index(i);
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{}: {word:032x}: {e}", TABLES[i].0));
    assert!(KEYS.contains(&decoded.key.as_str()), "{word:032x}: {}", decoded.key);
    let own = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(own, vendor, "{word:032x}");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
    (decoded.key.clone(), decoded.mod_group.clone())
}

/// Every form word -- the five predicates of both PLOP3 forms with `!`, the LUT and imm8 edges, the P2R / R2P
/// registers, byte selectors, 32-bit masks (incl. 0xff, 0x100, 0xffffffff) and `.reuse` -- decodes to the four keys,
/// prints NVIDIA's text (the R2P mask elided at 0xff, the masks unsigned) and re-encodes bit for bit.
#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    for i in 0..TABLES.len() {
        let mut n = 0;
        let mut groups = std::collections::BTreeSet::new();
        for row in fixture(i) {
            if row.get("lattice").is_some() {
                continue;
            }
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
            groups.insert(check(i, word, vendor));
            n += 1;
        }
        assert_eq!(n, 202, "form words in the fixture");
        assert_eq!(groups.len(), 7, "PLOP3 x 2 + P2R x 4 + R2P");
    }
}

/// The lattice: the frame bit (illegal) and the text-inert bits of each form -- never claimed.
#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    for i in 0..TABLES.len() {
        let (table, index) = table_and_index(i);
        let (mut n, mut undecoded) = (0, 0);
        for row in fixture(i) {
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
        assert_eq!(n, 158);
        assert_eq!(undecoded, 158);
    }
}

/// The four keys carry the measured rows, the encode-only `R2P_II_R` row bakes the elided 0xff mask, the ten junk
/// keys are aliases, the provenance legend names the tag.
#[test]
fn the_rows_are_measured_and_the_junk_keys_are_aliases() {
    for i in 0..TABLES.len() {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path(i)).unwrap()).unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        // the keys of the family outside the measured four: the register-sign form `PLOP3_P_P_R_R_R_II_II` (opcode 0x21f,
        // `PLOP3.LUT P0, P0, R0.SIGN, R0.SIGN, R0.SIGN, 0x0, 0x0` -- named by nvdisasm on SM103 / SM100, absent on SM120; a
        // harvest row for its own measurement) stays; these tables had none of sm120's junk keys, so there is nothing to alias
        let left: Vec<&String> = ins.keys().filter(|k| k.starts_with("PLOP3") || k.starts_with("P2R") || k.starts_with("R2P"))
            .filter(|k| !KEYS.contains(&k.as_str()) && k.as_str() != "R2P_II_R").collect();
        assert_eq!(left, vec!["PLOP3_P_P_R_R_R_II_II"], "{}", TABLES[i].0);
        let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
        assert!(aliases.keys().all(|k| !(k.starts_with("PLOP3") || k.starts_with("P2R") || k.starts_with("R2P"))), "{}", TABLES[i].0);
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 8);
        let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        for key in KEYS.iter().chain(["R2P_II_R"].iter()) {
            assert_eq!(ins[*key]["_src"], SOURCE, "{key}");
            let groups = ins[*key]["mod_groups"].as_object().unwrap();
            assert_eq!(groups.len(), if *key == "P2R_R_II_R_II" { 4 } else { 1 }, "{key}");
            for (name, g) in groups {
                assert_eq!(g["_src"], SOURCE, "{key} {name}");
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
                if key.starts_with("P2R") || *key == "R2P_II_R_II" {
                    assert_eq!(field_mask & (0xffff_ffffu128 << 32), 0xffff_ffffu128 << 32, "{key} {name}: a 32-bit mask field");
                }
            }
        }
        assert_eq!(ins["R2P_II_R"]["encode_only"], true);
        assert_eq!(number(&ins["R2P_II_R"]["mod_groups"][""]["and_base"]), 0x804 | (0xffu128 << 32));
        assert_eq!(number(&ins["PLOP3_P_P_P_P_UP_II_II"]["mod_groups"]["LUT"]["and_base"]), 0x81c | (1u128 << 67));
    }
}

/// The vendor's elided R2P spelling: the 0xff-mask word prints bare and re-encodes from the bare text through the
/// encode-only row; the explicit `, 0xff` spelling stays a bitwise alias; the census words and the 32-bit masks the
/// old 8-bit P2R field could not decode.
#[test]
fn witness_words_and_the_r2p_elision_round_trip() {
    for i in 0..TABLES.len() {
        let (table, index) = table_and_index(i);
        for (word, vendor) in [
            (0x000fe20000f0e170000000000080181cu128, "@P1 PLOP3.LUT P0, PT, P1, PT, PT, 0x8, 0x80"),
            (0x000fe20003f0f008000000000008781cu128, "PLOP3.LUT P0, PT, PT, PT, UP0, 0x80, 0x8"),
            (0x000fe2000000000000000040ff117803u128, "P2R R17, PR, RZ, 0x40"),
            (0x000fe20000000000ffffffffff117803u128, "P2R R17, PR, RZ, 0xffffffff"),
            (0x000fe200000000000000000600007804u128, "R2P PR, R0, 0x6"),
            (0x000fe20000000000000000ff00007804u128, "R2P PR, R0"),
            (0x000fe20000001000000000ff00007804u128, "R2P PR, R0.B1"),
            (0x000fe200000000008000000000007804u128, "R2P PR, R0, 0x80000000"),
        ] {
            check(i, word, vendor);
        }
        let explicit = cubit::parser::parse_sass("R2P PR, R0, 0xff", 0).unwrap();
        assert_eq!(cubit::encoder::encode_instruction(&explicit, table).unwrap() & ((1u128 << 96) - 1), 0x0000_00ff_0000_7804,
                   "the explicit 0xff spelling is a bitwise alias of the bare one");
        let d = index.decode(0x000fe20000000000000000ff00007804u128, 0, table).unwrap();
        assert_eq!(d.key, "R2P_II_R_II", "the bare word is owned by the decode-visible row");
    }
}
