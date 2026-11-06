//! SM120 `PLOP3` / `P2R` / `R2P` rebuilt from measurement (session G, 2026-11-06; KNOWN_ISSUES T1):
//! `tools/probes/re_sm120_plop3_p2r_r2p.py`, nvdisasm 13.1, 202 form + 158 lattice words, the same text on
//! `-b SM120` / `SM103` / `SM100`. PLOP3 (0x81c): guard, imm8 [23:16], LUT = [66:64] + [76:72], bit 67 = the third
//! source predicate is uniform (the `_UP_` key), Pc [70:68] + `!` 71, Pb [79:77] + `!` 80, Pd0 [83:81], Pd1 [86:84],
//! Pa [89:87] + `!` 90. P2R (0x803): Rd [23:16], Ra [31:24], imm32 [63:32] (the dsv41 row had 8 bits), the byte
//! selector [77:76] as the mnemonic suffix, `.reuse` 122. R2P (0x804): Ra [31:24] with the selector [77:76] as the
//! operand suffix (`R20.reuse.B2`), imm32 [63:32] -- elided by the vendor when it is 0xff (`R2P PR, R0`; the
//! encode-only `R2P_II_R` row carries the bare spelling), `.reuse` 122. The masks print unsigned. Ten junk keys
//! (the dotted PLOP3 twin, seven P2R and two R2P harvest keys) are `_meta.key_aliases` of the plain keys.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "plop3-p2r-r2p-family-2026-11-06";
const CTRL: u128 = 0x000f_e200u128 << 96;
const KEYS: [&str; 4] = ["PLOP3_P_P_P_P_P_II_II", "PLOP3_P_P_P_P_UP_II_II", "P2R_R_II_R_II", "R2P_II_R_II"];
const ALIASES: [(&str, &str); 10] = [
    ("PLOP3.LUT_P_P_P_P_P_II_II", "PLOP3_P_P_P_P_P_II_II"), ("P2R.B1_R_R_R_II", "P2R_R_II_R_II"), ("P2R_R_L_R_II", "P2R_R_II_R_II"),
    ("P2R_R_R_R_II", "P2R_R_II_R_II"), ("P2R_R_R_R_II_II", "P2R_R_II_R_II"), ("P2R_R_R_R_II_II_?", "P2R_R_II_R_II"),
    ("P2R_R_R_R_II_II_II_?", "P2R_R_II_R_II"), ("P2R_R_R_R_II_II_II_II_?", "P2R_R_II_R_II"), ("R2P_?_R_II", "R2P_II_R_II"),
    ("R2P_L_R_II", "R2P_II_R_II"),
];

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
    include_str!("fixtures/sm120_plop3_p2r_r2p_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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

/// Every form word -- the five predicates of both PLOP3 forms with `!`, the LUT and imm8 edges, the P2R / R2P
/// registers, byte selectors, 32-bit masks (incl. 0xff, 0x100, 0xffffffff) and `.reuse` -- decodes to the four keys,
/// prints NVIDIA's text (the R2P mask elided at 0xff, the masks unsigned) and re-encodes bit for bit.
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
    assert_eq!(n, 202, "form words in the fixture");
    assert_eq!(groups.len(), 7, "PLOP3 x 2 + P2R x 4 + R2P");
}

/// The lattice: the frame bit (illegal) and the text-inert bits of each form -- never claimed.
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
    assert_eq!(n, 158);
    assert_eq!(undecoded, 158);
}

/// The four keys carry the measured rows, the encode-only `R2P_II_R` row bakes the elided 0xff mask, the ten junk
/// keys are aliases, the provenance legend names the tag.
#[test]
fn the_rows_are_measured_and_the_junk_keys_are_aliases() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let left: Vec<&String> = ins.keys().filter(|k| k.starts_with("PLOP3") || k.starts_with("P2R") || k.starts_with("R2P"))
        .filter(|k| !KEYS.contains(&k.as_str()) && k.as_str() != "R2P_II_R").collect();
    assert!(left.is_empty(), "{left:?}");
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    for (old, new) in ALIASES {
        assert_eq!(aliases[old], new, "{old}");
    }
    assert_eq!(aliases["PLOP3.LUT_P1_P_P_P_P_P_II_II"], "PLOP3_P_P_P_P_P_II_II", "the era alias follows its retired target");
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

/// The vendor's elided R2P spelling: the 0xff-mask word prints bare and re-encodes from the bare text through the
/// encode-only row; the explicit `, 0xff` spelling stays a bitwise alias; the census words and the 32-bit masks the
/// old 8-bit P2R field could not decode.
#[test]
fn witness_words_and_the_r2p_elision_round_trip() {
    let (table, index) = table_and_index();
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
        check(word, vendor);
    }
    let explicit = cubit::parser::parse_sass("R2P PR, R0, 0xff", 0).unwrap();
    assert_eq!(cubit::encoder::encode_instruction(&explicit, table).unwrap() & ((1u128 << 96) - 1), 0x0000_00ff_0000_7804,
               "the explicit 0xff spelling is a bitwise alias of the bare one");
    let d = index.decode(0x000fe20000000000000000ff00007804u128, 0, table).unwrap();
    assert_eq!(d.key, "R2P_II_R_II", "the bare word is owned by the decode-visible row");
}
