//! NEEDS 59 (session T-22, 2026-11-08): the two harvest rows that batch 7's lattice tests exposed.
//!
//! (a) sm103a / sm100a `VIMNMX3_R_R_R_R_P` ("" and `RELU`) and `VIMNMX3_R_R_UR_R_P`: the harvest declared the fifth
//! operand's predicate as a 4-bit `pred` field at shift 1 -- inside the opcode nibble -- so the register form's match
//! ignored opcode bits 1..4 and claimed FMNMX words (`FMNMX R4, R2, R3, PT` decoded as `VIMNMX3 R4, R2, R3, R1, P4`; the
//! PLOP3 class of T-21's batch 6). The rows are a real form nvdisasm names, so they were measured, not deleted:
//! `tools/probes/re_sm120_rows.py probe --family intalu --arch SM103` / `SM100` (nvdisasm 13.1, the whole 128-bit
//! circumference of every row; fixtures `tests/fixtures/sm103a_rows_intalu_nvdisasm.jsonl` / `sm100a_…`) -- the predicate
//! sits at [89:87] with its sign at 90 (like IADD3's), bits 72 / 73 / 76 are the `.U32` / `.S16x2` / `.RELU` modifiers
//! (other groups' words), the rest of the word is text-inert or illegal, 0 witnesses in the B300 publish corpus.
//!
//! (b) sm121a `MUFU_R_L` (a label-typed harvest key whose mask tolerated the half-type bits 72 / 73) decoded the lattice
//! word `MUFU.INVALID6.F16 R4, R2` as `MUFU.RCP64H R4, R2`; every one of its eight canonical words is the plain
//! `MUFU.<fn> R0, R0` the measured `MUFU_R_R` rows decode (a whole-key twin) -- retired as a `_meta.key_aliases` entry.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-intalu-2026-11-07";
const CTRL: u128 = 0x000f_e200u128 << 96;
const TABLES: [(&str, &str); 2] = [
    ("tables/sm103a.json", include_str!("fixtures/sm103a_rows_intalu_nvdisasm.jsonl")),
    ("tables/sm100a.json", include_str!("fixtures/sm100a_rows_intalu_nvdisasm.jsonl")),
];
/// The three rows per table, (key, group, canonical text).
const ROWS: [(&str, &str, &str); 3] = [
    ("VIMNMX3_R_R_R_R_P", "", "VIMNMX3 R32, R48, R80, R24, PT"),
    ("VIMNMX3_R_R_R_R_P", "RELU", "VIMNMX3.RELU R32, R48, R80, R24, PT"),
    ("VIMNMX3_R_R_UR_R_P", "", "VIMNMX3 R32, R48, UR80, R96, PT"),
];
/// The FMNMX lattice word of `tests/sm103a_sm100a_fp32_alu.rs` (a text-inert bit on `FMNMX R4, R2, R3, PT`) that the
/// harvest VIMNMX3 row claimed.
const FMNMX_LATTICE_WORD: u128 = 0x000f_e200_0380_0001_0000_0003_0204_7209;
/// The MUFU lattice word of `tests/sm121a_conv.rs` (`MUFU.INVALID6.F16 R4, R2` for nvdisasm) that `MUFU_R_L` claimed.
const MUFU_LATTICE_WORD: u128 = 0x000f_e200_0000_1900_0000_0002_0004_7308;

fn table_and_index(path: &'static str) -> &'static (IsaTable, DecodeIndex) {
    static TABLES_LOADED: OnceLock<Vec<(&'static str, (IsaTable, DecodeIndex))>> = OnceLock::new();
    let all = TABLES_LOADED.get_or_init(|| {
        let mut paths: Vec<&'static str> = TABLES.iter().map(|(p, _)| *p).collect();
        paths.push("tables/sm121a.json");
        paths
            .into_iter()
            .map(|p| {
                let table = IsaTable::load(std::path::Path::new(p)).unwrap();
                let index = DecodeIndex::build(&table);
                (p, (table, index))
            })
            .collect()
    });
    &all.iter().find(|(p, _)| *p == path).unwrap().1
}

fn records(i: usize) -> Vec<Value> {
    TABLES[i].1.lines().skip(1).filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn hex(v: &Value) -> u128 {
    u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn bits_of<'a>(rec: &'a Value, class: &str) -> &'a [Value] {
    rec.get(class).and_then(|v| v.as_array()).map(|v| v.as_slice()).unwrap_or(&[])
}

fn reencode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let source = format!("[{control}] {text} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    assert!(parsed.hand_sched && parsed.rsd.is_none(), "{source}");
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

fn decode_text(path: &'static str, word: u128) -> Option<(String, String, String)> {
    let (table, index) = table_and_index(path);
    index.decode(word, 0, table).ok().map(|d| (d.key.clone(), d.mod_group.clone(), cubit::printer::to_sass_lossless(&d)))
}

/// Every measured row's canonical word decodes to the row itself with the vendor's text and re-encodes bit for bit;
/// every declared field bit (the guard, the four registers / the UR, the predicate and its sign, the `.reuse` slots)
/// moves exactly its own token and the word still round-trips.
#[test]
fn the_canonical_words_and_every_field_bit_round_trip() {
    for (i, (path, _)) in TABLES.iter().enumerate() {
        let (table, _) = table_and_index(path);
        let recs = records(i);
        assert_eq!(recs.len(), ROWS.len(), "{path}: rows in the fixture");
        for rec in &recs {
            assert_eq!(rec["status"], "measured", "{path}: {} {}", rec["key"], rec["group"]);
            let key = rec["key"].as_str().unwrap();
            let group = rec["group"].as_str().unwrap();
            let t0 = rec["t0"].as_str().unwrap();
            assert!(ROWS.iter().any(|(k, g, t)| *k == key && *g == group && *t == t0), "{path}: {key} {group} {t0}");
            let w0 = hex(&rec["w0"]) | CTRL;
            let (k, g, text) = decode_text(path, w0).unwrap_or_else(|| panic!("{path}: {w0:032x} does not decode"));
            assert_eq!((k.as_str(), g.as_str(), text.as_str()), (key, group, t0), "{path}: {w0:032x}");
            assert_eq!(reencode(table, w0, t0), w0, "{path}: {t0}");
            let mut n_field = 0;
            for entry in bits_of(rec, "field") {
                let bit = entry[0].as_u64().unwrap();
                let vendor = entry[1].as_str().unwrap();
                let word = w0 ^ (1u128 << bit);
                let (k, _, text) = decode_text(path, word).unwrap_or_else(|| panic!("{path}: field bit {bit}: {word:032x}"));
                assert_eq!(k, key, "{path}: field bit {bit} leaves the key");
                assert_eq!(text, vendor, "{path}: field bit {bit}");
                assert_eq!(reencode(table, word, vendor), word, "{path}: field bit {bit}: {vendor}");
                n_field += 1;
            }
            // 4 guard + 3 x 8 register (or 2 x 8 + 8 UR) + 3 predicate + 1 sign + the reuse slots, minus the flips
            // nvdisasm rejects inside a field (value-range limits are allowed inside a declared field)
            assert!(n_field >= 36, "{path}: {key} {group}: only {n_field} field bits verified");
        }
    }
}

/// Nothing outside the declared fields is ever rendered as a different VIMNMX3 text: a modifier bit's word is another
/// group's (decoded only to the vendor's text or not at all), a text-inert bit fails closed or prints the canonical
/// text, an nvdisasm-rejected bit is never a VIMNMX3 decode, and the FMNMX word the harvest row claimed is FMNMX's.
#[test]
fn the_lattice_around_each_row_is_never_rendered_as_another_vimnmx3_text() {
    for (i, (path, _)) in TABLES.iter().enumerate() {
        for rec in records(i) {
            let w0 = hex(&rec["w0"]) | CTRL;
            let t0 = rec["t0"].as_str().unwrap();
            for class in ["modifier", "complex", "operand_other"] {
                for entry in bits_of(&rec, class) {
                    let bit = entry[0].as_u64().unwrap();
                    let vendor = entry[1].as_str().unwrap();
                    if let Some((k, _, text)) = decode_text(path, w0 ^ (1u128 << bit)) {
                        assert_eq!(text, vendor, "{path}: {class} bit {bit} ({k})");
                    }
                }
            }
            for bit in bits_of(&rec, "inert") {
                let bit = bit.as_u64().unwrap();
                if let Some((k, _, text)) = decode_text(path, w0 ^ (1u128 << bit)) {
                    assert_eq!(text, t0, "{path}: text-inert bit {bit} ({k}) rendered differently");
                }
            }
            for bit in bits_of(&rec, "illegal") {
                let bit = bit.as_u64().unwrap();
                if bit >= 122 {
                    continue; // a `.reuse` bit on a slot without a register: nvdisasm rejects, cubit strips it (A12, `reuse_rejected`)
                }
                if let Some((k, _, text)) = decode_text(path, w0 ^ (1u128 << bit)) {
                    assert!(!k.starts_with("VIMNMX3"), "{path}: nvdisasm rejects bit {bit}, cubit prints `{text}` ({k})");
                }
            }
        }
        match decode_text(path, FMNMX_LATTICE_WORD) {
            None => {}
            Some((k, _, text)) => {
                assert!(!k.starts_with("VIMNMX3"), "{path}: the FMNMX lattice word is claimed by {k} (`{text}`) again");
                assert_eq!(text, "FMNMX R4, R2, R3, PT", "{path}: the FMNMX lattice word");
            }
        }
    }
}

/// The provenance: the three rows per table carry the tag, nothing else of VIMNMX3 is a harvest row, the table's
/// legend counts them, and no row of the family declares a field inside the opcode nibble.
#[test]
fn the_rows_are_measured_and_no_field_sits_in_the_opcode() {
    for (path, _) in TABLES.iter() {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(path).unwrap()).unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        let mut tagged = 0u64;
        for (key, e) in ins {
            if !key.starts_with("VIMNMX3") {
                continue;
            }
            for (name, g) in e["mod_groups"].as_object().unwrap() {
                assert_eq!(g["_src"], SOURCE, "{path}: {key} {name}");
                assert!(ROWS.iter().any(|(k, gn, _)| k == key && gn == name), "{path}: {key} {name}: a row the probe did not see");
                for f in g["fields"].as_array().unwrap() {
                    let shift = f["shift"].as_u64().unwrap();
                    assert!(shift >= 12, "{path}: {key} {name}: field {} at shift {shift} inside the opcode", f["extraction"]);
                }
                let mask = hex(&g["variable_mask"]);
                assert_eq!(mask & 0xfff, 0, "{path}: {key} {name}: opcode bits in the variable mask");
                tagged += 1;
            }
        }
        assert_eq!(tagged, ROWS.len() as u64, "{path}: tagged rows");
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], tagged, "{path}: the legend");
    }
}

/// sm121a: `MUFU_R_L` is an alias of the measured `MUFU_R_R` (encoder-visible, decoder-invisible) and the lattice
/// word it used to claim is no longer rendered as a MUFU text other than the vendor's.
#[test]
fn sm121a_mufu_r_l_is_an_alias_and_claims_nothing() {
    let path = "tables/sm121a.json";
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(path).unwrap()).unwrap();
    assert!(raw["instructions"].get("MUFU_R_L").is_none(), "MUFU_R_L is still a key");
    assert_eq!(raw["_meta"]["key_aliases"]["MUFU_R_L"], "MUFU_R_R");
    let (table, _) = table_and_index(path);
    let alias = table.entries.get("MUFU_R_L").expect("the alias clone is an entry");
    assert!(alias.encode_only, "the alias is decoder-invisible");
    assert!(!table.entries["MUFU_R_R"].encode_only);
    if let Some((k, _, text)) = decode_text(path, MUFU_LATTICE_WORD) {
        assert_eq!(text, "MUFU.INVALID6.F16 R4, R2", "the MUFU lattice word is rendered as `{text}` by {k}");
    }
    // the eight canonical words of the retired key are the plain MUFU_R_R words (RCP64H's at the function code 6)
    let word = 0x000f_e200_0000_1800_0000_0002_0004_7308u128;
    let (k, g, text) = decode_text(path, word).unwrap();
    assert_eq!((k.as_str(), g.as_str(), text.as_str()), ("MUFU_R_R", "RCP64H", "MUFU.RCP64H R4, R2"));
    assert_eq!(reencode(table, word, &text), word);
}
