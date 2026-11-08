//! SM120 `ISETP` / `UISETP` rebuilt from measurement (session G, 2026-11-06; KNOWN_ISSUES T1): the ten keys
//! (`ISETP_P_P_R_{R,UR,II}_P`, `UISETP_UP_UP_UR_{UR,II}_UP` and their `.EX` twins `_P` / `_UP`) carry 96 measured
//! groups each -- `tools/probes/re_sm120_isetp.py`, nvdisasm 13.1, 1 944 form + 192 lattice words. Law: guard
//! [15:12] (`@[!]UPn` on UISETP), Ra [31:24], Rb [39:32] / imm32 [63:32], [71:68] the `.EX` carry-in predicate
//! (bit 72 = `.EX`; without it the window is text-inert and nvcc writes PT -- baked 7, fail-closed), 73 signed
//! (no type suffix in the 32-bit signed mode), [75:74] the boolean (3 = `INVALID3`), [78:76] the comparison,
//! 80 = 64-bit (`.S64` / `.U64`, SM120-only: text-inert on `-b SM103` / `SM100`), Pd0 [83:81], Pd1 [86:84],
//! Pc [89:87] + `!` 90; `.reuse` Ra 122 / Rb 123 on ISETP, none on UISETP; [23:16], the unused part of [67:40],
//! 79 and [95:92] text-inert. 509 harvest rows (baked PT guards / sample predicates, masks excluding their own
//! fields) replaced, 67 missing immediate-form groups added, the 384 dsv41 rows of 2026-10-22 reproduced and kept.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "isetp-family-2026-11-06";
const DSV41: &str = "dsv41-sm120-2026-10-22";
const CTRL: u128 = 0x000f_e200u128 << 96;
const KEYS: [&str; 10] = ["ISETP_P_P_R_R_P", "ISETP_P_P_R_R_P_P", "ISETP_P_P_R_UR_P", "ISETP_P_P_R_UR_P_P", "ISETP_P_P_R_II_P",
                          "ISETP_P_P_R_II_P_P", "UISETP_UP_UP_UR_UR_UP", "UISETP_UP_UP_UR_UR_UP_UP", "UISETP_UP_UP_UR_II_UP",
                          "UISETP_UP_UP_UR_II_UP_UP"];

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
    include_str!("fixtures/sm120_isetp_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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

/// Every form word (the 960 groups on the canonical operands, the operand lattice of two groups per key --
/// guard, the three predicates and the `.EX` carry-in with `!`, RZ / URZ, the immediate edges incl. the negative
/// hexadecimals, `.reuse` -- and one word per key with every field away from its canonical value) decodes to the
/// ten keys, prints NVIDIA's text and re-encodes bit for bit.
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
    assert_eq!(n, 1944, "form words in the fixture");
    assert_eq!(groups.len(), 960, "10 keys x 96 groups");
}

/// The lattice: the `INVALID3` boolean, the frame bit flipped (illegal), the text-inert bits and the carry-in
/// window of a non-EX word away from nvcc's PT -- all unclaimed (fail-closed).
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
    assert_eq!(n, 192);
    assert_eq!(undecoded, 192);
    for text in ["ISETP.GE.INVALID3 P0, PT, R2, R3, PT", "UISETP.GE.INVALID3 UP0, UPT, UR2, UR3, UPT"] {
        let parsed = cubit::parser::parse_sass(text, 0).unwrap();
        assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "{text} must be refused");
    }
}

/// The ten keys carry 96 measured groups each (`_src` = this probe's tag or the dsv41 tag whose rows the probe
/// reproduced; mask == the fields; nothing baked under a field; the non-EX rows bake PT in the carry-in window; the
/// modifier bits of each group name and nothing else), plus the BUG-092 encode-only retention group of
/// `UISETP_UP_UP_UR_UR_UP`; the provenance legend names the tag.
#[test]
fn the_rows_are_measured() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 576);
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let cmp = ["F", "LT", "EQ", "LE", "GT", "NE", "GE", "T"];
    let (mut measured, mut dsv41) = (0, 0);
    for key in KEYS {
        // 2026-11-08 (tools/tablefmt.py): the key-level `_src` is the tag every row of the key carries -- the two
        // UR-form keys hold only the dsv41 rows this probe reproduced, so their key tag is the dsv41 one
        let key_tag = if key.contains("_R_UR_") { DSV41 } else { SOURCE };
        assert_eq!(ins[key]["_src"], key_tag, "{key}");
        let groups = ins[key]["mod_groups"].as_object().unwrap();
        let retention = key == "UISETP_UP_UP_UR_UR_UP";
        assert_eq!(groups.len(), if retention { 97 } else { 96 }, "{key}");
        for (name, g) in groups {
            if name.is_empty() {
                assert!(retention && g["encode_only"] == true, "{key}: the BUG-092 retention group");
                continue;
            }
            match g["_src"].as_str() {
                Some(SOURCE) => measured += 1,
                Some(DSV41) => dsv41 += 1,
                other => panic!("{key} {name}: {other:?}"),
            }
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
            let ex = name.split(',').any(|m| m == "EX");
            let mut want = if ex { 1u128 << 72 } else { 7u128 << 68 };
            let (mut signed, mut w64) = (true, false);
            for m in name.split(',') {
                match m {
                    "AND" | "EX" => {}
                    "OR" => want |= 1 << 74,
                    "XOR" => want |= 2 << 74,
                    "U32" => signed = false,
                    "S64" => w64 = true,
                    "U64" => { signed = false; w64 = true; }
                    c => want |= (cmp.iter().position(|x| *x == c).unwrap() as u128) << 76,
                }
            }
            want |= ((signed as u128) << 73) | ((w64 as u128) << 80);
            assert_eq!(base & !0xfffu128 & !(1u128 << 91), want, "{key} {name}");
            assert_eq!(field_mask & (0xf << 68) != 0, ex, "{key} {name}: the carry-in window is a field exactly on the .EX rows");
        }
    }
    assert_eq!((measured, dsv41), (576, 384));
}

/// Production census words of the family (nvcc output: the PT carry-in window, `.reuse`, negative immediates) and
/// the two shapes of the BUG-086 recanon.
#[test]
fn witness_words_round_trip() {
    for (word, vendor) in [
        (0x000fe20003f05070000000ff1600720cu128, "ISETP.NE.U32.AND P0, PT, R22, RZ, PT"),
        (0x040fe20000701270000000ff0400720cu128, "ISETP.LT.AND P0, PT, R4.reuse, RZ, P0"),
        (0x000fe20003f040700000007f0400780cu128, "ISETP.GT.U32.AND P0, PT, R4, 0x7f, PT"),
        (0x000fe2000bf1527000000006ff007c0cu128, "ISETP.NE.S64.AND P0, PT, RZ, UR6, PT"),
        (0x000fe2000bf04270000000050b00728cu128, "UISETP.GT.AND UP0, UPT, UR11, UR5, UPT"),
        (0x000fe2000bf05270000000014300788cu128, "UISETP.NE.AND UP0, UPT, UR67, 0x1, UPT"),
        (0x000fe20003f06100000001000300780cu128, "ISETP.GE.U32.AND.EX P0, PT, R3, 0x100, PT, P0"),
        (0x000fe20001743070000000070500780cu128, "ISETP.LE.U32.AND P2, PT, R5, 0x7, P2"),
    ] {
        check(word, vendor);
    }
}
