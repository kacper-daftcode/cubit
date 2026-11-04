//! nvdisasm's `IMAD.MOV` / `IMAD.IADD` / `IMAD.SHL` display aliases on SM120, measured 2026-11-04
//! (tools/probes/re_sm120_imad_alias.py, fixture tests/fixtures/sm120_imad_alias_nvdisasm.jsonl: the
//! four-operand forms R_R_R_R / R_R_R_II / R_R_II_R / R_R_R_UR, signed and .U32, over a / b / c in
//! {RZ, register, immediate 0 1 2 3 0x10 0x80000000}, 144 words, nvdisasm 13.1 one word per call).
//! The law (`cubit::printer::imad_alias`): `.MOV` when a = RZ, b = RZ, b = 0, or b = 1 with c = RZ
//! (a register or immediate c - a UR c never takes an alias, BUG-083); `.IADD` when b = 1 and c is a
//! register other than RZ; `.SHL` when b is a power of two in 2..=2^30 and c = RZ. The alias is a
//! print of the operands: the table's alias-named harvest groups (`MOV`, `MOV,U32`, `IADD`, `SHL,U32`
//! - they baked a sample's operands and put the Ra token on the Rb field, `IMAD.MOV.U32 R4, RZ, R14,
//! 0x10` printed as `R4, R14, R14, 0x10`) are gone, every form has a `U32` twin of its plain row, the
//! printer derives the name, the encoder accepts an alias only in the shape the vendor prints it for.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const CTRL: u128 = 0x000f_e200u128 << 96;

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
    include_str!("fixtures/sm120_imad_alias_nvdisasm.jsonl").lines()
        .map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn encode(table: &IsaTable, text: &str) -> Result<u128, String> {
    let parsed = cubit::parse_sass(&format!("{text} ;"), 0).map_err(|e| e.to_string())?;
    cubit::encoder::encode_instruction(&parsed, table).map_err(|e| e.to_string())
}

#[test]
fn every_probed_word_prints_the_vendor_name_and_reassembles() {
    let (table, index) = table_and_index();
    let mut aliases = std::collections::BTreeMap::new();
    for r in fixture() {
        let word = u128::from_str_radix(r["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        let vendor = r["nvidia_sass"].as_str().unwrap();
        let d = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
        let text = cubit::printer::to_sass_lossless(&d);
        assert_eq!(text, vendor, "{word:032x}");
        let back = encode(table, vendor).unwrap_or_else(|e| panic!("{vendor}: {e}"));
        assert_eq!(back & ((1u128 << 105) - 1), word & ((1u128 << 105) - 1), "{vendor}: payload");
        let mn = vendor.trim_start_matches(|c| c != 'I').split(' ').next().unwrap().to_string();
        *aliases.entry(mn).or_insert(0) += 1;
    }
    assert_eq!(aliases.values().sum::<i32>(), 144);
    for name in ["IMAD.MOV", "IMAD.MOV.U32", "IMAD.IADD", "IMAD.SHL", "IMAD.SHL.U32", "IMAD", "IMAD.U32"] {
        assert!(aliases.contains_key(name), "{name} missing from the sweep: {aliases:?}");
    }
}

#[test]
fn the_alias_law_on_operand_facts() {
    use cubit::printer::imad_alias_of_text as law;
    assert_eq!(law("RZ", "R14", "R10"), Some("MOV"));
    assert_eq!(law("R6", "RZ", "0x10"), Some("MOV"));
    assert_eq!(law("R6", "0x0", "R10"), Some("MOV"));
    assert_eq!(law("R6", "0x1", "RZ"), Some("MOV"));
    assert_eq!(law("R6", "0x1", "R10"), Some("IADD"));
    assert_eq!(law("R6", "0x2", "RZ"), Some("SHL"));
    assert_eq!(law("R6", "0x10", "RZ"), Some("SHL"));
    assert_eq!(law("R6", "0x3", "RZ"), None);
    assert_eq!(law("R6", "-0x80000000", "RZ"), None, "2^31 is negative as s32: plain");
    assert_eq!(law("R6", "0x10", "R10"), None);
    assert_eq!(law("RZ", "R14", "UR8"), None, "a UR c never takes an alias");
    assert_eq!(law("RZ", "RZ", "URZ"), None);
}

#[test]
fn alias_text_assembles_only_in_the_vendor_shape() {
    let (table, _) = table_and_index();
    for (alias, plain) in [
        ("IMAD.MOV R4, RZ, R14, R10", "IMAD R4, RZ, R14, R10"),
        ("IMAD.MOV.U32 R4, RZ, R14, 0x10", "IMAD.U32 R4, RZ, R14, 0x10"),
        ("IMAD.MOV R4, R6, 0x0, R10", "IMAD R4, R6, 0x0, R10"),
        ("IMAD.IADD R4, R6, 0x1, R10", "IMAD R4, R6, 0x1, R10"),
        ("IMAD.SHL.U32 R4, R6, 0x10, RZ", "IMAD.U32 R4, R6, 0x10, RZ"),
    ] {
        let a = encode(table, alias).unwrap_or_else(|e| panic!("{alias}: {e}"));
        let p = encode(table, plain).unwrap_or_else(|e| panic!("{plain}: {e}"));
        assert_eq!(a, p, "{alias} and {plain} are the same word");
    }
    for wrong in [
        "IMAD.MOV R4, R6, R14, R10",      // a product that is not zero
        "IMAD.SHL R4, R6, 0x3, RZ",       // not a power of two
        "IMAD.SHL R4, R6, 0x10, R10",     // c is not RZ
        "IMAD.IADD R4, R6, 0x1, RZ",      // that one prints as .MOV
        "IMAD.MOV.U32 R4, RZ, R14, UR8",  // a UR c never takes an alias
    ] {
        let e = encode(table, wrong).expect_err(wrong);
        assert!(e.contains("display alias") || e.contains("nvdisasm's name"), "{wrong}: {e}");
    }
}

#[test]
fn the_table_has_no_alias_named_groups_and_every_form_has_a_u32_twin() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    for key in ["IMAD_R_R_R_R", "IMAD_R_R_R_II", "IMAD_R_R_II_R", "IMAD_R_R_R_UR", "IMAD_R_R_UR_R"] {
        let groups = raw["instructions"][key]["mod_groups"].as_object().unwrap();
        for g in groups.keys() {
            assert!(!g.split(',').any(|m| matches!(m, "MOV" | "IADD" | "SHL")), "{key}: alias-named group {g}");
        }
        assert!(groups.contains_key("U32"), "{key}: U32 twin");
        let shifts: Vec<u64> = groups["U32"]["fields"].as_array().unwrap().iter().map(|f| f["shift"].as_u64().unwrap()).collect();
        let mut uniq = shifts.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), shifts.len(), "{key}: U32 fields overlap ({shifts:?})");
    }
}
