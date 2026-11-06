//! NEEDS 44 (2026-11-06): opcode 0x47e — the `IMMA.SF.16832.U8.U8` hypothesis of 2026-03-26 — measured on
//! sm_120 silicon by session R (test host GPU 0, RTX PRO 6000 SE; cubit-assembled probes next to the documented
//! `QMMA.SF.16832.F32.E4M3.E4M3.E8` / `…E2M1.E2M1.E8` on identical fragments): the word executes, writes fp32,
//! honours the E8M0 block scales (scale 0xff → NaN, scale ×2 → result ×2) and matches neither documented input
//! type (A = 0x38, B = 0x40, scales 1.0: 64.0 / 0.0 / 28.0). It is an undocumented QMMA.SF-family variant
//! selected by opcode bit 2 with unidentified input element types, not an integer MMA. The table row is
//! `QMMA.SF.16832.F32.UNIDENTIFIED.E8_R_R_R_R_R_R_UR` with the family's fields (Rd@16 Ra@24 Rb@32 Rc@64 sfA@40
//! sfB@52 UR@60+73), provenance `qmma-sf-opcode-bit2-silicon-2026-11-06` (`nvdisasm_sm120: "no text"`), the old
//! key an alias. nvdisasm 13.1 / 13.3 reject every 0x47e word, so there is no fixture to replay — the pins
//! below are R's probe words and the row's shape.
use cubit::decoder::DecodeIndex;
use cubit::table::IsaTable;
use serde_json::Value;
use std::sync::OnceLock;

const KEY: &str = "QMMA.SF.16832.F32.UNIDENTIFIED.E8_R_R_R_R_R_R_UR";
const OLD: &str = "IMMA.SF.16832.U8.U8_R_R_R_R_R_R_UR";
const SRC: &str = "qmma-sf-opcode-bit2-silicon-2026-11-06";
const SCHEDULE: u128 = ((1u128 << 23) - 1) << 105;

fn table_path() -> std::path::PathBuf {
    std::env::var_os("CUBIT_TABLE").map(std::path::PathBuf::from).unwrap_or_else(|| "tables/sm120.json".into())
}

fn loaded() -> &'static (IsaTable, DecodeIndex, Value) {
    static T: OnceLock<(IsaTable, DecodeIndex, Value)> = OnceLock::new();
    T.get_or_init(|| {
        let t = IsaTable::load(&table_path()).unwrap();
        let idx = DecodeIndex::build(&t);
        let raw: Value = serde_json::from_str(&cubit::table::read_table_text(table_path()).unwrap()).unwrap();
        (t, idx, raw)
    })
}

/// R's probe word (`R/immasf/imma_sf_probe2.sass`): the 0x47e word on the QMMA.SF field model, the one
/// that executed and produced the fp32 results above. (R's second variant with type-field bits 78 / 79 /
/// 83 / 85 set lies outside the row's mask and fails closed, as it did under the hypothesis row.)
const PROBE: &[(u128, &str)] = &[
    (0x013ede000000001061d01c0c0818747e, "QMMA.SF.16832.F32.UNIDENTIFIED.E8 R24, R8, R12, R16, R28, R29, UR6"),
];

#[test]
fn needs44_1_the_row_is_the_measured_variant_and_the_hypothesis_key_is_its_alias() {
    let (_, _, raw) = loaded();
    let ins = raw["instructions"].as_object().unwrap();
    assert!(!ins.contains_key(OLD), "the hypothesis key is gone");
    let row = &ins[KEY]["mod_groups"][""];
    assert_eq!(row["_src"], SRC);
    assert_eq!(u128::from_str_radix(ins[KEY]["mod_groups"][""]["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap() & 0xfff, 0x47e);
    // the family's field model: the donor's fields, one for one
    let donor = &ins["QMMA.SF.16832.F32.E4M3.E4M3.E8_R_R_R_R_R_R_UR"]["mod_groups"][""];
    let shape = |r: &Value| -> Vec<(u64, u64, String, i64)> {
        r["fields"].as_array().unwrap().iter()
            .map(|f| (f["shift"].as_u64().unwrap(), f["bits"].as_u64().unwrap(), f["extraction"].as_str().unwrap().to_string(), f["token_idx"].as_i64().unwrap()))
            .collect()
    };
    assert_eq!(shape(row), shape(donor), "the fields are the QMMA.SF family's");
    assert_eq!(row["variable_mask"], donor["variable_mask"]);
    assert_eq!(raw["_meta"]["key_aliases"][OLD], KEY);
    let src = &raw["_meta"]["provenance"]["sources"][SRC];
    assert_eq!(src["nvdisasm_sm120"], "no text");
    assert_eq!(src["rows"], 1);
}

#[test]
fn needs44_2_the_probe_words_decode_to_the_variant_and_reassemble() {
    let (t, idx, _) = loaded();
    for (word, text) in PROBE {
        let d = idx.decode(*word, 0, t).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
        assert_eq!(d.key, KEY);
        let printed = cubit::printer::to_sass(&d);
        assert_eq!(printed.trim().trim_end_matches(';').trim(), *text, "{word:032x}");
        let parsed = cubit::parser::parse_sass(&format!(" {text} ;"), 0).unwrap();
        let enc = cubit::encoder::encode_instruction(&parsed, t).unwrap();
        assert_eq!(enc & !SCHEDULE, *word & !SCHEDULE, "{word:032x} reassembles bit for bit");
    }
    // the type-field variant fails closed (outside the measured row's mask)
    assert!(idx.decode(0x013ede000028c01061d01c0c0818747e, 0, t).is_err());
}

#[test]
fn needs44_3_the_withdrawn_spelling_is_refused_with_the_measured_row_named() {
    let (t, _, _) = loaded();
    let parsed = cubit::parser::parse_sass(" IMMA.SF.16832.U8.U8 R20, R8, R12, R16, R28, R29, UR6 ;", 0).unwrap();
    let err = cubit::encoder::encode_instruction(&parsed, t).unwrap_err().to_string();
    assert!(err.contains(KEY.split('_').next().unwrap()), "{err}");
}
