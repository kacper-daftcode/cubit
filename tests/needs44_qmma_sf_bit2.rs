//! NEEDS 44: opcode 0x47e — the `IMMA.SF.16832.U8.U8` hypothesis of 2026-03-26 — measured on sm_120 silicon.
//! 2026-11-06 (session R, test host GPU 0, RTX PRO 6000 SE): the word executes, writes fp32, honours the E8M0
//! block scales and matches neither documented QMMA.SF input type — a QMMA.SF-family variant selected by opcode
//! bit 2, named `UNIDENTIFIED` until the types were known. 2026-11-07 (session T-13, same host; kernel
//! `needs44_types` with the five documented diagonal type pairs and the 0x47e word on identical fragments, fixture
//! `tests/fixtures/sm120_qmma_sf_mxint8_silicon.jsonl`): byte-value sweeps of A and of B against three references
//! give 32 · mx(a) · mx(b) with mx(byte) = int8(byte) / 64 **exactly for all 6 × 256 cases** — both operands are
//! OCP **MXINT8** (two's-complement int8 with six fractional bits under an E8M0 block scale; the E4M3 / E5M2 / E3M2 /
//! E2M3 / E2M1 / S8 / U8 maps do not fit); one-hot bytes light one D row (A) / one D column (B) exactly as the
//! E4M3.E4M3 row does (the m16n8k32 8-bit fragment layout); a byte is one element (0x04 → 0.0625, 0x44 → 1.0625);
//! the scale sweep gives D · 2^(s−127) for every E8M0 value with NaN at 0xff. The table row is therefore
//! `QMMA.SF.16832.F32.MXINT8.MXINT8.E8_R_R_R_R_R_R_UR` with the family's fields (Rd@16 Ra@24 Rb@32 Rc@64 sfA@40
//! sfB@52 UR@60+73), provenance `qmma-sf-mxint8-silicon-2026-11-07` (`nvdisasm_sm120: "no text"`); the hypothesis
//! key and the interim `UNIDENTIFIED` key are aliases. Side result pinned from the same run: the documented E2M1
//! type code computes exactly the E2M3 map on bits [5:0] of the container for every byte (PTX puts `.e2m1` in bits
//! [5:2] of the 8-bit container; the silicon does not mask bits [1:0]). nvdisasm 13.1 / 13.3 reject every 0x47e
//! word, so there is no vendor text to replay — the pins are the probe words, the row's shape and the measured law.
use cubit::decoder::DecodeIndex;
use cubit::table::IsaTable;
use serde_json::Value;
use std::sync::OnceLock;

const KEY: &str = "QMMA.SF.16832.F32.MXINT8.MXINT8.E8_R_R_R_R_R_R_UR";
const HYPOTHESIS: &str = "IMMA.SF.16832.U8.U8_R_R_R_R_R_R_UR";
const INTERIM: &str = "QMMA.SF.16832.F32.UNIDENTIFIED.E8_R_R_R_R_R_R_UR";
const SRC: &str = "qmma-sf-mxint8-silicon-2026-11-07";
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

fn fixture() -> Vec<Value> {
    include_str!("fixtures/sm120_qmma_sf_mxint8_silicon.jsonl").lines().filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap()).collect()
}

/// OCP MXINT8: the element is a two's-complement int8 with six fractional bits.
fn mxint8(b: u32) -> f64 {
    (b as u8 as i8) as f64 / 64.0
}

/// OCP FP6 E2M3 on the low six bits of the container (sign, 2 exponent bits with bias 1, 3 mantissa bits).
fn e2m3_lo6(b: u32) -> f64 {
    let b = b & 0x3f;
    let s = if b & 0x20 != 0 { -1.0 } else { 1.0 };
    let e = (b >> 3) & 3;
    let m = (b & 7) as f64;
    if e == 0 { s * m / 8.0 } else { s * (1.0 + m / 8.0) * 2f64.powi(e as i32 - 1) }
}

/// The probe words: R's 2026-11-06 word (Rd = R24) and T-13's 2026-11-07 word (Rd = R44) on the QMMA.SF field
/// model — the ones that executed and produced the measured results. (R's second variant with type-field bits
/// 78 / 79 / 83 / 85 set lies outside the row's mask and fails closed; the type-field lattice under opcode bit 2 is
/// not measured.)
const PROBE: &[(u128, &str)] = &[
    (0x013ede000000001061d01c0c0818747e, "QMMA.SF.16832.F32.MXINT8.MXINT8.E8 R24, R8, R12, R16, R28, R29, UR6"),
    (0x000f5e000000001061d01c0c082c747e, "QMMA.SF.16832.F32.MXINT8.MXINT8.E8 R44, R8, R12, R16, R28, R29, UR6"),
];

#[test]
fn needs44_1_the_row_is_the_measured_variant_and_the_historical_keys_are_its_aliases() {
    let (_, _, raw) = loaded();
    let ins = raw["instructions"].as_object().unwrap();
    assert!(!ins.contains_key(HYPOTHESIS), "the hypothesis key is gone");
    assert!(!ins.contains_key(INTERIM), "the interim UNIDENTIFIED key is gone");
    let row = &ins[KEY]["mod_groups"][""];
    assert_eq!(row["_src"], SRC);
    assert_eq!(u128::from_str_radix(row["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap() & 0xfff, 0x47e);
    // the family's field model: the donor's fields, one for one
    let donor = &ins["QMMA.SF.16832.F32.E4M3.E4M3.E8_R_R_R_R_R_R_UR"]["mod_groups"][""];
    let shape = |r: &Value| -> Vec<(u64, u64, String, i64)> {
        r["fields"].as_array().unwrap().iter()
            .map(|f| (f["shift"].as_u64().unwrap(), f["bits"].as_u64().unwrap(), f["extraction"].as_str().unwrap().to_string(), f["token_idx"].as_i64().unwrap()))
            .collect()
    };
    assert_eq!(shape(row), shape(donor), "the fields are the QMMA.SF family's");
    assert_eq!(row["variable_mask"], donor["variable_mask"]);
    assert_eq!(raw["_meta"]["key_aliases"][HYPOTHESIS], KEY);
    assert_eq!(raw["_meta"]["key_aliases"][INTERIM], KEY);
    let src = &raw["_meta"]["provenance"]["sources"][SRC];
    assert_eq!(src["nvdisasm_sm120"], "no text");
    assert_eq!(src["rows"], 1);
    assert!(raw["_meta"]["provenance"]["sources"].get("qmma-sf-opcode-bit2-silicon-2026-11-06").is_none(), "the interim tag is superseded");
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
fn needs44_3_the_withdrawn_spellings_assemble_through_the_aliases_or_are_refused_with_the_row_named() {
    let (t, _, _) = loaded();
    // the historical spellings resolve to the measured row (an alias is encode-only; the printed text is the new name)
    for (old, word) in [("IMMA.SF.16832.U8.U8", PROBE[0].0), ("QMMA.SF.16832.F32.UNIDENTIFIED.E8", PROBE[0].0)] {
        let parsed = cubit::parser::parse_sass(&format!(" {old} R24, R8, R12, R16, R28, R29, UR6 ;"), 0).unwrap();
        match cubit::encoder::encode_instruction(&parsed, t) {
            Ok(enc) => assert_eq!(enc & !SCHEDULE, word & !SCHEDULE, "{old}: the alias mints the measured word"),
            Err(e) => assert!(e.to_string().contains(KEY.split('_').next().unwrap()), "{old}: {e}"),
        }
    }
}

#[test]
fn needs44_4_the_measured_sweeps_are_the_mxint8_law_on_both_operands() {
    let mut checked = 0usize;
    for rec in fixture() {
        if rec["row"] != "0x47e" || !(rec["sweep"] == "A" || rec["sweep"] == "B") { continue; }
        let r = u32::from_str_radix(rec["ref"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        let values = rec["values"].as_array().unwrap();
        assert_eq!(values.len(), 256);
        for (v, d) in values.iter().enumerate() {
            let d = d.as_f64().unwrap_or_else(|| panic!("sweep {} ref {r:#04x} v {v:#04x}: NaN measured", rec["sweep"]));
            let want = 32.0 * mxint8(v as u32) * mxint8(r);
            assert_eq!(d as f32, want as f32, "sweep {} ref {r:#04x} v {v:#04x}: D = {d}, the MXINT8 law gives {want}", rec["sweep"]);
            checked += 1;
        }
    }
    assert_eq!(checked, 6 * 256, "six sweeps of 256 values");
}

#[test]
fn needs44_5_the_scale_law_the_layout_and_the_element_width() {
    for rec in fixture() {
        if rec["row"] != "0x47e" { continue; }
        match rec["sweep"].as_str().unwrap() {
            "scaleA" => {
                // A = B = 0x40 (1.0), sfB = 0x7f: D(s) = 32 * 2^(s - 127) in fp32 (overflow to inf), NaN at 0xff
                let values = rec["values"].as_array().unwrap();
                for (s, d) in values.iter().enumerate() {
                    if s == 255 { assert!(d.is_null(), "sf 0xff -> NaN"); continue; }
                    let want = (32.0f64 * 2f64.powi(s as i32 - 127)) as f32;
                    // the fp32 overflow is recorded as the string "inf"
                    let got = if d == "inf" { f32::INFINITY } else { d.as_f64().unwrap() as f32 };
                    assert_eq!(got, want, "sf {s:#04x}");
                }
            }
            "nibble" => {
                // one A byte at lane 0 byte 0, B = 0x40: the byte is one MXINT8 element, not two nibbles
                let v = rec["values"].as_object().unwrap();
                for (byte, want) in [("04", 0.0625), ("40", 1.0), ("44", 1.0625), ("08", 0.125), ("80", -2.0), ("88", -1.875)] {
                    assert_eq!(v[byte].as_array().unwrap().iter().map(|x| x.as_f64().unwrap()).collect::<Vec<_>>(), vec![want], "byte 0x{byte}");
                }
            }
            "onehot" => {
                let v = &rec["values"];
                assert_eq!(v["A_nonzero_per_byte"], serde_json::json!([8]), "one A byte -> the 8 D elements of one row");
                assert_eq!(v["B_nonzero_per_byte"], serde_json::json!([16]), "one B byte -> the 16 D elements of one column");
                assert_eq!(v["same_positions_as_E4M3"], true, "the m16n8k32 8-bit fragment layout");
            }
            _ => {}
        }
    }
}

#[test]
fn needs44_6_side_result_the_e2m1_type_code_is_the_e2m3_map_on_the_low_six_bits() {
    let mut rows = 0usize;
    for rec in fixture() {
        if rec["sweep"] != "A" || !(rec["row"] == "E2M1.E2M1" || rec["row"] == "E2M3.E2M3") { continue; }
        let r = u32::from_str_radix(rec["ref"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        for (v, d) in rec["values"].as_array().unwrap().iter().enumerate() {
            let want = (32.0 * e2m3_lo6(v as u32) * e2m3_lo6(r)) as f32;
            assert_eq!(d.as_f64().unwrap() as f32, want, "row {} ref {r:#04x} v {v:#04x}", rec["row"]);
        }
        rows += 1;
    }
    assert_eq!(rows, 4, "two rows x two references");
}
