//! SM120 OMMA block-scale operand `URi`: an eight-bit uniform-register number split across two fields (`ureg` [62:60] =
//! its low three bits, `ureg_shr3` [77:73] = its high five; 255 = `URZ`). Reported by ComradePenguin-1917 on 2026-09-18
//! (cubit pull request 2, blackwell-isa pull request 1): the table then declared one four-bit field at [63:60] -- `URZ`
//! and `UR16`+ could not be written and `UR8`..`UR15` lost their high bit without a diagnostic -- and the printer
//! *assigned* each slice of a split operand, so the high slice overwrote the low one (`UR6` came back as `UR0`); the
//! same report named the system-register operand of `CS2R` (no field) and the plain `CS2UR` (filed under `.32`, its
//! register baked into the row). All of it was fixed since, from measurement: blackwell-isa fcb8132 (2026-10-22: the
//! split fields, `reuse` at bit 51, `CS2R`'s register field) and 59561b2 (2026-10-23: `CS2UR` plain / `.32` by bit 80),
//! cubit 94489ed (2026-10-22: the printer reconstructs a split operand before the `URZ` spelling); the sixteen OMMA
//! rows were verified field by field on 2026-11-07 (tests/sm120_rows_tensor.rs).
//!
//! This file pins the report's own cases: every OMMA key x `UR0`..`UR63`, `URZ` encodes and decodes back to its text
//! (1 040 texts; on 2026-11-10 each of the 1 040 words was named by nvdisasm 13.1 `-b SM120` with the same text), eight
//! of the words are kept as literals with nvdisasm's text, and the four texts of the report's verification table
//! round-trip.

use cubit::{decoder::DecodeIndex, table::IsaTable};
use std::sync::OnceLock;

/// The instruction bits: everything below the control code [127:105], which the assembler owns.
const INSN: u128 = (1u128 << 105) - 1;

fn sm120() -> &'static (IsaTable, DecodeIndex) {
    static T: OnceLock<(IsaTable, DecodeIndex)> = OnceLock::new();
    T.get_or_init(|| {
        let table = IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    })
}

fn encode(text: &str) -> u128 {
    let (table, _) = sm120();
    let ins = cubit::parse_sass(text, 0).unwrap_or_else(|e| panic!("{text}: {e}"));
    cubit::encoder::encode_instruction(&ins, table).unwrap_or_else(|e| panic!("{text}: {e}"))
}

fn decode(word: u128) -> String {
    let (table, index) = sm120();
    let d = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
    cubit::printer::to_sass_lossless(&d) // with the `.reuse` flags, as nvdisasm prints them
}

/// One text per OMMA key and `URi` value: the key's operand signature spelled with fixed registers.
fn text_of(key: &str, ur: &str) -> String {
    let (op, sig) = key.split_once('_').unwrap();
    let mut regs = [64, 56, 72, 64, 2, 3].into_iter();
    let ops: Vec<String> = sig
        .split('_')
        .map(|s| match s {
            "R" => format!("R{}", regs.next().unwrap()),
            "UP" => "UP1".to_string(),
            "UR" => ur.to_string(),
            "II" => "0x1".to_string(),
            other => panic!("{key}: operand kind {other}"),
        })
        .collect();
    format!("{op} {}", ops.join(", "))
}

#[test]
fn every_omma_key_round_trips_the_whole_uri_range() {
    let (table, _) = sm120();
    let raw: serde_json::Value =
        serde_json::from_slice(&cubit::table::read_table_bytes(std::path::Path::new("tables/sm120.json")).unwrap()).unwrap();
    let keys: Vec<&String> = raw["instructions"].as_object().unwrap().keys().filter(|k| k.starts_with("OMMA")).collect();
    assert_eq!(keys.len(), 16, "the OMMA keys of sm120.json");
    let _ = table;
    let mut n = 0;
    for key in keys {
        // the split geometry the report asked for is the row's: low three bits at 60, high five at 73
        let fields = raw["instructions"][key]["mod_groups"][""]["fields"].as_array().unwrap();
        let has = |ext: &str, shift: u64, bits: u64| {
            fields.iter().any(|f| f["extraction"] == ext && f["shift"] == shift && f["bits"] == bits)
        };
        assert!(has("ureg", 60, 3) && has("ureg_shr3", 73, 5), "{key}: URi = ureg[62:60] + ureg_shr3[77:73]");
        for ur in (0..64).map(|i| format!("UR{i}")).chain(["URZ".to_string()]) {
            let text = text_of(key, &ur);
            let word = encode(&text);
            let value = if ur == "URZ" { 255 } else { ur[2..].parse::<u128>().unwrap() };
            assert_eq!((word >> 60) & 7, value & 7, "{text}: the low slice");
            assert_eq!((word >> 73) & 31, value >> 3, "{text}: the high slice");
            assert_eq!(decode(word), text, "{word:032x}");
            n += 1;
        }
    }
    assert_eq!(n, 16 * 65);
}

#[test]
fn the_words_nvdisasm_names() {
    // nvdisasm 13.1 -b SM120, 2026-11-10: each word prints the text beside it
    const OP: &str = "OMMA.SF.16864.F32.E2M1.E2M1.UE4M3.4X";
    for (word, ur) in [
        (0x000fc20000040040_003002483840747f_u128, "UR0"),
        (0x000fc20000040040_603002483840747f, "UR6"),
        (0x000fc20000040240_003002483840747f, "UR8"),  // the first value the four-bit field truncated
        (0x000fc20000040240_603002483840747f, "UR14"),
        (0x000fc20000040440_003002483840747f, "UR16"), // the first value it could not hold
        (0x000fc20000040840_003002483840747f, "UR32"),
        (0x000fc20000040e40_703002483840747f, "UR63"), // the architectural register, not the sink
        (0x000fc20000043e40_703002483840747f, "URZ"),
    ] {
        let text = format!("{OP} R64, R56, R72, R64, R2, R3, {ur}");
        assert_eq!(decode(word), text, "{word:032x}");
        assert_eq!(encode(&text) & INSN, word & INSN, "{text}");
    }
    // `.reuse` on the second scale register is bit 51 of the instruction word (the report's missing field)
    let word = 0x000fc20000043e40_703802483840747f_u128;
    let text = format!("{OP} R64, R56, R72, R64, R2, R3.reuse, URZ");
    assert_eq!(decode(word), text);
    assert_eq!(encode(&text) & INSN, word & INSN);
}

#[test]
fn the_reports_system_register_reads() {
    // nvdisasm 13.1 -b SM120, 2026-11-10: plain = bit 80 set, `.32` = bit 80 clear, the register number at [79:72]
    for (word, text) in [
        (0x000fc20000015000_00000000003c7805_u128, "CS2R R60, SR_CLOCKLO"),
        (0x000fc20000005000_00000000003c7805, "CS2R.32 R60, SR_CLOCKLO"),
        (0x000fc20000015200_00000000003c7805, "CS2R R60, SR_GLOBALTIMERLO"),
        (0x000fc20000015000_00000000000478cb, "CS2UR UR4, SR_CLOCKLO"),
        (0x000fc20000015000_00000000000878cb, "CS2UR UR8, SR_CLOCKLO"),
        (0x000fc20000005000_00000000000878cb, "CS2UR.32 UR8, SR_CLOCKLO"),
        (0x000fc20000015100_00000000003f78cb, "CS2UR UR63, SR_CLOCKHI"),
    ] {
        assert_eq!(decode(word), text, "{word:032x}");
        assert_eq!(encode(text) & INSN, word & INSN, "{text}");
    }
}
