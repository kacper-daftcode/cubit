//! BUG-379 (audit, no defect) + BUG-380 (graft) pins (F2-iter202, loop5/blind
//! front2, 2026-09-05): F2I F64-src (byte10=0x30, b76=1) lattice completion,
//! canonical a53eb20. Engine arm BUG-380a (decoder.rs): reuse [124:122]
//! fail-closed on every row of the family (+ the pre-existing 'F64,S64' /
//! F2I.S64.F64_R_R gap).
//!
//! Vendor law (arb380 50 + arb380b 64 + arb380c/c2 33 + arb380d 40 = 187
//! probes, nvdisasm 13.3.73 raw -b, x4 models SM100a/SM103a/SM120/SM121a
//! AGREE on EVERY, DIVERGENT=0):
//!   byte9 = round [79:78] (0 plain / 1 FLOOR / 2 CEIL / 3 TRUNC) + b77 NTZ
//!         + b76=1 + dst-selector (b75,b72): 00 U32 / 01 F64 / 10 U64 / 11
//!         S64; b73/b74 text-inert aliases; EVERY (round x NTZ x dst) cell
//!         legal x4; abs/neg tok2 everywhere; reuse ILLEGAL everywhere.
//! Pre-fix (publish cubit_py-11b78512, canonical 47e4ce4;
//! work/bug379_380/measure_pre379_380.json): 364/384 cells HOLE x4 legs,
//! zero wrong-text; encode of the 22 missing classes loud BUG-132 x4.
//! 379 (A-anchor U64-side alias pred-forms + 0x311 cross-family control):
//! measured 80/80 MATCH x4 = audit-closed, no table delta.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const LEGS4: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
const A380: u128 = 0x0030000000000006001a7311; // F64-src anchor (R26 <- R6)
const SE1: u128 = 0x0020d8000000001a00167311; // A-anchor U64.TRUNC, '@PT'

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec96(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}
fn dec128(t: &IsaTable, raw: u128) -> Result<String, String> {
    let idx = DecodeIndex::build(t);
    idx.decode(raw, 0, t)
        .map(|d| to_sass(&d))
        .map_err(|e| format!("{e}"))
}
fn enc96(t: &IsaTable, text: &str) -> Option<u128> {
    let insn = parse_sass(text, 0).unwrap();
    encode_instruction(&insn, t).ok()
}
const ROUNDS: [(u8, &str); 6] = [
    (0x10, ""),
    (0x30, ".NTZ"),
    (0x50, ".FLOOR"),
    (0x70, ".FLOOR.NTZ"),
    (0x90, ".CEIL"),
    (0xb0, ".CEIL.NTZ"),
];
fn dst_of(n: u8) -> &'static str {
    match n & 0x9 {
        0x0 => "U32.F64",
        0x1 => "F64",
        0x8 => "U64.F64",
        _ => "S64.F64",
    }
}

#[test]
fn t380_1_lattice_decode_vendor_exact_x4() {
    for leg in LEGS4 {
        let t = tab(leg);
        for (rb, rsuf) in ROUNDS {
            for n in 0..16u128 {
                let w = (A380 & !(0xffu128 << 72)) | (((rb as u128) | n) << 72);
                let want = format!("F2I.{}{} R26, R6", dst_of(n as u8), rsuf);
                assert_eq!(
                    dec96(&t, w).as_deref(),
                    Some(want.as_str()),
                    "{leg} round 0x{rb:02x} nibble {n:x}"
                );
            }
        }
    }
}

#[test]
fn t380_2_mint_word_exact_x4() {
    // the 96 lattice mints land on the exact cell word (low 96 bits)
    for leg in LEGS4 {
        let t = tab(leg);
        for (rb, rsuf) in ROUNDS {
            for n in [0u128, 1, 8, 9] {
                let w = (A380 & !(0xffu128 << 72)) | (((rb as u128) | n) << 72);
                let text = format!("F2I.{}{} R26, R6", dst_of(n as u8), rsuf);
                let got = enc96(&t, &text).unwrap_or_else(|| panic!("{leg} mint '{text}'"));
                assert_eq!(got & M96, w, "{leg} mint '{text}' word drift");
            }
        }
    }
}

#[test]
fn t380_3_reuse_arm_fail_closed_x4() {
    // full-128: any reuse bit on the family = loud BUG-380a attributed HOLE
    for leg in LEGS4 {
        let t = tab(leg);
        for (rb, _rsuf) in ROUNDS {
            for n in [1u128, 5] {
                let base = (A380 & !(0xffu128 << 72)) | (((rb as u128) | n) << 72);
                for rbit in [122u32, 124] {
                    let w = base | (1u128 << rbit);
                    let msg = dec128(&t, w).err().unwrap_or_default();
                    assert!(
                        msg.contains("BUG-380") || msg.contains("BUG-362"),
                        "{leg} reuse-armed 0x{w:032x} decoded: {msg}"
                    );
                }
            }
        }
    }
}

#[test]
fn t380_4_sign_window_tok2_vendor_exact() {
    // abs/neg on the new lattice classes incl the grafted plain-S64 fields
    let cases: [(u8, &str, u64, &str); 8] = [
        (0x10, "F2I.U32.F64", 62, "F2I.U32.F64 R26, |R6|"),
        (0x11, "F2I.F64", 63, "F2I.F64 R26, -R6"),
        (0x31, "F2I.F64.NTZ", 62, "F2I.F64.NTZ R26, |R6|"),
        (
            0x78,
            "F2I.U64.F64.FLOOR.NTZ",
            63,
            "F2I.U64.F64.FLOOR.NTZ R26, -R6",
        ),
        (0x91, "F2I.F64.CEIL", 62, "F2I.F64.CEIL R26, |R6|"),
        (
            0xb9,
            "F2I.S64.F64.CEIL.NTZ",
            63,
            "F2I.S64.F64.CEIL.NTZ R26, -R6",
        ),
        // grafted fields on pre-existing plain-S64 rows ('F64,S64' /
        // F2I.S64.F64_R_R): b63/b62-armed cells were HOLE pre-380
        (0x19, "F2I.S64.F64", 63, "F2I.S64.F64 R26, -R6"),
        (0x19, "F2I.S64.F64", 62, "F2I.S64.F64 R26, |R6|"),
    ];
    for leg in LEGS4 {
        let t = tab(leg);
        for (b9, _txt, bit, want) in cases {
            let w = (A380 & !(0xffu128 << 72)) | ((b9 as u128) << 72) | (1u128 << bit);
            assert_eq!(
                dec96(&t, w).as_deref(),
                Some(want),
                "{leg} 0x{b9:02x} b{bit}"
            );
        }
    }
}

#[test]
fn t380_5_pred_roundtrip_and_s64_alias_relax() {
    for leg in LEGS4 {
        let t = tab(leg);
        // pred forms on new cells (guard path is claim-generic)
        let w = (0x0030b1u128 << 72) | (0x000006001a1311u128); // ceilntz f64 + g1
        assert_eq!(
            dec96(&t, w).as_deref(),
            Some("@P1 F2I.F64.CEIL.NTZ R26, R6"),
            "{leg} pred on new cell"
        );
        let got = enc96(&t, "@P1 F2I.F64.CEIL.NTZ R26, R6").unwrap();
        assert_eq!(got & M96, w & M96, "{leg} pred mint word drift");
        // S64 plain alias relax: n in {9,b,d,f} all decode vendor text
        for n in [0x9u128, 0xb, 0xd, 0xf] {
            let w = (A380 & !(0xfu128 << 72)) | (0x10u128 << 72) | (n << 72);
            assert_eq!(
                dec96(&t, w).as_deref(),
                Some("F2I.S64.F64 R26, R6"),
                "{leg} S64 alias nibble {n:x}"
            );
        }
    }
}

#[test]
fn t380_6_390kand_narrow_dst_posture() {
    // b76=0 narrow-dst sub-lattice (vendor-legal 'F2I.S8.F64.FLOOR[.NTZ]',
    // arb380 K probes x4) stays HOLE = fail-closed posture (390-kand)
    for leg in LEGS4 {
        let t = tab(leg);
        for b9 in [0x41u128, 0x61, 0x01, 0x21] {
            let w = (A380 & !(0xffu128 << 72)) | (b9 << 72);
            assert!(dec96(&t, w).is_none(), "{leg} 390-kand cell 0x{b9:02x}");
        }
    }
}

#[test]
fn t379_1_a_anchor_alias_pred_audit_x4() {
    // BUG-379 audit pins (no graft): U64-side alias nibbles (8/a/c/e) under
    // predicates on the A-anchor + S64-side cross-family control
    for leg in LEGS4 {
        let t = tab(leg);
        for n in [0x8u128, 0xa, 0xc, 0xe] {
            for (g, pre) in [(0u128, ""), (1, "@P1 "), (3, "@P3 "), (7, "")] {
                let w = {
                    let mut v = SE1;
                    v &= !(0xfu128 << 72) & !(0xfu128 << 12);
                    v |= (n << 72) | (if g == 0 { 7 } else { g } << 12);
                    v
                };
                let want = format!("{pre}F2I.U64.TRUNC R22, R26");
                assert_eq!(
                    dec96(&t, w).as_deref(),
                    Some(want.as_str()),
                    "{leg} A-anchor n{n:x} g{g}"
                );
            }
        }
        for n in [0x9u128, 0xb, 0xd, 0xf] {
            let w =
                ((SE1 | (1 << 72)) & !(0xfu128 << 72) & !(0xfu128 << 12)) | (n << 72) | (1 << 12);
            assert_eq!(
                dec96(&t, w).as_deref(),
                Some("@P1 F2I.S64.TRUNC R22, R26"),
                "{leg} A-anchor S64 n{n:x} g1"
            );
        }
    }
}

#[test]
fn t379_2_pred_mint_word_exact_x4() {
    let want: u128 = 0x0020d8000000001a00161311;
    for leg in LEGS4 {
        let t = tab(leg);
        let got = enc96(&t, "@P1 F2I.U64.TRUNC R22, R26").unwrap();
        assert_eq!(got & M96, want, "{leg} '@P1 F2I.U64.TRUNC' mint drift");
    }
}
