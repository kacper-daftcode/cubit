//! BUG-390 pins (F2-iter210, loop5/blind front2, 2026-09-06): F2I F64-src
//! (byte10=0x30) b76=0 NARROW-dst sub-lattice graft, canonical a10350c.
//! Engine arm extension (decoder.rs, BUG-380a shape): reuse [124:122]
//! fail-closed on every narrow row of the family (32 era mgs + 32 keyed).
//!
//! Vendor law (arb390 147 + arb390b 52 = 199 probes, nvdisasm 13.3.73 raw
//! -b, x4 models SM100a/SM103a/SM120/SM121a AGREE on EVERY, DIVERGENT=0):
//!   byte9 = round [79:78] (0 plain / 1 FLOOR / 2 CEIL / 3 TRUNC) + b77 NTZ
//!         + b76=0 + dst-selector {b75,b72}: 00 U8 / 01 S8 / 10 U16 / 11
//!         S16; b73/b74 text-inert aliases; EVERY (round x NTZ x dst) cell
//!         legal x4 (128-cell sweep); abs/neg tok2 everywhere (28 probes);
//!         guard generic; reuse [124:122] ILLEGAL (26 probes rc=1 x4).
//! Pre-fix (publish cubit_py-0925480d, canonical bacdfb5;
//! work/bug390/measure_pre390.json): 512/512 cells HOLE x4 legs +
//! 128/128 encode loud-FAIL (t380_6 posture -- flipped t380_6 in place).
//! Corpus census390 (34,087,886 words ab240): the byte10=0x30/b76=0
//! bucket (12,797 words) is LDL-shaped, claimed by LDL rows (sample390
//! x40 vendor rc=1/FLO.U32 = pre-existing out-of-class register); no
//! F2I-anchor-shaped b76=0 corpus word -> graft corpus-invisible.
//! Witness data: work/bug390/pin_wit390.json (machine-built from the arb
//! verdicts by gen390data.py; this file's tables = witness json verbatim).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const LEGS4: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
const A390: u128 = 0x0030000000000006001a7311; // F64-src anchor (R26 <- R6)

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

/// 128-cell law map (byte9 -> vendor text), arb390 phase A verbatim.
const LATTICE: [(u128, &str); 128] = [
    (0x00, "F2I.U8.F64"),
    (0x01, "F2I.S8.F64"),
    (0x02, "F2I.U8.F64"),
    (0x03, "F2I.S8.F64"),
    (0x04, "F2I.U8.F64"),
    (0x05, "F2I.S8.F64"),
    (0x06, "F2I.U8.F64"),
    (0x07, "F2I.S8.F64"),
    (0x08, "F2I.U16.F64"),
    (0x09, "F2I.S16.F64"),
    (0x0a, "F2I.U16.F64"),
    (0x0b, "F2I.S16.F64"),
    (0x0c, "F2I.U16.F64"),
    (0x0d, "F2I.S16.F64"),
    (0x0e, "F2I.U16.F64"),
    (0x0f, "F2I.S16.F64"),
    (0x20, "F2I.U8.F64.NTZ"),
    (0x21, "F2I.S8.F64.NTZ"),
    (0x22, "F2I.U8.F64.NTZ"),
    (0x23, "F2I.S8.F64.NTZ"),
    (0x24, "F2I.U8.F64.NTZ"),
    (0x25, "F2I.S8.F64.NTZ"),
    (0x26, "F2I.U8.F64.NTZ"),
    (0x27, "F2I.S8.F64.NTZ"),
    (0x28, "F2I.U16.F64.NTZ"),
    (0x29, "F2I.S16.F64.NTZ"),
    (0x2a, "F2I.U16.F64.NTZ"),
    (0x2b, "F2I.S16.F64.NTZ"),
    (0x2c, "F2I.U16.F64.NTZ"),
    (0x2d, "F2I.S16.F64.NTZ"),
    (0x2e, "F2I.U16.F64.NTZ"),
    (0x2f, "F2I.S16.F64.NTZ"),
    (0x40, "F2I.U8.F64.FLOOR"),
    (0x41, "F2I.S8.F64.FLOOR"),
    (0x42, "F2I.U8.F64.FLOOR"),
    (0x43, "F2I.S8.F64.FLOOR"),
    (0x44, "F2I.U8.F64.FLOOR"),
    (0x45, "F2I.S8.F64.FLOOR"),
    (0x46, "F2I.U8.F64.FLOOR"),
    (0x47, "F2I.S8.F64.FLOOR"),
    (0x48, "F2I.U16.F64.FLOOR"),
    (0x49, "F2I.S16.F64.FLOOR"),
    (0x4a, "F2I.U16.F64.FLOOR"),
    (0x4b, "F2I.S16.F64.FLOOR"),
    (0x4c, "F2I.U16.F64.FLOOR"),
    (0x4d, "F2I.S16.F64.FLOOR"),
    (0x4e, "F2I.U16.F64.FLOOR"),
    (0x4f, "F2I.S16.F64.FLOOR"),
    (0x60, "F2I.U8.F64.FLOOR.NTZ"),
    (0x61, "F2I.S8.F64.FLOOR.NTZ"),
    (0x62, "F2I.U8.F64.FLOOR.NTZ"),
    (0x63, "F2I.S8.F64.FLOOR.NTZ"),
    (0x64, "F2I.U8.F64.FLOOR.NTZ"),
    (0x65, "F2I.S8.F64.FLOOR.NTZ"),
    (0x66, "F2I.U8.F64.FLOOR.NTZ"),
    (0x67, "F2I.S8.F64.FLOOR.NTZ"),
    (0x68, "F2I.U16.F64.FLOOR.NTZ"),
    (0x69, "F2I.S16.F64.FLOOR.NTZ"),
    (0x6a, "F2I.U16.F64.FLOOR.NTZ"),
    (0x6b, "F2I.S16.F64.FLOOR.NTZ"),
    (0x6c, "F2I.U16.F64.FLOOR.NTZ"),
    (0x6d, "F2I.S16.F64.FLOOR.NTZ"),
    (0x6e, "F2I.U16.F64.FLOOR.NTZ"),
    (0x6f, "F2I.S16.F64.FLOOR.NTZ"),
    (0x80, "F2I.U8.F64.CEIL"),
    (0x81, "F2I.S8.F64.CEIL"),
    (0x82, "F2I.U8.F64.CEIL"),
    (0x83, "F2I.S8.F64.CEIL"),
    (0x84, "F2I.U8.F64.CEIL"),
    (0x85, "F2I.S8.F64.CEIL"),
    (0x86, "F2I.U8.F64.CEIL"),
    (0x87, "F2I.S8.F64.CEIL"),
    (0x88, "F2I.U16.F64.CEIL"),
    (0x89, "F2I.S16.F64.CEIL"),
    (0x8a, "F2I.U16.F64.CEIL"),
    (0x8b, "F2I.S16.F64.CEIL"),
    (0x8c, "F2I.U16.F64.CEIL"),
    (0x8d, "F2I.S16.F64.CEIL"),
    (0x8e, "F2I.U16.F64.CEIL"),
    (0x8f, "F2I.S16.F64.CEIL"),
    (0xa0, "F2I.U8.F64.CEIL.NTZ"),
    (0xa1, "F2I.S8.F64.CEIL.NTZ"),
    (0xa2, "F2I.U8.F64.CEIL.NTZ"),
    (0xa3, "F2I.S8.F64.CEIL.NTZ"),
    (0xa4, "F2I.U8.F64.CEIL.NTZ"),
    (0xa5, "F2I.S8.F64.CEIL.NTZ"),
    (0xa6, "F2I.U8.F64.CEIL.NTZ"),
    (0xa7, "F2I.S8.F64.CEIL.NTZ"),
    (0xa8, "F2I.U16.F64.CEIL.NTZ"),
    (0xa9, "F2I.S16.F64.CEIL.NTZ"),
    (0xaa, "F2I.U16.F64.CEIL.NTZ"),
    (0xab, "F2I.S16.F64.CEIL.NTZ"),
    (0xac, "F2I.U16.F64.CEIL.NTZ"),
    (0xad, "F2I.S16.F64.CEIL.NTZ"),
    (0xae, "F2I.U16.F64.CEIL.NTZ"),
    (0xaf, "F2I.S16.F64.CEIL.NTZ"),
    (0xc0, "F2I.U8.F64.TRUNC"),
    (0xc1, "F2I.S8.F64.TRUNC"),
    (0xc2, "F2I.U8.F64.TRUNC"),
    (0xc3, "F2I.S8.F64.TRUNC"),
    (0xc4, "F2I.U8.F64.TRUNC"),
    (0xc5, "F2I.S8.F64.TRUNC"),
    (0xc6, "F2I.U8.F64.TRUNC"),
    (0xc7, "F2I.S8.F64.TRUNC"),
    (0xc8, "F2I.U16.F64.TRUNC"),
    (0xc9, "F2I.S16.F64.TRUNC"),
    (0xca, "F2I.U16.F64.TRUNC"),
    (0xcb, "F2I.S16.F64.TRUNC"),
    (0xcc, "F2I.U16.F64.TRUNC"),
    (0xcd, "F2I.S16.F64.TRUNC"),
    (0xce, "F2I.U16.F64.TRUNC"),
    (0xcf, "F2I.S16.F64.TRUNC"),
    (0xe0, "F2I.U8.F64.TRUNC.NTZ"),
    (0xe1, "F2I.S8.F64.TRUNC.NTZ"),
    (0xe2, "F2I.U8.F64.TRUNC.NTZ"),
    (0xe3, "F2I.S8.F64.TRUNC.NTZ"),
    (0xe4, "F2I.U8.F64.TRUNC.NTZ"),
    (0xe5, "F2I.S8.F64.TRUNC.NTZ"),
    (0xe6, "F2I.U8.F64.TRUNC.NTZ"),
    (0xe7, "F2I.S8.F64.TRUNC.NTZ"),
    (0xe8, "F2I.U16.F64.TRUNC.NTZ"),
    (0xe9, "F2I.S16.F64.TRUNC.NTZ"),
    (0xea, "F2I.U16.F64.TRUNC.NTZ"),
    (0xeb, "F2I.S16.F64.TRUNC.NTZ"),
    (0xec, "F2I.U16.F64.TRUNC.NTZ"),
    (0xed, "F2I.S16.F64.TRUNC.NTZ"),
    (0xee, "F2I.U16.F64.TRUNC.NTZ"),
    (0xef, "F2I.S16.F64.TRUNC.NTZ"),
];

#[test]
fn t390_1_lattice_decode_vendor_exact_x4() {
    for leg in LEGS4 {
        let t = tab(leg);
        for (b9, head) in LATTICE {
            let w = (A390 & !(0xffu128 << 72)) | (b9 << 72);
            let want = format!("{head} R26, R6");
            assert_eq!(
                dec96(&t, w).as_deref(),
                Some(want.as_str()),
                "{leg} byte9 0x{b9:02x}"
            );
        }
    }
}

fn dst_of(n: u8) -> &'static str {
    match n & 0x9 {
        0x0 => "U8",
        0x1 => "S8",
        0x8 => "U16",
        _ => "S16",
    }
}

#[test]
fn t390_2_mint_word_exact_32_classes_x4() {
    // every (round x NTZ x dst) class mints its base-nibble cell word
    // (alias bits b73/b74 baked 0 by graft construction); iterate the law
    // table directly (b9 values are sparse across the [79:72] window).
    for leg in LEGS4 {
        let t = tab(leg);
        for (b9, head) in LATTICE {
            if b9 & 0x6 != 0 {
                continue; // alias nibbles share the base row
            }
            let w = (A390 & !(0xffu128 << 72)) | (b9 << 72);
            let got = enc96(&t, &format!("{head} R26, R6")).unwrap();
            assert_eq!(got & M96, w & M96, "{leg} mint drift {head}");
        }
    }
}

/// vendor-ILLEGAL reuse words on the narrow family (arb390 B + arb390b
/// A/C sets verbatim, dedup) -- every bit of [124:122] refuses x4.
const REUSE_W: [u128; 26] = [
    0x040000000030010000000006001a7311u128,
    0x040000000030210000000006001a7311u128,
    0x040000000030410000000006001a7311u128,
    0x040000000030610000000006001a7311u128,
    0x040000000030810000000006001a7311u128,
    0x040000000030a10000000006001a7311u128,
    0x040000000030c10000000006001a7311u128,
    0x040000000030c90000000006001a7311u128,
    0x040000000030e10000000006001a7311u128,
    0x080000000030010000000006001a7311u128,
    0x080000000030210000000006001a7311u128,
    0x080000000030410000000006001a7311u128,
    0x080000000030610000000006001a7311u128,
    0x080000000030810000000006001a7311u128,
    0x080000000030a10000000006001a7311u128,
    0x080000000030c10000000006001a7311u128,
    0x080000000030e10000000006001a7311u128,
    0x100000000030010000000006001a7311u128,
    0x100000000030210000000006001a7311u128,
    0x100000000030410000000006001a7311u128,
    0x100000000030610000000006001a7311u128,
    0x100000000030810000000006001a7311u128,
    0x100000000030a10000000006001a7311u128,
    0x100000000030c10000000006001a7311u128,
    0x100000000030c90000000006001a7311u128,
    0x100000000030e10000000006001a7311u128,
];

#[test]
fn t390_3_reuse_fail_closed_x4() {
    for leg in LEGS4 {
        let t = tab(leg);
        for w in REUSE_W {
            assert!(dec128(&t, w).is_err(), "{leg} reuse word 0x{w:032x}");
        }
    }
}

/// abs/neg tok2 law samples (arb390 B-set + arb390b B/C sets verbatim).
const ABSNEG: [(u128, &str); 30] = [
    (
        0x000000000030400040000006001a7311u128,
        "F2I.U8.F64.FLOOR R26, |R6|",
    ),
    (
        0x000000000030400080000006001a7311u128,
        "F2I.U8.F64.FLOOR R26, -R6",
    ),
    (
        0x0000000000304000c0000006001a7311u128,
        "F2I.U8.F64.FLOOR R26, -|R6|",
    ),
    (
        0x000000000030410040000006001a7311u128,
        "F2I.S8.F64.FLOOR R26, |R6|",
    ),
    (
        0x000000000030410080000006001a7311u128,
        "F2I.S8.F64.FLOOR R26, -R6",
    ),
    (
        0x0000000000304100c0000006001a7311u128,
        "F2I.S8.F64.FLOOR R26, -|R6|",
    ),
    (
        0x000000000030480040000006001a7311u128,
        "F2I.U16.F64.FLOOR R26, |R6|",
    ),
    (
        0x000000000030480080000006001a7311u128,
        "F2I.U16.F64.FLOOR R26, -R6",
    ),
    (
        0x0000000000304800c0000006001a7311u128,
        "F2I.U16.F64.FLOOR R26, -|R6|",
    ),
    (
        0x000000000030490040000006001a7311u128,
        "F2I.S16.F64.FLOOR R26, |R6|",
    ),
    (
        0x000000000030490080000006001a7311u128,
        "F2I.S16.F64.FLOOR R26, -R6",
    ),
    (
        0x0000000000304900c0000006001a7311u128,
        "F2I.S16.F64.FLOOR R26, -|R6|",
    ),
    (
        0x000000000030010040000006001a7311u128,
        "F2I.S8.F64 R26, |R6|",
    ),
    (
        0x000000000030010080000006001a7311u128,
        "F2I.S8.F64 R26, -R6",
    ),
    (
        0x000000000030210040000006001a7311u128,
        "F2I.S8.F64.NTZ R26, |R6|",
    ),
    (
        0x000000000030210080000006001a7311u128,
        "F2I.S8.F64.NTZ R26, -R6",
    ),
    (
        0x000000000030410040000006001a7311u128,
        "F2I.S8.F64.FLOOR R26, |R6|",
    ),
    (
        0x000000000030410080000006001a7311u128,
        "F2I.S8.F64.FLOOR R26, -R6",
    ),
    (
        0x000000000030610040000006001a7311u128,
        "F2I.S8.F64.FLOOR.NTZ R26, |R6|",
    ),
    (
        0x000000000030610080000006001a7311u128,
        "F2I.S8.F64.FLOOR.NTZ R26, -R6",
    ),
    (
        0x000000000030810040000006001a7311u128,
        "F2I.S8.F64.CEIL R26, |R6|",
    ),
    (
        0x000000000030810080000006001a7311u128,
        "F2I.S8.F64.CEIL R26, -R6",
    ),
    (
        0x000000000030a10040000006001a7311u128,
        "F2I.S8.F64.CEIL.NTZ R26, |R6|",
    ),
    (
        0x000000000030a10080000006001a7311u128,
        "F2I.S8.F64.CEIL.NTZ R26, -R6",
    ),
    (
        0x000000000030c10040000006001a7311u128,
        "F2I.S8.F64.TRUNC R26, |R6|",
    ),
    (
        0x000000000030c10080000006001a7311u128,
        "F2I.S8.F64.TRUNC R26, -R6",
    ),
    (
        0x000000000030e10040000006001a7311u128,
        "F2I.S8.F64.TRUNC.NTZ R26, |R6|",
    ),
    (
        0x000000000030e10080000006001a7311u128,
        "F2I.S8.F64.TRUNC.NTZ R26, -R6",
    ),
    (
        0x000000000030c90040000006001a7311u128,
        "F2I.S16.F64.TRUNC R26, |R6|",
    ),
    (
        0x000000000030c90080000006001a7311u128,
        "F2I.S16.F64.TRUNC R26, -R6",
    ),
];

#[test]
fn t390_4_abs_neg_decode_vendor_exact_x4() {
    for leg in LEGS4 {
        let t = tab(leg);
        for (w, want) in ABSNEG {
            assert_eq!(dec96(&t, w).as_deref(), Some(want), "{leg} 0x{w:032x}");
        }
    }
    // abs/neg mint roundtrips through the encoder on each axis exemplar
    for leg in LEGS4 {
        let t = tab(leg);
        for txt in [
            "F2I.S8.F64 R26, |R6|",
            "F2I.S8.F64 R26, -R6",
            "F2I.S8.F64.FLOOR.NTZ R26, -|R6|",
            "F2I.U16.F64.TRUNC R26, |R6|",
            "F2I.S16.F64.TRUNC R26, -R6",
        ] {
            let w = enc96(&t, txt).unwrap();
            assert_eq!(dec96(&t, w).as_deref(), Some(txt), "{leg} rt {txt}");
        }
    }
}

#[test]
fn t390_5_guard_and_pred_forms_x4() {
    // guard sweep law samples (arb390/390b verbatim)
    for leg in LEGS4 {
        let t = tab(leg);
        assert_eq!(
            dec96(&t, 0x000000000030410000000006001a7311u128).as_deref(),
            Some("F2I.S8.F64.FLOOR R26, R6"),
            "{leg} guard 0x000000000030410000000006001a7311"
        );
        assert_eq!(
            dec96(&t, 0x000000000030410000000006001a7311u128).as_deref(),
            Some("F2I.S8.F64.FLOOR R26, R6"),
            "{leg} guard 0x000000000030410000000006001a7311"
        );
        assert_eq!(
            dec96(&t, 0x000000000030410000000006001a7311u128).as_deref(),
            Some("F2I.S8.F64.FLOOR R26, R6"),
            "{leg} guard 0x000000000030410000000006001a7311"
        );
        assert_eq!(
            dec96(&t, 0x000000000030410000000006001a7311u128).as_deref(),
            Some("F2I.S8.F64.FLOOR R26, R6"),
            "{leg} guard 0x000000000030410000000006001a7311"
        );
        assert_eq!(
            dec96(&t, 0x000000000030080000000006001a7311u128).as_deref(),
            Some("F2I.U16.F64 R26, R6"),
            "{leg} guard 0x000000000030080000000006001a7311"
        );
        assert_eq!(
            dec96(&t, 0x000000000030810000000006001a7311u128).as_deref(),
            Some("F2I.S8.F64.CEIL R26, R6"),
            "{leg} guard 0x000000000030810000000006001a7311"
        );
        assert_eq!(
            dec96(&t, 0x000000000030080000000006001a7311u128).as_deref(),
            Some("F2I.U16.F64 R26, R6"),
            "{leg} guard 0x000000000030080000000006001a7311"
        );
        assert_eq!(
            dec96(&t, 0x000000000030810000000006001a7311u128).as_deref(),
            Some("F2I.S8.F64.CEIL R26, R6"),
            "{leg} guard 0x000000000030810000000006001a7311"
        );
    }
    // pred form mint word-exact on one cell per leg (guard claim-generic)
    for leg in LEGS4 {
        let t = tab(leg);
        let txt = "@P1 F2I.S8.F64.CEIL.NTZ R26, R6";
        let w = enc96(&t, txt).unwrap();
        assert_eq!(dec96(&t, w).as_deref(), Some(txt), "{leg} pred rt");
        let want =
            ((A390 & !(0xffu128 << 72) & !(0xfu128 << 12)) | (0xa1u128 << 72) | (1u128 << 12))
                | w & (3u128 << 96 | 0); // pred mint = cell + g1 (byte0/byte1 verbatim)
        assert_eq!(
            w & !((0xfu128) << 12) & M96,
            want & !((0xfu128) << 12) & M96,
            "{leg} pred mint shape"
        );
    }
}

#[test]
fn t390_6_sm121a_tie_functional_proof() {
    // sm121a sanctioned tie-pairs (64 = 32 narrow x 2 degenerate HFMA2
    // FI_FI rows, patch390_report.json): decode of every lattice cell on
    // sm121a resolves to the F2I row vendor-exact (functional assertion
    // backing the mask-level sanction), cross-leg equal text.
    let t121 = tab("sm121a");
    let t103 = tab("sm103a");
    for (b9, head) in LATTICE {
        let w = (A390 & !(0xffu128 << 72)) | (b9 << 72);
        let want = format!("{head} R26, R6");
        assert_eq!(
            dec96(&t121, w).as_deref(),
            Some(want.as_str()),
            "sm121a tie cell 0x{b9:02x}"
        );
        assert_eq!(
            dec96(&t121, w).as_deref(),
            dec96(&t103, w).as_deref(),
            "cross-leg 0x{b9:02x}"
        );
    }
}

#[test]
fn t390_7_wide_side_and_illegal_doctrines_stand() {
    // FLIP (BUG-403, F2-iter211, canonical 2285a05): the WIDE b76=1 F64-src
    // TRUNC.NTZ axis is grafted (donor-clone of the wide TRUNC donors,
    // byte9 0xd0|nib -> 0xf0|nib; arb403+arb403b 37 probes x4 AGREE).
    // Full law pins: tests/bug403_f2i_wide_trunc_ntz.rs; here the former
    // posture cell pins the positive decode vendor-exact.
    for leg in LEGS4 {
        let t = tab(leg);
        assert_eq!(
            dec96(&t, 0x0030000000000006001a7311u128 | (0xf0u128 << 72)).as_deref(),
            Some("F2I.U32.F64.TRUNC.NTZ R26, R6"),
            "{leg} ex-403-kand wide TRUNC.NTZ cell"
        );
    }
    // b76=1 wide lattice unchanged (arb390b E controls verbatim)
    for leg in LEGS4 {
        let t = tab(leg);
        assert_eq!(
            dec96(&t, 0x000000000030510000000006001a7311u128).as_deref(),
            Some("F2I.F64.FLOOR R26, R6"),
            "{leg} wide ctrl 0x000000000030510000000006001a7311"
        );
    }
    for leg in LEGS4 {
        let t = tab(leg);
        assert_eq!(
            dec96(&t, 0x000000000030790000000006001a7311u128).as_deref(),
            Some("F2I.S64.F64.FLOOR.NTZ R26, R6"),
            "{leg} wide ctrl 0x000000000030790000000006001a7311"
        );
    }
    for leg in LEGS4 {
        let t = tab(leg);
        assert_eq!(
            dec96(&t, 0x000000000030180000000006001a7311u128).as_deref(),
            Some("F2I.U64.F64 R26, R6"),
            "{leg} wide ctrl 0x000000000030180000000006001a7311"
        );
    }
    // t380_6's four posture cells are now positive (flipped in place in
    // bug379_380_f2i_f64src_lattice.rs with BUG-390 attribution)
}
