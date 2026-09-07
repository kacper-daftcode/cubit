//! BUG-403 pins (F2-iter211, loop5/blind front2, 2026-09-06): F2I F64-src
//! (byte10=0x30) WIDE b76=1 TRUNC.NTZ axis donor-closure graft,
//! canonical 2285a05. Engine arm extension (decoder.rs, BUG-380a shape):
//! reuse [124:122] fail-closed on the 4 era mgs + 4 keyed rows.
//!
//! Vendor law (arb403 34 + arb403b 3 = 37 probes, nvdisasm 13.3.73 raw
//! -b, x4 models SM100a/SM103a/SM120/SM121a AGREE on EVERY, DIVERGENT=0):
//!   byte9 cells 0xf0|nib = TRUNC.NTZ wide dst (round=3 @[79:78] + b77
//!   NTZ + b76=1 + dst {b75,b72}: 00 U32 / 01 S32(default) / 10 U64 / 11
//!   S64; b73/b74 text-inert aliases); ALL 16 nibble cells legal x4;
//!   abs/neg tok2 on every dst class (9 probes); guard generic; reuse
//!   [124:122] ILLEGAL rc=1 x4 (4 probes). Controls: wide TRUNC/plain/
//!   NTZ/CEIL.NTZ and the 390 narrow TRUNC.NTZ rows live, unchanged.
//! Pre-fix (publish cubit_py-e55de0b9, canonical a10350c;
//! work/bug403/measure_pre403.json): 64/64 cells HOLE x4 legs + 16/16
//! encode loud-FAIL (t390_7 posture -- flipped in place). sm121a: 8
//! sanctioned tie-pairs (4 new keyed x 2 degenerate HFMA2 FI_FI rows,
//! same class as the 380/390 sanctions; functional proof t403_6).
//! Witness data: work/bug403/pin_wit403.json (machine-built from the arb
//! verdicts by gen403data.py; this file's tables = witness json verbatim).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const LEGS4: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
const A403: u128 = 0x0030000000000006001a7311; // F64-src anchor (R26 <- R6)

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

/// 16-cell law map (byte9 -> vendor text head), arb403 phase A verbatim.
const LATTICE: [(u128, &str); 16] = [
    (0xf0, "F2I.U32.F64.TRUNC.NTZ"),
    (0xf1, "F2I.F64.TRUNC.NTZ"),
    (0xf2, "F2I.U32.F64.TRUNC.NTZ"),
    (0xf3, "F2I.F64.TRUNC.NTZ"),
    (0xf4, "F2I.U32.F64.TRUNC.NTZ"),
    (0xf5, "F2I.F64.TRUNC.NTZ"),
    (0xf6, "F2I.U32.F64.TRUNC.NTZ"),
    (0xf7, "F2I.F64.TRUNC.NTZ"),
    (0xf8, "F2I.U64.F64.TRUNC.NTZ"),
    (0xf9, "F2I.S64.F64.TRUNC.NTZ"),
    (0xfa, "F2I.U64.F64.TRUNC.NTZ"),
    (0xfb, "F2I.S64.F64.TRUNC.NTZ"),
    (0xfc, "F2I.U64.F64.TRUNC.NTZ"),
    (0xfd, "F2I.S64.F64.TRUNC.NTZ"),
    (0xfe, "F2I.U64.F64.TRUNC.NTZ"),
    (0xff, "F2I.S64.F64.TRUNC.NTZ"),
];

#[test]
fn t403_1_axis_decode_vendor_exact_x4() {
    for leg in LEGS4 {
        let t = tab(leg);
        for (b9, head) in LATTICE {
            let w = (A403 & !(0xffu128 << 72)) | (b9 << 72);
            let want = format!("{head} R26, R6");
            assert_eq!(
                dec96(&t, w).as_deref(),
                Some(want.as_str()),
                "{leg} byte9 0x{b9:02x}"
            );
        }
    }
}

#[test]
fn t403_2_mint_word_exact_4_classes_x4() {
    // every dst class mints its base-nibble cell word (alias bits b73/b74
    // baked 0 by graft construction)
    for leg in LEGS4 {
        let t = tab(leg);
        for (b9, head) in LATTICE {
            if b9 & 0x6 != 0 {
                continue; // alias nibbles share the base row
            }
            let w = (A403 & !(0xffu128 << 72)) | (b9 << 72);
            let got = enc96(&t, &format!("{head} R26, R6")).unwrap();
            assert_eq!(got & M96, w & M96, "{leg} mint drift {head}");
        }
    }
}

/// vendor-ILLEGAL reuse words on the wide TRUNC.NTZ axis (arb403 C set
/// verbatim) -- [124:122] refuses x4.
const REUSE_W: [u128; 4] = [
    0x040000000030f10000000006001a7311u128,
    0x080000000030f10000000006001a7311u128,
    0x100000000030f10000000006001a7311u128,
    0x1c0000000030f90000000006001a7311u128,
];

#[test]
fn t403_3_reuse_fail_closed_x4() {
    for leg in LEGS4 {
        let t = tab(leg);
        for w in REUSE_W {
            assert!(dec128(&t, w).is_err(), "{leg} reuse word 0x{w:032x}");
        }
    }
}

/// abs/neg tok2 law samples (arb403 B set verbatim).
const ABSNEG: [(u128, &str); 9] = [
    (
        0x000000000030f00040000006001a7311u128,
        "F2I.U32.F64.TRUNC.NTZ R26, |R6|",
    ),
    (
        0x000000000030f00080000006001a7311u128,
        "F2I.U32.F64.TRUNC.NTZ R26, -R6",
    ),
    (
        0x000000000030f10040000006001a7311u128,
        "F2I.F64.TRUNC.NTZ R26, |R6|",
    ),
    (
        0x000000000030f10080000006001a7311u128,
        "F2I.F64.TRUNC.NTZ R26, -R6",
    ),
    (
        0x000000000030f80040000006001a7311u128,
        "F2I.U64.F64.TRUNC.NTZ R26, |R6|",
    ),
    (
        0x000000000030f80080000006001a7311u128,
        "F2I.U64.F64.TRUNC.NTZ R26, -R6",
    ),
    (
        0x000000000030f90040000006001a7311u128,
        "F2I.S64.F64.TRUNC.NTZ R26, |R6|",
    ),
    (
        0x000000000030f90080000006001a7311u128,
        "F2I.S64.F64.TRUNC.NTZ R26, -R6",
    ),
    (
        0x000000000030f100c0000006001a7311u128,
        "F2I.F64.TRUNC.NTZ R26, -|R6|",
    ),
];

#[test]
fn t403_4_abs_neg_decode_vendor_exact_x4() {
    for leg in LEGS4 {
        let t = tab(leg);
        for (w, want) in ABSNEG {
            assert_eq!(dec96(&t, w).as_deref(), Some(want), "{leg} 0x{w:032x}");
        }
    }
    // abs/neg mint roundtrips through the encoder on class exemplars
    for leg in LEGS4 {
        let t = tab(leg);
        for txt in [
            "F2I.U32.F64.TRUNC.NTZ R26, |R6|",
            "F2I.F64.TRUNC.NTZ R26, -R6",
            "F2I.U64.F64.TRUNC.NTZ R26, |R6|",
            "F2I.S64.F64.TRUNC.NTZ R26, -|R6|",
        ] {
            let w = enc96(&t, txt).unwrap();
            assert_eq!(dec96(&t, w).as_deref(), Some(txt), "{leg} rt {txt}");
        }
    }
}
#[test]
fn t403_5_guard_and_pred_forms_x4() {
    // guard sweep law samples (arb403 D set verbatim)
    for leg in LEGS4 {
        let t = tab(leg);
        assert_eq!(
            dec96(&t, 0x000000000030f10000000006001a7311u128).as_deref(),
            Some("F2I.F64.TRUNC.NTZ R26, R6"),
            "{leg} guard 0x000000000030f10000000006001a7311"
        );
        assert_eq!(
            dec96(&t, 0x000000000030f10000000006001a7311u128).as_deref(),
            Some("F2I.F64.TRUNC.NTZ R26, R6"),
            "{leg} guard 0x000000000030f10000000006001a7311"
        );
    }
    // pred form mint word-exact on one wide TRUNC.NTZ cell per leg
    for leg in LEGS4 {
        let t = tab(leg);
        let txt = "@P1 F2I.F64.TRUNC.NTZ R26, R6";
        let w = enc96(&t, txt).unwrap();
        assert_eq!(dec96(&t, w).as_deref(), Some(txt), "{leg} pred rt");
        let want =
            ((A403 & !(0xffu128 << 72) & !(0xfu128 << 12)) | (0xf1u128 << 72) | (1u128 << 12))
                | w & (3u128 << 96 | 0); // pred mint = cell + g1 (byte0/byte1 verbatim)
        assert_eq!(
            w & !((0xfu128) << 12) & M96,
            want & !((0xfu128) << 12) & M96,
            "{leg} pred mint shape"
        );
    }
}

#[test]
fn t403_6_sm121a_tie_functional_proof() {
    // sm121a sanctioned tie-pairs (8 = 4 wide TRUNC.NTZ keyed x 2
    // degenerate HFMA2 FI_FI rows, patch403_report.json): decode of every
    // axis cell on sm121a resolves to the F2I row vendor-exact (functional
    // assertion backing the mask-level sanction), cross-leg equal text.
    let t121 = tab("sm121a");
    let t103 = tab("sm103a");
    for (b9, head) in LATTICE {
        let w = (A403 & !(0xffu128 << 72)) | (b9 << 72);
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

/// neighbor controls (arb403 E/arb403b set verbatim): wide family axes and
/// the 390 narrow graft unchanged.
const CTRL: [(u128, &str); 6] = [
    (
        0x000000000030d10000000006001a7311u128,
        "F2I.F64.TRUNC R26, R6",
    ),
    (
        0x000000000030a90000000006001a7311u128,
        "F2I.S16.F64.CEIL.NTZ R26, R6",
    ),
    (
        0x000000000030e90000000006001a7311u128,
        "F2I.S16.F64.TRUNC.NTZ R26, R6",
    ),
    (
        0x000000000030b90000000006001a7311u128,
        "F2I.S64.F64.CEIL.NTZ R26, R6",
    ),
    (0x000000000030110000000006001a7311u128, "F2I.F64 R26, R6"),
    (
        0x000000000030300000000006001a7311u128,
        "F2I.U32.F64.NTZ R26, R6",
    ),
];

#[test]
fn t403_7_neighbor_controls_unchanged_x4() {
    for leg in LEGS4 {
        let t = tab(leg);
        for (w, want) in CTRL {
            assert_eq!(dec96(&t, w).as_deref(), Some(want), "{leg} 0x{w:032x}");
        }
    }
}
