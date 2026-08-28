//! BUG-209 (F2-iter106, front2/blind, 2026-08-27): REDG vec-f16 SCOPED
//! lane closure — 209-kand out of note 206 sec.6 ("vec-f16 RED scoped
//! SM/SYS — ptxas cordon").
//!
//! Measured facts:
//!  - ptxas 13.3.73 CORDON (work/bug209/probe/redvec209.cu):
//!    `red.relaxed.{sys,cta}.global.add.noftz.v{2,4,8}.f16` all rejected
//!    ("Arguments mismatch for instruction 'red'", 4/4 forms), while the
//!    SCALAR f16x2/bf16x2 scoped forms compile (probe206a witnesses);
//!  - vendor DISASSEMBLER accepts the scoped vec forms: b78 toggle on the
//!    F16x4/F16x8 GPU anchors prints `REDG.E.ADD.F16x{4,8}.RN.STRONG.SM`
//!    on all 3 arch containers (arb209.json); the SYS xor-delta from the
//!    F16x2 pair does NOT transfer — vec x4/x8 scope+space enum [80:77]
//!    is non-orthogonal (SYS-id falls onto the CONSTANT.CTA family), so
//!    no scoped-SYS vec print exists via the scalar law;
//!  - ZERO corpus exposure: no `RED.*F16` glyph in 88,663 records;
//!  - our state: decode of the crafted scoped words = HOLE fail-closed
//!    x3 tables (12/12); encode of the scoped glyph texts = fail-closed
//!    (REDG_dARI_R scoped rows absent); GPU/F16x2-scoped witnesses decode
//!    IDENT and encode round-trips to the nvcc words.
//!
//! POLICY (207-class): vendor-legal-but-unwitnessable lanes stay
//! fail-closed; modeling = "osobny gate swiadkow" owner decision.
//! Zero src/tables delta: pins only.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const T120: &str = "tables/sm120.json";
const T103: &str = "tables/sm103a.json";
const T100: &str = "tables/sm100a.json";
fn tab(p: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(p)).unwrap()
}
fn word(lo: u64, hi: u64) -> u128 {
    ((hi as u128) << 64) | lo as u128
}
const M96: u128 = (1u128 << 96) - 1;
const B78: u128 = 1u128 << 78; // GPU -> SM scope toggle on this lane (witness-derived)

/// Real nvcc witnesses. (glyph, lo, hi)
const WIT: &[(&str, u64, u64)] = &[
    (
        "REDG.E.ADD.F16x2.RN.STRONG.SM desc[UR4][R2.64], R5",
        0x00000005020079a6,
        0x001fe2000c12a104,
    ),
    (
        "REDG.E.ADD.F16x2.RN.STRONG.SYS desc[UR4][R2.64], R5",
        0x00000005020079a6,
        0x001fe2000c134104,
    ),
    (
        "REDG.E.ADD.BF16x2.RN.STRONG.SM desc[UR4][R2.64], R5",
        0x00000005020079a6,
        0x001fe2000c12a704,
    ),
    (
        "REDG.E.ADD.BF16x2.RN.STRONG.SYS desc[UR4][R2.64], R5",
        0x00000005020079a6,
        0x001fe2000c134704,
    ),
    (
        "REDG.E.ADD.F16x4.RN.STRONG.GPU desc[UR4][R2.64], R6",
        0x00000006020079a6,
        0x002fe8000c12e304,
    ),
    (
        "REDG.E.ADD.F16x8.RN.STRONG.GPU desc[UR4][R2.64], R4",
        0x00000004020079a6,
        0x002fe2000c12e504,
    ),
];
/// Crafted scoped vec words (b78 toggle of the GPU anchors) — nvdisasm
/// prints them as STRONG.SM on all 3 arch; they must stay HOLE for us.
const VEC_SM: &[u64; 2] = &[0x00000006020079a6, 0x00000004020079a6];
const VEC_SM_HI: &[u64; 2] = &[0x002fe8000c12e304, 0x002fe2000c12e504];

#[test]
fn t209_1_witnesses_alive_decode_ident() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        for (gl, lo, hi) in WIT {
            let got = idx
                .decode(word(*lo, *hi), 0, &t)
                .map(|d| to_sass(&d))
                .unwrap_or_else(|_| panic!("{tp}: witness HOLE for {gl}"));
            assert_eq!(&got, gl, "{tp}: witness decode drift");
        }
    }
}

#[test]
fn t209_2_scoped_vec_decode_failclosed() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        for (i, (lo, hi)) in VEC_SM.iter().zip(VEC_SM_HI.iter()).enumerate() {
            let w = word(*lo, *hi) ^ B78;
            assert!(
                idx.decode(w, 0, &t).is_err(),
                "{tp}: scoped vec-f16 word #{i} decoded — cordon lane must stay HOLE"
            );
        }
    }
}

#[test]
fn t209_3_encode_boundary_and_witness_roundtrip() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        for gl in [
            "REDG.E.ADD.F16x4.RN.STRONG.SM desc[UR4][R2.64], R6",
            "REDG.E.ADD.F16x8.RN.STRONG.SM desc[UR4][R2.64], R4",
        ] {
            let insn = parse_sass(&format!("{gl} ;"), 0).expect("parser accepts");
            assert!(
                encode_instruction(&insn, &t).is_err(),
                "{tp}: scoped vec-f16 encode must stay fail-closed"
            );
        }
        for (gl, lo, hi) in [WIT[0], WIT[4]] {
            let insn = parse_sass(&format!("{gl} ;"), 0).expect("parse witness");
            let w = encode_instruction(&insn, &t)
                .unwrap_or_else(|_| panic!("{tp}: witness encode HOLE for {gl}"));
            assert_eq!(w & M96, word(lo, hi) & M96, "{tp}: witness encode drift");
        }
    }
}
