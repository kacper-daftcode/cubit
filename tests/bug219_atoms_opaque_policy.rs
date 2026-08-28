//! BUG-219 (F2-iter106, front2/blind, 2026-08-27): ATOMS f8c-shape
//! (POPC.INC family, op[91:87)=27) vendor-OPAQUE width bits b73/b74 policy
//! closure — 219-kand LOW out of notes 218 sec.7(b) / 210 sec.6.
//!
//! Measured vendor print law (arb219.json; nvdisasm 13.3.73 in-place graft
//! on probe204a donors, clean same-slot ctrl carry, x100a/x103a/x120a,
//! x dest RZ/R8, x geometries ARI [R8+URZ] / AURI [UR4] / ARURI [UR4+0xc],
//! x imm): b[74:73] is the width-select enum 0..3 for the whole f8c lane.
//!  - op27 POPC.INC: only width 0 is enumerated (".32"); widths 1/2/3 print
//!    "ATOMS.POPC.INC.???1/.???2/.???3" = vendor-opaque (no glyph claim).
//!  - op26 ARRIVE (218-c PARKED lane): width 2 is enumerated (".64"),
//!    widths 0/1/3 print "ATOMS.ARRIVE.???0/.???1/.???3".
//!  - b72 measured INERT x3 arch (vendor prints the plain form); our
//!    decoder absorbs it identically (211C-style parity) — pinned here.
//!  - Exposure census: 478 (atomdb199) + 479 (atoms_all) f8c words, ALL
//!    op27 with b72=b73=b74=0, zero op26 ARRIVE; sources are shipped
//!    cuSOLVER/cuSPARSE sm_100/103 builds only.
//!  - Emission surface: nvcc 13.3 atomicInc lowers to ATOMS.INC (never
//!    POPC.INC); 64-bit shared atomicInc does not exist (compile probe
//!    rejected: "incompatible with parameter of type unsigned int *").
//!
//! POLICY (218 recommendation): vendor-opaque variants stay fail-closed
//! HOLE — authoring invented glyphs for vendor-unnamed widths would need
//! an !rsd-style surface decision (wlasciciel). Zero src/tables delta:
//! pins only.
use cubit::decoder::DecodeIndex;
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

/// Crafted f8c words (arb219.json payload, ctrl region zero).
/// anchor: ATOMS.POPC.INC.32 RZ, [R8+URZ]
const ANCHOR: (u64, u64) = (0x0000000008ff7f8c, 0x000000000d8000ff);
const ANCHOR_GLYPH: &str = "ATOMS.POPC.INC.32 RZ, [R8+URZ]";
/// b72 set (vendor prints plain form; inert)
const B72: (u64, u64) = (0x0000000008ff7f8c, 0x000000000d8001ff);
/// Vendor-opaque POPC variants: must stay fail-closed HOLE.
/// (b73, b74, b73|b74, x dest R8, x [UR4], x [UR4+0xc], x +0x10 imm)
const OPAQUE: &[(u64, u64)] = &[
    (0x0000000008ff7f8c, 0x000000000d8002ff), // b73 -> nv ".???1"
    (0x0000000008ff7f8c, 0x000000000d8004ff), // b74 -> nv ".???2"
    (0x0000000008ff7f8c, 0x000000000d8006ff), // w3  -> nv ".???3"
    (0x0000000008087f8c, 0x000000000d8002ff), // b73 dest R8
    (0x0000000008087f8c, 0x000000000d8004ff), // b74 dest R8
    (0x00000000ffff7f8c, 0x000000000d800204), // b73 [UR4]
    (0x00000000ffff7f8c, 0x000000000d800404), // b74 [UR4]
    (0x00000c00ffff7f8c, 0x000000000d800204), // b73 [UR4+0xc]
    (0x00000c00ffff7f8c, 0x000000000d800404), // b74 [UR4+0xc]
    (0x0000100008ff7f8c, 0x000000000d8002ff), // b73 imm +0x10
];
/// op26 ARRIVE lane (218-c parked): all forms fail-closed today.
const ARRIVE: &[(u64, u64)] = &[
    (0x0000000008ff7f8c, 0x000000000d0000ff), // nv "ATOMS.ARRIVE.???0"
    (0x0000000008ff7f8c, 0x000000000d0002ff), // nv "ATOMS.ARRIVE.???1"
    (0x0000000008ff7f8c, 0x000000000d0004ff), // nv "ATOMS.ARRIVE.64"
    (0x0000000008ff7f8c, 0x000000000d0006ff), // nv "ATOMS.ARRIVE.???3"
];
/// Real corpus anchor WITH live ctrl region (libcusolver sm_103 witness).
const CORPUS_REAL: (u64, u64) = (0x0000000008ff7f8c, 0x0001e2000d8000ff);

#[test]
fn t219_1_opaque_widths_failclosed() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        for (i, (lo, hi)) in OPAQUE.iter().enumerate() {
            assert!(
                idx.decode(word(*lo, *hi), 0, &t).is_err(),
                "{tp}: opaque variant #{i} decoded — vendor-opaque print must stay HOLE"
            );
        }
    }
}

#[test]
fn t219_2_b72_inert_parity() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        let got = idx
            .decode(word(B72.0, B72.1), 0, &t)
            .map(|d| to_sass(&d))
            .unwrap_or_else(|_| panic!("{tp}: b72-inert word must absorb like the anchor"));
        assert_eq!(
            got, ANCHOR_GLYPH,
            "{tp}: b72 inert parity drift vs vendor print"
        );
    }
}

#[test]
fn t219_3_arrive_lane_failclosed() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        for (i, (lo, hi)) in ARRIVE.iter().enumerate() {
            assert!(
                idx.decode(word(*lo, *hi), 0, &t).is_err(),
                "{tp}: ARRIVE variant #{i} decoded — parked lane must stay HOLE"
            );
        }
    }
}

#[test]
fn t219_4_lane_alive_anchor_and_corpus() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        for (lo, hi) in [ANCHOR, CORPUS_REAL] {
            let got = idx
                .decode(word(lo, hi), 0, &t)
                .map(|d| to_sass(&d))
                .unwrap_or_else(|_| panic!("{tp}: lane-alive anchor HOLE"));
            assert_eq!(got, ANCHOR_GLYPH, "{tp}: anchor decode drift");
        }
    }
}
