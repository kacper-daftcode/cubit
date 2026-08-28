//! BUG-215 (F2-iter106, front2/blind, 2026-08-27): ATOMS EXCH .64
//! WITNESSED closure — 215-kand sondy over the ATOMS .64 legs
//! (MIN/MAX/ADD/INC/EXCH; MIN answered negative in 208).
//!
//! Vendor-emission sondy (work/bug215/probe/u64_215.cu, nvcc 13.3.73,
//! sm_100a/103a/120a, payload byte-identical arch-eq):
//!  - atomicExch(shared u64)  -> ATOMS.EXCH.64 R4, [R5+0x2000], R2  NATIVE
//!  - atomicMax(shared u64/s64) -> ATOMS.CAST.SPIN.64 CAS-loop (negative)
//!  - atomicAdd(shared u64)     -> ATOMS.CAST.SPIN.64 CAS-loop (negative)
//!  - atomicInc(shared u64)     -> no overload (negative, 219-class)
//!
//! Pre-fix (published d99d264): the real EXCH.64 witness was decode-HOLE
//! x3 tables / encode fail-closed; corpus exposure ZERO (0 in 88,663).
//!
//! Fix: donor-clone ATOMS_R_ARI_R['EXCH'] (bug204) -> '64,EXCH' with
//! ab^=(1<<74), vm inherited (patch215.py replayable+idempotent, 3 rows,
//! _src bug215). Width-3 (b73|b74) stays fail-closed (vendor .INVALID3).
//! (glyph, lo, hi)
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

const W64: (&str, u64, u64) = (
    "ATOMS.EXCH.64 R4, [R5+0x2000], R2",
    0x002000020504738c,
    0x004e680004000400,
);
const BARE: &[(&str, u64, u64)] = &[
    (
        "ATOMS.EXCH R7, [R0+0x200], R3",
        0x000200030007738c,
        0x004e280004000000,
    ),
    (
        "ATOMS.EXCH R9, [R0+0x100], R5",
        0x000100050009738c,
        0x008e280004000000,
    ),
];

#[test]
fn t215_1_exch64_witness_decode_ident() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        let got = idx
            .decode(word(W64.1, W64.2), 0, &t)
            .map(|d| to_sass(&d))
            .unwrap_or_else(|_| panic!("{tp}: EXCH.64 witness HOLE — fix missing"));
        assert_eq!(got, W64.0, "{tp}: EXCH.64 witness drift");
    }
}

#[test]
fn t215_2_exch64_encode_roundtrip_low96() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let insn = parse_sass(&format!("{} ;", W64.0), 0).expect("parse");
        let w = encode_instruction(&insn, &t)
            .unwrap_or_else(|_| panic!("{tp}: encode HOLE for EXCH.64"));
        assert_eq!(w & M96, word(W64.1, W64.2) & M96, "{tp}: encode drift");
    }
}

#[test]
fn t215_3_bare_lane_untouched() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        for (gl, lo, hi) in BARE {
            let got = idx
                .decode(word(*lo, *hi), 0, &t)
                .map(|d| to_sass(&d))
                .unwrap_or_else(|_| panic!("{tp}: bare witness HOLE for {gl}"));
            assert_eq!(&got, gl, "{tp}: bare drift");
            let insn = parse_sass(&format!("{gl} ;"), 0).expect("parse");
            let w = encode_instruction(&insn, &t).expect("encode bare");
            assert_eq!(w & M96, word(*lo, *hi) & M96, "{tp}: bare encode drift");
        }
    }
}

#[test]
fn t215_4_width3_stays_failclosed_and_no_bare_absorb() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        // width-3 (b73|b74) on the real witness: vendor .INVALID3 -> our HOLE.
        let w3 = word(W64.1, W64.2) | (1u128 << 73);
        assert!(
            idx.decode(w3, 0, &t).is_err(),
            "{tp}: width-3 must stay HOLE"
        );
        // bare-lane round-trip is pinned by t215_3; here one extra guard:
        // the .64 clone must NOT swallow the canonical bare witness words.
        for (gl, lo, hi) in BARE {
            let got = idx.decode(word(*lo, *hi), 0, &t).expect("bare decodes");
            assert_eq!(&to_sass(&got), gl, "{tp}: bare absorbed by the .64 clone");
        }
    }
}
