//! BUG-224 (F2-iter108, front2/blind, 2026-08-27): sm120 SYNCS base-key
//! lane closure — donor-clone key SYNCS (mg 'CCTL,IVALL') from canonical
//! sm100a (canonical ae6b248).
//!
//! 221 parity residuum (iter107): 8 corpus lines HOLE on sm120, all the
//! SAME word modulo sched ctrl (lo=0x79b1, hi.low32=0 — SYNCS.CCTL.IVALL;
//! 8 sites in libcublasLt.so.539.sm_100a.cubin, 2 kernels; scan224.py
//! re-derives exactly 8/8 over the A/B 2014-corpus). sm100a/103a decode
//! via the base key already (era-2aE row, vm=0); sm120 lacked the base
//! key entirely -> "no instruction matches opcode 0x09b1".
//!
//! Graft law arb224.json (in-place nvdisasm 13.3.73 x3 arch, word
//! transplanted into arrive220_{100a,103a,120a}.cubin site; 92 singles +
//! guard sweep, x3-identical):
//!   b72 = IVALL(0)/WBALL(1) toggle (vendor prints .WBALL);
//!   b73 = opaque enum (1 -> SYNCS.???1.IVALL, vendor-opaque);
//!   b91 = form select (1 -> SYNCS.CCTL.IV [R0+UR0] operandful);
//!   b0..b11 excl. b1 = discriminator (flips -> NOGLYPH / other opcode;
//!   b1 collides into SUQUERY opcode space);
//!   the remaining 77 bits are vendor-INERT (kept fail-closed HOLE in the
//!   tables = donor-parity strictness, cf. 219 policy);
//!   guard [15:12): full predication legal (@P0..@P6/@!P0..@!PT);
//!   sched ctrl upper32 free (era template baked in and_base).
//! Unwitnessed forms (.WBALL / .???1 / .IV [R+UR]) are NOT modeled on any
//! table — 222-class residual. The generic prio-3 sign fallback used to
//! ABSORB b72-flipped words as plain .IVALL with a phantom neg@72 field on
//! ALL tables (wrong glyph vs vendor .WBALL); two src decoder arms
//! (is_memlike sign-gate + is_alu field post-pass, base "SYNCS") close it —
//! uniform fail-closed HOLE pinned x3 in t224_3.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const T120: &str = "tables/sm120.json";
const T103: &str = "tables/sm103a.json";
const T100: &str = "tables/sm100a.json";
const M96: u128 = (1u128 << 96) - 1;
fn tab(p: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(p)).unwrap()
}
fn word(lo: u64, hi: u64) -> u128 {
    ((hi as u128) << 64) | lo as u128
}
/// 103-corpus signature words (scan224 census 8/8; full hi incl. ctrl —
/// decode strips [127:96]). Pre-fix sm120: HOLE; donor tables: alive.
const CORPUS: &[(&str, u64, u64)] = &[
    ("SYNCS.CCTL.IVALL", 0x00000000000079b1, 0x002e640000000000),
    ("SYNCS.CCTL.IVALL", 0x00000000000079b1, 0x001ea40000000000),
    ("SYNCS.CCTL.IVALL", 0x00000000000079b1, 0x001ee40000000000),
];
/// Predicated form (graft guard sweep: full predication legal).
const PRED: &[(&str, u64, u64)] = &[
    (
        "@P0 SYNCS.CCTL.IVALL",
        0x00000000000009b1,
        0x002e640000000000,
    ),
    (
        "@!PT SYNCS.CCTL.IVALL",
        0x000000000000f9b1,
        0x002e640000000000,
    ),
];
/// Unwitnessed vendor-named/operandful forms: uniform fail-closed HOLE on
/// ALL 3 tables via the BUG-224 src arms (222-class residual — do not model
/// without witness; pre-arm state absorbed b72 as junk .IVALL+neg@72).
const NEG: &[(u64, u64)] = &[
    (0x00000000000079b1, 0x002e640000000100), // b72 -> .WBALL (vendor glyph)
    (0x00000000000079b1, 0x002e640000000200), // b73 -> .???1 (vendor-opaque)
    (0x00000000000079b1, 0x002e640008000000), // b91 -> SYNCS.CCTL.IV [R+UR]
];

#[test]
fn t224_1_corpus_decode_ident_x3() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        for (gl, lo, hi) in CORPUS.iter().chain(PRED) {
            let got = idx
                .decode(word(*lo, *hi), 0, &t)
                .map(|d| to_sass(&d))
                .unwrap_or_else(|_| panic!("{tp}: HOLE for witness {gl}"));
            assert_eq!(&got, gl, "{tp}: glyph drift");
        }
    }
}

#[test]
fn t224_2_encode_roundtrip_low96_x3() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let insn = parse_sass("SYNCS.CCTL.IVALL ;", 0).expect("parse");
        let w = encode_instruction(&insn, &t).unwrap_or_else(|_| panic!("{tp}: encode HOLE"));
        assert_eq!(w & M96, 0x79b1, "{tp}: encode drift");
    }
}

#[test]
fn t224_3_unwitnessed_forms_fail_closed_x3() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        for (lo, hi) in NEG {
            assert!(
                idx.decode(word(*lo, *hi), 0, &t).is_err(),
                "{tp}: absorb of unwitnessed form {lo:#x}/{hi:#x}"
            );
        }
    }
}

#[test]
fn t224_4_sched_variants_same_glyph_x3() {
    // Three era-ctrl templates observed in the corpus decode to one glyph;
    // donor-parity x3 (decode strips [127:96]).
    for (gl, lo, hi) in CORPUS {
        let mut outs = Vec::new();
        for tp in [T120, T103, T100] {
            let t = tab(tp);
            let idx = DecodeIndex::build(&t);
            outs.push(
                idx.decode(word(*lo, *hi), 0, &t)
                    .map(|d| to_sass(&d))
                    .unwrap(),
            );
        }
        assert!(outs.iter().all(|o| o == gl), "x3 drift {outs:?}");
    }
}
