//! BUG-207 (F2-iter106, front2/blind, 2026-08-27): generic-ATOM int lane
//! b76 ADDRESS-FORM law closure — 207-kand LOW out of note 205 sec.6(d)
//! ("forma [Rx.64+URn] b76 ATOM-generyczny, sonder swiadkow").
//!
//! Measured vendor law (arb205 walk, re-verified per-arch in arb207.json
//! on probe205a donors x100a/x103a/x120a; xor-toggle from the b76=1 desc
//! anchors; 12 anchors x3 arch):
//!  - b76=1 -> `desc[URn][Rx.64]` form (the only nvcc-emitted / corpus form),
//!  - b76=0 -> `[Rx.64+URn]` form (nvdisasm prints it fine; width bits
//!    [74:73] compose orthogonally on both forms),
//!  - b76 in FLOAT classes (F64/F32/F16 lanes, arb203) is NOT this toggle
//!    (natural b76=1 corpus words there decode IDENT today) — out of scope.
//!
//! Exposure: ZERO `[Rx.64+URn]` lexemes in 88,663 corpus records
//! (atomdb199 79,533 + atoms_all 9,130); ptxas 13.3 emits desc forms only
//! (205). Our state: decode HOLE fail-closed x12 variants x3 tables;
//! encode fail-closed (`ATOM_P_R_ARURI_R` key absent) while the desc form
//! round-trips to the nvcc witness word. POLICY: keep fail-closed; adding
//! unwitnessed rows is the "osobny gate swiadkow" decision (wlasciciel,
//! note 205 sec.6). Zero src/tables delta: pins only.
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
/// b76 address-form bit (1 = desc, 0 = [R.64+UR] on the int lane).
const B76: u128 = 1u128 << 76;

/// Real nvcc witnesses (probe205a anchors, x3-arch payload-eq).
/// (glyph, lo, hi)
const WIT: &[(&str, u64, u64)] = &[
    (
        "ATOM.E.MIN.64.STRONG.SM P0, R4, desc[UR4][R2.64], R4",
        0x800000040204798a,
        0x001162000890b504,
    ),
    (
        "ATOM.E.MIN.S64.STRONG.SM P0, R4, desc[UR4][R2.64], R4",
        0x800000040204798a,
        0x001162000890b704,
    ),
    (
        "ATOM.E.MIN.64.STRONG.GPU P0, R4, desc[UR4][R2.64], R4",
        0x800000040204798a,
        0x001162000890f504,
    ),
    (
        "ATOM.E.MIN.S64.STRONG.GPU P0, R4, desc[UR4][R2.64], R4",
        0x800000040204798a,
        0x001162000890f704,
    ),
    (
        "ATOM.E.MIN.64.STRONG.SYS P0, R4, desc[UR4][R2.64], R4",
        0x800000040204798a,
        0x0011620008915504,
    ),
    (
        "ATOM.E.MIN.S64.STRONG.SYS P0, R4, desc[UR4][R2.64], R4",
        0x800000040204798a,
        0x0011620008915704,
    ),
    (
        "ATOM.E.MIN.STRONG.SM PT, R3, desc[UR4][R2.64], R7",
        0x800000070203798a,
        0x001eac00089eb104,
    ),
    (
        "ATOM.E.MIN.S32.STRONG.SM PT, R3, desc[UR4][R2.64], R7",
        0x800000070203798a,
        0x001eac00089eb304,
    ),
    (
        "ATOM.E.MIN.STRONG.GPU PT, R3, desc[UR4][R2.64], R7",
        0x800000070203798a,
        0x001eac00089ef104,
    ),
    (
        "ATOM.E.MIN.S32.STRONG.GPU PT, R3, desc[UR4][R2.64], R7",
        0x800000070203798a,
        0x001eac00089ef304,
    ),
    (
        "ATOM.E.MIN.STRONG.SYS PT, R3, desc[UR4][R2.64], R7",
        0x800000070203798a,
        0x001eac00089f5104,
    ),
    (
        "ATOM.E.MIN.S32.STRONG.SYS PT, R3, desc[UR4][R2.64], R7",
        0x800000070203798a,
        0x001eac00089f5304,
    ),
];

#[test]
fn t207_1_ur80_form_decode_failclosed() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        for (i, (_, lo, hi)) in WIT.iter().enumerate() {
            let w = word(*lo, *hi) ^ B76; // desc -> [R2.64+UR4]
            assert!(
                idx.decode(w, 0, &t).is_err(),
                "{tp}: [R.64+UR] form #{i} decoded — unwitnessed form must stay HOLE"
            );
        }
    }
}

#[test]
fn t207_2_desc_form_witnesses_ident() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        for (gl, lo, hi) in WIT {
            let got = idx
                .decode(word(*lo, *hi), 0, &t)
                .map(|d| to_sass(&d))
                .unwrap_or_else(|_| panic!("{tp}: desc witness HOLE for {gl}"));
            assert_eq!(&got, gl, "{tp}: desc witness drift");
        }
    }
}

#[test]
fn t207_3_encode_boundary_ur80_failclosed_desc_roundtrip() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let ur_gl = "ATOM.E.MIN.64.STRONG.SM P0, R4, [R2.64+UR4], R4";
        let insn = parse_sass(&format!("{ur_gl} ;"), 0).expect("parser accepts the lexeme");
        assert!(
            encode_instruction(&insn, &t).is_err(),
            "{tp}: [R.64+UR] encode must stay fail-closed (ATOM_P_R_ARURI_R absent)"
        );
        let (gl, lo, hi) = WIT[0];
        let insn = parse_sass(&format!("{gl} ;"), 0).expect("parse desc witness");
        let w = encode_instruction(&insn, &t)
            .unwrap_or_else(|_| panic!("{tp}: desc witness encode HOLE"));
        assert_eq!(
            w & M96,
            word(lo, hi) & M96,
            "{tp}: desc witness encode drift"
        );
    }
}

#[test]
fn t207_4_widths_compose_under_ur80_and_stay_failclosed() {
    // b76=0 plus width toggles b73/b74 -> nvdisasm prints e.g.
    // "ATOM.E.MIN.S64.STRONG.SM ... [R2.64+UR4]"; decode must stay HOLE.
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        for (i, (_, lo, hi)) in WIT.iter().take(4).enumerate() {
            for wbit in [73u32, 74u32] {
                let w = (word(*lo, *hi) ^ B76) ^ (1u128 << wbit);
                assert!(
                    idx.decode(w, 0, &t).is_err(),
                    "{tp}: [R.64+UR]+width variant #{i} b{wbit} decoded — must stay HOLE"
                );
            }
        }
    }
}
