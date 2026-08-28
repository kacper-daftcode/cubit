//! BUG-220b (F2-iter107, front2/blind, 2026-08-27): REDG F32x2/F32x4 scoped
//! lane (SM/SYS/GPU) — law lock for the BUG-209 follow-up "F32x2 scoped
//! analog". Contrast BUG-209: scoped vec-F16 is ptxas-CORDONED, but scoped
//! F32x2/F32x4 COMPILE on nvcc 13.3.73 x sm_100a/sm_103a/sm_120a
//! (work/bug220/probe/redvec220.cu) and are native witnesses:
//!   red.relaxed.cta/gpu/sys.global.add.v2.f32 ->
//!       REDG.E.ADD.F32x2.FTZ.RN.STRONG.{SM,GPU,SYS} desc[UR4][R2.64], R4
//!   red.relaxed.sys.global.add.v4.f32 ->
//!       REDG.E.ADD.F32x4.FTZ.RN.STRONG.SYS desc[UR4][R2.64], R8
//! State on published cubit-71cc7be: all decode IDENT x3 (covered by the
//! BUG-206 scope wave). Pins lock the law; encode roundtrip low96 x3.
//! BUG-220a (ATOMS.ARRIVE completion) = separate closure: emission ZERO
//! (mbarrier lowers to SYNCS.ARRIVE, see BUG-221); op26 lane stays
//! parked (218-c) pending the wlasciciel policy decision; t219_3 pins
//! already hold that boundary.
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
/// redvec220 witnesses (payload arch-eq x3; ctrl region zeroed).
const W: &[(&str, u64, u64)] = &[
    (
        "REDG.E.ADD.F32x2.FTZ.RN.STRONG.GPU desc[UR4][R2.64], R4",
        0x00000004020079a6,
        0x0c12f504,
    ),
    (
        "REDG.E.ADD.F32x2.FTZ.RN.STRONG.SM desc[UR4][R2.64], R4",
        0x00000004020079a6,
        0x0c12b504,
    ),
    (
        "REDG.E.ADD.F32x2.FTZ.RN.STRONG.SYS desc[UR4][R2.64], R4",
        0x00000004020079a6,
        0x0c135504,
    ),
    (
        "REDG.E.ADD.F32x4.FTZ.RN.STRONG.SYS desc[UR4][R2.64], R8",
        0x00000008020079a6,
        0x0c135704,
    ),
];

#[test]
fn t220_1_scoped_f32_decode_ident_x3() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        for (gl, lo, hi) in W {
            let got = idx
                .decode(word(*lo, *hi), 0, &t)
                .map(|d| to_sass(&d))
                .unwrap_or_else(|_| panic!("{tp}: HOLE for {gl}"));
            assert_eq!(&got, gl, "{tp}: glyph drift");
        }
    }
}

#[test]
fn t220_2_scoped_f32_encode_roundtrip_low96_x3() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        for (gl, lo, hi) in W {
            let insn = parse_sass(&format!("{gl} ;"), 0).expect("parse");
            let w = encode_instruction(&insn, &t)
                .unwrap_or_else(|_| panic!("{tp}: encode HOLE for {gl}"));
            assert_eq!(w & M96, word(*lo, *hi) & M96, "{tp}: encode drift for {gl}");
        }
    }
}

#[test]
fn t220_3_scope_enum_not_flattened() {
    // SM/GPU/SYS are three distinct scope encodings on the F32x2 lane
    // (209 law: [80:77] space/scope enum) — the renders must stay distinct.
    let t = tab(T103);
    let idx = DecodeIndex::build(&t);
    let mut renders = Vec::new();
    for (_, lo, hi) in &W[0..3] {
        renders.push(
            idx.decode(word(*lo, *hi), 0, &t)
                .map(|d| to_sass(&d))
                .unwrap(),
        );
    }
    assert!(renders[0] != renders[1] && renders[1] != renders[2] && renders[0] != renders[2]);
}
