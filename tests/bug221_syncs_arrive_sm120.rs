//! BUG-221 (F2-iter107, front2/blind, 2026-08-27): sm120 SYNCS.ARRIVE.TRANS64
//! lane law closure (witness-first donor-clone from canonical sm100a,
//! canonical d749415).
//!
//! Found during the BUG-220 ARRIVE emission hunt
//! (work/bug220/probe/arrive220.cu, nvcc 13.3.73 x sm_100a/sm_103a/sm_120a,
//! payload arch-eq): the mbarrier arrive family lowers to
//! SYNCS.ARRIVE.TRANS64(.RED)(.A1T0) — the vendor ARRIVE vehicle
//! (ATOMS.ARRIVE op26 stays emission-zero, parked 218-c).
//! Pre-fix sm120 (published cubit-71cc7be):
//!  (a) SILENT WRONG GLYPH: the RED variant decoded with .RED DROPPED
//!      (loose lone row absorbed it — class-218 absorb);
//!  (b) HOLE: the expect_tx plain form (no A1T0) was fail-closed.
//! sm100a/103a decoded all witnesses IDENT already. Graft law
//! arb220b.json: 132/132 cells identical x3 arch — b74=RED, b84/85/86
//! A-enum (00 none/01 A0T1/10 A1T0/11 A0TR; b86 second letter R/X),
//! b73=TMASK, b75=OPTOUT (named prints, unwitnessed), RED+TMASK=INVALID3,
//! [URx] field @[68:73) stride 16 identical x3.
//!
//! Fix: REPLACE lone loose 'A1T0,ARRIVE,TRANS64' by the donor row +
//! ADD {'A1T0,ARRIVE,RED,TRANS64','ARRIVE,RED,TRANS64','ARRIVE,TRANS64',
//! 'A0TR,ARRIVE,RED,TRANS64'} (era rows _src bug221-2026-08-27).
//! Unwitnessed named variants (TMASK / OPTOUT / bare A-enum singles) sit
//! in the decoder absorb class UNIFORMLY on all 3 tables (donor parity)
//! — residual lanes filed as 222-kand; x3 parity pinned in t221_4.
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
/// nvcc-emitted witnesses (arrive220, payload arch-eq x3). hi = low32 bits
/// only (ctrl region zeroed).
const WITNESS: &[(&str, u64, u64)] = &[
    (
        "SYNCS.ARRIVE.TRANS64.A1T0 RZ, [UR4], RZ",
        0x000000ffffff79a7,
        0x08100004,
    ),
    (
        "SYNCS.ARRIVE.TRANS64.A1T0 R2, [UR4], RZ",
        0x000000ffff0279a7,
        0x08100004,
    ),
    (
        "SYNCS.ARRIVE.TRANS64.RED.A1T0 RZ, [UR4], RZ",
        0x000000ffffff79a7,
        0x08100404,
    ),
    (
        "SYNCS.ARRIVE.TRANS64 R2, [UR4], R2",
        0x00000002ff0279a7,
        0x08000004,
    ),
];
/// Graft-proven legal combos (b74 RED on plain; b85 A0TR on RED.A1T0).
const GRAFT: &[(&str, u64, u64)] = &[
    (
        "SYNCS.ARRIVE.TRANS64.RED R2, [UR4], R2",
        0x00000002ff0279a7,
        0x08000404,
    ),
    (
        "SYNCS.ARRIVE.TRANS64.RED.A0TR RZ, [UR4], RZ",
        0x000000ffffff79a7,
        0x08300404,
    ),
];
/// 103-corpus signature words on the donor-cloned keys (arb220_sigs.json;
/// full hi incl. ctrl — decode strips [127:96]). The sm120 pre-fix states:
/// EXCH64/PHASE_TRYWAIT/ARRIVE_ARI were HOLE-or-absorbed; PHASE_AURI was
/// already alive via the pre-existing SYNCS_P_AURI_R key (untouched here).
const CORPUS: &[(&str, u64, u64)] = &[
    (
        "SYNCS.EXCH.64 URZ, [UR29], UR6",
        0x000000061dff75b2,
        0x0022b00008000100,
    ),
    (
        "SYNCS.PHASECHK.TRANS64.TRYWAIT P1, [R5+URZ+0x140], R0",
        0x00014000050075a7,
        0x000ea400080211ff,
    ),
    (
        "SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R5+URZ+0x130], RZ",
        0x000130ff05ff79a7,
        0x0005e200081000ff,
    ),
    (
        "SYNCS.PHASECHK.TRANS64 P0, [UR4+0xe0], R3",
        0x0000e003ff0075a7,
        0x000e640008001004,
    ),
];
/// Encode-supported subset of CORPUS (sm120 P_AURI_R has a pre-existing
/// encode-side imm-offset field gap — decode alive, encode HOLE on all
/// arch tables equally until 223-kand; NOT part of the 221 decode-law fix).
const CORPUS_ENC: &[(&str, u64, u64)] = &[
    (
        "SYNCS.EXCH.64 URZ, [UR29], UR6",
        0x000000061dff75b2,
        0x0022b00008000100,
    ),
    (
        "SYNCS.PHASECHK.TRANS64.TRYWAIT P1, [R5+URZ+0x140], R0",
        0x00014000050075a7,
        0x000ea400080211ff,
    ),
    (
        "SYNCS.ARRIVE.TRANS64.A1T0 RZ, [R5+URZ+0x130], RZ",
        0x000130ff05ff79a7,
        0x0005e200081000ff,
    ),
];

#[test]
fn t221_1_witnesses_decode_ident_x3() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        for (gl, lo, hi) in WITNESS.iter().chain(GRAFT).chain(CORPUS) {
            let got = idx
                .decode(word(*lo, *hi), 0, &t)
                .map(|d| to_sass(&d))
                .unwrap_or_else(|_| panic!("{tp}: HOLE for witness {gl}"));
            assert_eq!(&got, gl, "{tp}: glyph drift");
        }
    }
}

#[test]
fn t221_2_witness_encode_roundtrip_low96_x3() {
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        for (gl, lo, hi) in WITNESS.iter().chain(CORPUS_ENC) {
            let insn = parse_sass(&format!("{gl} ;"), 0).expect("parse");
            let w = encode_instruction(&insn, &t)
                .unwrap_or_else(|_| panic!("{tp}: encode HOLE for {gl}"));
            assert_eq!(w & M96, word(*lo, *hi) & M96, "{tp}: encode drift for {gl}");
        }
    }
}

#[test]
fn t221_3_negative_boundary_fail_closed_x3() {
    // RED|TMASK = vendor INVALID3 (graft); b91 cleared = no vendor glyph.
    const NEG: &[(u64, u64)] = &[
        (0x000000ffffff79a7, 0x08102404), // RED.A1T0 | TMASK -> INVALID3
        (0x000000ffffff79a7, 0x00100404), // b91 cleared -> nv NOGLYPH
    ];
    for tp in [T120, T103, T100] {
        let t = tab(tp);
        let idx = DecodeIndex::build(&t);
        for (lo, hi) in NEG {
            assert!(
                idx.decode(word(*lo, *hi), 0, &t).is_err(),
                "{tp}: absorb of INVALID3/NOGLYPH word {lo:#x}/{hi:#x}"
            );
        }
    }
}

#[test]
fn t221_4_unwitnessed_named_lane_x3_parity_lock() {
    // Donor-parity boundary: unwitnessed named graft variants behave
    // IDENTICALLY on all 3 tables (222-kand residual; do not re-derive
    // vendor semantics here — lock x3 uniformity only).
    const UNWITNESSED: &[(u64, u64)] = &[
        (0x000000ffffff79a7, 0x08102004), // TMASK on A1T0 (today: HOLE x3)
        (0x000000ffffff79a7, 0x08100804), // OPTOUT on A1T0 (today: absorb)
        (0x00000002ff0279a7, 0x08200004), // A0T1 on plain (today: HOLE x3)
        (0x00000002ff0279a7, 0x08300004), // A0TR on plain (today: absorb)
    ];
    for (lo, hi) in UNWITNESSED {
        let mut outs = Vec::new();
        for tp in [T120, T103, T100] {
            let t = tab(tp);
            let idx = DecodeIndex::build(&t);
            outs.push(
                idx.decode(word(*lo, *hi), 0, &t)
                    .map(|d| to_sass(&d))
                    .unwrap_or_else(|_| "HOLE".to_string()),
            );
        }
        assert!(
            outs[0] == outs[1] && outs[1] == outs[2],
            "x3 parity break for unwitnessed {lo:#x}/{hi:#x}: {outs:?}"
        );
    }
}
