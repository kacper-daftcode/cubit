//! BUG-285 (F2-iter157, loop5/blind front2, 2026-08-30): HFMA2.BF16_V2 (b85)
//! cross-key family closure on the packed-f16 imm parents
//! (HFMA2_R_R_R_{II_FI,FI_FI,II_II}), canonical e41a438.
//!
//! Law arb285 (200 labels, 812 probes, nvdisasm 13.3.73 raw -b, x4 models
//! SM100a/SM103a/SM120/SM121a agree on EVERY probe; supersedes arb279b
//! b85-leg): the [80:76] suffix window law is IDENTICAL on all 3 parents:
//! legal F in {0 '', 1 FMZ, 2 SAT, 3 FMZ.SAT, 8 RELU, 9 FMZ.RELU, 16 FTZ,
//! 17 OOB, 18 FTZ.SAT, 19 OOB.SAT, 24 FTZ.RELU, 25 OOB.RELU}; b85|b78 =>
//! vendor '.INVALID3' (hole by doctrine); SAT+RELU => rc=1 x4 (hole).
//! tok3 law carries over unchanged: [82:81] 1=.F32 2=.H0_H0 3=.H1_H1,
//! abs@83, neg@84 compose ('-|RZ|.H0_H0'); b86 = '.H0_NH1', with hsel =>
//! INVALID5/6 (271 law) hole; tok2@74 v1 = '.INVALID1' (306 law); RELU
//! trailing pred 3b@87/inv@90 with PT(7,0) elision (279-P law); II_FI
//! guard field composes (@P0/@P1/@P5 print, PT elides).
//! Pre-fix measured (pub pyo3-e67ee9e, measure_pre285): every vendor-legal
//! b85 word = decode HOLE x2 legs (266/266, zero mis-claims); every
//! authored BF16_V2 text on this family LOUD-fails (BUG-132 mod-drop gate
//! / no-entry / lint / unknown-suffix). routex285 FULL 2,406 cubins x4
//! legs: 97,338 lattice words per leg, ZERO b85 => corpus-neutral.
//! Graft patch285.py (replayable+idempotent, re-run skip-idem x96):
//! 12 mgs x3 parents x2 legs (72) + 4 dotted RELU _P keys x3 sigs x2 legs
//! (24). Engine arm: printer mod_priority HFMA2 BF16_V2 -> 0 (vendor prints
//! the cross-key first; b85+b78 = INVALID3 so F32 never co-occurs).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

const M96: u128 = (1u128 << 96) - 1;
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc_res(t: &IsaTable, text: &str) -> anyhow::Result<u128> {
    let insn = parse_sass(&format!("{text};"), 0).unwrap_or_else(|e| panic!("parse {text}: {e}"));
    encode_instruction(&insn, t)
}

/// Full vendor-legal decode matrix (arb285, x4 models agree, both graft legs).
const DECODE_LAW: &[(u128, &str)] = &[
    (
        0xFC000002800FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, |RZ|, 0, 0",
    ), // C _R_R_FI_FI t3abs
    (
        0xFC000003000FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, -RZ, 0, 0",
    ), // C _R_R_FI_FI t3neg
    (
        0xFC000002200FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, RZ.F32, 0, 0",
    ), // C _R_R_FI_FI t3v1
    (
        0xFC000002400FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, RZ.H0_H0, 0, 0",
    ), // C _R_R_FI_FI t3v2
    (
        0xFC000003C00FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, -|RZ|.H0_H0, 0, 0",
    ), // C _R_R_FI_FI t3v2absneg
    (
        0xFC000003400FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, -RZ.H0_H0, 0, 0",
    ), // C _R_R_FI_FI t3v2neg
    (
        0xFC000002600FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, RZ.H1_H1, 0, 0",
    ), // C _R_R_FI_FI t3v3
    (0x2800FF00000000FF037431, "HFMA2.BF16_V2 R3, RZ, |RZ|, 0, 0"), // C _R_R_II_FI t3abs
    (0x3000FF00000000FF037431, "HFMA2.BF16_V2 R3, RZ, -RZ, 0, 0"),  // C _R_R_II_FI t3neg
    (
        0x2200FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, RZ.F32, 0, 0",
    ), // C _R_R_II_FI t3v1
    (
        0x2400FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, RZ.H0_H0, 0, 0",
    ), // C _R_R_II_FI t3v2
    (
        0x3C00FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, -|RZ|.H0_H0, 0, 0",
    ), // C _R_R_II_FI t3v2absneg
    (
        0x3400FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, -RZ.H0_H0, 0, 0",
    ), // C _R_R_II_FI t3v2neg
    (
        0x2600FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, RZ.H1_H1, 0, 0",
    ), // C _R_R_II_FI t3v3
    (
        0x2801FF00000000FF037431,
        "HFMA2.BF16_V2 R3, -RZ, |RZ|, 0, 0",
    ), // C _R_R_II_II t3abs
    (0x3001FF00000000FF037431, "HFMA2.BF16_V2 R3, -RZ, -RZ, 0, 0"), // C _R_R_II_II t3neg
    (
        0x2201FF00000000FF037431,
        "HFMA2.BF16_V2 R3, -RZ, RZ.F32, 0, 0",
    ), // C _R_R_II_II t3v1
    (
        0x2401FF00000000FF037431,
        "HFMA2.BF16_V2 R3, -RZ, RZ.H0_H0, 0, 0",
    ), // C _R_R_II_II t3v2
    (
        0x3C01FF00000000FF037431,
        "HFMA2.BF16_V2 R3, -RZ, -|RZ|.H0_H0, 0, 0",
    ), // C _R_R_II_II t3v2absneg
    (
        0x3401FF00000000FF037431,
        "HFMA2.BF16_V2 R3, -RZ, -RZ.H0_H0, 0, 0",
    ), // C _R_R_II_II t3v2neg
    (
        0x2601FF00000000FF037431,
        "HFMA2.BF16_V2 R3, -RZ, RZ.H1_H1, 0, 0",
    ), // C _R_R_II_II t3v3
    (
        0xFC000002000FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, RZ, 0, 0",
    ), // F _R_R_FI_FI F=00
    (
        0xFC000002010FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ R3, RZ, RZ, 0, 0",
    ), // F _R_R_FI_FI F=01
    (
        0xFC000002020FF00000000FF037431,
        "HFMA2.BF16_V2.SAT R3, RZ, RZ, 0, 0",
    ), // F _R_R_FI_FI F=02
    (
        0xFC000002030FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.SAT R3, RZ, RZ, 0, 0",
    ), // F _R_R_FI_FI F=03
    (
        0xFC000002080FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, RZ, RZ, 0, 0, P0",
    ), // F _R_R_FI_FI F=08
    (
        0xFC000002090FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, RZ, RZ, 0, 0, P0",
    ), // F _R_R_FI_FI F=09
    (
        0xFC000002100FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ R3, RZ, RZ, 0, 0",
    ), // F _R_R_FI_FI F=16
    (
        0xFC000002110FF00000000FF037431,
        "HFMA2.BF16_V2.OOB R3, RZ, RZ, 0, 0",
    ), // F _R_R_FI_FI F=17
    (
        0xFC000002120FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.SAT R3, RZ, RZ, 0, 0",
    ), // F _R_R_FI_FI F=18
    (
        0xFC000002130FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.SAT R3, RZ, RZ, 0, 0",
    ), // F _R_R_FI_FI F=19
    (
        0xFC000002180FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, RZ, RZ, 0, 0, P0",
    ), // F _R_R_FI_FI F=24
    (
        0xFC000002190FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, RZ, RZ, 0, 0, P0",
    ), // F _R_R_FI_FI F=25
    (0x2000FF00000000FF037431, "HFMA2.BF16_V2 R3, RZ, RZ, 0, 0"),   // F _R_R_II_FI F=00
    (
        0x2010FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ R3, RZ, RZ, 0, 0",
    ), // F _R_R_II_FI F=01
    (
        0x2020FF00000000FF037431,
        "HFMA2.BF16_V2.SAT R3, RZ, RZ, 0, 0",
    ), // F _R_R_II_FI F=02
    (
        0x2030FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.SAT R3, RZ, RZ, 0, 0",
    ), // F _R_R_II_FI F=03
    (
        0x2080FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, RZ, RZ, 0, 0, P0",
    ), // F _R_R_II_FI F=08
    (
        0x2090FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, RZ, RZ, 0, 0, P0",
    ), // F _R_R_II_FI F=09
    (
        0x2100FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ R3, RZ, RZ, 0, 0",
    ), // F _R_R_II_FI F=16
    (
        0x2110FF00000000FF037431,
        "HFMA2.BF16_V2.OOB R3, RZ, RZ, 0, 0",
    ), // F _R_R_II_FI F=17
    (
        0x2120FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.SAT R3, RZ, RZ, 0, 0",
    ), // F _R_R_II_FI F=18
    (
        0x2130FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.SAT R3, RZ, RZ, 0, 0",
    ), // F _R_R_II_FI F=19
    (
        0x2180FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, RZ, RZ, 0, 0, P0",
    ), // F _R_R_II_FI F=24
    (
        0x2190FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, RZ, RZ, 0, 0, P0",
    ), // F _R_R_II_FI F=25
    (0x2001FF00000000FF037431, "HFMA2.BF16_V2 R3, -RZ, RZ, 0, 0"),  // F _R_R_II_II F=00
    (
        0x2011FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ R3, -RZ, RZ, 0, 0",
    ), // F _R_R_II_II F=01
    (
        0x2021FF00000000FF037431,
        "HFMA2.BF16_V2.SAT R3, -RZ, RZ, 0, 0",
    ), // F _R_R_II_II F=02
    (
        0x2031FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.SAT R3, -RZ, RZ, 0, 0",
    ), // F _R_R_II_II F=03
    (
        0x2081FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, -RZ, RZ, 0, 0, P0",
    ), // F _R_R_II_II F=08
    (
        0x2091FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, -RZ, RZ, 0, 0, P0",
    ), // F _R_R_II_II F=09
    (
        0x2101FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ R3, -RZ, RZ, 0, 0",
    ), // F _R_R_II_II F=16
    (
        0x2111FF00000000FF037431,
        "HFMA2.BF16_V2.OOB R3, -RZ, RZ, 0, 0",
    ), // F _R_R_II_II F=17
    (
        0x2121FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.SAT R3, -RZ, RZ, 0, 0",
    ), // F _R_R_II_II F=18
    (
        0x2131FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.SAT R3, -RZ, RZ, 0, 0",
    ), // F _R_R_II_II F=19
    (
        0x2181FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, -RZ, RZ, 0, 0, P0",
    ), // F _R_R_II_II F=24
    (
        0x2191FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, -RZ, RZ, 0, 0, P0",
    ), // F _R_R_II_II F=25
    (
        0x2000FF00000000FF030431,
        "@P0 HFMA2.BF16_V2 R3, RZ, RZ, 0, 0",
    ), // G II_FI g0 F0
    (
        0x2100FF00000000FF030431,
        "@P0 HFMA2.BF16_V2.FTZ R3, RZ, RZ, 0, 0",
    ), // G II_FI g0 FTZ
    (
        0x2000FF00000000FF031431,
        "@P1 HFMA2.BF16_V2 R3, RZ, RZ, 0, 0",
    ), // G II_FI g1 F0
    (
        0x2100FF00000000FF031431,
        "@P1 HFMA2.BF16_V2.FTZ R3, RZ, RZ, 0, 0",
    ), // G II_FI g1 FTZ
    (
        0x2000FF00000000FF035431,
        "@P5 HFMA2.BF16_V2 R3, RZ, RZ, 0, 0",
    ), // G II_FI g5 F0
    (
        0x2100FF00000000FF035431,
        "@P5 HFMA2.BF16_V2.FTZ R3, RZ, RZ, 0, 0",
    ), // G II_FI g5 FTZ
    (0x2000FF00000000FF037431, "HFMA2.BF16_V2 R3, RZ, RZ, 0, 0"),   // G II_FI g7 F0
    (
        0x2100FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ R3, RZ, RZ, 0, 0",
    ), // G II_FI g7 FTZ
    (
        0xFC000007000FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, -RZ.H0_NH1, 0, 0",
    ), // H _R_R_FI_FI b86 neg
    (
        0xFC000006000FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, RZ.H0_NH1, 0, 0",
    ), // H _R_R_FI_FI b86 plain
    (
        0x7000FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, -RZ.H0_NH1, 0, 0",
    ), // H _R_R_II_FI b86 neg
    (
        0x6000FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, RZ.H0_NH1, 0, 0",
    ), // H _R_R_II_FI b86 plain
    (
        0x7001FF00000000FF037431,
        "HFMA2.BF16_V2 R3, -RZ, -RZ.H0_NH1, 0, 0",
    ), // H _R_R_II_II b86 neg
    (
        0x6001FF00000000FF037431,
        "HFMA2.BF16_V2 R3, -RZ, RZ.H0_NH1, 0, 0",
    ), // H _R_R_II_II b86 plain
    (
        0xFC000002180FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, RZ, RZ, 0, 0, P0",
    ), // R _R_R_FI_FI F=24 p0i0
    (
        0xFC00001A180FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, RZ, RZ, 0, 0, P3",
    ), // R _R_R_FI_FI F=24 p3i0
    (
        0xFC00005A180FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, RZ, RZ, 0, 0, !P3",
    ), // R _R_R_FI_FI F=24 p3i1
    (
        0xFC00003A180FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, RZ, RZ, 0, 0",
    ), // R _R_R_FI_FI F=24 p7i0
    (
        0xFC00007A180FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, RZ, RZ, 0, 0, !PT",
    ), // R _R_R_FI_FI F=24 p7i1
    (
        0xFC000002190FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, RZ, RZ, 0, 0, P0",
    ), // R _R_R_FI_FI F=25 p0i0
    (
        0xFC00001A190FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, RZ, RZ, 0, 0, P3",
    ), // R _R_R_FI_FI F=25 p3i0
    (
        0xFC00005A190FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, RZ, RZ, 0, 0, !P3",
    ), // R _R_R_FI_FI F=25 p3i1
    (
        0xFC00003A190FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, RZ, RZ, 0, 0",
    ), // R _R_R_FI_FI F=25 p7i0
    (
        0xFC00007A190FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, RZ, RZ, 0, 0, !PT",
    ), // R _R_R_FI_FI F=25 p7i1
    (
        0xFC000002080FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, RZ, RZ, 0, 0, P0",
    ), // R _R_R_FI_FI F=8 p0i0
    (
        0xFC00001A080FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, RZ, RZ, 0, 0, P3",
    ), // R _R_R_FI_FI F=8 p3i0
    (
        0xFC00005A080FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, RZ, RZ, 0, 0, !P3",
    ), // R _R_R_FI_FI F=8 p3i1
    (
        0xFC00003A080FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, RZ, RZ, 0, 0",
    ), // R _R_R_FI_FI F=8 p7i0
    (
        0xFC00007A080FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, RZ, RZ, 0, 0, !PT",
    ), // R _R_R_FI_FI F=8 p7i1
    (
        0xFC000002090FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, RZ, RZ, 0, 0, P0",
    ), // R _R_R_FI_FI F=9 p0i0
    (
        0xFC00001A090FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, RZ, RZ, 0, 0, P3",
    ), // R _R_R_FI_FI F=9 p3i0
    (
        0xFC00005A090FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, RZ, RZ, 0, 0, !P3",
    ), // R _R_R_FI_FI F=9 p3i1
    (
        0xFC00003A090FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, RZ, RZ, 0, 0",
    ), // R _R_R_FI_FI F=9 p7i0
    (
        0xFC00007A090FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, RZ, RZ, 0, 0, !PT",
    ), // R _R_R_FI_FI F=9 p7i1
    (
        0x2180FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, RZ, RZ, 0, 0, P0",
    ), // R _R_R_II_FI F=24 p0i0
    (
        0x1A180FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, RZ, RZ, 0, 0, P3",
    ), // R _R_R_II_FI F=24 p3i0
    (
        0x5A180FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, RZ, RZ, 0, 0, !P3",
    ), // R _R_R_II_FI F=24 p3i1
    (
        0x3A180FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, RZ, RZ, 0, 0",
    ), // R _R_R_II_FI F=24 p7i0
    (
        0x7A180FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, RZ, RZ, 0, 0, !PT",
    ), // R _R_R_II_FI F=24 p7i1
    (
        0x2190FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, RZ, RZ, 0, 0, P0",
    ), // R _R_R_II_FI F=25 p0i0
    (
        0x1A190FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, RZ, RZ, 0, 0, P3",
    ), // R _R_R_II_FI F=25 p3i0
    (
        0x5A190FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, RZ, RZ, 0, 0, !P3",
    ), // R _R_R_II_FI F=25 p3i1
    (
        0x3A190FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, RZ, RZ, 0, 0",
    ), // R _R_R_II_FI F=25 p7i0
    (
        0x7A190FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, RZ, RZ, 0, 0, !PT",
    ), // R _R_R_II_FI F=25 p7i1
    (
        0x2080FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, RZ, RZ, 0, 0, P0",
    ), // R _R_R_II_FI F=8 p0i0
    (
        0x1A080FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, RZ, RZ, 0, 0, P3",
    ), // R _R_R_II_FI F=8 p3i0
    (
        0x5A080FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, RZ, RZ, 0, 0, !P3",
    ), // R _R_R_II_FI F=8 p3i1
    (
        0x3A080FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, RZ, RZ, 0, 0",
    ), // R _R_R_II_FI F=8 p7i0
    (
        0x7A080FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, RZ, RZ, 0, 0, !PT",
    ), // R _R_R_II_FI F=8 p7i1
    (
        0x2090FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, RZ, RZ, 0, 0, P0",
    ), // R _R_R_II_FI F=9 p0i0
    (
        0x1A090FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, RZ, RZ, 0, 0, P3",
    ), // R _R_R_II_FI F=9 p3i0
    (
        0x5A090FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, RZ, RZ, 0, 0, !P3",
    ), // R _R_R_II_FI F=9 p3i1
    (
        0x3A090FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, RZ, RZ, 0, 0",
    ), // R _R_R_II_FI F=9 p7i0
    (
        0x7A090FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, RZ, RZ, 0, 0, !PT",
    ), // R _R_R_II_FI F=9 p7i1
    (
        0x2181FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, -RZ, RZ, 0, 0, P0",
    ), // R _R_R_II_II F=24 p0i0
    (
        0x1A181FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, -RZ, RZ, 0, 0, P3",
    ), // R _R_R_II_II F=24 p3i0
    (
        0x5A181FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, -RZ, RZ, 0, 0, !P3",
    ), // R _R_R_II_II F=24 p3i1
    (
        0x3A181FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, -RZ, RZ, 0, 0",
    ), // R _R_R_II_II F=24 p7i0
    (
        0x7A181FF00000000FF037431,
        "HFMA2.BF16_V2.FTZ.RELU R3, -RZ, RZ, 0, 0, !PT",
    ), // R _R_R_II_II F=24 p7i1
    (
        0x2191FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, -RZ, RZ, 0, 0, P0",
    ), // R _R_R_II_II F=25 p0i0
    (
        0x1A191FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, -RZ, RZ, 0, 0, P3",
    ), // R _R_R_II_II F=25 p3i0
    (
        0x5A191FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, -RZ, RZ, 0, 0, !P3",
    ), // R _R_R_II_II F=25 p3i1
    (
        0x3A191FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, -RZ, RZ, 0, 0",
    ), // R _R_R_II_II F=25 p7i0
    (
        0x7A191FF00000000FF037431,
        "HFMA2.BF16_V2.OOB.RELU R3, -RZ, RZ, 0, 0, !PT",
    ), // R _R_R_II_II F=25 p7i1
    (
        0x2081FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, -RZ, RZ, 0, 0, P0",
    ), // R _R_R_II_II F=8 p0i0
    (
        0x1A081FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, -RZ, RZ, 0, 0, P3",
    ), // R _R_R_II_II F=8 p3i0
    (
        0x5A081FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, -RZ, RZ, 0, 0, !P3",
    ), // R _R_R_II_II F=8 p3i1
    (
        0x3A081FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, -RZ, RZ, 0, 0",
    ), // R _R_R_II_II F=8 p7i0
    (
        0x7A081FF00000000FF037431,
        "HFMA2.BF16_V2.RELU R3, -RZ, RZ, 0, 0, !PT",
    ), // R _R_R_II_II F=8 p7i1
    (
        0x2091FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, -RZ, RZ, 0, 0, P0",
    ), // R _R_R_II_II F=9 p0i0
    (
        0x1A091FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, -RZ, RZ, 0, 0, P3",
    ), // R _R_R_II_II F=9 p3i0
    (
        0x5A091FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, -RZ, RZ, 0, 0, !P3",
    ), // R _R_R_II_II F=9 p3i1
    (
        0x3A091FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, -RZ, RZ, 0, 0",
    ), // R _R_R_II_II F=9 p7i0
    (
        0x7A091FF00000000FF037431,
        "HFMA2.BF16_V2.FMZ.RELU R3, -RZ, RZ, 0, 0, !PT",
    ), // R _R_R_II_II F=9 p7i1
    (
        0xFC000002008FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ.H0_H0, RZ, 0, 0",
    ), // T2 FI_FI tok2 v2
    (
        0xFC00000200CFF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ.H1_H1, RZ, 0, 0",
    ), // T2 FI_FI tok2 v3
    (
        0xFC000002004FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ.INVALID1, RZ, 0, 0",
    ), // T2 FI_FI tok2 v1
];

/// Illegal carriers (decode hole + encode fail-closed, 274/279/264 doctrine).
const HOLE_CARRIERS: &[(u128, &str)] = &[
    (
        0xFC000002040FF00000000FF037431,
        "HFMA2.INVALID3 R3, RZ, RZ, 0, 0",
    ), // F _R_R_FI_FI F=04
    (
        0xFC000002050FF00000000FF037431,
        "HFMA2.INVALID3.FMZ R3, RZ, RZ, 0, 0",
    ), // F _R_R_FI_FI F=05
    (
        0xFC000002060FF00000000FF037431,
        "HFMA2.INVALID3.SAT R3, RZ, RZ, 0, 0",
    ), // F _R_R_FI_FI F=06
    (
        0xFC000002070FF00000000FF037431,
        "HFMA2.INVALID3.FMZ.SAT R3, RZ, RZ, 0, 0",
    ), // F _R_R_FI_FI F=07
    (0xFC0000020A0FF00000000FF037431, "<rc=1>"), // F _R_R_FI_FI F=10
    (0xFC0000020B0FF00000000FF037431, "<rc=1>"), // F _R_R_FI_FI F=11
    (
        0xFC0000020C0FF00000000FF037431,
        "HFMA2.INVALID3.RELU R3, RZ, RZ, 0, 0, P0",
    ), // F _R_R_FI_FI F=12
    (
        0xFC0000020D0FF00000000FF037431,
        "HFMA2.INVALID3.FMZ.RELU R3, RZ, RZ, 0, 0, P0",
    ), // F _R_R_FI_FI F=13
    (0xFC0000020E0FF00000000FF037431, "<rc=1>"), // F _R_R_FI_FI F=14
    (0xFC0000020F0FF00000000FF037431, "<rc=1>"), // F _R_R_FI_FI F=15
    (
        0xFC000002140FF00000000FF037431,
        "HFMA2.INVALID3.FTZ R3, RZ, RZ, 0, 0",
    ), // F _R_R_FI_FI F=20
    (
        0xFC000002150FF00000000FF037431,
        "HFMA2.INVALID3.OOB R3, RZ, RZ, 0, 0",
    ), // F _R_R_FI_FI F=21
    (
        0xFC000002160FF00000000FF037431,
        "HFMA2.INVALID3.FTZ.SAT R3, RZ, RZ, 0, 0",
    ), // F _R_R_FI_FI F=22
    (
        0xFC000002170FF00000000FF037431,
        "HFMA2.INVALID3.OOB.SAT R3, RZ, RZ, 0, 0",
    ), // F _R_R_FI_FI F=23
    (0xFC0000021A0FF00000000FF037431, "<rc=1>"), // F _R_R_FI_FI F=26
    (0xFC0000021B0FF00000000FF037431, "<rc=1>"), // F _R_R_FI_FI F=27
    (
        0xFC0000021C0FF00000000FF037431,
        "HFMA2.INVALID3.FTZ.RELU R3, RZ, RZ, 0, 0, P0",
    ), // F _R_R_FI_FI F=28
    (
        0xFC0000021D0FF00000000FF037431,
        "HFMA2.INVALID3.OOB.RELU R3, RZ, RZ, 0, 0, P0",
    ), // F _R_R_FI_FI F=29
    (0xFC0000021E0FF00000000FF037431, "<rc=1>"), // F _R_R_FI_FI F=30
    (0xFC0000021F0FF00000000FF037431, "<rc=1>"), // F _R_R_FI_FI F=31
    (0x2040FF00000000FF037431, "HFMA2.INVALID3 R3, RZ, RZ, 0, 0"), // F _R_R_II_FI F=04
    (
        0x2050FF00000000FF037431,
        "HFMA2.INVALID3.FMZ R3, RZ, RZ, 0, 0",
    ), // F _R_R_II_FI F=05
    (
        0x2060FF00000000FF037431,
        "HFMA2.INVALID3.SAT R3, RZ, RZ, 0, 0",
    ), // F _R_R_II_FI F=06
    (
        0x2070FF00000000FF037431,
        "HFMA2.INVALID3.FMZ.SAT R3, RZ, RZ, 0, 0",
    ), // F _R_R_II_FI F=07
    (0x20A0FF00000000FF037431, "<rc=1>"),        // F _R_R_II_FI F=10
    (0x20B0FF00000000FF037431, "<rc=1>"),        // F _R_R_II_FI F=11
    (
        0x20C0FF00000000FF037431,
        "HFMA2.INVALID3.RELU R3, RZ, RZ, 0, 0, P0",
    ), // F _R_R_II_FI F=12
    (
        0x20D0FF00000000FF037431,
        "HFMA2.INVALID3.FMZ.RELU R3, RZ, RZ, 0, 0, P0",
    ), // F _R_R_II_FI F=13
    (0x20E0FF00000000FF037431, "<rc=1>"),        // F _R_R_II_FI F=14
    (0x20F0FF00000000FF037431, "<rc=1>"),        // F _R_R_II_FI F=15
    (
        0x2140FF00000000FF037431,
        "HFMA2.INVALID3.FTZ R3, RZ, RZ, 0, 0",
    ), // F _R_R_II_FI F=20
    (
        0x2150FF00000000FF037431,
        "HFMA2.INVALID3.OOB R3, RZ, RZ, 0, 0",
    ), // F _R_R_II_FI F=21
    (
        0x2160FF00000000FF037431,
        "HFMA2.INVALID3.FTZ.SAT R3, RZ, RZ, 0, 0",
    ), // F _R_R_II_FI F=22
    (
        0x2170FF00000000FF037431,
        "HFMA2.INVALID3.OOB.SAT R3, RZ, RZ, 0, 0",
    ), // F _R_R_II_FI F=23
    (0x21A0FF00000000FF037431, "<rc=1>"),        // F _R_R_II_FI F=26
    (0x21B0FF00000000FF037431, "<rc=1>"),        // F _R_R_II_FI F=27
    (
        0x21C0FF00000000FF037431,
        "HFMA2.INVALID3.FTZ.RELU R3, RZ, RZ, 0, 0, P0",
    ), // F _R_R_II_FI F=28
    (
        0x21D0FF00000000FF037431,
        "HFMA2.INVALID3.OOB.RELU R3, RZ, RZ, 0, 0, P0",
    ), // F _R_R_II_FI F=29
    (0x21E0FF00000000FF037431, "<rc=1>"),        // F _R_R_II_FI F=30
    (0x21F0FF00000000FF037431, "<rc=1>"),        // F _R_R_II_FI F=31
    (0x2041FF00000000FF037431, "HFMA2.INVALID3 R3, -RZ, RZ, 0, 0"), // F _R_R_II_II F=04
    (
        0x2051FF00000000FF037431,
        "HFMA2.INVALID3.FMZ R3, -RZ, RZ, 0, 0",
    ), // F _R_R_II_II F=05
    (
        0x2061FF00000000FF037431,
        "HFMA2.INVALID3.SAT R3, -RZ, RZ, 0, 0",
    ), // F _R_R_II_II F=06
    (
        0x2071FF00000000FF037431,
        "HFMA2.INVALID3.FMZ.SAT R3, -RZ, RZ, 0, 0",
    ), // F _R_R_II_II F=07
    (0x20A1FF00000000FF037431, "<rc=1>"),        // F _R_R_II_II F=10
    (0x20B1FF00000000FF037431, "<rc=1>"),        // F _R_R_II_II F=11
    (
        0x20C1FF00000000FF037431,
        "HFMA2.INVALID3.RELU R3, -RZ, RZ, 0, 0, P0",
    ), // F _R_R_II_II F=12
    (
        0x20D1FF00000000FF037431,
        "HFMA2.INVALID3.FMZ.RELU R3, -RZ, RZ, 0, 0, P0",
    ), // F _R_R_II_II F=13
    (0x20E1FF00000000FF037431, "<rc=1>"),        // F _R_R_II_II F=14
    (0x20F1FF00000000FF037431, "<rc=1>"),        // F _R_R_II_II F=15
    (
        0x2141FF00000000FF037431,
        "HFMA2.INVALID3.FTZ R3, -RZ, RZ, 0, 0",
    ), // F _R_R_II_II F=20
    (
        0x2151FF00000000FF037431,
        "HFMA2.INVALID3.OOB R3, -RZ, RZ, 0, 0",
    ), // F _R_R_II_II F=21
    (
        0x2161FF00000000FF037431,
        "HFMA2.INVALID3.FTZ.SAT R3, -RZ, RZ, 0, 0",
    ), // F _R_R_II_II F=22
    (
        0x2171FF00000000FF037431,
        "HFMA2.INVALID3.OOB.SAT R3, -RZ, RZ, 0, 0",
    ), // F _R_R_II_II F=23
    (0x21A1FF00000000FF037431, "<rc=1>"),        // F _R_R_II_II F=26
    (0x21B1FF00000000FF037431, "<rc=1>"),        // F _R_R_II_II F=27
    (
        0x21C1FF00000000FF037431,
        "HFMA2.INVALID3.FTZ.RELU R3, -RZ, RZ, 0, 0, P0",
    ), // F _R_R_II_II F=28
    (
        0x21D1FF00000000FF037431,
        "HFMA2.INVALID3.OOB.RELU R3, -RZ, RZ, 0, 0, P0",
    ), // F _R_R_II_II F=29
    (0x21E1FF00000000FF037431, "<rc=1>"),        // F _R_R_II_II F=30
    (0x21F1FF00000000FF037431, "<rc=1>"),        // F _R_R_II_II F=31
    (
        0xFC000006200FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, RZ.INVALID5, 0, 0",
    ), // H _R_R_FI_FI b86 v1
    (
        0xFC000006400FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, RZ.INVALID6, 0, 0",
    ), // H _R_R_FI_FI b86 v2
    (
        0x6200FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, RZ.INVALID5, 0, 0",
    ), // H _R_R_II_FI b86 v1
    (
        0x6400FF00000000FF037431,
        "HFMA2.BF16_V2 R3, RZ, RZ.INVALID6, 0, 0",
    ), // H _R_R_II_FI b86 v2
    (
        0x6201FF00000000FF037431,
        "HFMA2.BF16_V2 R3, -RZ, RZ.INVALID5, 0, 0",
    ), // H _R_R_II_II b86 v1
    (
        0x6401FF00000000FF037431,
        "HFMA2.BF16_V2 R3, -RZ, RZ.INVALID6, 0, 0",
    ), // H _R_R_II_II b86 v2
];

#[test]
fn t285_1_structure() {
    const PARENTS: [&str; 3] = [
        "HFMA2_R_R_R_II_FI",
        "HFMA2_R_R_R_FI_FI",
        "HFMA2_R_R_R_II_II",
    ];
    const NEW_MGS: [&str; 12] = [
        "BF16_V2",
        "BF16_V2,FMZ",
        "BF16_V2,SAT",
        "BF16_V2,FMZ,SAT",
        "BF16_V2,FTZ",
        "BF16_V2,OOB",
        "BF16_V2,FTZ,SAT",
        "BF16_V2,OOB,SAT",
        "BF16_V2,RELU",
        "BF16_V2,FMZ,RELU",
        "BF16_V2,FTZ,RELU",
        "BF16_V2,OOB,RELU",
    ];
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for p in PARENTS {
            let e = &t.entries[p];
            let sig = p.strip_prefix("HFMA2_").unwrap();
            let base = &e.mod_groups[""];
            let ab0 = u128::from(base.and_base);
            assert_eq!((ab0 >> 85) & 1, 0, "{leg}|{p}: '' b85 drift");
            for nm in NEW_MGS {
                let g = e
                    .mod_groups
                    .get(nm)
                    .unwrap_or_else(|| panic!("{leg}|{p}|{nm}: mg missing"));
                let ab = u128::from(g.and_base);
                let vm = u128::from(g.variable_mask);
                assert_eq!((ab >> 85) & 1, 1, "{leg}|{p}|{nm}: b85 not baked");
                assert_eq!((vm >> 85) & 1, 0, "{leg}|{p}|{nm}: b85 variable");
                // suffix window [79:76] carved per-mg into and_base
                assert_eq!((vm >> 76) & 0xF, 0, "{leg}|{p}|{nm}: window left in vm");
                // fields shape == '' fields (tok3 arms carried: hsel@81,
                // abs@83, neg@84, h0nh1@86)
                assert_eq!(
                    g.fields.len(),
                    base.fields.len(),
                    "{leg}|{p}|{nm}: field count drift vs ''"
                );
                for (sh, bi, ex) in [
                    (81u32, 2u32, Extraction::HalfSel),
                    (83, 1, Extraction::Abs),
                    (84, 1, Extraction::Neg),
                    (86, 1, Extraction::H0NH1),
                ] {
                    assert!(
                        g.fields.iter().any(|f| f.shift == sh
                            && f.bits == bi
                            && f.extraction == ex
                            && f.token_idx == 3),
                        "{leg}|{p}|{nm}: tok3 ({sh},{bi}) field missing"
                    );
                }
            }
            // RELU PT-bake: ab carries b79|PT@87, no pred field
            let g = &e.mod_groups["BF16_V2,RELU"];
            let ab = u128::from(g.and_base);
            assert_eq!((ab >> 79) & 1, 1, "{leg}|{p}: RELU b79");
            assert_eq!((ab >> 87) & 7, 7, "{leg}|{p}: RELU PT bake");
            assert!(
                !g.fields.iter().any(|f| f.token_idx == 6),
                "{leg}|{p}: RELU mg carries pred field"
            );
            // dotted RELU _P keys (4 per sig)
            for dot in ["BF16_V2", "BF16_V2.FMZ", "BF16_V2.FTZ", "BF16_V2.OOB"] {
                let k = format!("HFMA2.{dot}.RELU_{sig}_P");
                let e = t
                    .entries
                    .get(k.as_str())
                    .unwrap_or_else(|| panic!("{leg}|{k}: key missing"));
                let g = &e.mod_groups[""];
                let ab = u128::from(g.and_base);
                let vm = u128::from(g.variable_mask);
                assert_eq!((ab >> 85) & 1, 1, "{leg}|{k}: b85");
                assert_eq!((ab >> 79) & 1, 1, "{leg}|{k}: b79");
                assert_eq!((vm >> 87) & 7, 7, "{leg}|{k}: pred window in vm");
                assert!(
                    g.fields
                        .iter()
                        .any(|f| f.shift == 87 && f.bits == 3 && f.token_idx == 6)
                        && g.fields
                            .iter()
                            .any(|f| f.shift == 90 && f.bits == 1 && f.token_idx == 6),
                    "{leg}|{k}: pred/inv fields"
                );
            }
        }
    }
    // donors byte-untouched: no BF16_V2 mg on these parents, no dotted keys
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        for p in PARENTS {
            if let Some(e) = t.entries.get(p) {
                assert!(
                    !e.mod_groups.keys().any(|k| k.starts_with("BF16_V2")),
                    "{leg}|{p}: donor touched"
                );
            }
        }
        assert!(
            !t.entries.keys().any(|k| k.starts_with("HFMA2.BF16_V2.")
                && k.ends_with("_P")
                && k.contains("RELU_R_R_R")),
            "{leg}: donor dotted key"
        );
    }
}

#[test]
fn t285_2_decode_law_vendor_exact() {
    const B85: u128 = 1 << 85;
    // sm120 = vendor-exact oracle. sm121a inherits the era II-host print
    // shape ('0x0' for a fixed tok4-II; the same shape the b85=0 era rows
    // print -- measured on pub e67ee9e, e.g. HFMA2.RELU_*_II_FI_P); equality
    // is asserted as cross-key parity: dec(w&~B85) with head 'HFMA2' ->
    // 'HFMA2.BF16_V2' must equal dec(w). Any real decode drift fails BOTH.
    let t120 = tab("sm120");
    for (w, want) in DECODE_LAW {
        let got = dec(&t120, w & M96).unwrap_or_else(|| panic!("sm120 word {w:#034x} hole"));
        assert_eq!(&got, want, "sm120 word {w:#034x}");
    }
    let t121 = tab("sm121a");
    for (w, want) in DECODE_LAW {
        let got = dec(&t121, w & M96).unwrap_or_else(|| panic!("sm121a word {w:#034x} hole"));
        if &got == want {
            continue;
        }
        let sib =
            dec(&t121, (w & !B85) & M96).unwrap_or_else(|| panic!("sm121a sibling {w:#034x} hole"));
        let norm = sib.replacen("HFMA2", "HFMA2.BF16_V2", 1);
        assert_eq!(got, norm,
            "sm121a word {w:#034x}: neither vendor-exact ({want:?}) nor              era-sibling parity ({norm:?})");
    }
}

#[test]
fn t285_3_hole_carriers_stay_hole() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (w, vend) in HOLE_CARRIERS {
            assert!(
                dec(&t, w & M96).is_none(),
                "{leg} word {w:#034x} (vendor {vend}) claimed"
            );
        }
    }
}

#[test]
fn t285_4_encode_law_and_roundtrip() {
    // (text, expected low96 word) -- words = verified arb285 mints.
    const CASES: &[(&str, u128)] = &[
        (
            "HFMA2.BF16_V2 R3, RZ, RZ, 0, 0",
            0x002000FF00000000FF037431u128,
        ), // F _R_R_FI_FI F=00
        (
            "HFMA2.BF16_V2.FMZ R3, RZ, RZ, 0, 0",
            0x002010FF00000000FF037431u128,
        ), // F _R_R_FI_FI F=01
        (
            "HFMA2.BF16_V2.SAT R3, RZ, RZ, 0, 0",
            0x002020FF00000000FF037431u128,
        ), // F _R_R_FI_FI F=02
        (
            "HFMA2.BF16_V2.FMZ.SAT R3, RZ, RZ, 0, 0",
            0x002030FF00000000FF037431u128,
        ), // F _R_R_FI_FI F=03
        (
            "HFMA2.BF16_V2.FTZ R3, RZ, RZ, 0, 0",
            0x002100FF00000000FF037431u128,
        ), // F _R_R_FI_FI F=16
        (
            "HFMA2.BF16_V2.OOB R3, RZ, RZ, 0, 0",
            0x002110FF00000000FF037431u128,
        ), // F _R_R_FI_FI F=17
        (
            "HFMA2.BF16_V2.FTZ.SAT R3, RZ, RZ, 0, 0",
            0x002120FF00000000FF037431u128,
        ), // F _R_R_FI_FI F=18
        (
            "HFMA2.BF16_V2.OOB.SAT R3, RZ, RZ, 0, 0",
            0x002130FF00000000FF037431u128,
        ), // F _R_R_FI_FI F=19
        (
            "HFMA2.BF16_V2 R3, RZ, |RZ|, 0, 0",
            0x002800FF00000000FF037431u128,
        ), // C _R_R_FI_FI t3abs
        (
            "HFMA2.BF16_V2 R3, RZ, -RZ, 0, 0",
            0x003000FF00000000FF037431u128,
        ), // C _R_R_FI_FI t3neg
        (
            "HFMA2.BF16_V2 R3, RZ, RZ.F32, 0, 0",
            0x002200FF00000000FF037431u128,
        ), // C _R_R_FI_FI t3v1
        (
            "HFMA2.BF16_V2 R3, RZ, RZ.H0_H0, 0, 0",
            0x002400FF00000000FF037431u128,
        ), // C _R_R_FI_FI t3v2
        (
            "HFMA2.BF16_V2 R3, RZ, RZ.H1_H1, 0, 0",
            0x002600FF00000000FF037431u128,
        ), // C _R_R_FI_FI t3v3
        (
            "HFMA2.BF16_V2 R3, RZ, -|RZ|.H0_H0, 0, 0",
            0x003C00FF00000000FF037431u128,
        ), // C _R_R_FI_FI t3v2absneg
        (
            "@P0 HFMA2.BF16_V2 R3, RZ, RZ, 0, 0",
            0x002000FF00000000FF030431u128,
        ), // G II_FI g0 F0
        (
            "@P5 HFMA2.BF16_V2.FTZ R3, RZ, RZ, 0, 0",
            0x002100FF00000000FF035431u128,
        ), // G II_FI g5 FTZ
        (
            "@P1 HFMA2.BF16_V2 R3, RZ, RZ, 0, 0",
            0x002000FF00000000FF031431u128,
        ), // G II_FI g1 F0
        (
            "HFMA2.BF16_V2.RELU R3, RZ, RZ, 0, 0, P3",
            0x01A080FF00000000FF037431u128,
        ), // R _R_R_FI_FI F=8 p3i0
        (
            "HFMA2.BF16_V2.RELU R3, RZ, RZ, 0, 0, P0",
            0x002080FF00000000FF037431u128,
        ), // R _R_R_FI_FI F=8 p0i0
        (
            "HFMA2.BF16_V2.FMZ.RELU R3, RZ, RZ, 0, 0, !P3",
            0x05A090FF00000000FF037431u128,
        ), // R _R_R_FI_FI F=9 p3i1
        (
            "HFMA2.BF16_V2.FTZ.RELU R3, RZ, RZ, 0, 0, P0",
            0x002180FF00000000FF037431u128,
        ), // R _R_R_FI_FI F=24 p0i0
        (
            "HFMA2.BF16_V2.OOB.RELU R3, RZ, RZ, 0, 0, P3",
            0x01A190FF00000000FF037431u128,
        ), // R _R_R_FI_FI F=25 p3i0
        (
            "HFMA2.BF16_V2.OOB.RELU R3, RZ, RZ, 0, 0",
            0x03A190FF00000000FF037431u128,
        ), // R _R_R_FI_FI F=25 p7i0
    ];
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (text, wantw) in CASES {
            let w = enc_res(&t, text).unwrap_or_else(|e| panic!("{leg}|{text}: encode {e}"));
            // cross-key parity with the b85=0 era sibling mint (absorbs the
            // pre-existing sm121a II_II-shape encode winner -- measured on
            // pub e67ee9e: 'HFMA2 R3, RZ, RZ, 0, 0' mints the 0x1ff (neg@72)
            // word there; 286-attachment, NOT a 285 graft defect). On sm120
            // the parity word equals the arb285 vendor word bit-exact.
            let sibtext = text
                .replacen(".BF16_V2.", ".", 1)
                .replacen(".BF16_V2 ", " ", 1);
            let ws = enc_res(&t, &sibtext)
                .unwrap_or_else(|e| panic!("{leg}|{sibtext}: sibling encode {e}"));
            assert_eq!(
                w & M96,
                (ws | (1 << 85)) & M96,
                "{leg}|{text}: cross-key mint drift (sibling {sibtext})"
            );
            if leg == "sm120" {
                assert_eq!(w & M96, *wantw, "{leg}|{text}: arb word drift");
            }
            let rt = dec(&t, w & M96).unwrap_or_else(|| panic!("{leg}|{text}: self-hole"));
            if leg == "sm120" {
                assert_eq!(rt, *text, "{leg}|{text}: roundtrip drift");
            } else {
                // sm121a era-shape parity: the II_II-shape mint re-decodes
                // with the era tok2 sign ('-RZ') exactly like the b85=0
                // sibling (286-attachment, pre-existing on pub e67ee9e).
                let rts = dec(&t, ws & M96)
                    .unwrap_or_else(|| panic!("{leg}|{sibtext}: sibling self-hole"));
                let norm = rts.replacen("HFMA2", "HFMA2.BF16_V2", 1);
                assert_eq!(rt, norm, "{leg}|{text}: sibling parity drift");
            }
        }
        // PT-elided RELU form: prints without trailing predicate
        let w = enc_res(&t, "HFMA2.BF16_V2.RELU R3, RZ, RZ, 0, 0")
            .unwrap_or_else(|e| panic!("{leg}: PT RELU {e}"));
        assert_eq!((w >> 87) & 7, 7, "{leg}: PT bake lost");
        let rt = dec(&t, w & M96).unwrap();
        if leg == "sm120" {
            assert_eq!(rt, "HFMA2.BF16_V2.RELU R3, RZ, RZ, 0, 0", "{leg}: PT elide");
        } else {
            // era II-shape parity (see above; pre-existing on pub e67ee9e)
            let ws = enc_res(&t, "HFMA2.RELU R3, RZ, RZ, 0, 0").unwrap();
            let norm = dec(&t, ws & M96)
                .unwrap()
                .replacen("HFMA2", "HFMA2.BF16_V2", 1);
            assert_eq!(rt, norm, "{leg}: PT elide parity");
        }
    }
}

#[test]
fn t285_5_fail_closed_and_anchors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // vendor-INVALID carriers fail closed (arb285 F/H sets, x4)
        for bad in [
            "HFMA2.BF16_V2.F32 R3, RZ, RZ, 0, 0",
            "HFMA2.BF16_V2.F32.SAT R3, RZ, RZ, 0, 0",
            "HFMA2.BF16_V2.SAT.RELU R3, RZ, RZ, 0, 0, P0",
            "HFMA2.BF16_V2.FTZ.SAT.RELU R3, RZ, RZ, 0, 0",
            "HFMA2.INVALID3 R3, RZ, RZ, 0, 0",
            "HFMA2.BF16_V2 R3, RZ, RZ.H0_H1, 0, 0",
            "HFMA2.BF16_V2 R3, RZ.INVALID1, RZ, 0, 0",
            "HFMA2.BF16_V2 R3, RZ, RZ.INVALID5, 0, 0",
        ] {
            assert!(enc_res(&t, bad).is_err(), "{leg}|{bad}: must fail closed");
        }
        // b85=0 family intact (279/271/306 anchors)
        let d0 = dec(&t, 0x000FC600000001FF00000000FF037431u128 & M96).expect("D0 hole");
        assert!(
            d0 == "HFMA2 R3, -RZ, RZ, 0, 0" || d0 == "HFMA2 R3, RZ, RZ, 0, 0",
            "{leg}: D0 drift: {d0}"
        );
        assert_eq!(
            dec(
                &t,
                (0x000FC000000000FF00000000FF037431u128 | (1 << 74)) & M96
            )
            .as_deref(),
            Some("HFMA2 R3, RZ.INVALID1, RZ, 0, 0"),
            "{leg}: 306 tok2 law lost"
        );
        // siblings untouched: 'HFMA2.SAT.RELU' (b85=0) stays fail-closed
        assert!(
            enc_res(&t, "HFMA2.SAT.RELU R3, RZ, RZ, 0, 0").is_err(),
            "{leg}: SAT+RELU b85=0 fail-closed lost"
        );
    }
    // donor legs: lattice BF16 word stays hole (donor freeze invariant)
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert!(
            dec(&t, 0xFC000002000FF00000000FF037431u128 & M96).is_none(),
            "{leg}: donor BF16 lattice decoded"
        );
    }
}
