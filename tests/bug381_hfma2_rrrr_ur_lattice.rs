//! BUG-381 (F2-iter203, loop5/blind front2, 2026-09-05): sparse-leg HFMA2
//! R_R_R_R (0x231 window) + R_R_UR_R (0x7c31 window) mod-lattice completion
//! vs the DENSE row set -- 34 new mgs (22 direct + 12 RELU pv7-bake) +
//! 12 RELU _P dotted keys (pred 3b@87 + inv@90 tok5) per family, legs
//! sm100a+sm103a (canonical graft patch381.py, a53eb20 -> 3cb31e4; ENGINE
//! src ZERO changes). Registered 381-kand LOW at 367.md sec.6 (F2-iter193).
//!
//! MEASUREMENT (pre-fix publish cubit_py-54f6f4de.so 93437b8c.., canonical
//! a53eb20; work/bug381/measure_pre381.json):
//!  (a) sparse DECODE of in-scope window words = LOUD HOLE 130/134 (4 OK =
//!      the carried plain/BF16_V2 cells); ZERO WRONG cells.
//!  (b) sparse ENCODE of 33/33 authored texts = loud REFUSE.
//!  (c) dense legs pre == vendor-exact 134/134 + 31/33 (2 FAIL = SAT.RELU
//!      kill + invented 'FTZ.OOB.SAT' -- correct loud refuse).
//! Graft corpus exposure measured by routex381 (battery ab240 2,406 cubins
//! x4 legs, OLD publish tables a53eb20 vs NEW): changed = 0.
//!
//! LAW: arb381 176 probes + arb381b 26 probes = 202, nvdisasm 13.3.73 raw
//! -b, x4 models SM100a/103a/120/121a AGREE on EVERY probe, DIVERGENT=0
//! (work/bug381/arb381_verdicts.json + arb381b_verdicts.json): b76 FMZ /
//! b77 SAT / b78 F32 / b79 RELU / b80 FTZ / b85 BF16_V2 / OOB = fused
//! b76+b80; RELU mgs bake pv7 (PT-elided); dotted keys carry pred 3b@87 +
//! inv@90 tok5 (pv0..6 ', Pv' / pv7+inv0 elides / pv7+inv1 '!PT' / pv+inv
//! '!Pv'). KILLS stay HOLE fail-closed all legs: SATxRELU any combo
//! (rc=1), b91 on 0x231 (rc=1), F32xBF16 INVALID3-285, stray b90/pv w/o
//! b79 + b92/93/95 vendor-INERT (289 doctrine). BF16-class rows clone the
//! local BF16_V2 donor geometry (vm {22,31,39,72} + neg@72 tok2 on the
//! sparse 0x231 BF16 row), plain-class the '' donor.
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const B79: u128 = 1 << 79;
const PVF: u128 = 0xf << 87;
const SPARSE: [&str; 2] = ["sm100a", "sm103a"];
const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
const FAMS: [&str; 2] = ["HFMA2_R_R_R_R", "HFMA2_R_R_UR_R"];
const DOTMODS: [&str; 12] = [
    "RELU",
    "F32.RELU",
    "FMZ.RELU",
    "FTZ.RELU",
    "OOB.RELU",
    "BF16_V2.RELU",
    "F32.FMZ.RELU",
    "F32.FTZ.RELU",
    "F32.OOB.RELU",
    "BF16_V2.FMZ.RELU",
    "BF16_V2.FTZ.RELU",
    "BF16_V2.OOB.RELU",
];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    DecodeIndex::build(t)
        .decode(w & M96, 0, t)
        .map(|d| to_sass(&d))
        .ok()
        .map(|s| s.trim_end().trim_end_matches(';').to_string())
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}

const R4_CELLS: [(u128, &str); 36] = [
    (0x50000000403020231u128, "@P0 HFMA2 R2, R3, R4, R5"),
    (
        0x2000050000000403020231u128,
        "@P0 HFMA2.BF16_V2 R2, R3, R4, R5",
    ),
    (0x40050000000403020231u128, "@P0 HFMA2.F32 R2, R3, R4, R5"),
    (0x10050000000403020231u128, "@P0 HFMA2.FMZ R2, R3, R4, R5"),
    (
        0x50050000000403020231u128,
        "@P0 HFMA2.F32.FMZ R2, R3, R4, R5",
    ),
    (0x20050000000403020231u128, "@P0 HFMA2.SAT R2, R3, R4, R5"),
    (
        0x30050000000403020231u128,
        "@P0 HFMA2.FMZ.SAT R2, R3, R4, R5",
    ),
    (
        0x60050000000403020231u128,
        "@P0 HFMA2.F32.SAT R2, R3, R4, R5",
    ),
    (
        0x70050000000403020231u128,
        "@P0 HFMA2.F32.FMZ.SAT R2, R3, R4, R5",
    ),
    (0x100050000000403020231u128, "@P0 HFMA2.FTZ R2, R3, R4, R5"),
    (0x110050000000403020231u128, "@P0 HFMA2.OOB R2, R3, R4, R5"),
    (
        0x120050000000403020231u128,
        "@P0 HFMA2.FTZ.SAT R2, R3, R4, R5",
    ),
    (
        0x130050000000403020231u128,
        "@P0 HFMA2.OOB.SAT R2, R3, R4, R5",
    ),
    (
        0x140050000000403020231u128,
        "@P0 HFMA2.F32.FTZ R2, R3, R4, R5",
    ),
    (
        0x150050000000403020231u128,
        "@P0 HFMA2.F32.OOB R2, R3, R4, R5",
    ),
    (
        0x160050000000403020231u128,
        "@P0 HFMA2.F32.FTZ.SAT R2, R3, R4, R5",
    ),
    (
        0x170050000000403020231u128,
        "@P0 HFMA2.F32.OOB.SAT R2, R3, R4, R5",
    ),
    (
        0x2010050000000403020231u128,
        "@P0 HFMA2.BF16_V2.FMZ R2, R3, R4, R5",
    ),
    (
        0x2020050000000403020231u128,
        "@P0 HFMA2.BF16_V2.SAT R2, R3, R4, R5",
    ),
    (
        0x2030050000000403020231u128,
        "@P0 HFMA2.BF16_V2.FMZ.SAT R2, R3, R4, R5",
    ),
    (
        0x2100050000000403020231u128,
        "@P0 HFMA2.BF16_V2.FTZ R2, R3, R4, R5",
    ),
    (
        0x2110050000000403020231u128,
        "@P0 HFMA2.BF16_V2.OOB R2, R3, R4, R5",
    ),
    (
        0x2120050000000403020231u128,
        "@P0 HFMA2.BF16_V2.FTZ.SAT R2, R3, R4, R5",
    ),
    (
        0x2130050000000403020231u128,
        "@P0 HFMA2.BF16_V2.OOB.SAT R2, R3, R4, R5",
    ),
    (
        0x38080050000000403020231u128,
        "@P0 HFMA2.RELU R2, R3, R4, R5",
    ),
    (
        0x380c0050000000403020231u128,
        "@P0 HFMA2.F32.RELU R2, R3, R4, R5",
    ),
    (
        0x38090050000000403020231u128,
        "@P0 HFMA2.FMZ.RELU R2, R3, R4, R5",
    ),
    (
        0x380d0050000000403020231u128,
        "@P0 HFMA2.F32.FMZ.RELU R2, R3, R4, R5",
    ),
    (
        0x38180050000000403020231u128,
        "@P0 HFMA2.FTZ.RELU R2, R3, R4, R5",
    ),
    (
        0x38190050000000403020231u128,
        "@P0 HFMA2.OOB.RELU R2, R3, R4, R5",
    ),
    (
        0x381c0050000000403020231u128,
        "@P0 HFMA2.F32.FTZ.RELU R2, R3, R4, R5",
    ),
    (
        0x381d0050000000403020231u128,
        "@P0 HFMA2.F32.OOB.RELU R2, R3, R4, R5",
    ),
    (
        0x3a080050000000403020231u128,
        "@P0 HFMA2.BF16_V2.RELU R2, R3, R4, R5",
    ),
    (
        0x3a090050000000403020231u128,
        "@P0 HFMA2.BF16_V2.FMZ.RELU R2, R3, R4, R5",
    ),
    (
        0x3a180050000000403020231u128,
        "@P0 HFMA2.BF16_V2.FTZ.RELU R2, R3, R4, R5",
    ),
    (
        0x3a190050000000403020231u128,
        "@P0 HFMA2.BF16_V2.OOB.RELU R2, R3, R4, R5",
    ),
];

const UR_CELLS: [(u128, &str); 36] = [
    (0x80000050000000403027c31u128, "HFMA2 R2, R3, UR4, R5"),
    (
        0x82000050000000403027c31u128,
        "HFMA2.BF16_V2 R2, R3, UR4, R5",
    ),
    (0x80040050000000403027c31u128, "HFMA2.F32 R2, R3, UR4, R5"),
    (0x80010050000000403027c31u128, "HFMA2.FMZ R2, R3, UR4, R5"),
    (
        0x80050050000000403027c31u128,
        "HFMA2.F32.FMZ R2, R3, UR4, R5",
    ),
    (0x80020050000000403027c31u128, "HFMA2.SAT R2, R3, UR4, R5"),
    (
        0x80030050000000403027c31u128,
        "HFMA2.FMZ.SAT R2, R3, UR4, R5",
    ),
    (
        0x80060050000000403027c31u128,
        "HFMA2.F32.SAT R2, R3, UR4, R5",
    ),
    (
        0x80070050000000403027c31u128,
        "HFMA2.F32.FMZ.SAT R2, R3, UR4, R5",
    ),
    (0x80100050000000403027c31u128, "HFMA2.FTZ R2, R3, UR4, R5"),
    (0x80110050000000403027c31u128, "HFMA2.OOB R2, R3, UR4, R5"),
    (
        0x80120050000000403027c31u128,
        "HFMA2.FTZ.SAT R2, R3, UR4, R5",
    ),
    (
        0x80130050000000403027c31u128,
        "HFMA2.OOB.SAT R2, R3, UR4, R5",
    ),
    (
        0x80140050000000403027c31u128,
        "HFMA2.F32.FTZ R2, R3, UR4, R5",
    ),
    (
        0x80150050000000403027c31u128,
        "HFMA2.F32.OOB R2, R3, UR4, R5",
    ),
    (
        0x80160050000000403027c31u128,
        "HFMA2.F32.FTZ.SAT R2, R3, UR4, R5",
    ),
    (
        0x80170050000000403027c31u128,
        "HFMA2.F32.OOB.SAT R2, R3, UR4, R5",
    ),
    (
        0x82010050000000403027c31u128,
        "HFMA2.BF16_V2.FMZ R2, R3, UR4, R5",
    ),
    (
        0x82020050000000403027c31u128,
        "HFMA2.BF16_V2.SAT R2, R3, UR4, R5",
    ),
    (
        0x82030050000000403027c31u128,
        "HFMA2.BF16_V2.FMZ.SAT R2, R3, UR4, R5",
    ),
    (
        0x82100050000000403027c31u128,
        "HFMA2.BF16_V2.FTZ R2, R3, UR4, R5",
    ),
    (
        0x82110050000000403027c31u128,
        "HFMA2.BF16_V2.OOB R2, R3, UR4, R5",
    ),
    (
        0x82120050000000403027c31u128,
        "HFMA2.BF16_V2.FTZ.SAT R2, R3, UR4, R5",
    ),
    (
        0x82130050000000403027c31u128,
        "HFMA2.BF16_V2.OOB.SAT R2, R3, UR4, R5",
    ),
    (0xb8080050000000403027c31u128, "HFMA2.RELU R2, R3, UR4, R5"),
    (
        0xb80c0050000000403027c31u128,
        "HFMA2.F32.RELU R2, R3, UR4, R5",
    ),
    (
        0xb8090050000000403027c31u128,
        "HFMA2.FMZ.RELU R2, R3, UR4, R5",
    ),
    (
        0xb80d0050000000403027c31u128,
        "HFMA2.F32.FMZ.RELU R2, R3, UR4, R5",
    ),
    (
        0xb8180050000000403027c31u128,
        "HFMA2.FTZ.RELU R2, R3, UR4, R5",
    ),
    (
        0xb8190050000000403027c31u128,
        "HFMA2.OOB.RELU R2, R3, UR4, R5",
    ),
    (
        0xb81c0050000000403027c31u128,
        "HFMA2.F32.FTZ.RELU R2, R3, UR4, R5",
    ),
    (
        0xb81d0050000000403027c31u128,
        "HFMA2.F32.OOB.RELU R2, R3, UR4, R5",
    ),
    (
        0xba080050000000403027c31u128,
        "HFMA2.BF16_V2.RELU R2, R3, UR4, R5",
    ),
    (
        0xba090050000000403027c31u128,
        "HFMA2.BF16_V2.FMZ.RELU R2, R3, UR4, R5",
    ),
    (
        0xba180050000000403027c31u128,
        "HFMA2.BF16_V2.FTZ.RELU R2, R3, UR4, R5",
    ),
    (
        0xba190050000000403027c31u128,
        "HFMA2.BF16_V2.OOB.RELU R2, R3, UR4, R5",
    ),
];

const R4_DOTS: [(u128, &str); 12] = [
    (
        0x10080050000000403020231u128,
        "@P0 HFMA2.RELU R2, R3, R4, R5, P2",
    ),
    (
        0x100c0050000000403020231u128,
        "@P0 HFMA2.F32.RELU R2, R3, R4, R5, P2",
    ),
    (
        0x10090050000000403020231u128,
        "@P0 HFMA2.FMZ.RELU R2, R3, R4, R5, P2",
    ),
    (
        0x10180050000000403020231u128,
        "@P0 HFMA2.FTZ.RELU R2, R3, R4, R5, P2",
    ),
    (
        0x10190050000000403020231u128,
        "@P0 HFMA2.OOB.RELU R2, R3, R4, R5, P2",
    ),
    (
        0x12080050000000403020231u128,
        "@P0 HFMA2.BF16_V2.RELU R2, R3, R4, R5, P2",
    ),
    (
        0x100d0050000000403020231u128,
        "@P0 HFMA2.F32.FMZ.RELU R2, R3, R4, R5, P2",
    ),
    (
        0x101c0050000000403020231u128,
        "@P0 HFMA2.F32.FTZ.RELU R2, R3, R4, R5, P2",
    ),
    (
        0x101d0050000000403020231u128,
        "@P0 HFMA2.F32.OOB.RELU R2, R3, R4, R5, P2",
    ),
    (
        0x12090050000000403020231u128,
        "@P0 HFMA2.BF16_V2.FMZ.RELU R2, R3, R4, R5, P2",
    ),
    (
        0x12180050000000403020231u128,
        "@P0 HFMA2.BF16_V2.FTZ.RELU R2, R3, R4, R5, P2",
    ),
    (
        0x12190050000000403020231u128,
        "@P0 HFMA2.BF16_V2.OOB.RELU R2, R3, R4, R5, P2",
    ),
];

const UR_DOTS: [(u128, &str); 12] = [
    (
        0x90080050000000403027c31u128,
        "HFMA2.RELU R2, R3, UR4, R5, P2",
    ),
    (
        0x900c0050000000403027c31u128,
        "HFMA2.F32.RELU R2, R3, UR4, R5, P2",
    ),
    (
        0x90090050000000403027c31u128,
        "HFMA2.FMZ.RELU R2, R3, UR4, R5, P2",
    ),
    (
        0x90180050000000403027c31u128,
        "HFMA2.FTZ.RELU R2, R3, UR4, R5, P2",
    ),
    (
        0x90190050000000403027c31u128,
        "HFMA2.OOB.RELU R2, R3, UR4, R5, P2",
    ),
    (
        0x92080050000000403027c31u128,
        "HFMA2.BF16_V2.RELU R2, R3, UR4, R5, P2",
    ),
    (
        0x900d0050000000403027c31u128,
        "HFMA2.F32.FMZ.RELU R2, R3, UR4, R5, P2",
    ),
    (
        0x901c0050000000403027c31u128,
        "HFMA2.F32.FTZ.RELU R2, R3, UR4, R5, P2",
    ),
    (
        0x901d0050000000403027c31u128,
        "HFMA2.F32.OOB.RELU R2, R3, UR4, R5, P2",
    ),
    (
        0x92090050000000403027c31u128,
        "HFMA2.BF16_V2.FMZ.RELU R2, R3, UR4, R5, P2",
    ),
    (
        0x92180050000000403027c31u128,
        "HFMA2.BF16_V2.FTZ.RELU R2, R3, UR4, R5, P2",
    ),
    (
        0x92190050000000403027c31u128,
        "HFMA2.BF16_V2.OOB.RELU R2, R3, UR4, R5, P2",
    ),
];

const PV_LAW: [(u128, &str); 16] = [
    (
        0x180050000000403020231u128,
        "@P0 HFMA2.FTZ.RELU R2, R3, R4, R5, P0",
    ), // PVR4_FTZ_RELU_0
    (
        0x10180050000000403020231u128,
        "@P0 HFMA2.FTZ.RELU R2, R3, R4, R5, P2",
    ), // PVR4_FTZ_RELU_2
    (
        0x30180050000000403020231u128,
        "@P0 HFMA2.FTZ.RELU R2, R3, R4, R5, P6",
    ), // PVR4_FTZ_RELU_6
    (
        0x38180050000000403020231u128,
        "@P0 HFMA2.FTZ.RELU R2, R3, R4, R5",
    ), // PVR4_FTZ_RELU_7
    (
        0x78180050000000403020231u128,
        "@P0 HFMA2.FTZ.RELU R2, R3, R4, R5, !PT",
    ), // PVR4_FTZ_RELU_7inv
    (
        0x58180050000000403020231u128,
        "@P0 HFMA2.FTZ.RELU R2, R3, R4, R5, !P3",
    ), // PVR4_FTZ_RELU_inv3
    (
        0x80190050000000403027c31u128,
        "HFMA2.OOB.RELU R2, R3, UR4, R5, P0",
    ), // PVUR_OOB_RELU_0
    (
        0x98190050000000403027c31u128,
        "HFMA2.OOB.RELU R2, R3, UR4, R5, P3",
    ), // PVUR_OOB_RELU_3
    (
        0xb0190050000000403027c31u128,
        "HFMA2.OOB.RELU R2, R3, UR4, R5, P6",
    ), // PVUR_OOB_RELU_6
    (
        0xb8190050000000403027c31u128,
        "HFMA2.OOB.RELU R2, R3, UR4, R5",
    ), // PVUR_OOB_RELU_7
    (
        0xf8190050000000403027c31u128,
        "HFMA2.OOB.RELU R2, R3, UR4, R5, !PT",
    ), // PVUR_OOB_RELU_7inv
    (
        0xd8190050000000403027c31u128,
        "HFMA2.OOB.RELU R2, R3, UR4, R5, !P3",
    ), // PVUR_OOB_RELU_inv3
    (
        0x10080050000000403020231u128,
        "@P0 HFMA2.RELU R2, R3, R4, R5, P2",
    ), // PVR4_plain_2
    (
        0x38080050000000403020231u128,
        "@P0 HFMA2.RELU R2, R3, R4, R5",
    ), // PVR4_plain_7
    (
        0x90080050000000403027c31u128,
        "HFMA2.RELU R2, R3, UR4, R5, P2",
    ), // PVUR_plain_2
    (0xb8080050000000403027c31u128, "HFMA2.RELU R2, R3, UR4, R5"), // PVUR_plain_7
];

const MINTS: [(&str, u128); 12] = [
    ("HFMA2.SAT R2, R3, R4, R5", 0x20050000000403027231u128), // pt-guard bake on no-guard authored text (witness probe g0)
    ("HFMA2.OOB R2, R3, R4, R5", 0x110050000000403027231u128), // pt-guard bake on no-guard authored text (witness probe g0)
    (
        "HFMA2.F32.FTZ.SAT R2, R3, R4, R5",
        0x160050000000403027231u128,
    ), // pt-guard bake on no-guard authored text (witness probe g0)
    (
        "HFMA2.BF16_V2.OOB.SAT R2, R3, R4, R5",
        0x2130050000000403027231u128,
    ), // pt-guard bake on no-guard authored text (witness probe g0)
    ("HFMA2.SAT R2, R3, UR4, R5", 0x80020050000000403027c31u128), // pt-guard bake on no-guard authored text (witness probe g0)
    (
        "HFMA2.F32.FTZ R2, R3, UR4, R5",
        0x80140050000000403027c31u128,
    ), // pt-guard bake on no-guard authored text (witness probe g0)
    (
        "HFMA2.BF16_V2.OOB.SAT R2, R3, UR4, R5",
        0x82130050000000403027c31u128,
    ), // pt-guard bake on no-guard authored text (witness probe g0)
    (
        "HFMA2.FTZ.RELU R2, R3, R4, R5, P1",
        0x8180050000000403027231u128,
    ), // pt-guard bake on no-guard authored text (witness probe g0)
    (
        "HFMA2.OOB.RELU R2, R3, UR4, R5, P2",
        0x90190050000000403027c31u128,
    ), // pt-guard bake on no-guard authored text (witness probe g0)
    ("HFMA2.RELU R2, R3, R4, R5", 0x38080050000000403027231u128), // pt-guard bake on no-guard authored text (witness probe g0)
    (
        "HFMA2.F32.RELU R2, R3, UR4, R5",
        0xb80c0050000000403027c31u128,
    ), // pt-guard bake on no-guard authored text (witness probe g0)
    (
        "HFMA2.BF16_V2.FTZ.RELU R2, R3, R4, R5, !P2",
        0x52180050000000403027231u128,
    ), // pt-guard bake on no-guard authored text (witness probe g0)
];

const KILLS: [(&str, u128); 9] = [
    ("K4_SATxRELU", 0x380a0050000000403020231u128),
    ("K4_SATxRELUxFTZ", 0x381a0050000000403020231u128),
    ("KU_SATxRELU", 0xb80a0050000000403027c31u128),
    ("K4_b91", 0x80000050000000403020231u128),
    ("K4_b91xSAT", 0x80020050000000403020231u128),
    ("KU_strayb90", 0xc0020050000000403027c31u128),
    ("KU_straypv2", 0x90000050000000403027c31u128),
    ("K4_F32xBF16", 0x2040050000000403020231u128),
    ("KU_b92", 0x180000050000000403027c31u128),
];

const SIGNS: [(&str, u128, &str); 3] = [
    (
        "K4_b63",
        0x58000000403020231u128,
        "@P0 HFMA2 R2, R3, -R4, R5",
    ),
    (
        "K4_b62",
        0x54000000403020231u128,
        "@P0 HFMA2 R2, R3, |R4|, R5",
    ),
    (
        "KU_b83",
        0x80800050000000403027c31u128,
        "HFMA2 R2, R3, UR4, |R5|",
    ),
];

#[test]
fn t381_1_structure_lattice_completion() {
    let dense = tab("sm120");
    for fam in FAMS {
        let dnames: std::collections::BTreeSet<&String> =
            dense.entries[fam].mod_groups.keys().collect();
        assert_eq!(dnames.len(), 36, "dense {fam}: lattice drift");
        for leg in SPARSE {
            let t = tab(leg);
            let e = &t.entries[fam];
            let snames: std::collections::BTreeSet<&String> = e.mod_groups.keys().collect();
            assert_eq!(snames, dnames, "{leg}:{fam}: sparse mg set != dense");
            assert_eq!(e.mod_groups.len(), 36, "{leg}:{fam}: mg count drift");
            let pl = &e.mod_groups[""];
            let bf = &e.mod_groups["BF16_V2"];
            assert_eq!(bf.and_base ^ pl.and_base, 1 << 85, "{leg}:{fam}: BF16 law");
            for (name, mg) in &e.mod_groups {
                if name.is_empty() || name.as_str() == "BF16_V2" {
                    continue;
                }
                let isbf = name.contains("BF16_V2");
                let donor = if isbf { bf } else { pl };
                let relu = name.contains("RELU");
                let mut want = mg.and_base ^ donor.and_base;
                want &= !(1 << 85); // donor-relative
                let mut law = 0u128;
                for part in name.split(',') {
                    match part {
                        "F32" => law |= 1 << 78,
                        "FMZ" => law |= 1 << 76,
                        "SAT" => law |= 1 << 77,
                        "FTZ" => law |= 1 << 80,
                        "OOB" => law |= 1 << 76 | 1 << 80,
                        "BF16_V2" | "RELU" => {}
                        other => panic!("law: unknown part {other}"),
                    }
                }
                if relu {
                    law |= B79 | (0x7 << 87);
                }
                assert_eq!(want, law, "{leg}:{fam}:{name}: ab delta drift");
                // FLIP (BUG-393 / F2-iter214, canonical 8f2571b): the
                // inert-window closure relaxes donor vm by
                // [55:40]|[59:56]|[87:90]|[92:95]; RELU mgs get the same
                // MINUS the pv window (measured LIVE pred-elision there:
                // f87->P6 f88->P5 f89->P3 f90->!PT x4 legs AGREE,
                // work/bug393/measure393_closure.json).
                let want_vm = if relu {
                    donor.variable_mask & !(0xfu128 << 87)
                } else {
                    donor.variable_mask
                };
                assert_eq!(
                    mg.variable_mask, want_vm,
                    "{leg}:{fam}:{name}: vm delta drift beyond 393 closure law"
                );
                assert_eq!(
                    mg.fields.len(),
                    donor.fields.len(),
                    "{leg}:{fam}:{name}: field-set drift"
                );
            }
            // dotted _P keys: 12 per family, per-name delta law vs their lane
            for mods in DOTMODS {
                let dk = format!("HFMA2.{mods}_{}_P", &fam["HFMA2_".len()..]);
                let d = t
                    .entries
                    .get(&dk)
                    .unwrap_or_else(|| panic!("{leg}:{dk} missing"));
                let lane_name = mods
                    .split('.')
                    .filter(|m| *m != "RELU")
                    .collect::<Vec<_>>()
                    .join(",");
                let lane = &e.mod_groups[lane_name.as_str()];
                let dg = &d.mod_groups[""];
                assert_eq!(dg.and_base, lane.and_base | B79, "{leg}:{dk}: ab law");
                assert_eq!(dg.and_base & PVF, 0, "{leg}:{dk}: pv baked into dotted ab");
                // FLIP (BUG-393 / F2-iter214, canonical 8f2571b): lane vm
                // gained the full closure relax, so the pv delta cancels
                // (PVF is now in BOTH operands) and what remains is the
                // non-pv window relax: [55:40]|[59:56]|[92:95] (SPARSE
                // legs; dense lanes already had [55:40] relaxed pre-393,
                // so dense reads [59:56]|[92:95] -- this loop is SPARSE).
                const DOTTED_XOR_393: u128 = 0xf00000000fffff0000000000u128;
                // the 0x7c31 UR family is OUT of 393's scope (unmeasured
                // lattice; 391/395 tail) and keeps the pre-393 PVF law.
                let want_xor = if fam == "HFMA2_R_R_R_R" {
                    DOTTED_XOR_393
                } else {
                    PVF
                };
                assert_eq!(
                    dg.variable_mask ^ lane.variable_mask,
                    want_xor,
                    "{leg}:{dk}: vm law beyond 393 closure"
                );
                let extras: Vec<_> = dg
                    .fields
                    .iter()
                    .filter(|f| {
                        !lane.fields.iter().any(|g| {
                            g.bits == f.bits
                                && g.shift == f.shift
                                && g.token_idx == f.token_idx
                                && g.extraction == f.extraction
                        })
                    })
                    .collect();
                assert_eq!(extras.len(), 2, "{leg}:{dk}: extras count drift");
                use cubit::table::Extraction;
                assert!(
                    extras.iter().any(|f| f.extraction == Extraction::Pred
                        && f.bits == 3
                        && f.shift == 87
                        && f.token_idx == 5),
                    "{leg}:{dk}: pred 3b@87 tok5 missing"
                );
                assert!(
                    extras.iter().any(|f| f.extraction == Extraction::Inv
                        && f.bits == 1
                        && f.shift == 90
                        && f.token_idx == 5),
                    "{leg}:{dk}: inv 1b@90 tok5 missing"
                );
            }
        }
    }
}

#[test]
fn t381_2_decode_battery_vendor_exact() {
    for leg in LEGS {
        let t = tab(leg);
        for (w, want) in R4_CELLS.iter().chain(UR_CELLS.iter()) {
            let got = dec(&t, *w).unwrap_or_else(|| panic!("{leg}: HOLE on {want}"));
            assert_eq!(&got, want, "{leg}: decode drift for {want} (w={w:#x})");
        }
    }
}

#[test]
fn t381_3_dotted_pv_decode_law() {
    for leg in LEGS {
        let t = tab(leg);
        for (w, want) in R4_DOTS.iter().chain(UR_DOTS.iter()) {
            let got = dec(&t, *w).unwrap_or_else(|| panic!("{leg}: HOLE on {want}"));
            assert_eq!(&got, want, "{leg}: dotted pv drift for {want}");
        }
        // pv sweep law on FTZ.RELU / OOB.RELU carriers (arb381 PV section)
        for (w, want) in PV_LAW.iter() {
            let got = dec(&t, *w).unwrap_or_else(|| panic!("{leg}: HOLE on {want}"));
            assert_eq!(&got, want, "{leg}: pv-law drift for {want}");
        }
    }
}

#[test]
fn t381_4_authored_mints_word_exact() {
    for leg in SPARSE {
        let t = tab(leg);
        for (text, w) in MINTS.iter() {
            let got = enc(&t, text).unwrap_or_else(|e| panic!("{leg}: REFUSE on {text}: {e}"));
            assert_eq!(got & M96, w & M96, "{leg}: mint word drift for {text}");
            let back = dec(&t, got).unwrap_or_else(|| panic!("{leg}: roundtrip HOLE {text}"));
            assert_eq!(&back, text, "{leg}: roundtrip text drift for {text}");
        }
    }
}

// FLIP (BUG-393 / F2-iter214, canonical 8f2571b): the five stray-window
// words below were kill-pins under the 289 fail-closed doctrine; the
// measured vendor law (nvdisasm 13.3.73 raw -b, these exact words, x4
// models AGREE) renders the bare lane text, and the engine now matches
// it <-- lawful-accept. KU_ strays on the 0x7c31 UR lattice STAY dead
// (the UR family is out of 393's scope -- 391/395 tail).
const LAWFUL_393: [(&str, u128, &str); 5] = [
    (
        "K4_strayb90",
        0x40020050000000403020231u128,
        "@P0 HFMA2.SAT R2, R3, R4, R5",
    ),
    (
        "K4_straypv2",
        0x10000050000000403020231u128,
        "@P0 HFMA2 R2, R3, R4, R5",
    ),
    (
        "K4_b92",
        0x100000050000000403020231u128,
        "@P0 HFMA2 R2, R3, R4, R5",
    ),
    (
        "K4_b93",
        0x200000050000000403020231u128,
        "@P0 HFMA2 R2, R3, R4, R5",
    ),
    (
        "K4_b95",
        0x800000050000000403020231u128,
        "@P0 HFMA2 R2, R3, R4, R5",
    ),
];

#[test]
fn t381_5_kills_fail_closed() {
    for leg in LEGS {
        let t = tab(leg);
        for (tag, w) in KILLS.iter() {
            assert!(dec(&t, *w).is_none(), "{leg}:{tag}: kill word decoded");
        }
        for (tag, w, want) in LAWFUL_393.iter() {
            let got = dec(&t, *w).unwrap_or_else(|| panic!("{leg}:{tag}: lawful-inert word HOLE"));
            assert_eq!(&got, want, "{leg}:{tag}: lawful-inert text drift");
        }
        for text in [
            "HFMA2.SAT.RELU R2, R3, R4, R5",
            "HFMA2.SAT.RELU R2, R3, UR4, R5",
        ] {
            assert!(enc(&t, text).is_err(), "{leg}: kill text encoded: {text}");
        }
        // sign-field guard rail: these decode vendor-exact already pre-graft
        for (tag, w, want) in SIGNS.iter() {
            let got = dec(&t, *w).unwrap_or_else(|| panic!("{leg}:{tag}: sign HOLE"));
            assert_eq!(&got, want, "{leg}:{tag}: sign decode drift");
        }
    }
    // census/source pins
    for leg in SPARSE {
        let t = tab(leg);
        assert_eq!(
            t.entries.len(),
            635,
            "{leg}: key census drift (635 = 632 + 3 BUG-450 keys [donor-clone sm121a non-NA dARI EFL2.256; canonical 589be87 ride F2-iter255]; 632 = 612 + 20 BUG-447 keys [donor-clone sm121a NA-ARURI EFL2.256; canonical 099faa0 ride F2-iter252]; 612 = 593 + 19 BUG-443 keys [8 T2 + 11 T3 STG other-family enum keys; STS S8/S16 stay mgs; canonical e8d1af3 ride F2-iter250]; was 593 = 590 + 3 BUG-435 keys [LD_R_dARI_P + LDG_P_R_dARI{{,_P}} per sparse leg], canonical 0a6b178; was 590 = 576 + 13 BUG-419 + 1 BUG-413(ii))"
        );
        for fam in FAMS {
            assert_eq!(
                t.entries[fam].mod_groups.len(),
                36,
                "{leg}:{fam}: mg census"
            );
        }
        let mut ndot = 0usize;
        for mods in DOTMODS {
            for fam in FAMS {
                let dk = format!("HFMA2.{mods}_{}_P", &fam["HFMA2_".len()..]);
                if t.entries.contains_key(&dk) {
                    ndot += 1;
                }
            }
        }
        assert_eq!(ndot, 24, "{leg}: dotted _P census drift");
    }
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    // [FLIP with attribution, BUG-386 / F2-iter204]: manifest pin moves
    // [FLIP with attribution, BUG-409 / F2-iter224]: manifest pin moves
    // with the canonical sm100a LDC_R_cAI|S16 vm|b37 graft (+cubit decoder arm).
    // with the canonical base-gap lattice graft.
    // [FLIP with attribution, BUG-405/406 / F2-iter222]: manifest pin moves
    // with the 0x7c31 h0nh1 graft (canonical d908ee9 = BUG-395; rides 74a06b7 = BUG-405/406 HADD2 release + HFMA2 two-imm slot graft; rides 19363f6 = BUG-400, which rode 5d32aec = BUG-398, 96f196b = BUG-402, dd477eb = BUG-407, 8f2571b = BUG-393).
    assert!(
        // [FLIP with attribution, BUG-384 / F2-iter205]: manifest pin moves with the canonical era-key hygiene delete.
        m["base_revision"].as_str().unwrap().starts_with("9b60b92"),
        "SOURCE.json must pin canonical 57e7ecd [was ffa3244 = BUG-441, bb1ba6c = BUG-438, 54c5b02 = BUG-439, 3032686 = BUG-423, 61858fb = BUG-433, 0a6b178 = BUG-435+434+435b, 1810912 = 435+434 hop, 70eb0fe = BUG-416, 52cb73c = BUG-425+425b, 3f6ca6f = BUG-425, 616f185 = BUG-429, a5e6d0a = BUG-427, 2a631d5 = BUG-426, 291ed59b = BUG-424, 13e13b6 = BUG-421+422] (BUG-442 graft F2-iter246 z atrybucja; ride-chain): {:?}",
        m["base_revision"]
    );
}
