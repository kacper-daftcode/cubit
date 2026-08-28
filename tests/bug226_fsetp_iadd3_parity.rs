//! BUG-226 (F2-iter110, front2/blind, 2026-08-27): sm120 vendor-parity
//! patch 1 — FSETP bool-op window {b75,b74} + IADD3 .X gate b74 (canonical
//! 4704d57; patch226.py replayable+idempotent).
//!
//! Defect (measured, work/bug226): 57 prio-3-matched sm120 rows held 6,497
//! corpus words; 3,910 rendered WRONG vs nvdisasm 13.3.73 (truth table
//! verify225 pass-3, ctrl-aware verified hit226v2). Two classes repaired:
//!
//!   A. sm120 FSETP rows left the bool-op lattice {b75,b74} unpinned and
//!      lacked the abs/neg fields, so vendor-OR/XOR words fell through to
//!      the prio-3 sign-tolerant tier and printed `.AND` (or sat on a bare
//!      key with an off-by-one ureg field). Law (graft arb226 x{100a,120a},
//!      print-identical, so sm100a donor-clone is lawful): {b75,b74} =
//!      00=AND 01=OR 10=XOR 11=INVALID3; cmp b76..79; FTZ b80; destP@81,
//!      P1@84, P5@87+neg@90; Ra@24+neg@72+abs@73; Rb@32+abs@62+neg@63
//!      (R_II: f32 imm @32..63; R_UR bare: ureg 8b@32). b91 must be 0.
//!   B. sm120 IADD3_R_P_P_R_UR_R lacked the P2@84 field (bits 84..86 baked
//!      constant 0), so every P2!=PT-sibling word missed strict and fell to
//!      the 8-operand .X key via prio-3: printed "IADD3.X ..., !PT, !PT"
//!      while vendor prints plain 6-operand IADD3 (3,278 words). Law:
//!      b74 = .X toggle; plain form neg@72/63/75, .X form inv@72/63/75
//!      + tail preds P@87+neg@90, P@77+neg@80.
//!
//! Fix: donor-clone rows from canonical sm100a where a donor exists
//! (FSETP_P_P_R_R_P 7 replaces + 8 OR/XOR adds; IADD3 4 rows), measured-law
//! field repair where none exists (FSETP_P_P_R_II_P 3 repairs + 3 OR adds;
//! bare FSETP.EQ.AND/OR_P_P_R_UR_P rebuilt, vm=0 era stance).
//!
//! Zero-mismatch rows (AND,GT 918 / AND,NEU 332 / AND,NUM / GT,OR / II
//! AND,NE 139) and the 120-only mgs are intentionally untouched.
//! Battery: verify226_gold.py 10,420/10,420 occurrence-paired MATCH.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const T120: &str = "tables/sm120.json";
const M96: u128 = (1u128 << 96) - 1;
fn tab(p: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(p)).unwrap()
}
fn decode(t: &IsaTable, w128: u128) -> Result<String, String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w128, 0, t)
        .map(|d| to_sass(&d))
        .map_err(|e| format!("{e}"))
}
fn mk(w96: u128, ctrl: u64) -> u128 {
    (w96 & ((1 << 96) - 1)) | ((ctrl as u128) << 96)
}
/// Cured anchors: (sm120 glyph == vendor text, word96, ctrl observations).
const CURED: &[(&str, u128, &[u64])] = &[
    // A: FSETP_P_P_R_R_P bool-op rows (donor-clone)
    (
        "FSETP.EQ.OR P0, PT, R7, RZ, P0",
        0x00702400000000ff0700720b,
        &[0x000fda00, 0x000fe200],
    ),
    (
        "FSETP.GE.OR P6, PT, R6, R5, P6",
        0x037c6400000000050600720b,
        &[0x000fe400],
    ),
    (
        "FSETP.GEU.XOR P6, PT, R9, RZ, !P4",
        0x067ce800000000ff0900720b,
        &[0x008fe400],
    ),
    (
        "FSETP.GTU.OR P0, PT, R26, R3, P0",
        0x0070c400000000031a00720b,
        &[0x000fc600],
    ),
    (
        "FSETP.LE.OR P0, PT, R13, 1.9721522630525295135e-31, P1",
        0x00f034000c8000000d00780b,
        &[0x000fda00],
    ),
    (
        "FSETP.LEU.OR P0, PT, R11, RZ, P0",
        0x0070b400000000ff0b00720b,
        &[0x000fc800],
    ),
    (
        "FSETP.LT.OR P1, PT, R43, R46, P1",
        0x00f214000000002e2b00720b,
        &[0x000fc800],
    ),
    (
        "FSETP.NAN.OR P0, PT, |R11|, |R11|, P0",
        0x007086004000000b0b00720b,
        &[0x000fe200],
    ),
    // B: FSETP_P_P_R_II_P (field repair + OR landing)
    (
        "FSETP.GEU.OR P1, PT, |R10|, 1.175494350822287508e-38, !P0",
        0x0472e600008000000a00780b,
        &[0x000fe200, 0x000fe400],
    ),
    // C: bare UR keys (AND row carried vendor-OR words and vice versa)
    (
        "FSETP.EQ.OR P0, PT, RZ, UR12, !P0",
        0x0c7024000000000cff007c0b,
        &[0x000fda00],
    ),
    (
        "FSETP.EQ.AND P0, PT, RZ, UR27, !P0",
        0x0c7020000000001bff007c0b,
        &[0x000fe400],
    ),
    // D: IADD3 .X gate (6-op row restored; guard + neg-UR variants)
    (
        "IADD3 R10, P1, P0, R5, UR4, R128",
        0x0f83e08000000004050a7c10,
        &[0x002fe200],
    ),
    (
        "IADD3 R158, P3, P2, R158, -UR6, R132",
        0x0fa7e084800000069e9e7c10,
        &[0x000fe200],
    ),
    (
        "@P3 IADD3 R74, P5, P4, R80, UR12, R73",
        0x0fcbe0490000000c504a3c10,
        &[0x000fc800],
    ),
    (
        "IADD3.X R55, PT, PT, ~R40, 0x7fe00000, RZ, P5, !PT",
        0x02ffe5ff7fe0000028377810,
        &[0x000fe400],
    ),
    (
        "FSETP.NE.AND P0, PT, |R40|, +INF , PT",
        0x03f052007f8000002800780b,
        &[0x000fe200],
    ),
];
/// Stability anchors: class-stable words that matched pre-patch and must
/// stay byte-identical. The .reuse print tracks the per-occurrence ctrl
/// reuse bits (gold gate verify226_gold: 22,068/22,068 occurrence-paired
/// MATCH incl. every ctrl template below; texts are gold-verified).
const STABLE: &[(&str, u128, u64)] = &[
    (
        "FSETP.GT.AND P2, PT, |R23|, R28, PT",
        0x03f442000000001c1700720b,
        0x008fc800,
    ),
    (
        "FSETP.GT.AND P2, PT, |R23|, R28, PT",
        0x03f442000000001c1700720b,
        0x010fc800,
    ),
    (
        "FSETP.GT.AND P2, PT, |R23|.reuse, R28.reuse, PT",
        0x03f442000000001c1700720b,
        0x0c0fe200,
    ),
    (
        "FSETP.GT.AND P2, PT, |R23|.reuse, R28.reuse, PT",
        0x03f442000000001c1700720b,
        0x0c2fe200,
    ),
    (
        "FSETP.GT.AND P2, PT, |R23|.reuse, R28.reuse, PT",
        0x03f442000000001c1700720b,
        0x0e0fe200,
    ),
];

#[test]
fn t226_1_cured_anchors_decode_exact_sm120() {
    let t = tab(T120);
    let mut n = 0;
    for (glyph, w96, ctrls) in CURED {
        for ctl in ctrls.iter() {
            let got = decode(&t, mk(*w96, *ctl)).unwrap_or_else(|e| panic!("HOLE {glyph}: {e}"));
            assert_eq!(&got, glyph, "sm120 drift @{ctl:#x}");
            n += 1;
        }
    }
    assert!(n >= 17);
}

#[test]
fn t226_2_stable_anchors_unchanged_sm120() {
    let t = tab(T120);
    for (glyph, w96, ctl) in STABLE {
        let got = decode(&t, mk(*w96, *ctl)).unwrap_or_else(|e| panic!("HOLE {glyph}: {e}"));
        assert_eq!(&got, glyph, "sm120 stability broke @{ctl:#x}");
    }
}

#[test]
fn t226_3_fail_closed_boundaries_sm120() {
    let t = tab(T120);
    // INVALID3 lattice word (b74|b75 on an EQ.OR base): all table rows pin
    // the bool-op lattice but the prio-3 sign window {62,63,72,73,74,75}
    // still absorbs it as OR with b75 silently dropped (same on the donor
    // tables; the lawful FSETP sign decodes -- 918 AND,GT + 332 AND,NEU --
    // ride the same tier, so arming it is src work scoped per base, logged
    // as 226-forward). The enforced contract (bug089-class): the rendered
    // text must NOT re-encode to the INVALID3 word, so the frozen __raw__
    // path keeps the exact bits.
    let invalid3 = 0x00702400000000ff0700720b | (1u128 << 75);
    let got = decode(&t, mk(invalid3, 0x000fe200)).expect("absorbed decodes");
    let insn = parse_sass(&got, 0).unwrap();
    let re = encode_instruction(&insn, &t).map(|c| c & M96).ok();
    assert_ne!(
        re,
        Some(invalid3 & M96),
        "INVALID3 must not survive a text round-trip"
    );
    // b91 set (vendor NOGLYPH) must not decode via any FSETP row.
    let b91 = 0x00702400000000ff0700720b | (1u128 << 91);
    assert!(decode(&t, mk(b91, 0x000fe200)).is_err(), "b91 absorbed");
}

#[test]
fn t226_4_encode_roundtrip_low96_sm120() {
    let t = tab(T120);
    for (text, lo96) in [
        (
            "FSETP.EQ.OR P0, PT, R7, RZ, P0 ;",
            0x00702400000000ff0700720b,
        ),
        (
            "FSETP.EQ.OR P0, PT, RZ, UR12, !P0 ;",
            0x0c7024000000000cff007c0b,
        ),
        (
            "IADD3 R10, P1, P0, R5, UR4, R128 ;",
            0x0f83e08000000004050a7c10,
        ),
        (
            "IADD3 R158, P3, P2, R158, -UR6, R132 ;",
            0x0fa7e084800000069e9e7c10,
        ),
    ] {
        let insn = parse_sass(text, 0).expect("parse");
        let w = encode_instruction(&insn, &t).unwrap_or_else(|_| panic!("encode HOLE: {text}"));
        assert_eq!(w & M96, lo96, "encode drift: {text}");
    }
}
