//! BUG-229b / 229-p2+p3 (F2-iter113, front2/blind, 2026-08-27): sm120
//! vendor-parity SHFL+USHF donor-law rewrite (canonical 35da13b; patch229b.py
//! replayable+idempotent).
//!
//! Defect (measured, work/bug229b full-pop census over the 2,406-file
//! battery, occurrence-paired to nvdisasm 13.3.73): the era-scaffolded
//! SHFL/USHF key space produced 260,233 decode holes (whole SHFL.DOWN/IDX/
//! BFLY/UP forms, USHF.R.U64/S64/...), ~131k text mismatches (junk DOWN mode
//! pivot, off-by-one reg @25, dropped tok5 reg@64 -> 0x0, 13b imm tok5 lost,
//! junk UR0 token, USHF.L.U64.HI imm narrowed to 3b, ...) and 26,744
//! same-text pin-residuals (USHF.L.U32 b73/b74 never claimed).
//!
//! Law (wholesale): sm100a donor table decodes 610,832/610,832 directly
//! paired + 12,417/12,417 truncation-recovered occurrences byte-identical to
//! vendor (true 128-bit ctrl); graft arb229b (21 class reps x discriminant
//! walks x{100a,103a,120a}) arch-identical on every cell. Repairs: DELETE 24
//! era scaffold keys; REPLACE the 4+3 canonical keys' mod_groups with donor
//! rows + 4 graft repairs (tok1 pred 4b@12 -> 3b@81 on II_II IDX/UP/BFLY
//! [guard-echo], II_II IDX imm 28b@53 -> 5b [soaked mode pivots], II_II/II_R
//! DOWN imm 6b@53 -> 5b [soaked b58]; zero corpus exposure, routing-census
//! asserted). Keys 1540 -> 1516, baked-ctrl 706 -> 747.

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

/// Cured anchors: (vendor glyph, word96, ctrl32) — every triple is an
/// occurrence-paired corpus hit (work/bug229b pop census), spanning the
/// hole-heal and text-cure classes of both families.
const CURED: &[(&str, u128, u64)] = &[
    // SHFL decode-hole heals (whole forms previously "no instruction matches")
    (
        "SHFL.DOWN P1, R17, R41, R40, R23",
        0x000200170800002829117389,
        0x00006400,
    ),
    (
        "SHFL.IDX PT, R8, R10, 0x1, 0x101f",
        0x000e000000301f000a087f89,
        0x001ea400,
    ),
    (
        "SHFL.BFLY P1, R11, R23, R10, R9",
        0x000200090c00000a170b7389,
        0x00006400,
    ),
    (
        "SHFL.UP P6, R29, R32, R33, R34",
        0x000c002204000021201d7389,
        0x00006400,
    ),
    // SHFL text cures: tok5 reg@64 (RZ), junk DOWN->IDX pivot, 13b imm tok5,
    // arity-junk (UR0), dst off-by-window, out-pred slot [83:81]
    (
        "SHFL.UP PT, R35, R34, 0x1, RZ",
        0x000e00ff0420000022237989,
        0x008ee200,
    ),
    (
        "SHFL.IDX PT, R10, R12, 0x1, 0x1f",
        0x000e000000201f000c0a7f89,
        0x001ea400,
    ),
    (
        "SHFL.IDX PT, R7, R3, R0, 0x1f",
        0x000e000000001f0003077589,
        0x008e6400,
    ),
    (
        "SHFL.IDX PT, R8, R10, RZ, 0x101f",
        0x000e000000101fff0a087589,
        0x004ee400,
    ),
    (
        "SHFL.BFLY P0, R12, R21, R10, R11",
        0x0000000b0c00000a150c7389,
        0x00006400,
    ),
    (
        "SHFL.UP P0, R66, R27, 0x1, RZ",
        0x000000ff042000001b427989,
        0x000e2400,
    ),
    // USHF: b73/b74 pin class (was same-text residual), imm window restored,
    // UR window spill (b35/b36), whole-family hole heals
    (
        "USHF.L.U32 UR4, UR4, 0x3, URZ",
        0x080006ff0000000304047899,
        0x000fe200,
    ),
    (
        "USHF.L.U64.HI UR24, UR18, 0xf, UR19",
        0x080102130000000f12187899,
        0x008fc400,
    ),
    (
        "USHF.L.U64.HI UR15, UR34, 0x3, UR35",
        0x0801022300000003220f7899,
        0x000fe200,
    ),
    (
        "USHF.R.U64 UR4, UR4, 0x8, UR5",
        0x080012050000000804047899,
        0x000fe200,
    ),
    (
        "USHF.R.S32.HI UR4, URZ, UR9, UR31",
        0x0801141f00000009ff047299,
        0x001fc800,
    ),
    (
        "USHF.L.U32 UR4, UR4, UR6, URZ",
        0x080006ff0000000604047299,
        0x001fe400,
    ),
];

#[test]
fn t229b_1_cured_anchors_decode_exact_sm120() {
    let t = tab(T120);
    for (glyph, w96, ctl) in CURED {
        let got = decode(&t, mk(*w96, *ctl)).unwrap_or_else(|e| panic!("HOLE {glyph}: {e}"));
        assert_eq!(&got, glyph, "sm120 drift @{ctl:#x}");
    }
    // guard-prefixed SHFL now prints vendor-exactly (graft repair: out-pred
    // reads [83:81] pinned PT, not the guard slot); zero corpus exposure.
    let base = 0x000e00000c201f0021237f89u128 ^ (1 << 12); // b12: PT->guard P-class
    let got = decode(&t, mk(base, 0x00106800)).unwrap();
    assert_eq!(got, "@P6 SHFL.BFLY PT, R35, R33, 0x1, 0x1f");
}

#[test]
fn t229b_2_structure_sm120() {
    let j: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(T120).unwrap()).unwrap();
    let ins = &j["instructions"];
    // era scaffold keys are gone
    for k in [
        "SHFL.BFLY_P_R_R_II_II",
        "SHFL.BFLY_P_R_R_II_II_?",
        "SHFL.BFLY_P_R_R_R_R",
        "SHFL.IDX_P_R_R_II_II",
        "SHFL.IDX_P_R_R_II_II_?",
        "SHFL.IDX_P_R_R_R_II",
        "SHFL.IDX_P_R_R_R_II_?",
        "SHFL.UP_P_R_R_II_II",
        "USHF.L.U32_P_UR_UR_II_?",
        "USHF.L.U32_UP0_UR_UR_II_UR",
        "USHF.L.U32_UR_UR_II_II",
        "USHF.L.U32_UR_UR_II_UR",
        "USHF.L.U32_UR_UR_UR_UR",
        "USHF.L.U64.HI_UR_UR_II_UR",
        "USHF.L.U64.HI_UR_UR_UR_II",
        "USHF.L.W.U32.HI_UR_UR_II_UR",
        "USHF.R.S32.HI_UR_UR_II_UR",
        "USHF.R.S32.HI_UR_UR_II_UR_II_?",
        "USHF.R.S32.HI_UR_UR_II_UR_II_II_?",
        "USHF.R.S32.HI_UR_UR_II_UR_UR",
        "USHF.R.S64_UR_UR_II_UR",
        "USHF.R.U32.HI_UR_UR_II_UR",
        "USHF.R.U32.HI_UR_UR_UR_UR",
        "USHF.R.W.U32_UR_UR_UR_II",
    ] {
        assert!(ins[k].is_null(), "era key {k} must be deleted");
    }
    // canonical keys carry exactly the donor mod-group law sets
    let mgs = |k: &str| {
        let mut v: Vec<&str> = ins[k]["mod_groups"]
            .as_object()
            .unwrap()
            .keys()
            .map(|s| s.as_str())
            .collect();
        v.sort();
        v
    };
    assert_eq!(mgs("SHFL_P_R_R_II_II"), ["BFLY", "DOWN", "IDX", "UP"]);
    assert_eq!(mgs("SHFL_P_R_R_II_R"), ["DOWN", "UP"]);
    assert_eq!(mgs("SHFL_P_R_R_R_II"), ["IDX"]);
    assert_eq!(mgs("SHFL_P_R_R_R_R"), ["BFLY", "DOWN", "IDX", "UP"]);
    assert_eq!(mgs("USHF_UR_UR_II_UR").len(), 32);
    assert_eq!(mgs("USHF_UR_UR_UR_II"), ["R,U64"]);
    assert_eq!(
        mgs("USHF_UR_UR_UR_UR"),
        ["HI,R,S32", "HI,R,U32", "L,U32", "R,U64"]
    );
    // graft repairs are load-bearing
    let idx = &ins["SHFL_P_R_R_II_II"]["mod_groups"]["IDX"];
    let fs = idx["fields"].as_array().unwrap();
    assert!(fs
        .iter()
        .any(|f| f["extraction"] == "pred" && f["shift"] == 81 && f["bits"] == 3));
    assert!(fs
        .iter()
        .any(|f| f["extraction"] == "imm" && f["shift"] == 53 && f["bits"] == 5));
    assert!(!fs
        .iter()
        .any(|f| f["extraction"] == "pred" && f["shift"] == 12));
    // USHF.L.U32 rows finally claim the b73/b74 pins (26,151-residual class)
    let lu32 = &ins["USHF_UR_UR_II_UR"]["mod_groups"]["L,U32"];
    let ab = u128::from_str_radix(
        lu32["and_base"].as_str().unwrap().trim_start_matches("0x"),
        16,
    )
    .unwrap();
    assert_eq!((ab >> 73) & 3, 3, "L,U32 must pin b73/b74");
}

#[test]
fn t229b_3_fail_closed_and_stability_sm120() {
    let t = tab(T120);
    // off-corpus fail-closed (zero exposure, graft-measured): register-tok5
    // forms with bits [53:58] set hole out instead of soaking junk
    for (w96, ctl) in [
        (0x000200090c20000a170b7389u128, 0x00006400u64), // BFLY R_R + b53 (nv inert)
        (0x000e0002002000004c4a7989, 0x000fe200),        // DOWN II_R b59 flip: donor-law holes
                                                         // like the donor does (fail-closed); nvdisasm prints IDX here — the
                                                         // off-corpus IDX-II_R gap is parked as 233-kand LOW, zero exposure.
    ] {
        assert!(
            decode(&t, mk(w96, ctl)).is_err(),
            "must stay a hole: {w96:#x}"
        );
    }
    // cross-key stability: 226/226b/229 anchors must not drift
    for (glyph, w96, ctl) in [
        (
            "FSETP.EQ.OR P0, PT, R7, RZ, P0",
            0x00702400000000ff0700720bu128,
            0x000fda00u64,
        ),
        (
            "IADD3 R10, P1, P0, R5, UR4, R128",
            0x0f83e08000000004050a7c10,
            0x002fe200,
        ),
        (
            "LEA.HI R55, R57, 0x1, RZ, 0x17",
            0x078fb8ff0000000139377811,
            0x000fe400,
        ),
        (
            "SHF.R.U32 R0, R0, 0x10, RZ",
            0x000016ff0000001000007819,
            0x002fc800,
        ),
    ] {
        let got = decode(&t, mk(w96, ctl)).unwrap_or_else(|e| panic!("HOLE {glyph}: {e}"));
        assert_eq!(&got, glyph, "stability broke @{ctl:#x}");
    }
}

#[test]
fn t229b_4_encode_roundtrip_low96_sm120() {
    let t = tab(T120);
    for (text, lo96) in [
        (
            "SHFL.UP PT, R35, R34, 0x1, RZ ;",
            0x000e00ff0420000022237989u128,
        ),
        (
            "SHFL.IDX PT, R8, R10, 0x1, 0x101f ;",
            0x000e000000301f000a087f89u128,
        ),
        (
            "SHFL.BFLY P1, R11, R23, R10, R9 ;",
            0x000200090c00000a170b7389u128,
        ),
        (
            "USHF.L.U32 UR4, UR4, 0x3, URZ ;",
            0x080006ff0000000304047899u128,
        ),
        (
            "USHF.L.U64.HI UR24, UR18, 0xf, UR19 ;",
            0x080102130000000f12187899u128,
        ),
        (
            "USHF.R.U64 UR4, UR4, 0x8, UR5 ;",
            0x080012050000000804047899u128,
        ),
    ] {
        let insn = parse_sass(text, 0).expect("parse");
        let w = encode_instruction(&insn, &t).unwrap_or_else(|_| panic!("encode HOLE: {text}"));
        assert_eq!(w & M96, lo96 & M96, "encode drift: {text}");
    }
}
