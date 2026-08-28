//! BUG-226c (F2-iter115, front2/blind, 2026-08-28): sm120 vendor-parity
//! patch 5 — FFMA family era-phantom closure + donor-law re-row
//! (canonical cb44e0b; patch226c.py replayable+idempotent).
//!
//! Measured defect census (pop226c full-population occurrence-paired
//! pairing vs nvdisasm 13.3.73, 2,406-file battery, true ctrl per word;
//! 198,058 non-FFMA2 DIFF words):
//!  * era 5-token phantom keys FFMA_P_R_R_R_R / FFMA_P_R_R_R_II drop the
//!    real Rd@16 (print `PT` as tok1) and print Rc twice; sign/reuse bits
//!    they tolerate are exactly what the starved era rows pinned away:
//!    ours   `FFMA PT, R19, -R17.reuse, R36, R36`
//!    vendor `FFMA R27, R19, -R17.reuse, R36`
//!  * era FFMA_R_R_UR_R_R phantom caught UR words (~b34 window / neg bits);
//!    era plain UR row had ureg 2b@32 (vendor window = 8b: UR4+ truncated,
//!    UR9+ = HOLE x767) and no neg fields.
//!  * era FFMA_R_R_R_R neg lattice `neg 2b@72` printed `-|Ra|` where vendor
//!    prints `|Ra|` (abs dominant under b72+b73): 2,326 lines.
//!  * era R_R_R_II missed reuse@123 (tok3, Rb@64 window) + neg@75/abs@74;
//!    its FTZ mg pinned the b80 .FTZ pivot wrong -> 4 HOLEs.
//!  * 4 `_?` fallback keys shadowed the engine prio-3 sign-tolerant path
//!    the donor tables use for abs@62 (|Rb|) words -> 302 ghost renders.
//!
//! Law: donor sm100a == sm103a byte-identical FFMA entries; donor-table
//! true-ctrl decode == vendor on all 198,058/198,058 DIFF words;
//! post-patch full-pop 1,610,857/1,610,857 EQ. Graft arb226c
//! x{100a,103a,120a} print-identical: b91 = UR-form identity (flip ->
//! nvdisasm ILLEGAL x3), b63 = neg of the @32 window ('-UR9'), b72/b73 =
//! neg/abs Ra, b74/b75 = abs/neg of the @64 window, b80 = .FTZ pivot on
//! the imm form. FFMA2 (opcode 0x249, 122,432 words) untouched: printer
//! default-mod law needed -> 234-kand.
//!
//! Fix (data-only): DELETE 10 era phantom keys; REPLACE mod_groups from
//! donor on FFMA_R_R_R_R (5 mgs), FFMA_R_R_UR_R (''+FTZ; dead-pin RM/RP
//! dropped fail-closed), FFMA_R_R_R_II ('',FTZ,RM,SAT <- donor R_R_R_FI
//! law, key name kept); ADD FFMA_R_R_R_UR (32 tok4-UR exposures).
//! baked-ctrl 747 -> 758 (+11 donor-era template rows; ratchet moved).

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

/// Cured anchors: (vendor glyph, word96, ctrl32) — occurrence-paired corpus
/// hits (pop226c), spanning every cured class in census order.
const CURED: &[(&str, u128, u64)] = &[
    // class 1: FFMA_P_R_R_R_R phantom (150,011) — PT dest ghost, Rd dropped
    (
        "FFMA R27, R19, -R17.reuse, R36",
        0x0000002480000011131b7223u128,
        0x080fe200u64,
    ),
    (
        "FFMA R21, R19, -R17.reuse, R30",
        0x0000001e8000001113157223u128,
        0x080fe200u64,
    ),
    // class 2: FFMA_R_R_UR_R_R phantom (36,731) — 5-token dup
    (
        "FFMA R16, R27.reuse, UR8, -R16",
        0x08000810000000081b107c23u128,
        0x040fe200u64,
    ),
    (
        "FFMA R17, R27, UR9, R30",
        0x0800001e000000091b117c23u128,
        0x000fc600u64,
    ),
    // class 3: FFMA_R_R_UR_R ureg 2b truncation + missing neg (8,152)
    (
        "FFMA R14, R15.reuse, UR4, -R14",
        0x0800080e000000040f0e7c23u128,
        0x040fe200u64,
    ),
    (
        "FFMA R15, R15, UR5, R12",
        0x0800000c000000050f0f7c23u128,
        0x000fc600u64,
    ),
    // class 4: abs-dominant lattice (2,326): vendor `|Ra|`, not `-|Ra|`
    (
        "FFMA R30, |R4|, R33, RZ",
        0x000002ff00000021041e7223u128,
        0x000fc800u64,
    ),
    // class 5: FTZ neg@75 tok4 (512)
    (
        "FFMA.FTZ R2, R44, R9.reuse, -R0.reuse",
        0x00010800000000092c027223u128,
        0x180fe200u64,
    ),
    // class 6: II-form reuse@123 on the Rb@64 window (87 + SAT 25 + FTZ 6)
    (
        "FFMA R9, R8, R27.reuse, 1",
        0x0000001b3f80000008097423u128,
        0x080fe200u64,
    ),
    // class 7: FFMA_P_R_R_R_II phantom (208) — ghost tok5 `0x0`
    (
        "FFMA R0, R46, |R47|, -1",
        0x0000042fbf8000002e007423u128,
        0x001fc800u64,
    ),
    // class 8: tok4 UR — donor key FFMA_R_R_R_UR (32 exposures)
    (
        "FFMA R11, R9, R6, UR6",
        0x0800000600000006090b7e23u128,
        0x000fc800u64,
    ),
    // class 9: UR-high window HOLEs (767): UR33 needs the 8b window
    (
        "FFMA R26, R19, UR33, R26",
        0x0800001a00000021131a7c23u128,
        0x004fe200u64,
    ),
    // class 10: FTZ imm-form HOLEs (4): b80 .FTZ pivot
    (
        "FFMA.FTZ R0, R2, R3, 1.1641532182693481445e-10",
        0x000100032f00000002007423u128,
        0x000fe800u64,
    ),
    // class 11: prio-3 abs@62 |Rb| via generic post-pass (was `_?` ghosts)
    (
        "FFMA R0, R4.reuse, |R47|, R49",
        0x000000314000002f04007223u128,
        0x040fe200u64,
    ),
];

#[test]
fn t226c_1_phantoms_absent_donor_law_present() {
    let raw = std::fs::read_to_string(T120).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let ins = v["instructions"].as_object().unwrap();
    for k in [
        "FFMA_P_R_R_R_R",
        "FFMA_P_R_R_R_II",
        "FFMA_P_R_R_FI_R",
        "FFMA_P_R_R_II_II",
        "FFMA_R_R_UR_R_R",
        "FFMA_R_R_R_R_R",
        "FFMA_R_R_R_II_?",
        "FFMA_R_R_R_R_II_?",
        "FFMA_R_R_R_R_II_II_?",
        "FFMA_R_R_R_R_II_II_II_?",
    ] {
        assert!(ins.get(k).is_none(), "phantom key survived: {k}");
    }
    assert!(
        !ins.keys().any(|k| k.starts_with("FFMA_P_")),
        "FFMA_P_ residue"
    );
    // donor-law fields on the plain row
    let r = &ins["FFMA_R_R_R_R"]["mod_groups"][""];
    let fs = r["fields"].as_array().unwrap();
    let has = |e: &str, b: u64, s: u64, t: u64| {
        fs.iter().any(|f| {
            f["extraction"] == e && f["bits"] == b && f["shift"] == s && f["token_idx"] == t
        })
    };
    assert!(has("guard", 4, 12, 0));
    assert!(has("neg", 1, 72, 2) && has("abs", 1, 73, 2), "Ra neg/abs");
    assert!(has("neg", 1, 63, 3), "Rb neg@63");
    assert!(has("neg", 1, 75, 4) && has("abs", 1, 74, 4), "Rc neg/abs");
    assert!(has("reuse", 1, 122, 2) && has("reuse", 1, 123, 3) && has("reuse", 1, 124, 4));
    assert!(!has("neg", 2, 72, 2), "era 2-bit neg lattice must be gone");
    // UR row: true 8b window + neg@63
    let r = &ins["FFMA_R_R_UR_R"]["mod_groups"][""];
    let fs = r["fields"].as_array().unwrap();
    let has = |e: &str, b: u64, s: u64, t: u64| {
        fs.iter().any(|f| {
            f["extraction"] == e && f["bits"] == b && f["shift"] == s && f["token_idx"] == t
        })
    };
    assert!(has("ureg", 8, 32, 3), "ureg window must be 8b@32");
    assert!(
        !has("ureg", 2, 32, 3),
        "era ureg 2b truncation must be gone"
    );
    assert!(has("neg", 1, 63, 3) && has("neg", 1, 75, 4));
    let ab =
        u128::from_str_radix(r["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    assert_eq!((ab >> 91) & 1, 1, "UR identity pivot b91 must be baked 1");
    // II row: donor FI law on sm120 key name
    let r = &ins["FFMA_R_R_R_II"]["mod_groups"]["FTZ"];
    let fs = r["fields"].as_array().unwrap();
    let has = |e: &str, b: u64, s: u64, t: u64| {
        fs.iter().any(|f| {
            f["extraction"] == e && f["bits"] == b && f["shift"] == s && f["token_idx"] == t
        })
    };
    assert!(
        has("reg", 8, 64, 3) && has("f32", 32, 32, 4),
        "Rb@64 + imm f32@32"
    );
    let ab =
        u128::from_str_radix(r["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    assert_eq!((ab >> 80) & 1, 1, "FTZ pivot b80 must be baked 1");
    // dead-pin era mgs dropped fail-closed
    let ur = ins["FFMA_R_R_UR_R"]["mod_groups"].as_object().unwrap();
    assert!(ur.get("RM").is_none() && ur.get("RP").is_none());
    let ii = ins["FFMA_R_R_R_II"]["mod_groups"].as_object().unwrap();
    assert!(ii.get("RP").is_none());
    // new donor key
    let r = &ins["FFMA_R_R_R_UR"]["mod_groups"][""];
    let fs = r["fields"].as_array().unwrap();
    let has = |e: &str, b: u64, s: u64, t: u64| {
        fs.iter().any(|f| {
            f["extraction"] == e && f["bits"] == b && f["shift"] == s && f["token_idx"] == t
        })
    };
    assert!(has("ureg", 8, 32, 4), "tok4 UR = ureg 8b@32 window");
}

#[test]
fn t226c_2_cured_anchors_sm120() {
    let t = tab(T120);
    for (glyph, w96, ctl) in CURED {
        let got = decode(&t, mk(*w96, *ctl)).unwrap_or_else(|e| panic!("HOLE {glyph}: {e}"));
        assert_eq!(&got, glyph, "cure broke @{ctl:#x}");
        assert!(!got.contains("FFMA PT,"), "phantom glyph survived: {got}");
    }
}

#[test]
fn t226c_3_fail_closed_and_stability_sm120() {
    let t = tab(T120);
    // FFMA2 was closed by BUG-234 (t234_*; canonical 2aa6514): the word
    // below now decodes through FFMA2_R_R_R_R + printer arm.
    assert_eq!(
        decode(&t, mk(0x010a013a0000002740467249u128, 0x0d0fe200)).unwrap(),
        "FFMA2 R70, -R64.reuse.F32x2.LO_HI.NP, R39.reuse.F32, R58.F32x2.HI_LO"
    );
    // the phantom 5-token text must be unencodable (ghost form deleted):
    // 'FFMA P0, R1, R2, R3, R4' has no lawful key anymore
    if let Ok(insn) = parse_sass("FFMA P0, R1, R2, R3, R4 ;", 0) {
        let _ = encode_instruction(&insn, &t).expect_err("ghost P-dest FFMA must be fail-closed");
    }
    // b63-cleared twin decodes plain (no spurious neg on Rb)
    let got = decode(&t, mk(0x0000002400000011131b7223u128, 0x080fe200)).unwrap();
    assert_eq!(got, "FFMA R27, R19, R17.reuse, R36");
    // cross-patch stability: 226/226b/229/229b/230 anchors must not drift
    for (glyph, w96, ctl) in [
        (
            "LEA R4, R3.reuse, -R4, 0x3",
            0x078e18ff8000000403047211u128,
            0x040fe200u64,
        ),
        (
            "LEA.HI R55, R57, 0x1, RZ, 0x17",
            0x078fb8ff0000000139377811u128,
            0x000fe400u64,
        ),
        (
            "SHFL.DOWN P1, R17, R41, R40, R23",
            0x000200170800002829117389u128,
            0x00006400u64,
        ),
    ] {
        let got = decode(&t, mk(w96, ctl)).unwrap_or_else(|e| panic!("HOLE {glyph}: {e}"));
        assert_eq!(&got, glyph, "stability broke @{ctl:#x}");
    }
}

#[test]
fn t226c_4_encode_roundtrip_low96_sm120() {
    let t = tab(T120);
    for (text, lo96) in [
        ("FFMA R27, R19, -R17, R36 ;", 0x0000002480000011131b7223u128),
        ("FFMA R16, R27, UR8, -R16 ;", 0x08000810000000081b107c23u128),
        ("FFMA R30, |R4|, R33, RZ ;", 0x000002ff00000021041e7223u128),
        ("FFMA R9, R8, R27, 1 ;", 0x0000001b3f80000008097423u128),
        // NB: `|Rx|`+f32-imm encode leaves abs@74 un-emitted (PRE==POST,
        // pre-existing encoder gap on abs+f32imm shapes = 235-kand LOW);
        // the decode-side parity for that class is pinned in CURED above.
        ("FFMA R0, R46, R47, -1 ;", 0x0000002fbf8000002e007423u128),
        ("FFMA R11, R9, R6, UR6 ;", 0x0800000600000006090b7e23u128),
        ("FFMA R26, R19, UR33, R26 ;", 0x0800001a00000021131a7c23u128),
        // no-neg plain regression (b63 cleared twin)
        ("FFMA R27, R19, R17, R36 ;", 0x0000002400000011131b7223u128),
    ] {
        let insn = parse_sass(text, 0).expect("parse");
        let w = encode_instruction(&insn, &t).unwrap_or_else(|_| panic!("encode HOLE: {text}"));
        assert_eq!(w & M96, lo96 & M96, "encode drift: {text}");
    }
}
