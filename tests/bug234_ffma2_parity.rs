//! BUG-234 (F2-iter116, front2/blind, 2026-08-28): sm120 vendor-parity
//! patch 6 — FFMA2 closure (canonical 2aa6514; patch234.py
//! replayable+idempotent; printer arm "BUG-234" in src/printer.rs).
//!
//! Measured law (census ana234: 122,432/122,432 corpus words, 100% sm_100
//! sections of the s120as battery, 5 cells over bits {81,82,83,88}; graft
//! arb234x/arb234y x{100a,103a} print-identical; sm_120a nvdisasm REJECTS
//! FFMA2 outright, so the sm120 contract is textual parity with the
//! native-arch vendor decode):
//!  * t2: b82 -> .F32 (dominates b88); b82&b81 -> .INVALID3 (zero corpus
//!    exposure, graft-corner); else .F32x2 + .LO_HI(b81) / .HI_LO(default)
//!    [+ .NP(b83)]  — the non-default mods are table fields (opmod:F32@82 /
//!    F32x2@88 / LO_HI@81 / NP@83), the defaults are the printer arm.
//!  * t3: b88 -> .F32 ; else .F32x2.HI_LO   (arm)
//!  * t4: .F32x2.HI_LO always (arm); neg@75/abs@74/reuse@124 = row fields
//!    (graft-proven, donor-extended).
//!  * UR / imm / @guard forms: zero corpus exposure; crafted donor-UR word
//!    is vendor-ILLEGAL on {100a,103a,120a} -> NOT cloned, holes stay.
//!
//! Fix: ADD FFMA2_R_R_R_R[''] from donor sm100a (+t4 graft fields, vm +=
//! 74/75/124); forms 1506->1507, variants 2683->2684, baked-ctrl 758->759
//! (donor-template ctrl[19:14]=0x3f, satisfied by 122,432/122,432 words).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const T120: &str = "tables/sm120.json";
const T103: &str = "tables/sm103a.json";
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

/// Cured anchors: (vendor glyph, word96, ctrl32) — census cells 1-6 are
/// occurrence-paired corpus hits (pop234_ffma2), G1-G8 are graft corners
/// (arb234x/arb234y, x{100a,103a} print-identical).
const CURED: &[(&str, u128, u64)] = &[
    // census cell (81,82,83,88) = (0,0,0,1), 68,416 words
    (
        "FFMA2 R66, R64.F32x2.HI_LO, R36.reuse.F32, R56.F32x2.HI_LO",
        0x010000380000002440427249u128,
        0x080fe200u64,
    ),
    // (0,0,1,1), 5,248
    (
        "FFMA2 R66, R40.F32x2.HI_LO.NP, R48.reuse.F32, R66.F32x2.HI_LO",
        0x010800420000003028427249u128,
        0x080fe200u64,
    ),
    // (0,1,0,0), 22,144 — b82 F32-form
    (
        "FFMA2 R84, R20.F32, R24.reuse.F32x2.HI_LO, R64.F32x2.HI_LO",
        0x000400400000001814547249u128,
        0x094fe200u64,
    ),
    // (1,0,0,1), 5,248 — LO_HI, no NP
    (
        "FFMA2 R68, R36.F32x2.LO_HI, R51.F32, R68.F32x2.HI_LO",
        0x010200440000003324447249u128,
        0x002fe200u64,
    ),
    // (1,0,1,1), 21,376 — LO_HI.NP, neg t2, reuse t2+t3
    (
        "FFMA2 R70, -R64.reuse.F32x2.LO_HI.NP, R39.reuse.F32, R58.F32x2.HI_LO",
        0x010a013a0000002740467249u128,
        0x0d0fe200u64,
    ),
    // (1,0,1,1) with neg t3, 3,968 corpus t3-neg class
    (
        "FFMA2 R58, -R32.F32x2.LO_HI.NP, -R43.F32, R58.F32x2.HI_LO",
        0x010a013a8000002b203a7249u128,
        0x002fe200u64,
    ),
    // G1: graft t4 abs@74 (zero corpus exposure; arb234x W88^b74)
    (
        "FFMA2 R66, R64.F32x2.HI_LO, R36.reuse.F32, |R56|.F32x2.HI_LO",
        0x010000380000002440427249u128 | (1u128 << 74),
        0x080fe200u64,
    ),
    // G2: graft t4 neg@75 (arb234x W88^b75)
    (
        "FFMA2 R66, R64.F32x2.HI_LO, R36.reuse.F32, -R56.F32x2.HI_LO",
        0x010000380000002440427249u128 | (1u128 << 75),
        0x080fe200u64,
    ),
    // G3: graft t4 reuse@124 = ctrl bit 28 (arb234x W88 cl28)
    (
        "FFMA2 R66, R64.F32x2.HI_LO, R36.reuse.F32, R56.reuse.F32x2.HI_LO",
        0x010000380000002440427249u128,
        0x080fe200u64 ^ (1 << 28),
    ),
    // G4: graft INVALID3 corner b82&b81 (arb234x W82^b81)
    (
        "FFMA2 R84, R20.INVALID3, R24.reuse.F32x2.HI_LO, R64.F32x2.HI_LO",
        0x000400400000001814547249u128 | (1u128 << 81),
        0x094fe200u64,
    ),
    // G5: graft both-set b82&b88 — b82 dominates (arb234x W88^b82)
    (
        "FFMA2 R66, R64.F32, R36.reuse.F32, R56.F32x2.HI_LO",
        0x010000380000002440427249u128 | (1u128 << 82),
        0x080fe200u64,
    ),
    // G6: graft both-set + NP (arb234x W88^82^83)
    (
        "FFMA2 R66, R64.F32.NP, R36.reuse.F32, R56.F32x2.HI_LO",
        0x010000380000002440427249u128 | (1u128 << 82) | (1u128 << 83),
        0x080fe200u64,
    ),
    // G7: graft neither-set (arb234y 0000)
    (
        "FFMA2 R66, R64.F32x2.HI_LO, R36.reuse.F32x2.HI_LO, R56.F32x2.HI_LO",
        0x010000380000002440427249u128 ^ (1u128 << 88),
        0x080fe200u64,
    ),
    // G8: graft b81 alone (arb234y 81)
    (
        "FFMA2 R66, R64.F32x2.LO_HI, R36.reuse.F32x2.HI_LO, R56.F32x2.HI_LO",
        0x010000380000002440427249u128 ^ (1u128 << 88) ^ (1u128 << 81),
        0x080fe200u64,
    ),
];

#[test]
fn t234_1_structure_donor_clone_graft_fields() {
    let raw = std::fs::read_to_string(T120).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let ins = v["instructions"].as_object().unwrap();
    let ff2: Vec<&String> = ins.keys().filter(|k| k.starts_with("FFMA2")).collect();
    assert_eq!(ff2.len(), 1, "exactly one FFMA2 key: {ff2:?}");
    let e = &ins["FFMA2_R_R_R_R"];
    let mgs = e["mod_groups"].as_object().unwrap();
    assert_eq!(mgs.len(), 1);
    let r = &mgs[""];
    let fs = r["fields"].as_array().unwrap();
    let has = |x: &str, b: u64, s: u64, t: u64| {
        fs.iter().any(|f| {
            f["extraction"] == x && f["bits"] == b && f["shift"] == s && f["token_idx"] == t
        })
    };
    // donor fields
    assert!(has("reg", 8, 16, 1) && has("reg", 8, 24, 2) && has("reg", 8, 32, 3));
    assert!(has("reg", 8, 64, 4), "Rc@64");
    assert!(has("neg", 1, 72, 2) && has("neg", 1, 63, 3));
    assert!(has("reuse", 1, 122, 2) && has("reuse", 1, 123, 3));
    assert!(has("opmod:F32", 1, 82, 2) && has("opmod:F32x2", 1, 88, 2));
    assert!(has("opmod:LO_HI", 1, 81, 2) && has("opmod:NP", 1, 83, 2));
    // graft-proven extensions
    assert!(has("abs", 1, 74, 4) && has("neg", 1, 75, 4), "t4 abs/neg");
    assert!(has("reuse", 1, 124, 4), "t4 reuse@124 (ctrl bit 28)");
    // guard pinned (zero @guard exposures): b12..14 = 1, b15 = 0
    let ab =
        u128::from_str_radix(r["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    assert_eq!((ab >> 12) & 0xF, 0x7, "guard band must bake PT (no guard)");
    assert_eq!((ab >> 74) & 1, 0);
    assert_eq!((ab >> 75) & 1, 0);
    assert_eq!((ab >> 124) & 1, 0);
    let vm = u128::from_str_radix(
        r["variable_mask"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
        16,
    )
    .unwrap();
    for b in [74u32, 75, 124, 81, 82, 83, 88, 63, 72, 122, 123] {
        assert_eq!((vm >> b) & 1, 1, "bit {b} must be variable");
    }
    // donor-template baked ctrl[19:14] = 0x3f (satisfied by all corpus words)
    assert_eq!((ab >> (96 + 14)) & 0x3F, 0x3F, "baked ctrl template");
}

#[test]
fn t234_2_cured_anchors_sm120() {
    let t = tab(T120);
    for (glyph, w96, ctl) in CURED {
        let got = decode(&t, mk(*w96, *ctl)).unwrap_or_else(|e| panic!("HOLE {glyph}: {e}"));
        assert_eq!(&got, glyph, "cure broke @{ctl:#x}");
    }
}

#[test]
fn t234_3_fail_closed_and_stability_sm120() {
    let t = tab(T120);
    // UR-form hole stays fail-closed: crafted donor-UR word is vendor-ILLEGAL
    // on {100a,103a,120a} (arb234x UR cells) and has zero corpus exposure.
    let ur_word = 0x000fc000092000000000000000007c49u128 & M96
        | (30u128 << 16)
        | (27u128 << 24)
        | (9u128 << 32)
        | (17u128 << 64);
    assert!(
        decode(&t, mk(ur_word, 0x080fe200)).is_err(),
        "FFMA2 UR form must stay fail-closed"
    );
    if let Ok(insn) = parse_sass("FFMA2 R30, R27, UR9, R17 ;", 0) {
        let _ = encode_instruction(&insn, &t).expect_err("FFMA2 UR encode must be fail-closed");
    }
    // cross-patch stability: 226c/229/229b/230 anchors must not drift
    for (glyph, w96, ctl) in [
        (
            "FFMA R27, R19, -R17.reuse, R36",
            0x0000002480000011131b7223u128,
            0x080fe200u64,
        ),
        (
            "LEA R4, R3.reuse, -R4, 0x3",
            0x078e18ff8000000403047211u128,
            0x040fe200u64,
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
fn t234_4_encode_roundtrip_low96_sm120() {
    let t = tab(T120);
    for (text, lo96) in [
        (
            "FFMA2 R66, R64.F32x2.HI_LO, R36.reuse.F32, R56.F32x2.HI_LO ;",
            0x010000380000002440427249u128,
        ),
        (
            "FFMA2 R84, R20.F32, R24.reuse.F32x2.HI_LO, R64.F32x2.HI_LO ;",
            0x000400400000001814547249u128,
        ),
        (
            "FFMA2 R68, R36.F32x2.LO_HI, R51.F32, R68.F32x2.HI_LO ;",
            0x010200440000003324447249u128,
        ),
        (
            "FFMA2 R66, R40.F32x2.HI_LO.NP, R48.reuse.F32, R66.F32x2.HI_LO ;",
            0x010800420000003028427249u128,
        ),
        (
            "FFMA2 R70, -R64.reuse.F32x2.LO_HI.NP, R39.reuse.F32, R58.F32x2.HI_LO ;",
            0x010a013a0000002740467249u128,
        ),
        (
            "FFMA2 R58, -R32.F32x2.LO_HI.NP, -R43.F32, R58.F32x2.HI_LO ;",
            0x010a013a8000002b203a7249u128,
        ),
        // graft-proven t4 abs/neg encode through the new row fields
        (
            "FFMA2 R66, R64.F32x2.HI_LO, R36.reuse.F32, |R56|.F32x2.HI_LO ;",
            0x010000380000002440427249u128 | (1u128 << 74),
        ),
        (
            "FFMA2 R66, R64.F32x2.HI_LO, R36.reuse.F32, -R56.F32x2.HI_LO ;",
            0x010000380000002440427249u128 | (1u128 << 75),
        ),
    ] {
        let insn = parse_sass(text, 0).expect("parse");
        let w = encode_instruction(&insn, &t).unwrap_or_else(|_| panic!("encode HOLE: {text}"));
        assert_eq!(w & M96, lo96 & M96, "encode drift: {text}");
    }
    // decode(encode(text)) must reproduce the printed form (arm law closed)
    for text in [
        "FFMA2 R66, R64.F32x2.HI_LO, R36.F32, R56.F32x2.HI_LO",
        "FFMA2 R70, -R64.F32x2.LO_HI.NP, R39.F32, R58.F32x2.HI_LO",
        "FFMA2 R84, R20.F32, R24.F32x2.HI_LO, R64.F32x2.HI_LO",
    ] {
        let insn = parse_sass(&format!("{text} ;"), 0).expect("parse");
        let w = encode_instruction(&insn, &t).expect("encode");
        let got = decode(&t, w).expect("decode");
        assert_eq!(got, text, "roundtrip drift");
    }
}

/// Donor-side UR-class (pop234b: 512 words, all cell b88=1, in sm_103a cubins;
/// graft arb234z corners x{100a,103a}). The sm120 table intentionally has no
/// UR row (t234_3 fail-closed); the ARM fixes the pre-existing donor prints.
#[test]
fn t234_5_donor_ur_form_law() {
    let t = tab(T103);
    const W: u128 = 0x092000a90000000464647c49u128;
    for (glyph, w96, ctl) in [
        // corpus representative (occurrence class 512/512)
        (
            "FFMA2 R100, R100.F32x2.HI_LO, UR4.F32, R169.reuse.F32",
            W,
            0x100fe200u64,
        ),
    ] {
        let got = decode(&t, mk(w96, ctl)).unwrap_or_else(|e| panic!("HOLE {glyph}: {e}"));
        assert_eq!(&got, glyph, "donor UR-form law broke @{ctl:#x}");
    }
    // graft corners (arb234z): the donor UR row pins b88=1/b81=b82=b83=0 in
    // and_base -> every off-cell word stays a fail-closed HOLE on purpose
    for b in [81u32, 82, 83, 88] {
        assert!(
            decode(&t, mk(W ^ (1u128 << b), 0x100fe200)).is_err(),
            "UR-form corner b{b} must stay fail-closed on the donor table"
        );
    }
}
