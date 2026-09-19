//! BUG-419 pins (F2-iter228, loop5/blind front2, 2026-09-08): tail of
//! BUG-417 (registration 419-kand LOW, 417.md sec.6; hint F2-iter227/228).
//!
//! Modifier ROUTES on the HADD2 FI FI frame (0x430) and the HFMA2 two-imm
//! R-final frames (0x7831; keys HFMA2_R_R_{FI_FI,II_II}_R):
//!
//! (a) A-frame: b77='.SAT' b78='.F32' (3-token; single f16 lane [32:48)
//!     tok3, [48:64)+b73 inert) b80='.FTZ' b85='.BF16_V2'; measured combos
//!     F32+SAT (FTZ bit absorbed), F32+FTZ, FTZ+SAT, BF16+SAT/FTZ/
//!     FTZ+SAT; F32+BF16 = vendor-refuse x4 (HOLE). Pre: 100a/103a HOLE,
//!     120/121a era-junk tok0 fields misrouted claims to PLAIN print
//!     (silent wrong-text: word with b77 rendered 'HADD2 R0, R0, 0, 0'
//!     where vendor prints 'HADD2.SAT ...'; measure419_pre 110 WRONG).
//! (b) B/C-frames: {b76,b80}=FMZ/FTZ/OOB enum (BUG-279 law), b77='.SAT',
//!     b78: f16='.F32' / BF16=INVALID3(doctrine HOLE), b79='.RELU'
//!     trailing _P (pred 3b@87, 7=PT ELIDED, inv@90). Combolaw measured
//!     (arb419 x4 AGREE EVERY): FMZ+SAT / FTZ+SAT / OOB+SAT / F32+SAT /
//!     F32+FMZ / F32+FTZ / F32+FMZ+SAT + RELU branch + BF16_V2 mirrors;
//!     SAT+RELU / FMZ+SAT+RELU / b78-on-BF16 = vendor refuse x4 (HOLE).
//! (c) B/C tok5 hsel window [81:83): b81 INVALID1 / b82 H0_H0 / both
//!     H1_H1, composed with the tok2 law (c74+81).
//!
//! Vendor law: arb417 (71) + arb419 (110) probes, nvdisasm 13.3.73 raw -b
//! per-word, x4 models SM100a/SM103a/SM120/SM121a AGREE EVERY probe,
//! DIVERGENT=0 (work/bug419x/arb419_law.json).
//!
//! Graft (canonical 18b6cec -> 2ae87b3, patch419.py replayable+idempotent,
//! monotone where measured; ENGINE arms in this commit's sibling graphs):
//!  * HADD2 '' (120/121a): era tok0 junk removed (''@85, reg 8b@72 [the
//!    care-eater over [72:80)], neg@77/78/80) + route bits lifted out of
//!    the era variable_masks on all four legs = measured claim-tighten
//!    + care-routing; new mgs SAT/FTZ/BF16_V2/FTZ,SAT/BF16_V2,SAT/
//!    BF16_V2,FTZ/BF16_V2,FTZ,SAT/F32-absorber cloned from the cleaned
//!    ''; F32 branch = dotted keys HADD2.F32[.SAT/.FTZ]_R_R_FI.
//!  * HFMA2 parents x4 (+II_II on 120/121a): new mgs cloned per law
//!    (b86 relax where measured-inert); 121a FI_FI_R era tok0 junk
//!    reg@[76..93) removed from ''+BF16_V2; hsel(2)@81 tok5 on the new
//!    mgs + existing ''/BF16_V2; RELU decode via dotted _P keys
//!    (HFMA2.<path>_R_R_{FI_FI,II_II}_R_P), bare-RELU admission via the
//!    parent RELU mgs (encode_only: decoder keeps the dotted claims).
//!  * ENGINE: mod-prio arm extended to base HADD2 (BF16_V2(0) F32(1)
//!    FMZ/FTZ/OOB(2) SAT(3) -- arb419 combo prints x4); r_hsel_invalid1
//!    _slot += HFMA2 tok5; decoder generic abs@73 synth skipped on the
//!    F32 dotted keys (b73 vendor-inert there); printer trailing-pred
//!    PT elision on the RELU _P keys (== PT && !inv -> omitted).
//!
//! Lost 121a family-overlap pair (HFMA2, UIMNMX) from the junk surgery is
//! behavior-neutral: tie-break witnesses pre==post==UIMNMX on all 8 and
//! vendor-RC1 (uimnmx_witnesses.json, t419_5).
//!
//! Witness data: tests/bug419_data.inc (gen419pins.py; rc=2 self-checks):
//! LAW419 828 cells == measure419_post per-cell MATCH; DOCTRINE419 20
//! cells pinned HOLE; UIMNMX419 8 witnesses.
//! Foreign flip WITH attribution (this commit): POSTURE417_419 68 cells
//! CLOSED (post := vendor, tag stays "419"); 4 INVALID3 cells stay HOLE;
//! SOURCE pins t371/t373/t381/t409/t417 + t414 CANON414 -> 2ae87b3
//! (ride-chain). Registration 419-kand LOW (F2-iter226; hint iter228).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug419_data.inc");

const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
const M96: u128 = (1u128 << 96) - 1;

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn text_of(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let ins = parse_sass(text, 0).map_err(|e| e.to_string())?;
    encode_instruction(&ins, t).map_err(|e| e.to_string())
}

/// t419_1: full measured law grid vendor-exact on every leg (828 cells:
/// A-window signs/hsel/inert (417) + A routes +A-F32 geometry + B/C
/// dotted routes + RELU pred law + tok5 markers; per-word x leg x vendor
/// from nvdisasm x4 AGREE EVERY).
#[test]
fn t419_1_law_grid_vendor_exact() {
    for (w, tag, leg, vendor) in LAW419 {
        let t = tab(leg);
        let got = text_of(&t, *w).unwrap_or_else(|| "HOLE".to_string());
        assert_eq!(
            got.as_str(),
            *vendor,
            "419 law {tag} word 0x{w:032x}: {got:?} != vendor {vendor:?}"
        );
    }
}

/// t419_2: INVALID3-mnemonic words stay HOLE on every leg (285/324
/// doctrine: the engine never prints the vendor's invalid marker name).
#[test]
fn t419_2_invalid3_doctrine_hole() {
    for (w, tag, leg, vendor) in DOCTRINE419 {
        assert!(vendor.contains("INVALID3"), "doctrine tag {tag}");
        let t = tab(leg);
        let got = text_of(&t, *w).unwrap_or_else(|| "HOLE".to_string());
        assert_eq!(
            got.as_str(),
            "HOLE",
            "419 doctrine {tag} word 0x{w:032x}: engine printed {got:?} (vendor marker {vendor:?})"
        );
    }
}

/// t419_3: encode direction -- legal mints circle byte-exact to the vendor
/// law canonical words (M96: pins/ctrl not minted); the bare PT-elided
/// RELU mint must set pred=7 and decode back WITHOUT the trailing P.
#[test]
fn t419_3_encode_circles_and_bare_relu() {
    // canonical law canonical words (from arb419; texts are the vendor
    // prints pinned by LAW419):
    let circles: &[(&str, &str, u128)] = &[
        (
            "sm120",
            "@P0 HADD2.SAT R0, R0, 0, 0",
            0x00000000000020000000000000000430 & M96,
        ),
        (
            "sm120",
            "@P0 HADD2.F32.SAT R0, R0, 0",
            0x00000000000060000000000000000430 & M96,
        ),
        (
            "sm120",
            "@P0 HADD2.BF16_V2.FTZ.SAT R0, R0, 0, 0",
            0x00000000002120000000000000000430 & M96,
        ),
        (
            "sm120",
            "HFMA2.BF16_V2.FMZ.SAT R0, R0, 1, 1, R0",
            0x00000000002030003f803f8000007831 & M96,
        ),
        (
            "sm120",
            "HFMA2.FTZ.SAT R0, R0, 1, 1, R0",
            0x00000000000120003c003c0000007831 & M96,
        ),
        (
            "sm120",
            "HFMA2.BF16_V2.RELU R0, R0, 1, 1, R0, P1",
            0x0000000000a080003f803f8000007831 & M96,
        ),
        (
            "sm120",
            "HFMA2.BF16_V2 R0, R0, 1, 1, R0.H0_H0",
            0x00000000002400003f803f8000007831 & M96,
        ),
        (
            "sm103a",
            "HFMA2 R0, R0, 1, 1, R0.H1_H1",
            0x00000000000600003c003c0000007831 & M96,
        ),
    ];
    for (leg, text, want) in circles {
        let t = tab(leg);
        let w = enc(&t, &format!("{text} ;"))
            .unwrap_or_else(|e| panic!("{leg} mint failed for {text:?}: {e}"));
        assert_eq!(
            w & M96,
            *want,
            "{leg} mint {text:?}: word 0x{:032x} != canonical law word 0x{:032x}",
            w & M96,
            want
        );
        let back = text_of(&t, w).unwrap_or_else(|| "HOLE".to_string());
        assert_eq!(back.as_str(), *text, "{leg} roundtrip {text:?}");
    }
    // bare RELU (PT elided): pred defaults to 7, decode elides the slot:
    for leg in LEGS {
        if leg == "sm121a" {
            continue; // 121a era-key mint posture unchanged (t417 contract)
        }
        let t = tab(leg);
        let w = enc(&t, "HFMA2.RELU R1, R2, 1, 1, R3 ;")
            .unwrap_or_else(|e| panic!("{leg} bare-RELU mint failed: {e}"));
        assert_eq!((w >> 87) & 0x7, 7, "{leg}: bare RELU must mint PT (pred=7)");
        assert_eq!((w >> 90) & 1, 0, "{leg}: bare RELU inv bit must stay 0");
        let back = text_of(&t, w).unwrap_or_else(|| "HOLE".to_string());
        assert_eq!(
            back.as_str(),
            "HFMA2.RELU R1, R2, 1, 1, R3",
            "{leg}: PT slot must elide on decode"
        );
        assert!(
            ((w >> 79) & 1) == 1,
            "{leg}: RELU route bit b79 must be set"
        );
    }
}

/// t419_4: encode-loud REFUSES (fail-closed with attribution): the vendor-
/// refused combos never mint; vendor-illegal marker spellings refuse.
#[test]
fn t419_4_encode_refuses() {
    let refuses: &[(&str, &str)] = &[
        ("sm120", "HADD2.BF16_V2.F32 R0, R0, 1"), // x4 vendor-refuse combo
        ("sm120", "HFMA2.BF16_V2.F32 R0, R0, 1, 1, R0"), // INVALID3 (b85xb78)
        ("sm120", "HFMA2.BF16_V2.SAT.RELU R0, R0, 1, 1, R0, P0"), // SAT+RELU refuse
        ("sm120", "HFMA2.FMZ.SAT.RELU R0, R0, 1, 1, R0, P0"), // FMZ+SAT+RELU refuse
        ("sm120", "HFMA2.BF16_V2 R0, R0, 1, 1, R0.H0_H1"), // 306-law tok5
        ("sm100a", "HADD2.F32 R0, R0.INVALID1, 1"), // INVALID1 literal
    ];
    for (leg, text) in refuses {
        let t = tab(leg);
        let r = enc(&t, &format!("{text} ;"));
        assert!(
            r.is_err(),
            "{leg}: {text:?} must refuse (minted 0x{:032x})",
            r.unwrap_or(0)
        );
    }
}

/// t419_5: row-shape + claim-contract audit (machine-verifiable).
#[test]
fn t419_5_row_shape_audit() {
    // HADD2 '' on every leg: NO tok0 fields over [72:86) (the era junk);
    // route bits NOT in variable_mask (care-routing); new mgs exist.
    for leg in LEGS {
        let t = tab(leg);
        let m = t
            .get("HADD2_R_R_FI_FI", "")
            .unwrap_or_else(|| panic!("{leg} HADD2 ''"));
        let route: u128 = (1 << 77) | (1 << 78) | (1 << 80) | (1 << 85);
        assert_eq!(
            m.variable_mask & route,
            0,
            "{leg}: HADD2 '' vm still carries route bits (misroute posture)"
        );
        for f in &m.fields {
            assert!(
                !(f.token_idx == 0 && f.shift >= 72 && f.shift < 86),
                "{leg}: HADD2 '' junk tok0 field at shift {} survives",
                f.shift
            );
        }
        for want in ["SAT", "FTZ", "BF16_V2", "FTZ,SAT", "BF16_V2,FTZ,SAT"] {
            assert!(
                t.get("HADD2_R_R_FI_FI", want).is_some(),
                "{leg}: missing HADD2 mg {want:?}"
            );
        }
        for key in [
            "HADD2.F32_R_R_FI",
            "HADD2.F32.SAT_R_R_FI",
            "HADD2.F32.FTZ_R_R_FI",
        ] {
            assert!(t.get(key, "").is_some(), "{leg}: missing {key}");
        }
        // F32 absorb law: the F32,SAT row's vm must carry b80.
        let fs = t.get("HADD2.F32.SAT_R_R_FI", "").unwrap();
        assert_ne!(
            fs.variable_mask & (1 << 80),
            0,
            "{leg}: F32,SAT must relax b80 (absorb law)"
        );
        // HFMA2 R-final parents: tok5 hsel on '' + BF16_V2; route care.
        for pk in ["HFMA2_R_R_FI_FI_R", "HFMA2_R_R_II_II_R"] {
            if t.get(pk, "").is_none() {
                continue; // II_II exists on 120/121a only
            }
            for mg in ["", "BF16_V2"] {
                let m = t.get(pk, mg).unwrap_or_else(|| panic!("{leg} {pk}|{mg}"));
                assert!(
                    m.fields
                        .iter()
                        .any(|f| f.bits == 2 && f.shift == 81 && f.token_idx == 5),
                    "{leg} {pk}|{mg}: hsel(2)@81 tok5 missing"
                );
                let hrt: u128 = 0x1f << 76;
                assert_eq!(
                    m.variable_mask & hrt,
                    0,
                    "{leg} {pk}|{mg}: route bits in vm"
                );
            }
            // RELU decode dotted claim + encode_only parent admission:
            let _ = t
                .get("HFMA2.RELU_R_R_FI_FI_R_P", "")
                .unwrap_or_else(|| panic!("{leg}: RELU dotted key missing"));
            let relu_tok6_pred = t
                .get("HFMA2_R_R_FI_FI_R", "RELU")
                .unwrap_or_else(|| panic!("{leg}: parent RELU mg missing"));
            assert!(
                relu_tok6_pred.encode_only,
                "{leg}: parent RELU mg must be encode_only"
            );
        }
        if leg != "sm121a" {
            continue;
        }
        // 121a junk surgery: no tok0 junk reg fields over [76:96):
        for mg in ["", "BF16_V2"] {
            let m = t.get("HFMA2_R_R_FI_FI_R", mg).unwrap();
            for f in &m.fields {
                assert!(
                    !(f.token_idx == 0 && f.bits == 8 && f.shift >= 76 && f.shift < 96),
                    "sm121a {mg}: junk tok0 route/pred field at shift {} survives",
                    f.shift
                );
            }
        }
    }
}

/// t419_6: 121a UIMNMX tie-break neutrality (junk-surgery side-effect):
/// every double-claim witness decodes exactly like pre-graft.
#[test]
fn t419_6_uimnmx_witnesses_unchanged() {
    let t = tab("sm121a");
    for (w, pre) in UIMNMX419 {
        let got = text_of(&t, *w).unwrap_or_else(|| "HOLE".to_string());
        assert_eq!(
            got.as_str(),
            *pre,
            "sm121a UIMNMX witness 0x{w:032x}: {got:?} != pre-graft {pre:?}"
        );
    }
}

/// t419_7: vendored tables pin canonical 2ae87b3 (BUG-419 graft).
#[test]
fn t419_7_source_pin() {
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        m["base_revision"].as_str().unwrap().starts_with("cc2f62c"), // ride F2-iter278 (BUG-467 canonical graft 668f842; was 67b54f4 BUG-466)
        "SOURCE.json must pin canonical 57e7ecd [was ffa3244 = BUG-441, bb1ba6c = BUG-438, 54c5b02 = BUG-439, 3032686 = BUG-423, 61858fb = BUG-433, 0a6b178 = BUG-435+434+435b, 1810912 = 435+434 hop, 70eb0fe = BUG-416, 52cb73c = BUG-425+425b, 3f6ca6f = BUG-425, 616f185 = BUG-429, a5e6d0a = BUG-427, 2a631d5 = BUG-426, 291ed59b = BUG-424, 13e13b6 = BUG-421+422] (BUG-442 graft F2-iter246 z atrybucja; ride-chain): {:?}",
        m["base_revision"]
    );
}
