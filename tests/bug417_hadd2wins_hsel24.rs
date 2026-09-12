//! BUG-417 pins (F2-iter226, loop5/blind front2, 2026-09-08): tail of
//! BUG-405/406 (registration 417-kand LOW, 405_406.md sec.6).
//!
//! (a) HADD2_R_R_FI_FI '' row [64:90) window lattice: [64:72)+b76+b79+
//! [81:85)+[86:90) vendor-INERT on all four legs (engine: HOLE on 120/121a
//! for [64:72), HOLE on 100a/103a for b76/b79, HOLE x4 for the hi block);
//! b72='-R0'/b73='|R0|'/72+73='-|R0|' on tok2 (engine dropped the sign on
//! 100a/103a -- that era's row carries no neg field: the format_reg neg
//! fallback only fires for NO-field rows, and the field-carrying 100a row
//! read only the raw-bit ABS fallback); b74/b75/74+75 =
//! R0.INVALID1/R0.H0_H0/R0.H1_H1 tok2 hsel on 100a/103a (engine printed
//! plain R0). Vendor law arb417 (71 probes, nvdisasm 13.3.73 raw -b,
//! x4 models SM100a/SM103a/SM120/SM121a AGREE EVERY, DIVERGENT=0).
//! (b) tok2 hsel window [74:76) on the HFMA2 two-imm R-final rows
//! (HFMA2_R_R_FI_FI_R + HFMA2_R_R_II_II_R mgs '' + BF16_V2): engine
//! claimed the words but printed plain R0 where vendor prints
//! .INVALID1/.H0_H0/.H1_H1. The BUG-306 laws are already armed engine-side
//! (r_hsel_invalid1_slot: HADD2 all slots + HFMA2 tok2/tok4 ->
//! '.INVALID1'; 'H0_H1' authored mint fails closed; '.INVALID1' literal
//! refused upstream by the BUG-272 suffix gate) -- table-only graft adds
//! the fields where missing (x11 rows; sm121a FI_FI_R already armed by
//! bug270; sm120/121a HADD2 '' already armed by bug261/266-era grafts).
//!
//! Graft (canonical c7f1d39 -> NEW, patch417.py replayable+idempotent,
//! monotone relax / field-adds only, and_base invariant, collision audit
//! zero family-overlap deltas): HADD2_R_R_FI_FI '' x4 legs vm |= INERT
//! ([64:72)|76|79|[81:85)|[86:90)); sm100a/103a '' rows +fields
//! neg@72/abs@73/hsel(2)@74 tok2; hsel(2)@74 tok2 on the two-imm R-final
//! HFMA2 rows x4 legs where missing.
//!
//! Encode-loud posture (registration requirement): '.INVALID1' literal and
//! '.H0_H1' on these slots REFUSE (t417_3); the legal '.H0_H0'/'.H1_H1'
//! mint roundtrips byte-exact (t417_3, law words).
//!
//! Corpus exposure pre-fix (census417, ab240 2,406 cubins x4 legs,
//! publish dbef92a0): HFMA2 two-imm rows = 12,942 clean claims/leg, ZERO
//! with b74/75 set (decode-side invisible graft there); HADD2 '' = 7
//! signhsel claims + 1 free claim/leg (100a/103a era words; the same words
//! are HOLE on 120/121a pre). Every distinct touched word measured
//! NEW == vendor x4 (attr417_corpus.json; t417_5).
//!
//! NOT grafted -> registered 419-kand LOW (posture pins t417_4):
//!  - A-frame mod-group routes b77='.SAT'/b78='.F32 (3-tok)'/b80='.FTZ'/
//!    b85='.BF16_V2' x4 (rows do not exist; on 120/121a era-junk tok0
//!    fields misroute the claims to plain print = pre-existing silent-wrong
//!    kept byte-pinned; own bug with its own mg-lattice arb).
//!  - B/C-frame routes b76('.FMZ')/b77('.SAT')/b78('.F32'|INVALID3)/
//!    b79('.RELU trailing-P')/b80('.FTZ') x4 (missing dotted R-final rows).
//!  - B/C tok5 hsel window [81:83) b81='R0.INVALID1'/b82='R0.H0_H0' x4
//!    (needs r_hsel_invalid1_slot extension to HFMA2 tok5 = engine change).
//!  B.bit78 vendor 'HFMA2.INVALID3 ...' = INVALID-mnemonic -> engine HOLE
//!  is the 285/324-doctrine posture (kept, pinned).
//!
//! Witness data: tests/bug417_data.inc (gen417pins.py; rc=2 self-checks).
//! Foreign flip WITH attribution: POSTURE405_6 24 cells CLOSED (post :=
//! vendor, tag 417-closed) inside bug405_406_data.inc header note.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug417_data.inc");

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

/// t417_1: A-frame window lattice now vendor-exact on every leg
/// (inert prints, tok2 signs, tok2 hsel; 28 singles + 7 combos x4 legs).
#[test]
fn t417_1_a_windows_vendor_exact() {
    for (w, tag, vendor) in LAW417_A {
        for leg in LEGS {
            let t = tab(leg);
            let got = text_of(&t, *w).unwrap_or_else(|| "HOLE".to_string());
            assert_eq!(
                got.as_str(),
                *vendor,
                "417 A-law {tag} leg {leg} word 0x{w:032x}: {got:?} != vendor {vendor:?}"
            );
        }
    }
}

/// t417_2: B/C-frame tok2 hsel markers vendor-exact on every leg.
#[test]
fn t417_2_bc_tok2_markers_vendor_exact() {
    for (w, tag, vendor) in LAW417_BC {
        for leg in LEGS {
            let t = tab(leg);
            let got = text_of(&t, *w).unwrap_or_else(|| "HOLE".to_string());
            assert_eq!(
                got.as_str(),
                *vendor,
                "417 BC-law {tag} leg {leg} word 0x{w:032x}: {got:?} != vendor {vendor:?}"
            );
        }
    }
}

/// t417_3: encode direction -- legal mints circle byte-exact to the vendor
/// law words; illegal marker spellings stay REFUSED with attribution.
#[test]
fn t417_3_encode_loud_and_circles() {
    // mint circles on the FIXED classes (law words, M96 compare):
    let circles: &[(&str, u128, &str)] = &[
        (
            "sm100a",
            0x00000000000001000000000000000430,
            "@P0 HADD2 R0, -R0, 0, 0",
        ),
        (
            "sm103a",
            0x00000000000001000000000000000430,
            "@P0 HADD2 R0, -R0, 0, 0",
        ),
        (
            "sm100a",
            0x00000000000003000000000000000430,
            "@P0 HADD2 R0, -|R0|, 0, 0",
        ),
        (
            "sm103a",
            0x00000000000008000000000000000430,
            "@P0 HADD2 R0, R0.H0_H0, 0, 0",
        ),
        (
            "sm100a",
            0x00000000002008003f803f8000007831,
            "HFMA2.BF16_V2 R0, R0.H0_H0, 1, 1, R0",
        ),
        (
            "sm103a",
            0x00000000002008003f803f8000007831,
            "HFMA2.BF16_V2 R0, R0.H0_H0, 1, 1, R0",
        ),
        (
            "sm120",
            0x00000000002008003f803f8000007831,
            "HFMA2.BF16_V2 R0, R0.H0_H0, 1, 1, R0",
        ),
        (
            "sm120",
            0x0000000000200c003f803f8000007831,
            "HFMA2.BF16_V2 R0, R0.H1_H1, 1, 1, R0",
        ),
        (
            "sm100a",
            0x00000000000008003c003c0000007831,
            "HFMA2 R0, R0.H0_H0, 1, 1, R0",
        ),
        (
            "sm103a",
            0x00000000000008003c003c0000007831,
            "HFMA2 R0, R0.H0_H0, 1, 1, R0",
        ),
        (
            "sm120",
            0x00000000000008003c003c0000007831,
            "HFMA2 R0, R0.H0_H0, 1, 1, R0",
        ),
    ];
    for (leg, w, text) in circles {
        let t = tab(leg);
        let eb =
            enc(&t, text).unwrap_or_else(|e| panic!("417 mint refuse leg {leg} text {text}: {e}"));
        assert_eq!(
            eb & M96,
            w & M96,
            "417 mint circle leg {leg} text {text}: {eb:032x} != {w:032x}"
        );
        let back = text_of(&t, eb).expect("circle decode");
        assert_eq!(back, *text, "417 mint rt leg {leg} {text}");
    }
    // encode-loud: .INVALID1 literal + .H0_H1 on the grafted slots REFUSE.
    for leg in LEGS {
        let t = tab(leg);
        assert!(
            enc(&t, "HFMA2.BF16_V2 R0, R0.INVALID1, 1, 1, R0").is_err(),
            "{leg}: .INVALID1 literal mint must stay refused (272 gate)"
        );
        assert!(
            enc(&t, "HFMA2.BF16_V2 R0, R0.H0_H1, 1, 1, R0").is_err(),
            "{leg}: .H0_H1 mint on HFMA2 tok2 must fail closed (BUG-306 law)"
        );
        assert!(
            enc(&t, "@P0 HADD2 R0, R0.INVALID1, 0, 0").is_err(),
            "{leg}: HADD2 .INVALID1 literal mint must stay refused"
        );
        assert!(
            enc(&t, "@P0 HADD2 R0, R0.H0_H1, 0, 0").is_err(),
            "{leg}: HADD2 .H0_H1 mint must fail closed (BUG-306 law)"
        );
    }
}

/// t417_4: 419 posture ledger -- [F2-iter228 CLOSED by BUG-419]: the
/// formerly pinned classes (A-frame routes b77/78/80/85, B/C dotted
/// b76..b80, tok5 markers b81/82) are now grafted and every closed cell is
/// flipped WITH ATTRIBUTION to the vendor text (post := vendor, tag "419").
/// The INVALID3 cells (B.bit78 x4) stay doctrine-pinned HOLE (285/324).
#[test]
fn t417_4_untouched_posture_tripwire() {
    for (w, tag, leg, vendor, post, src) in POSTURE417_419 {
        let t = tab(leg);
        let got = text_of(&t, *w).unwrap_or_else(|| "HOLE".to_string());
        assert_eq!(
            got.as_str(), *post,
            "posture drift ({src}) on {tag} word 0x{w:032x}: engine {got:?} != pinned {post:?} (vendor {vendor:?})"
        );
    }
}

/// t417_5: every distinct corpus word touching the graft surfaces decodes
/// NEW == vendor on every leg (attr417_corpus.json, nvdisasm x4).
#[test]
fn t417_5_corpus_witnesses() {
    for (w, leg, vendor) in CORPUS417 {
        let t = tab(leg);
        let got = text_of(&t, *w).unwrap_or_else(|| "HOLE".to_string());
        assert_eq!(
            got.as_str(),
            *vendor,
            "corpus417 leg {leg} word 0x{w:032x}: {got:?} != vendor {vendor:?}"
        );
    }
}

/// t417_6: row-shape invariants of the graft (machine-verifiable):
/// neg@72/abs@73/hsel@74 tok2 present on all four HADD2 '' rows; hsel@74
/// tok2 present on the two-imm R-final HFMA2 rows; and_base invariant.
#[test]
fn t417_6_row_shape_audit() {
    // and_base constants captured pre-graft (publish c7f1d39), one per row/leg:
    let ab_expect: &[(&str, u128)] = &[
        ("sm100a", 0x000fc400000009003c003c00ff000430),
        ("sm103a", 0x000fc400000009003c003c00ff000430),
        ("sm120", 0x00000000000000000000000000000430),
        ("sm121a", 0x00000000000000000000000000000430),
    ];
    for (leg, ab) in ab_expect {
        let t = tab(leg);
        let m = t
            .get("HADD2_R_R_FI_FI", "")
            .unwrap_or_else(|| panic!("{leg} HADD2_R_R_FI_FI|''"));
        assert_eq!(m.and_base, *ab, "{leg} HADD2 '' and_base drift");
        let has = |want: &cubit::table::Extraction, bits: u32, shift: u32, tok: i32| {
            m.fields.iter().any(|f| {
                std::mem::discriminant(&f.extraction) == std::mem::discriminant(want)
                    && f.bits == bits
                    && f.shift == shift
                    && f.token_idx == tok
            })
        };
        assert!(
            has(&cubit::table::Extraction::Neg, 1, 72, 2),
            "{leg} HADD2 '' missing neg@72 tok2"
        );
        assert!(
            has(&cubit::table::Extraction::Abs, 1, 73, 2),
            "{leg} HADD2 '' missing abs@73 tok2"
        );
        assert!(
            has(&cubit::table::Extraction::HalfSel, 2, 74, 2),
            "{leg} HADD2 '' missing hsel@74 tok2"
        );
    }
    let rows: &[(&str, &str)] = &[
        ("sm100a", "HFMA2_R_R_FI_FI_R"),
        ("sm103a", "HFMA2_R_R_FI_FI_R"),
        ("sm120", "HFMA2_R_R_FI_FI_R"),
        ("sm120", "HFMA2_R_R_II_II_R"),
        ("sm121a", "HFMA2_R_R_II_II_R"),
        ("sm121a", "HFMA2_R_R_FI_FI_R"),
    ];
    for (leg, key) in rows {
        let t = tab(leg);
        for mg in ["", "BF16_V2"] {
            let m = t.get(key, mg).unwrap_or_else(|| panic!("{leg} {key}|{mg}"));
            assert!(
                m.fields.iter().any(|f| {
                    std::mem::discriminant(&f.extraction)
                        == std::mem::discriminant(&cubit::table::Extraction::HalfSel)
                        && f.bits == 2
                        && f.shift == 74
                        && f.token_idx == 2
                }),
                "{leg} {key}|{mg} missing hsel@74 tok2 (417/270)"
            );
        }
    }
}

/// t417_7: canonical ride-chain ratchet (SOURCE.json) + graft identity:
/// INERT vm-set present on all four HADD2 '' rows.
#[test]
fn t417_7_source_and_vm_ratchet() {
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").expect("SOURCE.json"))
            .expect("SOURCE.json parse");
    assert!(
        m["base_revision"].as_str().unwrap().starts_with("9b60b92"),
        "SOURCE.json must pin canonical 57e7ecd [was ffa3244 = BUG-441, bb1ba6c = BUG-438, 54c5b02 = BUG-439, 3032686 = BUG-423, 61858fb = BUG-433, 0a6b178 = BUG-435+434+435b, 1810912 = 435+434 hop, 70eb0fe = BUG-416, 52cb73c = BUG-425+425b, 3f6ca6f = BUG-425, 616f185 = BUG-429, a5e6d0a = BUG-427, 2a631d5 = BUG-426, 291ed59b = BUG-424, 13e13b6 = BUG-421+422] (BUG-442 graft F2-iter246 z atrybucja; ride-chain): {:?}",
        m["base_revision"]
    );
    let inert: u128 = (0xFFu128 << 64) | (1 << 76) | (1 << 79) | (0xF << 81) | (0xF << 86);
    for leg in LEGS {
        let t = tab(leg);
        let mm = t.get("HADD2_R_R_FI_FI", "").expect("HADD2 '' row");
        assert_eq!(
            mm.variable_mask & inert,
            inert,
            "{leg} HADD2 '' INERT vm-set drift"
        );
    }
}
