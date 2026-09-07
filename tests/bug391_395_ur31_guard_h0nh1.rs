//! BUG-391 + BUG-395 pins (F2-iter223, loop5/blind front2, 2026-09-07):
//! HFMA2 0x7c31 (R_R_UR_R) guard window audit + tok3 h0nh1 closure.
//!
//! 391 AUDIT-CLOSED (zero table change, 397-doctrine): guard@[15:12] is
//! vendor-variable on the 0x7c31 window (arb391 61 probes, nvdisasm
//! 13.3.73 raw -b, x4 models SM100a/103a/120/121a AGREE EVERY,
//! DIVERGENT=0): full sweep x16 == the shipped 'guard' extraction map
//! (0..6 -> @P0..6, 7 -> elide, 8..14 -> @!P0..6, 15 -> @!PT), composing
//! with the whole mod lattice, RELU pv7-bake, the dotted RELU_P keys and
//! the tok3 sign/h0nh1 forms. The engine ALREADY decodes+encodes every
//! guard form vendor-exact on ALL FOUR legs via the generic tok0 guard
//! path (claim attribution pinned in t391_3); the F2-iter203 registration
//! (381.md sec.5, "tabele pinuja [15:12]=7 = LOUD HOLE") is an engine-era
//! artefact overtaken by later waves (measure_pre391 on publish
//! cubit_py-ff198e07: 115x4 = OK 367 / HOLE 93 / WRONG 0; every HOLE
//! carries h0nh1 => 395-class, zero guard HOLEs).
//!
//! 395 FIXED (canonical graft 74a06b7 -> d908ee9, x3 sparse legs, ENGINE
//! src ZERO): tok3 h0nh1@86 was missing on the 0x7c31 rows of
//! sm100a/sm103a/sm120 (present on sm121a): every h0nh1-carrying form
//! ('-UR4.H0_NH1' joint incl.) was DECODE-HOLE + ENCODE-refuse pre-fix
//! (30/30 per leg; singles neg@63/abs@62 engine-global OK). Vendor law
//! arb395 (54 probes x4 AGREE EVERY, DIVERGENT=0): singles + all pairs +
//! triple legal on plain/SAT/FTZ/OOB/BF16_V2/RELU carriers incl dotted
//! RELU_P; hsel!=0 x h0nh1 -> vendor INVALID{5,6,7} markers (stay
//! fail-closed = 285-doctrine, pinned t395_5; sm121a shipped that posture
//! already). Graft: HFMA2_R_R_UR_R (36 mgs) + HFMA2.*RELU_R_R_UR_R_P (12
//! keys) += {token_idx:3, shift:86, bits:1, extraction:'h0nh1'} on the 3
//! sparse legs (donor-law verbatim from sm121a same-name rows;
//! adding-only field: care shrinks by bit86, and_base invariant; sm121a
//! byte-invariant). Corpus census391_395 (ab240 battery 2,406 cubins x4
//! legs, pre-graft care): 70 claims, ZERO with guard!=7 or b62|b63|b86
//! set = graft corpus-invisible.
//!
//! Witnesses: tests/bug391_395_data.inc (machine-built by
//! work/bug391x/gen391_395pins.py from arb391/arb395 law files; no hand
//! hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

mod data {
    include!("bug391_395_data.inc");
}
use data::*;

const M96: u128 = (1 << 96) - 1;
const LEGS4: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec96(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}
fn text_of(t: &IsaTable, w: u128) -> Option<String> {
    dec96(t, w).map(|s| s.trim_end_matches(';').trim().to_string())
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let ins = parse_sass(text, 0).map_err(|e| e.to_string())?;
    encode_instruction(&ins, t).map_err(|e| e.to_string())
}

/// t391_1: guard law -- every arb391 probe decodes vendor-exact on x4 legs
/// (incl sweep x16, mod carriers, RELU pv7-bake, dotted RELU_P rows and
/// guard x tok3-joint composes).
#[test]
fn t391_1_guard_law_vendor_exact() {
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (w, tag, ven) in LAW391 {
        for (li, leg) in LEGS4.iter().enumerate() {
            let got = text_of(&tabs[li], *w)
                .unwrap_or_else(|| panic!("391 leg {leg} tag {tag}: HOLE on 0x{w:032x}"));
            assert_eq!(
                got.as_str(),
                *ven,
                "391 leg {leg} tag {tag} word 0x{w:032x}"
            );
        }
    }
}

/// t391_2: every guard nibble value 0..15 renders through the shipped map
/// (the 397-class audit-freeze; vendor x4 AGREE on each cell).
#[test]
fn t391_2_guard_map_sweep() {
    let base: u128 = LAW391
        .iter()
        .find(|(_, tag, _)| *tag == "arb391.A_plain_g7")
        .map(|(w, _, _)| *w)
        .expect("law base cell");
    let want = [
        "@P0 ", "@P1 ", "@P2 ", "@P3 ", "@P4 ", "@P5 ", "@P6 ", "", "@!P0 ", "@!P1 ", "@!P2 ",
        "@!P3 ", "@!P4 ", "@!P5 ", "@!P6 ", "@!PT ",
    ];
    for g in 0..16u128 {
        let w = (base & !(0xf << 12)) | (g << 12);
        for a in LEGS4 {
            let t = tab(a);
            let got =
                text_of(&t, w).unwrap_or_else(|| panic!("391 map leg {a} g{g}: HOLE 0x{w:032x}"));
            assert!(
                got.starts_with(&format!("{}HFMA2 ", want[g as usize])),
                "391 map leg {a} g{g}: {got:?}"
            );
        }
    }
}

/// t391_3: claim attribution -- guard!=7 words strict-claim the HFMA2
/// 0x7c31 rows (plain key or RELU _P dotted key), never a foreign family.
#[test]
fn t391_3_guard_claim_route() {
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (w, tag, _ven) in LAW391 {
        if (w >> 12) & 0xf == 7 {
            continue; // elided guard cell still pins the unguarded claim
        }
        for (li, leg) in LEGS4.iter().enumerate() {
            let idx = DecodeIndex::build(&tabs[li]);
            let d = idx
                .decode(*w & M96, 0, &tabs[li])
                .unwrap_or_else(|_| panic!("391 route leg {leg} tag {tag}: HOLE"));
            assert!(
                d.key == "HFMA2_R_R_UR_R" || d.key.ends_with("RELU_R_R_UR_R_P"),
                "391 route leg {leg} tag {tag}: claimed by {}",
                d.key
            );
        }
    }
}

/// t395_1: tok3 h0nh1 law -- every legal arb395 probe decodes vendor-exact
/// on x4 legs (pre-fix HOLE on the 3 sparse legs; sm121a shipped).
#[test]
fn t395_1_h0nh1_law_vendor_exact() {
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (w, tag, ven) in LAW395 {
        for (li, leg) in LEGS4.iter().enumerate() {
            let got = text_of(&tabs[li], *w)
                .unwrap_or_else(|| panic!("395 leg {leg} tag {tag}: HOLE on 0x{w:032x}"));
            assert_eq!(
                got.as_str(),
                *ven,
                "395 leg {leg} tag {tag} word 0x{w:032x}"
            );
        }
    }
}

/// t395_2: the grafted rows carry the donor field verbatim -- h0nh1
/// {tok3, 1b@86} present on every HFMA2_R_R_UR_R mg + every RELU _R_R_UR_R_P
/// key, on x4 legs; and_base on every such row keeps bit86 == 0 (adding-only
/// invariant).
#[test]
fn t395_2_donor_field_structure() {
    for leg in LEGS4 {
        let t = tab(leg);
        let mut rows = 0usize;
        for (k, e) in &t.entries {
            let fam = k == "HFMA2_R_R_UR_R" || k.ends_with("RELU_R_R_UR_R_P");
            if !fam {
                continue;
            }
            for g in e.mod_groups.values() {
                let has = g.fields.iter().any(|f| {
                    f.extraction == Extraction::H0NH1
                        && f.shift == 86
                        && f.bits == 1
                        && f.token_idx == 3
                });
                assert!(has, "{leg}|{k}: missing donor h0nh1 field");
                let ab: u128 = g.and_base.into();
                assert_eq!(ab & (1 << 86), 0, "{leg}|{k}: and_base widened");
                rows += 1;
            }
        }
        assert_eq!(rows, 48, "{leg}: 0x7c31 row count drift");
    }
}

/// t395_3: mint circles -- vendor-true texts (guard forms + h0nh1 forms)
/// re-encode to the source words on every leg (low96 byte-exact).
#[test]
fn t395_3_mint_circles() {
    let mut n = 0usize;
    for (w, text) in CIRCLE391_395 {
        for a in LEGS4 {
            let t = tab(a);
            let eb = enc(&t, text)
                .unwrap_or_else(|e| panic!("395 mint refuse leg {a} text {text}: {e}"));
            assert_eq!(
                eb & M96,
                w & M96,
                "395 mint circle leg {a} text {text} -> 0x{:032x} != 0x{:032x}",
                eb & M96,
                w & M96
            );
            n += 1;
        }
    }
    assert!(n >= 40 * 4, "circle census too thin: {n}");
}

/// t395_4: claim attribution -- h0nh1 words strict-claim the 0x7c31 family
/// rows (plain key or RELU _P dotted key).
#[test]
fn t395_4_h0nh1_claim_route() {
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (w, tag, _ven) in LAW395 {
        if w & (1 << 86) == 0 {
            continue;
        }
        for (li, leg) in LEGS4.iter().enumerate() {
            let idx = DecodeIndex::build(&tabs[li]);
            let d = idx
                .decode(*w & M96, 0, &tabs[li])
                .unwrap_or_else(|_| panic!("395 route leg {leg} tag {tag}: HOLE"));
            assert!(
                d.key == "HFMA2_R_R_UR_R" || d.key.ends_with("RELU_R_R_UR_R_P"),
                "395 route leg {leg} tag {tag}: claimed by {}",
                d.key
            );
        }
    }
}

/// t395_5: hsel!=0 x h0nh1 on tok3 = vendor INVALID{5,6,7} markers; the
/// engine stays fail-closed (decode HOLE + encode refuses the marker
/// spelling) on x4 legs -- 285-doctrine, sm121a shipped this posture
/// already pre-graft (measure_pre391: 3 HOLEs on sm121a exactly these).
#[test]
fn t395_5_invalid_markers_fail_closed() {
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (w, tag, ven) in INVALID395 {
        assert!(ven.contains(".INVALID"), "INVALID set drift: {tag} {ven}");
        for (li, leg) in LEGS4.iter().enumerate() {
            assert!(
                text_of(&tabs[li], *w).is_none(),
                "395 INVALID leg {leg} tag {tag}: decoded 0x{w:032x}"
            );
            assert!(
                enc(&tabs[li], ven).is_err(),
                "395 INVALID leg {leg} tag {tag}: marker text encoded"
            );
        }
    }
}

/// t395_6: guard-rail regression -- the engine-global tok3 single signs
/// (neg@63/abs@62 without h0nh1) stay vendor-exact x4 (they were OK
/// pre-fix on every leg; the graft must not tear them).
#[test]
fn t395_6_single_sign_regression_rail() {
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    let mut n = 0usize;
    for (w, tag, ven) in LAW395 {
        if w & (1 << 86) != 0 {
            continue;
        }
        if !(tag.contains("_neg") || tag.contains("_abs")) {
            continue;
        }
        for (li, leg) in LEGS4.iter().enumerate() {
            let got = text_of(&tabs[li], *w)
                .unwrap_or_else(|| panic!("395 rail leg {leg} tag {tag}: HOLE"));
            assert_eq!(got.as_str(), *ven, "395 rail leg {leg} tag {tag}");
            n += 1;
        }
    }
    assert!(n >= 10 * 4, "rail census too thin: {n}");
}
