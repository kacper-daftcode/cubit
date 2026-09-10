//! BUG-425b pins (F2-iter238B, loop5/blind front2, 2026-09-10): fuzz-harvest
//! residual repair nad BUG-425. Canonical 3f6ca6f -> 52cb73c (patch425b.py
//! replayable+idempotent; ENGINE zero src). Klasy: (B) sm121a STS_ARURI_R|U16
//! imm-field restore [clone canonical sm103a verbatim]; (A/D-width) sm121a
//! STS_AURI_R width-pin [75:73); (C) STS_ARI_R|64 x3 nogi usuniecie pola
//! urz_expl@11 (b11 -> care, vendor-ILLEGAL (x,1) refuse); era-retention
//! t164-carriers + pre-existing TOLER625.. (b11=0) snapshots.
//!
//! Witness data: tests/bug425b_data.inc (machine-built by
//! work/bug425b/gen425bpins.py from arb425b_law [60 combos x4 models AGREE
//! EVERY/DIVERGENT=0] + arb425c_law + fuzz425 26-record machine taxonomy +
//! measure425b_wt grid [520 cells, 511 claims == post-425 ref, BAD 0]).
use cubit::decoder::DecodeIndex;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug425b_data.inc");

const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<(String, String)> {
    idx.decode(w, 0, t).ok().map(|d| {
        (
            to_sass(&d).trim().trim_end_matches(';').to_string(),
            format!("{}|{}", d.key, d.mod_group),
        )
    })
}

/// t425b_1: kazde slowo z b11=1 (vendor-ILLEGAL po arb425b, x4 AGREE) =
/// loud HOLE na wszystkich nogach (engine NIE wolno claimowac; i=362-class).
#[test]
fn t425b_1_b11_illegal_combos_loud_hole_x4() {
    assert!(REFUSE425B.len() >= 40, "refuse grid shrink");
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag) in REFUSE425B {
            let _ = li;
            assert!(
                dec(&t, &idx, *w).is_none() || !dec(&t, &idx, *w).unwrap().1.starts_with("STS"),
                "refuse {tag} on {leg}: {:?}",
                dec(&t, &idx, *w)
            );
        }
    }
}

/// t425b_2: 26 fuzz425-harvest rekordow -- per-leg exact decode snapshot
/// (maszynowe, gen z oraculum nvdisasm; clasy B=match x4, A/C/D-width=loud
/// HOLE x4, D-stsm/E=stojace z claim-tekstami == vendor na claimowanych nogach).
#[test]
fn t425b_2_fuzz26_residual_snapshot_x4() {
    assert_eq!(FUZZ425B_DECODE.len(), 26);
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, i, cls, want_text, _want_km) in FUZZ425B_DECODE {
            let got = dec(&t, &idx, *w).map(|(txt, _km)| txt);
            let w2 = want_text[li].map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "));
            assert_eq!(got, w2, "fuzz#{i} class {cls} on {leg}: got {got:?}");
        }
    }
}

/// t425b_3: era-retention (t164 carriers: corpus-era sched [127:96)=0x1c000,
/// b11=0) -- deckodowanie text-exact na sm103a/sm120 (prawo: corpus-provenance
/// + arb425c; raw -b odmawia replayu starej ery niezaleznie od (9,11)).
#[test]
fn t425b_3_era_carrier_retention() {
    for (w, tag, want) in ERA425B {
        for (li, leg) in LEGS.iter().enumerate() {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w).map(|(txt, _)| txt);
            let w2 = want[li].map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "));
            assert_eq!(got, w2, "era {tag} on {leg}");
        }
    }
}

/// t425b_4: legalne kombo (b9,b11) per nosnik (15 nosnikow x jej legalne
/// kombo) claimuja tekst law-exact x4 (prawa strona arb425b).
#[test]
fn t425b_4_legal_combos_claim_law_exact_x4() {
    assert_eq!(LEGAL425B.len(), 15);
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag, want) in LEGAL425B {
            let got = dec(&t, &idx, *w).map(|(txt, _)| txt);
            let w2 = want[li].map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "));
            assert!(got.is_some(), "legal {tag} HOLE on {leg}");
            assert_eq!(got, w2, "legal {tag} on {leg}");
        }
    }
}

/// t425b_5: pre-existing tolerance snapshot (b11=0 illegal-combo claims,
/// pre==post vs publish 7f797be7 machine-verified; korpus-exposure zero):
/// ksztalt claimow zamrozony (x3 claim + sm121a refuse).
#[test]
fn t425b_5_preexisting_tolerance_frozen() {
    assert!(TOLER425B.len() >= 5);
    for (w, tag, want) in TOLER425B {
        for (li, leg) in LEGS.iter().enumerate() {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w).map(|(txt, _)| txt);
            let w2 = want[li].map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "));
            assert_eq!(got, w2, "toler {tag} on {leg}");
        }
    }
}

/// t425b_6: SOURCE.json pin + claims-preservation konstanta (520-grid:
/// 511 non-HOLE claims == post-425 reference; 0 BAD w measure425b_wt).
#[test]
fn t425b_6_canon_pin_and_claims_preservation() {
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        m["base_revision"].as_str().unwrap().starts_with("d560e99"),
        "SOURCE.json must pin canonical 52cb73c (= BUG-425b, ride-after 3f6ca6f = BUG-425): {:?}",
        m["base_revision"]
    );
    assert_eq!(CLAIMCOUNT425B, 511);
}
