//! BUG-425b pins (F2-iter238B, loop5/blind front2, 2026-09-10): fuzz-harvest
//! residual repair over BUG-425. Canonical 3f6ca6f -> 52cb73c (patch425b.py
//! replayable + idempotent; ENGINE zero src). Classes: (B) sm121a STS_ARURI_R|U16
//! imm-field restore [clone canonical sm103a verbatim]; (A/D-width) sm121a
//! STS_AURI_R width pin [75:73); (C) STS_ARI_R|64 on 3 legs: the field
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

/// 2026-11-08 (T-18, rows-memory-2026-11-07): on sm120 these law-grid words carry a bit the measured
/// LDS / STS / LDSM / STSM rows fail closed on -- the text-inert control / sub-UR / gap bits nvdisasm
/// names as the base word (verified: nvdisasm text == the base text, 0 census witnesses). The measured-row
/// convention; the three other legs keep the harvest tolerance.
const SM120_FAIL_CLOSED: &[u128] = &[
    0x000fc200880005e0ffffff04ff00e988u128,
    // 2026-11-08 (T-19, rows-memory-2026-11-07): the measured STS_ARURI_R / STL_AURI_R rows read the UR base in 8 bits --
    // bit 72 is text-inert for nvdisasm 13.1 on every width (tools/probes/re_sm120_rows.py --family memory) -- so the
    // grid's bit-72 carriers are holes on sm120 now (0 census witnesses; T-19 whole-census parity)
    0x000fc2000800033500000004ff009988u128,  // was @!P1 STS.S8 [UR53], R4
    0x000fc2000800039580000004ff007988u128,  // was STS.S8 [UR149+-0x800000], R4
    0x000fc2000800052e7fffff040a007988u128,  // was STS.U16 [R10+UR46+0x7fffff], R4
    0x000fc2000800055263eb67040a007988u128,  // was STS.U16 [R10+UR82+0x63eb67], R4
    0x000fc200080005af800001040a007988u128,  // was STS.U16 [R10+UR175+-0x7fffff], R4
    0x000fc200080005ba7fffff040a007988u128,  // was STS.U16 [R10+UR186+0x7fffff], R4
    0x000fc2000800144e800001040a00e988u128,  // was @!P6 STS.U16 [R10+UR78+-0x7fffff], R4
    0x000fc200080015c63b9218040a007988u128,  // was STS.U16 [R10+UR198+0x3b9218], R4
    0x000fc20008002484800000040a007988u128,  // was STS.U16 [R10+UR132+-0x800000], R4
    0x000fc2000800456c7ffffe040a006988u128,  // was @P6 STS.U16 [R10.X4+UR108+0x7ffffe], R4
    0x000fc200080047322e5ada04ff007988u128,  // was STS.S16 [RZ.X4+UR50+0x2e5ada], R4
    0x000fc200080055257ffffe040a001988u128,  // was @P1 STS.U16 [R10.X4+UR37+0x7ffffe], R4
    0x000fc20008010461ffffff040a007988u128,  // was STS.U16 [R10+UR97+-0x1], R4
    0x000fc200080104ff7ffffe040a007988u128,  // was STS.U16 [R10+URZ+0x7ffffe], R4
];


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

include!("t25_fail_closed.inc");

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
            // T-18: the measured STS row fails closed on its text-inert bits on sm120 (SM120_FAIL_CLOSED)
            if *leg == "sm120" && SM120_FAIL_CLOSED.contains(w) {
                assert!(got.is_none(), "fuzz#{i} class {cls} on {leg}: measured row tolerates a text-inert bit");
                continue;
            }
            let w2 = want_text[li].map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "));
            // T-25 (2026-11-09): the STS rows are measured on sm100a / sm103a / sm121a as well (rows-memory-2026-11-07 on
            // -b SM100 / SM103 / SM121) -- the clean word's reading keeps the vendor pin on the fail-closed cells
            let got = match want_text[li] {
                Some(want) => got.or_else(|| t25_closed_as(&t, *w, Some(want)).map(|s| s.trim().trim_end_matches(';').to_string())),
                None => got,
            };
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
        m["base_revision"].as_str().unwrap().starts_with("b230bc541119ee47454d8718583619f32c296186" /* 2026-11-06 T-11 (was c258f8a, T-10) */), /* 2026-11-06 T-10 (was b75cc20) */ // ride F2-iter278 (BUG-467 canonical graft 668f842; was 67b54f4 BUG-466)
        "SOURCE.json must pin canonical e03e0348d98b9d20ffb4ca557cfc6eae625cf995 (= BUG-452 narrow, ride-after 4ee843162216e75d037135b5907c819759471296, = BUG-454 graft, ride-after 589be874 (= BUG-450) (= BUG-450 graft, ride-after 099faa0 = BUG-447, ride-after e8d1af3 = BUG-443, 57e7ecd = BUG-442, ffa3244 = BUG-441, bb1ba6c = BUG-438, 54c5b02 = BUG-439, 3032686 = BUG-423, 61858fb = BUG-433, 0a6b178 = BUG-435+434+435b, = BUG-435+435b, ride-after 1810912 = 435+434, 70eb0fe = BUG-416, 52cb73c = BUG-425+425b): {:?}",
        m["base_revision"]
    );
    assert_eq!(CLAIMCOUNT425B, 511);
}
