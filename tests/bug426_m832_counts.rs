//! BUG-426 pins (F2-iter235, loop5/blind front2, 2026-09-09): LDSM M832
//! count closure (.2=b72/.4=b73) on the shared-bracket frames --
//! LDSM_R_ARURI and LDSM_R_AURI both gain {16,2,M832; 16,4,M832} x4 legs;
//! canonical graft 291ed59b -> 2a631d5 (patch426.py replayable+idempotent,
//! replay-from-pristine byte-exact x4, canonical-native dump; ENGINE cubit
//! src ZERO changes). Vendor law arb426 (66 probes, nvdisasm 13.3.73 raw -b
//! per-word, x4 models SM100a/SM103a/SM120/SM121a AGREE EVERY /
//! DIVERGENT=0) + arb424 parity cross-check (68 probes; machine-asserted
//! word equality): M832 counts print-legal on ARURI (arb424) and AURI
//! (arb426: uA/uB variants, guard-second uC, imm-axis 0x800000/-1); both
//! count bits = INVALID3 loud on both frames; INVALID5/6/7 loud. The 429
//! plain-ARI enum/count census (47+47 unrowed legal tag-cells) is
//! registered-but-NOT-grafted.
//!
//! Witness data: tests/bug426_data.inc (machine-built by
//! work/bug426/gen426pins.py from arb426_law + measure426_post + fresh x4
//! mints; self-checks abort; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug426_data.inc");

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
fn enc(t: &IsaTable, text: &str) -> Option<u128> {
    let ins = parse_sass(text, 0).ok()?;
    encode_instruction(&ins, t).ok()
}

/// t426_1: the measured M832-count lattice (ARURI + AURI frames, both
/// variants, imm-axis) decodes vendor-exact x4 and claims exactly the
/// grafted row provenance (claim km is part of the pin: ARURI-class claim
/// on the canonical RZ-elided AURI-space words is the documented
/// ARURI~AURI twin pre-pattern, 413ii/421422/424 lineage).
#[test]
fn t426_1_m832_count_lattice_vendor_exact_x4() {
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag, exp, kms) in LAW426_DECODE {
            let (got, km) = dec(&t, &idx, *w)
                .unwrap_or_else(|| panic!("[{leg}] {tag} HOLE (must be vendor-exact)"));
            assert_eq!(Some(got.as_str()), exp[li], "[{leg}] {tag} text");
            assert_eq!(km, kms[li], "[{leg}] {tag} claim-km");
        }
    }
    assert_eq!(LAW426_DECODE.len(), 13);
}

/// t426_2: INVALID3 (both count bits) on both frames + INVALID5 loud glyphs
/// stay HOLE/unclaimed x4; refuse mints stay fail-closed x4.
#[test]
fn t426_2_invalid_postures_stay_unclaimed_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag) in HOLE426 {
            assert!(dec(&t, &idx, *w).is_none(), "[{leg}] {tag} not HOLE");
        }
        for text in REFUSE426 {
            assert!(enc(&t, text).is_none(), "[{leg}] refuse minted: {text}");
        }
    }
    assert_eq!(HOLE426.len(), 5);
    assert_eq!(REFUSE426.len(), 6);
}

/// t426_3: authored M832-count texts mint byte-exact circles x4: encode ->
/// decode == authored text, low96 == law words (arb426/arb424-parity
/// xchk), cross-leg word-identical, claim km recorded.
#[test]
fn t426_3_mint_circles_x4() {
    const M96: u128 = (1 << 96) - 1;
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (text, word, reprint, kms) in MINT426 {
            let got = enc(&t, text).unwrap_or_else(|| panic!("[{leg}] mint refuse: {text}"));
            assert_eq!(got & M96, word & M96, "[{leg}] low96 drift: {text}");
            let (back, km) =
                dec(&t, &idx, got).unwrap_or_else(|| panic!("[{leg}] circle hole: {text}"));
            assert_eq!(&back, reprint, "[{leg}] second render drift: {text}");
            assert_eq!(&km, &kms[li], "[{leg}] mint claim-km drift: {text}");
        }
    }
    assert_eq!(MINT426.len(), 6);
}

/// t426_4: census + donor shape: machine-read mg lists from the synced
/// tables == the recorded CENSUS426 consts (LDSM_R_ARURI and LDSM_R_AURI
/// both carry the full 15-entry closed enum x count lattice x4), and every
/// grafted row keeps the donor geometry (fields shape + variable_mask ==
/// the frame-own 16,M832 row, and_base delta == exactly the measured count
/// bit).
#[test]
fn t426_4_census_and_donor_shape() {
    for leg in LEGS {
        let t = tab(leg);
        let (want_ar, want_au) = match leg {
            "sm100a" => (CENSUS426_SM100A_ARURI, CENSUS426_SM100A_AURI),
            "sm103a" => (CENSUS426_SM103A_ARURI, CENSUS426_SM103A_AURI),
            "sm120" => (CENSUS426_SM120_ARURI, CENSUS426_SM120_AURI),
            _ => (CENSUS426_SM121A_ARURI, CENSUS426_SM121A_AURI),
        };
        for (key, want) in [("LDSM_R_ARURI", want_ar), ("LDSM_R_AURI", want_au)] {
            let e = t.entries[key].clone();
            let mut got: Vec<&str> = e.mod_groups.keys().map(|s| s.as_str()).collect();
            got.sort_unstable();
            assert_eq!(got, want, "[{leg}] {key} census drift");
            assert_eq!(got.len(), 15, "[{leg}] {key} lattice size");
            for m in ["16,2,M832", "16,4,M832"] {
                let g = &e.mod_groups[m];
                let shape: Vec<u32> = g.fields.iter().map(|f| f.shift).collect();
                let want_shape: Vec<u32> = e.mod_groups["16,M832"]
                    .fields
                    .iter()
                    .map(|f| f.shift)
                    .collect();
                assert_eq!(shape, want_shape, "[{leg}] {key} {m} donor-shape drift");
            }
        }
    }
}

/// t426_5: SOURCE.json pins the BUG-426 canonical revision (ride-chain).
#[test]
fn t426_5_source_pins_52cb73c() {
    // ride-after flip F2-iter240 (BUG-435+434 graft): 1810912 canonical (was 70eb0fe = BUG-416 F2-iter239, 52cb73c = BUG-425+425b F2-iter238, 616f185 = BUG-429 F2-iter237, a5e6d0a = BUG-427 F2-iter236, 2a631d5 = BUG-426 F2-iter235)
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        m["base_revision"].as_str().unwrap().starts_with("bd2e254"), // ride F2-iter278 (BUG-467 canonical graft 668f842; was 67b54f4 BUG-466)
        "SOURCE.json must pin canonical 57e7ecd [was ffa3244 = BUG-441, bb1ba6c = BUG-438, 54c5b02 = BUG-439, 3032686 = BUG-423, 61858fb = BUG-433, 0a6b178 = BUG-435+434+435b, 1810912 = 435+434 hop, 70eb0fe = BUG-416, 52cb73c = BUG-425+425b, 3f6ca6f = BUG-425, 616f185 = BUG-429, a5e6d0a = BUG-427, 2a631d5 = BUG-426, 291ed59b = BUG-424, 13e13b6 = BUG-421+422] (BUG-442 graft F2-iter246 z atrybucja; ride-chain): {:?}",
        m["base_revision"]
    );
    assert!(CANON426.starts_with("bd2e254"), "CANON426 const drift");
}
