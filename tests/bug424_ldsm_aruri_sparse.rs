//! BUG-424 pins (F2-iter234, loop5/blind front2, 2026-09-09): LDSM ARURI-frame
//! sparse enum/count closure -- LDSM_R_ARURI gains {16,2,M88; 16,MT88;
//! 16,2,MT88} on sm100a/103a/120 and {16,MT88} on sm121a; canonical graft
//! 13e13b6 -> 291ed59b (ride F2-iter238: 52cb73c = BUG-425; ride F2-iter237: 616f185 = BUG-429; ride F2-iter236: a5e6d0a = BUG-427; ride F2-iter235: 2a631d5 = BUG-426; patch424 replayable+idempotent, replay-from-
//! pristine byte-exact x4, canonical-native dump [INC-234a healed]; ENGINE
//! cubit src ZERO changes). Vendor law arb424 (68 probes, nvdisasm 13.3.73
//! raw -b per-word, x4 models SM100a/SM103a/SM120/SM121a AGREE EVERY /
//! DIVERGENT=0): full enum x count matrix UNIFORM on the R+UR shared-bracket
//! frame; both count bits = INVALID3 loud; enum 5/6/7 = INVALIDn loud;
//! M832 .2/.4 measured print-legal but NOT rowed (426-scope contract).
//!
//! Witness data: tests/bug424_data.inc (machine-built by
//! work/bug424/gen424pins.py from arb424_law + measure424_{pre,post} + fresh
//! x4 mints; self-checks abort; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug424_data.inc");

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

/// t424_1: the measured ARURI-frame legal lattice decodes vendor-exact x4
/// and claims exactly the row provenance measured post-graft (claim km is
/// part of the pin -- the healed cells must resolve to the grafted
/// LDSM_R_ARURI rows, standing cells to their historical rows).
#[test]
fn t424_1_aruri_lattice_vendor_exact_x4() {
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag, exp, kms) in LAW424_DECODE {
            let (got, km) = dec(&t, &idx, *w)
                .unwrap_or_else(|| panic!("[{leg}] {tag} HOLE (must be vendor-exact)"));
            assert_eq!(Some(got.as_str()), exp[li], "[{leg}] {tag} text");
            assert_eq!(km, kms[li], "[{leg}] {tag} claim-km");
        }
    }
    assert_eq!(LAW424_DECODE.len(), 30);
}

/// t424_2: INVALID3/INVALID5/6/7 glyphs decode as HOLE x4 and refuse to
/// mint x4. (FLIP BUG-426 F2-iter235: the M832-count construct cells closed
/// -- vendor-exact decode + mints pinned in MINT424 / bug426 pack; INVALIDn
/// stay loud-but-unclaimed.)
#[test]
fn t424_2_invalid_and_construct_stay_unclaimed_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag) in HOLE424 {
            assert!(dec(&t, &idx, *w).is_none(), "[{leg}] {tag} not HOLE");
        }
        for text in REFUSE424 {
            assert!(enc(&t, text).is_none(), "[{leg}] refuse minted: {text}");
        }
    }
    // FLIP (BUG-426, F2-iter235): M832-count ARURI constructs closed; 38 -> 34.
    assert_eq!(HOLE424.len(), 34);
    // FLIP (BUG-426, F2-iter235): M832.2/.4 ARURI shed to MINT424; 7 -> 5.
    assert_eq!(REFUSE424.len(), 5);
}

/// t424_3: authored R+UR-bracket texts mint byte-exact circles x4 (cross-leg
/// word-identical; low96 pinned at gen time to the arb424 law words;
/// reprint == authored text).
#[test]
fn t424_3_mint_circles_x4() {
    const M96: u128 = (1u128 << 96) - 1;
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (text, word, reprint) in MINT424 {
            let got = enc(&t, text).unwrap_or_else(|| panic!("[{leg}] mint refuse: {text}"));
            assert_eq!(got & M96, word & M96, "[{leg}] low96 drift: {text}");
            let (back, km) =
                dec(&t, &idx, got).unwrap_or_else(|| panic!("[{leg}] circle hole: {text}"));
            assert_eq!(&back, reprint, "[{leg}] second render drift: {text}");
            assert!(
                km.starts_with("LDSM_R_ARURI|"),
                "[{leg}] mint claims non-ARURI row {km}: {text}"
            );
        }
    }
    // FLIP (BUG-426, F2-iter235): += the two healed M832-count ARURI circles; was 8.
    assert_eq!(MINT424.len(), 10);
}

/// t424_4: structure census -- the grafted rows exist with verbatim donor
/// geometry (guard/reg/sub_r0/sub_ur1/sub_imm1 shape, count=None) and the
/// ARURI mg list matches the machine-read post-sync set.
#[test]
fn t424_4_structure_census() {
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let e = t.entries["LDSM_R_ARURI"].clone();
        let mut got: Vec<&str> = e.mod_groups.keys().map(|s| s.as_str()).collect();
        got.sort_unstable();
        let want: &[&str] = match *leg {
            "sm100a" => CENSUS424_SM100A_ARURI,
            "sm103a" => CENSUS424_SM103A_ARURI,
            "sm120" => CENSUS424_SM120_ARURI,
            _ => CENSUS424_SM121A_ARURI,
        };
        assert_eq!(got, want, "[{leg}] ARURI mg-set drift");
        let targets: &[&str] = if *leg == "sm121a" {
            &["16,MT88"]
        } else {
            &["16,2,M88", "16,MT88", "16,2,MT88"]
        };
        for m in targets {
            let g = &e.mod_groups[*m];
            let shape: Vec<u32> = g.fields.iter().map(|f| f.shift).collect();
            assert_eq!(shape, [12, 16, 24, 32, 40], "[{leg}] {m} donor-shape drift");
            // JSON-side count=None proven at gen time (ModGroupEntry drops it at load).
        }
        let _ = li;
    }
}

/// t424_5: SOURCE.json pins the BUG-424 canonical revision (ride-chain).
#[test]
fn t424_5_source_pins_52cb73c() {
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        m["base_revision"].as_str().unwrap().starts_with("bd2e254"), // ride F2-iter278 (BUG-467 canonical graft 668f842; was 67b54f4 BUG-466)
        "SOURCE.json must pin canonical 57e7ecd [was ffa3244 = BUG-441, bb1ba6c = BUG-438, 54c5b02 = BUG-439, 3032686 = BUG-423, 61858fb = BUG-433, 0a6b178 = BUG-435+434+435b, 1810912 = 435+434 hop, 70eb0fe = BUG-416, 52cb73c = BUG-425+425b, 3f6ca6f = BUG-425, 616f185 = BUG-429, a5e6d0a = BUG-427, 2a631d5 = BUG-426, 291ed59b = BUG-424, 13e13b6 = BUG-421+422] (BUG-442 graft F2-iter246 z atrybucja; ride-chain): {:?}",
        m["base_revision"]
    );
    assert!(CANON424.starts_with("bd2e254"), "CANON424 const drift");
}
