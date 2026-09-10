//! BUG-427 pins (F2-iter236, loop5/blind front2, 2026-09-09): LDS.S16 on
//! the ARI/ARURI frames + S16 addr-scale [79:78) closure on all three LDS
//! carriers -- LDS_R_ARI and LDS_R_ARURI gain S16 (U16 donor-clone, and_base
//! |= b73 window delta, fields+vm verbatim incl the 420 addr_scale arm,
//! count=None) and LDS_R_AURI|S16 gains the addr_scale arm (421422 cordon
//! lifted by measurement) -- canonical graft 2a631d5 -> a5e6d0a (ride F2-iter237: 616f185 = BUG-429; ride F2-iter238: 52cb73c = BUG-425)
//! (patch427.py replayable+idempotent, replay-from-pristine byte-exact x4,
//! canonical-native dump; ENGINE cubit src ZERO changes). Vendor law arb427
//! (43 probes, DONOR-CLONE construction [v1 lesson: the LDS uniform opclass
//! validates the opex selector in [96:128), and_base-OR is invalid],
//! nvdisasm 13.3.73 raw -b per-word, x4 models SM100a/SM103a/SM120/SM121a
//! AGREE EVERY / DIVERGENT=0): S16 prints legal x4 on both frames; scale
//! b78='.X4' b79='.X8' both='.X16' legal x4 on every S16 carrier incl the
//! RZ-elided AURI-space form '[RZ.Xn+URm+imm]'. w7 'LDS.???7' loud glyphs
//! stay unclaimed (423-era doctrine). 429 (LDSM plain-ARI enum/count)
//! NOT grafted.
//!
//! Witness data: tests/bug427_data.inc (machine-built by
//! work/bug427/gen427pins.py from arb427_law + measure427_post + fresh x4
//! mints; self-checks abort; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug427_data.inc");

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

/// t427_1: the measured S16 frame-lattice (ARURI x scale x imm-axis,
/// ARI x scale x imm-axis, fuzz witnesses w1/w2/w3) decodes vendor-exact
/// x4 and claims exactly the grafted row provenance (AURI-space RZ-elided
/// scale cells claim via the ARURI~AURI twin pre-pattern, 413ii/421422/424/
/// 426 lineage; text vendor-exact both sides).
#[test]
fn t427_1_s16_frame_lattice_vendor_exact_x4() {
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag, exp, kms) in LAW427_DECODE {
            let (got, km) = dec(&t, &idx, *w)
                .unwrap_or_else(|| panic!("[{leg}] {tag} HOLE (must be vendor-exact)"));
            assert_eq!(Some(got.as_str()), exp[li], "[{leg}] {tag} text");
            assert_eq!(km, kms[li], "[{leg}] {tag} claim-km");
        }
        for (w, tag, exp) in LAW427_STANDING {
            let (got, _km) =
                dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] standing {tag} HOLE"));
            assert_eq!(Some(got.as_str()), exp[li], "[{leg}] standing {tag} text");
        }
    }
    assert_eq!(LAW427_DECODE.len(), 27);
    assert_eq!(LAW427_STANDING.len(), 13);
}

/// t427_2: w7 'LDS.???7' era loud-glyphs (423 doctrine) stay HOLE/unclaimed
/// x4; refuse mints (S15/R256/UR256/imm-overflow/INVALID3-mod/no-bracket)
/// stay fail-closed x4.
#[test]
fn t427_2_era_glyphs_and_refuse_stay_unclaimed_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag) in HOLE427 {
            assert!(dec(&t, &idx, *w).is_none(), "[{leg}] {tag} not HOLE");
        }
        for text in REFUSE427 {
            assert!(enc(&t, text).is_none(), "[{leg}] refuse minted: {text}");
        }
    }
    assert_eq!(HOLE427.len(), 3);
    assert_eq!(REFUSE427.len(), 6);
}

/// t427_3: authored S16 texts mint byte-exact circles x4: encode -> decode
/// == authored text, low96 == arb427 law words, cross-leg word-identical,
/// claim km recorded.
#[test]
fn t427_3_mint_circles_x4() {
    const M96: u128 = (1 << 96) - 1;
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (text, word, reprint, kms) in MINT427 {
            let got = enc(&t, text).unwrap_or_else(|| panic!("[{leg}] mint refuse: {text}"));
            assert_eq!(got & M96, word & M96, "[{leg}] low96 drift: {text}");
            let (back, km) =
                dec(&t, &idx, got).unwrap_or_else(|| panic!("[{leg}] circle hole: {text}"));
            assert_eq!(&back, reprint, "[{leg}] second render drift: {text}");
            assert_eq!(&km, &kms[li], "[{leg}] mint claim-km drift: {text}");
        }
    }
    assert_eq!(MINT427.len(), 14);
}

/// t427_4: census + donor shape: mg lists of all three LDS frames == the
/// recorded CENSUS427 consts (S16 everywhere: {'',128,64,S16,S8,U16,U8}),
/// every grafted row keeps the U16 donor geometry (fields shape + vm == the
/// frame-own U16 row, and_base delta == exactly b73; AURI keeps its 421422
/// ab/vm and gains the 420 addr_scale arm shape).
#[test]
fn t427_4_census_and_donor_shape() {
    for leg in LEGS {
        let t = tab(leg);
        for (key, want_mgs) in [
            (
                "LDS_R_ARI",
                match leg {
                    "sm100a" => CENSUS427_SM100A_ARI,
                    "sm103a" => CENSUS427_SM103A_ARI,
                    "sm120" => CENSUS427_SM120_ARI,
                    _ => CENSUS427_SM121A_ARI,
                },
            ),
            (
                "LDS_R_ARURI",
                match leg {
                    "sm100a" => CENSUS427_SM100A_ARURI,
                    "sm103a" => CENSUS427_SM103A_ARURI,
                    "sm120" => CENSUS427_SM120_ARURI,
                    _ => CENSUS427_SM121A_ARURI,
                },
            ),
            (
                "LDS_R_AURI",
                match leg {
                    "sm100a" => CENSUS427_SM100A_ARURI,
                    "sm103a" => CENSUS427_SM103A_ARURI,
                    "sm120" => CENSUS427_SM120_ARURI,
                    _ => CENSUS427_SM121A_ARURI,
                },
            ),
        ] {
            let e = t.entries[key].clone();
            let mut got: Vec<&str> = e.mod_groups.keys().map(|s| s.as_str()).collect();
            got.sort_unstable();
            assert_eq!(got, want_mgs, "[{leg}] {key} census drift");
            let g = &e.mod_groups["S16"];
            let d = &e.mod_groups["U16"];
            let shape: Vec<(u32, u32)> = g
                .fields
                .iter()
                .filter(|f| !matches!(f.extraction, cubit::table::Extraction::AddrScale))
                .map(|f| (f.shift, f.bits))
                .collect();
            let want: Vec<(u32, u32)> = d
                .fields
                .iter()
                .filter(|f| !matches!(f.extraction, cubit::table::Extraction::AddrScale))
                .map(|f| (f.shift, f.bits))
                .collect();
            assert_eq!(shape, want, "[{leg}] {key} S16 fields drift (minus scale)");
            let sc: Vec<_> = g
                .fields
                .iter()
                .filter(|f| matches!(f.extraction, cubit::table::Extraction::AddrScale))
                .collect();
            assert_eq!(sc.len(), 1, "[{leg}] {key} S16 scale-arm count");
            assert_eq!(
                (sc[0].shift, sc[0].bits),
                (78, 2),
                "[{leg}] {key} S16 scale-arm"
            );
            if key != "LDS_R_AURI" {
                assert_eq!(
                    g.and_base ^ d.and_base,
                    1u128 << 73,
                    "[{leg}] {key} S16 ab delta != b73"
                );
                assert_eq!(
                    g.variable_mask, d.variable_mask,
                    "[{leg}] {key} S16 vm drift"
                );
            }
        }
    }
}

/// t427_5: SOURCE.json pins the BUG-427 canonical revision (ride-chain).
#[test]
fn t427_5_source_pins_52cb73c() {
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        m["base_revision"].as_str().unwrap().starts_with("d560e99"),
        "SOURCE.json must pin canonical 52cb73c [was 3f6ca6f = BUG-425, 616f185 = BUG-429, a5e6d0a = BUG-427, 2a631d5 = BUG-426, 291ed59b = BUG-424, 13e13b6 = BUG-421+422, 0eddad5 = BUG-420] (BUG-425+425b grafts F2-iter238(A/B) z atrybucja; ride-chain): {:?}",
        m["base_revision"]
    );
    assert!(CANON427.starts_with("d560e99"), "CANON427 const drift");
    assert_eq!(m["base_revision"].as_str().unwrap(), CANON427);
}

/// t427_6: POSTURE430 (430-kand registration): scale tokens with unbound
/// values ('.X2'/'.X32') and the '???7' loud glyph mint -- but silently
/// drop the token and emit the plain/no-scale word. PRE-EXISTING posture
/// (OLD publish d3f50bdf + canonical 2a631d5 behaves identically on the
/// standing U16 carriers; S16 joined that posture by acquiring rows -- the
/// BUG-132 guard fired pre-graft only because the S16 modifier itself was
/// unknown). Pinned loud so a future engine fix flips deliberately.
#[test]
fn t427_6_posture430_silent_drops_pinned() {
    for leg in LEGS {
        let t = tab(leg);
        for (drop, plain, want) in POSTURE430 {
            let w1 = enc(&t, drop).unwrap_or_else(|| panic!("[{leg}] {drop} must mint (posture)"));
            let w2 = enc(&t, plain).unwrap_or_else(|| panic!("[{leg}] {plain} must mint"));
            assert_eq!(w1, w2, "[{leg}] posture drift: {drop}");
            assert_eq!(w1, *want, "[{leg}] posture word drift: {drop}");
        }
    }
    assert_eq!(POSTURE430.len(), 4);
}
