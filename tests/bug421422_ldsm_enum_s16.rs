//! BUG-421+422 pins (F2-iter233, loop5/blind front2, 2026-09-09): LDSM
//! mod-enum [80:78) closure M816(2)/M832(3)/MT1616(4) x counts {1,2,4} on
//! the shared-bracket frame (ARURI+AURI twins) + LDS.S16 width window
//! [75:73)=011 on the AURI frame; canonical graft 0eddad5 -> 13e13b6
//! (ride: BUG-425 canonical 52cb73c F2-iter238, pin flips only; ride: BUG-429 canonical 616f185 F2-iter237, pin flips only; ride: BUG-427 canonical a5e6d0a F2-iter236: S16 frame+scale closure -> REFUSE421 11->6, MINT421 11->16, cordon lifted; ride BUG-426 canonical 2a631d5 F2-iter235: M832 counts closed -> HOLE421 10->8, REFUSE421 13->11, MINT421 9->11; ride BUG-424 canonical 291ed59b F2-iter234, pin flips only)
//! (patch421422.py replayable+idempotent, replay-from-pristine byte-exact,
//! idem all-skip; ENGINE cubit src ZERO changes). Vendor law arb413+arb413b
//! (204 probes, nvdisasm 13.3.73 raw -b per-word, x4 models AGREE EVERY /
//! DIVERGENT=0); count law b72='.2'/b73='.4'/both=INVALID3 measured for
//! e1/e2/e4 (M832 counts UNMEASURED -> stay refused/unclaimed); INVALID5/6/7
//! loud glyphs stay unclaimed; 420 addr_scale field NOT inherited by S16
//! (scale on the S16 carrier MEASURED legal x4 by arb427 in BUG-427 --
//! the 421422 cordon (care pins [79:78)=0; refuse-pinned) was lifted in
//! F2-iter236; original 421422 note:
//! refuses S16-scale mints).
//!
//! Witness data: tests/bug421422_data.inc (machine-built by
//! work/bug421422/gen421422pins.py from arb413/arb413b law +
//! measure413_{pre,post}421422 + fresh x4 mints; self-checks abort; no
//! hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug421422_data.inc");

const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
        .ok()
}
fn enc(t: &IsaTable, text: &str) -> Option<u128> {
    let ins = parse_sass(text, 0).ok()?;
    encode_instruction(&ins, t).ok()
}

/// t421_1: the enum lattice decodes vendor-exact x4 -- the 7 grafted
/// M816/M832/MT1616 combos + their single-bit witness twins + 4 standing
/// M88/MT88 controls.
#[test]
fn t421_1_enum_grid_vendor_exact_x4() {
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag, exp) in LAW421_DECODE {
            let got = dec(&t, &idx, *w);
            assert_eq!(got.as_deref(), exp[li], "[{leg}] {tag}");
        }
    }
    assert_eq!(LAW421_DECODE.len(), 13);
}

/// t421_2: INVALID3 (both count bits, three spellings), INVALID5/6/7 enum
/// glyphs decode as HOLE x4 (not "???", not a wrong-row claim) and refuse
/// to mint, x4. (FLIP BUG-426 F2-iter235: the M832 count constructs closed
/// -- mints+claims pinned in MINT421/bug426 pack.)
#[test]
fn t421_2_invalid_and_unmeasured_stay_unclaimed_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag) in HOLE421 {
            assert!(dec(&t, &idx, *w).is_none(), "[{leg}] {tag} not HOLE");
        }
        for text in REFUSE421 {
            assert!(enc(&t, text).is_none(), "[{leg}] refuse minted: {text}");
        }
    }
    // FLIP (BUG-426, F2-iter235): M832-count constructs closed on both frames; 10 -> 8.
    assert_eq!(HOLE421.len(), 8);
    // FLIP (BUG-427, F2-iter236): the five S16-scale/ARI-frame forms healed
    // (RZ-scale x3 + ARI x2 -> MINT421); 11 -> 6. (426 shed M832.2/.4; 13 -> 11.)
    assert_eq!(REFUSE421.len(), 6);
}

/// t421_3 + t422_2: authored texts mint byte-exact circles x4 (cross-leg
/// word-identical; low96 pinned at gen time to the law words where a pure
/// witness exists; reprint == authored text).
#[test]
fn t421_3_t422_2_mint_circles_x4() {
    const M96: u128 = (1u128 << 96) - 1;
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (text, word, reprint) in MINT421 {
            let got = enc(&t, text).unwrap_or_else(|| panic!("[{leg}] mint refuse: {text}"));
            assert_eq!(got & M96, word & M96, "[{leg}] low96 drift: {text}");
            let back = dec(&t, &idx, got).unwrap_or_else(|| panic!("[{leg}] circle hole: {text}"));
            assert_eq!(&back, reprint, "[{leg}] second render drift: {text}");
        }
    }
    // FLIP (BUG-426, F2-iter235): += the two healed M832-count circles (.2/.4 [UR4]); was 9.
    // FLIP (BUG-427, F2-iter236): += five healed S16 circles (RZ.X4/X8/X16+UR4 +
    // ARI-frame S16 plain/scale); was 11 (426:
    // += two healed M832-count circles; was 9).
    assert_eq!(MINT421.len(), 16);
}

/// t421_4: structure census -- mg sets per leg machine-read at gen time;
/// S16 field shape: the 413ii F_AURI quadruple + the 420 addr_scale arm
/// (FLIP BUG-427 F2-iter236: cordon lifted -- scale-on-S16 measured legal x4;
/// was: WITHOUT addr_scale, scale-S16 cordon contract): guard/reg/sub_ur0/
/// sub_imm1 + addr_scale@78.
#[test]
fn t421_4_structure_census() {
    for leg in LEGS {
        let t = tab(leg);
        let aruri: Vec<&str> = t.entries["LDSM_R_ARURI"]
            .mod_groups
            .keys()
            .map(|s| s.as_str())
            .collect();
        let auri: Vec<&str> = t.entries["LDSM_R_AURI"]
            .mod_groups
            .keys()
            .map(|s| s.as_str())
            .collect();
        let lds: Vec<&str> = t.entries["LDS_R_AURI"]
            .mod_groups
            .keys()
            .map(|s| s.as_str())
            .collect();
        let (e_aruri, e_auri, e_lds): (&[&str], &[&str], &[&str]) = match leg {
            "sm100a" => (
                CENSUS_SM100A_ARURI,
                CENSUS_SM100A_AURI,
                CENSUS_SM100A_LDS_AURI,
            ),
            "sm103a" => (
                CENSUS_SM103A_ARURI,
                CENSUS_SM103A_AURI,
                CENSUS_SM103A_LDS_AURI,
            ),
            "sm120" => (CENSUS_SM120_ARURI, CENSUS_SM120_AURI, CENSUS_SM120_LDS_AURI),
            _ => (
                CENSUS_SM121A_ARURI,
                CENSUS_SM121A_AURI,
                CENSUS_SM121A_LDS_AURI,
            ),
        };
        let mut s1 = aruri.clone();
        s1.sort_unstable();
        assert_eq!(s1, e_aruri, "[{leg}] ARURI mg-set drift");
        let mut s2 = auri.clone();
        s2.sort_unstable();
        assert_eq!(s2, e_auri, "[{leg}] AURI mg-set drift");
        let mut s3 = lds.clone();
        s3.sort_unstable();
        assert_eq!(s3, e_lds, "[{leg}] LDS_R_AURI mg-set drift");
        let s16 = &t.entries["LDS_R_AURI"].mod_groups["S16"];
        let shape: Vec<(u32, u32)> = s16.fields.iter().map(|f| (f.shift, f.bits)).collect();
        assert_eq!(
            shape,
            [(12, 4), (16, 8), (32, 8), (40, 24), (78, 2)],
            "[{leg}] S16 field-shape drift (FLIP BUG-427: addr_scale arm REQUIRED; was: guard/reg/sub_ur0/sub_imm1 only, cordon)"
        );
        for mg in [
            "16,M816",
            "16,2,M816",
            "16,4,M816",
            "16,M832",
            "16,MT1616",
            "16,2,MT1616",
            "16,4,MT1616",
        ] {
            assert!(
                t.entries["LDSM_R_ARURI"].mod_groups.contains_key(mg)
                    && t.entries["LDSM_R_AURI"].mod_groups.contains_key(mg),
                "[{leg}] {mg} missing"
            );
        }
        // FLIP (BUG-426, F2-iter235): M832 counts measured legal (arb426 law)
        // and grafted on both frames -- posture 'unmeasured/unrowed' inverted
        // to present-with-donor-shape (was !contains_key at 13e13b6/291ed59b).
        for mg in ["16,2,M832", "16,4,M832"] {
            assert!(
                t.entries["LDSM_R_ARURI"].mod_groups.contains_key(mg)
                    && t.entries["LDSM_R_AURI"].mod_groups.contains_key(mg),
                "[{leg}] {mg} missing (426 graft)"
            );
        }
    }
}

/// t422_1: the S16 AURI window decodes vendor-exact x4 with the width-window
/// context controls (S8 base / b73->U8 / b75->64 byte-parity kept).
#[test]
fn t422_1_s16_grid_vendor_exact_x4() {
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag, exp) in LAW422_DECODE {
            let got = dec(&t, &idx, *w);
            assert_eq!(got.as_deref(), exp[li], "[{leg}] {tag}");
        }
    }
    assert_eq!(LAW422_DECODE.len(), 5);
}

/// t422_3: 428-kand posture pin -- the bare-UR bracket scale token
/// '[UR4.X4]' is silently unapplied on EVERY width carrier (pre-existing;
/// S8 sibling witness pre==post on 0eddad5): the minted word equals the
/// plain mint. NOT an overclaim (zero scale bits emitted = the
/// measured-legal word). (FLIP BUG-427 F2-iter236: the MEASURED scale
/// forms [RZ.Xn+URm] now mint -- pinned in MINT421; the bare-bracket
/// [UR4.X4] drop posture below is unchanged, word-identical.)
#[test]
fn t422_3_bare_bracket_scale_drop_posture() {
    for leg in LEGS {
        let t = tab(leg);
        let plain = enc(&t, "LDS.S16 R93, [UR4] ;").unwrap();
        let dropped = enc(&t, "LDS.S16 R93, [UR4.X4] ;").unwrap();
        assert_eq!(plain, dropped, "[{leg}] 428 posture drift");
        assert_eq!(plain, POSTURE428_WORD, "[{leg}] 428 word drift");
    }
}

/// t421_5: SOURCE.json pins the graft canonical revision (ride-chain).
#[test]
fn t421_5_source_pins_52cb73c() {
    // ride-after flip F2-iter238 (BUG-425 graft): 52cb73c canonical (was 616f185 = BUG-429 F2-iter237, a5e6d0a = BUG-427 F2-iter236, 2a631d5 = BUG-426 F2-iter235, 291ed59b = BUG-424 F2-iter234)
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        m["base_revision"].as_str().unwrap().starts_with("d560e99"),
        "SOURCE.json must pin canonical 52cb73c [was 3f6ca6f = BUG-425, 616f185 = BUG-429, a5e6d0a = BUG-427, 2a631d5 = BUG-426, 291ed59b = BUG-424, 13e13b6 = BUG-421+422, 0eddad5 = BUG-420] (BUG-425+425b grafts F2-iter238(A/B) z atrybucja; ride-chain): {:?}",
        m["base_revision"]
    );
    assert_eq!(m["base_revision"].as_str().unwrap(), CANON421422);
}
