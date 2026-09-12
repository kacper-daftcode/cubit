//! BUG-441 pins (F2-iter245, loop5/blind front2, 2026-09-11): LDSM 16,M88
//! ARURI frame full inert-band closure x4 legs.
//! Canonical bb1ba6c -> ffa3244 (patch441.py replayable+idempotent; replay
//! z pristine bb1ba6c byte-exact x4 = f4a64d4b/b7c21306/cdb1088e/5305885f;
//! idem rerun all-skip; ENGINE src ZERO). Vendor law arb441 (54 probes,
//! nvdisasm raw -b x4 models AGREE EVERY / DIVERGENT=0;
//! work/bug441/arb441_law.json): band-rest {88,89,93,94} singles + ALL 11
//! combos + cross-D mixes + all-8 mix + rich carriers vendor-legal INERT x4
//! (plain carrier); full inert band {84,85,86,87,88,89,90,92,93,94,95}
//! singles + pairs + full mixes under count carriers .2/.4 vendor-legal x4.
//! Defect pre (measure441_pre; publish cubit_py-c1b901d9 b76c3f1c +
//! canonical bb1ba6c): 3 MATCH + 50 HOLE + 1 RC1-era posture per leg
//! (49 HOLE in graft scope). Graft: G1 x4 plain row vm |= 0x63<<88
//! (band-rest); G2 x4 count rows '16,2,M88'/'16,4,M88' vm |= full inert
//! band; ab/fields/count invariant (pure relax).
//!
//! NOT grafted (pinned here): INVALID3 loud carrier (b72+b73; 285-doctrine);
//! RC1 era carrier class (440-kand; era-cut HOLE->CLAIM transition is the
//! documented ENGINE era-strip doctrine, same as arb423 C.b122/123/124).
//!
//! Witness data: tests/bug441_data.inc (machine-built by
//! work/bug441/gen441pins.py; rc=2 self-checks; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug441_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

/// t441_1: healed grid -- decode == vendor x4 legs on every graft-scope word
/// (22 plain + 14 count.2 + 13 count.4 = 49 words, 196 cell-legs; every one
/// engine-HOLE pre-graft on every leg).
#[test]
fn t441_1_healed_grid_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW441_HEAL {
            let got = dec(&t, &idx, *w)
                .unwrap_or_else(|| panic!("[{leg}] LDSM {vendor} HOLE (must decode post-graft)"));
            assert_eq!(&got, vendor, "[{leg}] healed text != vendor");
        }
    }
    assert_eq!(LAW441_HEAL.len(), 49);
}

/// t441_2: carrier anchors vendor-exact pre==post (A.ref + A.cnt2 + A.cnt4) x4.
#[test]
fn t441_2_stable_anchors_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW441_STABLE {
            let got =
                dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] stable anchor HOLE: {vendor}"));
            assert_eq!(&got, vendor, "[{leg}] stable anchor drift");
        }
    }
    assert_eq!(LAW441_STABLE.len(), 3);
}

/// t441_3: INVALID3 loud carrier (b72+b73) stays engine-HOLE on every leg
/// pre==post (vendor prints the INVALID3 form; loud class NOT grafted,
/// 285-doctrine).
#[test]
fn t441_3_invalid3_posture_standing_hole() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag) in POSTURE441_INVALID3 {
            assert!(
                dec(&t, &idx, *w).is_none(),
                "[{leg}] {tag}: INVALID3 loud class must stay HOLE (NOT grafted)"
            );
        }
    }
}

/// t441_4: RC1 era carrier (440-kand era-cut doctrine) -- engine strips era
/// [127:96) per standing rule, so post-graft this cell decodes via the plain
/// row (HOLE -> CLAIM transition documented; vendor refuses the word x4).
#[test]
fn t441_4_rc1_era_car_eracut_claim() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag) in RC1CARRIERS441 {
            let got = dec(&t, &idx, *w)
                .unwrap_or_else(|| panic!("[{leg}] {tag}: era-cut claim lost (440-doctrine)"));
            assert_eq!(
                &got, "LDSM.16.M88 R16, [UR4]",
                "[{leg}] {tag}: era-cut claim text drift"
            );
        }
    }
}

/// t441_5: masked mints -- encode of vendor text never sets relaxed-band bits
/// (graft is decode-side only); masked byte-compare vs the law word (band
/// mask + era excluded) + decode circle == vendor text, x4 legs.
#[test]
fn t441_5_masked_mints_and_circles() {
    const ERA: u128 = 0xffffffffu128 << 96;
    const BAND: u128 = (1u128 << 84)
        | (1u128 << 85)
        | (1u128 << 86)
        | (1u128 << 87)
        | (1u128 << 88)
        | (1u128 << 89)
        | (1u128 << 90)
        | (1u128 << 92)
        | (1u128 << 93)
        | (1u128 << 94)
        | (1u128 << 95);
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, text, mask) in MASKMINT441 {
            let ins = parse_sass(&format!(" {text} ;"), 0)
                .unwrap_or_else(|e| panic!("[{leg}] parse {text}: {e}"));
            let w2 = encode_instruction(&ins, &t)
                .unwrap_or_else(|e| panic!("[{leg}] encode {text}: {e}"));
            assert_eq!(w2 & BAND, 0, "[{leg}] encode sets band bits: {text}");
            let cmp = !(mask | ERA);
            assert_eq!(w2 & cmp, w & cmp, "[{leg}] masked mint drift: {text}");
            let rt = dec(&t, &idx, w2).unwrap_or_else(|| panic!("[{leg}] circle HOLE {text}"));
            assert_eq!(&rt, text, "[{leg}] circle text drift");
        }
    }
    assert_eq!(MASKMINT441.len(), 8);
}

/// t441_6: source manifest + graft invariants -- CANON441 pin ffa3244,
/// ARURI|16,M88 + count rows carry the bug441 _src tag + full band relax x4;
/// plain count bits b72/73 stay strict-cared on the plain row (count rows
/// own); ab contract bit b91=1 retained; j84 relax (423) + D-band (439)
/// retained on the plain row.
#[test]
fn t441_6_source_manifest_and_invariants() {
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        src["base_revision"]
            .as_str()
            .unwrap()
            .starts_with("9b60b92"),
        "SOURCE.json must pin canonical 57e7ecd [was ffa3244 = BUG-441, bb1ba6c = BUG-438, 54c5b02 = BUG-439, 3032686 = BUG-423, 61858fb = BUG-433, 0a6b178 = BUG-435+434+435b, 1810912 = 435+434 hop, 70eb0fe = BUG-416, 52cb73c = BUG-425+425b, 3f6ca6f = BUG-425, 616f185 = BUG-429, a5e6d0a = BUG-427, 2a631d5 = BUG-426, 291ed59b = BUG-424, 13e13b6 = BUG-421+422] (BUG-442 graft F2-iter246 z atrybucja; ride-chain): {:?}",
        src["base_revision"]
    );
    assert!(CANON441.starts_with("9b60b92"), "CANON441 const drift");
    const DBAND: u128 = (1u128 << 84)
        | (1u128 << 85)
        | (1u128 << 86)
        | (1u128 << 87)
        | (1u128 << 88)
        | (1u128 << 89)
        | (1u128 << 90)
        | (1u128 << 92)
        | (1u128 << 93)
        | (1u128 << 94)
        | (1u128 << 95);
    for leg in LEGS {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        let mgi = &ins["LDSM_R_ARURI"]["mod_groups"];
        for mgn in ["16,M88", "16,2,M88", "16,4,M88"] {
            let mg = &mgi[mgn];
            assert_eq!(
                mg["_src"].as_str().unwrap(),
                "bug441-2026-09-11",
                "{leg}: ARURI {mgn} missing BUG-441 graft tag"
            );
            let vm = u128::from_str_radix(
                mg["variable_mask"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap();
            assert_eq!(vm & DBAND, DBAND, "{leg}: {mgn} band relax lost");
            assert_eq!(
                (u128::from_str_radix(
                    mg["and_base"].as_str().unwrap().trim_start_matches("0x"),
                    16,
                )
                .unwrap()
                    >> 91)
                    & 1,
                1,
                "{leg}: {mgn} ab contract bit b91=1 drift"
            );
        }
        let mg = &mgi["16,M88"];
        let vm = u128::from_str_radix(
            mg["variable_mask"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap();
        let mut fbits: u128 = 0;
        for f in mg["fields"].as_array().unwrap() {
            let b = f["bits"].as_u64().unwrap();
            let s = f["shift"].as_u64().unwrap();
            fbits |= ((1u128 << b) - 1) << s;
        }
        let care = !(vm | fbits);
        assert_eq!(
            care & (3 << 72),
            3 << 72,
            "{leg}: plain row count bits b72/73 must stay strict (count rows own)"
        );
    }
}

/// t441_7: sm121a key census unchanged by the graft (pure mask relax:
/// 15726 forms == BUG-442 post state (G3 donor-clone adds key STG_ARURI_R
/// on sm121a: 15725 -> 15726; previous census waves in history).
    /// FLIP (BUG-443, canonical e8d1af3): +19 sm121a keys (8 T2 base E-form
    /// + 11 T3 cross STG other-family enum keys; STS S8/S16 land as mgs and
    /// do not move the counter) 15726 -> 15745.
#[test]
fn t441_7_key_census_unchanged() {
    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm121a.json").unwrap()).unwrap();
    assert_eq!(
        raw["instructions"].as_object().unwrap().len(),
        15745,
        "sm121a key census must equal the BUG-443 post state (8 T2 + 11 T3 noE-cross keys; 442->443)"
    );
}
