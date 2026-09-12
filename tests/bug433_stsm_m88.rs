//! BUG-433 pins (F2-iter241, loop5/blind front2, 2026-09-10): STSM.16 ARI
//! M88 count closure x4 legs + STS.U16 AURI bare-UR era-band relax x3 legs.
//! Canonical ffa3244 -> 57e7ecd (patch442.py replayable+idempotent; replay z
//! pristine byte-exact x4; idem all-skip; ENGINE src ZERO). Scope:
//!  - x3 legs STSM_ARI_R += 16,M88 + 16,2,M88 (donor own 16,4,M88; plains
//!    were the i=426 fuzz witness family, .2 measured legal x4);
//!  - sm120 NEW KEY STSM_ARI_R (clone sm103a geometry; scheduling from
//!    same-leg STSM.8.MT168.2_AR_R) = whole-family hole from iter238 fuzz;
//!  - sm121a += 16,2,M88 (the only missing count there);
//!  - x3 STS_AURI_R|U16 vm |= (1<<95)|(1<<109)|(1<<115): era-band 8-combo
//!    inert x4 (arb433b K-law; i=690 witness family; 121a healed by 425b).
//!
//! NOT grafted (registration, pinned standing here): STSM MT88/MT168 +
//! b80-alias rows + INVALID3 glyphs; STS_AURI width-family era-band beyond
//! U16; STG AUR-era cavities (438-kand / 423 envelope).
//!
//! Witness data: tests/bug433_data.inc (machine-built by
//! work/bug433/gen433pins.py; rc=2 self-checks; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug433_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
fn enc(t: &IsaTable, text: &str) -> Option<u128> {
    let ins = parse_sass(text, 0).ok()?;
    encode_instruction(&ins, t).ok()
}
const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

/// t433_1: STSM.16 M88 count closure law -- decode == vendor x4 legs
/// (arb433 witness + B/Bv count lattice + C.e0 + D imm-extent + E RZ-clamp
/// + F guard-neg + G legal-era carriers).
#[test]
fn t433_1_stsm_m88_count_closure_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW433_STSM {
            let got = dec(&t, &idx, *w)
                .unwrap_or_else(|| panic!("[{leg}] STSM {vendor} HOLE (must decode)"));
            assert_eq!(&got, vendor, "[{leg}] STSM text != vendor");
        }
    }
    assert_eq!(LAW433_STSM.len(), 42);
}

/// t433_2: STS.U16 AURI bare-UR era-band K-law (8-combo on {95,109,115}) +
/// the i=690 witness -- decode == vendor x4 legs (x3 healed by the vm relax;
/// 121a reference was healed by 425b R6/R7 and must stay).
#[test]
fn t433_2_sts_u16_bare_ur_era_band_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW433_U16 {
            let got = dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] STS.U16 {vendor} HOLE"));
            assert_eq!(&got, vendor, "[{leg}] STS.U16 text != vendor");
        }
    }
    assert_eq!(LAW433_U16.len(), 9);
}

/// t433_3: registered 438-kand postures stay pre==post (machine-snapped):
/// STSM MT88/MT168 + b80-alias coverage holes + INVALID3 count/enum loud
/// glyphs; STS_AURI width-family era-band beyond U16 (witness-bit cells).
#[test]
fn t433_3_postures_pinned_pre_post() {
    for (w, tag_leg, snapped) in POSTURE433 {
        let leg = ["sm121a", "sm120", "sm103a", "sm100a"]
            .iter()
            .find(|l| tag_leg.ends_with(&format!(".{l}")))
            .copied()
            .expect("posture tag without leg suffix");
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let expect = if *snapped == "HOLE" {
            None
        } else {
            Some(snapped.to_string())
        };
        let got = dec(&t, &idx, *w);
        assert_eq!(
            got, expect,
            "[{leg}] posture {tag_leg} drift (must stay pinned)"
        );
    }
    assert_eq!(POSTURE433.len(), 52);
}

/// t433_4: era-rc1 tolerance carriers (decoder cuts the [127:96) band):
/// x3/121a standing pre==post; sm120 acquires the SAME parity posture with
/// the new key (by design -- the old era 0x1c000 is legal and stays claimed).
#[test]
fn t433_4_era_rc1_tolerance_carriers() {
    for (w, tag_leg, snapped) in ERATOL433 {
        let leg = if tag_leg.ends_with(".sm121a") {
            "sm121a"
        } else if tag_leg.ends_with(".sm120") {
            "sm120"
        } else if tag_leg.ends_with(".sm103a") {
            "sm103a"
        } else {
            "sm100a"
        };
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let expect = if *snapped == "HOLE" {
            None
        } else {
            Some(snapped.to_string())
        };
        let got = dec(&t, &idx, *w);
        assert_eq!(got, expect, "[{leg}] era-tolerance {tag_leg} drift");
        assert!(
            got.is_some(),
            "[{leg}] era-tolerance must be CLAIMED (parity): {tag_leg}"
        );
    }
    assert_eq!(ERATOL433.len(), 15);
}

/// t433_5: mint circles (word == vendor-law word; encode+decode circle) x4
/// legs + loud-refuse forms x4 + canonical pin.
#[test]
fn t433_5_mints_refuse_canon() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, text) in MINT433 {
            let minted = enc(&t, text).unwrap_or_else(|| panic!("[{leg}] mint refused: {text}"));
            // witness carriers (wits) keep contact bits [71:64] the encoder
            // zeroes by construction: word compare is masked on those.
            if text.starts_with("@P0 STSM.16.M88") && (*w >> 64) & 0xFF != 0 {
                let mask = !(0xFFu128 << 64);
                assert_eq!(
                    minted & mask,
                    w & mask,
                    "[{leg}] mint word(mask) drift: {text}"
                );
            } else {
                assert_eq!(minted, *w, "[{leg}] mint word != vendor law word: {text}");
            }
            let got = dec(&t, &idx, minted).unwrap_or_default();
            assert_eq!(&got, text, "[{leg}] circle: {text}");
        }
        for (w, text) in CIRCLE433 {
            let minted =
                enc(&t, text).unwrap_or_else(|| panic!("[{leg}] circle-mint refused: {text}"));
            let got = dec(&t, &idx, minted).unwrap_or_default();
            assert_eq!(&got, text, "[{leg}] circle: {text}");
            let got2 = dec(&t, &idx, *w).unwrap_or_default();
            assert_eq!(&got2, text, "[{leg}] circle law-word decode: {text}");
        }
        for text in REFUSE433 {
            assert!(
                enc(&t, text).is_none(),
                "[{leg}] loud-refuse form minted?! {text}"
            );
        }
    }
    assert_eq!(MINT433.len(), 10);
    assert_eq!(CIRCLE433.len(), 6);
    assert_eq!(REFUSE433.len(), 5);
    assert!(CANON433.starts_with("9b60b92"));
}

/// t433_6: SOURCE.json manifest pins canonical 57e7ecd (BUG-442 graft F2-iter246, ride; was BUG-441 graft F2-iter245, ride; was BUG-439 graft F2-iter243, ride; was BUG-423 graft F2-iter242, ride; was BUG-433 graft) and
/// the vendored tables carry the new sm120 key + the U16 relax.
#[test]
fn t433_6_source_manifest_and_table_presence() {
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert_eq!(
        src["base_revision"].as_str().unwrap(),
        CANON433,
        "SOURCE.json canonical drift (ride-chain ffa3244 -> 57e7ecd = BUG-442 F2-iter246)"
    );
    let t = tab("sm120");
    assert!(
        t.get("STSM_ARI_R", "16,M88").is_some(),
        "sm120 new key mg 16,M88 missing"
    );
    assert!(
        t.get("STSM_ARI_R", "16,2,M88").is_some(),
        "sm120 new key mg 16,2,M88 missing"
    );
    assert!(
        t.get("STSM_ARI_R", "16,4,M88").is_some(),
        "sm120 new key mg 16,4,M88 missing"
    );
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert!(
            t.get("STSM_ARI_R", "16,M88").is_some(),
            "[{leg}] mg 16,M88 missing"
        );
        assert!(
            t.get("STSM_ARI_R", "16,2,M88").is_some(),
            "[{leg}] mg 16,2,M88 missing"
        );
    }
    let t = tab("sm121a");
    assert!(
        t.get("STSM_ARI_R", "16,2,M88").is_some(),
        "sm121a mg 16,2,M88 missing"
    );
    for leg in ["sm100a", "sm103a", "sm120"] {
        let t = tab(leg);
        let e = t.get("STS_AURI_R", "U16").expect("STS_AURI_R|U16 missing");
        let vm = e.variable_mask;
        assert!(
            vm & (1u128 << 95) != 0,
            "[{leg}] U16 era-band relax missing bit 95 (vm={vm:#034x})"
        );
        // bits {109,115} stay tight in the row vm: they live in the [127:96)
        // era band the decoder cuts anyway (arb433b K-law; no payload there).
        assert!(
            vm & (1u128 << 109) == 0 && vm & (1u128 << 115) == 0,
            "[{leg}] U16 vm drift on era-band bits (109/115 must stay tight)"
        );
    }
    let t = tab("sm121a");
    let vm = t.get("STS_AURI_R", "U16").unwrap().variable_mask;
    let _ = vm; // 121a U16 row stays as healed by 425b (no extra relax here)
}
