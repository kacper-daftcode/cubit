//! BUG-423 pins (F2-iter242, loop5/blind front2, 2026-09-10): sm121a era-row
//! LDSM.16.M88_R_AUR recanon DELETE (dotted junk key; bug098 sm120 precedent,
//! same key GONE on x3 legs) + LDSM_R_ARURI|'16,M88' variable_mask |=
//! (7<<84) x4 legs (j84-band closure). Canonical 61858fb -> 3032686
//! (patch423.py replayable+idempotent; replay z pristine 61858fb byte-exact
//! x4; idem all-skip; ENGINE src ZERO). Scope:
//!  - D1 sm121a DELETE KEY LDSM.16.M88_R_AUR: fabricated base R0
//!    ('[R0+UR4]') on junk-band singles (row carries no base-reg field;
//!    printer unwrap_or(0)); claims ride onto LDSM_R_ARURI strict/broad +
//!    LDSM_R_AURI with vendor-exact texts;
//!  - D2 x4 ARURI|16,M88 vm relax on [84:87) (arb423 law: singles+combos
//!    vendor-legal inert x4, true base/ureg/imm printed; ab/fields
//!    invariant, pure measured relax).
//!
//! NOT grafted (registrations, pinned standing here): 439-kand D-class
//! {b87,b90,b92,b95} singles vendor-legal inert x4 but engine-HOLE x4
//! pre==post (outside the era-row claim region); 440-kand b122/123/124
//! singles vendor-RC1 x4 but admitted by the ENGINE era cut [127:96) on
//! every leg (decoder.rs ERA domain = ENGINE-gated, jak 428/430/431).
//!
//! Witness data: tests/bug423_data.inc (machine-built by
//! work/bug423/gen423pins.py; rc=2 self-checks; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug423_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
const JUNK: u128 = (0xffu128 << 64) | (7u128 << 84);
const ERA: u128 = 0xffffffffu128 << 96;

/// t423_1: healed grid -- decode == vendor x4 legs on every word whose
/// engine text was healed by the graft (37 fabrication cells sm121a + 36
/// j84-family HOLE cells x3 = 73 cell-legs).
#[test]
fn t423_1_healed_grid_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW423_HEAL {
            let got = dec(&t, &idx, *w)
                .unwrap_or_else(|| panic!("[{leg}] LDSM {vendor} HOLE (must decode post-graft)"));
            assert_eq!(&got, vendor, "[{leg}] healed text != vendor");
        }
    }
    assert_eq!(LAW423_HEAL.len(), 26);
}

/// t423_2: continuity -- cells already vendor-exact pre-graft stay exact.
#[test]
fn t423_2_stable_grid_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW423_STABLE {
            let got = dec(&t, &idx, *w)
                .unwrap_or_else(|| panic!("[{leg}] LDSM {vendor} HOLE (was exact pre-graft)"));
            assert_eq!(&got, vendor, "[{leg}] stable text drift");
        }
    }
    assert_eq!(LAW423_STABLE.len(), 19);
}

/// t423_3: BUG-439 heal-attribution -- D-class singles decode vendor-exact
/// 'LDSM.16.M88 R16, [UR4]' on every leg (was standing-HOLE posture pre-439;
/// flipped by the BUG-439 graft canonical 54c5b02; flip439.py machine-verified
/// on the work .so x4 legs before edit).
#[test]
fn t423_3_posture439_healed_by_439() {
    assert_eq!(POSTURE439.len(), 4);
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag) in POSTURE439 {
            let got = dec(&t, &idx, *w)
                .unwrap_or_else(|| panic!("[{leg}] {tag}: BUG-439 heal lost (must decode)"));
            assert_eq!(
                &got, "LDSM.16.M88 R16, [UR4]",
                "[{leg}] {tag}: BUG-439 heal text drift"
            );
        }
    }
}

/// t423_4: 440-kand standing postures -- b122/123/124 singles stay claimed
/// via the ENGINE era cut [127:96) on every leg (vendor RC1; ERA domain is
/// ENGINE-gated). Snapped machine text (post-graft: true-base print x4;
/// sm121a was fabricated '[R0+UR4]' pre-graft per POSTURE423/manifest).
#[test]
fn t423_4_posture440_engine_era_cut() {
    assert_eq!(POSTURE440.len(), 3);
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag, snap) in POSTURE440 {
            let got =
                dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] {tag}: era-cut claim lost"));
            assert_eq!(&got, snap, "[{leg}] {tag}: 440 snap drift");
        }
    }
}

/// t423_5: mints -- byte-shape encode mints (era [127:96) + junk band
/// encode-zeroed by construction) + decode circle, x4 legs. Masked mints
/// cover the junk-band carriers.
#[test]
fn t423_5_mints_and_circles() {
    const CMPMASK: u128 = !(JUNK | ERA);
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, text) in MINT423.iter().chain(MASKMINT423.iter()) {
            let ins = parse_sass(&format!(" {text} ;"), 0)
                .unwrap_or_else(|e| panic!("[{leg}] parse {text}: {e}"));
            let w2 = encode_instruction(&ins, &t)
                .unwrap_or_else(|e| panic!("[{leg}] encode {text}: {e}"));
            assert_eq!(
                w2 & CMPMASK,
                w & CMPMASK,
                "[{leg}] mint drift (cmpmask): {text}"
            );
            let rt = dec(&t, &idx, w2).unwrap_or_else(|| panic!("[{leg}] circle HOLE {text}"));
            assert_eq!(&rt, text, "[{leg}] circle text drift");
        }
    }
    assert_eq!(MINT423.len(), 17);
    assert_eq!(MASKMINT423.len(), 26);
}

/// t423_6: source manifest + recanon invariants -- CANON423 pin (57e7ecd ride F2-iter246/BUG-442), sm121a era
/// key absent, LDSM_R_ARURI|16,M88 present with the _src graft tag x4.
#[test]
fn t423_6_source_manifest_and_recanon() {
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        src["base_revision"]
            .as_str()
            .unwrap()
            .starts_with("cc2f62c"), // ride F2-iter278 (BUG-467 canonical graft 668f842; was 67b54f4 BUG-466)
        "SOURCE.json must pin canonical 57e7ecd [was ffa3244 = BUG-441, bb1ba6c = BUG-438, 54c5b02 = BUG-439, 3032686 = BUG-423, 61858fb = BUG-433, 0a6b178 = BUG-435+434+435b, 1810912 = 435+434 hop, 70eb0fe = BUG-416, 52cb73c = BUG-425+425b] (BUG-442 graft F2-iter246 z atrybucja; ride-chain): {:?}",
        src["base_revision"]
    );
    assert!(CANON423.starts_with("cc2f62c"), "CANON423 const drift");
    for leg in LEGS {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        assert!(
            ins.get("LDSM.16.M88_R_AUR").is_none(),
            "{leg}: dotted junk era key resurrected"
        );
        let mg = &ins["LDSM_R_ARURI"]["mod_groups"]["16,M88"];
        assert_eq!(
            mg["_src"].as_str().unwrap(),
            "bug441-2026-09-11",
            "{leg}: ARURI 16,M88 missing graft tag (ride F2-iter245+: BUG-441 owns the row; 439/423 previous owners)"
        );
        let vm = u128::from_str_radix(
            mg["variable_mask"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap();
        assert_eq!(vm & (7 << 84), 7 << 84, "{leg}: j84-band relax lost");
        assert_eq!(
            vm & (0x129 << 87),
            0x129 << 87,
            "{leg}: BUG-439 D-band relax lost (ride-added F2-iter243)"
        );
    }
}
