//! BUG-435+434 pins (F2-iter240, loop5/blind front2, 2026-09-10): x4-leg
//! LDG/LD dARI E-lane LTC+pred lattice closure. Canonical 70eb0fe -> 1810912
//! (patch435.py replayable+idempotent; replay z pristine byte-exact x4;
//! idem all-skip; ENGINE src ZERO). Scope:
//!  - x3 legs LDG true-lane 128,E full LTC x pv lattice (arb416 B + arb400c)
//!  - x3 LD 'E'-lane + LD.128 dARI LTC x pv lattices (arb416d/arb435/arb435b)
//!  - LD_R_dARI_P NEW KEY on x3 (121a-key precedent z ery BUG-400)
//!  - LDG pred-output A-lane family: NEW KEYS LDG_P_R_dARI{,_P} x3 (12-cell
//!    HOLE) + 121a += E,LTC64B/128B/256B (9-cell LTC-drop, 434)
//!  - sm120 LDG.E.LTC128B.128_R_dARI fabricated-geometry REPAIR (sibling
//!    sm103a verbatim; canonical cnt=33 real corpus claims live-misdecoded)
//!
//! Witness data: tests/bug435_data.inc (machine-built by
//! work/bug435/gen435pins.py; rc=2 self-checks; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug435_data.inc");

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

/// t435_1: LDG true-lane 128,E LTC x pv law -- decode == vendor x4 legs
/// (arb416 B-set + arb400c ltc1/ltc3 incl b70/b71/ball inert crosses).
#[test]
fn t435_1_ldg_true_lane_lattice_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW435_LDG {
            let got = dec(&t, &idx, *w)
                .unwrap_or_else(|| panic!("[{leg}] LDG {vendor} HOLE (must decode)"));
            assert_eq!(&got, vendor, "[{leg}] LDG text != vendor");
        }
    }
    assert_eq!(LAW435_LDG.len(), 21);
}

/// t435_2: LD 'E'-lane full lattice ltc{0..3} x pv{0,1,8} incl @P0 forms
/// and b70/b71 inert crosses (arb416d P/Q) -- decode == vendor x4 legs.
#[test]
fn t435_2_ld_e_lane_lattice_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW435_LD {
            let got = dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] LD {vendor} HOLE"));
            assert_eq!(&got, vendor, "[{leg}] LD text != vendor");
        }
        for (w, vendor) in LAW435_DOLD {
            let got = dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] DOLD {vendor} HOLE"));
            assert_eq!(&got, vendor, "[{leg}] DOLD text != vendor (435b J1/J2)");
        }
    }
    assert_eq!(LAW435_LD.len(), 18);
    assert_eq!(LAW435_DOLD.len(), 6);
}

/// t435_3: 0c1019-lane b0=0 words = LD family (migration analog on x3) and
/// LD.128 dARI lanes (arb435b P128d + arb435 C.hi) -- decode == vendor x4.
#[test]
fn t435_3_ld_migration_and_128_lattice_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW435_MIGRATE {
            let got = dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] migrate {vendor} HOLE"));
            assert_eq!(&got, vendor, "[{leg}] migrate text != vendor");
        }
        for (w, vendor) in LAW435_LD128 {
            let got = dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] LD128 {vendor} HOLE"));
            assert_eq!(&got, vendor, "[{leg}] LD128 text != vendor");
        }
    }
    assert_eq!(LAW435_MIGRATE.len(), 12);
    assert_eq!(LAW435_LD128.len(), 6);
}

/// t435_4: LDG pred-output A-lane family (b0=1): full LTC x pv lattice
/// decodes vendor == 'LDG.E[.LTC..] P0, R33, ..' x4 legs (HEALED 12-cell
/// x3 HOLE + 9-cell 121a token drop; arb416 A.b0_1 x4 AGREE).
#[test]
fn t435_4_ldg_pred_output_family_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor) in LAW435_POUT {
            let got = dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] pout {vendor} HOLE"));
            assert_eq!(&got, vendor, "[{leg}] pout text != vendor");
            assert!(
                got.contains("P0, R33"),
                "[{leg}] pout regressed form: {got}"
            );
        }
    }
    assert_eq!(LAW435_POUT.len(), 12);
}

/// t435_5: registered postures stay pre==post (machine-snapped):
/// [81:84)=7 LD parallel lanes unclaimed (lane-separator pin), reuse rc1,
/// walk-C masks, D.old.ltc era-ctrl carriers (436-kand), D.pout inert-window.
#[test]
fn t435_5_postures_pinned_pre_post() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag_leg, snapped) in POSTURE435 {
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
    }
    assert_eq!(POSTURE435.len(), 132);
}

/// t435_6: mint circles (word == vendor-law word, decode circle) x4 legs
/// + loud-refuse forms x4 + canonical pin.
#[test]
fn t435_6_mints_refuse_canon() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, text) in MINT435 {
            if leg == "sm120" && SM120_090_SHADOW435.iter().any(|(_, st)| st == text) {
                continue; // 090-era junk route owns this text on sm120
            }
            let minted = enc(&t, text).unwrap_or_else(|| panic!("[{leg}] mint refused: {text}"));
            assert_eq!(minted, *w, "[{leg}] mint word != vendor law word: {text}");
            let got = dec(&t, &idx, minted).unwrap_or_default();
            assert_eq!(&got, text, "[{leg}] circle: {text}");
        }
        for text in REFUSE435 {
            assert!(
                enc(&t, text).is_none(),
                "[{leg}] loud-refuse form minted?! {text}"
            );
        }
    }
    // sm120 090-shadow: plain LDG.E.LTC*.128 mints keep the era junk route
    // (BUG-090 contract); machine-pinned words, one per shadowed mint class.
    {
        let t = tab("sm120");
        for (w, text) in SM120_090_SHADOW435 {
            let minted =
                enc(&t, text).unwrap_or_else(|| panic!("[sm120] shadow mint refused: {text}"));
            assert_eq!(minted, *w, "[sm120] 090-shadow mint drift: {text}");
        }
    }
    assert_eq!(MINT435.len(), 47);
    assert_eq!(SM120_090_SHADOW435.len(), 1);
    assert_eq!(REFUSE435.len(), 5);
    // canonical pin (manifest pin check lives in the SOURCE.json pack)
    assert!(CANON435.starts_with("9b60b92"));
}
