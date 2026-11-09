//! BUG-393 pins (F2-iter214, loop5/blind front2, 2026-09-06): HFMA2
//! 0x231-bases inert-window relax x4 legs, canonical 16ddeb6 (graft
//! patch393.py, replayable+idempotent). ENGINE src ZERO changes.
//!
//! Vendor law (measure_pre394 per-bit lattice, 170 probes = 2 bases x
//! [base + flips 12..95], nvdisasm 13.3.73 raw -b, x4 models
//! SM100a/SM103a/SM120/SM121a AGREE on EVERY probe, DIVERGENT=0):
//!   [55:40], [59:56], [90:87] (pv-stray w/o b79, elided-PT render),
//!   [92:95] write-inert on both bases (ERA5R = HFMA2_R_R_R_R '',
//!   ERABF = HFMA2_R_R_R_R BF16_V2); joint balls (per-window all-ones +
//!   grand) re-probed at pinning time render the base text x4 models.
//!   b91 = VENDOR_KILL x4 (rc=1) stays care-0 pinned; b78 (F32xBF16
//!   INVALID3) + b86 (h0nh1/INVALID6) markers stay HOLE (285-doctrine).
//! Pre-fix (canonical 2285a05): sparse legs HOLE_inert 28/base =
//!   [55:40]x16 + [59:56]x4 + [90:87]x4 + [92:95]x4; dense legs 12/base
//!   ([55:40] already relaxed = posture asymmetry now closed).
//! Post-graft join (work/bug393/measure_post393.json): DELTA-EXACT --
//!   every HOLE_inert cell CURED to MATCH, all other classes unchanged,
//!   WRONG 0 / HOLE_live 0 / ENGINE_OVERREACH 0 on every leg.
//! Witness data: work/bug393/pin_wit393.json (machine-built by
//!   gen393pins.py; this file's tables = witness json verbatim).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
const LEGS4: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec96(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}

include!("bug393_data.inc");

/// 2026-11-09 (T-25; rows-half-2026-11-07 on -b SM100 / SM103 / SM121, T-23's per-row passes): the HFMA2_R_R_R_R '' and
/// BF16_V2 rows are measured field by field on sm100a / sm103a / sm121a -- the 393 windows [55:40] / [59:56] / [90:87] /
/// [95:92] are text-inert for nvdisasm and the measured row fails closed on them (its mask is its fields); the sm120 harvest
/// rows keep the 393 relax. A window word is a HOLE exactly when the clean word's row is measured; the clean word renders
/// the vendor base text on every leg.
const INERT_393: u128 = (0xffffu128 << 40) | (0xfu128 << 56) | (0xfu128 << 87) | (0xfu128 << 92);
fn expect_window(t: &IsaTable, leg: &str, word: u128, want: &str) {
    let idx = DecodeIndex::build(t);
    match idx.decode(word & M96, 0, t) {
        Ok(d) => assert_eq!(to_sass(&d), want, "leg {leg} word {word:024x}"),
        Err(_) => {
            assert!(word & INERT_393 != 0, "leg {leg} word {word:024x}: HOLE on a clean word");
            let d = idx
                .decode(word & M96 & !INERT_393, 0, t)
                .unwrap_or_else(|_| panic!("leg {leg} word {word:024x}: the clean word is a HOLE"));
            assert_eq!(to_sass(&d), want, "leg {leg} word {word:024x}: clean-word text");
            assert!(
                t.entries[&d.key].mod_groups[&d.mod_group].row_probe,
                "leg {leg} word {word:024x}: a harvest row fails closed ({}[{}])",
                d.key,
                d.mod_group
            );
        }
    }
}

#[test]
fn t393_1_base_anchors_vendor_exact() {
    // the two claim bases decode to the vendor text on all four legs;
    // posture anchor (pre+post invariant).
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (leg, word, want) in ANCHORS {
        let got = dec96(&tabs[leg], word);
        assert_eq!(
            got.as_deref(),
            Some(want),
            "leg {} word {word:024x}",
            LEGS4[leg]
        );
    }
}

#[test]
fn t393_2_window_edges_cured() {
    // edge bits of every relaxed window: junk word now decodes to the
    // vendor base text on every leg (pre: HOLE_inert sparse x28 / dense
    // x12 per base; [55:40] edges were already MATCH on dense).
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (leg, word, want) in EDGES {
        expect_window(&tabs[leg], LEGS4[leg], word, want);
    }
}

#[test]
fn t393_3_joint_balls_cured() {
    // per-window all-ones balls + grand ball: no joint-liveness, decode
    // to the vendor base text on every leg (vendor re-probed at pinning).
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (leg, word, want) in BALLS {
        expect_window(&tabs[leg], LEGS4[leg], word, want);
    }
}

#[test]
fn t393_4_b91_kill_pin_stands() {
    // b91 = VENDOR_KILL rc=1 x4 models; engine must keep refusing.
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (leg, t) in tabs.iter().enumerate() {
        for word in KILL {
            assert!(
                dec96(t, word).is_none(),
                "leg {} word {word:024x} must HOLE",
                LEGS4[leg]
            );
        }
    }
}

#[test]
fn t393_5_invalid_markers_stand() {
    // 285-doctrine: ERABF b78 (F32xBF16 INVALID3) + b86 (INVALID6) on
    // both bases stay HOLE (relaxed windows exclude 78/79/86/91).
    let tabs: Vec<IsaTable> = LEGS4.iter().map(|a| tab(a)).collect();
    for (leg, t) in tabs.iter().enumerate() {
        for word in INVALID {
            assert!(
                dec96(t, word).is_none(),
                "leg {} word {word:024x} must HOLE",
                LEGS4[leg]
            );
        }
    }
}

#[test]
fn t393_6_sparse_parity_full_window() {
    // [55:40] parity: all 16 window bits decode on the sparse legs
    // (pre: dense-only MATCH). Asserted against vendor base text.
    let tabs: Vec<IsaTable> = LEGS4[..2].iter().map(|a| tab(a)).collect();
    for (leg, word, want) in PARITY16 {
        expect_window(&tabs[leg], LEGS4[leg], word, want);
    }
}

#[test]
fn t393_7_mint_circle_bases() {
    // encode path untouched: parse vendor base text per leg -> mint ==
    // claim and_base on the matching row (encoder is table-driven).
    for (leg, _word, want) in ANCHORS {
        let arch = LEGS4[leg];
        let t = tab(arch);
        let ins = parse_sass(want, 0).unwrap_or_else(|e| panic!("{arch} parse '{want}': {e}"));
        let word =
            encode_instruction(&ins, &t).unwrap_or_else(|e| panic!("{arch} encode '{want}': {e}"));
        let round = dec96(&t, word).expect("minted word decodes");
        assert_eq!(round, want, "{arch} mint-circle drift");
    }
}
