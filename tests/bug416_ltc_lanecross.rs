//! BUG-416 pins (F2-iter239, loop5/blind front2, 2026-09-10): sm121a LDG
//! lane-cross LTC lattice closure. Canonical 52cb73c -> 70eb0fe (patch416.py
//! replayable+idempotent; ENGINE src ZERO). The harvested row
//! LDG_R_dARI_P|'128,E,LTC128B' (ab 0c1019..7980) was a lane-cross
//! FABRICATION: its claim region = the LD.E family on the true 0c1019/0980
//! lane (arb416 A-set x4 AGREE); the true LDG 7981-lane provably walks
//! [68:70) as LTC incl ltc2 x trailing-pred (arb416 B-set = arb400c skip
//! closed); the TRUE LD 'E' lane walks the full ltc{0..3} x pv{0,1,8}
//! lattice with b70/71 measured-inert (arb416d x4 AGREE).
//!
//! Witness data: tests/bug416_data.inc (machine-built by
//! work/bug416/gen416pins.py; rc=2 self-checks; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug416_data.inc");

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

/// t416_1: LDG true-lane (7981) LTC law on sm121a -- ltc2 x pv{0,1,8}
/// (arb400c skip closed by arb416 B-set) + arb400c inert ltc1/ltc3 crosses;
/// decode == vendor, claim = grafted LDG_R_dARI_P LTC mg / pre-existing
/// LTC128B base key. Pre-state neg-ctl per-row in bug416_data.inc comments.
#[test]
fn t416_1_ldg_true_lane_ltc_lattice() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (w, tag, vendor, km) in LAW416_LDG {
        let (got, got_km) =
            dec(&t, &idx, *w).unwrap_or_else(|| panic!("[sm121a] {tag} HOLE (must decode)"));
        assert_eq!(got, *vendor, "[sm121a] {tag} text != vendor");
        assert_eq!(&got_km, km, "[sm121a] {tag} claim-route drift");
    }
    assert_eq!(LAW416_LDG.len(), 13);
}

/// t416_2: LD 'E' TRUE lane full lattice ltc{0..3} x pv{0,1,8} (arb416d P):
/// decode == vendor, claim covers the grafted LD_R_dARI[_P] rows.
#[test]
fn t416_2_ld_e_lane_lattice() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (w, tag, vendor, km) in LAW416_LD {
        let (got, got_km) =
            dec(&t, &idx, *w).unwrap_or_else(|| panic!("[sm121a] {tag} HOLE (must decode)"));
        assert_eq!(got, *vendor, "[sm121a] {tag} text != vendor");
        assert_eq!(&got_km, km, "[sm121a] {tag} claim-route drift");
    }
    assert_eq!(LAW416_LD.len(), 12);
}

/// t416_3: inert b70/b71 relax + payload (guard/imm/reuse-refuse) law on the
/// LD 'E' lane (arb416d Q/R + arb416c G): decode == vendor.
#[test]
fn t416_3_ld_e_inert_and_payload() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (w, tag, vendor, km) in LAW416_INERT {
        if *vendor == "HOLE" {
            continue; // reuse-junk rc=1 cells covered by posture, not law decode
        }
        let (got, got_km) = dec(&t, &idx, *w).unwrap_or_else(|| panic!("[sm121a] {tag} HOLE"));
        assert_eq!(got, *vendor, "[sm121a] {tag} text != vendor");
        assert_eq!(&got_km, km, "[sm121a] {tag} claim-route drift");
    }
}

/// t416_4: fabrication-region repair -- hybrid words (0c1019-hi + LDG-lo16,
/// b0=0) now claim the LD family with vendor-exact text (pre: fabricated
/// 'LDG.E.LTC128B.128 ...' prints / pred-drops, machine-recorded in the
/// .inc comments); postures on the b0=1 pred-output junk class are frozen
/// pre==post (snapshot).
#[test]
fn t416_4_fabric_region_reclaimed_and_postures() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (w, tag, vendor, km) in LAW416_FABRIC {
        let (got, got_km) =
            dec(&t, &idx, *w).unwrap_or_else(|| panic!("[sm121a] {tag} HOLE (must decode)"));
        assert_eq!(got, *vendor, "[sm121a] {tag} text != vendor");
        assert_eq!(&got_km, km, "[sm121a] {tag} claim-route drift");
        assert!(
            got_km.starts_with("LD_R_dARI"),
            "[sm121a] {tag} fabricated LDG claim persists: {got_km}"
        );
    }
    for (w, tag, snap) in POSTURE416 {
        let got = dec(&t, &idx, *w)
            .map(|(s, _)| s)
            .unwrap_or_else(|| "HOLE".to_string());
        assert_eq!(
            &got, snap,
            "[sm121a] {tag} posture moved (must stay pre==post)"
        );
    }
    // reuse loose-claim (CLAIM-class, pre-existing) + C-walk standing HOLEs
    // on the LD.128 b0=0 lane (ungrafted): text frozen pre==post.
    for (w, tag, snap) in POSTURE416_JUNK {
        let got = dec(&t, &idx, *w)
            .map(|(s, _)| s)
            .unwrap_or_else(|| "HOLE".to_string());
        assert_eq!(&got, snap, "[sm121a] {tag} junk posture moved");
    }
}

/// t416_5: mint circles -- the 10 authored vendor-legal texts mint
/// vendor-verified words (nvdisasm-checked at gen time) and reprint
/// identical text; pre-fix two of them (LTC128B+pred) minted the junk
/// lane (silent garbage, measure416_pre m1/m2).
#[test]
fn t416_5_mint_circles_vendor_words() {
    const M96: u128 = (1 << 96) - 1;
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (word, text) in MINT416 {
        let got = enc(&t, text).unwrap_or_else(|| panic!("[sm121a] mint refuse: {text}"));
        assert_eq!(got & M96, word & M96, "[sm121a] mint word drift: {text}");
        let (back, _) =
            dec(&t, &idx, got).unwrap_or_else(|| panic!("[sm121a] circle hole: {text}"));
        assert_eq!(back, *text, "[sm121a] reprint: {text}");
    }
    assert_eq!(MINT416.len(), 10);
}

/// t416_6: fail-closed set (r1 FLIPPED to mint pin by 435-era LD.128 lattice
/// z atrybucja / ungrafted LDG 'E' LTC
/// carrier / invalid pred / R255 / imm overflow) + canonical pin.
#[test]
fn t416_6_refuse_closed_and_canon_pin() {
    let t = tab("sm121a");
    for (tag, text) in REFUSE416 {
        if tag == &"r1" {
            // FLIP-435 (F2-iter240, 435 A2 LD.128 LTC lattice): r1 is a
            // vendor-legal mint since this iteration; pinned machine word +
            // decode circle. r2..r5 keep the refuse contract.
            let minted = enc(&t, text).expect("[sm121a] r1 mint (post-435)");
            assert_eq!(
                minted, 0x000fc2000c101d100000000c0c217980u128,
                "[sm121a] r1 mint drift"
            );
            continue;
        }
        if tag == &"r2" {
            // FLIP-435b (F2-iter240, J1/J2 old-lane LDG E heal, arb435 D-set
            // x4 AGREE): r2 vendor-legal since this iteration.
            let minted = enc(&t, text).expect("[sm121a] r2 mint (post-435b)");
            assert_eq!(
                minted, 0x000fc2000c1e19100000000c0c217981u128,
                "[sm121a] r2 mint drift"
            );
            continue;
        }
        assert!(
            enc(&t, text).is_none(),
            "[sm121a] {tag} must refuse: {text}"
        );
    }
    assert_eq!(REFUSE416.len(), 5);
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        src["base_revision"].as_str().unwrap().starts_with("cc2f62c"), // ride F2-iter278 (BUG-467 canonical graft 668f842; was 67b54f4 BUG-466)
        "SOURCE.json must pin canonical a64b82bff6706350b82018609016f624188b99a5 (= BUG-463 ltc-widths, ride-after f58ed1683bded052bcb100a0762c16e7e91248c4 = BUG-461 glyph, ride-after f37655889e6da3ddd25b73a926c21ec3b58fa768 = BUG-462 narrow, ride-after 700524e698304dcbf1a3884f72f05abff609b8aa = BUG-453 graft, ride-after e03e0348d98b9d20ffb4ca557cfc6eae625cf995, = BUG-452 narrow, ride-after 4ee843162216e75d037135b5907c819759471296, = BUG-454 graft, ride-after 589be874 (= BUG-450) (= BUG-450 graft, ride-after 099faa0 = BUG-447, ride-after e8d1af3 = BUG-443, 57e7ecd = BUG-442, ffa3244 = BUG-441, bb1ba6c = BUG-438, 54c5b02 = BUG-439, 3032686 = BUG-423, 61858fb = BUG-433, 0a6b178 = BUG-435+434+435b, was 1810912 = BUG-435+434 graft F2-iter240; 70eb0fe = BUG-416 F2-iter239; older 52cb73c = BUG-425+425b): {:?}",
        src["base_revision"]
    );
    assert!(CANON416.starts_with("cc2f62c"), "CANON416 const drift");
}
