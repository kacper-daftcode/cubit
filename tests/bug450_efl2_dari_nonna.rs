//! BUG-450 pins (F2-iter255, loop5/blind front2, 2026-09-12): x3 legs
//! (sm100a/sm103a/sm120) EFL2.256 non-NA dARI coverage-gap -- the family
//! `LDG.E.EFL2.256[_R_R_dARI{,_P}]` / `STG.E.EFL2.256[_dARI_R_R]` existed
//! only on sm121a; x3 decode of vendor-legal words was HOLE (measured:
//! measure450_pre 21 legal HOLE x3, vendor law arb447 F 8 probes
//! nvdisasm 13.3.73 raw -b x4 AGREE EVERY/DIVERGENT=0: non-NA dARI EFL2
//! = GENUINE `desc[URx][Ry.64]` + trailing policy-imm/pred-out legal).
//! Graft = canonical 099faa0 -> 589be874: ADD 3 keys per x3 leg cloned
//! VERBATIM from sm121a (count=None, _src450), 121a byte-untouched,
//! ENGINE src ZERO. Deferred-from-447 overlap worry DOMKNIETY maszynowo:
//! patch450 A2 = 0 pair-intersections (3x3 space-components per row pair)
//! between the new rows and ALL pre-existing x3 rows (discriminators
//! [79:75]=11100 & b82=0 & b86=0 sit in strict masks; ENL2/ELL2/NA rows
//! contradict; b84/b85 are vm-don't-care). Defect pre->post (publish
//! 7f972f80 + canonical 099faa0 -> 589be874; 36 cells): x3 21 HOLE/3
//! HOLE-OK -> 12 heal MATCH vendor-exact (4 words x3) + WRONG 0 +
//! pol-trailer parity HOLE kept (3x4) + raRZ CLONE-ILLEG donor-symmetric
//! standing (x4 claim, vendor rc=1 x4 -- class 452; narrowing on
//! donor+clones is the 452 audit, not this graft).
//! Witness data: tests/bug450_data.inc (machine-built by
//! work/bug450/gen450pins.py; rc=2 fail-closed; no hand hex; mints
//! nvdisasm-crossed x4 at generation time; guard-aware BUG-060 wzorzec
//! gen447pins v2).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug450_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
const LEGS450: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
static ERRATA_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let full = format!(" {text} ;");
    let parsed = parse_sass(&full, 0).map_err(|e| e.to_string())?;
    encode_instruction(&parsed, t).map_err(|e| e.to_string())
}
fn nforms(arch: &str) -> usize {
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(format!("tables/{arch}.json")).unwrap())
            .unwrap();
    v["instructions"].as_object().unwrap().len()
}

/// t450_1: heal grid -- decode == vendor x4-unanimous text on every healed
/// cell (16 cells: 4 words x 4 legs; x3 heal + 121a standing parity).
#[test]
fn t450_1_heal_grid() {
    for (w, leg, vendor) in LAW450_HEAL {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(
            got.as_deref(),
            Some(*vendor),
            "[{leg}] heal drift {w:#034x}"
        );
    }
}

/// t450_2: parity holes HEALED (flip F2-iter263 BUG-453, canonical 700524e):
/// trailing policy-imm cells sa claimowane vendor-exact na WSZYSTKICH nogach
/// wlacznie z donorem 121a (synth _II keys donor-first; HOLE450 data zostaja
/// jako swiadkowie pre-stanu w data.inc). Teksty x4-unanim z arb447 law.
#[test]
fn t450_2_parity_holes_healed_453() {
    const HEALED453: &[(u128, &str)] = &[
        (
            0x000be4000810182c000000261c30197eu128,
            "@P1 LDG.E.EFL2.256 R44, R48, desc[UR38][R28.64], 0x0",
        ), // F.ldg_dari_pol00
        (
            0x000be4000810182cfe0000261c30197eu128,
            "@P1 LDG.E.EFL2.256 R44, R48, desc[UR38][R28.64], 0x7f",
        ), // F.ldg_dari_pol7f
        (
            0x000be400081018260000002c1c30197fu128,
            "@P1 STG.E.EFL2.256 desc[UR38][R28.64], R44, R48, 0x0",
        ), // F.stg_dari_pol00
    ];
    assert_eq!(
        HOLE450.len() / 4,
        HEALED453.len(),
        "HOLE450/healed grid drift"
    );
    for (i, (w, want)) in HEALED453.iter().enumerate() {
        for (hw, leg) in HOLE450.iter().skip(i * 4).take(4) {
            assert_eq!(hw, w, "HOLE450 grid order drift");
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            assert_eq!(
                dec(&t, &idx, *hw).as_deref(),
                Some(*want),
                "[{leg}] healed-453 drift {hw:#034x}"
            );
        }
    }
}

/// t450_3: CLONE-ILLEG standing-ZWERYFIKOWANY-do-HOLE (flip F2-iter260
/// BUG-452): raRZ word (vendor rc=1 x4) ma claim zdjety na WSZYSTKICH nogach
/// wlacznie z donorem (claim_forbid; overclaim donora naprawiony
/// donor-first). Poprzedni standing w komentarzu w data.inc.
#[test]
fn t450_3_cloneilleg_standing() {
    for (w,) in CLONEILLEG450 {
        for leg in LEGS450 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            assert_eq!(got, None, "[{leg}] narrowed-452 must refuse {w:#034x}");
        }
    }
}

/// t450_4: mints x4 -- encode(vendor text) == mint word AND
/// decode(mint) == vendor text; guard_hatch cells take the BUG-060
/// refuse-assert + CUBIT_DISABLE_ERRATA hatch under ERRATA_LOCK
/// (wzorzec t447_5/INC-252f).
#[test]
fn t450_4_mints_x4() {
    for (text, leg, w, ghatch) in MINT450 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = if *ghatch {
            let _g = ERRATA_LOCK.lock().unwrap();
            let e = enc(&t, text).expect_err("[sm103a] BUG-060 guard must refuse even desc-base");
            assert!(format!("{e}").contains("BUG-060"), "guard msg: {e}");
            std::env::set_var("CUBIT_DISABLE_ERRATA", "1");
            let r = enc(&t, text);
            std::env::remove_var("CUBIT_DISABLE_ERRATA");
            r.unwrap_or_else(|e| panic!("[{leg}] hatch mint refuse {text}: {e}"))
        } else {
            enc(&t, text).unwrap_or_else(|e| panic!("[{leg}] mint refuse {text}: {e}"))
        };
        assert_eq!(got, *w, "[{leg}] mint drift {text}");
        let back = dec(&t, &idx, got).unwrap_or_else(|| panic!("[{leg}] mint HOLE {text}"));
        assert_eq!(&back, text, "[{leg}] circle drift {text} -> {back}");
    }
}

/// t450_5: refuse grid -- raw encode of the guard cells on sm103a refuses
/// with the BUG-060 citation (keeper parity; REFUSE450 x2).
#[test]
fn t450_5_refuse_grid() {
    let _g = ERRATA_LOCK.lock().unwrap();
    let t = tab("sm103a");
    for (text, leg) in REFUSE450 {
        assert_eq!(*leg, "sm103a");
        let e = enc(&t, text).expect_err("[sm103a] guard must refuse even desc-base");
        assert!(format!("{e}").contains("BUG-060"), "guard msg: {e}");
    }
}

/// t450_6: census tripwire -- +3 forms per x3 leg, 121a untouched.
#[test]
fn t450_6_census() {
    for (leg, n) in CENSUS450 {
        assert_eq!(
            nforms(leg),
            *n,
            "[{leg}] form-count drift (post-450 expected {n})"
        );
    }
}

/// t450_7: canonical pin -- SOURCE.json base_revision == BUG-450 graft rev.
#[test]
fn t450_7_canonical_pin() {
    assert_eq!(CANON450, "cc2f62c"); // ride F2-iter275 (BUG-466 ELL2-plain); was 23976eb (BUG-465 modsub); ride F2-iter267 (BUG-432 ari-cavity); was a64b82b (BUG-463 ltc-widths);  ride F2-iter266 (BUG-463 ltc-widths); was f58ed16 (BUG-461 glyph); // ride F2-iter265 (BUG-461 glyph); was f376558 (BUG-462 narrow); // ride F2-iter264 (BUG-462 narrow); was 700524e (BUG-453 graft); // ride F2-iter263 (BUG-453 graft); was e03e034 (BUG-452 narrow); // ride F2-iter258 (BUG-454 graft) [flip-ride 467: pin 67b54f4 -> 668f842]
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        src["base_revision"].as_str().unwrap().starts_with(CANON450),
        "SOURCE.json must pin canonical a64b82bff6706350b82018609016f624188b99a5 (= BUG-463 ltc-widths, ride-after f58ed1683bded052bcb100a0762c16e7e91248c4 = BUG-461 glyph, ride-after f37655889e6da3ddd25b73a926c21ec3b58fa768 = BUG-462 narrow, ride-after 700524e698304dcbf1a3884f72f05abff609b8aa = BUG-453 graft, ride-after e03e0348d98b9d20ffb4ca557cfc6eae625cf995, = BUG-452 narrow, ride-after 4ee843162216e75d037135b5907c819759471296, = BUG-454 graft, ride-after 589be874 (= BUG-450) (= BUG-450; was 099faa0 = BUG-447): {:?}",
        src["base_revision"]
    );
}
