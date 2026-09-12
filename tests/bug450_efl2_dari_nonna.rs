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

/// t450_2: parity holes -- trailing policy-imm cells stay HOLE on ALL legs
/// (donor-side coverage gap; 453-kand), 12 cells.
#[test]
fn t450_2_parity_holes() {
    for (w, leg) in HOLE450 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        assert_eq!(
            dec(&t, &idx, *w),
            None,
            "[{leg}] parity-hole claimed {w:#034x}"
        );
    }
}

/// t450_3: CLONE-ILLEG standing -- raRZ word (vendor rc=1 x4) claims the
/// donor text on every leg, identical to sm121a pre/post (class 452;
/// documented donor-symmetry). Overclaim is the donor's, not the graft's.
#[test]
fn t450_3_cloneilleg_standing() {
    for (w, donor_text) in CLONEILLEG450 {
        for leg in LEGS450 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*donor_text),
                "[{leg}] clone-illeg standing drift {w:#034x}"
            );
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
    assert_eq!(CANON450, "9b60b92");
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        src["base_revision"].as_str().unwrap().starts_with(CANON450),
        "SOURCE.json must pin canonical 9b60b92014970a8d386c7dafea93d087862dca5e (= BUG-450; was 099faa0 = BUG-447): {:?}",
        src["base_revision"]
    );
}
