//! BUG-447 pins (F2-iter252, loop5/blind front2, 2026-09-12): x3 legs
//! (sm100a/sm103a/sm120) LDG/STG EFL2.256 NA family -- vendored era dARI
//! mod-groups rendered the family as `desc[URx][Ry.64]` (NA misroute: era
//! rows baked from single training records) or holed on policy/pred combos;
//! vendor nvdisasm 13.3.73 prints plain `[Rx.U32+URy]` on ALL FOUR legs
//! (arb446 54 probes + arb447 11 probes, raw -b x4 models AGREE
//! EVERY/DIVERGENT=0). Graft = canonical 099faa0: DELETE 3 era mgs x3
//! (exact-and_base fail-closed) + ADD 20 keys NA-ARURI cloned verbatim from
//! sm121a (LDG {CONSTANT.GPU,STRONG.GPU}[.LTC64B] x {ARURI,II,_P,II_P} = 16;
//! STG {MMIO.SYS.ORDERED,STRONG.GPU} x {,II} = 4); 121a leg byte-untouched;
//! ENGINE src ZERO. Corpus-ground: 340 EFL2.256.NA words live ONLY in
//! r055_raw_* BUG-055 repro fixtures (census447.json; zero production-lib
//! exposure). Defect pre->post (measure447; publish 9d226456 lineage +
//! canonical e8d1af3 -> work + 099faa0; 59 cells x4): x3 29 WRONG desc /
//! 28 HOLE / 2 POSTURE -> 55 MATCH / 2 WRONG (A.raRZ + C.raRZ standing:
//! vendor ELIDES `[RZ.U32+URnn]` base, print-side elision = 448-kand,
//! pre-existing on 121a as SNAP446_RZSTAND) / 2 POSTURE (b91 kill);
//! sm121a 55/2/2 -> 55/2/2 unchanged. NON-NA dARI EFL2 (LDG.E.EFL2.256 /
//! STG.E.EFL2.256) stays desc: genuine vendor desc x4 (arb447 F), 3-key
//! clone gap registered as 449-kand (overlap with healthy era ENL2 mgs).
//!
//! Witness data: tests/bug447_data.inc (machine-built by
//! work/bug447/gen447pins.py; rc=2 fail-closed; no hand hex; mints
//! nvdisasm-crossed x4 at generation time).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug447_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
const LEGS447: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

/// Serializacja CUBIT_DISABLE_ERRATA hatch: testy w tym binarce biegna
/// wielowatkowo; hatch jest proces-globalny, wiec kazdy refuse-assert
/// (guard musi odmowic) i kazde hatch-encode MUSZA trzymac ten sam lock.
/// (INC-252f: race t447_5 x t447_7 zlapany full-suite release 2202/1.)
static ERRATA_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let full = format!(" {text} ;");
    let parsed = parse_sass(&full, 0).map_err(|e| e.to_string())?;
    encode_instruction(&parsed, t).map_err(|e| e.to_string())
}

/// t447_1: heal grid -- x3 legs decode == vendor x4-unanimous text on every
/// cell that was desc-misroute/HOLE pre (165 cells: 55 words x 3 legs).
#[test]
fn t447_1_heal_grid() {
    for (w, leg, vendor) in LAW447_HEAL {
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

/// t447_2: 121a stable grid -- donor leg byte-untouched by the graft; every
/// cell stays decode == vendor (zero-drift tripwire).
#[test]
fn t447_2_stable_121a() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (w, vendor) in LAW447_STABLE121A {
        let got = dec(&t, &idx, *w);
        assert_eq!(
            got.as_deref(),
            Some(*vendor),
            "[sm121a] stable drift {w:#034x}"
        );
    }
}

/// t447_3: base-RZ cells -- family is plain on x3 now, but the RZ base is
/// base now elided exactly like vendor (BUG-448 healed the standing
/// class; flip448 F5). Machine-flipped post text, x4-identical.
#[test]
fn t447_3_rzstand_snap() {
    for leg in LEGS447 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, snap) in SNAP447_RZSTAND {
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*snap),
                "[{leg}] rzstand drift {w:#034x}"
            );
        }
    }
}

/// t447_4: b91=0 kill posture -- vendor rc=1 x4; engine must hole on all
/// four legs (pre == post == HOLE; donor rows must not claim kill words --
/// audit A3 in patch447_log.json, pinned here).
#[test]
fn t447_4_kill_posture() {
    for leg in LEGS447 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for w in POST447_KILL {
            assert_eq!(dec(&t, &idx, *w), None, "[{leg}] kill claimed {w:#034x}");
        }
    }
}

/// t447_5: mints + circles x4 -- encode(vendor text) == mint word (full
/// 128b; era normalized to the encode control word) on every leg (x3 donor
/// keys are encode-side too), decode(mint) == vendor text; mints
/// nvdisasm 13.3.73 cross-verified x4 unanimous at generation time.
/// guard103=true: even-Rn LDG base -- BUG-060 keeper arm (encoder.rs,
/// F2-iter252 companion) must REFUSE on sm103a with the BUG-060 citation;
/// the byte mapping is still proven under CUBIT_DISABLE_ERRATA (RE hatch,
/// decode circle runs un-hatched).
#[test]
fn t447_5_mints_x4() {
    for leg in LEGS447 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, text, g103) in MASKMINT447 {
            let hatch = *g103 && leg == "sm103a";
            let got = if hatch {
                let _g = ERRATA_LOCK.lock().unwrap();
                let e = enc(&t, text).expect_err("[sm103a] guard must refuse even-Rn NA EFL2");
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
}

/// t447_6: dead-bit normalization -- decode(law word with dead bits) ==
/// decode(mint) == vendor text (b72/b73/b87 set as measured in 446).
#[test]
fn t447_6_deadnorm() {
    for leg in LEGS447 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (law, mint) in DEADNORM447 {
            let a = dec(&t, &idx, *law).expect("law word HOLE");
            let b = dec(&t, &idx, *mint).expect("mint HOLE");
            assert_eq!(a, b, "[{leg}] dead-bit render split {law:#034x}");
        }
    }
}

/// t447_7: corpus evidence -- five real r055_raw_* words (era-carrying),
/// decode == vendor text x4 legs + encode(text) lo96-exact (dead set of
/// t447_6 tolerated).
#[test]
fn t447_7_corpus() {
    for leg in LEGS447 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, vendor, g103) in CORPUS447 {
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] corpus drift {w:#034x}"
            );
            let hatch = *g103 && leg == "sm103a";
            let mint = if hatch {
                let _g = ERRATA_LOCK.lock().unwrap();
                let e = enc(&t, vendor).expect_err("[sm103a] guard must refuse corpus even-Rn");
                assert!(format!("{e}").contains("BUG-060"), "guard msg: {e}");
                std::env::set_var("CUBIT_DISABLE_ERRATA", "1");
                let r = enc(&t, vendor);
                std::env::remove_var("CUBIT_DISABLE_ERRATA");
                r.expect("corpus hatch mint refuse")
            } else {
                enc(&t, vendor).expect("corpus mint refuse")
            };
            let x = (mint ^ w) & ((1u128 << 96) - 1);
            assert_eq!(
                x & !((1u128 << 72) | (1u128 << 73) | (1u128 << 87)),
                0,
                "[{leg}] corpus mint lo96 drift xor={x:#x}"
            );
        }
    }
}

/// t447_8: canonical pin -- blackwell-isa HEAD rides (was BUG-447 graft 099faa0, now 589be87 BUG-450) and
/// the vendored SOURCE manifest carries it.
#[test]
fn t447_8_canonical_pin() {
    // public-line hygiene: lane-side live rev-parse hermetized to the vendored manifest pin
    let head = std::fs::read_to_string("tables/SOURCE.json").unwrap();
    assert!(head.contains(CANON447), "canonical moved: {head}");
    let src = std::fs::read_to_string("tables/SOURCE.json").unwrap();
    assert!(
        src.contains("bd2e254"), // ride F2-iter275 BUG-466 ELL2-plain; was 23976eb F2-iter272 BUG-465; ride F2-iter267 BUG-432 ari-cavity; was a64b82b BUG-463 ltc-widths; ride F2-iter258 (BUG-454 graft; was 589be87 F2-iter255 BUG-450) [flip-ride 467: pin 67b54f4 -> 668f842]
        "tables SOURCE drift (BUG-447 graft): {src}"
    );
}
