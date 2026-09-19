//! BUG-453 pins (F2-iter263, loop5/blind front2, 2026-09-13): non-NA dARI
//! EFL2.256 trailing policy-imm -- rodziny `LDG.E.EFL2.256[_R_R_dARI{,_P}]` /
//! `STG.E.EFL2.256[_dARI_R_R]` nie mialy wariantow `_II` na ZADNEJ nodze
//! (donor 121a tez; fuzz450 TRUNC-POLICY-DONOR). Defekt: (a) slowa z
//! policy-imm != 0xff i b72=0 = HOLE-parity (coverage-gap donor-side);
//! (b) b72=1 pol!=0xff = broad-claim ze SCIETA przycinka (engine drukowal
//! bez ', 0xNN', vendor z trailerem). Graft = canonical e03e034 -> 700524e:
//! ADD 3 klucze/noga x4 (DONOR-FIRST, 121a tez) syntezowane transformem
//! bit-delta zmierzonym na NA-parach (baza->_II) tej samej nogi
//! [LDG: delA=setV=0x100fe00000000000000; STG: 0x7000000f800000000000000],
//! claim_forbid (452 [24:32)==255) kopiowane verbatim, ENGINE src ZERO.
//! Vendor law: arb453 (94 sondy) + arb453b (18) + arb453c (16) -- nvdisasm
//! 13.3.73 raw -b x4 AGREE EVERY/DIVERGENT=0: pol 8b pelny zakres legal,
//! 0xff ELIDED (baza strict wygrywa tie-break krotszym kluczem), trailer
//! PRZED pred-out, imm17/19 signed<<5, RZ/URZ glyph legal, guard/era-b118/
//! reuse-b122 legalne; KILL x4: ra255 (452) + b91=0. Poza scope
//! (parity-HOLE resid, rejestracje): nNA LTC64B (463), vendor-noop bity
//! (STG 72/73/87/[92:96), LDG [92:96); 463), plain ARURI trailer (464),
//! modsub MMIO/CONSTANT/EF/PRIVATE (465). Witness data:
//! tests/bug453_data.inc (machine-built by work/bug453/gen453pins.py;
//! rc=2 fail-closed; no hand hex; minty nvdisasm-crossed x4 przy generacji).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug453_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
fn deckey(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t).ok().map(|d| d.key)
}
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

/// t453_1: trailer grid -- decode == vendor x4-unanim text na kazdej celi
/// (55 slow x 4 nogi; klasy (a) HOLE-heal i (b) TRUNC-heal).
#[test]
fn t453_1_trailer_grid() {
    for (w, leg, vendor) in LAW453_TRAILER {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        assert_eq!(
            dec(&t, &idx, *w).as_deref(),
            Some(*vendor),
            "[{leg}] trailer drift {w:#034x}"
        );
    }
}

/// t453_2: elide cells -- pol==0xff zostaje na BAZIE (print bez trailera,
/// klucz bazowy nie _II; tie-break krotszym kluczem ma nie byc skradziony).
#[test]
fn t453_2_elide_stays_base() {
    for (w, leg, vendor) in ELIDE453 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        assert_eq!(
            dec(&t, &idx, *w).as_deref(),
            Some(*vendor),
            "[{leg}] elide drift {w:#034x}"
        );
        let k = deckey(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] elide HOLE"));
        assert!(
            !k.contains("_II"),
            "[{leg}] elide word claimed by _II key {k} ({w:#034x})"
        );
    }
}

/// t453_3: trailer words route to the NEW _II keys (dowod tie-breaku:
/// _II strict bije base broad; pred-cells do _II_P).
#[test]
fn t453_3_trailer_routes_ii() {
    let mut n = 0;
    for (w, leg, vendor) in LAW453_TRAILER {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let k = deckey(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] trailer HOLE"));
        assert!(k.contains("_II"), "[{leg}] trailer {w:#034x} not _II: {k}");
        if vendor.contains(", !PT") || vendor.contains(", PT") {
            assert!(
                k.ends_with("_II_P"),
                "[{leg}] pred-trailer {w:#034x} not _II_P: {k}"
            );
        }
        n += 1;
    }
    assert_eq!(n, LAW453_TRAILER.len());
}

/// t453_4: resid parity-holes HEALED463 (ride, canonical a64b82b):
/// 68 komorek (17 tagow x4) z klasy 463 (noop-band STG/LDG + LTC64B
/// selektor b73) -- swiadkowie zostaja w RESID453, dekodowanie =
/// vendor text (arb453b/453c). Wortsy resid 464/465 (trailer
/// policy-imm plain ARURI + modsub MMIO/CONSTANT/EF) NIE sa tu
/// objete (sobie slow nie ma w RESID453).
#[test]
fn t453_4_resid_holes_healed_463() {
    const HEALED463: &[(u128, &str)] = &[
        (
            61739659495252407648695271340120447u128,
            "@P1 STG.E.EFL2.256 desc[UR38][R28.64], R44, R48, 0xe4",
        ), // S.pole4_flip72
        (
            61739659495257130015178140985334143u128,
            "@P1 STG.E.EFL2.256 desc[UR38][R28.64], R44, R48, 0xe4",
        ), // S.pole4_flip73
        (
            61739659649990190192884936057297279u128,
            "@P1 STG.E.EFL2.256 desc[UR38][R28.64], R44, R48, 0xe4",
        ), // S.pole4_flip87
        (
            61739659495252423213135583532554623u128,
            "@P1 STG.E.EFL2.256 desc[UR38][R28.64], R44, R48",
        ), // S.polff_flip72
        (
            61739659495257145579618453177768319u128,
            "@P1 STG.E.EFL2.256 desc[UR38][R28.64], R44, R48",
        ), // S.polff_flip73
        (
            61739659649990205757325248249731455u128,
            "@P1 STG.E.EFL2.256 desc[UR38][R28.64], R44, R48",
        ), // S.polff_flip87
        (
            61739657328866910309495822464588158u128,
            "@P1 LDG.E.EFL2.LTC64B.256 R44, R48, desc[UR38][R28.64]",
        ), // L.polff_flip73
        (
            61739664447007842423733501291403647u128,
            "@P1 STG.E.EFL2.256 desc[UR38][R28.64], R44, R48, 0xe4",
        ), // S.pole4_f92
        (
            61739669398767999565254600887900543u128,
            "@P1 STG.E.EFL2.256 desc[UR38][R28.64], R44, R48, 0xe4",
        ), // S.pole4_f93
        (
            61739679302288313848296800080894335u128,
            "@P1 STG.E.EFL2.256 desc[UR38][R28.64], R44, R48, 0xe4",
        ), // S.pole4_f94
        (
            61739699109328942414381198466881919u128,
            "@P1 STG.E.EFL2.256 desc[UR38][R28.64], R44, R48, 0xe4",
        ), // S.pole4_f95
        (
            61739662280617618826941104722549118u128,
            "@P1 LDG.E.EFL2.256 R44, R48, desc[UR38][R28.64], 0xe4",
        ), // L.pole4_f92
        (
            61739667232377775968462204319046014u128,
            "@P1 LDG.E.EFL2.256 R44, R48, desc[UR38][R28.64], 0xe4",
        ), // L.pole4_f93
        (
            61739677135898090251504403512039806u128,
            "@P1 LDG.E.EFL2.256 R44, R48, desc[UR38][R28.64], 0xe4",
        ), // L.pole4_f94
        (
            61739696942938718817588801898027390u128,
            "@P1 LDG.E.EFL2.256 R44, R48, desc[UR38][R28.64], 0xe4",
        ), // L.pole4_f95
        (
            61739699109328957978821510659316095u128,
            "@P1 STG.E.EFL2.256 desc[UR38][R28.64], R44, R48",
        ), // S.polff_f95
        (
            61739696942938722708698879946135934u128,
            "@P1 LDG.E.EFL2.256 R44, R48, desc[UR38][R28.64]",
        ), // L.polff_f95
    ];
    assert_eq!(
        RESID453.len() / 4,
        HEALED463.len(),
        "RESID453/healed grid drift"
    );
    for (i, (w, want)) in HEALED463.iter().enumerate() {
        for (hw, leg) in RESID453.iter().skip(i * 4).take(4) {
            assert_eq!(hw, w, "RESID453 grid order drift");
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *hw).unwrap_or_else(|| panic!("[{leg}] heal {hw:#034x} HOLE"));
            assert_eq!(got, *want, "[{leg}] heal {hw:#034x}");
        }
    }
}

/// t453_5: kill-preserve -- ra255 (452 claim_forbid przeniesione na _II) +
/// b91=0 structure-kills, wszystkie nogi (16 cel).
#[test]
fn t453_5_kill_preserve() {
    for (w, leg) in KILL453 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        assert_eq!(
            dec(&t, &idx, *w),
            None,
            "[{leg}] kill-word claimed {w:#034x}"
        );
    }
}

/// t453_6: mints x4 -- encode(text) == mint word AND decode(mint) == text;
/// guard_hatch cells biora BUG-060 refuse-assert + hatch pod ERRATA_LOCK
/// (wzorzec t450_4/INC-252f).
#[test]
fn t453_6_mints_x4() {
    for (text, leg, w, ghatch) in MINT453 {
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

/// t453_7: refuse grid -- RZ-baza desc na _II-formach odmawia encode z
/// cytatem BUG-452 (claim_forbid symmetric) na kazdej nodze.
#[test]
fn t453_7_refuse452_grid() {
    const TEXTS: [&str; 2] = [
        "LDG.E.EFL2.256 R45, R48, desc[UR38][RZ.64], 0x99",
        "STG.E.EFL2.256 desc[UR38][RZ.64], R44, R48, 0xe4",
    ];
    for leg in REFUSE453_452 {
        let t = tab(leg);
        for text in TEXTS {
            let e = enc(&t, text).expect_err("[{leg}] RZ.64 desc must refuse");
            assert!(format!("{e}").contains("452"), "[{leg}] refuse msg: {e}");
        }
    }
}

/// t453_8: census tripwire (+3 formy per leg x4; 121a pierwszy ruch od 443)
/// + canonical pin (SOURCE.json == BUG-453 graft rev).
#[test]
fn t453_8_census_and_canonical() {
    for (leg, n) in CENSUS453 {
        assert_eq!(
            nforms(leg),
            *n,
            "[{leg}] form-count drift (post-453 expected {n})"
        );
    }
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        src["base_revision"].as_str().unwrap().starts_with("cc2f62c"),
        "SOURCE.json must pin canonical {CANON453} (= BUG-453 graft, ride-after e03e0348d98b9d20ffb4ca557cfc6eae625cf995 = BUG-452 narrow): {:?}",
        src["base_revision"]
    );
}
