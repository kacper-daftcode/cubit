//! BUG-476 pins (F2-iter291/292, loop5/blind front2, 2026-09-17): plain
//! ELL2.256 dARI-era side-bits standing -- 476a NA-side graft + 476b fantom-_II.
//! 476a: NA-klony z donorow EL, delta 0x7@[86:84] (EL nibble 0x2 -> NA 0x5)
//! zmierzona verbatim z par 466; vm/fields/ctrl/scheduling verbatim, count
//! zdjety, _src476. LDG x4 nogi (+8: STRONG.GPU_R_R_ARURI64; LTC{64B,128B,
//! 256B}.256.STRONG.GPU_R_R_ARURI{,64}; CONSTANT.GPU_R_R_ARURI{,64}; swiadek:
//! Sna.b75b73/b75b74 heal przez klon-64 vm-side) + STG x3 nogi (+3:
//! STRONG.GPU_ARURI64_R_R; MMIO.SYS.ORDERED_ARURI_R_R{,64}; 121a STG-NA base
//! absent -> 121a-parity [NT], NIE graftowane). NIE graftowane: LTC256B x b75
//! (nie sondowane), _II/_P, b81 LDG era-split INVALID3/RML2 + b85-NA
//! E.INVALID7 + b81-STG INVALID3 x4 (standing-loud 285/440; 476c ledger).
//! 476b: STG.E.EL.ELL2.256.STRONG.GPU_ARURI_R_R_II (_src474) drukowal fantom
//! ', 0xff' na Sel.{b73,b74,b73b74} (pola nienazwane {72,73,87}->token4);
//! vendor b73/b74 tu INERT x4 -> claim_forbid [74:73] in {1,2,3} = HOLE-parity
//! (ekspozycja ab240 ZERO, census476). 121a NIE ruszana (winner _ARURI_R_R
//! EXACT pre==post). ENGINE ZERO src. Vendor law: arb476 72 sondy + arb476b 4
//! combo, nvdisasm 13.3.73 raw -b x4 AGREE EVERY poza b81 split. Data:
//! patch476.py replay byte-exact x4 + idem all-skip 44; audity A0/A0b(29)/A1
//! (heal 29/29/29/16; b476-hole 3x3)/A2/A3/A4(+11/+11/+11/+8; touched==476b
//! -key x3)/A5 (14879/14879/16016/23833; cf 1170/1170/1167/1183) fail-closed.
//! Canonical commit = cc2f62c379c3e190ef373ab9e8f76af0aeef326c
//! (serializacja INC-283a: po publish475; flip476b faza B). Census476b: 771 kluczy/noga ze wzorcem {72,73,87}-token4
//! -- poza zakresem bez prawa per-rama (aneks raportu).
//! Witness: tests/bug476_data.inc (maszynowe gen476pins.py rc=2; macierz klas
//! lock x patch476_log.json A1/A5: HEAL 29x3+16, B476 3x3+keep3, INERT 12+1,
//! BASE 131, STANDING 32, CORPUS 36, MINT 234 wierszy (220 exact +
//! 14 inert-kanon roundtrip; INC-299a: emisja generatora ustawiona na klasie
//! roundtrip z docstringu, roundtrip razem 44).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;
use std::collections::HashMap;
use std::sync::OnceLock;

include!("bug476_data.inc");

fn pool() -> &'static HashMap<&'static str, (IsaTable, DecodeIndex)> {
    static POOL: OnceLock<HashMap<&'static str, (IsaTable, DecodeIndex)>> = OnceLock::new();
    POOL.get_or_init(|| {
        let mut m = HashMap::new();
        for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
            let t = IsaTable::load(std::path::Path::new(&format!("tables/{leg}.json"))).unwrap();
            let idx = DecodeIndex::build(&t);
            m.insert(leg, (t, idx));
        }
        m
    })
}
fn dec(leg: &str, w: u128) -> Option<String> {
    let (t, idx) = pool().get(leg).unwrap();
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
fn enc(leg: &str, text: &str) -> Result<u128, String> {
    let (t, _) = pool().get(leg).unwrap();
    let full = format!(" {text} ;");
    let parsed = parse_sass(&full, 0).map_err(|e| e.to_string())?;
    encode_instruction(&parsed, t).map_err(|e| e.to_string())
}

/// t476_1: heal -- NA-klony 476a dekoduja DOKLADNIE tekst vendora x komorki
/// prawa (29 tagow x3 nogi + 16 na 121a); cold==HOLE (sygnatura generatora).
#[test]
fn t476_1_heal_decode() {
    for (w, leg, _key, want, tag) in HEAL476 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] heal {tag} {w:#034x}");
    }
}

/// t476_2: 476b -- fantom-print ', 0xff' NIESTY: HOLE-parity x3 nogi +
/// 121a EXACT keep (_ARURI_R_R winner pre==post, NIE ruszane).
#[test]
fn t476_2_b476_hole_and_121a_keep() {
    for (w, leg, cold_wrong, tag, _kind) in B476HOLE476 {
        let got = dec(leg, *w);
        assert!(got.is_none(), "[{leg}] 476b {tag} {w:#034x} -> {got:?}");
        assert!(
            cold_wrong.contains("0xff"),
            "swiadek zimnego fantomu zgubiony"
        );
    }
    for (w, leg, want, tag, _kind) in B476KEEP476 {
        let got = dec(leg, *w);
        assert_eq!(
            got.as_deref(),
            Some(*want),
            "[{leg}] 121a-keep {tag} {w:#034x}"
        );
    }
}

/// t476_3: inert-hole -- vendor-legal LTC-inert STG (b73/b74 bez .64) i 121a
/// STG-NA base (pre-hole 491-strefa): celowe HOLE (doktryna degenerate; tekst
/// vendora rejestrowany w pinie jako dokument, NIKI ne claim).
#[test]
fn t476_3_inert_hole() {
    for (w, leg, _vend, tag, _kind) in INERTHOLE476 {
        let got = dec(leg, *w);
        assert!(
            got.is_none(),
            "[{leg}] inert-hole {tag} {w:#034x} -> {got:?}"
        );
    }
}

/// t476_4: base-ident -- kotwice 466/474-era (EL ramy, NA baze) hot==cold==
/// vendor tekst (asercja maszynowa w generatorze; tu: == vendor).
#[test]
fn t476_4_base_ident() {
    for (w, leg, want, tag, _kind) in BASE476 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] base {tag} {w:#034x}");
    }
}

/// t476_5: standing-loud -- b81 era-split / b85 INVALID7: NIGDY kluczem;
/// pin = hot==cold werdykt zapisany w generatorze ("" = HOLE).
#[test]
fn t476_5_standing() {
    for (w, leg, want, tag, _kind) in STANDING476 {
        let got = dec(leg, *w);
        if want.is_empty() {
            assert!(got.is_none(), "[{leg}] standing {tag} {w:#034x} -> {got:?}");
        } else {
            assert_eq!(
                got.as_deref(),
                Some(*want),
                "[{leg}] standing {tag} {w:#034x}"
            );
        }
    }
}

/// t476_6: mint -- encode tekstu vendora: instr-bits [95:0] == slowo prawa
/// dla klas kanonicznych; piny base255 ('[UR4]' dwuznacznosc b75) + LTC-inert
/// STG combo = klasa (roundtrip): dec(enc(text)) == text. Kontrola/era poza
/// porownaniem (probe 0xbe400 vs kanon enkodera 0xfc200 -- dokument w generatorze).
#[test]
fn t476_6_mint_circle() {
    const CTL: u128 = !((1u128 << 96) - 1);
    for (w, leg, key, text, tag) in MINT476 {
        let m = enc(leg, text).unwrap_or_else(|e| panic!("[{leg}] mint {tag} err {e}"));
        if *key == "(roundtrip)" {
            let rt = dec(leg, m);
            assert_eq!(
                rt.as_deref(),
                Some(*text),
                "[{leg}] roundtrip {tag} {m:#034x}"
            );
        } else {
            assert_eq!(m & !CTL, w & !CTL, "[{leg}] mint {tag} instr-bits");
        }
    }
}

/// t476_7: corpus36 dARI EXACT keep x4 (hot==cold==ref w generatorze).
#[test]
fn t476_7_corpus_exact() {
    for (w, want, _scope, wh, _kind) in CORPUS476 {
        for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
            let got = dec(leg, *w);
            assert_eq!(got.as_deref(), Some(*want), "[{leg}] corpus {wh}");
        }
    }
}

/// t476_8: census + SOURCE -- forms/variants/cf-count lock z A5 patch476;
/// pre-flip: CANON476 pending + base_revision 978c0918 + brak _476_note;
/// post-flip (flip476b): pin na realny commit + note obecna.
#[test]
fn t476_8_census_and_source() {
    for (leg, want_forms, want_variants, want_cf) in CENSUS476 {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        assert_eq!(ins.len(), *want_forms, "[{leg}] forms census drift");
        let variants: usize = ins
            .values()
            .map(|v| v["mod_groups"].as_object().map(|m| m.len()).unwrap_or(0))
            .sum();
        assert_eq!(variants, *want_variants, "[{leg}] variants census drift");
        // errata pseudo-entries (sm121a) nie maja mod_groups -> traktowane
        // jako 0, dokladnie jak A5 patch476 (.get('mod_groups', {})); INC-299a
        let cf = ins
            .values()
            .filter_map(|v| v["mod_groups"].as_object())
            .flat_map(|m| m.values())
            .filter(|mg| {
                mg["claim_forbid"]
                    .as_array()
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
            })
            .count();
        assert_eq!(cf, *want_cf, "[{leg}] claim_forbid census drift");
    }
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    if CANON476 == "pending-476" {
        assert!(
            src["base_revision"]
                .as_str()
                .unwrap()
                .starts_with("cc2f62c"),
            "SOURCE pin pre-flip drift"
        );
        assert!(
            src.get("_476_note").is_none(),
            "_476_note istnieje przed flip476b"
        );
    } else {
        assert!(
            src["base_revision"].as_str().unwrap().starts_with(CANON476),
            "SOURCE pin drift po flipie"
        );
        assert!(
            src["_476_note"].as_str().unwrap().contains("476"),
            "brak _476_note po flipie"
        );
    }
}
