//! BUG-475 pins (F2-iter287/288, loop5/blind front2, 2026-09-17): dARI modsub
//! lattice (b76=1) na frame E*L2.256 (LDG 0x97e / STG 0x97f, desc[URx][Ry.64])
//! -- klon 6 donorow *_dARI EFL2.256/noga (LDG x4 {,_P,_II,_II_P}, STG x2
//! {_II}) na kratke 191 kombinacji/op (l1,l2,sem \ baza; l2!=3) = +1146
//! kluczy/noga; clone zmienia TYLKO and_base (piny [77:86), b76=1) + base_op;
//! vm/fields verbatim. REKANON 462-mgs ENL2 (489-absorb): DELETE 13/13/7 mgs
//! ENL2 ltc=0 na widthless-kluczach (puste LDG_R_R_dARI/STG_dARI_R_R kasacja
//! x100a/103a; x120 mg tylko), 121a REPLACE 9 heritage _src462 lattice-named +
//! DELETE 2 anomalie-tokenowe NA/EU (count=0 dead). ENGINE ZERO src (sciezka
//! op dARI sterowana podpisem). Vendor law: arb475 560 sond nvdisasm 13.3.73
//! raw -b x4 AGREE EVERY poza l2=3 (div = wylacznie 64 komorki LDG l2=3
//! era-split standing-463; STG l2=3 glyph INVALID3); kills b91=0 rc=1 x4;
//! ra255 REFUSE x4 (BRAK elizji '[URm]' plain-464); ur255 desc[URZ]; imm
//! podpisane<<5 w nawiasie desc; STG LTC-sel [74:73] inert x4. Data:
//! patch475.py replay z canon_pre (68ac5aa-content) byte-exact x4 + idem
//! all-skip 4584; audity A0/A0b(408)/A1/A2/A4(+1146 -2 key x4)/A5 census
//! (14868/14868/16005/23825)/A9-R2 (+R3/R3b: NA/EU/alias + 121a anomalie) fail-closed. Canonical commit = cc2f62c379c3e190ef373ab9e8f76af0aeef326c
//! (serializacja INC-283a: po publish474; flip475b faza B). Korpus: 36 uniq
//! dARI w ab240 EXACT keep x4 (era-korekta iter288: corpus475_verify_v2).
//! Witness: tests/bug475_data.inc (maszynowe gen475pins.py rc=2; macierz klas
//! lock x claim475 engine-truth; NOTA: A1 split heal/heal462 bylo candidate-
//! based -- generator mierzy slinikowo: 6/6/4/4 vs A1 3/3/3/4; suma zgodna).
//! R3 (F2-iter289, INC-289d): R2 over-delete po mis-klasyfikacji 489 --
//! odtworzenie pokrycia vendor-legal: NA/EU ENL2.256 dARI (klon-okna grafta,
//! NIE verbatim 462 [ur5@32+imm20@37shr2]; arb475r3 27 sond x4 div0/invalid0,
//! cold-MIS=15) + alias-encode ".E.256.ENL2" (LDG_R_R_dARI mg encode_only).
//! collision-sweep 596x4 diffs=0; verify475r3 GATE PASS; 121a bajtowo nietkn.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;
use std::collections::HashMap;
use std::sync::OnceLock;

include!("bug475_data.inc");

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

/// t475_1: heal-decode -- graft-celle b76=1 dARI modsub (lattice E*L2.256)
/// dekoduja DOKLADNIE tekst vendora x4; cold HOLE (kind heal) lub MIS-glyph
/// z 462-era (kind heal462) -- obie strony maszynowo rozroznione w generatorze.
#[test]
fn t475_1_heal_decode() {
    for (w, leg, want, _kind) in HEAL475 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] heal {w:#034x}");
    }
}

/// t475_2: base + LTC -- base-ident EXACT pre==post==vendor (kotwica) +
/// LDG ltc-cross anchor (lane 490: tekst "" = HOLE hot==cold) + STG ltc
/// inert (stg-base EXACT keep / stg-heal na tekst vendora).
#[test]
fn t475_2_base_and_ltc() {
    for (w, leg, want) in BASE475 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] base {w:#034x}");
    }
    for (w, leg, kind, text) in LTC475 {
        let got = dec(leg, *w);
        match *kind {
            "ldg-anchor" => {
                if text.is_empty() {
                    assert!(got.is_none(), "[{leg}] ltc-ldg {w:#034x} -> {got:?}");
                } else {
                    assert_eq!(got.as_deref(), Some(*text), "[{leg}] ltc-ldg {w:#034x}");
                }
            }
            "stg-base" | "stg-heal" => {
                assert_eq!(got.as_deref(), Some(*text), "[{leg}] {kind} {w:#034x}");
            }
            other => panic!("nieznany kind {other}"),
        }
    }
}

/// t475_3: anchors standing -- l2=3 era-split (LDG) + glyph INVALID3 (STG) +
/// div-klasy: pin = COLD werdykt (tekst albo "" = HOLE); pre==post.
#[test]
fn t475_3_anchor_parity() {
    for (w, leg, cold) in ANCH475 {
        let got = dec(leg, *w);
        if cold.is_empty() {
            assert!(got.is_none(), "[{leg}] anchor-drill {w:#034x} -> {got:?}");
        } else {
            assert_eq!(got.as_deref(), Some(*cold), "[{leg}] anchor {w:#034x}");
        }
    }
}

/// t475_4: kills -- b91=0 vendor rc=1 x4 + ra255 REFUSE x4: engine HOLE.
#[test]
fn t475_4_kill_parity() {
    for (w, leg) in KILL475 {
        let got = dec(leg, *w);
        assert!(got.is_none(), "[{leg}] kill-claim {w:#034x} -> {got:?}");
    }
}

/// t475_5: mint-circle -- lattice teksty mintuja slowo; decode circle == tekst
/// x4 (BUG-077/060 polaryzacja: EFL2.256 odd base R29, ENL2/ELL2 even R28;
/// URZ-texts wylaczone -- encoder-side canonical UR63 [pre-existing, nota
/// generatora], pokrycie URZ po stronie decode w HEAL).
#[test]
fn t475_5_mint_circle() {
    for (w, leg, text) in MINT475 {
        let got = enc(leg, text).unwrap_or_else(|e| panic!("[{leg}] mint {text:?}: {e}"));
        assert_eq!(
            got, *w,
            "[{leg}] mint word {text:?}: {got:#034x} != {w:#034x}"
        );
        let back = dec(leg, got);
        assert_eq!(back.as_deref(), Some(*text), "[{leg}] mint circle {text:?}");
    }
    for (text, leg) in SEALED475 {
        assert!(
            enc(leg, text).is_err(),
            "[{leg}] sealed-parity {text:?} minted"
        );
    }
}

/// t475_6: refuse-parity encode: ra255 odmowa x4 (obiektywie oba engine-ery).
#[test]
fn t475_6_refuse_parity() {
    for (text, leg, _class) in MINTREF475 {
        assert!(enc(leg, text).is_err(), "[{leg}] refuse {text:?} minted");
    }
}

/// t475_7: census + SOURCE pin w stanie POST-FLIP (base_revision == CANON475;
/// stan pre-flip pending-475 historyczny w galezi przed flip475b). Census =
/// raw map-len (z _errata x2 na 121a: 23825; loader-visible 23823).
#[test]
fn t475_7_census_and_source() {
    for (leg, want) in CENSUS475 {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        assert_eq!(ins.len(), *want, "[{leg}] census drift");
    }
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    if CANON475 == "pending-475" {
        // stan pre-flip: base_revision == 68ac5aa (474 canonical) + note.
        assert!(
            src["base_revision"]
                .as_str()
                .unwrap()
                .starts_with("cc2f62c"),
            "SOURCE pin pre-flip drift"
        );
        assert!(
            src.get("_475_note").is_none(),
            "_475_note istnieje przed flip475b"
        );
    } else {
        assert!(
            src["base_revision"].as_str().unwrap().starts_with(CANON475),
            "SOURCE pin drift po flipie"
        );
        assert!(
            src["_475_note"].as_str().unwrap().contains("475"),
            "brak _475_note po flipie"
        );
    }
}

/// t475_8: corpus36 EXACT keep z era-pelna reprezentacja (0x000be400<<96|w;
/// korekta iter288 -- STG-ven w corpus475_verify bylo null). hot==vendor x4.
#[test]
fn t475_8_corpus_exact() {
    for (w, leg, want) in CORPUS475 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] corpus {w:#034x}");
    }
}

/// t475_9: rekanon R2+R3 -- absent: puste widthless/anomalie NIE zyja;
/// R3 (INC-289d): alias-encode-only = LDG_R_R_dARI wraca z JEDNYM mg
/// '256,E,ENL2' encode_only (legacy-spelling; decoder-skipped);
/// r3-restored = NA/EU lattice-key obecny (klon-okna grafta).
#[test]
fn t475_9_rekanon() {
    for (key, leg, mode) in REKANON475 {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        match *mode {
            "absent" => assert!(
                ins.get(*key).is_none(),
                "[{leg}] rekanon-key {key} przezywa"
            ),
            "alias-encode-only" => {
                let k = ins
                    .get(*key)
                    .unwrap_or_else(|| panic!("[{leg}] alias-key {key} absent"));
                let mg = k["mod_groups"].as_object().unwrap();
                assert_eq!(mg.len(), 1, "[{leg}] alias-key mg-set != 1");
                let a = &mg["256,E,ENL2"];
                assert_eq!(a["encode_only"], true, "[{leg}] alias mg bez encode_only");
                assert_eq!(
                    a["and_base"], "0x8121900fe0000000000097e",
                    "[{leg}] alias and_base drift"
                );
                assert_eq!(
                    k["_src475r3"], "bug475r3-2026-09-17",
                    "[{leg}] alias bez _src475r3"
                );
            }
            "r3-restored" => assert!(
                ins.get(*key).is_some(),
                "[{leg}] R3-restore-key {key} absent"
            ),
            "r3b-restored-anom" => {
                let k = ins
                    .get(*key)
                    .unwrap_or_else(|| panic!("[{leg}] R3b-anomalia {key} absent po restore"));
                assert_eq!(
                    k["_src475r3"], "bug475r3b-2026-09-17",
                    "[{leg}] {key} bez tagu R3b"
                );
                assert_eq!(
                    k["mod_groups"][""]["count"], 0,
                    "[{leg}] {key} count != 0 po restore"
                );
            }
            other => panic!("nieznany REK-mode {other}"),
        }
    }
}

/// t475_10: R3 restore EXACT -- NA/EU ENL2.256 desc-dARI (INC-289d) dekoduja
/// DOKLADNIE tekst vendora x4 na nogach legal (klon-okna grafta; ghost UR6
/// 462-era nie wraca -- pin ur.38w drukuje UR38 bez ghost-imm). "" = HOLE-keep
/// (121a + EU-120: vendor-legal, pokrycia nigdy nie bylo; kand 491).
#[test]
fn t475_10_r3_restore() {
    let legs = ["sm100a", "sm103a", "sm120", "sm121a"];
    for &(w, t100, t103, t120, t121) in R3R475 {
        let wants = [t100, t103, t120, t121];
        for (leg, want) in legs.iter().zip(wants.iter()) {
            let got = dec(leg, w);
            let want: Option<&str> = if want.is_empty() { None } else { Some(*want) };
            assert_eq!(
                got.as_deref(),
                want,
                "[{leg}] r3-restore {w:#034x}: got {got:?} want {want:?}"
            );
        }
    }
}

/// t475_11: alias-encode parity (INC-289d) -- legacy-spelling ".E.256.ENL2"
/// mintuje DOKLADNIE slowo kanonicznego spellingu (== cold474-mint; pin-word
/// maszynowy). Odd-base: sm103a sealed (BUG-077); 100a/120 parity z cold474.
#[test]
fn t475_11_alias_mint() {
    for (ta, tc, w, leg) in ALIAS475 {
        let a = enc(leg, ta).unwrap_or_else(|e| panic!("[{leg}] alias-err {ta:?}: {e}"));
        let c = enc(leg, tc).unwrap_or_else(|e| panic!("[{leg}] canon-err {tc:?}: {e}"));
        assert_eq!(a, *w, "[{leg}] alias mint {ta:?} != pin {w:#034x}");
        assert_eq!(c, *w, "[{leg}] canon mint {tc:?} != pin {w:#034x}");
    }
    for (t, leg, w) in ODD077R475 {
        if *w == 0 {
            assert!(enc(leg, t).is_err(), "[{leg}] odd-base {t:?} minted");
        } else {
            let a = enc(leg, t).unwrap_or_else(|e| panic!("[{leg}] odd-err {t:?}: {e}"));
            assert_eq!(a, *w, "[{leg}] odd parity {t:?} != cold-mint {w:#034x}");
        }
    }
}
