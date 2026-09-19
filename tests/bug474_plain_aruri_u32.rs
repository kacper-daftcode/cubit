//! BUG-474 pins (F2-iter285, loop5/blind front2, 2026-09-17): plain (nNA)
//! E*L2.256 ARURI U32-sibling (b75=0) -- blizniaki '_ARURI' CALEJ rodziny
//! plain ARURI64 x4 nogi (464 baza 6 / 465 lattice / 468 LTC-sel; 3456
//! donorow/noga -> +3454/+3454/+3454/+3455 kluczy; skip-celle pre-claimed:
//! x3 LDG+STG.EL.ELL2.256.STRONG.GPU [466-row] + 121a LDG [469-row]; 121a
//! STG-twin (466 x3-only) heal-uje tam komorke). and_base &= ~(1<<75);
//! vm/fields/base_op/ctrl/scheduling verbatim z donora; count=None.
//! ENGINE printer.rs: format_plain_u32_ur +flaga plain_u32 (kluczem LDG.E./
//! STG.E. + token E*L2 + !.NA. + raw b75==0): width zawsze 'U32' (STG
//! [91:90]==3 NIE moze leakowac '.64' reg. 099), baza 255 -> czysta elizja
//! '[URm(+off)]'. ENCODER: w guardzie Addr{base:None,ur} kandydaci
//! '_ARURI64' PRZED '_ARURI' (obietnica 464-arm: '[URm]' mintuje b75=1;
//! explicit '[Rn.U32+URm]' mintuje wiersz _ARURI b75=0 osobnym kluczem).
//! Vendor law: arb474 (165) + arb474b (62) + arb474c (8) + arb474d (15) sond
//! nvdisasm 13.3.73 raw -b x4 AGREE EVERY/DIVERGENT=0 + claim474 227 sond x4
//! (EXACT 3/noga flip75-ctrl + HOLE 218/noga + REFUSE-OK 6/noga, MIS 0).
//! KILL: b91=0 rc=1 x4; b76=1 REFUSE x4 (po U32 NIE ma desc-formy). Encode:
//! desc-formy plain-L2 = sealed parity pre==post (MINTDESC 7 + ENCTAIL 5;
//! korekta iter286), explicit-U32 mint b75=0 (skip sm103a-even-base = BUG-060
//! guard parity). Standing:
//! junk L2=3 (INVALID3/RML2 wspoldzielone z 469, HOLE-parity), inert-parity
//! (b83/band pinowane jak strona .64), NA-side lattice gap = 485-kand.
//! Data: patch474.py replay z canon_pre (bd48e63-content) byte-exact x4 +
//! idem all-skip 13817; audity A0/A0b(226)/A1(420-422 heal/noga)/A2/A3/A4
//! (+3454 x3, +3455 121a, reszta byte-equal)/A5(->13721/13721/14859/22688)/
//! A6/A7 fail-closed. Canonical commit = cc2f62c379c3e190ef373ab9e8f76af0aeef326c (INC-283a: flip po publish469; flip474b iter286).
//! Witness: tests/bug474_data.inc (maszynowe gen474pins.py rc=2).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;
use std::collections::HashMap;
use std::sync::OnceLock;

include!("bug474_data.inc");

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

/// t474_1: heal-decode -- graft-celle b75=0 (cala lattice plain nNA; law
/// 250 sond + claim474 HOLE) dekoduje DOKLADNIE tekst vendora x4; cold
/// (publish-pending 469) HOLE potwierdzone maszynowo w generatorze.
#[test]
fn t474_1_heal_decode() {
    for (w, leg, want) in HEAL474 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] heal {w:#034x}");
    }
}

/// t474_2: edge -- 121a STG skip-cell heal przez twin (466 x3-only; na x3
/// winnerem zostaje 466-row, pokryte ANCH474 przez migracje cold!=None).
#[test]
fn t474_2_edge_121a_stg() {
    for (w, leg, want) in EDGE474 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] edge {w:#034x}");
    }
}

/// t474_3: anchors -- junk L2=3 / inert-parity / b86-zone / refuse-b76 /
/// ctrl64-side: pin = COLD werdykt (tekst albo "" = HOLE); pre==post.
#[test]
fn t474_3_anchor_parity() {
    for (w, leg, cold) in ANCH474 {
        let got = dec(leg, *w);
        if cold.is_empty() {
            assert!(got.is_none(), "[{leg}] anchor-drill {w:#034x} -> {got:?}");
        } else {
            assert_eq!(got.as_deref(), Some(*cold), "[{leg}] anchor {w:#034x}");
        }
    }
}

/// t474_4: kills -- b91=0 (vendor rc=1 x4) + vendor-REFUSE: engine HOLE.
#[test]
fn t474_4_kill_parity() {
    for (w, leg) in KILL474 {
        let got = dec(leg, *w);
        assert!(got.is_none(), "[{leg}] kill-claim {w:#034x} -> {got:?}");
    }
}

/// t474_5: mint explicit-U32 -- tekst '[Rn.U32+URm(+off)]' na E*L2 lattice
/// mintuje wiersz _ARURI (slowo b75=0), decode circle == tekst, x4 nogi.
#[test]
fn t474_5_mint_explicit_u32() {
    for (text, leg) in MINT474 {
        let w = enc(leg, text).unwrap_or_else(|e| panic!("[{leg}] mint {text:?}: {e}"));
        assert_eq!((w >> 75) & 1, 0, "[{leg}] mint b75!=0 {text:?}: {w:#034x}");
        let back = dec(leg, w);
        assert_eq!(back.as_deref(), Some(*text), "[{leg}] mint circle {text:?}");
    }
}

/// t474_6: elide '[URm(+off)]' -- obietnica 464-arm utrzymana (kandydat
/// _ARURI64 PRZED _ARURI): slowo b75=1, baza 255, circle == tekst, x4 nogi.
/// ENCTAIL474: desc-formy refuse = sealed parity cold==hot (fail-closed).
#[test]
fn t474_6_elide_mint_464arm() {
    for (text, leg) in MINTELIDE474 {
        let w = enc(leg, text).unwrap_or_else(|e| panic!("[{leg}] elide {text:?}: {e}"));
        assert_eq!((w >> 75) & 1, 1, "[{leg}] elide b75!=1 (464-arm) {text:?}");
        assert_eq!((w >> 24) & 0xff, 255, "[{leg}] elide base!=255 {text:?}");
        let back = dec(leg, w);
        assert_eq!(
            back.as_deref(),
            Some(*text),
            "[{leg}] elide circle {text:?}"
        );
    }
    for (text, leg) in ENCTAIL474 {
        assert!(
            enc(leg, text).is_err(),
            "[{leg}] enc-standing {text:?} otwarte"
        );
    }
    // RIDE475R3 (INC-289e): tekst opuscil ENCTAIL po 475-graft (gain) --
    // mintujemy bajtowo slowo vendora + circle decode == tekst.
    for (text, leg, want) in MINTGAIN474 {
        let w = enc(leg, text).unwrap_or_else(|e| panic!("[{leg}] mint-gain {text:?}: {e}"));
        assert_eq!(w, *want, "[{leg}] mint-gain word {text:?}");
        assert_eq!(
            dec(leg, w).as_deref(),
            Some(*text),
            "[{leg}] mint-gain circle {text:?}"
        );
    }
}

/// t474_6b: MINTDESC -- desc-formy plain-L2 mintowalne PRE-474 (7/12;
/// dowod iter286: cold /tmp/det469 + canon_pre mintuje identycznym slowem).
/// Graft 474 NIE klaimuje tych komorek: hot word == zapieczetowane cold.
#[test]
fn t474_6b_mintdesc_sealed_parity() {
    for (text, leg, cold_hex) in MINTDESC474 {
        let w = enc(leg, text).unwrap_or_else(|e| panic!("[{leg}] mintdesc {text:?}: {e}"));
        assert_eq!(
            format!("{w:032x}"),
            *cold_hex,
            "[{leg}] mintdesc word drift {text:?}"
        );
        let back = dec(leg, w);
        assert_eq!(
            back.as_deref(),
            Some(*text),
            "[{leg}] mintdesc circle {text:?}"
        );
    }
}

/// t474_7: census + SOURCE pin w stanie POST-FLIP (base_revision ==
/// 68ac5aa; stan pre-flip pending-474 historyczny w galezi przed
/// flip474b -- TESTOWO zawsze fail-closed na drift).
#[test]
fn t474_7_census_and_source() {
    for (leg, want) in CENSUS474 {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        assert_eq!(ins.len(), *want, "[{leg}] census drift");
    }
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    if CANON474 == "pending-474" {
        // stan pre-flip: base_revision == bd48e63 (rodzic 469) + pending note.
        assert!(
            src["base_revision"]
                .as_str()
                .unwrap()
                .starts_with("cc2f62c"),
            "SOURCE pin pre-flip drift"
        );
        assert!(
            src["_pending_note"].as_str().unwrap().contains("474"),
            "brak _pending_note 474"
        );
    } else {
        assert!(
            src["base_revision"].as_str().unwrap().starts_with(CANON474),
            "SOURCE pin drift po flipie"
        );
    }
}
