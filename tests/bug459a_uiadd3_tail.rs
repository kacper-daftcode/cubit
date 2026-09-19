//! BUG-459a pins (F2-iter296 pre-study + iter301 wykonanie, loop5/blind
//! front2, 2026-09-18): UIADD3 plain junk-tail ", UPT, UPT" -- DELETE junk
//! mod-groups "" / "64" z kluczy UIADD3_UR_UP_UP_UR_{UR,II}_UR_UP_UP
//! (sm120+sm121a). Junk-mgs mialy pred-out bity [77:81)+[87:91) spine na
//! default 0xf/0xf BEZ ekstrakcji tokenow 6..8 -> drukowaly suffix ", UPT,
//! UPT" i shadowowaly dobre wiersze 6-tokenowe (winner-shadow; na 100a/103a
//! te same slowa trafialy w poprawne wiersze -- junk mg tam byl nieszkodliwy
//! -> A4b nogi bajtowo nietkniete). sm120: klucz UR_II pusty po kasacji ->
//! key-del (DOKLADNIE 1). Prawo vendora (arb459a 136 sond, nvdisasm 13.3.73
//! raw -b x4 AGREE EVERY): natywne slowa imm/UR + sweep guard [12:16) x16 +
//! rama .64 ZAWSZE drukuja forme 6-tokenowa; bity [77:91) DEAD na ramie imm
//! (flip = vendor bez zmian). Audity patch459a.py: A0 (zawartosc kasowanych
//! mg and_base/vm lock + brak ekstrakcji [77:91)), A4 (removed==DOKLADNIE
//! {UR_II} sm120, touched=={UR_UR} sm120 + oba klucze sm121a), A4b
//! byte-parity 100a/103a, A5 census (14879/14879/16015/23833 forms;
//! 16450/16446/17631/26385 variants; cf 1170/1170/1167/1183) fail-closed.
//! ENGINE cubit NIE ruszony (table-only). Canonical commit 96372cb (po 476
//! c88778e; serializacja INC-283a).
//! Witness: tests/bug459a_data.inc (maszynowe gen459apins.py rc=2; macierz
//! klas lock): HEAL 66 (33 sm120 + 33 sm121a), EXACT 8 (121a), HOLEPAR 8
//! (sm120 flip77..80,87..90 -- vendor-legal poza oknem dobrego wiersza),
//! REFPAR 190 (vendor refuse, hole-parity x2), X3STABLE 66 + X3STANDING 16
//! (x3 overprint dead-bitow [77:91): UIADD3.X + UPx-tail, cold==hot,
//! 408-residuum companion -- parity-only wg doktryny 285/440), MINT 8
//! (4 teksty x {120,121a}), JUNK 8-token encode fail-closed x2.
//! Klasa KILL = 0 (delete nie zdejmuje zadnego overclaimu dekodera; pre-fix
//! junk-mint 0xfc2000fffe0fffffffff0070a7890 potwierdzony encode-side).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;
use std::collections::HashMap;
use std::sync::OnceLock;

include!("bug459a_data.inc");

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

/// t459a_1: macierz dekodera -- HEAL/EXACT/X3STABLE/X3STANDING == zapisany
/// tekst; HOLEPAR/REFPAR/X3HOLEPAR == HOLE. Klasy z generatora (cold/hot/
/// vendor x136 sond); STANDING-x3 = parity-only (408-residuum companion).
#[test]
fn t459a_1_decode_matrix() {
    for (w, leg, want, tag, _scope) in HEAL459A {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] heal {tag} {w:#034x}");
    }
    for (w, leg, want, tag, _scope) in EXACT459A {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] exact {tag} {w:#034x}");
    }
    for (w, leg, want, tag, _scope) in X3STABLE459A {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] x3stable {tag} {w:#034x}");
    }
    for (w, leg, want, tag, _scope) in X3STANDING459A {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] x3standing {tag} {w:#034x}");
    }
    for (name, rows) in [
        ("holepar", HOLEPAR459A),
        ("refpar", REFPAR459A),
        ("x3holepar", X3HOLEPAR459A),
    ] {
        for (w, leg, _t, tag, _scope) in rows {
            let got = dec(leg, *w);
            assert!(got.is_none(), "[{leg}] {name} {tag} {w:#034x} -> {got:?}");
        }
    }
}

/// t459a_2: mint-circle (encode tekstow vendora, instr-bits [95:0]; ctrl
/// poza porownaniem wg INC-249b) + junk-8token fail-closed x2 + census
/// forms/variants/cf (lock A5 patch459a) + SOURCE.json (base_revision ==
/// CANON459A + nota 459a). Klasa KILL pusta -- JUNK row = encode-side.
#[test]
fn t459a_2_mint_junk_census_source() {
    const CTL: u128 = !((1u128 << 96) - 1);
    for (w, leg, text, tag, _scope) in MINT459A {
        let m = enc(leg, text).unwrap_or_else(|e| panic!("[{leg}] mint {tag} err {e}"));
        assert_eq!(m & !CTL, w & !CTL, "[{leg}] mint {tag} instr-bits");
        let rt = dec(leg, m);
        assert_eq!(rt.as_deref(), Some(*text), "[{leg}] roundtrip {tag} {m:#034x}");
    }
    for leg in ["sm120", "sm121a"] {
        assert!(
            enc(leg, JUNK459A_TEXT).is_err(),
            "[{leg}] junk 8-token nadal encodable po 459a"
        );
    }
    for (leg, want_forms, want_variants, want_cf) in CENSUS459A {
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
    assert!(
        src["base_revision"]
            .as_str()
            .unwrap()
            .starts_with(CANON459A),
        "SOURCE pin drift po flipie 459a"
    );
    assert!(
        src["_459a_note"].as_str().unwrap().contains("459a"),
        "brak _459a_note po flipie"
    );
}
