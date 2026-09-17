//! BUG-468 pins (F2-iter280, loop5/blind front2, 2026-09-16): LTC-width
//! selektor [74:73] lattice closure -- LDG E*L2.256 plain ARURI64 (nNA)
//! x3 sel (2304 kluczy/noga: {LTC64B,LTC128B,LTC256B} x 768 donorow z
//! 464/465-lattice) + NA-side LTC128B/LTC256B (16/noga; LTC64B dzialal
//! pre). Klony donorow verbatim (vm/fields), ZMIANA TYLKO and_base |=
//! sel<<73 + base_op + count=None + _src468; ENGINE ZERO (data-only).
//! Vendor law (arb468 3140 sond nvdisasm 13.3.73 raw -b x4 AGREE
//! EVERY/DIVERGENT=0): 192 ramki x sel{0,1,2,3} wszystkie vendor-legal,
//! REFUSE 0; mnemonic-regula = wstawka .LTCnm. PO tokenie L2
//! (EFL2/ENL2/ELL2); kills b91=0 rc=1 x4 pod kazdym sel; ra255 ->
//! '[URm(+imm)]' elizja bazy, ur255 -> 'URZ' (plain-geometria 464 -- kill
//! ra255 z 452 dotyczy WYLACZNIE dARI desc-form). Canonical 668f8429 ->
//! 08a6145 (patch468.py replay+idem; audity A0(sym,count-121a=41 drift
//! metadata)/A0b(2320 mnem==vendor)/A1(NONE->GRAFT 9376/STABLE 3232/
//! STRICTIFY 0/BAD 0)/A2(strict-set mapa-donora 9280)/A3(killsym 144)/
//! A4(+2320/noga exact)/A5/A7 fail-closed).
//! Witness: tests/bug468_data.inc (maszynowe gen468pins.py rc=2).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;
use std::collections::HashMap;
use std::sync::OnceLock;

include!("bug468_data.inc");

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

/// t468_1: heal-decode -- 9280 rekordow (2320 graft-celli x4 nogi)
/// dekoduje DOKLADNIE tekst vendora; pre-fix HOLE maszynowo potwierdzone
/// (gen: cold publish e7d4a91f + pre_tabs 668f8429 -> None na kazdym).
#[test]
fn t468_1_heal_decode() {
    for (w, leg, want) in HEAL468 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] heal {w:#034x}");
    }
}

/// t468_2: anchors -- sel0/NA-LTC64B kontrole: pre == post == vendor
/// (776 slow x4 nogi).
#[test]
fn t468_2_anchors() {
    for (w, leg, want) in ANCH468 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] anchor {w:#034x}");
    }
}

/// t468_3: kills b91=0 pod kazdym sel (12 sond x4): rc=1 vendor ->
/// engine decode HOLE (fail-closed parity).
#[test]
fn t468_3_kill_parity() {
    for (w, leg) in KILL468 {
        let got = dec(leg, *w);
        assert!(got.is_none(), "[{leg}] kill-claim {w:#034x} -> {got:?}");
    }
}

/// t468_4: edge glyphy pod sel: ra255 -> elizja bazy '[URm(+imm)]',
/// ur255 -> 'URZ' (24 sondy x4 -> tekst vendora).
#[test]
fn t468_4_edge_glyphs() {
    for (w, leg, want) in EDGE468 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] edge {w:#034x}");
    }
}

/// t468_5: mint-circle -- 212 form (53 teksty x4 nogi): asm ->
/// w slowie sel-bits rozne od 0 -> decode == tekst.
#[test]
fn t468_5_mint_circle() {
    for (text, leg) in MINT468 {
        let w = enc(leg, text).unwrap_or_else(|e| panic!("[{leg}] mint {text:?}: {e}"));
        assert_ne!(
            (w >> 73) & 3,
            0,
            "[{leg}] sel-bits dropped on mint {text:?}"
        );
        let back = dec(leg, w);
        assert_eq!(back.as_deref(), Some(*text), "[{leg}] mint circle {text:?}");
    }
}

/// t468_6: census + SOURCE pin == canonical graft 08a6145.
#[test]
fn t468_6_census_and_source() {
    for (leg, want) in CENSUS468 {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let got = raw["instructions"].as_object().unwrap().len();
        assert_eq!(got, *want, "[{leg}] key census post-468");
    }
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert_eq!(
        src["base_revision"].as_str().unwrap(),
        CANON468,
        "SOURCE.json base_revision == canonical graft 08a6145"
    );
}

/// t468_7: donor-parity transform -- kazdy klucz-graft ma poprawne sel
/// bity w and_base i dzieli vm/fields z DONOREM (semantyczny audit,
/// tylko raw JSON).
#[test]
fn t468_7_graft_vs_donor_transform() {
    let sel_nm = [(1u8, "LTC64B"), (2u8, "LTC128B"), (3u8, "LTC256B")];
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        let mut n = 0usize;
        for (k, rec) in ins {
            if rec.get("_src468") != Some(&serde_json::json!("bug468-2026-09-16")) {
                continue;
            }
            n += 1;
            let mg = rec["mod_groups"]
                .as_object()
                .unwrap()
                .values()
                .next()
                .unwrap();
            let ab = u128::from_str_radix(
                mg["and_base"].as_str().unwrap().trim_start_matches("0x"),
                16,
            )
            .unwrap();
            let sel = ((ab >> 73) & 3) as u8;
            let want_nm = sel_nm.iter().find(|(s, _)| *s == sel).unwrap().1;
            assert!(
                k.contains(&format!(".{want_nm}.256")),
                "[{leg}] {k}: sel/name mismatch"
            );
            // donor: LTC token zdjety; gdy brak (NA-side klucze LTC128B/256B
            // publicznie za pierwszym razem) donor = wariant LTC64B.
            let mut don = k.clone();
            for (_, nm) in &sel_nm {
                don = don.replace(&format!(".{nm}.256"), ".256");
            }
            if !ins.contains_key(&don) {
                don = k
                    .replace(".LTC128B.256", ".LTC64B.256")
                    .replace(".LTC256B.256", ".LTC64B.256");
            }
            let drec = ins
                .get(&don)
                .unwrap_or_else(|| panic!("[{leg}] donor {don} absent dla {k}"));
            let dmg = drec["mod_groups"]
                .as_object()
                .unwrap()
                .values()
                .next()
                .unwrap();
            let dab = u128::from_str_radix(
                dmg["and_base"].as_str().unwrap().trim_start_matches("0x"),
                16,
            )
            .unwrap();
            assert_eq!(
                ab & !(3u128 << 73),
                dab & !(3u128 << 73),
                "[{leg}] {k}: and_base poza sel != donor {don}"
            );
            assert_eq!(
                mg["variable_mask"], dmg["variable_mask"],
                "[{leg}] {k} vm != donor"
            );
            assert_eq!(mg["fields"], dmg["fields"], "[{leg}] {k} fields != donor");
        }
        assert_eq!(n, 2320, "[{leg}] graft census");
    }
}
