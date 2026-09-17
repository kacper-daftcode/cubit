//! BUG-460 pins (F2-iter262, loop5/blind front2, 2026-09-13): encoder
//! width-select ARURI64. Tekst '... [Rn.64+URm(+off)]' typowal sie
//! suffix-blindo jako _ARURI_R (operand_type_label gubi suffix) i mincil
//! slowo U32-shape (b90=0) na WSZYSTKICH 4 nogach -- z cichym render-driftem
//! roundtrip .64 -> .U32 (triage460: 20/20 vs publish cubit_py-9594899e;
//! klasa WRONG-FORM = strata informacji o szerokosci adresu w bajtach).
//! Dodatkowo '[RZ.64+URx]' mintowal omijajac claim_forbid BUG-452 (guard
//! siedzi na wierszach ARURI64 -- L2 encode-side pelny zasieg dopiero po
//! tym fixie). Fix (encoder, ~1 arm, canonical STOI e03e034): gdy Addr ma
//! base+UR i suffix=="64", kandydaci *_ARURI64_* ida NAJWYZSZYM
//! priorytetem przed suffix-blindo lancuchem; fit fail-closed jak dotad
//! (entry_matches_operands); rodziny bez wierszy ARURI64 (wszystkie poza
//! REDG, census: _ARURI64* tylko REDG 3072/noga x4) zachowuja sciezke
//! ARURI bez zmian. Vendor law b90 (arb454 x4 AGREE): '.64' iff b90=1.
//! Piny vendor-proven: kazda celka MINT64 zgate'owana nvdisasm 13.3.73
//! -b SM103a (donor-verbatim x4, patch454 A2) przy GENERACJI (gen460pins.py,
//! rc=2 fail-closed, zero recznego hex). Witness: tests/bug460_data.inc.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug460_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let full = format!(" {text} ;");
    let parsed = parse_sass(&full, 0).map_err(|e| e.to_string())?;
    encode_instruction(&parsed, t).map_err(|e| e.to_string())
}
fn w(s: &str) -> u128 {
    u128::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()
}

/// t460_1: MINT64 -- '.64' text mincuje DOKLADNIE udowodnione slowo
/// ARURI64 (vendor-oracle gen + rt), b90=1; roundtrip zachowuje '.64+UR'.
#[test]
fn t460_1_mint_aruri64_oracle_words() {
    let mut tabs = std::collections::HashMap::new();
    let mut idxs = std::collections::HashMap::new();
    for (word, text, leg) in T460_MINT64 {
        let t = tabs.entry(*leg).or_insert_with(|| tab(leg));
        let i = idxs.entry(*leg).or_insert_with(|| DecodeIndex::build(t));
        let got = enc(t, text.trim_end_matches(';').trim())
            .unwrap_or_else(|e| panic!("t460_1 refuse {leg} {text}: {e}"));
        assert_eq!(got, w(word), "t460_1 word {leg} {text}");
        assert_eq!((got >> 90) & 1, 1, "t460_1 b90 {leg} {text}");
        let rt = dec(t, i, got).expect("t460_1 rt None");
        assert!(
            rt.contains(".64+UR"),
            "t460_1 rt drift {leg} {text} -> {rt}"
        );
        // atrybucja: cold-mint (pre-fix) mintowal slowo z b90=0
        // (komentarz cold= w data.inc; sprawdzenie roznicy dokladnie 1 bit)
    }
}

/// t460_2: KEEP32 -- '.U32' text mincuje jak PRZED fixem (ARURI_R, b90=0);
/// byte-parity z publish 452 (slowo zabite w data.inc).
#[test]
fn t460_2_keep32_byteparity() {
    let mut tabs = std::collections::HashMap::new();
    for (word, text, leg) in T460_KEEP32 {
        let t = tabs.entry(*leg).or_insert_with(|| tab(leg));
        let got = enc(t, text.trim_end_matches(';').trim())
            .unwrap_or_else(|e| panic!("t460_2 refuse {leg} {text}: {e}"));
        assert_eq!(got, w(word), "t460_2 word {leg} {text}");
        assert_eq!((got >> 90) & 1, 0, "t460_2 b90 {leg} {text}");
    }
}

/// t460_3: PLAIN -- adres bez suffixu '[Rn+URm]' mincuje bez zmian.
#[test]
fn t460_3_plain_suffixless_unchanged() {
    let mut tabs = std::collections::HashMap::new();
    for (word, text, leg) in T460_PLAIN {
        let t = tabs.entry(*leg).or_insert_with(|| tab(leg));
        let got = enc(t, text.trim_end_matches(';').trim())
            .unwrap_or_else(|e| panic!("t460_3 refuse {leg} {text}: {e}"));
        assert_eq!(got, w(word), "t460_3 word {leg} {text}");
    }
}

/// t460_4: RZ64 -- '[RZ.64+URx]' po fixie jest RZECZYWISCIE odgrodzone
/// BUG-452 (pelny encode-side zasieg guarda): refuse z cytatem; cold mintowal
/// cicho (dowod w data.inc).
#[test]
fn t460_4_rz64_refuse_claim_forbidden() {
    let mut tabs = std::collections::HashMap::new();
    for (text, leg, _coldword) in T460_RZ64 {
        let t = tabs.entry(*leg).or_insert_with(|| tab(leg));
        match enc(t, text.trim_end_matches(';').trim()) {
            Ok(got) => panic!("t460_4 minted {leg} {text} -> {got:#034x}"),
            Err(e) => {
                assert!(e.contains("claim-forbidden"), "t460_4 err shape {leg}: {e}");
                assert!(e.contains("BUG-452"), "t460_4 cite {leg}: {e}");
            }
        }
    }
}

/// t460_5: RZ32 keeper (BUG-451-law): '[RZ.U32+URx]' dalej mincuje +
/// drukuje 'RZ.U32' (U32-forma legalna, nietknieta).
#[test]
fn t460_5_rz32_keeper() {
    let mut tabs = std::collections::HashMap::new();
    let mut idxs = std::collections::HashMap::new();
    for (word, text, leg) in T460_RZ32 {
        let t = tabs.entry(*leg).or_insert_with(|| tab(leg));
        let i = idxs.entry(*leg).or_insert_with(|| DecodeIndex::build(t));
        let got = enc(t, text.trim_end_matches(';').trim())
            .unwrap_or_else(|e| panic!("t460_5 refuse {leg} {text}: {e}"));
        assert_eq!(got, w(word), "t460_5 word {leg} {text}");
        let rt = dec(t, i, got).expect("t460_5 rt None");
        assert!(rt.contains("RZ.U32"), "t460_5 rt {leg}: {rt}");
    }
}

/// t460_6: ERA454 -- fallback spietrzenia 454 (era desc+PT text) mincuje
/// dokladnie slowo era (b90=0, suffix-None splaszczenie nietkniete arm 460).
#[test]
fn t460_6_era454_fallback_unchanged() {
    let mut tabs = std::collections::HashMap::new();
    for (word, text, leg) in T460_ERA {
        let t = tabs.entry(*leg).or_insert_with(|| tab(leg));
        let got = enc(t, text.trim_end_matches(';').trim())
            .unwrap_or_else(|e| panic!("t460_6 refuse {leg} {text}: {e}"));
        assert_eq!(got, w(word), "t460_6 word {leg} {text}");
        assert_eq!((got >> 90) & 1, 0, "t460_6 b90 {leg} {text}");
    }
}

/// t460_7: SWEEPKE -- rozstaw 16 (leg,key) z przestrzeni 12,288 kluczy:
/// mincja z tekstu wynikajacego z base_op wiersza == slowo domkniace
/// roundtrip z '.64+UR' (kompletnosc trasowania na calej rodzinie; pelna
/// 12,288-slotowa walidacja = sweep460 w TAILU).
#[test]
fn t460_7_sweepkeys_route_completeness() {
    let mut tabs = std::collections::HashMap::new();
    let mut idxs = std::collections::HashMap::new();
    for (leg, key) in T460_SWEEPKEYS {
        let t = tabs.entry(*leg).or_insert_with(|| tab(leg));
        let i = idxs.entry(*leg).or_insert_with(|| DecodeIndex::build(t));
        let base_op = row_base_op(key);
        for (b, u, imm, v) in [(3, 5, 0, 9), (255u32, 0u32, 0u32, 0u32)] {
            if b == 255 {
                // claim_forbid BUG-452 (RZ.64) -- refuse oczekiwany
                let tx = format!("{base_op} [RZ.64+UR{u}], R{v}");
                assert!(enc(t, &tx).is_err(), "t460_7 RZ64 minted {leg} {key}");
                continue;
            }
            let tx = format!(
                "{base_op} [R{b}.64+UR{u}{}], R{v}",
                if imm != 0 {
                    format!("+0x{imm:x}")
                } else {
                    String::new()
                }
            );
            let got = enc(t, &tx).unwrap_or_else(|e| panic!("t460_7 refuse {leg} {key} {tx}: {e}"));
            assert_eq!((got >> 90) & 1, 1, "t460_7 b90 {leg} {key}");
            let rt = dec(t, i, got).expect("t460_7 rt None");
            assert!(rt.contains(".64+UR"), "t460_7 rt drift {leg} {key} -> {rt}");
        }
    }
}

fn row_base_op(key: &str) -> String {
    // base_op = key bez koncowego '_ARURI64_R'
    key.trim_end_matches("_ARURI64_R").to_string()
}
