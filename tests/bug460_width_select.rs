//! BUG-460 pins (F2-iter262, loop5/blind front2, 2026-09-13): the encoder's
//! ARURI64 width select. The text '... [Rn.64+URm(+off)]' was typed suffix-blind as
//! _ARURI_R (operand_type_label drops the suffix) and minted the U32-shape word
//! (b90 = 0) on ALL 4 legs -- with a silent render drift in the round trip .64 ->
//! .U32 (triage460: 20/20 vs the publish cubit_py-9594899e; the WRONG-FORM class =
//! the loss of the address-width information in the bytes). In addition
//! '[RZ.64+URx]' minted around the BUG-452 claim_forbid (the guard sits on the
//! ARURI64 rows -- the L2 encode side reaches its full range only after this fix).
//! Fix (encoder, ~1 arm, canonical STANDS at e03e034): when the Addr has base + UR
//! and the suffix == "64", the *_ARURI64_* candidates go FIRST, before the
//! suffix-blind chain; the fit fails closed as before (entry_matches_operands);
//! families without ARURI64 rows (all but REDG; census: _ARURI64* only REDG, 3072 per
//! leg x4) keep the ARURI path unchanged. Vendor law for b90 (arb454 x4 AGREE): '.64'
//! iff b90 = 1. Vendor-proven pins: every MINT64 cell gated with nvdisasm 13.3.73
//! -b SM103a (donor-verbatim x4, patch454 A2) at GENERATION time (gen460pins.py,
//! rc=2 fail-closed, zero hand hex). Witness: tests/bug460_data.inc.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug460_data.inc");

// Immutable fixtures only: every word still runs through decode/encode.
fn pool() -> &'static std::collections::HashMap<&'static str, (IsaTable, DecodeIndex)> {
    static POOL: std::sync::OnceLock<std::collections::HashMap<&'static str, (IsaTable, DecodeIndex)>> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        ["sm100a", "sm103a", "sm120", "sm121a"].into_iter().map(|arch| {
            let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
            let index = DecodeIndex::build(&table);
            (arch, (table, index))
        }).collect()
    })
}
fn tab(arch: &str) -> &'static IsaTable {
    &pool().get(arch).unwrap().0
}
fn cached_index(table: &IsaTable) -> &'static DecodeIndex {
    pool().values().find(|(fixture, _)| std::ptr::eq(fixture, table))
        .map(|(_, index)| index).expect("table must come from the immutable fixture pool")
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
        let i = idxs.entry(*leg).or_insert_with(|| cached_index(t));
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
        let i = idxs.entry(*leg).or_insert_with(|| cached_index(t));
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
        let i = idxs.entry(*leg).or_insert_with(|| cached_index(t));
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
