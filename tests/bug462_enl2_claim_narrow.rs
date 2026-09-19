//! BUG-462 pins (F2-iter264, loop5/blind front2, 2026-09-13): donor-first
//! claim-narrowing -- claim_forbid {shift:24, bits:8, values:[255]} na
//! wszystkich ISTNIEJACYCH wierszach desc dARI ENL2.256 (48 mod-grup:
//! 15/15/7/11 na nogach; LDG/STG R_R{,_II,_P} + 121a ELL2.256). Vendor law:
//! nvdisasm 13.3.73 era-gated x4 AGREE EVERY -- base [24:32)==255 to rc=1
//! REFUSE na kazdym zawezanym wierszu; anchory legalne (254; sweep
//! {0,28,127,253} arb462e). Pre: engine drukowal 'desc[URx][RZ.64]'.
//! Keeper NIE claimowane: KEEPER-RZ 1501 wierszy (m.in. produkcyjny ATOMG
//! desc RZ.64 z census452quick; pin t462_5) i ELL2.256 na 100a/103a/120
//! (vendor: plain '[Rx.U32+URy]', base=255 ACCEPT '[URy]'; divergence
//! text-parity = 466-kand, pin t462_6 dokumentuje postawe). sm103a RZ-mint
//! po stronie enkodera odpalal juz BUG-077 (odd desc pair) -- refuse'ow
//! szuka sie tu w wyniku JEDNEGO z dwoch fail-closed armow (t462_3).
//! Canonical 700524e -> f376558 (48 mg claim_forbid + 19 instr _src462;
//! patch462.py replay+idem byte-exact x4; audit semantyczny zero innego
//! diffu). Witness: tests/bug462_data.inc (maszynowe gen462pins.py).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug462_data.inc");

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

/// t462_1: refuse -- kazde ze 48 slow scope (base=255, era-gated) ma byc
/// HOLE (pin do pinna z vendor-rc=1 dowodami arb462b/462d).
#[test]
fn t462_1_enl2_ra255_hole() {
    for (w, leg) in REFUSE462 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        assert_eq!(dec(&t, &idx, *w), None, "[{leg}] 462 claimed {w:#034x}");
    }
}

/// t462_2: kill-preserve -- slowa base=254 TYCH SAMYCH wierszy dekoduja
/// sie z 'R254' (adnotacja dziala wylacznie na v==255).
#[test]
fn t462_2_kill_preserve() {
    for (w, leg) in KEEP462 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] 254 killed {w:#034x}"));
        assert!(got.contains("R254"), "[{leg}] 254 drift: {got}");
    }
}

/// t462_3: mint-refuse -- teksty desc z baza RZ odmawiaja (arm 452
/// claim-forbid cytat albo arm 077 odd-pair; oba fail-closed).
#[test]
fn t462_3_mint_refuse() {
    for (leg, text) in MINTREF462 {
        let t = tab(leg);
        let e = enc(&t, text).expect_err("mint must refuse");
        let ok = e.contains("claim-forbidden") || e.contains("ODD base");
        assert!(ok, "[{leg}] refuse msg: {e}");
    }
}

/// t462_4: census claim_forbid per noga [ride 461: 2026-09-14, canonical
/// f58ed16] -- po L2-UNCLAIM BUG-461 (zdjetych 3072 cf/noga z wierszy REDG
/// *_ARURI64_R; glif drukarski zamiast HOLE) sklad: L1 452=3 + legacy 099=3
/// + 462=15/15/7/11 = 21/21/13/17 (atrybucja danych, fail-closed na drift).
/// Trajektoria: 452=3075 -> 453=+3 -> 462=+15/15/7/11 -> 461=-3072/noga.
/// [ride 463: +12 cf/noga (LTC klucze); canonical a64b82b] = 33/33/25/29.
/// [RIDE469 (F2-iter285): graft 469 sm121a +17 cf (mg 0x981 CF_RA/CF_RA_PRED7
/// + EF-klucze); canonical bd48e63] = 33/33/25/46.
#[test]
fn t462_4_claim_census() {
    for (leg, want) in [
        ("sm100a", 1170usize), // RIDE476 (F2-iter299, canonical c88778e): +1 cf/noga x3 (476b fantom _II forbid na STG.E.EL.ELL2.256.STRONG.GPU_ARURI_R_R_II)
        /* RIDE475r3 (F2-iter289, INC-289e, canonical 978c091): cf-dziedziczenie donorow 475 (+1136), R3 +3, R3b 121a +2 */
        ("sm103a", 1170usize),
        ("sm120", 1168usize), // RIDE458a2 (F2-iter309, canonical 952d336): cf +1 (graft mg F2FP_R_R_R PACK_AB.RZ, klon z 100a, cf verbatim)
        ("sm121a", 1184usize), // RIDE469: +17 cf (graft 469); canonical bd48e63 + // RIDE458a2 (F2-iter309, canonical 952d336): cf +1 (graft mg F2FP_R_R_R PACK_AB.RZ, klon z 100a, cf verbatim) (121a)
    ] {
        let raw = std::fs::read_to_string(format!("tables/{leg}.json")).unwrap();
        let n = raw.matches("\"claim_forbid\"").count();
        assert_eq!(n, want, "[{leg}] claim_forbid census");
    }
}
