//! BUG-462 pins (F2-iter264, loop5/blind front2, 2026-09-13): donor-first
//! claim-narrowing -- claim_forbid {shift:24, bits:8, values:[255]} na
//! wszystkich ISTNIEJACYCH wierszach desc dARI ENL2.256 (48 mod-grup:
//! 15/15/7/11 na nogach; LDG/STG R_R{,_II,_P} + 121a ELL2.256). Vendor law:
//! nvdisasm 13.3.73 era-gated x4 AGREE EVERY -- base [24:32)==255 to rc=1
//! REFUSE on every narrowed row; the anchors legal (254; the sweep {0,28,127,253}
//! arb462e). Before: the engine printed 'desc[URx][RZ.64]'.
//! Keepers NOT claimed: KEEPER-RZ 1501 rows (among them the production ATOMG desc
//! RZ.64 from census452quick; pin t462_5) and ELL2.256 on 100a / 103a / 120 (the
//! vendor: plain '[Rx.U32+URy]', base=255 ACCEPT '[URy]'; the text-parity
//! divergence = candidate 466, pin t462_6 documents the posture). The sm103a RZ
//! mint on the encoder side already tripped BUG-077 (odd desc pair) -- the refuses
//! are looked for here as the result of ONE of the two fail-closed arms (t462_3).
//! Canonical 700524e -> f376558 (48 mg claim_forbid + 19 instr _src462;
//! patch462.py replay+idem byte-exact x4; audit semantyczny zero innego
//! diffu). Witness: tests/bug462_data.inc (maszynowe gen462pins.py).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug462_data.inc");

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

/// t462_1: refuse -- kazde ze 48 slow scope (base=255, era-gated) ma byc
/// HOLE (pin do pinna z vendor-rc=1 dowodami arb462b/462d).
#[test]
fn t462_1_enl2_ra255_hole() {
    for (w, leg) in REFUSE462 {
        let t = tab(leg);
        let idx = cached_index(t);
        assert_eq!(dec(t, idx, *w), None, "[{leg}] 462 claimed {w:#034x}");
    }
}

/// t462_2: kill-preserve -- slowa base=254 TYCH SAMYCH wierszy dekoduja
/// sie z 'R254' (adnotacja dziala wylacznie na v==255).
#[test]
fn t462_2_kill_preserve() {
    for (w, leg) in KEEP462 {
        let t = tab(leg);
        let idx = cached_index(t);
        let got = dec(t, idx, *w).unwrap_or_else(|| panic!("[{leg}] 254 killed {w:#034x}"));
        assert!(got.contains("R254"), "[{leg}] 254 drift: {got}");
    }
}

/// t462_3: mint-refuse -- teksty desc z baza RZ odmawiaja (arm 452
/// claim-forbid cytat albo arm 077 odd-pair; oba fail-closed).
#[test]
fn t462_3_mint_refuse() {
    for (leg, text) in MINTREF462 {
        let t = tab(leg);
        let e = enc(t, text).expect_err("mint must refuse");
        let ok = e.contains("claim-forbidden") || e.contains("ODD base");
        assert!(ok, "[{leg}] refuse msg: {e}");
    }
}

/// t462_4: census claim_forbid per noga [ride 461: 2026-09-14, canonical
/// f58ed16] -- po L2-UNCLAIM BUG-461 (zdjetych 3072 cf/noga z wierszy REDG
/// *_ARURI64_R; glif drukarski zamiast HOLE) sklad: L1 452=3 + legacy 099=3
/// + 462=15/15/7/11 = 21/21/13/17 (atrybucja danych, fail-closed na drift).
///   Trajektoria: 452=3075 -> 453=+3 -> 462=+15/15/7/11 -> 461=-3072/noga.
///   [ride 463: +12 cf/noga (LTC klucze); canonical a64b82b] = 33/33/25/29.
///   [RIDE469 (F2-iter285): graft 469 sm121a +17 cf (mg 0x981 CF_RA/CF_RA_PRED7
/// + EF-klucze); canonical bd48e63] = 33/33/25/46.
#[test]
fn t462_4_claim_census() {
    for (leg, want) in [
        ("sm100a", 6979usize), // 2026-11-06 T-11 (canonical 348535f): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-06 T-7 (canonical 135068e): +2 claim_forbid rows per table = the ATOMG .EL 64-bit-base rows (bit 76 excluded) -> 6978 / 6977 / 7016 // T-6 (canonical 2eed3ac): +2 claim_forbid rows per table = the measured ATOMG .EL rows (bit 63 / bit 76 excluded) -> 6976 / 6975 / 7014 // RIDE476 (F2-iter299, canonical c88778e): +1 cf/noga x3 (476b fantom _II forbid na STG.E.EL.ELL2.256.STRONG.GPU_ARURI_R_R_II)
        /* RIDE475r3 (F2-iter289, INC-289e, canonical 978c091): cf-dziedziczenie donorow 475 (+1136), R3 +3, R3b 121a +2 */
        ("sm103a", 6978usize), // 2026-11-06 T-11 (canonical 348535f): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-06 T-7 (canonical 135068e): +2 claim_forbid rows per table = the ATOMG .EL 64-bit-base rows (bit 76 excluded) -> 6978 / 6977 / 7016 // 
// T-6 (canonical 2eed3ac): +2 claim_forbid rows per table = the measured ATOMG .EL rows (bit 63 / bit 76 excluded) -> 6976 / 6975 / 7014 //
        ("sm120", 10837usize), // G batch 10 LDG.256 dARI 2026-11-07: the 782 dotted / harvest `_R_R_dARI` rows with the RZ-base claim_forbid retired, the 4 608 measured LDG_R_R_dARI[_II][_P] rows carry it (desc[UR][RZ.64] is illegal on nvdisasm 13.1) -> 7011 - 782 + 4608 = 10837 // // G batch 9 FSET / FSEL / FCHK 2026-11-07: the junk FCHK_P_R_UR row carried a claim_forbid on the opcode nibble [4:1]; the measured row pins the whole opcode -> claim_forbid rows 7012 -> 7011 // 2026-11-06 T-11 (canonical 348535f): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // (claim_forbid rows 7013 -> 7011: two retired BRA harvest rows carried the tag) // 2026-11-06 T-8 F2FP twins retired (canonical 09a7141): sm120 keys 16065 -> 16063, variants 26599 -> 26596, claim_forbid rows 7016 -> 7013 // 2026-11-06 T-7 (canonical 135068e): +2 claim_forbid rows per table = the ATOMG .EL 64-bit-base rows (bit 76 excluded) -> 6978 / 6977 / 7016 // T-6 (canonical 2eed3ac): +2 claim_forbid rows per table = the measured ATOMG .EL rows (bit 63 / bit 76 excluded) -> 6976 / 6975 / 7014 // RIDE458a2 (F2-iter309, canonical 952d336): cf +1 (graft mg F2FP_R_R_R PACK_AB.RZ, klon z 100a, cf verbatim)
        ("sm121a", 1244usize), // 2026-11-06 T-11 (canonical 348535f): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-04 (T-4): +1 cf (SM120 row adopted into SM121a in the text-parity pass) // RIDE469: +17 cf (graft 469); canonical bd48e63 + // RIDE458a2 (F2-iter309, canonical 952d336): cf +1 (graft mg F2FP_R_R_R PACK_AB.RZ, klon z 100a, cf verbatim) (121a)
    ] {
        let raw = cubit::table::read_table_text(format!("tables/{leg}.json")).unwrap();
        let n = raw.matches("\"claim_forbid\"").count();
        assert_eq!(n, want, "[{leg}] claim_forbid census");
    }
}
