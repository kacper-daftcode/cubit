//! BUG-461 pins (F2-iter265, loop5/blind front2, 2026-09-14): text-parity
//! glyph '???255.64' for L2 REDG *_ARURI64_R instead of HOLE (452 deliberately
//! chose HOLE parity; the registry 452_claim_narrow_donor_first_103a.md sec. 5).
//! Vendor law (arb452 g3 + triage461 fresh nvdisasm 13.3.73 era-gated x4
//! AGREE EVERY / DIVERGENT=0): base[24:32) == 255 -> rc=0, the glyph
//! '[???255.64+UR..(+off)]'; 0..254 -> 'R{n}.64' (kill-preserve); the U32 form
//! (b90=0) 255 -> 'RZ.U32' KEEPER (the 451 law, untouched).
//! Fix: the data-side L2 UNCLAIM (canonical f376558 -> f58ed16, patch461.py
//! replayable + idempotent, 12,288 annotations lifted from 3072 keys x4; L1
//! EFL2.256 desc + 462 ENL2 / ELL2 + the legacy 099 STAY) + the printer arm
//! (format_plain_u32_ur glyph255=true only on the REDG.E ARURI64 branch) + the
//! encoder's mint-side refuse (the BUG-461 citation; the BUG-452 policy continued:
//!   a '.64' text with base R255 / RZ does not mint; the U32 fallback is not allowed).
//!   Witness: tests/bug461_data.inc (machine-built by gen461pins.py rc=2).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug461_data.inc");

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
/// Session T-20 (2026-11-08): the REDG uniform-indexed forms are measured on sm120 (G, batch 14), sm103a and sm100a
/// (tools/probes/re_sm120_redg.py --arch SM103 / SM100); a measured row fails closed on its text-inert bits ([23:16],
/// 76, 82, 83, [95:92] on REDG 0x98e with bit 91) -- the 2026-09 fuzz words of this file that carry such bits have no
/// decode on those legs (the glyph law itself is pinned by the words without them).
/// sm121a since T-21 batch 5 (2026-11-08): `re_sm120_redg.py --arch SM121` (and the LDG.256 / STG.256 probes), `tests/sm121a_redg_aruri.rs`.
fn redg_measured(leg: &str) -> bool {
    matches!(leg, "sm120" | "sm103a" | "sm100a" | "sm121a")
}
fn redg_inert_bits_set(w: u128) -> bool {
    const INERT: u128 = (0xffu128 << 16) | (1u128 << 76) | (1u128 << 82) | (1u128 << 83) | (0xfu128 << 92);
    (w & 0xfff) == 0x98e && (w >> 91) & 1 == 1 && (w & INERT) != 0
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

/// t461_1: glif-decode -- 13 slow base=255 ARURI64 (klatki x4 + 5 fuzz
/// STAND454) dekoduje DOKLADNIE tekst vendora '???255.64' (pre-fix: HOLE;
/// werdykt glifu z nvdisasm, nie z hot-silnika -- gen461pins rc=2).
#[test]
fn t461_1_glyph_decode() {
    let mut glyphs = 0;
    for (w, leg, want) in GLYPH461 {
        let t = tab(leg);
        let idx = cached_index(t);
        let got = dec(t, idx, *w);
        assert!(want.contains("???255.64"), "glyph shape: {want}");
        if redg_measured(leg) && redg_inert_bits_set(*w) {
            assert!(got.is_none(), "[{leg}] {w:#034x}: a text-inert bit set -- the measured rows fail closed (T-20): {got:?}");
            continue;
        }
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] glyph {w:#034x}");
        glyphs += 1;
    }
    assert!(glyphs >= 8, "{glyphs} glyph words still pin the ???255.64 print on the measured legs");
}

/// t461_2: kill-preserve -- bazay {0,28,127,253,254} na 2 klatkach x4 nogi
/// dekoduja dokladnie jak przed fixem (teksty z cold publish 79aebc2b).
#[test]
fn t461_2_kill_preserve() {
    for (w, leg, want) in KEEP461_PREPOST {
        let t = tab(leg);
        let idx = cached_index(t);
        let got = dec(t, idx, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] kill drift {w:#034x}");
    }
}

/// t461_3: mint-refuse -- teksty '.64' z baza R255/RZ odmawiaja z cytatem
/// BUG-461 na wszystkich nogach (mint-side kontynuacja polisy BUG-452).
#[test]
fn t461_3_mint_refuse() {
    for (leg, text) in MINTREF461 {
        let t = tab(leg);
        let e = enc(t, text).expect_err("mint must refuse");
        assert!(e.contains("BUG-461"), "[{leg}] cite: {e}");
    }
}

/// t461_4: data-attribution -- claim_forbid census per noga PO zdjeciu L2
/// (21/21/13/17; L1 3/noga + 462 + legacy 099 stoja), zero cf na ARURI64,
/// markery _src461 na wszystkich 3072 kluczach/noga.
#[test]
fn t461_4_census_attribution() {
    // ride 463: +12 cf/noga (LTC klucze); canonical a64b82b = 33/33/25/29.
    // RIDE469 (F2-iter285): graft 469 sm121a +17 cf (9 mg R/R_P/P_R/P_R_P z
    // CF_RA + 4 klucze EF-band z cf + 4 LTC-mg G2/G4 z CF_RA); canonical bd48e63
    // = 33/33/25/46.
    let want = [
        ("sm100a", 10978u32), // T-20 2026-11-08 batch 4 (canonical f254702): sm103a / sm100a LDG.256 (3 forms) + STG.256 measured on -b SM103 / SM100, 8 946 dotted keys per table retired as aliases: sm103a forms 8784 -> 650, variants 25517 -> 32916, claim_forbid 6978 -> 10977; sm100a 8783 -> 649, 25511 -> 32910, 6979 -> 10978; num_keys with the alias clones 14928 -> 14944 / 14927 -> 14943 // 2026-11-06 T-11 (canonical f254702): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-06 T-7 (canonical 582dfd8): +2 claim_forbid rows per table = the ATOMG .EL 64-bit-base rows (bit 76 excluded) -> 6978 / 6977 / 7016 // T-6 (canonical 2eed3ac): +2 claim_forbid rows per table = the measured ATOMG .EL rows (bit 63 / bit 76 excluded) -> 6976 / 6975 / 7014 // RIDE476 (F2-iter299, canonical c88778e): +1 cf/noga x3 (476b fantom _II forbid; _src474 key) // RIDE475r3 (F2-iter289, INC-289e, canonical 978c091)
        ("sm103a", 10977), // T-20 2026-11-08 batch 4 (canonical f254702): sm103a / sm100a LDG.256 (3 forms) + STG.256 measured on -b SM103 / SM100, 8 946 dotted keys per table retired as aliases: sm103a forms 8784 -> 650, variants 25517 -> 32916, claim_forbid 6978 -> 10977; sm100a 8783 -> 649, 25511 -> 32910, 6979 -> 10978; num_keys with the alias clones 14928 -> 14944 / 14927 -> 14943 // 2026-11-06 T-11 (canonical f254702): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-06 T-7: see above
// T-6 (canonical 2eed3ac): +2 claim_forbid rows per table = the measured ATOMG .EL rows (bit 63 / bit 76 excluded) -> 6976 / 6975 / 7014 //
        ("sm120", 10990), // G batch 13 STG.256 2026-11-07: the 576 measured STG_dARI_R_R[_II] rows carry the RZ-base claim_forbid, the 384 retired dotted dARI rows had it, 7 other retired rows had one -> 11013 // G batch 12 LDG.256 ARURI 2026-11-07: 5 retired dotted `_R_R_ARURI` rows carried a claim_forbid -> 10828 // G batch 11 LDG.256 ARURI64 2026-11-07: 4 retired dotted `_R_R_ARURI64` rows carried a claim_forbid -> 10833 // // G batch 10 LDG.256 dARI 2026-11-07: the 782 dotted / harvest `_R_R_dARI` rows with the RZ-base claim_forbid retired, the 4 608 measured LDG_R_R_dARI[_II][_P] rows carry it (desc[UR][RZ.64] is illegal on nvdisasm 13.1) -> 7011 - 782 + 4608 = 10837 // // G batch 9 FSET / FSEL / FCHK 2026-11-07: the junk FCHK_P_R_UR row carried a claim_forbid on the opcode nibble [4:1]; the measured row pins the whole opcode -> claim_forbid rows 7012 -> 7011 // 2026-11-06 T-11 (canonical f254702): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // (claim_forbid rows 7013 -> 7011: two retired BRA harvest rows carried the tag) // 2026-11-06 T-8 F2FP twins retired (canonical 09a7141): sm120 keys 16065 -> 16063, variants 26599 -> 26596, claim_forbid rows 7016 -> 7013 // 2026-11-06 T-7 (canonical 582dfd8): +2 claim_forbid rows = the ATOMG .EL 64-bit-base rows // T-6 (canonical 2eed3ac): +2 claim_forbid rows per table = the measured ATOMG .EL rows (bit 63 / bit 76 excluded) -> 6976 / 6975 / 7014 // RIDE458a2 (F2-iter309, canonical 952d336): cf +1 (graft mg F2FP_R_R_R PACK_AB.RZ, klon z 100a, cf verbatim) // G run 5 batch 16 (T-17): 12 claim_forbid-bearing rows gone -- the 6 retired F2FP / ATOMG twin keys (aliases) and the 6 dead F2FP_R_R_R_R junk groups, 0 census witnesses -> 11001 // 2026-11-08 T-18 b2: 32 whole-key twins retired as aliases; 2 of them carried a claim_forbid -> 11001 -> 10999 // 2026-11-08 T-19: the long tail closed -- 9 claim_forbid-bearing rows gone (the 4 duplicate F2FP_R_R_R_R spellings and the 5 F2FP `*PACK_AB_P_R_R_R` phantom-predicate keys, 0 census witnesses) -> 10999 -> 10990
        ("sm121a", 5253), // T-21 2026-11-08 (canonical f254702): sm121a LDG.256 x 3 forms + STG.256 + REDG ARURI / ARURI64 measured on -b SM121 (G's batch 10-14 probes with --arch SM121 --witnesses; 167 GB10 corpus words moved to the plain keys, texts unchanged) -- 14 286 dotted harvest keys retired as aliases: sm121a forms 23754 -> 9488 (loader-visible 23752 -> 9486), variants 26595 -> 37077, claim_forbid 1244 -> 5253 (the 4 608 measured LDG_R_R_dARI rows + 576 STG_dARI rows carry the RZ-base claim_forbid; the 781 + 193 retired dotted dARI keys had it), num_keys with the alias clones 23872 -> 23892 // 2026-11-06 T-11 (canonical f254702): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // RIDE458a2 (F2-iter309, canonical 952d336): cf +1 (graft mg F2FP_R_R_R PACK_AB.RZ, klon z 100a, cf verbatim) (121a)
    ];
    for (leg, want_cf) in want {
        let v: serde_json::Value =
            serde_json::from_str(&cubit::table::read_table_text(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = v["instructions"].as_object().unwrap();
        let mut n_cf = 0u32;
        let mut n_a64 = 0u32;
        let mut n_a64cf = 0u32;
        let mut n_src461 = 0u32;
        for (k, rec) in ins {
            // pseudo-rekordy _errata_* (reserved top-level annotations) nie
            // nosza mod_groups -- pomijane, jak w gen461pins.
            let mgs = match rec["mod_groups"].as_object() {
                Some(m) => m,
                None => continue,
            };
            for (_, g) in mgs {
                if g.get("claim_forbid").is_some() {
                    n_cf += 1;
                }
            }
            // 2026-11-06 (T-7): the two measured ATOMG `.EL` 64-bit-base keys also end in `_ARURI64_R`
            // (`ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R`, provenance atomg-el-aruri64-2026-11-06)
            // and carry a claim_forbid on bit 76 (the descriptor form) by measurement; this census is
            // the REDG family's (BUG-461: no data-side claim_forbid on the 3072 REDG rows).
            if k.starts_with("REDG") && k.ends_with("_ARURI64_R") {
                n_a64 += 1;
                if rec["_src461"] == "bug461-2026-09-14" {
                    n_src461 += 1;
                }
                for (_, g) in mgs {
                    if g.get("claim_forbid").is_some() {
                        n_a64cf += 1;
                    }
                }
            }
        }
        // 2026-11-07 (session G, batch 14, tools/probes/re_sm120_redg.py): on sm120 the 3 072 dotted
        // `REDG.E.<op>[.cache][.type].<scope>_ARURI64_R` keys are `_meta.key_aliases` of the one measured plain key
        // `REDG_ARURI64_R` (3 072 groups, no claim_forbid -- the `???255` glyph stays a print matter, BUG-461's
        // doctrine; the `_src461` marker was the dotted keys'). The other legs are untouched.
        // T-20 (2026-11-08): the same on sm103a / sm100a (`--arch SM103` / `SM100`).
        if redg_measured(leg) {
            assert_eq!((n_cf, n_a64, n_a64cf, n_src461), (want_cf, 1, 0, 0), "[{leg}] census drift (G batch 14 / T-20)");
            let plain = &ins["REDG_ARURI64_R"];
            assert_eq!(plain["_src"], "redg-aruri-family-2026-11-07", "[{leg}] the measured plain key");
            assert_eq!(plain["mod_groups"].as_object().unwrap().len(), 3072, "[{leg}] the .E half of the lattice");
            let aliases = v["_meta"]["key_aliases"].as_object().unwrap();
            let n_alias = aliases.iter().filter(|(k, t)| k.starts_with("REDG.") && k.ends_with("_ARURI64_R") && t.as_str() == Some("REDG_ARURI64_R")).count();
            assert_eq!(n_alias, 3072, "[{leg}] the dotted .64 keys alias the plain key");
            continue;
        }
        assert_eq!(
            (n_cf, n_a64, n_a64cf, n_src461),
            (want_cf, 3072, 0, 3072),
            "[{leg}] census drift"
        );
    }
}

/// t461_5: U32 keeper -- REDG plain U32-form base=255 dekoduje 'RZ.U32'
/// (451-law; arm glifu NIE dotyka b90=0 po stronie decode ani mint).
#[test]
fn t461_5_u32_keeper() {
    for (w, leg, want) in U32KEEP461 {
        let t = tab(leg);
        let idx = cached_index(t);
        let got = dec(t, idx, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] U32 drift {w:#034x}");
        assert!(want.contains("RZ.U32"), "expected RZ.U32 glyph: {want}");
    }
}
