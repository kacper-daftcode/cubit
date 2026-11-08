//! BUG-463 pins (F2-iter266, loop5/blind front2, 2026-09-14): nNA EFL2.256
//! dARI frame donor-symmetric holes -- (a) vendor-noop band vm-relax
//! (STG {72,73,74,87,92..95}; LDG {92..95}), (b) LTC-width selektor [74:73]
//! the keys LTC64B / 128B / 256B absent x4 (ab |= selbits, the form = NA LTC64B
//! delta {73}; the BUG-452 claim_forbid verbatim; count=None).
//! Vendor law (arb463 44 + arb463b 12 + arb463c 5 probes nvdisasm 13.3.73
//! raw -b x4 AGREE EVERY / DIVERGENT=0): the band a no-op under pole4 / pol00 / polff /
//! @P0/rich; pol sweep {00,01,64,7f,ff} (0xff elided, trailer PRZED
//! pred-out); kills b91 + ra255 (452) rc=1 x4 obu selektorow; URZ/RZ glyph
//! legalne; era-b118/reuse-b122 legalne; imm17 signed '+-'. Canonical
//! f58ed16 -> a64b82b (patch463.py replayable+idempotent, audity A0-A7
//! fail-closed; A1 NONE->GRAFT 3752 / STABLE 252 / BAD 0).
//! Witness: tests/bug463_data.inc (maszynowe gen463pins.py rc=2).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug463_data.inc");

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

/// t463_1: heal-decode -- 200 slow band/LTC (50 tagow x4 nogi) dekoduje
/// DOKLADNIE tekst vendora (nvdisasm); pre-fix HOLE maszynowo potwierdzone
/// (gen, cold publish eace8461 + f58ed16).
#[test]
fn t463_1_heal_decode() {
    for (w, leg, want) in HEAL463 {
        let t = tab(leg);
        let idx = cached_index(t);
        let got = dec(t, idx, *w);
        // 2026-11-07 (session G, batch 10, tools/probes/re_sm120_ldg256.py): the sm120 descriptor-form rows are
        // measured (`LDG_R_R_dARI[_II][_P]`) and fail closed on the text-inert bits 83 / 92-95 (T-10's convention
        // for measured rows); the band words of this grid carry one of them. The other legs are untouched.
        if *leg == "sm120" && (*w & 0xfff) == 0x97e && (*w & ((1u128 << 83) | (0xfu128 << 92))) != 0 {
            assert_eq!(got, None, "[{leg}] heal {w:#034x}: inert bits fail closed (G batch 10)");
            continue;
        }
        // Batch 13 (tools/probes/re_sm120_stg256.py): the 256-bit store's measured rows fail closed on [74:72] / 83 / 87 /
        // [95:92] (the store has no LTC width: [74:72] are text-inert there, the band words of this grid set them).
        if *leg == "sm120" && (*w & 0xfff) == 0x97f && (*w & ((7u128 << 72) | (1u128 << 83) | (1u128 << 87) | (0xfu128 << 92))) != 0 {
            assert_eq!(got, None, "[{leg}] heal {w:#034x}: inert bits fail closed (G batch 13)");
            continue;
        }
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] heal {w:#034x}");
    }
}

/// t463_2: anchors -- 16 komorek (S.base/S.pol00.base/L.base/L.flip72 x4)
/// pre == post == vendor (L.flip72 = pol-bit7 keeper, NIE noop).
#[test]
fn t463_2_anchors() {
    for (w, leg, want) in ANCH463 {
        let t = tab(leg);
        let idx = cached_index(t);
        let got = dec(t, idx, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] anchor {w:#034x}");
    }
}

/// t463_3: kill-preserve -- b91 + ra255 (452) pod LTC64B/LTC128B dekoduje
/// HOLE x4 nogi (claim_forbid przeniesiony verbatim na nowe klucze).
#[test]
fn t463_3_kill_preserve() {
    for (w, leg) in KILL463 {
        let t = tab(leg);
        let idx = cached_index(t);
        assert_eq!(dec(t, idx, *w), None, "[{leg}] kill-claim {w:#034x}");
    }
}

/// t463_4: mint-circle -- 48 probek (12 form x4 nogi): encode textu
/// mintuje selektor b[74:73] poprawnie i decode(enc(txt)) == txt.
#[test]
fn t463_4_mint_circle() {
    for (leg, text) in MINTCIR463 {
        let t = tab(leg);
        let w = enc(t, text).unwrap_or_else(|e| panic!("[{leg}] mint {text}: {e}"));
        let sel = ((w >> 73) & 3) as u8;
        let want: u8 = if text.contains("LTC64B") {
            1
        } else if text.contains("LTC128B") {
            2
        } else if text.contains("LTC256B") {
            3
        } else {
            0
        };
        assert_eq!(sel, want, "[{leg}] selector {text} -> {sel}");
        let idx = cached_index(t);
        let got = dec(t, idx, w);
        assert_eq!(got.as_deref(), Some(*text), "[{leg}] circle {text}");
    }
}

/// t463_5: mint-refuse -- ra=255/RZ pod kazdym selektorem LTC odmawia z
/// cytatem BUG-452 x4 nogi (claim_forbid arm encode-side z 452).
#[test]
fn t463_5_mint_refuse() {
    for (leg, text) in MINTREF463 {
        let t = tab(leg);
        let e = enc(t, text).expect_err("mint must refuse");
        assert!(e.contains("BUG-452"), "[{leg}] cite: {e}");
    }
}

/// t463_6: data-attribution -- census kluczy/cf/LTC/_src463 per noga
/// (6791/33/12/12 x2, 7932/25/12/12, 15758/29/12/12; pseudo-rekordy
/// _errata_* pomijane), SOURCE pin a64b82b.
#[test]
fn t463_6_census_attribution() {
    // FLIP-ride (BUG-464, F2-iter270, canonical 4968113): +6 kluczy/noga
    // (plain nNA ARURI64 EFL2.256 lattice; cf/LTC/_src463 niezmienione) --
    // licznik loader-side jak poprzednio (121a loader-visible +6 -> 15764;
    // raw JSON 15766, offset -2 pre-existing).
    // FLIP-ride (BUG-465, F2-iter272, canonical 23976eb): +1146 kluczy/noga
    // (modsub plain E*L2.256 lattice; cf/LTC/_src463 niezmienione) --
    // loader-visible jak poprzednio (121a 16910; raw 16912, offset -2). flip-ride 467: po delete BUG-467 loader 16905 / raw 16907.
    let want = [
        ("sm100a", 14925u32, 6979u32, 12u32, 12u32), // 2026-11-06 T-11 (canonical 7f12b68): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-06 T-10 (canonical 315bffa): BRA sm103a/sm100a 14912 -> 14913 forms, 22363 -> 22420 variants; sm120 BRX/BRXU/RET + the audit batches 16045 -> 15935 forms, 26646 -> 26562 variants // 2026-11-06 T-8 (LEA family rebuilt from measurement, tools/probes/re_sm120_lea.py: sm120 56 keys / 100 rows -> 24 keys / 36 rows, sm103a / sm100a 18 keys / 21 rows -> 24 / 36): sm120 16097 -> 16065 forms, 26663 -> 26599 variants; sm103a / sm100a 14906 -> 14912, 22348 -> 22363 // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // // (claim_forbid rows +2 per table: the new rows exclude bit 76) // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // T-6 (canonical 2eed3ac): +2 claim_forbid rows per table = the measured ATOMG .EL rows (bit 63 / bit 76 excluded) -> 6976 / 6975 / 7014 // RIDE476 (F2-iter299, canonical c88778e): +11 keys +1 cf (476a NA-graft + 476b forbid) -> 14879/1170 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146/-2 keys (dARI modsub lattice b76=1 + rekanon 462-mgs ENL2); cf 33->1166 (claim_forbid dziedziczone z donorow dARI modsub graft) // was: 13721/33 // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454 keys (twins _ARURI U32 b75=0; loader-visible 22688-2) // was: 10267 ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145),
        ("sm103a", 14926, 6978, 12, 12), // 2026-11-07 T-14 (canonical 7f12b68: the sm103a MUFU packed-half lanes measured, MUFU_R_FI_FI new): sm103a forms 14925 -> 14926, variants 22439 -> 22445 // 2026-11-06 T-11 (canonical 7f12b68): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-06 T-10 (canonical 315bffa): BRA sm103a/sm100a 14912 -> 14913 forms, 22363 -> 22420 variants; sm120 BRX/BRXU/RET + the audit batches 16045 -> 15935 forms, 26646 -> 26562 variants // 2026-11-06 T-8 (LEA family rebuilt from measurement, tools/probes/re_sm120_lea.py: sm120 56 keys / 100 rows -> 24 keys / 36 rows, sm103a / sm100a 18 keys / 21 rows -> 24 / 36): sm120 16097 -> 16065 forms, 26663 -> 26599 variants; sm103a / sm100a 14906 -> 14912, 22348 -> 22363 // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // // (claim_forbid rows +2 per table: the new rows exclude bit 76) // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // T-6 (canonical 2eed3ac): +2 claim_forbid rows per table = the measured ATOMG .EL rows (bit 63 / bit 76 excluded) -> 6976 / 6975 / 7014 // RIDE476 (F2-iter299, canonical c88778e): +11 keys +1 cf -> 14879/1170 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146/-2 keys (dARI modsub lattice b76=1 + rekanon 462-mgs ENL2); cf 33->1166 // was: 13721/33 // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454 keys (twins _ARURI U32 b75=0; loader-visible 22688-2) // was: 10267 ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145),
        ("sm120", 1015, 10999, 0, 0), // 2026-11-08 T-18 (canonical 7f12b68: 32 whole-key twins retired as aliases) // 2026-11-08 T-18 (canonical 7f12b68: the 192 wave-pinned rows measured / aliased) // re-pinned on sm120 for the long tail (G run 5 batch 16 re-applied by T-17 on the batches 12-15 base, 7f12b68) // re-pinned 2026-11-07 (T-16: G run 5 batch 15 — the tensor-core long tail verified row by row — on the batches 12-14 base) // re-pinned 2026-11-07 (G batch 14: REDG uniform-indexed forms measured whole) // G batch 13 STG.256 2026-11-07: the 576 measured STG_dARI_R_R[_II] rows carry the RZ-base claim_forbid, the 384 retired dotted dARI rows had it, 7 other retired rows had one -> 11013 // re-pinned 2026-11-07 (G batch 13: STG.256 measured whole) // G batch 12 LDG.256 ARURI 2026-11-07: 5 retired dotted `_R_R_ARURI` rows carried a claim_forbid -> 10828 // re-pinned 2026-11-07 (G batch 12: LDG.256 ARURI measured whole) // G batch 11 LDG.256 ARURI64 2026-11-07: 4 retired dotted `_R_R_ARURI64` rows carried a claim_forbid -> 10833 // // re-pinned 2026-11-07 (G batch 11: LDG.256 ARURI64 measured whole) // G batch 10 LDG.256 dARI 2026-11-07: the 782 dotted / harvest `_R_R_dARI` rows with the RZ-base claim_forbid retired, the 4 608 measured LDG_R_R_dARI[_II][_P] rows carry it (desc[UR][RZ.64] is illegal on nvdisasm 13.1) -> 7011 - 782 + 4608 = 10837; the 12 `EFL2.LTC*_R_R_dARI` keys with `_src463` are groups of the measured plain keys now // // re-pinned 2026-11-07 (G batch 10: LDG.256 dARI measured whole) // G batch 9 FSET / FSEL / FCHK 2026-11-07: the junk FCHK_P_R_UR row carried a claim_forbid on the opcode nibble [4:1]; the measured row pins the whole opcode -> claim_forbid rows 7012 -> 7011 // G batch 9 FSET / FSEL / FCHK 2026-11-07 // G batch 8 conversions 2026-11-07 // G batch 7 uniform FP32 ALU 2026-11-07 // G batch 6 FP32 ALU 2026-11-07 // 2026-11-06 G (canonical 7f12b68): UFSETP measured, 6 junk keys retired as aliases: sm120 15840 -> 15834 forms, 26442 -> 26341 variants // 2026-11-06 G (canonical 7f12b68): PLOP3 / P2R / R2P measured, 10 junk keys retired as aliases, R2P_II_R added: sm120 15849 -> 15840 forms, 26451 -> 26442 variants // 2026-11-06 G (canonical 7f12b68): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 7f12b68): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 2026-11-06 T-11 (canonical 7f12b68): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-06 T-10 IMMA family (canonical c258f8a): sm120 15935 -> 15953 forms, 26562 -> 26580 variants // 2026-11-06 T-10 (canonical 315bffa): BRA sm103a/sm100a 14912 -> 14913 forms, 22363 -> 22420 variants; sm120 BRX/BRXU/RET + the audit batches 16045 -> 15935 forms, 26646 -> 26562 variants // (claim_forbid rows 7013 -> 7011: two retired BRA harvest rows carried the tag) // 2026-11-06 T-9 (BRA family rebuilt from measurement, tools/probes/re_sm120_bra.py: sm120 15 keys / 31 rows -> 6 keys / 66 rows, canonical b75cc20): sm120 keys 16054 -> 16045, variants 26611 -> 26646, loader 16074 -> 16068 (+3 key aliases) // 2026-11-06 T-8 ATOMS_R_ARURI_R rebuilt (36 groups) + 9 junk keys retired (canonical 5222c58): sm120 keys 16063 -> 16054, variants 26596 -> 26612 // 2026-11-06 T-8 F2FP twins retired (canonical 09a7141): sm120 keys 16065 -> 16063, variants 26599 -> 26596, claim_forbid rows 7016 -> 7013 // 2026-11-06 T-8 (LEA family rebuilt from measurement, tools/probes/re_sm120_lea.py: sm120 56 keys / 100 rows -> 24 keys / 36 rows, sm103a / sm100a 18 keys / 21 rows -> 24 / 36): sm120 16097 -> 16065 forms, 26663 -> 26599 variants; sm103a / sm100a 14906 -> 14912, 22348 -> 22363 // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // (claim_forbid rows +2 per table: the new rows exclude bit 76) // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // T-6 (canonical 2eed3ac): +2 claim_forbid rows per table = the measured ATOMG .EL rows (bit 63 / bit 76 excluded) -> 6976 / 6975 / 7014 // 2026-11-04 (canonical T-3 batches b063d43/15caf70/6f11f6b): -20 era keys (now _meta.key_aliases), +1 LDL_R_ARURI = 16107 forms; variants 20883 -> 20894 (LDL +14, MUFU_R_UR 4 -> 26, IMAD -7 alias groups +4 U32 twins, F2F_R_R F32,F64 removed); sm121a -10 era keys = 23823 raw / 23821 loader-visible, variants 26380. // 2026-11-03 dynamic-audit batch 1 (canonical 6619782): -12 sm120 keys / -22 variants (FSETP_P_P_L_FI_P, FSETP_P_P_L_L_P, F2FP.F16.F32.PACK_AB_P_R_R_R, HMMA *_P0_* rows, LOP3.LUT_P_R_R_R_R_II_P, QMMA.16816.F16.E4M3.E4M3_P_R_R_R_R: their words are other instructions for nvdisasm) = 16126 forms, 20883 variants; LDGSTS base field 8 bits, LDC/LDCU reuse field removed; hygiene pass (canonical 64eaa21) cleared the baked control bits, counts unchanged. // 2026-11-02 HMUL2 imm / LDSM FP4-FP6 / PRMT UR / ARRIVES.LDGSTSBAR / UTMASTG dims (canonical 77a3dfa): +3 sm120 keys (HMUL2_R_R_FI_FI, PRMT_R_R_UR_R, ARRIVES_ARURI), +30 LDSM_R_ARI and +4 UTMASTG groups (variants 20850 -> 20905) = 16138. // 2026-10-29 ATOMS [R+UR+imm] / STSM.8.MT168 / UBLKPF.L2 (canonical 137cd34): +2 sm120 keys (UBLKPF_AURI_UR, UBLKPF_AURI_UR_II), +3 STSM_ARI_R groups, ATOMS_R_ARURI_R MAX,S32 re-measured (variants 20845 -> 20850) = 16135. // 2026-10-28 F2FP.BF16.E8.UNPACK_B_R_R (canonical f1e02b3): +1 sm120 key (UE8M0 -> BF16x2 unpack, variants 20844 -> 20845) = 16133. // 2026-10-23 CS2UR (canonical 59561b2): -1 sm120 key (junk CS2UR_UR_II immediate row removed; CS2UR_UR_L gains the plain group, variants unchanged 20837) = 16132 // RIDE458a2 (F2-iter309, canonical 952d336): cf +1 (graft mg F2FP_R_R_R PACK_AB.RZ, klon z 100a, cf verbatim): +1 cf // RIDE459a (F2-iter301, canonical 96372cb): -1 sm120 key (459a junk-mg "" / 64 DELETE -> key-del UR_II_..._UP_UP) -> forms 16015, variants -4=17631; sm121a variants -4=26385; cf stoi // RIDE476 (F2-iter299, canonical c88778e): +11 keys +1 cf -> 16016/1167 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146/-2 keys (dARI modsub lattice b76=1 + rekanon 462-mgs ENL2); cf 25->1164 // was: 14859/25 // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454 keys (twins _ARURI U32 b75=0; loader-visible 22688-2) // was: 11405 ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145) // was: flip-ride 467: -3 sm120 keys (degen era delete) // G run 5 batch 16 (T-17): claim_forbid census 11013 -> 11001 (the 6 retired F2FP / ATOMG twin keys and the 6 dead F2FP_R_R_R_R junk groups carried them; 0 census witnesses) // 2026-11-08 T-18 b2: 32 whole-key twins retired as aliases; 2 of them carried a claim_forbid -> 11001 -> 10999
        ("sm121a", 23858, 1244, 12, 12), // 2026-11-06 T-11 (sm121a raw keys 23848 -> 23858) (canonical 7f12b68): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-04 (canonical T-3 batches b063d43/15caf70/6f11f6b): -20 era keys (now _meta.key_aliases), +1 LDL_R_ARURI = 16107 forms; variants 20883 -> 20894 (LDL +14, MUFU_R_UR 4 -> 26, IMAD -7 alias groups +4 U32 twins, F2F_R_R F32,F64 removed); sm121a -10 era keys = 23823 raw / 23821 loader-visible, variants 26380. // RIDE458a2 (F2-iter309, canonical 952d336): cf +1 (graft mg F2FP_R_R_R PACK_AB.RZ, klon z 100a, cf verbatim) (121a): +1 cf // RIDE476 (F2-iter299, canonical c88778e): +8 keys -> 23831 (raw 23833 - 2 errata; licznik pomija rekordy bez mod_groups) // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146/-2 keys (dARI modsub lattice b76=1 + rekanon 462-mgs ENL2); cf 46->1181 // was: 22686/46 // RIDE474 (F2-iter285 BUG-474, canonical PENDING-474): +3454 keys (twins _ARURI U32 b75=0; loader-visible 22688-2) // was: 19231 ride RIDE469b (F2-iter285): cf-census 29->46 (+17 z graftu 469: mg 0x981 + EF-klucze; canonical bd48e63) // ride F2-iter282 BUG-469: +6 sm121a keys (widthless ARURI graft: 2x ELL2.256 R_R_ARURI donor-103a verbatim-era0 + mg R/R_P/P_R/P_R_P plain-band + 4x EF-band P_R_ARURI_P; canonical bd48e63) (loader-visible 19233-2), // ride F2-iter280 BUG-468: +2320 keys (LTC-sel [74:73] lattice closure plain ARURI64 + NA LTC128B/256B; canonical 08a6145) // was: flip-ride 467: -5 sm121a keys (degen era delete)
    ];
    for (leg, w_keys, w_cf, w_ltc, w_src463) in want {
        let v: serde_json::Value =
            serde_json::from_str(&cubit::table::read_table_text(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = v["instructions"].as_object().unwrap();
        let mut n_keys = 0u32;
        let mut n_cf = 0u32;
        let mut n_ltc = 0u32;
        let mut n_src463 = 0u32;
        for (k, rec) in ins {
            let mgs = match rec["mod_groups"].as_object() {
                Some(m) => m,
                None => continue, // pseudo-rekordy _errata_*
            };
            n_keys += 1;
            for (_, g) in mgs {
                if g.get("claim_forbid").is_some() {
                    n_cf += 1;
                }
            }
            if k.contains("EFL2.LTC") && k.contains("_dARI") && !k.contains("NA.") {
                n_ltc += 1;
            }
            if rec["_src463"] == "bug463-2026-09-14" {
                n_src463 += 1;
            }
        }
        assert_eq!(
            (n_keys, n_cf, n_ltc, n_src463),
            (w_keys, w_cf, w_ltc, w_src463),
            "[{leg}] census drift"
        );
        let src: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
        assert!(
            src["base_revision"]
                .as_str()
                .unwrap()
                .starts_with("7f12b68e829952041a9fea898b7f3c3e02fa6187") /* 2026-11-06 T-11 (was c258f8a, T-10) */,
            "SOURCE pin drift"
        );
    }
}

/// t463_7: era/glyph klasa -- era-b118 / reuse-b122 legalne, URZ/RZ glyph,
/// imm signed '+-', polff+pred bez trailerza (20 komorek x4 nogi).
#[test]
fn t463_7_era_glyph_legal() {
    for (w, leg, want) in ERAGLYPH463 {
        let t = tab(leg);
        let idx = cached_index(t);
        let got = dec(t, idx, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] era/glyph {w:#034x}");
    }
}
