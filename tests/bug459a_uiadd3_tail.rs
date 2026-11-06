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
/// CANON459A + structured SM120 source digest/census). Klasa KILL pusta --
/// JUNK row = encode-side.
#[test]
fn t459a_2_mint_junk_census_source() {
    // Current byte-pinned cut; historical fixture provenance remains unchanged.
    const CURRENT_VENDORED_CANON: &str = "5b4b03cde6d2995b501aa2e51cee27ce513c52f8" /* 2026-11-06 T-11 (was c258f8a, T-10) */ /* 2026-11-06 T-10 (was b75cc20, T-9) */;
    assert_eq!(CANON459A, "9c0e4ce", "historical fixture revision drift");

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
            serde_json::from_str(&cubit::table::read_table_text(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        assert_eq!(ins.len(), *want_forms, "[{leg}] forms census drift");
        let variants: usize = ins
            .values()
            .map(|v| v["mod_groups"].as_object().map(|m| m.len()).unwrap_or(0))
            .sum();
        // Six measured SM120 LDSM.8.MT1616 x1/x2 groups and seven measured CCTL `.E` register
        // groups (CCTL_ARI: PF1/PF2/WB/IV/RS/PML2/DML2/RML2 with the .E address form) are new;
        // the historical CENSUS array and every other architecture stay exact.
        if *leg == "sm120" {
            assert_eq!(*want_variants, 20831, "historical SM120 variants snapshot drift");
        }
        // 2026-10-28: + the F2FP.BF16.E8.UNPACK_B_R_R row (UE8M0 -> BF16x2; canonical f1e02b3) = 14.
        // 2026-10-29: + the three STSM.8.MT168 groups and the two UBLKPF.L2 rows (canonical 137cd34) = 19.
        // 2026-11-02: + 12 HMUL2_R_R_FI_FI + 30 LDSM FP4/FP6 + 7 PRMT_R_R_UR_R + 2 ARRIVES_ARURI + 4 UTMASTG groups (canonical 77a3dfa) = 74.
        // 2026-11-03: - 22 rows whose words are other instructions for nvdisasm (dynamic-audit batch 1, canonical 6619782) = 52.
        // 2026-11-04: - 20 era keys (now _meta.key_aliases) + 14 LDL_R_ARURI + 22 MUFU_R_UR (4 -> 26) - 3 IMAD (7 alias groups
        //             -> 4 U32 twins) - 1 F2F_R_R 'F32,F64' + 1 (MUFU/F2F rebuild accounting; canonical 6f11f6b) = 63.
        //
        // WAVE-11 INTEGRATION (2026-11-05, canonical e99598a (wave 11; pin now 2eed3ac)): 63 -> 5781. The lane lineage merged onto the
        // 2026-11-05 main brings the whole October row canon: the BUG-509 ATOM/ATOMG enumeration alone is
        // +5747 rows (2876 + 2871, each carrying the silicon-confirmed claim_forbid on [63:60] -- nibbles 0..7
        // TRAP on the RTX PRO 6000, measured 2026-11-05), plus the F2FP/VIADD/ELL2.256 families. Every one of
        // these was adjudicated before being merged: see pubwave/wave11/INTEGRATION.md.
        let sm120_delta = 5620usize; // 2026-11-06 G (canonical 5b4b03c): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 5b4b03c): ISETP / UISETP measured, 67 groups added: sm120 26595 -> 26662 variants // 2026-11-06 G (canonical 5b4b03c): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 26598 - 20831 (2026-11-06 T-11 (canonical 5b4b03c: the IDP family measured whole + the audit exceptions)) // was 5749 = 26580 - 20831 (2026-11-06 T-10 IMMA family) // was 5731 = 26562 - 20831 // 2026-11-06 T-10 (canonical 315bffa): BRX/BRXU/RET + the audit batches, variants 26646 -> 26562 // was 5815 = 26646 - 20831 // 2026-11-06 T-9 BRA family (canonical b75cc20): variants 26611 -> 26646 // was 5780 = 26611 - 20831 // 2026-11-06 T-8 ATOMS_R_ARURI_R rebuilt (36 groups) + 9 junk keys retired (canonical 5222c58): sm120 keys 16063 -> 16054, variants 26596 -> 26612, loader 16074: 26612 - 20831 // 2026-11-06 T-8 F2FP twins retired (canonical 09a7141): sm120 keys 16065 -> 16063, variants 26599 -> 26596, loader 16083: 26596 - 20831 // 2026-11-06 T-8 (LEA family rebuilt from measurement, tools/probes/re_sm120_lea.py): sm120 keys 16097 -> 16065 (56 LEA keys -> 24), variants 26663 -> 26599, loader 16085; sm103a / sm100a keys 14906 -> 14912 (18 -> 24), variants 22348 -> 22363: the wave-11 variant delta over the CENSUS459A snapshot 20831 is now 26599 - 20831 // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // 2026-11-05 T-6 item 2: 26 656 - 20 831 (the SHF rebuild: -116 dotted/mixed groups, +160 measured = +44 over wave 11)
        let current_variants = *want_variants + if *leg == "sm120" { sm120_delta } else { 0 };
        assert_eq!(variants, current_variants, "[{leg}] variants census drift");
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
            .starts_with(CURRENT_VENDORED_CANON),
        "SOURCE pin drift po flipie 459a"
    );
    let sm120 = &src["tables"]["sm120.json"];
    assert_eq!(
        sm120["base_sha256"].as_str(),
        Some("c8fc84f8fc169838dfe67da304a7d5d3c4e52e9605d99264dbbd5a8a070cc5f1"),
        "SM120 source digest drift"
    );
    assert_eq!(sm120["instruction_forms"].as_u64(), Some(15849)); // 2026-11-06 G (canonical 5b4b03c): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 5b4b03c): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 2026-11-06 T-11 (canonical 5b4b03c): 15953 -> 15964 // 2026-11-06 T-10 (canonical 315bffa): sm120 16045 -> 15935 forms, 26646 -> 26562 variants; sm103a / sm100a 14912 -> 14913, 22363 -> 22420  // 2026-11-06 T-9 BRA family (canonical b75cc20): 16054 -> 16045 // 2026-11-06 T-8 (LEA family rebuilt, F2FP twins + 9 junk keys retired, ATOMS_R_ARURI_R 36 measured groups; canonical 7094efc+): sm120 16097 -> 16054 forms, 26663 -> 26611 variants // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // 2026-11-05 T-6 item 2 (T-5's SHF + LDTM/STTM rows on the wave-11 tables, canonical 377b507): sm120 keys 16143 -> 16103 (-40 dotted SHF), variants 26612 -> 26656; sm100a/sm103a variants 22199 -> 22340; loader sm120 16123 // 2026-11-04 (canonical T-3 batches b063d43/15caf70/6f11f6b): -20 era keys (now _meta.key_aliases), +1 LDL_R_ARURI = 16107 forms; variants 20883 -> 20894 (LDL +14, MUFU_R_UR 4 -> 26, IMAD -7 alias groups +4 U32 twins, F2F_R_R F32,F64 removed); sm121a -10 era keys = 23823 raw / 23821 loader-visible, variants 26380. // 2026-11-03 dynamic-audit batch 1 (canonical 6619782): -12 sm120 keys / -22 variants (FSETP_P_P_L_FI_P, FSETP_P_P_L_L_P, F2FP.F16.F32.PACK_AB_P_R_R_R, HMMA *_P0_* rows, LOP3.LUT_P_R_R_R_R_II_P, QMMA.16816.F16.E4M3.E4M3_P_R_R_R_R: their words are other instructions for nvdisasm) = 16126 forms, 20883 variants; LDGSTS base field 8 bits, LDC/LDCU reuse field removed; hygiene pass (canonical 64eaa21) cleared the baked control bits, counts unchanged. // 2026-11-02 HMUL2 imm / LDSM FP4-FP6 / PRMT UR / ARRIVES.LDGSTSBAR / UTMASTG dims (canonical 77a3dfa): +3 sm120 keys (HMUL2_R_R_FI_FI, PRMT_R_R_UR_R, ARRIVES_ARURI), +30 LDSM_R_ARI and +4 UTMASTG groups (variants 20850 -> 20905) = 16138. // 2026-10-29 ATOMS [R+UR+imm] / STSM.8.MT168 / UBLKPF.L2 (canonical 137cd34): +2 sm120 keys (UBLKPF_AURI_UR, UBLKPF_AURI_UR_II), +3 STSM_ARI_R groups, ATOMS_R_ARURI_R MAX,S32 re-measured (variants 20845 -> 20850) = 16135. // 2026-10-28 F2FP.BF16.E8.UNPACK_B_R_R (canonical f1e02b3): +1 sm120 key
    assert_eq!(sm120["encoding_variants"].as_u64(), Some(26451)); // 2026-11-06 G (canonical 5b4b03c): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 5b4b03c): ISETP / UISETP measured, 67 groups added: sm120 26595 -> 26662 variants // 2026-11-06 G (canonical 5b4b03c): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 2026-11-06 T-11 (canonical 5b4b03c): 26580 -> 26598 // 2026-11-06 T-10 (canonical 315bffa): sm120 16045 -> 15935 forms, 26646 -> 26562 variants; sm103a / sm100a 14912 -> 14913, 22363 -> 22420  // 2026-11-06 T-9 BRA family (canonical b75cc20): 26611 -> 26646 // 2026-11-06 T-8 (LEA family rebuilt, F2FP twins + 9 junk keys retired, ATOMS_R_ARURI_R 36 measured groups; canonical 7094efc+): sm120 16097 -> 16054 forms, 26663 -> 26611 variants // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // 2026-11-05 T-6 item 2 (T-5's SHF + LDTM/STTM rows on the wave-11 tables, canonical 377b507): sm120 keys 16143 -> 16103 (-40 dotted SHF), variants 26612 -> 26656; sm100a/sm103a variants 22199 -> 22340; loader sm120 16123 // 2026-11-04 (canonical T-3 batches b063d43/15caf70/6f11f6b): -20 era keys (now _meta.key_aliases), +1 LDL_R_ARURI = 16107 forms; variants 20883 -> 20894 (LDL +14, MUFU_R_UR 4 -> 26, IMAD -7 alias groups +4 U32 twins, F2F_R_R F32,F64 removed); sm121a -10 era keys = 23823 raw / 23821 loader-visible, variants 26380. // 2026-11-03 dynamic-audit batch 1 (canonical 6619782): -12 sm120 keys / -22 variants (FSETP_P_P_L_FI_P, FSETP_P_P_L_L_P, F2FP.F16.F32.PACK_AB_P_R_R_R, HMMA *_P0_* rows, LOP3.LUT_P_R_R_R_R_II_P, QMMA.16816.F16.E4M3.E4M3_P_R_R_R_R: their words are other instructions for nvdisasm) = 16126 forms, 20883 variants; LDGSTS base field 8 bits, LDC/LDCU reuse field removed; hygiene pass (canonical 64eaa21) cleared the baked control bits, counts unchanged. // 2026-11-02 HMUL2 imm / LDSM FP4-FP6 / PRMT UR / ARRIVES.LDGSTSBAR / UTMASTG dims (canonical 77a3dfa): +3 sm120 keys (HMUL2_R_R_FI_FI, PRMT_R_R_UR_R, ARRIVES_ARURI), +30 LDSM_R_ARI and +4 UTMASTG groups (variants 20850 -> 20905) = 16138. // 2026-10-29 ATOMS [R+UR+imm] / STSM.8.MT168 / UBLKPF.L2 (canonical 137cd34): +2 sm120 keys (UBLKPF_AURI_UR, UBLKPF_AURI_UR_II), +3 STSM_ARI_R groups, ATOMS_R_ARURI_R MAX,S32 re-measured (variants 20845 -> 20850) = 16135. // 2026-10-28 F2FP.BF16.E8.UNPACK_B_R_R (canonical f1e02b3): +1 sm120 key, variants 20844 -> 20845; 2026-10-25 CCTL (canonical 8d26508): +7 mod groups in CCTL_ARI (E,PF1/WB/IV/RS/PML2/RML2 + DML2,E), keys unchanged 16132, variants 20837 -> 20844
}

/// NVIDIA SM120 distinguishes X by bit74. Non-X ignores the carry selector
/// bits varied by HOLEPAR, so its visible mnemonic cannot preserve those
/// words. Do not promote vendor-visible but lossy words to strict successes.
#[test]
fn t459a_3_sm120_full_word_semantics() {
    let (table, index) = pool().get("sm120").unwrap();
    for (word, leg, _, tag, _) in HEAL459A.iter().chain(MINT459A) {
        if *leg != "sm120" {
            continue;
        }
        let mut failures = Vec::new();
        let (report, _) = cubit::roundtrip_audit::audit_kernel(
            ".text.uiadd3", 0, &word.to_le_bytes(), table, index,
            &mut |failure| { failures.push(failure.clone()); Ok(()) },
        ).unwrap();
        assert!(report.passed && report.stream_verified, "{tag}: {failures:?}");
        assert_eq!(report.matched, 1);
    }
    for (word, leg, _, tag, _) in HOLEPAR459A.iter().chain(REFPAR459A) {
        if *leg != "sm120" {
            continue;
        }
        let (report, _) = cubit::roundtrip_audit::audit_kernel(
            ".text.uiadd3", 0, &word.to_le_bytes(), table, index,
            &mut |_| Ok(()),
        ).unwrap();
        assert!(!report.passed, "lossy/invalid word accepted: {tag} {word:#034x}");
    }
}
