//! BUG-459a pins (F2-iter296 pre-study + iter301 execution, loop5/blind front2,
//! 2026-09-18): the UIADD3 plain junk tail ", UPT, UPT" -- DELETE the junk mod groups
//! "" / "64" from the keys UIADD3_UR_UP_UP_UR_{UR,II}_UR_UP_UP (sm120 + sm121a). The
//! junk mod groups had the pred-out bits [77:81) + [87:91) baked at the default
//! 0xf / 0xf WITHOUT an extraction of tokens 6..8 -> they printed the suffix ", UPT,
//! UPT" and shadowed the good 6-token rows (winner shadow; on 100a / 103a the same
//! words landed in the correct rows -- the junk mg was harmless there -> the A4b legs
//! byte-untouched). sm120: the UR_II key is empty after the deletion -> key deletion
//! (EXACTLY 1). Vendor law (arb459a, 136 probes, nvdisasm 13.3.73 raw -b x4 AGREE
//! EVERY): the native imm / UR words + the guard sweep [12:16) x16 + the .64 frame
//! ALWAYS print the 6-token form; bits [77:91) DEAD on the imm frame (a flip = the
//! vendor unchanged). Audits of patch459a.py: A0 (the content of the deleted mgs'
//! and_base / vm locked + no extraction of [77:91)), A4 (removed == EXACTLY {UR_II}
//! sm120, touched == {UR_UR} sm120 + both keys on sm121a), A4b byte parity 100a / 103a,
//! A5 census (14879/14879/16015/23833 forms; 16450/16446/17631/26385 variants;
//! cf 1170/1170/1167/1183) fail-closed. The cubit ENGINE NOT touched (table only).
//! Canonical commit 96372cb (after 476 c88778e; serialisation INC-283a).
//! Witness: tests/bug459a_data.inc (machine-built by gen459apins.py rc=2; the class
//! matrix locked): HEAL 66 (33 sm120 + 33 sm121a), EXACT 8 (121a), HOLEPAR 8 (sm120
//! flips 77..80, 87..90 -- vendor-legal outside the good row's window), REFPAR 190
//! (vendor refuse, hole parity x2), X3STABLE 66 + X3STANDING 16 (the x3 overprint of
//! the dead bits [77:91): UIADD3.X + the UPx tail, cold == hot, the 408 residue
//! companion -- parity only, by the 285 / 440 doctrine), MINT 8 (4 texts x {120,121a}),
//! JUNK 8-token encode fail-closed x2. The KILL class = 0 (the deletion lifts no
//! decoder overclaim; the pre-fix junk mint 0xfc2000fffe0fffffffff0070a7890 confirmed
//! on the encode side).

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
    const CURRENT_VENDORED_CANON: &str = "89dc967e3d9f5c78bd58e8d06fcee6140dac8bd1" /* 2026-11-06 T-11 (was c258f8a, T-10) */ /* 2026-11-06 T-10 (was b75cc20, T-9) */;
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
        let sm120_delta = 18007usize; // T-19 2026-11-08: the long tail closed, 111 -> 7 rows without _src // 2026-11-08 T-18 (canonical 89dc967: 32 whole-key twins retired as aliases) // 2026-11-08 T-18 (canonical 89dc967: the 192 wave-pinned rows measured / aliased) // re-pinned on sm120 for the long tail (G run 5 batch 16 re-applied by T-17 on the batches 12-15 base, 89dc967) // re-pinned 2026-11-07 (T-16: G run 5 batch 15 — the tensor-core long tail verified row by row — on the batches 12-14 base) // re-pinned 2026-11-07 (G batch 14: REDG uniform-indexed forms measured whole) // re-pinned 2026-11-07 (G batch 13: STG.256 measured whole) // re-pinned 2026-11-07 (G batch 12: LDG.256 ARURI measured whole) // re-pinned 2026-11-07 (G batch 11: LDG.256 ARURI64 measured whole) // re-pinned 2026-11-07 (G batch 10: LDG.256 dARI measured whole) // G batch 9 FSET / FSEL / FCHK 2026-11-07 // G batch 8 conversions 2026-11-07 // G batch 7 uniform FP32 ALU 2026-11-07 // G batch 6 FP32 ALU 2026-11-07 // 2026-11-06 G (canonical 89dc967): UFSETP measured, 6 junk keys retired as aliases: sm120 15840 -> 15834 forms, 26442 -> 26341 variants // 2026-11-06 G (canonical 89dc967): PLOP3 / P2R / R2P measured, 10 junk keys retired as aliases, R2P_II_R added: sm120 15849 -> 15840 forms, 26451 -> 26442 variants // 2026-11-06 G (canonical 89dc967): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 89dc967): ISETP / UISETP measured, 67 groups added: sm120 26595 -> 26662 variants // 2026-11-06 G (canonical 89dc967): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 26598 - 20831 (2026-11-06 T-11 (canonical 89dc967: the IDP family measured whole + the audit exceptions)) // was 5749 = 26580 - 20831 (2026-11-06 T-10 IMMA family) // was 5731 = 26562 - 20831 // 2026-11-06 T-10 (canonical 315bffa): BRX/BRXU/RET + the audit batches, variants 26646 -> 26562 // was 5815 = 26646 - 20831 // 2026-11-06 T-9 BRA family (canonical b75cc20): variants 26611 -> 26646 // was 5780 = 26611 - 20831 // 2026-11-06 T-8 ATOMS_R_ARURI_R rebuilt (36 groups) + 9 junk keys retired (canonical 5222c58): sm120 keys 16063 -> 16054, variants 26596 -> 26612, loader 16074: 26612 - 20831 // 2026-11-06 T-8 F2FP twins retired (canonical 09a7141): sm120 keys 16065 -> 16063, variants 26599 -> 26596, loader 16083: 26596 - 20831 // 2026-11-06 T-8 (LEA family rebuilt from measurement, tools/probes/re_sm120_lea.py): sm120 keys 16097 -> 16065 (56 LEA keys -> 24), variants 26663 -> 26599, loader 16085; sm103a / sm100a keys 14906 -> 14912 (18 -> 24), variants 22348 -> 22363: the wave-11 variant delta over the CENSUS459A snapshot 20831 is now 26599 - 20831 // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // 2026-11-05 T-6 item 2: 26 656 - 20 831 (the SHF rebuild: -116 dotted/mixed groups, +160 measured = +44 over wave 11)
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
        Some("47748150a5465780370be1bd5d16d2731194261d205d0f5bfe046c8ea75d66e5"),
        "SM120 source digest drift"
    );
    assert_eq!(sm120["instruction_forms"].as_u64(), Some(979)); // T-19 2026-11-08: the long tail closed, 111 -> 7 rows without _src // 2026-11-08 T-18 (canonical 89dc967: 32 whole-key twins retired as aliases) // 2026-11-08 T-18 (canonical 89dc967: the 192 wave-pinned rows measured / aliased) // re-pinned on sm120 for the long tail (G run 5 batch 16 re-applied by T-17 on the batches 12-15 base, 89dc967) // re-pinned 2026-11-07 (T-16: G run 5 batch 15 — the tensor-core long tail verified row by row — on the batches 12-14 base) // re-pinned 2026-11-07 (G batch 14: REDG uniform-indexed forms measured whole) // re-pinned 2026-11-07 (G batch 13: STG.256 measured whole) // re-pinned 2026-11-07 (G batch 12: LDG.256 ARURI measured whole) // re-pinned 2026-11-07 (G batch 11: LDG.256 ARURI64 measured whole) // re-pinned 2026-11-07 (G batch 10: LDG.256 dARI measured whole) // G batch 9 FSET / FSEL / FCHK 2026-11-07 // G batch 8 conversions 2026-11-07 // G batch 7 uniform FP32 ALU 2026-11-07 // G batch 6 FP32 ALU 2026-11-07 // 2026-11-06 G (canonical 89dc967): UFSETP measured, 6 junk keys retired as aliases: sm120 15840 -> 15834 forms, 26442 -> 26341 variants // 2026-11-06 G (canonical 89dc967): PLOP3 / P2R / R2P measured, 10 junk keys retired as aliases, R2P_II_R added: sm120 15849 -> 15840 forms, 26451 -> 26442 variants // 2026-11-06 G (canonical 89dc967): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 89dc967): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 2026-11-06 T-11 (canonical 89dc967): 15953 -> 15964 // 2026-11-06 T-10 (canonical 315bffa): sm120 16045 -> 15935 forms, 26646 -> 26562 variants; sm103a / sm100a 14912 -> 14913, 22363 -> 22420  // 2026-11-06 T-9 BRA family (canonical b75cc20): 16054 -> 16045 // 2026-11-06 T-8 (LEA family rebuilt, F2FP twins + 9 junk keys retired, ATOMS_R_ARURI_R 36 measured groups; canonical 7094efc+): sm120 16097 -> 16054 forms, 26663 -> 26611 variants // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // 2026-11-05 T-6 item 2 (T-5's SHF + LDTM/STTM rows on the wave-11 tables, canonical 377b507): sm120 keys 16143 -> 16103 (-40 dotted SHF), variants 26612 -> 26656; sm100a/sm103a variants 22199 -> 22340; loader sm120 16123 // 2026-11-04 (canonical T-3 batches b063d43/15caf70/6f11f6b): -20 era keys (now _meta.key_aliases), +1 LDL_R_ARURI = 16107 forms; variants 20883 -> 20894 (LDL +14, MUFU_R_UR 4 -> 26, IMAD -7 alias groups +4 U32 twins, F2F_R_R F32,F64 removed); sm121a -10 era keys = 23823 raw / 23821 loader-visible, variants 26380. // 2026-11-03 dynamic-audit batch 1 (canonical 6619782): -12 sm120 keys / -22 variants (FSETP_P_P_L_FI_P, FSETP_P_P_L_L_P, F2FP.F16.F32.PACK_AB_P_R_R_R, HMMA *_P0_* rows, LOP3.LUT_P_R_R_R_R_II_P, QMMA.16816.F16.E4M3.E4M3_P_R_R_R_R: their words are other instructions for nvdisasm) = 16126 forms, 20883 variants; LDGSTS base field 8 bits, LDC/LDCU reuse field removed; hygiene pass (canonical 64eaa21) cleared the baked control bits, counts unchanged. // 2026-11-02 HMUL2 imm / LDSM FP4-FP6 / PRMT UR / ARRIVES.LDGSTSBAR / UTMASTG dims (canonical 77a3dfa): +3 sm120 keys (HMUL2_R_R_FI_FI, PRMT_R_R_UR_R, ARRIVES_ARURI), +30 LDSM_R_ARI and +4 UTMASTG groups (variants 20850 -> 20905) = 16138. // 2026-10-29 ATOMS [R+UR+imm] / STSM.8.MT168 / UBLKPF.L2 (canonical 137cd34): +2 sm120 keys (UBLKPF_AURI_UR, UBLKPF_AURI_UR_II), +3 STSM_ARI_R groups, ATOMS_R_ARURI_R MAX,S32 re-measured (variants 20845 -> 20850) = 16135. // 2026-10-28 F2FP.BF16.E8.UNPACK_B_R_R (canonical f1e02b3): +1 sm120 key
    assert_eq!(sm120["encoding_variants"].as_u64(), Some(38838)); // T-19 2026-11-08: the long tail closed, 111 -> 7 rows without _src // 2026-11-08 T-18 (canonical 89dc967: 32 whole-key twins retired as aliases) // 2026-11-08 T-18 (canonical 89dc967: the 192 wave-pinned rows measured / aliased) // re-pinned on sm120 for the long tail (G run 5 batch 16 re-applied by T-17 on the batches 12-15 base, 89dc967) // re-pinned 2026-11-07 (T-16: G run 5 batch 15 — the tensor-core long tail verified row by row — on the batches 12-14 base) // re-pinned 2026-11-07 (G batch 14: REDG uniform-indexed forms measured whole) // re-pinned 2026-11-07 (G batch 13: STG.256 measured whole) // re-pinned 2026-11-07 (G batch 12: LDG.256 ARURI measured whole) // re-pinned 2026-11-07 (G batch 11: LDG.256 ARURI64 measured whole) // re-pinned 2026-11-07 (G batch 10: LDG.256 dARI measured whole) // G batch 9 FSET / FSEL / FCHK 2026-11-07 // G batch 8 conversions 2026-11-07 // G batch 7 uniform FP32 ALU 2026-11-07 // G batch 6 FP32 ALU 2026-11-07 // 2026-11-06 G (canonical 89dc967): UFSETP measured, 6 junk keys retired as aliases: sm120 15840 -> 15834 forms, 26442 -> 26341 variants // 2026-11-06 G (canonical 89dc967): PLOP3 / P2R / R2P measured, 10 junk keys retired as aliases, R2P_II_R added: sm120 15849 -> 15840 forms, 26451 -> 26442 variants // 2026-11-06 G (canonical 89dc967): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 89dc967): ISETP / UISETP measured, 67 groups added: sm120 26595 -> 26662 variants // 2026-11-06 G (canonical 89dc967): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 2026-11-06 T-11 (canonical 89dc967): 26580 -> 26598 // 2026-11-06 T-10 (canonical 315bffa): sm120 16045 -> 15935 forms, 26646 -> 26562 variants; sm103a / sm100a 14912 -> 14913, 22363 -> 22420  // 2026-11-06 T-9 BRA family (canonical b75cc20): 26611 -> 26646 // 2026-11-06 T-8 (LEA family rebuilt, F2FP twins + 9 junk keys retired, ATOMS_R_ARURI_R 36 measured groups; canonical 7094efc+): sm120 16097 -> 16054 forms, 26663 -> 26611 variants // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // 2026-11-05 T-6 item 2 (T-5's SHF + LDTM/STTM rows on the wave-11 tables, canonical 377b507): sm120 keys 16143 -> 16103 (-40 dotted SHF), variants 26612 -> 26656; sm100a/sm103a variants 22199 -> 22340; loader sm120 16123 // 2026-11-04 (canonical T-3 batches b063d43/15caf70/6f11f6b): -20 era keys (now _meta.key_aliases), +1 LDL_R_ARURI = 16107 forms; variants 20883 -> 20894 (LDL +14, MUFU_R_UR 4 -> 26, IMAD -7 alias groups +4 U32 twins, F2F_R_R F32,F64 removed); sm121a -10 era keys = 23823 raw / 23821 loader-visible, variants 26380. // 2026-11-03 dynamic-audit batch 1 (canonical 6619782): -12 sm120 keys / -22 variants (FSETP_P_P_L_FI_P, FSETP_P_P_L_L_P, F2FP.F16.F32.PACK_AB_P_R_R_R, HMMA *_P0_* rows, LOP3.LUT_P_R_R_R_R_II_P, QMMA.16816.F16.E4M3.E4M3_P_R_R_R_R: their words are other instructions for nvdisasm) = 16126 forms, 20883 variants; LDGSTS base field 8 bits, LDC/LDCU reuse field removed; hygiene pass (canonical 64eaa21) cleared the baked control bits, counts unchanged. // 2026-11-02 HMUL2 imm / LDSM FP4-FP6 / PRMT UR / ARRIVES.LDGSTSBAR / UTMASTG dims (canonical 77a3dfa): +3 sm120 keys (HMUL2_R_R_FI_FI, PRMT_R_R_UR_R, ARRIVES_ARURI), +30 LDSM_R_ARI and +4 UTMASTG groups (variants 20850 -> 20905) = 16138. // 2026-10-29 ATOMS [R+UR+imm] / STSM.8.MT168 / UBLKPF.L2 (canonical 137cd34): +2 sm120 keys (UBLKPF_AURI_UR, UBLKPF_AURI_UR_II), +3 STSM_ARI_R groups, ATOMS_R_ARURI_R MAX,S32 re-measured (variants 20845 -> 20850) = 16135. // 2026-10-28 F2FP.BF16.E8.UNPACK_B_R_R (canonical f1e02b3): +1 sm120 key, variants 20844 -> 20845; 2026-10-25 CCTL (canonical 8d26508): +7 mod groups in CCTL_ARI (E,PF1/WB/IV/RS/PML2/RML2 + DML2,E), keys unchanged 16132, variants 20837 -> 20844
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
