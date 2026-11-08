//! BUG-474 pins (F2-iter285, loop5/blind front2, 2026-09-17): the plain (nNA)
//! E*L2.256 ARURI U32 sibling (b75 = 0) -- the '_ARURI' twins of the WHOLE plain
//! ARURI64 family on 4 legs (464 base 6 / 465 lattice / 468 LTC sel; 3456 donors per
//! leg -> +3454 / +3454 / +3454 / +3455 keys; skipped cells pre-claimed: x3
//! LDG + STG.EL.ELL2.256.STRONG.GPU [the 466 row] + 121a LDG [the 469 row]; the 121a
//! STG twin (466 x3 only) heals that cell). and_base &= ~(1<<75); vm / fields /
//! base_op / ctrl / scheduling verbatim from the donor; count = None.
//! ENGINE printer.rs: format_plain_u32_ur + the flag plain_u32 (keyed by LDG.E. /
//! STG.E. + the E*L2 token + !.NA. + raw b75 == 0): the width always 'U32' (STG
//! [91:90] == 3 must NOT leak '.64', rule 099), base 255 -> the clean elision
//! '[URm(+off)]'. ENCODER: in the Addr{base: None, ur} guard the '_ARURI64' candidates
//! BEFORE '_ARURI' (the 464-arm promise: '[URm]' mints b75 = 1; an explicit
//! '[Rn.U32+URm]' mints the _ARURI row b75 = 0 as a separate key).
//! Vendor law: arb474 (165) + arb474b (62) + arb474c (8) + arb474d (15) probes,
//! nvdisasm 13.3.73 raw -b x4 AGREE EVERY / DIVERGENT = 0 + claim474 227 probes x4
//! (EXACT 3 per leg flip75-ctrl + HOLE 218 per leg + REFUSE-OK 6 per leg, MIS 0).
//! KILL: b91 = 0 rc=1 x4; b76 = 1 REFUSE x4 (there is NO desc form after U32). Encode:
//! the plain-L2 desc forms = sealed parity pre == post (MINTDESC 7 + ENCTAIL 5; the
//! iter286 correction), the explicit U32 mint b75 = 0 (skip sm103a-even-base = the
//! BUG-060 guard parity). Standing:
//! the junk L2 = 3 (INVALID3 / RML2 shared with 469, HOLE parity), inert parity
//! (b83 / the band pinned like the .64 side), the NA-side lattice gap = candidate 485.
//! Data: patch474.py replay from canon_pre (bd48e63 content) byte-exact x4 +
//! idempotent all-skip 13817; audits A0 / A0b (226) / A1 (420-422 heal per leg) / A2 /
//! A3 / A4 (+3454 x3, +3455 121a, the rest byte-equal) / A5 (-> 13721/13721/14859/22688) /
//! A6 / A7 fail-closed. Canonical commit = cc2f62c379c3e190ef373ab9e8f76af0aeef326c (INC-283a: the flip after publish469; flip474b iter286).
//! Witness: tests/bug474_data.inc (machine-built by gen474pins.py rc=2).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;
use std::collections::HashMap;
use std::sync::OnceLock;

include!("bug474_data.inc");

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
/// The legs whose 256-bit LDG / STG family is measured (one row per modifier group, fail-closed on the text-inert
/// bits): sm120 since G's batches 10-13 (2026-11-07); sm103a / sm100a since T-20 / T-21 batch 4 (2026-11-08,
/// `tools/probes/re_sm120_ldg256.py --arch SM103 / SM100` x 3 forms + `re_sm120_stg256.py --arch SM103 / SM100`,
/// nvdisasm 13.1 -- every form word prints the SM120 text on both targets; fixtures
/// `tests/fixtures/sm103a_*256*_nvdisasm.jsonl` / `sm100a_*`, tests `tests/sm103a_sm100a_*256*.rs`).
/// sm121a since T-21 batch 5 (2026-11-08): the same five probes with `--arch SM121 --witnesses` (the GB10 census words
/// of the forms) -- every form word prints the SM120 text; `tests/sm121a_{ldg256_dari,ldg256_aruri64,ldg256_aruri,stg256,redg_aruri}.rs`.
fn measured256(leg: &str) -> bool {
    matches!(leg, "sm120" | "sm103a" | "sm100a" | "sm121a")
}

/// t474_1: heal-decode -- graft-celle b75=0 (cala lattice plain nNA; law
/// 250 sond + claim474 HOLE) dekoduje DOKLADNIE tekst vendora x4; cold
/// (publish-pending 469) HOLE potwierdzone maszynowo w generatorze.
#[test]
fn t474_1_heal_decode() {
    for (w, leg, want) in HEAL474 {
        let got = dec(leg, *w);
        // 2026-11-07 (session G, batch 12, tools/probes/re_sm120_ldg256.py): the measured sm120 rows of the
        // 256-bit load's U32 uniform-indexed form (`LDG_R_R_ARURI[_II][_P]`) fail closed on the text-inert bits
        // 83 / 92-95 (T-10's convention for measured rows, as batches 10-11); the `L99.set92` cell carries bit 92.
        // T-21 batch 4 (2026-11-08): the same measured rows on sm103a / sm100a (`measured256`); sm121a is untouched.
        if measured256(leg) && (*w & 0xfff) == 0x97e && (*w & ((1u128 << 83) | (0xfu128 << 92))) != 0 {
            assert_eq!(got, None, "[{leg}] heal {w:#034x}: inert bits fail closed (G batch 12 / T-21 batch 4)");
            continue;
        }
        // Batch 13 (tools/probes/re_sm120_stg256.py): the 256-bit store's measured rows fail closed on [74:72] / 83 / 87 /
        // [95:92] the same way (the store has no LTC width and no trailing predicate).
        if measured256(leg) && (*w & 0xfff) == 0x97f && (*w & ((7u128 << 72) | (1u128 << 83) | (1u128 << 87) | (0xfu128 << 92))) != 0 {
            assert_eq!(got, None, "[{leg}] heal {w:#034x}: inert bits fail closed (G batch 13 / T-21 batch 4)");
            continue;
        }
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] heal {w:#034x}");
    }
}

/// t474_2: edge -- 121a STG skip-cell heal przez twin (466 x3-only; na x3
/// winnerem zostaje 466-row, pokryte ANCH474 przez migracje cold!=None).
#[test]
fn t474_2_edge_121a_stg() {
    for (w, leg, want) in EDGE474 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] edge {w:#034x}");
    }
}

/// t474_3: anchors -- junk L2=3 / inert-parity / b86-zone / refuse-b76 /
/// ctrl64-side: pin = COLD werdykt (tekst albo "" = HOLE); pre==post.
#[test]
fn t474_3_anchor_parity() {
    for (w, leg, cold) in ANCH474 {
        let got = dec(leg, *w);
        // 2026-11-07 (session G, batch 12, tools/probes/re_sm120_ldg256.py): five `b86-zone` drills -- the cache
        // codes 4 (EU) and 5 (NA) with no scope, NA with ELL2 / LTC128B / the trailing byte -- are legal words
        // nvdisasm 13.1 names on SM120 / SM103 / SM100; the 2026-09 HOLE stood on the harvest's silence. The measured
        // `LDG_R_R_ARURI[_II]` rows claim them on sm120 (the bug464 `.C3.ldg_b86` precedent of batch 11) -- and on
        // sm103a / sm100a since T-21 batch 4 (`measured256`: the probes with `--arch SM103 / SM100` print the same texts).
        let measured_legal: Option<&str> = if !measured256(leg) { None } else { match *w {
            0x000be4000840012cfe0000261c30197e => Some("@P1 LDG.E.EU.EFL2.256 R44, R48, [R28.U32+UR38]"),
            0x000be4000854012cfe0000261c30197e => Some("@P1 LDG.E.NA.ELL2.256 R44, R48, [R28.U32+UR38]"),
            0x000be4000850052cfe0000261c30197e => Some("@P1 LDG.E.NA.EFL2.LTC128B.256 R44, R48, [R28.U32+UR38]"),
            0x000be4000850012c320000261c30197e => Some("@P1 LDG.E.NA.EFL2.256 R44, R48, [R28.U32+UR38], 0x99"),
            0x000be4000850012cfe0000261c30197e => Some("@P1 LDG.E.NA.EFL2.256 R44, R48, [R28.U32+UR38]"),
            // batch 13: the store twin of the EU drill (`STG_ARURI_R_R`, group `256,E,EFL2,EU`)
            0x000be4000f400026f800002c1c30197f => Some("@P1 STG.E.EU.EFL2.256 [R28.U32+UR38], R44, R48"),
            0x000be4000f540026f800002c1c30197f => Some("@P1 STG.E.NA.ELL2.256 [R28.U32+UR38], R44, R48"),
            0x000be4000d5000260000002c1c30197f => Some("@P1 STG.E.NA.EFL2.256 [R28.U32+UR38], R44, R48, 0xa0"),
            _ => None,
        } };
        if let Some(text) = measured_legal {
            assert_eq!(got.as_deref(), Some(text), "[{leg}] anchor (measured legal, G batch 12 / T-21 batch 4) {w:#034x}");
            continue;
        }
        if cold.is_empty() {
            assert!(got.is_none(), "[{leg}] anchor-drill {w:#034x} -> {got:?}");
        } else {
            assert_eq!(got.as_deref(), Some(*cold), "[{leg}] anchor {w:#034x}");
        }
    }
}

/// t474_4: kills -- b91=0 (vendor rc=1 x4) + vendor-REFUSE: engine HOLE.
#[test]
fn t474_4_kill_parity() {
    for (w, leg) in KILL474 {
        let got = dec(leg, *w);
        assert!(got.is_none(), "[{leg}] kill-claim {w:#034x} -> {got:?}");
    }
}

/// t474_5: mint explicit-U32 -- tekst '[Rn.U32+URm(+off)]' na E*L2 lattice
/// mintuje wiersz _ARURI (slowo b75=0), decode circle == tekst, x4 nogi.
#[test]
fn t474_5_mint_explicit_u32() {
    for (text, leg) in MINT474 {
        let w = enc(leg, text).unwrap_or_else(|e| panic!("[{leg}] mint {text:?}: {e}"));
        assert_eq!((w >> 75) & 1, 0, "[{leg}] mint b75!=0 {text:?}: {w:#034x}");
        let back = dec(leg, w);
        assert_eq!(back.as_deref(), Some(*text), "[{leg}] mint circle {text:?}");
    }
}

/// t474_6: elide '[URm(+off)]' -- obietnica 464-arm utrzymana (kandydat
/// _ARURI64 PRZED _ARURI): slowo b75=1, baza 255, circle == tekst, x4 nogi.
/// ENCTAIL474: desc-formy refuse = sealed parity cold==hot (fail-closed).
#[test]
fn t474_6_elide_mint_464arm() {
    for (text, leg) in MINTELIDE474 {
        let w = enc(leg, text).unwrap_or_else(|e| panic!("[{leg}] elide {text:?}: {e}"));
        assert_eq!((w >> 75) & 1, 1, "[{leg}] elide b75!=1 (464-arm) {text:?}");
        assert_eq!((w >> 24) & 0xff, 255, "[{leg}] elide base!=255 {text:?}");
        let back = dec(leg, w);
        assert_eq!(
            back.as_deref(),
            Some(*text),
            "[{leg}] elide circle {text:?}"
        );
    }
    for (text, leg) in ENCTAIL474 {
        assert!(
            enc(leg, text).is_err(),
            "[{leg}] enc-standing {text:?} otwarte"
        );
    }
    // RIDE475R3 (INC-289e): tekst opuscil ENCTAIL po 475-graft (gain) --
    // mintujemy bajtowo slowo vendora + circle decode == tekst.
    for (text, leg, want) in MINTGAIN474 {
        let w = enc(leg, text).unwrap_or_else(|e| panic!("[{leg}] mint-gain {text:?}: {e}"));
        assert_eq!(w, *want, "[{leg}] mint-gain word {text:?}");
        assert_eq!(
            dec(leg, w).as_deref(),
            Some(*text),
            "[{leg}] mint-gain circle {text:?}"
        );
    }
}

/// t474_6b: MINTDESC -- desc-formy plain-L2 mintowalne PRE-474 (7/12;
/// dowod iter286: cold /tmp/det469 + canon_pre mintuje identycznym slowem).
/// Graft 474 NIE klaimuje tych komorek: hot word == zapieczetowane cold.
#[test]
fn t474_6b_mintdesc_sealed_parity() {
    for (text, leg, cold_hex) in MINTDESC474 {
        let w = enc(leg, text).unwrap_or_else(|e| panic!("[{leg}] mintdesc {text:?}: {e}"));
        assert_eq!(
            format!("{w:032x}"),
            *cold_hex,
            "[{leg}] mintdesc word drift {text:?}"
        );
        let back = dec(leg, w);
        assert_eq!(
            back.as_deref(),
            Some(*text),
            "[{leg}] mintdesc circle {text:?}"
        );
    }
}

/// t474_7: census + SOURCE pin w stanie POST-FLIP (base_revision ==
/// 68ac5aa; stan pre-flip pending-474 historyczny w galezi przed
/// flip474b -- TESTOWO zawsze fail-closed na drift).
#[test]
fn t474_7_census_and_source() {
    // Current byte-pinned cut; historical fixture provenance remains unchanged.
    const CURRENT_VENDORED_CANON: &str = "7eeed9c07410807231d32c3e1d7697053c27ce71" /* 2026-11-06 T-11 (was c258f8a, T-10) */ /* 2026-11-06 T-10 (was b75cc20, T-9) */;
    assert_eq!(CANON474, "9c0e4ce", "historical fixture revision drift");

    for (leg, want) in CENSUS474 {
        let raw: serde_json::Value =
            serde_json::from_str(&cubit::table::read_table_text(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        assert_eq!(ins.len(), *want, "[{leg}] census drift");
    }
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        src["base_revision"].as_str().unwrap().starts_with(CURRENT_VENDORED_CANON),
        "SOURCE pin drift po flipie"
    );
    // Structured provenance is emitted by sync_table.py; historical free-text
    // flip notes are not part of its manifest schema.
    assert_eq!(src["tables"]["sm120.json"]["base_sha256"],
        "b7cdbbb4df76cc27b3fe2b92bd2869ebd687e6243a7855dfdf3f4d06a1528ba5");
    assert_eq!(src["tables"]["sm120.json"]["instruction_forms"], 979); // T-19 2026-11-08: the long tail closed, 111 -> 7 rows without _src // 2026-11-08 T-18 (canonical 3fb3b82: 32 whole-key twins retired as aliases) // 2026-11-08 T-18 (canonical 3fb3b82: the 192 wave-pinned rows measured / aliased) // re-pinned on sm120 for the long tail (G run 5 batch 16 re-applied by T-17 on the batches 12-15 base, 3fb3b82) // re-pinned 2026-11-07 (T-16: G run 5 batch 15 — the tensor-core long tail verified row by row — on the batches 12-14 base) // re-pinned 2026-11-07 (G batch 14: REDG uniform-indexed forms measured whole) // re-pinned 2026-11-07 (G batch 13: STG.256 measured whole) // re-pinned 2026-11-07 (G batch 12: LDG.256 ARURI measured whole) // re-pinned 2026-11-07 (G batch 11: LDG.256 ARURI64 measured whole) // re-pinned 2026-11-07 (G batch 10: LDG.256 dARI measured whole) // G batch 9 FSET / FSEL / FCHK 2026-11-07 // G batch 8 conversions 2026-11-07 // G batch 7 uniform FP32 ALU 2026-11-07 // G batch 6 FP32 ALU 2026-11-07 // 2026-11-06 G (canonical 3fb3b82): UFSETP measured, 6 junk keys retired as aliases: sm120 15840 -> 15834 forms, 26442 -> 26341 variants // 2026-11-06 G (canonical 3fb3b82): PLOP3 / P2R / R2P measured, 10 junk keys retired as aliases, R2P_II_R added: sm120 15849 -> 15840 forms, 26451 -> 26442 variants // 2026-11-06 G (canonical 3fb3b82): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 3fb3b82): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 2026-11-06 T-11 (canonical 3fb3b82: the IDP family measured whole + the audit exceptions): 15953 -> 15964 // 2026-11-06 T-10 (canonical 315bffa): sm120 16045 -> 15935 forms, 26646 -> 26562 variants; sm103a / sm100a 14912 -> 14913, 22363 -> 22420  // 2026-11-06 T-9 BRA family (canonical b75cc20): 16054 -> 16045 // 2026-11-06 T-8 (LEA family rebuilt, F2FP twins + 9 junk keys retired, ATOMS_R_ARURI_R 36 measured groups; canonical 7094efc+): sm120 16097 -> 16054 forms, 26663 -> 26611 variants // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // 2026-11-05 T-6 item 2 (T-5's SHF + LDTM/STTM rows on the wave-11 tables, canonical 377b507): sm120 keys 16143 -> 16103 (-40 dotted SHF), variants 26612 -> 26656; sm100a/sm103a variants 22199 -> 22340; loader sm120 16123 // 2026-11-04 (canonical T-3 batches): forms 16107 / variants 20894 (-20 era keys -> _meta.key_aliases, +LDL_R_ARURI, MUFU_R_UR rebuilt, IMAD alias groups -> U32 twins, F2F_R_R F32,F64 removed) // 2026-11-03 dynamic-audit batch 1 (canonical 6619782): -12 sm120 keys / -22 variants (FSETP_P_P_L_FI_P, FSETP_P_P_L_L_P, F2FP.F16.F32.PACK_AB_P_R_R_R, HMMA *_P0_* rows, LOP3.LUT_P_R_R_R_R_II_P, QMMA.16816.F16.E4M3.E4M3_P_R_R_R_R: their words are other instructions for nvdisasm) = 16126 forms, 20883 variants; LDGSTS base field 8 bits, LDC/LDCU reuse field removed; hygiene pass (canonical 64eaa21) cleared the baked control bits, counts unchanged. // 2026-11-02 HMUL2 imm / LDSM FP4-FP6 / PRMT UR / ARRIVES.LDGSTSBAR / UTMASTG dims (canonical 77a3dfa): +3 sm120 keys (HMUL2_R_R_FI_FI, PRMT_R_R_UR_R, ARRIVES_ARURI), +30 LDSM_R_ARI and +4 UTMASTG groups (variants 20850 -> 20905) = 16138. // 2026-10-29 ATOMS [R+UR+imm] / STSM.8.MT168 / UBLKPF.L2 (canonical 137cd34): +2 sm120 keys (UBLKPF_AURI_UR, UBLKPF_AURI_UR_II), +3 STSM_ARI_R groups, ATOMS_R_ARURI_R MAX,S32 re-measured (variants 20845 -> 20850) = 16135. // 2026-10-28 F2FP.BF16.E8.UNPACK_B_R_R (canonical f1e02b3): +1 sm120 key
    assert_eq!(src["tables"]["sm120.json"]["encoding_variants"], 38838); // T-19 2026-11-08: the long tail closed, 111 -> 7 rows without _src // 2026-11-08 T-18 (canonical 3fb3b82: 32 whole-key twins retired as aliases) // 2026-11-08 T-18 (canonical 3fb3b82: the 192 wave-pinned rows measured / aliased) // re-pinned on sm120 for the long tail (G run 5 batch 16 re-applied by T-17 on the batches 12-15 base, 3fb3b82) // re-pinned 2026-11-07 (T-16: G run 5 batch 15 — the tensor-core long tail verified row by row — on the batches 12-14 base) // re-pinned 2026-11-07 (G batch 14: REDG uniform-indexed forms measured whole) // re-pinned 2026-11-07 (G batch 13: STG.256 measured whole) // re-pinned 2026-11-07 (G batch 12: LDG.256 ARURI measured whole) // re-pinned 2026-11-07 (G batch 11: LDG.256 ARURI64 measured whole) // re-pinned 2026-11-07 (G batch 10: LDG.256 dARI measured whole) // G batch 9 FSET / FSEL / FCHK 2026-11-07 // G batch 8 conversions 2026-11-07 // G batch 7 uniform FP32 ALU 2026-11-07 // G batch 6 FP32 ALU 2026-11-07 // 2026-11-06 G (canonical 3fb3b82): UFSETP measured, 6 junk keys retired as aliases: sm120 15840 -> 15834 forms, 26442 -> 26341 variants // 2026-11-06 G (canonical 3fb3b82): PLOP3 / P2R / R2P measured, 10 junk keys retired as aliases, R2P_II_R added: sm120 15849 -> 15840 forms, 26451 -> 26442 variants // 2026-11-06 G (canonical 3fb3b82): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 3fb3b82): ISETP / UISETP measured, 67 groups added: sm120 26595 -> 26662 variants // 2026-11-06 G (canonical 3fb3b82): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 2026-11-06 T-11 (canonical 3fb3b82): 26580 -> 26598 // 2026-11-06 T-10 (canonical 315bffa): sm120 16045 -> 15935 forms, 26646 -> 26562 variants; sm103a / sm100a 14912 -> 14913, 22363 -> 22420  // 2026-11-06 T-9 BRA family (canonical b75cc20): 26611 -> 26646 // 2026-11-06 T-8 (LEA family rebuilt, F2FP twins + 9 junk keys retired, ATOMS_R_ARURI_R 36 measured groups; canonical 7094efc+): sm120 16097 -> 16054 forms, 26663 -> 26611 variants // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // 2026-11-05 T-6 item 2 (T-5's SHF + LDTM/STTM rows on the wave-11 tables, canonical 377b507): sm120 keys 16143 -> 16103 (-40 dotted SHF), variants 26612 -> 26656; sm100a/sm103a variants 22199 -> 22340; loader sm120 16123 // 2026-11-04 (canonical T-3 batches): forms 16107 / variants 20894 (-20 era keys -> _meta.key_aliases, +LDL_R_ARURI, MUFU_R_UR rebuilt, IMAD alias groups -> U32 twins, F2F_R_R F32,F64 removed) // 2026-11-03 dynamic-audit batch 1 (canonical 6619782): -12 sm120 keys / -22 variants (FSETP_P_P_L_FI_P, FSETP_P_P_L_L_P, F2FP.F16.F32.PACK_AB_P_R_R_R, HMMA *_P0_* rows, LOP3.LUT_P_R_R_R_R_II_P, QMMA.16816.F16.E4M3.E4M3_P_R_R_R_R: their words are other instructions for nvdisasm) = 16126 forms, 20883 variants; LDGSTS base field 8 bits, LDC/LDCU reuse field removed; hygiene pass (canonical 64eaa21) cleared the baked control bits, counts unchanged. // 2026-11-02 HMUL2 imm / LDSM FP4-FP6 / PRMT UR / ARRIVES.LDGSTSBAR / UTMASTG dims (canonical 77a3dfa): +3 sm120 keys (HMUL2_R_R_FI_FI, PRMT_R_R_UR_R, ARRIVES_ARURI), +30 LDSM_R_ARI and +4 UTMASTG groups (variants 20850 -> 20905) = 16138. // 2026-10-29 ATOMS [R+UR+imm] / STSM.8.MT168 / UBLKPF.L2 (canonical 137cd34): +2 sm120 keys (UBLKPF_AURI_UR, UBLKPF_AURI_UR_II), +3 STSM_ARI_R groups, ATOMS_R_ARURI_R MAX,S32 re-measured (variants 20845 -> 20850) = 16135. // 2026-10-28 F2FP.BF16.E8.UNPACK_B_R_R (canonical f1e02b3): +1 sm120 key, variants 20844 -> 20845; 2026-10-25 CCTL (canonical 8d26508): +7 mod groups in CCTL_ARI (E,PF1/WB/IV/RS/PML2/RML2 + DML2,E), keys unchanged 16132, variants 20837 -> 20844
}
