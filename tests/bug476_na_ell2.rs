//! BUG-476 pins (F2-iter291/292, loop5/blind front2, 2026-09-17): the plain
//! ELL2.256 dARI-era side bits, standing -- 476a the NA-side graft + 476b the phantom
//! _II. 476a: NA clones of the EL donors, delta 0x7@[86:84] (the EL nibble 0x2 -> NA
//! 0x5) measured verbatim from the 466 pairs; vm / fields / ctrl / scheduling verbatim,
//! count removed, _src476. LDG on 4 legs (+8: STRONG.GPU_R_R_ARURI64; LTC{64B,128B,
//! 256B}.256.STRONG.GPU_R_R_ARURI{,64}; CONSTANT.GPU_R_R_ARURI{,64}; witness:
//! Sna.b75b73 / b75b74 heal through the clone-64 on the vm side) + STG on 3 legs (+3:
//! STRONG.GPU_ARURI64_R_R; MMIO.SYS.ORDERED_ARURI_R_R{,64}; the 121a STG-NA base is
//! absent -> 121a parity [NT], NOT grafted). NOT grafted: LTC256B x b75 (not probed),
//! _II/_P, the b81 LDG era split INVALID3 / RML2 + b85-NA E.INVALID7 + b81-STG INVALID3
//! x4 (standing-loud 285 / 440; the 476c ledger). 476b: STG.E.EL.ELL2.256.STRONG.GPU_
//! ARURI_R_R_II (_src474) printed a phantom ', 0xff' on Sel.{b73, b74, b73b74} (the
//! unnamed fields {72,73,87} -> token 4); the vendor's b73 / b74 are INERT here x4 ->
//! claim_forbid [74:73] in {1,2,3} = HOLE parity (exposure ab240 ZERO, census476). 121a
//! NOT touched (the winner _ARURI_R_R EXACT pre == post). ENGINE: zero source changes.
//! Vendor law: arb476 72 probes + arb476b 4 combos, nvdisasm 13.3.73 raw -b x4 AGREE
//! EVERY except the b81 split. Data: patch476.py replay byte-exact x4 + idempotent
//! all-skip 44; audits A0 / A0b (29) / A1 (heal 29/29/29/16; the b476 hole 3x3) / A2 /
//! A3 / A4 (+11/+11/+11/+8; touched == the 476b key x3) / A5 (14879/14879/16016/23833;
//! cf 1170/1170/1167/1183) fail-closed. Canonical commit =
//! cc2f62c379c3e190ef373ab9e8f76af0aeef326c (serialisation INC-283a: after publish475;
//! the flip476b phase B). Census476b: 771 keys per leg with the {72,73,87}-token-4
//! pattern -- out of scope without a per-frame law (the report's annex).
//! Witness: tests/bug476_data.inc (machine-built by gen476pins.py rc=2; the class
//! matrix locked x patch476_log.json A1 / A5: HEAL 29x3+16, B476 3x3 + keep 3, INERT
//! 12+1, BASE 131, STANDING 32, CORPUS 36, MINT 234 rows (220 exact + 14 inert-canon
//! round trip; INC-299a: the generator's emission set on the round-trip class from the
//! docstring, round trip 44 in total).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;
use std::collections::HashMap;
use std::sync::OnceLock;

include!("bug476_data.inc");

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

/// t476_1: heal -- NA-klony 476a dekoduja DOKLADNIE tekst vendora x komorki
/// prawa (29 tagow x3 nogi + 16 na 121a); cold==HOLE (sygnatura generatora).
#[test]
fn t476_1_heal_decode() {
    for (w, leg, _key, want, tag) in HEAL476 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] heal {tag} {w:#034x}");
    }
}

/// t476_2: 476b -- fantom-print ', 0xff' NIESTY: HOLE-parity x3 nogi +
/// 121a EXACT keep (_ARURI_R_R winner pre==post, NIE ruszane).
#[test]
fn t476_2_b476_hole_and_121a_keep() {
    // WAVE-11 INTEGRATION (2026-11-05): the b73/b74 selector words below are NOT
    // holes. The lane's STG.E.EL/NA.ELL2.256 row carries the measured claim_forbid
    // on [63:59] (values 0..30) and [90:88] (0..6); these words sit at 31 and 7 --
    // the legal corner -- and nvdisasm 13.4 renders all three of them identically:
    //
    //   @P0 STG.E.EL.ELL2.256.STRONG.GPU [R28.U32+UR4], R0, R0
    //
    // The pre-integration expectation ("HOLE") came from a table that had no such
    // row at all. What the test must still prove is the part that was right:
    // the cold era printed a phantom `, 0xff` tail (the BUG-476b defect), and the
    // b73/b74 bits never reach the text.
    for (w, leg, cold_wrong, tag, _kind) in B476HOLE476 {
        let got = dec(leg, *w);
        let text = got
            .as_deref()
            .unwrap_or_else(|| panic!("[{leg}] 476b {tag} {w:#034x} -> HOLE"));
        assert_eq!(
            text, "@P0 STG.E.EL.ELL2.256.STRONG.GPU [R28.U32+UR4], R0, R0",
            "[{leg}] 476b {tag} {w:#034x}"
        );
        assert!(
            !text.contains("0xff"),
            "[{leg}] 476b {tag} {w:#034x}: cold phantom tail came back"
        );
        assert!(
            cold_wrong.contains("0xff"),
            "swiadek zimnego fantomu zgubiony"
        );
    }
    for (w, leg, want, tag, _kind) in B476KEEP476 {
        let got = dec(leg, *w);
        assert_eq!(
            got.as_deref(),
            Some(*want),
            "[{leg}] 121a-keep {tag} {w:#034x}"
        );
    }
}

/// t476_3: inert-hole -- vendor-legal LTC-inert STG (b73/b74 bez .64).
///
/// WAVE-11 INTEGRATION (2026-11-05): the expectation is now PER LEG, because the
/// legs genuinely differ and the difference is the point:
///
///   sm100a / sm103a / sm120 -- the lane's STG.E.NA.ELL2.256 row models this
///     geometry, so the word decodes to exactly the vendor text the fixture
///     records. The old "HOLE" came from a table that had no such row.
///   sm121a -- still a coverage gap: that table is delta-driven and never got the
///     row. Kept as a fail-closed HOLE and asserted as such, so the gap stays
///     visible instead of being papered over.
#[test]
fn t476_3_inert_hole() {
    for (w, leg, vend, tag, _kind) in INERTHOLE476 {
        let got = dec(leg, *w);
        if *leg == "sm121a" {
            assert!(
                got.is_none(),
                "[{leg}] inert-hole {tag} {w:#034x} -> {got:?} (expected the known coverage gap)"
            );
        } else {
            assert_eq!(got.as_deref(), Some(*vend), "[{leg}] inert-hole {tag} {w:#034x}");
        }
    }
}

/// t476_4: base-ident -- kotwice 466/474-era (EL ramy, NA baze) hot==cold==
/// vendor tekst (asercja maszynowa w generatorze; tu: == vendor).
#[test]
fn t476_4_base_ident() {
    for (w, leg, want, tag, _kind) in BASE476 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] base {tag} {w:#034x}");
    }
}

/// t476_5: standing-loud -- b81 era-split / b85 INVALID7: NIGDY kluczem;
/// pin = hot==cold werdykt zapisany w generatorze ("" = HOLE).
#[test]
fn t476_5_standing() {
    for (w, leg, want, tag, _kind) in STANDING476 {
        let got = dec(leg, *w);
        if want.is_empty() {
            assert!(got.is_none(), "[{leg}] standing {tag} {w:#034x} -> {got:?}");
        } else {
            assert_eq!(
                got.as_deref(),
                Some(*want),
                "[{leg}] standing {tag} {w:#034x}"
            );
        }
    }
}

/// t476_6: mint -- encode tekstu vendora: instr-bits [95:0] == slowo prawa
/// dla klas kanonicznych; piny base255 ('[UR4]' dwuznacznosc b75) + LTC-inert
/// STG combo = klasa (roundtrip): dec(enc(text)) == text. Kontrola/era poza
/// porownaniem (probe 0xbe400 vs kanon enkodera 0xfc200 -- dokument w generatorze).
#[test]
fn t476_6_mint_circle() {
    const CTL: u128 = !((1u128 << 96) - 1);
    for (w, leg, key, text, tag) in MINT476 {
        let m = enc(leg, text).unwrap_or_else(|e| panic!("[{leg}] mint {tag} err {e}"));
        if *key == "(roundtrip)" {
            let rt = dec(leg, m);
            assert_eq!(
                rt.as_deref(),
                Some(*text),
                "[{leg}] roundtrip {tag} {m:#034x}"
            );
        } else {
            assert_eq!(m & !CTL, w & !CTL, "[{leg}] mint {tag} instr-bits");
        }
    }
}

/// t476_7: corpus36 dARI EXACT keep x4 (hot==cold==ref w generatorze).
#[test]
fn t476_7_corpus_exact() {
    for (w, want, _scope, wh, _kind) in CORPUS476 {
        for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
            let got = dec(leg, *w);
            assert_eq!(got.as_deref(), Some(*want), "[{leg}] corpus {wh}");
        }
    }
}

/// t476_8: census + SOURCE -- forms/variants/cf-count lock z A5 patch476;
/// pre-flip: CANON476 pending + base_revision 978c0918 + brak _476_note;
/// post-flip (flip476b): pin na realny commit + note obecna.
#[test]
fn t476_8_census_and_source() {
    // Current byte-pinned cut; historical fixture provenance remains unchanged.
    const CURRENT_VENDORED_CANON: &str = "8aa5f34f25ed2b4ad3008e78ce8ceb93508b9eb2" /* 2026-11-06 T-11 (was c258f8a, T-10) */ /* 2026-11-06 T-10 (was b75cc20, T-9) */;
    assert_eq!(CANON476, "9c0e4ce", "historical fixture revision drift");

    for (leg, want_forms, want_variants, want_cf) in CENSUS476 {
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
        // WAVE-11 INTEGRATION (2026-11-05, canonical e99598a (wave 11; pin now 7094efc)): the snapshot literal below is
        // now the CURRENT variant count. The 20831 it used to hold was the pre-lane base that a
        // +63 delta was added to; the merged table is itself the snapshot.
        if *leg == "sm120" {
            assert_eq!(*want_variants, 32555, "SM120 variants snapshot (T-11)"); // re-pinned 2026-11-07 (G batch 10: LDG.256 dARI measured whole) // G batch 9 FSET / FSEL / FCHK 2026-11-07 // G batch 8 conversions 2026-11-07 // G batch 7 uniform FP32 ALU 2026-11-07 // G batch 6 FP32 ALU 2026-11-07 // 2026-11-06 G (canonical 8aa5f34): UFSETP measured, 6 junk keys retired as aliases: sm120 15840 -> 15834 forms, 26442 -> 26341 variants // 2026-11-06 G (canonical 8aa5f34): PLOP3 / P2R / R2P measured, 10 junk keys retired as aliases, R2P_II_R added: sm120 15849 -> 15840 forms, 26451 -> 26442 variants // 2026-11-06 G (canonical 8aa5f34): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 8aa5f34): ISETP / UISETP measured, 67 groups added: sm120 26595 -> 26662 variants // 2026-11-06 G (canonical 8aa5f34): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 2026-11-06 T-11 (canonical 8aa5f34): 26580 -> 26598 // 2026-11-06 T-10 (canonical 315bffa): sm120 16045 -> 15935 forms, 26646 -> 26562 variants; sm103a / sm100a 14912 -> 14913, 22363 -> 22420  // 2026-11-06 T-9 BRA family (canonical b75cc20): 26611 -> 26646 // ATOMS_R_AURI_R [EXCH] retired: 26612 -> 26611 // 2026-11-06 T-8 ATOMS_R_ARURI_R rebuilt (36 groups) + 9 junk keys retired (canonical 5222c58): sm120 keys 16063 -> 16054, variants 26596 -> 26612, loader 16074 // 2026-11-06 T-8 F2FP twins retired (canonical 09a7141): sm120 keys 16065 -> 16063, variants 26599 -> 26596, loader 16083 // 2026-11-06 T-8 (LEA family rebuilt from measurement, tools/probes/re_sm120_lea.py): sm120 keys 16097 -> 16065 (56 LEA keys -> 24), variants 26663 -> 26599, loader 16085; sm103a / sm100a keys 14906 -> 14912 (18 -> 24), variants 22348 -> 22363 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // 
 // 2026-11-05 T-6 item 2 (T-5's SHF + LDTM/STTM rows on the wave-11 tables, canonical 377b507): sm120 keys 16143 -> 16103 (-40 dotted SHF), variants 26612 -> 26656; sm100a/sm103a variants 22199 -> 22340; loader sm120 16123
        }
        // 2026-10-28: + the F2FP.BF16.E8.UNPACK_B_R_R row (UE8M0 -> BF16x2; canonical f1e02b3) = 14.
        // 2026-10-29: + the three STSM.8.MT168 groups and the two UBLKPF.L2 rows (canonical 137cd34) = 19.
        // 2026-11-02: + 12 HMUL2_R_R_FI_FI + 30 LDSM FP4/FP6 + 7 PRMT_R_R_UR_R + 2 ARRIVES_ARURI + 4 UTMASTG groups (canonical 77a3dfa) = 74.
        // 2026-11-03: - 22 rows whose words are other instructions for nvdisasm (dynamic-audit batch 1, canonical 6619782) = 52.
        // 2026-11-04: - 20 era keys (now _meta.key_aliases) + 14 LDL_R_ARURI + 22 MUFU_R_UR (4 -> 26) - 3 IMAD (7 alias groups
        //             -> 4 U32 twins) - 1 F2F_R_R 'F32,F64' + 1 (MUFU/F2F rebuild accounting; canonical 6f11f6b) = 63.
        // WAVE-11 INTEGRATION (2026-11-05, canonical e99598a (wave 11; pin now 7094efc)): the CENSUS476 table below now carries the
        // CURRENT measured values (the ATOM/ATOMG BUG-509 enumeration alone is +5747 rows, each with the
        // silicon-confirmed claim_forbid on [63:60]), so the historical "+63 delta" accounting is gone: the
        // tuple *is* the snapshot. Adjudicated in pubwave/wave11/INTEGRATION.md.
        let current_variants = *want_variants;
        assert_eq!(variants, current_variants, "[{leg}] variants census drift");
        // errata pseudo-entries (sm121a) nie maja mod_groups -> traktowane
        // jako 0, dokladnie jak A5 patch476 (.get('mod_groups', {})); INC-299a
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
        src["base_revision"].as_str().unwrap().starts_with(CURRENT_VENDORED_CANON),
        "SOURCE pin drift po flipie"
    );
    // Structured provenance is emitted by sync_table.py; historical free-text
    // flip notes are not part of its manifest schema.
    assert_eq!(src["tables"]["sm120.json"]["base_sha256"],
        "5f0c6a63fc5f05dc7e427a11e8b0dfb558e7419ca04ee7d3107f34e396ebb90f");
    assert_eq!(src["tables"]["sm120.json"]["instruction_forms"], 14805) /* 2026-11-06 T-11 (canonical 8aa5f34): 15953 -> 14805 */; // re-pinned 2026-11-07 (G batch 10: LDG.256 dARI measured whole) // G batch 9 FSET / FSEL / FCHK 2026-11-07 // G batch 8 conversions 2026-11-07 // G batch 7 uniform FP32 ALU 2026-11-07 // G batch 6 FP32 ALU 2026-11-07 // 2026-11-06 G (canonical 8aa5f34): UFSETP measured, 6 junk keys retired as aliases: sm120 15840 -> 15834 forms, 26442 -> 26341 variants // 2026-11-06 G (canonical 8aa5f34): PLOP3 / P2R / R2P measured, 10 junk keys retired as aliases, R2P_II_R added: sm120 15849 -> 15840 forms, 26451 -> 26442 variants // 2026-11-06 G (canonical 8aa5f34): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 8aa5f34): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 2026-11-06 T-10 (canonical 315bffa): sm120 16045 -> 15935 forms, 26646 -> 26562 variants; sm103a / sm100a 14912 -> 14913, 22363 -> 22420  // 2026-11-06 T-9 BRA family (canonical b75cc20): 16054 -> 16045 // 2026-11-06 T-8 (LEA family rebuilt, F2FP twins + 9 junk keys retired, ATOMS_R_ARURI_R 36 measured groups, ATOMS_R_AURI_R [EXCH] retired; canonical 7094efc): sm120 16097 -> 16054 forms, 26663 -> 26611 variants // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // 2026-11-05 T-6 item 2 (T-5's SHF + LDTM/STTM rows on the wave-11 tables, canonical 377b507): sm120 keys 16143 -> 16103 (-40 dotted SHF), variants 26612 -> 26656; sm100a/sm103a variants 22199 -> 22340; loader sm120 16123 // 2026-11-04 (canonical T-3 batches b063d43/15caf70/6f11f6b): -20 era keys retired into _meta.key_aliases, +1 LDL_R_ARURI = 16107 forms, 20894 variants (re-pinned by R, the one census pin T-3 missed). // 2026-11-03 dynamic-audit batch 1 (canonical 6619782): -12 sm120 keys / -22 variants (FSETP_P_P_L_FI_P, FSETP_P_P_L_L_P, F2FP.F16.F32.PACK_AB_P_R_R_R, HMMA *_P0_* rows, LOP3.LUT_P_R_R_R_R_II_P, QMMA.16816.F16.E4M3.E4M3_P_R_R_R_R: their words are other instructions for nvdisasm) = 16126 forms, 20883 variants; LDGSTS base field 8 bits, LDC/LDCU reuse field removed; hygiene pass (canonical 64eaa21) cleared the baked control bits, counts unchanged. // 2026-11-02 HMUL2 imm / LDSM FP4-FP6 / PRMT UR / ARRIVES.LDGSTSBAR / UTMASTG dims (canonical 77a3dfa): +3 sm120 keys (HMUL2_R_R_FI_FI, PRMT_R_R_UR_R, ARRIVES_ARURI), +30 LDSM_R_ARI and +4 UTMASTG groups (variants 20850 -> 20905) = 16138. // 2026-10-29 ATOMS [R+UR+imm] / STSM.8.MT168 / UBLKPF.L2 (canonical 137cd34): +2 sm120 keys (UBLKPF_AURI_UR, UBLKPF_AURI_UR_II), +3 STSM_ARI_R groups, ATOMS_R_ARURI_R MAX,S32 re-measured (variants 20845 -> 20850) = 16135. // 2026-10-28 F2FP.BF16.E8.UNPACK_B_R_R (canonical f1e02b3): +1 sm120 key
    assert_eq!(src["tables"]["sm120.json"]["encoding_variants"], 32555) /* 2026-11-06 T-11 (canonical 8aa5f34): 26580 -> 32555 */; // re-pinned 2026-11-07 (G batch 10: LDG.256 dARI measured whole) // G batch 9 FSET / FSEL / FCHK 2026-11-07 // G batch 8 conversions 2026-11-07 // G batch 7 uniform FP32 ALU 2026-11-07 // G batch 6 FP32 ALU 2026-11-07 // 2026-11-06 G (canonical 8aa5f34): UFSETP measured, 6 junk keys retired as aliases: sm120 15840 -> 15834 forms, 26442 -> 26341 variants // 2026-11-06 G (canonical 8aa5f34): PLOP3 / P2R / R2P measured, 10 junk keys retired as aliases, R2P_II_R added: sm120 15849 -> 15840 forms, 26451 -> 26442 variants // 2026-11-06 G (canonical 8aa5f34): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 8aa5f34): ISETP / UISETP measured, 67 groups added: sm120 26595 -> 26662 variants // 2026-11-06 G (canonical 8aa5f34): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 2026-11-06 T-10 (canonical 315bffa): sm120 16045 -> 15935 forms, 26646 -> 26562 variants; sm103a / sm100a 14912 -> 14913, 22363 -> 22420  // 2026-11-06 T-9 BRA family (canonical b75cc20): 26611 -> 26646 // 2026-11-06 T-8 (LEA family rebuilt, F2FP twins + 9 junk keys retired, ATOMS_R_ARURI_R 36 measured groups, ATOMS_R_AURI_R [EXCH] retired; canonical 7094efc): sm120 16097 -> 16054 forms, 26663 -> 26611 variants // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // 2026-11-05 T-6 item 2 (T-5's SHF + LDTM/STTM rows on the wave-11 tables, canonical 377b507): sm120 keys 16143 -> 16103 (-40 dotted SHF), variants 26612 -> 26656; sm100a/sm103a variants 22199 -> 22340; loader sm120 16123 // 2026-11-04: see above. // 2026-11-03 dynamic-audit batch 1 (canonical 6619782): -12 sm120 keys / -22 variants (FSETP_P_P_L_FI_P, FSETP_P_P_L_L_P, F2FP.F16.F32.PACK_AB_P_R_R_R, HMMA *_P0_* rows, LOP3.LUT_P_R_R_R_R_II_P, QMMA.16816.F16.E4M3.E4M3_P_R_R_R_R: their words are other instructions for nvdisasm) = 16126 forms, 20883 variants; LDGSTS base field 8 bits, LDC/LDCU reuse field removed; hygiene pass (canonical 64eaa21) cleared the baked control bits, counts unchanged. // 2026-11-02 HMUL2 imm / LDSM FP4-FP6 / PRMT UR / ARRIVES.LDGSTSBAR / UTMASTG dims (canonical 77a3dfa): +3 sm120 keys (HMUL2_R_R_FI_FI, PRMT_R_R_UR_R, ARRIVES_ARURI), +30 LDSM_R_ARI and +4 UTMASTG groups (variants 20850 -> 20905) = 16138. // 2026-10-29 ATOMS [R+UR+imm] / STSM.8.MT168 / UBLKPF.L2 (canonical 137cd34): +2 sm120 keys (UBLKPF_AURI_UR, UBLKPF_AURI_UR_II), +3 STSM_ARI_R groups, ATOMS_R_ARURI_R MAX,S32 re-measured (variants 20845 -> 20850) = 16135. // 2026-10-28 F2FP.BF16.E8.UNPACK_B_R_R (canonical f1e02b3): +1 sm120 key, variants 20844 -> 20845; 2026-10-25 CCTL (canonical 8d26508): +7 mod groups in CCTL_ARI (E,PF1/WB/IV/RS/PML2/RML2 + DML2,E), keys unchanged 16132, variants 20837 -> 20844
}
