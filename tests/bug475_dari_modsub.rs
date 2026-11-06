//! BUG-475 pins (F2-iter287/288, loop5/blind front2, 2026-09-17): dARI modsub
//! lattice (b76=1) na frame E*L2.256 (LDG 0x97e / STG 0x97f, desc[URx][Ry.64])
//! -- klon 6 donorow *_dARI EFL2.256/noga (LDG x4 {,_P,_II,_II_P}, STG x2
//! {_II}) na kratke 191 kombinacji/op (l1,l2,sem \ baza; l2!=3) = +1146
//! kluczy/noga; clone zmienia TYLKO and_base (piny [77:86), b76=1) + base_op;
//! vm/fields verbatim. REKANON 462-mgs ENL2 (489-absorb): DELETE 13/13/7 mgs
//! ENL2 ltc=0 na widthless-kluczach (puste LDG_R_R_dARI/STG_dARI_R_R kasacja
//! x100a/103a; x120 mg tylko), 121a REPLACE 9 heritage _src462 lattice-named +
//! DELETE 2 anomalie-tokenowe NA/EU (count=0 dead). ENGINE ZERO src (sciezka
//! op dARI sterowana podpisem). Vendor law: arb475 560 sond nvdisasm 13.3.73
//! raw -b x4 AGREE EVERY poza l2=3 (div = wylacznie 64 komorki LDG l2=3
//! era-split standing-463; STG l2=3 glyph INVALID3); kills b91=0 rc=1 x4;
//! ra255 REFUSE x4 (BRAK elizji '[URm]' plain-464); ur255 desc[URZ]; imm
//! podpisane<<5 w nawiasie desc; STG LTC-sel [74:73] inert x4. Data:
//! patch475.py replay z canon_pre (68ac5aa-content) byte-exact x4 + idem
//! all-skip 4584; audity A0/A0b(408)/A1/A2/A4(+1146 -2 key x4)/A5 census
//! (14868/14868/16005/23825)/A9-R2 (+R3/R3b: NA/EU/alias + 121a anomalie) fail-closed. Canonical commit = cc2f62c379c3e190ef373ab9e8f76af0aeef326c
//! (serializacja INC-283a: po publish474; flip475b faza B). Korpus: 36 uniq
//! dARI w ab240 EXACT keep x4 (era-korekta iter288: corpus475_verify_v2).
//! Witness: tests/bug475_data.inc (maszynowe gen475pins.py rc=2; macierz klas
//! lock x claim475 engine-truth; NOTA: A1 split heal/heal462 bylo candidate-
//! based -- generator mierzy slinikowo: 6/6/4/4 vs A1 3/3/3/4; suma zgodna).
//! R3 (F2-iter289, INC-289d): R2 over-delete po mis-klasyfikacji 489 --
//! odtworzenie pokrycia vendor-legal: NA/EU ENL2.256 dARI (klon-okna grafta,
//! NIE verbatim 462 [ur5@32+imm20@37shr2]; arb475r3 27 sond x4 div0/invalid0,
//! cold-MIS=15) + alias-encode ".E.256.ENL2" (LDG_R_R_dARI mg encode_only).
//! collision-sweep 596x4 diffs=0; verify475r3 GATE PASS; 121a bajtowo nietkn.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;
use std::collections::HashMap;
use std::sync::OnceLock;

include!("bug475_data.inc");

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

/// t475_1: heal-decode -- graft-celle b76=1 dARI modsub (lattice E*L2.256)
/// dekoduja DOKLADNIE tekst vendora x4; cold HOLE (kind heal) lub MIS-glyph
/// z 462-era (kind heal462) -- obie strony maszynowo rozroznione w generatorze.
#[test]
fn t475_1_heal_decode() {
    for (w, leg, want, _kind) in HEAL475 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] heal {w:#034x}");
    }
}

/// t475_2: base + LTC -- base-ident EXACT pre==post==vendor (kotwica) +
/// LDG ltc-cross anchor (lane 490: tekst "" = HOLE hot==cold) + STG ltc
/// inert (stg-base EXACT keep / stg-heal na tekst vendora).
#[test]
fn t475_2_base_and_ltc() {
    for (w, leg, want) in BASE475 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] base {w:#034x}");
    }
    for (w, leg, kind, text) in LTC475 {
        let got = dec(leg, *w);
        match *kind {
            "ldg-anchor" => {
                if text.is_empty() {
                    assert!(got.is_none(), "[{leg}] ltc-ldg {w:#034x} -> {got:?}");
                } else {
                    assert_eq!(got.as_deref(), Some(*text), "[{leg}] ltc-ldg {w:#034x}");
                }
            }
            "stg-base" | "stg-heal" => {
                assert_eq!(got.as_deref(), Some(*text), "[{leg}] {kind} {w:#034x}");
            }
            other => panic!("nieznany kind {other}"),
        }
    }
}

/// t475_3: anchors standing -- l2=3 era-split (LDG) + glyph INVALID3 (STG) +
/// div-klasy: pin = COLD werdykt (tekst albo "" = HOLE); pre==post.
#[test]
fn t475_3_anchor_parity() {
    for (w, leg, cold) in ANCH475 {
        let got = dec(leg, *w);
        if cold.is_empty() {
            assert!(got.is_none(), "[{leg}] anchor-drill {w:#034x} -> {got:?}");
        } else {
            assert_eq!(got.as_deref(), Some(*cold), "[{leg}] anchor {w:#034x}");
        }
    }
}

/// t475_4: kills -- b91=0 vendor rc=1 x4 + ra255 REFUSE x4: engine HOLE.
#[test]
fn t475_4_kill_parity() {
    for (w, leg) in KILL475 {
        let got = dec(leg, *w);
        assert!(got.is_none(), "[{leg}] kill-claim {w:#034x} -> {got:?}");
    }
}

/// t475_5: mint-circle -- lattice teksty mintuja slowo; decode circle == tekst
/// x4 (BUG-077/060 polaryzacja: EFL2.256 odd base R29, ENL2/ELL2 even R28;
/// URZ-texts wylaczone -- encoder-side canonical UR63 [pre-existing, nota
/// generatora], pokrycie URZ po stronie decode w HEAL).
#[test]
fn t475_5_mint_circle() {
    for (w, leg, text) in MINT475 {
        let got = enc(leg, text).unwrap_or_else(|e| panic!("[{leg}] mint {text:?}: {e}"));
        assert_eq!(
            got, *w,
            "[{leg}] mint word {text:?}: {got:#034x} != {w:#034x}"
        );
        let back = dec(leg, got);
        assert_eq!(back.as_deref(), Some(*text), "[{leg}] mint circle {text:?}");
    }
    for (text, leg) in SEALED475 {
        assert!(
            enc(leg, text).is_err(),
            "[{leg}] sealed-parity {text:?} minted"
        );
    }
}

/// t475_6: refuse-parity encode: ra255 odmowa x4 (obiektywie oba engine-ery).
#[test]
fn t475_6_refuse_parity() {
    for (text, leg, _class) in MINTREF475 {
        assert!(enc(leg, text).is_err(), "[{leg}] refuse {text:?} minted");
    }
}

/// t475_7: census + SOURCE pin w stanie POST-FLIP (base_revision == CANON475;
/// stan pre-flip pending-475 historyczny w galezi przed flip475b). Census =
/// raw map-len (z _errata x2 na 121a: 23825; loader-visible 23823).
#[test]
fn t475_7_census_and_source() {
    // Current byte-pinned cut; historical fixture provenance remains unchanged.
    const CURRENT_VENDORED_CANON: &str = "5b4b03cde6d2995b501aa2e51cee27ce513c52f8" /* 2026-11-06 T-11 (was c258f8a, T-10) */ /* 2026-11-06 T-10 (was b75cc20, T-9) */;
    assert_eq!(CANON475, "9c0e4ce", "historical fixture revision drift");

    for (leg, want) in CENSUS475 {
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
        "c8fc84f8fc169838dfe67da304a7d5d3c4e52e9605d99264dbbd5a8a070cc5f1");
    assert_eq!(src["tables"]["sm120.json"]["instruction_forms"], 15849); // 2026-11-06 G (canonical 5b4b03c): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 5b4b03c): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 2026-11-06 T-11 (canonical 5b4b03c): 15953 -> 15964 // 2026-11-06 T-10 (canonical 315bffa): sm120 16045 -> 15935 forms, 26646 -> 26562 variants; sm103a / sm100a 14912 -> 14913, 22363 -> 22420  // 2026-11-06 T-9 BRA family (canonical b75cc20): 16054 -> 16045 // 2026-11-06 T-8 (LEA family rebuilt, F2FP twins + 9 junk keys retired, ATOMS_R_ARURI_R 36 measured groups, ATOMS_R_AURI_R [EXCH] retired; canonical 7094efc): sm120 16097 -> 16054 forms, 26663 -> 26611 variants // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // 2026-11-05 T-6 item 2 (T-5's SHF + LDTM/STTM rows on the wave-11 tables, canonical 377b507): sm120 keys 16143 -> 16103 (-40 dotted SHF), variants 26612 -> 26656; sm100a/sm103a variants 22199 -> 22340; loader sm120 16123 // 2026-11-04 (canonical T-3 batches): forms 16107 / variants 20894 (-20 era keys -> _meta.key_aliases, +LDL_R_ARURI, MUFU_R_UR rebuilt, IMAD alias groups -> U32 twins, F2F_R_R F32,F64 removed) // 2026-11-03 dynamic-audit batch 1 (canonical 6619782): -12 sm120 keys / -22 variants (FSETP_P_P_L_FI_P, FSETP_P_P_L_L_P, F2FP.F16.F32.PACK_AB_P_R_R_R, HMMA *_P0_* rows, LOP3.LUT_P_R_R_R_R_II_P, QMMA.16816.F16.E4M3.E4M3_P_R_R_R_R: their words are other instructions for nvdisasm) = 16126 forms, 20883 variants; LDGSTS base field 8 bits, LDC/LDCU reuse field removed; hygiene pass (canonical 64eaa21) cleared the baked control bits, counts unchanged. // 2026-11-02 HMUL2 imm / LDSM FP4-FP6 / PRMT UR / ARRIVES.LDGSTSBAR / UTMASTG dims (canonical 77a3dfa): +3 sm120 keys (HMUL2_R_R_FI_FI, PRMT_R_R_UR_R, ARRIVES_ARURI), +30 LDSM_R_ARI and +4 UTMASTG groups (variants 20850 -> 20905) = 16138. // 2026-10-29 ATOMS [R+UR+imm] / STSM.8.MT168 / UBLKPF.L2 (canonical 137cd34): +2 sm120 keys (UBLKPF_AURI_UR, UBLKPF_AURI_UR_II), +3 STSM_ARI_R groups, ATOMS_R_ARURI_R MAX,S32 re-measured (variants 20845 -> 20850) = 16135. // 2026-10-28 F2FP.BF16.E8.UNPACK_B_R_R (canonical f1e02b3): +1 sm120 key
    assert_eq!(src["tables"]["sm120.json"]["encoding_variants"], 26451); // 2026-11-06 G (canonical 5b4b03c): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 5b4b03c): ISETP / UISETP measured, 67 groups added: sm120 26595 -> 26662 variants // 2026-11-06 G (canonical 5b4b03c): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 2026-11-06 T-11 (canonical 5b4b03c): 26580 -> 26598 // 2026-11-06 T-10 (canonical 315bffa): sm120 16045 -> 15935 forms, 26646 -> 26562 variants; sm103a / sm100a 14912 -> 14913, 22363 -> 22420  // 2026-11-06 T-9 BRA family (canonical b75cc20): 26611 -> 26646 // 2026-11-06 T-8 (LEA family rebuilt, F2FP twins + 9 junk keys retired, ATOMS_R_ARURI_R 36 measured groups, ATOMS_R_AURI_R [EXCH] retired; canonical 7094efc): sm120 16097 -> 16054 forms, 26663 -> 26611 variants // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // 2026-11-05 T-6 item 2 (T-5's SHF + LDTM/STTM rows on the wave-11 tables, canonical 377b507): sm120 keys 16143 -> 16103 (-40 dotted SHF), variants 26612 -> 26656; sm100a/sm103a variants 22199 -> 22340; loader sm120 16123 // 2026-11-04 (canonical T-3 batches): forms 16107 / variants 20894 (-20 era keys -> _meta.key_aliases, +LDL_R_ARURI, MUFU_R_UR rebuilt, IMAD alias groups -> U32 twins, F2F_R_R F32,F64 removed) // 2026-11-03 dynamic-audit batch 1 (canonical 6619782): -12 sm120 keys / -22 variants (FSETP_P_P_L_FI_P, FSETP_P_P_L_L_P, F2FP.F16.F32.PACK_AB_P_R_R_R, HMMA *_P0_* rows, LOP3.LUT_P_R_R_R_R_II_P, QMMA.16816.F16.E4M3.E4M3_P_R_R_R_R: their words are other instructions for nvdisasm) = 16126 forms, 20883 variants; LDGSTS base field 8 bits, LDC/LDCU reuse field removed; hygiene pass (canonical 64eaa21) cleared the baked control bits, counts unchanged. // 2026-11-02 HMUL2 imm / LDSM FP4-FP6 / PRMT UR / ARRIVES.LDGSTSBAR / UTMASTG dims (canonical 77a3dfa): +3 sm120 keys (HMUL2_R_R_FI_FI, PRMT_R_R_UR_R, ARRIVES_ARURI), +30 LDSM_R_ARI and +4 UTMASTG groups (variants 20850 -> 20905) = 16138. // 2026-10-29 ATOMS [R+UR+imm] / STSM.8.MT168 / UBLKPF.L2 (canonical 137cd34): +2 sm120 keys (UBLKPF_AURI_UR, UBLKPF_AURI_UR_II), +3 STSM_ARI_R groups, ATOMS_R_ARURI_R MAX,S32 re-measured (variants 20845 -> 20850) = 16135. // 2026-10-28 F2FP.BF16.E8.UNPACK_B_R_R (canonical f1e02b3): +1 sm120 key, variants 20844 -> 20845; 2026-10-25 CCTL (canonical 8d26508): +7 mod groups in CCTL_ARI (E,PF1/WB/IV/RS/PML2/RML2 + DML2,E), keys unchanged 16132, variants 20837 -> 20844
}

/// t475_8: corpus36 EXACT keep z era-pelna reprezentacja (0x000be400<<96|w;
/// korekta iter288 -- STG-ven w corpus475_verify bylo null). hot==vendor x4.
#[test]
fn t475_8_corpus_exact() {
    for (w, leg, want) in CORPUS475 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] corpus {w:#034x}");
    }
}

/// t475_9: rekanon R2+R3 -- absent: puste widthless/anomalie NIE zyja;
/// R3 (INC-289d): alias-encode-only = LDG_R_R_dARI wraca z JEDNYM mg
/// '256,E,ENL2' encode_only (legacy-spelling; decoder-skipped);
/// r3-restored = NA/EU lattice-key obecny (klon-okna grafta).
#[test]
fn t475_9_rekanon() {
    for (key, leg, mode) in REKANON475 {
        let raw: serde_json::Value =
            serde_json::from_str(&cubit::table::read_table_text(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        match *mode {
            "absent" => assert!(
                ins.get(*key).is_none(),
                "[{leg}] rekanon-key {key} przezywa"
            ),
            "alias-encode-only" => {
                let k = ins
                    .get(*key)
                    .unwrap_or_else(|| panic!("[{leg}] alias-key {key} absent"));
                let mg = k["mod_groups"].as_object().unwrap();
                assert_eq!(mg.len(), 1, "[{leg}] alias-key mg-set != 1");
                let a = &mg["256,E,ENL2"];
                assert_eq!(a["encode_only"], true, "[{leg}] alias mg bez encode_only");
                assert_eq!(
                    a["and_base"], "0x8121900fe0000000000097e",
                    "[{leg}] alias and_base drift"
                );
                assert_eq!(
                    k["_src475r3"], "bug475r3-2026-09-17",
                    "[{leg}] alias bez _src475r3"
                );
            }
            "r3-restored" => assert!(
                ins.get(*key).is_some(),
                "[{leg}] R3-restore-key {key} absent"
            ),
            "r3b-restored-anom" => {
                let k = ins
                    .get(*key)
                    .unwrap_or_else(|| panic!("[{leg}] R3b-anomalia {key} absent po restore"));
                assert_eq!(
                    k["_src475r3"], "bug475r3b-2026-09-17",
                    "[{leg}] {key} bez tagu R3b"
                );
                assert_eq!(
                    k["mod_groups"][""]["count"], 0,
                    "[{leg}] {key} count != 0 po restore"
                );
            }
            other => panic!("nieznany REK-mode {other}"),
        }
    }
}

/// t475_10: R3 restore EXACT -- NA/EU ENL2.256 desc-dARI (INC-289d) dekoduja
/// DOKLADNIE tekst vendora x4 na nogach legal (klon-okna grafta; ghost UR6
/// 462-era nie wraca -- pin ur.38w drukuje UR38 bez ghost-imm). "" = HOLE-keep
/// (121a + EU-120: vendor-legal, pokrycia nigdy nie bylo; kand 491).
#[test]
fn t475_10_r3_restore() {
    let legs = ["sm100a", "sm103a", "sm120", "sm121a"];
    for &(w, t100, t103, t120, t121) in R3R475 {
        let wants = [t100, t103, t120, t121];
        for (leg, want) in legs.iter().zip(wants.iter()) {
            let got = dec(leg, w);
            let want: Option<&str> = if want.is_empty() { None } else { Some(*want) };
            assert_eq!(
                got.as_deref(),
                want,
                "[{leg}] r3-restore {w:#034x}: got {got:?} want {want:?}"
            );
        }
    }
}

/// t475_11: alias-encode parity (INC-289d) -- legacy-spelling ".E.256.ENL2"
/// mintuje DOKLADNIE slowo kanonicznego spellingu (== cold474-mint; pin-word
/// maszynowy). Odd-base: sm103a sealed (BUG-077); 100a/120 parity z cold474.
#[test]
fn t475_11_alias_mint() {
    for (ta, tc, w, leg) in ALIAS475 {
        let a = enc(leg, ta).unwrap_or_else(|e| panic!("[{leg}] alias-err {ta:?}: {e}"));
        let c = enc(leg, tc).unwrap_or_else(|e| panic!("[{leg}] canon-err {tc:?}: {e}"));
        assert_eq!(a, *w, "[{leg}] alias mint {ta:?} != pin {w:#034x}");
        assert_eq!(c, *w, "[{leg}] canon mint {tc:?} != pin {w:#034x}");
    }
    for (t, leg, w) in ODD077R475 {
        if *w == 0 {
            assert!(enc(leg, t).is_err(), "[{leg}] odd-base {t:?} minted");
        } else {
            let a = enc(leg, t).unwrap_or_else(|e| panic!("[{leg}] odd-err {t:?}: {e}"));
            assert_eq!(a, *w, "[{leg}] odd parity {t:?} != cold-mint {w:#034x}");
        }
    }
}
