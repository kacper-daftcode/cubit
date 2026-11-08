//! BUG-475 pins (F2-iter287/288, loop5/blind front2, 2026-09-17): the dARI modsub
//! lattice (b76 = 1) on the E*L2.256 frame (LDG 0x97e / STG 0x97f, desc[URx][Ry.64])
//! -- a clone of the 6 *_dARI EFL2.256 donors per leg (LDG x4 {,_P,_II,_II_P}, STG x2
//! {_II}) onto the lattice of 191 combinations per op (l1, l2, sem \ base; l2 != 3) =
//! +1146 keys per leg; the clone changes ONLY and_base (the pins [77:86), b76 = 1) +
//! base_op; vm / fields verbatim. The RE-CANON of the 462 mgs ENL2 (the 489 absorb):
//! DELETE 13/13/7 mgs ENL2 ltc = 0 on the widthless keys (the emptied LDG_R_R_dARI /
//! STG_dARI_R_R deleted on x100a / 103a; on x120 the mg only), 121a REPLACE 9 heritage
//! _src462 lattice-named + DELETE 2 token anomalies NA / EU (count = 0, dead). ENGINE
//! ZERO source changes (the dARI op path is driven by the signature). Vendor law:
//! arb475 560 probes nvdisasm 13.3.73 raw -b x4 AGREE EVERY except l2 = 3 (the
//! divergence = exactly the 64 LDG l2 = 3 cells, the era split standing from 463; STG
//! l2 = 3 the glyph INVALID3); the kills b91 = 0 rc=1 x4; ra255 REFUSE x4 (NO '[URm]'
//! elision as in plain 464); ur255 desc[URZ]; the imm signed<<5 inside the desc
//! brackets; the STG LTC selector [74:73] inert x4. Data: patch475.py replay from
//! canon_pre (68ac5aa content) byte-exact x4 + idempotent all-skip 4584; audits A0 /
//! A0b (408) / A1 / A2 / A4 (+1146 -2 keys x4) / A5 census (14868/14868/16005/23825) /
//! A9-R2 (+R3 / R3b: NA / EU / alias + the 121a anomalies) fail-closed. Canonical commit = cc2f62c379c3e190ef373ab9e8f76af0aeef326c
//! (serialisation INC-283a: after publish474; flip475b phase B). Corpus: 36 uniq dARI
//! in ab240 EXACT keep x4 (the era correction of iter288: corpus475_verify_v2).
//! Witness: tests/bug475_data.inc (machine-built by gen475pins.py rc=2; the class
//! matrix locked x claim475 engine truth; NOTE: the A1 split heal / heal462 was
//! candidate-based -- the generator measures through the engine: 6/6/4/4 vs A1
//! 3/3/3/4; the sums agree).
//! R3 (F2-iter289, INC-289d): the R2 over-delete after the 489 mis-classification --
//! the vendor-legal coverage restored: NA / EU ENL2.256 dARI (clones of the graft's
//! window, NOT the verbatim 462 [ur5@32 + imm20@37 shr2]; arb475r3 27 probes x4 div 0
//! / invalid 0, cold-MIS = 15) + the alias encode ".E.256.ENL2" (LDG_R_R_dARI mg
//! encode_only). The collision sweep 596 x4 diffs = 0; verify475r3 GATE PASS; 121a
//! byte-untouched.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;
use std::collections::HashMap;
use std::sync::OnceLock;

include!("bug475_data.inc");

/// 2026-11-07 (session G, batch 10, tools/probes/re_sm120_ldg256.py, nvdisasm 13.1 on SM120 / SM103 / SM100): the
/// 256-bit load's descriptor form is measured whole on sm120 (`LDG_R_R_dARI[_II][_P]`, 1 152 groups each). Three
/// consequences for these 2026-09 pins on the sm120 leg: (1) the text-inert bits 83 / 92-95 fail closed on the
/// measured rows (T-10's convention for measured rows, every G batch; the 2026-09 rows tolerated the "noop band"),
/// (2) the LTC x ENL2 cross words of LTC475 are legal words the vendor names (the lane-490 HOLE was the harvest's
/// silence), (3) the EU cache code is legal on sm120 too (R3R475's "EU-120 HOLE-keep": nvdisasm names it on the
/// three targets). The other legs are untouched.
const G10_INERT_SM120: u128 = (1u128 << 83) | (0xfu128 << 92);
/// G batch 13 (tools/probes/re_sm120_stg256.py): the 256-bit store's text-inert bits -- no LTC width ([74:72]), no
/// trailing predicate (87), 83 and [95:92]; the measured `STG_{dARI,ARURI,ARURI64}_R_R[_II]` rows fail closed on them.
const G13_INERT_STG_SM120: u128 = (7u128 << 72) | (1u128 << 83) | (1u128 << 87) | (0xfu128 << 92);
const G10_LTC_SM120: [(u128, &str); 3] = [
    (0x000be40008125b2c320000261c30197e, "@P1 LDG.E.ENL2.LTC64B.256.CONSTANT.CTA R44, R48, desc[UR38][R28.64], 0x99"),
    (0x000be40008125d2c320000261c30197e, "@P1 LDG.E.ENL2.LTC128B.256.CONSTANT.CTA R44, R48, desc[UR38][R28.64], 0x99"),
    (0x000be40008125f2c320000261c30197e, "@P1 LDG.E.ENL2.LTC256B.256.CONSTANT.CTA R44, R48, desc[UR38][R28.64], 0x99"),
];

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
        if *leg == "sm120" && (*w & 0xfff) == 0x97e && (*w & G10_INERT_SM120) != 0 {
            assert_eq!(got, None, "[{leg}] heal {w:#034x}: text-inert bits fail closed on the measured rows (G batch 10)");
            continue;
        }
        if *leg == "sm120" && (*w & 0xfff) == 0x97f && (*w & G13_INERT_STG_SM120) != 0 {
            assert_eq!(got, None, "[{leg}] heal {w:#034x}: text-inert bits fail closed on the measured store rows (G batch 13)");
            continue;
        }
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
                if let Some((_, measured)) = G10_LTC_SM120.iter().find(|(mw, _)| *leg == "sm120" && mw == w) {
                    assert_eq!(got.as_deref(), Some(*measured), "[{leg}] ltc-ldg {w:#034x} (measured legal, G batch 10)");
                } else if text.is_empty() {
                    assert!(got.is_none(), "[{leg}] ltc-ldg {w:#034x} -> {got:?}");
                } else {
                    assert_eq!(got.as_deref(), Some(*text), "[{leg}] ltc-ldg {w:#034x}");
                }
            }
            "stg-base" | "stg-heal" => {
                // G batch 13: the LTC bits [74:73] are text-inert on the 256-bit store and the measured rows fail closed on
                // them (the "stg ltc inert" cells of this grid); the base cells decode as before.
                if *leg == "sm120" && (*w & 0xfff) == 0x97f && (*w & G13_INERT_STG_SM120) != 0 {
                    assert_eq!(got, None, "[{leg}] {kind} {w:#034x}: inert bits fail closed (G batch 13)");
                    continue;
                }
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
    const CURRENT_VENDORED_CANON: &str = "6a468a2e6505999ed99ddec8f4f3dde0f2a8f06f" /* 2026-11-06 T-11 (was c258f8a, T-10) */ /* 2026-11-06 T-10 (was b75cc20, T-9) */;
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
        "a4ea25e88d75d3264e923dae0f841969b43ecd612d13cde4040e30fad72f2442");
    assert_eq!(src["tables"]["sm120.json"]["instruction_forms"], 979); // T-19 2026-11-08: the long tail closed, 111 -> 7 rows without _src // 2026-11-08 T-18 (canonical 6a468a2: 32 whole-key twins retired as aliases) // 2026-11-08 T-18 (canonical 6a468a2: the 192 wave-pinned rows measured / aliased) // re-pinned on sm120 for the long tail (G run 5 batch 16 re-applied by T-17 on the batches 12-15 base, 6a468a2) // re-pinned 2026-11-07 (T-16: G run 5 batch 15 — the tensor-core long tail verified row by row — on the batches 12-14 base) // re-pinned 2026-11-07 (G batch 14: REDG uniform-indexed forms measured whole) // re-pinned 2026-11-07 (G batch 13: STG.256 measured whole) // re-pinned 2026-11-07 (G batch 12: LDG.256 ARURI measured whole) // re-pinned 2026-11-07 (G batch 11: LDG.256 ARURI64 measured whole) // re-pinned 2026-11-07 (G batch 10: LDG.256 dARI measured whole) // G batch 9 FSET / FSEL / FCHK 2026-11-07 // G batch 8 conversions 2026-11-07 // G batch 7 uniform FP32 ALU 2026-11-07 // G batch 6 FP32 ALU 2026-11-07 // 2026-11-06 G (canonical 6a468a2): UFSETP measured, 6 junk keys retired as aliases: sm120 15840 -> 15834 forms, 26442 -> 26341 variants // 2026-11-06 G (canonical 6a468a2): PLOP3 / P2R / R2P measured, 10 junk keys retired as aliases, R2P_II_R added: sm120 15849 -> 15840 forms, 26451 -> 26442 variants // 2026-11-06 G (canonical 6a468a2): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 6a468a2): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 2026-11-06 T-11 (canonical 6a468a2): 15953 -> 15964 // 2026-11-06 T-10 (canonical 315bffa): sm120 16045 -> 15935 forms, 26646 -> 26562 variants; sm103a / sm100a 14912 -> 14913, 22363 -> 22420  // 2026-11-06 T-9 BRA family (canonical b75cc20): 16054 -> 16045 // 2026-11-06 T-8 (LEA family rebuilt, F2FP twins + 9 junk keys retired, ATOMS_R_ARURI_R 36 measured groups, ATOMS_R_AURI_R [EXCH] retired; canonical 7094efc): sm120 16097 -> 16054 forms, 26663 -> 26611 variants // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // 2026-11-05 T-6 item 2 (T-5's SHF + LDTM/STTM rows on the wave-11 tables, canonical 377b507): sm120 keys 16143 -> 16103 (-40 dotted SHF), variants 26612 -> 26656; sm100a/sm103a variants 22199 -> 22340; loader sm120 16123 // 2026-11-04 (canonical T-3 batches): forms 16107 / variants 20894 (-20 era keys -> _meta.key_aliases, +LDL_R_ARURI, MUFU_R_UR rebuilt, IMAD alias groups -> U32 twins, F2F_R_R F32,F64 removed) // 2026-11-03 dynamic-audit batch 1 (canonical 6619782): -12 sm120 keys / -22 variants (FSETP_P_P_L_FI_P, FSETP_P_P_L_L_P, F2FP.F16.F32.PACK_AB_P_R_R_R, HMMA *_P0_* rows, LOP3.LUT_P_R_R_R_R_II_P, QMMA.16816.F16.E4M3.E4M3_P_R_R_R_R: their words are other instructions for nvdisasm) = 16126 forms, 20883 variants; LDGSTS base field 8 bits, LDC/LDCU reuse field removed; hygiene pass (canonical 64eaa21) cleared the baked control bits, counts unchanged. // 2026-11-02 HMUL2 imm / LDSM FP4-FP6 / PRMT UR / ARRIVES.LDGSTSBAR / UTMASTG dims (canonical 77a3dfa): +3 sm120 keys (HMUL2_R_R_FI_FI, PRMT_R_R_UR_R, ARRIVES_ARURI), +30 LDSM_R_ARI and +4 UTMASTG groups (variants 20850 -> 20905) = 16138. // 2026-10-29 ATOMS [R+UR+imm] / STSM.8.MT168 / UBLKPF.L2 (canonical 137cd34): +2 sm120 keys (UBLKPF_AURI_UR, UBLKPF_AURI_UR_II), +3 STSM_ARI_R groups, ATOMS_R_ARURI_R MAX,S32 re-measured (variants 20845 -> 20850) = 16135. // 2026-10-28 F2FP.BF16.E8.UNPACK_B_R_R (canonical f1e02b3): +1 sm120 key
    assert_eq!(src["tables"]["sm120.json"]["encoding_variants"], 38838); // T-19 2026-11-08: the long tail closed, 111 -> 7 rows without _src // 2026-11-08 T-18 (canonical 6a468a2: 32 whole-key twins retired as aliases) // 2026-11-08 T-18 (canonical 6a468a2: the 192 wave-pinned rows measured / aliased) // re-pinned on sm120 for the long tail (G run 5 batch 16 re-applied by T-17 on the batches 12-15 base, 6a468a2) // re-pinned 2026-11-07 (T-16: G run 5 batch 15 — the tensor-core long tail verified row by row — on the batches 12-14 base) // re-pinned 2026-11-07 (G batch 14: REDG uniform-indexed forms measured whole) // re-pinned 2026-11-07 (G batch 13: STG.256 measured whole) // re-pinned 2026-11-07 (G batch 12: LDG.256 ARURI measured whole) // re-pinned 2026-11-07 (G batch 11: LDG.256 ARURI64 measured whole) // re-pinned 2026-11-07 (G batch 10: LDG.256 dARI measured whole) // G batch 9 FSET / FSEL / FCHK 2026-11-07 // G batch 8 conversions 2026-11-07 // G batch 7 uniform FP32 ALU 2026-11-07 // G batch 6 FP32 ALU 2026-11-07 // 2026-11-06 G (canonical 6a468a2): UFSETP measured, 6 junk keys retired as aliases: sm120 15840 -> 15834 forms, 26442 -> 26341 variants // 2026-11-06 G (canonical 6a468a2): PLOP3 / P2R / R2P measured, 10 junk keys retired as aliases, R2P_II_R added: sm120 15849 -> 15840 forms, 26451 -> 26442 variants // 2026-11-06 G (canonical 6a468a2): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 6a468a2): ISETP / UISETP measured, 67 groups added: sm120 26595 -> 26662 variants // 2026-11-06 G (canonical 6a468a2): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 2026-11-06 T-11 (canonical 6a468a2): 26580 -> 26598 // 2026-11-06 T-10 (canonical 315bffa): sm120 16045 -> 15935 forms, 26646 -> 26562 variants; sm103a / sm100a 14912 -> 14913, 22363 -> 22420  // 2026-11-06 T-9 BRA family (canonical b75cc20): 26611 -> 26646 // 2026-11-06 T-8 (LEA family rebuilt, F2FP twins + 9 junk keys retired, ATOMS_R_ARURI_R 36 measured groups, ATOMS_R_AURI_R [EXCH] retired; canonical 7094efc): sm120 16097 -> 16054 forms, 26663 -> 26611 variants // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658 (12 measured groups replace 3 + the 7 keys' 11 groups); loader sm120 16116 // 2026-11-05 T-6 item 2 (T-5's SHF + LDTM/STTM rows on the wave-11 tables, canonical 377b507): sm120 keys 16143 -> 16103 (-40 dotted SHF), variants 26612 -> 26656; sm100a/sm103a variants 22199 -> 22340; loader sm120 16123 // 2026-11-04 (canonical T-3 batches): forms 16107 / variants 20894 (-20 era keys -> _meta.key_aliases, +LDL_R_ARURI, MUFU_R_UR rebuilt, IMAD alias groups -> U32 twins, F2F_R_R F32,F64 removed) // 2026-11-03 dynamic-audit batch 1 (canonical 6619782): -12 sm120 keys / -22 variants (FSETP_P_P_L_FI_P, FSETP_P_P_L_L_P, F2FP.F16.F32.PACK_AB_P_R_R_R, HMMA *_P0_* rows, LOP3.LUT_P_R_R_R_R_II_P, QMMA.16816.F16.E4M3.E4M3_P_R_R_R_R: their words are other instructions for nvdisasm) = 16126 forms, 20883 variants; LDGSTS base field 8 bits, LDC/LDCU reuse field removed; hygiene pass (canonical 64eaa21) cleared the baked control bits, counts unchanged. // 2026-11-02 HMUL2 imm / LDSM FP4-FP6 / PRMT UR / ARRIVES.LDGSTSBAR / UTMASTG dims (canonical 77a3dfa): +3 sm120 keys (HMUL2_R_R_FI_FI, PRMT_R_R_UR_R, ARRIVES_ARURI), +30 LDSM_R_ARI and +4 UTMASTG groups (variants 20850 -> 20905) = 16138. // 2026-10-29 ATOMS [R+UR+imm] / STSM.8.MT168 / UBLKPF.L2 (canonical 137cd34): +2 sm120 keys (UBLKPF_AURI_UR, UBLKPF_AURI_UR_II), +3 STSM_ARI_R groups, ATOMS_R_ARURI_R MAX,S32 re-measured (variants 20845 -> 20850) = 16135. // 2026-10-28 F2FP.BF16.E8.UNPACK_B_R_R (canonical f1e02b3): +1 sm120 key, variants 20844 -> 20845; 2026-10-25 CCTL (canonical 8d26508): +7 mod groups in CCTL_ARI (E,PF1/WB/IV/RS/PML2/RML2 + DML2,E), keys unchanged 16132, variants 20837 -> 20844
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
        if *leg == "sm120" && key.contains("_R_R_dARI") {
            // G batch 10: `LDG_R_R_dARI` is the measured plain key (1 152 groups, the legacy `256,E,ENL2` spelling
            // among them with the same and_base, measured rather than encode-only); the restored NA / EU lattice
            // key is a `_meta.key_aliases` entry of the plain key and its tokens name one of its groups.
            match *mode {
                "alias-encode-only" => {
                    let k = &ins[*key];
                    assert_eq!(k["_src"], "ldg256-family-2026-11-07", "[{leg}] {key}");
                    let mg = k["mod_groups"].as_object().unwrap();
                    assert_eq!(mg.len(), 1152, "[{leg}] measured group count");
                    let a = &mg["256,E,ENL2"];
                    assert_eq!(a["and_base"], "0x0000000008121900fe0000000000097e", "[{leg}] the legacy spelling's and_base");
                    assert!(a.get("encode_only").is_none(), "[{leg}] a measured row, not encode-only");
                }
                "r3-restored" => {
                    assert!(ins.get(*key).is_none(), "[{leg}] {key} retired as an alias");
                    let target = raw["_meta"]["key_aliases"][*key].as_str().unwrap_or_else(|| panic!("[{leg}] {key} not an alias"));
                    assert_eq!(target, "LDG_R_R_dARI", "[{leg}] {key}");
                    let mut toks: Vec<&str> = key.split('_').next().unwrap().split('.').skip(1).collect();
                    toks.sort_unstable();
                    assert!(ins[target]["mod_groups"].get(toks.join(",")).is_some(), "[{leg}] {key}: group of the plain key");
                }
                other => panic!("[{leg}] unexpected mode {other} for {key}"),
            }
            continue;
        }
        if *leg == "sm120" && *key == "STG_dARI_R_R" {
            // G batch 13 (tools/probes/re_sm120_stg256.py): the widthless anomaly key of the R2 rekanon is the measured
            // plain key of the 256-bit store's descriptor form now (288 groups, every one with the RZ-base claim_forbid).
            let k = &ins[*key];
            assert_eq!(k["_src"], "stg256-family-2026-11-07", "[{leg}] {key}");
            assert_eq!(k["mod_groups"].as_object().unwrap().len(), 288, "[{leg}] {key}: the measured group count");
            continue;
        }
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
            // the EU.ENL2.256 descriptor words: legal on sm120 since G batch 10 -- the text of the other legs
            let want: &str = if *leg == "sm120" && want.is_empty() && (w & 0xfff) == 0x97e { t103 } else { want };
            let want: Option<&str> = if want.is_empty() { None } else { Some(want) };
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
