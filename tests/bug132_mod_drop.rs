//! BUG-132 (encoder/wrong-code): the lookup chain
//! (fk,mg)->(key,mg)->(fk,"")->(key,"") when no row exists for the EXACT
//! mod combination fell to the "" group and SILENTLY dropped mods, emitting a DIFFERENT
//! variant. Pre-fix repro (HEAD 22e27ef8, tables/sm120.json):
//!   `FADD.RZ.SAT R1, R2, R3 ;`      -> a word with bits [80:78]=000 (plain RN!)
//!   `FADD.FTZ.RZ.SAT R1, R2, R3 ;`  -> ditto (FTZ lost too)
//! (the FADD_R_R_R rows: "", FTZ, RZ, SAT, FTZ,RZ — no SAT+rounding
//! combination). The "silent or loud" verdict: the word decoded as plain FADD,
//! so re-asm of the render returned a different variant than the author wrote (the
//! 129/130/131 doctrine: errors must be loud).
//!
//! Fix (encoder.rs): after the row pick, if the chosen group != the requested one,
//! decode-back verification (fail-closed): the word decoded by the same table
//! must CLAIM every requested mod (the claim set = mods baked into the InsKey
//! of the matched row UNION the row's mod group; two harvest eras).
//! Superset rule: a row may claim MORE than requested (the only hidden
//! form, e.g. LDGSTS "128,E" -> the "128,BYPASS,E,LTC128B" row), never
//! less. Load-bearing idioms (proven by corpus byte round-trips)
//! pass because their words decode WITH mods:
//!   IMAD.U32 _UR (sm120+sm103a), BRXU.U / LOP3.LUT.PAND / IADD3.X.RCNEG /
//!   BAR.SYNC.DEFER_BLOCKING (tb_i82p3; there the mods live in the key name).
//!
//! Kontrola pre-fix (HEAD 22e27ef8, ta sama binarka/testy): t132_1 i t132_5
//! FAIL (encode OK instead of an error — silent drop; sweep: 3/3 silent), t132_2,
//! t132_3, t132_4 PASS (inwarianty niezalezne od fixa).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn t103() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }

fn enc(t: &IsaTable, line: &str) -> anyhow::Result<u128> {
    let ins = parse_sass(line, 0).unwrap_or_else(|e| panic!("parse {line:?}: {e}"));
    encode_instruction(&ins, t)
}

/// t132_1: row-less mod combinations must FAIL loudly (not silently
/// zakodowac innej wariancie). Komunikat nazywa klase + zgubione mody.
#[test]
fn t132_1_uncovered_combo_fails_loud() {
    let t = t120();
    for line in ["FADD.RZ.SAT R1, R2, R3 ;", "FADD.FTZ.RZ.SAT R1, R2, R3 ;"] {
        match enc(&t, line) {
            Ok(w) => panic!("{line:?} silently encoded as 0x{w:032x} (BUG-132 regression)"),
            Err(e) => {
                let m = format!("{e:#}");
                assert!(m.contains("silent modifier drop"), "{line:?}: wrong error: {m}");
                assert!(m.contains("SAT"), "{line:?}: error must name the dropped mod: {m}");
            }
        }
    }
}

/// t132_2: load-bearing ""-fallback idiomy NIE moga byc zlamane: slowo
/// wychodzi, a decode-back roszczi zadane mody (tu: U32).
#[test]
fn t132_2_load_bearing_ur_idiom_survives() {
    for t in [t120(), t103()] {
        let w = enc(&t, "IMAD.U32 R1, R2, R3, UR4 ;")
            .expect("IMAD.U32 _UR idiom must keep encoding");
        let idx = DecodeIndex::build(&t);
        let d = idx.decode(w, 0, &t).expect("produced word must decode back");
        assert!(d.key.starts_with("IMAD_R"), "decode-back key: {}", d.key);
        assert!(d.mod_group.split(',').any(|m| m == "U32"),
                "decode-back must claim U32 (got {}::{:?})", d.key, d.mod_group);
    }
}

/// t132_3: the superset rule: the only form (here: LDGSTS.128 with full policy
/// cache w and_base) moze roszcic WIECEJ niz zadano — encode przechodzi.
#[test]
fn t132_3_superset_policy_row_passes() {
    let t = t120();
    let w = enc(&t, "LDGSTS.E.128 [R4], [R6] ;").expect("LDGSTS.E.128 must encode");
    let idx = DecodeIndex::build(&t);
    let d = idx.decode(w, 0, &t).expect("decode-back");
    assert!(d.key.starts_with("LDGSTS"), "key: {}", d.key);
}

/// t132_4: dokladne kombinacje (wiersz istnieje) = byte-exact slowa vendor
/// z BUG-131 evidence; guard @P1 tez dokladny.
#[test]
fn t132_4_exact_combos_byte_exact() {
    let t = t120();
    const GOLD: &[(u128, &str)] = &[
        (0x000fe2000000c0000000000a0d151221u128, "@P1 FADD.RZ R21, R13, R10"),
        (0x000fe4000001c0000000001a1b221221u128, "@P1 FADD.FTZ.RZ R34, R27, R26"),
    ];
    const SCHED: u128 = 0xFFFF_FFFFu128 << 96;
    for &(word, line) in GOLD {
        let w = enc(&t, line).unwrap_or_else(|e| panic!("{line:?}: {e:#}"));
        assert_eq!(w & !SCHED, word & !SCHED, "payload bits differ for {line:?}");
    }
}

/// t132_5: sweep — kazda kombinacja {FTZ?, RM/RP/RZ, SAT} FADD_R_R_R, ktora
/// has NO row (and the full table confirms as much), it rejects loudly; every
/// ktora ma wiersz, koduje z zachowanymi modami (decode-back superset).
/// RN swiadomie POZA kratka: RN = implicit default rounding, zaden wiersz
/// does not model it, so an explicit `.RN` is now loudly rejected too (evidence of
/// rule stiffness; nvdisasm never prints `.RN`, the rt98 corpus is clean).
#[test]
fn t132_5_combo_sweep_matches_table_coverage() {
    let t = t120();
    // RN is explicit only in authored text; post-fix = a loud error.
    let e = enc(&t, "FADD.RN R1, R2, R3 ;").expect_err("explicit .RN must refuse");
    assert!(format!("{e:#}").contains("silent modifier drop"));
    let covered: std::collections::BTreeSet<String> = t.entries["FADD_R_R_R"]
        .mod_groups.keys().cloned().collect();
    let idx = DecodeIndex::build(&t);
    let mut bailed = 0u32;
    let mut encoded = 0u32;
    for ftz in ["", "FTZ."] {
        for rnd in ["", "RM.", "RP.", "RZ."] {
            for sat in ["", "SAT."] {
                let mods = format!("{ftz}{rnd}{sat}").trim_end_matches('.').to_string();
                let line = format!("FADD{} R1, R2, R3 ;",
                    if mods.is_empty() { String::new() } else { format!(".{mods}") });
                match enc(&t, &line) {
                    Ok(w) => {
                        encoded += 1;
                        let d = idx.decode(w, 0, &t).expect("decode-back of encoded word");
                        for m in mods.split('.').filter(|m| !m.is_empty()) {
                            let in_key = d.key.split('_').next().unwrap_or("")
                                .split('.').any(|x| x == m);
                            let in_mg = d.mod_group.split(',').any(|x| x == m);
                            assert!(in_key || in_mg,
                                "{line:?}: mod {m} silently dropped ({}::{:?})",
                                d.key, d.mod_group);
                        }
                    }
                    Err(e) => {
                        bailed += 1;
                        assert!(format!("{e:#}").contains("silent modifier drop"),
                                "{line:?}: unexpected error: {e:#}");
                        // no row for the combination = the table itself confirms it
                        let mut key = mods.split('.').filter(|m| !m.is_empty())
                            .collect::<Vec<_>>();
                        key.sort_unstable();
                        assert!(!covered.contains(&key.join(",")),
                                "{line:?} bailed but table HAS the row {:?}", key);
                    }
                }
            }
        }
    }
    assert!(encoded > 0 && bailed > 0, "sweep degenerated: {encoded}/{bailed}");
}

/// t132_6: tolerowane idiomy (allowlista, kazdy z dowodem bajtowym/stabilnosci
/// pre-fix) must NOT be broken by the fail-closed check: the F2FP wildcard
/// (sm120, qpack production) i REDUX.ADD.U32 (sm103a, bug080 t5) koduja Ok.
/// Also guards that the allowlist does NOT blur onto other mods (see t132_1/5).
/// NOTE BUG-135: `LDC.128 R-form` zostal WYLACZONY z allowlisty — dawniej
/// tolerowany "byte-exact pin" okazal sie cichym width-dropem do plain LDC
/// (nvdisasm: R-domain width 2/3 = INVALID6/7; zero such words in the
/// vendor corpus). Authored `LDC.128 R...` now BAILS (pins in bug135).
#[test]
fn t132_6_tolerated_idioms_pinned() {
    enc(&t120(), "F2FP.SATFINITE.E4M3.F32.PACK_AB_MERGE_C R26, R14, R26 ;")
        .expect("F2FP wildcard idiom");
    enc(&t103(), "@P0 REDUX.ADD.U32 UR4, R10 ;").expect("REDUX idiom");
    // anti-rozmycie: LDC.128 R-domain MUSI bailowac glosno (BUG-135)
    let e = enc(&t103(), "LDC.128 R53, c[0x0][0x380] ;")
        .expect_err("LDC.128 R-form has no encoding (BUG-135)");
    assert!(format!("{e}").contains("128"), "error must name the dropped mod: {e}");
}
